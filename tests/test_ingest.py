"""Wire-layer tests for POST /v1/ingest (CONTRACT_SPEC.md §7.1–§7.6).

Offline + deterministic (§B has no server and no outbound network): every request is served
by an ``httpx.MockTransport`` whose handler returns a fixture response or captures the request
for assertion. TLS / cert verification is httpx's default and is never disabled here.

Async-runner choice (no new dependency): the public surface is the SYNCHRONOUS ``IngestClient``
facade, exercised with plain sync tests. The one test of the async core
(``test_async_core_directly``) drives the coroutine via stdlib ``asyncio.run`` inside a sync
test function — so the suite needs NO pytest async plugin (neither anyio's plugin nor
pytest-asyncio) and adds no dev/runtime dependency beyond httpx.
"""

from __future__ import annotations

import asyncio
from uuid import UUID

import httpx
import pytest

from cephios_core.errors import ValidationError
from cephios_core.ingest import (
    HEADER_API_VERSION,
    HEADER_BATCH_SEQUENCE,
    HEADER_SESSION_ID,
    OCTET_STREAM,
    WIRE_API_VERSION,
    AsyncIngestClient,
    BackoffPolicy,
    Disposition,
    IngestClient,
    api_key,
    bearer,
    decode_error,
    parse_retry_after,
)
from vector_loader import vector

_SID = UUID("018f0c00-0000-7000-8000-000000000001")
_ENV = bytes.fromhex("ce0f010104050607080910111213141516010203040506070809101112131415ff")


def _persisted_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "status": "persisted",
            "received_at": "2026-05-28T14:30:00Z",
            "envelope_byte_count": 33,
        },
        headers={"X-Cephios-Supported-Versions": "1.0"},
    )


def _client(handler, **kwargs) -> IngestClient:
    return IngestClient(
        credential=bearer("session-token-xyz"),
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# §7.2 request shape — the five required headers + raw octet-stream body.
# ---------------------------------------------------------------------------


def test_five_required_headers_and_raw_octet_body():
    seen: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["req"] = request
        return _persisted_response(request)

    with _client(handler) as client:
        client.ingest(_SID, 7, _ENV)

    req = seen["req"]
    assert req.method == "POST"
    assert req.url.path == "/v1/ingest"
    # The five required §7.2 headers, exact values.
    assert req.headers["Content-Type"] == OCTET_STREAM
    assert req.headers["Authorization"] == "Bearer session-token-xyz"
    assert req.headers[HEADER_API_VERSION] == "1.0"
    assert req.headers[HEADER_SESSION_ID] == str(_SID)
    assert req.headers[HEADER_BATCH_SEQUENCE] == "7"
    # Body is the RAW envelope bytes — no JSON wrapper, no base64 (§7.2).
    assert req.content == _ENV


def test_api_key_credential_scheme():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["Authorization"]
        return _persisted_response(request)

    client = IngestClient(credential=api_key("svc-key-123"), transport=httpx.MockTransport(handler))
    try:
        client.ingest(_SID, 0, _ENV)
    finally:
        client.close()
    assert seen["auth"] == "ApiKey svc-key-123"


def test_request_matches_ingestion_persisted_vector():
    # The request the client builds for the ingestion_idempotency 'persisted' vector matches the
    # vector's documented request byte-for-byte (headers + raw body). RED-CAPABLE: a JSON-wrapped
    # body or a renamed/missing header flips one of these assertions.
    vec = vector("ingestion_idempotency", "ingestion_persisted_001")
    req_spec = vec["input"]["request"]
    sid = UUID(req_spec["headers"]["X-Cephios-Session-Id"])
    seq = int(req_spec["headers"]["X-Cephios-Batch-Sequence"])
    body = bytes.fromhex(req_spec["body_hex"])

    seen: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["req"] = request
        return _persisted_response(request)

    with _client(handler) as client:
        client.ingest(sid, seq, body)

    req = seen["req"]
    for name, value in req_spec["headers"].items():
        assert req.headers[name] == value, f"header {name} mismatch vs vector"
    assert req.content == body
    # The vector omits Authorization (a shape fixture); the live client always sends it (§7.2).
    assert req.headers["Authorization"].startswith("Bearer ")


def test_wire_version_is_pinned_to_1_0():
    assert WIRE_API_VERSION == "1.0"  # the wire version (§15.6), not a document revision


def test_negative_batch_sequence_rejected():
    with _client(_persisted_response) as client:
        with pytest.raises(ValueError, match="non-negative"):
            client.ingest(_SID, -1, _ENV)


# ---------------------------------------------------------------------------
# §7.3 / §7.6 response classification — the §7.7.4 disposition inputs.
# ---------------------------------------------------------------------------


def test_persisted_response_is_ack():
    with _client(_persisted_response) as client:
        outcome = client.ingest(_SID, 0, _ENV)
    assert outcome.disposition is Disposition.ACK
    assert outcome.http_status == 200
    assert outcome.ack is not None
    assert outcome.ack.status == "persisted"
    assert outcome.ack.envelope_byte_count == 33


def test_deduplicated_response_is_ack():
    vec = vector("ingestion_idempotency", "ingestion_deduplicated_001")
    body = vec["expected_output"]["response"]["body"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    with _client(handler) as client:
        outcome = client.ingest(_SID, 0, _ENV)
    assert outcome.disposition is Disposition.ACK
    assert outcome.ack is not None
    assert outcome.ack.status == "deduplicated"  # both persisted + deduplicated are ACKs (§7.3)


def test_429_is_backpressure_with_retry_after():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"Retry-After": "12"},
            json={"error": {"category": "BufferError", "code": "ingest_rate_exceeded"}},
        )

    with _client(handler) as client:
        outcome = client.ingest(_SID, 0, _ENV)
    assert outcome.disposition is Disposition.BACKPRESSURE  # NOT a rejection (§7.6)
    assert outcome.retry_after == 12.0


def test_5xx_is_retryable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503, json={"error": {"category": "InternalError", "code": "unavailable"}}
        )

    with _client(handler) as client:
        outcome = client.ingest(_SID, 0, _ENV)
    assert outcome.disposition is Disposition.RETRYABLE  # idempotent retry safe (§7.3)


def test_non_429_4xx_is_rejected_with_decoded_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400, json={"error": {"category": "ValidationError", "code": "batch_too_large"}}
        )

    with _client(handler) as client:
        outcome = client.ingest(_SID, 0, _ENV)
    assert outcome.disposition is Disposition.REJECTED  # non-retryable (§7.7.4)
    assert isinstance(outcome.error, ValidationError)
    assert outcome.error.code == "batch_too_large"


def test_transport_error_is_retryable():
    # A connection reset / timeout after bytes sent → retain + re-attempt (§7.7.4), never purge.
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection reset")

    with _client(handler) as client:
        outcome = client.ingest(_SID, 0, _ENV)
    assert outcome.disposition is Disposition.RETRYABLE
    assert outcome.http_status is None


def test_unexpected_3xx_is_retained_not_lost():
    # An unmodeled status (here 302) is treated as RETRYABLE so the record is retained, never
    # silently purged on a response the protocol does not define.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "/elsewhere"})

    with _client(handler) as client:
        outcome = client.ingest(_SID, 0, _ENV)
    assert outcome.disposition is Disposition.RETRYABLE


# ---------------------------------------------------------------------------
# §14.1 minimal decode + §7.6 Retry-After + §7.6 backoff (pure units).
# ---------------------------------------------------------------------------


def test_decode_error_valid_envelope():
    err = decode_error(b'{"error": {"category": "ValidationError", "code": "batch_too_large"}}')
    assert isinstance(err, ValidationError)
    assert err.category == "ValidationError"
    assert err.code == "batch_too_large"


@pytest.mark.parametrize("body", [
    b"",                                   # empty body
    b"not json at all",                    # non-JSON
    b'{"no_error_key": true}',             # missing "error"
    b'{"error": {"code": "x"}}',           # missing "category"
    b'{"error": {"category": "ValidationError"}}',  # missing "code"
    b'{"error": {"category": "NotARealCategory", "code": "x"}}',  # unknown category
])
def test_decode_error_returns_none_on_unparseable(body):
    assert decode_error(body) is None  # → rejected_reason(None) → rejected_other (§7.7.3)


@pytest.mark.parametrize("value,expected", [
    ("12", 12.0),
    ("0", 0.0),
    (" 5 ", 5.0),
    ("-3", None),         # negative → fall back to backoff
    ("soon", None),       # non-numeric (incl. HTTP-date form) → fall back to backoff
    (None, None),         # header absent
])
def test_parse_retry_after(value, expected):
    assert parse_retry_after(value) == expected


def test_backoff_grows_and_clamps():
    policy = BackoffPolicy(base_seconds=0.5, factor=2.0, maximum_seconds=4.0)
    assert policy.delay(0) == 0.5
    assert policy.delay(1) == 1.0
    assert policy.delay(2) == 2.0
    assert policy.delay(3) == 4.0
    assert policy.delay(10) == 4.0  # clamped to maximum
    assert policy.delay(-1) == 0.5  # negative attempt floored to 0


# ---------------------------------------------------------------------------
# KC: credential token never rendered; the async core works directly.
# ---------------------------------------------------------------------------


def test_credential_repr_redacts_token():
    cred = bearer("super-secret-session-token")
    assert "super-secret-session-token" not in repr(cred)
    assert "<redacted>" in repr(cred)
    assert cred.header_value() == "Bearer super-secret-session-token"  # the real value still works


def test_async_core_directly():
    # Drive the async core via stdlib asyncio.run (no pytest async plugin needed). Proves the
    # async-first implementation and that the sync facade is a faithful wrapper of it.
    async def go() -> object:
        client = AsyncIngestClient(
            credential=bearer("t"), transport=httpx.MockTransport(_persisted_response)
        )
        try:
            return await client.ingest(_SID, 0, _ENV)
        finally:
            await client.aclose()

    outcome = asyncio.run(go())
    assert outcome.disposition is Disposition.ACK
