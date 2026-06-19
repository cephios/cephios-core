"""Control-plane + key-mgmt wire surface (CONTRACT_SPEC.md §8, §9, §10.5) — Commit 5b.

Q-C2 client semantics (ratified G12-D3): cephios-core is a client SDK with no live server. Each
server-response-shape test asserts BOTH (1) the client constructs the correct REQUEST
(method/path/headers/body) for the vector's input AND (2) it decodes the documented RESPONSE
shape from the canned fixture — with NO live round-trip. Built on ``httpx.MockTransport``
(offline, deterministic). Where a v1.0 vector field is a placeholder ("<base64url-encoded ...>"),
the test substitutes a real value (a C3 ``wrap_dek`` envelope / real 32-byte keys) so the
base64url round-trip is genuinely exercised; the request path/method/headers still match the
vector input.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from cephios_core.control import (
    WRAPPED_DEK_REVOKE_REASONS,
    AsyncControlClient,
    ControlClient,
    SubjectErased,
    _b64url_decode,
    _b64url_encode,
)
from cephios_core.errors import (
    AuthorizationError,
    ConsentError,
    NetworkError,
    ValidationError,
    VersionError,
)
from cephios_core.ingest import bearer
from cephios_core.wrapped_dek import unwrap_dek, wrap_dek
from vector_loader import vector


class _Recorder:
    """A MockTransport handler that records the request and returns a canned response."""

    def __init__(self, status: int, body: Any) -> None:
        self._status = status
        self._body = body
        self.request: httpx.Request | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.request = request
        return httpx.Response(self._status, json=self._body)


def _client(handler) -> ControlClient:
    return ControlClient(credential=bearer("session-token"), transport=httpx.MockTransport(handler))


def _real_wrap_envelope() -> tuple[bytes, bytes]:
    """A genuine 76-byte §6.3 wrap envelope + the private key that unwraps it."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    env = wrap_dek(pub, os.urandom(32))
    return env, priv_raw


# ---------------------------------------------------------------------------
# base64url (§8 32-byte / 76-byte values).
# ---------------------------------------------------------------------------


def test_b64url_round_trips_32_and_76_bytes():
    for n in (32, 76):
        raw = os.urandom(n)
        assert _b64url_decode(_b64url_encode(raw)) == raw


def test_b64url_encode_is_unpadded_and_url_safe():
    raw = b"\xfb\xff\xfe" * 11  # bytes that map to '+' '/' in standard base64
    encoded = _b64url_encode(raw)
    assert "=" not in encoded  # unpadded
    assert "+" not in encoded and "/" not in encoded  # url-safe alphabet


def test_b64url_decode_tolerates_missing_padding():
    raw = os.urandom(32)
    padded = base64.urlsafe_b64encode(raw).decode()  # WITH '=' padding
    assert _b64url_decode(padded) == raw
    assert _b64url_decode(padded.rstrip("=")) == raw  # and WITHOUT


# ---------------------------------------------------------------------------
# §9.1 session open — fresh + idempotent retry + failure modes.
# ---------------------------------------------------------------------------


def test_session_open_request_and_response_match_vector():
    vec = vector("session_lifecycle", "session_open_001")
    req_body = vec["input"]["request"]["body"]
    resp_body = vec["expected_output"]["response"]["body"]
    rec = _Recorder(200, resp_body)

    with _client(rec) as client:
        opened = client.open_session(
            session_id=uuid.UUID(req_body["session_id"]),
            workspace_id=uuid.UUID(req_body["workspace_id"]),
            subject_id=uuid.UUID(req_body["subject_id"]),
            consent_record_id=uuid.UUID(req_body["consent_record_id"]),
            modality=req_body["modality"],
            schema_declaration=req_body["schema_declaration"],
            dek_version=req_body["dek_version"],
        )

    # (1) request construction matches the vector input.
    assert rec.request is not None
    assert rec.request.method == "POST"
    assert rec.request.url.path == "/v1/sessions"
    assert rec.request.headers["Content-Type"] == "application/json"
    assert rec.request.headers["Authorization"] == "Bearer session-token"
    assert rec.request.headers["X-Cephios-API-Version"] == "1.1"  # §15.1 (vector omits it)
    assert json.loads(rec.request.content) == req_body  # fully concrete body == vector
    # (2) response decode.
    assert opened.session_id == uuid.UUID(resp_body["session_id"])
    assert opened.state == "open"
    assert opened.idempotent is False
    assert opened.audit_entry_id == uuid.UUID(resp_body["audit_entry_id"])


def test_session_open_idempotent_retry_parses_as_existing_session():
    # No vector for the idempotent-retry response shape (§9.1 documents it); unit-tested here.
    # RED: treating the idempotent retry as a new/failed open (missing idempotent / mishandling
    # the absent audit_entry_id).
    sid = uuid.uuid4()
    resp = {"session_id": str(sid), "state": "open", "opened_at": "2026-05-25T13:00:00Z",
            "idempotent": True}
    with _client(_Recorder(200, resp)) as client:
        opened = client.open_session(
            session_id=sid, workspace_id=uuid.uuid4(), subject_id=uuid.uuid4(),
            consent_record_id=uuid.uuid4(), modality="EEG",
            schema_declaration={"channel_count": 1}, dek_version=0,
        )
    assert opened.idempotent is True
    assert opened.state == "open"
    assert opened.audit_entry_id is None  # no new proof row on an idempotent retry


@pytest.mark.parametrize("status,category,code,exc", [
    (403, "ConsentError", "consent_not_active", ConsentError),
    (400, "ValidationError", "modality_mismatch", ValidationError),
    (403, "AuthorizationError", "workspace_role_insufficient", AuthorizationError),
])
def test_session_open_failure_modes_raise_typed_errors(status, category, code, exc):
    body = {"error": {"category": category, "code": code, "message": "x"}}
    with _client(_Recorder(status, body)) as client:
        with pytest.raises(exc) as excinfo:
            client.open_session(
                session_id=uuid.uuid4(), workspace_id=uuid.uuid4(), subject_id=uuid.uuid4(),
                consent_record_id=uuid.uuid4(), modality="EEG",
                schema_declaration={"channel_count": 1}, dek_version=0,
            )
        assert excinfo.value.code == code
        assert excinfo.value.http_status == status


# ---------------------------------------------------------------------------
# §9.2 close + §9.3 read.
# ---------------------------------------------------------------------------


def test_session_close_request_and_response_match_vector():
    vec = vector("session_lifecycle", "session_close_001")
    resp_body = vec["expected_output"]["response"]["body"]
    sid = uuid.UUID(resp_body["session_id"])
    rec = _Recorder(200, resp_body)

    with _client(rec) as client:
        closed = client.close_session(sid)

    assert rec.request.method == "POST"
    assert rec.request.url.path == f"/v1/sessions/{sid}/close"
    # client always sends end_state "closed"; "timeout-closed" is cloud-set only (§9.2)
    assert json.loads(rec.request.content) == {"end_state": "closed"}
    assert closed.state == "closed"
    assert closed.total_batches == 0
    assert closed.total_envelope_bytes == 0
    assert closed.audit_entry_id == uuid.UUID(resp_body["audit_entry_id"])


def test_session_read_parses_record():
    # No §9.3 vector (loosely specified); unit-tested. session_id + state are surfaced typed and
    # the full record is preserved in .raw.
    sid = uuid.uuid4()
    record = {"session_id": str(sid), "state": "closed", "opened_at": "2026-05-25T13:00:00Z",
              "closed_at": "2026-05-25T13:30:00Z", "total_batches": 5}
    with _client(_Recorder(200, record)) as client:
        result = client.read_session(sid)
    assert result.session_id == sid
    assert result.state == "closed"
    assert result.raw["total_batches"] == 5


# ---------------------------------------------------------------------------
# §8.1 public-key upload.
# ---------------------------------------------------------------------------


def test_public_key_upload_request_and_response_match_vector():
    vec = vector("wrapped_dek", "member_public_key_upload_shape_001")
    member_id = uuid.UUID(vec["input"]["request"]["path"].split("/")[3])
    resp_body = vec["expected_output"]["response"]["body"]
    rec = _Recorder(200, resp_body)

    pub = os.urandom(32)
    token_hash = os.urandom(32)
    fingerprint = os.urandom(32)
    with _client(rec) as client:
        registered = client.register_public_key(
            member_id, public_key_x25519=pub,
            auth_verification_token_sha256=token_hash, public_key_fingerprint=fingerprint,
        )

    assert rec.request.method == "POST"
    assert rec.request.url.path == f"/v1/members/{member_id}/public-key"
    sent = json.loads(rec.request.content)
    assert sent["public_key_algorithm"] == "X25519"
    # base64url round-trips: the wire values decode back to the exact bytes passed in.
    assert _b64url_decode(sent["public_key_x25519"]) == pub
    assert _b64url_decode(sent["auth_verification_token_sha256"]) == token_hash
    assert _b64url_decode(sent["public_key_fingerprint"]) == fingerprint
    assert registered.member_id == member_id
    assert registered.public_key_version == 1


def test_public_key_upload_carries_no_secret_material():
    # KC (§9.8): only public values on the wire — no private-key seed, master password, or DEK.
    rec = _Recorder(200, {"member_id": str(uuid.uuid4()), "public_key_version": 1,
                          "registered_at": "2026-05-25T13:00:00Z"})
    with _client(rec) as client:
        client.register_public_key(
            uuid.uuid4(), public_key_x25519=os.urandom(32),
            auth_verification_token_sha256=os.urandom(32), public_key_fingerprint=os.urandom(32),
        )
    sent = json.loads(rec.request.content)
    assert set(sent) == {"public_key_x25519", "auth_verification_token_sha256",
                         "public_key_algorithm", "public_key_fingerprint"}
    forbidden = {"private_key", "private_key_seed", "x25519_private_key_seed", "master_password",
                 "password", "dek", "unwrapped_dek", "seed"}
    assert not (set(sent) & forbidden)


# ---------------------------------------------------------------------------
# §8.2 wrapped-DEK upload + §8.3 fetch (incl. empty array) + §8.4 revoke.
# ---------------------------------------------------------------------------


def test_wrapped_dek_upload_request_and_response_match_vector():
    vec = vector("wrapped_dek", "wrapped_dek_upload_shape_001")
    tenant_id = uuid.UUID(vec["input"]["request"]["path"].split("/")[3])
    resp_body = vec["expected_output"]["response"]["body"]
    rec = _Recorder(200, resp_body)

    envelope, _ = _real_wrap_envelope()  # a genuine 76-byte §6.3 envelope (C3 crypto, unchanged)
    for_member = uuid.UUID(resp_body["for_member_id"])
    wrapped_by = uuid.uuid4()
    with _client(rec) as client:
        uploaded = client.upload_wrapped_dek(
            tenant_id, for_member_id=for_member, dek_version=1,
            wrapped_dek_envelope=envelope, wrapped_by_member_id=wrapped_by,
        )

    assert rec.request.method == "POST"
    assert rec.request.url.path == f"/v1/tenants/{tenant_id}/wrapped-deks"
    sent = json.loads(rec.request.content)
    assert _b64url_decode(sent["wrapped_dek_envelope"]) == envelope  # 76 bytes survive the wire
    assert len(envelope) == 76
    assert sent["for_member_id"] == str(for_member)
    assert sent["wrapped_by_member_id"] == str(wrapped_by)
    assert uploaded.wrapped_dek_id == uuid.UUID(resp_body["wrapped_dek_id"])
    assert uploaded.dek_version == 1


def test_wrapped_dek_fetch_current_decodes_envelope_and_unwraps():
    vec = vector("wrapped_dek", "wrapped_dek_fetch_current_shape_001")
    member_id = uuid.UUID(vec["input"]["request"]["path"].split("/")[3])
    # Substitute a REAL base64url envelope (+ matching key) for the vector's placeholder so the
    # decode + a full unwrap round-trip through the HTTP layer is genuinely exercised.
    dek = os.urandom(32)
    priv = X25519PrivateKey.generate()
    envelope = wrap_dek(priv.public_key().public_bytes_raw(), dek)
    resp = {"wrapped_deks": [{"wrapped_dek_id": "018f0c00-0000-7000-8000-000000000010",
                              "dek_version": 1, "wrapped_dek_envelope": _b64url_encode(envelope),
                              "created_at": "2026-05-25T13:00:00Z"}]}
    rec = _Recorder(200, resp)
    with _client(rec) as client:
        records = client.fetch_wrapped_deks(member_id)

    assert rec.request.method == "GET"
    assert rec.request.url.path == f"/v1/members/{member_id}/wrapped-deks"
    assert rec.request.url.query == b""  # no dek_version query when omitted
    assert len(records) == 1
    assert records[0].wrapped_dek_envelope == envelope  # decoded back to the raw 76 bytes
    assert unwrap_dek(records[0].wrapped_dek_envelope, priv.private_bytes_raw()) == dek


def test_wrapped_dek_fetch_with_version_adds_query_param():
    rec = _Recorder(200, {"wrapped_deks": []})
    with _client(rec) as client:
        client.fetch_wrapped_deks(uuid.uuid4(), dek_version=3)
    assert rec.request.url.params["dek_version"] == "3"


def test_wrapped_dek_fetch_empty_array_is_success_not_error():
    vec = vector("wrapped_dek", "wrapped_dek_fetch_empty_shape_001")
    member_id = uuid.UUID(vec["input"]["request"]["path"].split("/")[3])
    resp_body = vec["expected_output"]["response"]["body"]  # {"wrapped_deks": []}
    with _client(_Recorder(200, resp_body)) as client:
        records = client.fetch_wrapped_deks(member_id)
    assert records == []  # empty == "not yet onboarded", a 200 success — RED: treating [] as error


def test_wrapped_dek_revoke_request_and_response_match_vector():
    vec = vector("wrapped_dek", "wrapped_dek_revoke_shape_001")
    wrapped_dek_id = uuid.UUID(vec["input"]["request"]["path"].split("/")[3])
    resp_body = vec["expected_output"]["response"]["body"]
    rec = _Recorder(200, resp_body)
    with _client(rec) as client:
        revoked = client.revoke_wrapped_dek(wrapped_dek_id, reason="member-deactivated")
    assert rec.request.method == "POST"
    assert rec.request.url.path == f"/v1/wrapped-deks/{wrapped_dek_id}/revoke"
    assert json.loads(rec.request.content) == {"reason": "member-deactivated"}
    assert revoked.wrapped_dek_id == wrapped_dek_id
    assert revoked.revoked_at == resp_body["revoked_at"]


def test_revoke_rejects_reason_outside_the_enum():
    assert WRAPPED_DEK_REVOKE_REASONS == frozenset(
        {"member-deactivated", "dek-rotated", "compromised"}
    )
    rec = _Recorder(200, {})
    with _client(rec) as client:
        with pytest.raises(ValueError, match="enum"):
            client.revoke_wrapped_dek(uuid.uuid4(), reason="just-because")
    assert rec.request is None  # rejected client-side; no request sent


# ---------------------------------------------------------------------------
# §10.5 control-plane erasure — erased + idempotent already_erased.
# ---------------------------------------------------------------------------


def test_subject_erase_success_matches_vector():
    vec = vector("control_plane_erasure", "subject_erase_success_001")
    subject_id = uuid.UUID(vec["input"]["request"]["path"].split("/")[3])
    resp_body = vec["expected_output"]["response"]["body"]
    rec = _Recorder(200, resp_body)
    with _client(rec) as client:
        erased = client.erase_subject(subject_id)
    assert rec.request.method == "DELETE"
    assert rec.request.url.path == f"/v1/subjects/{subject_id}"
    assert rec.request.content == b""  # no body
    assert erased.status == "erased"
    assert erased.erased_at == resp_body["erased_at"]
    assert erased.audit_entry_id == uuid.UUID(resp_body["audit_entry_id"])  # the erasure proof


def test_subject_already_erased_is_success_with_no_proof_row():
    vec = vector("control_plane_erasure", "subject_erase_already_erased_001")
    subject_id = uuid.UUID(vec["input"]["request"]["path"].split("/")[3])
    resp_body = vec["expected_output"]["response"]["body"]  # status already_erased, no audit id
    with _client(_Recorder(200, resp_body)) as client:
        result = client.erase_subject(subject_id)
    # RED: treating already_erased as an error, or expecting an audit_entry_id proof row.
    assert isinstance(result, SubjectErased)
    assert result.status == "already_erased"
    assert result.erased_at is None
    assert result.audit_entry_id is None  # no new proof row on idempotent re-erase


# ---------------------------------------------------------------------------
# Transport failure -> NetworkError (§14.2, no HTTP status); async core direct.
# ---------------------------------------------------------------------------


def test_transport_failure_raises_network_error():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with _client(boom) as client:
        with pytest.raises(NetworkError) as excinfo:
            client.erase_subject(uuid.uuid4())
        assert excinfo.value.http_status is None


def test_async_core_directly():
    # Drive the async core via stdlib asyncio.run (no pytest async plugin) — proves async-first.
    import asyncio

    from cephios_core.ingest import bearer

    resp = {"subject_id": str(uuid.uuid4()), "status": "erased",
            "erased_at": "2026-05-31T16:00:00Z",
            "audit_entry_id": "018f0c00-0000-7000-8000-0000000000ce"}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=resp)

    async def go() -> SubjectErased:
        client = AsyncControlClient(
            credential=bearer("t"), transport=httpx.MockTransport(handler)
        )
        try:
            return await client.erase_subject(uuid.UUID(resp["subject_id"]))
        finally:
            await client.aclose()

    result = asyncio.run(go())
    assert result.status == "erased"


def test_version_error_decodes_from_426():
    # A §8/§9 call that hits VersionError 'api_version_unsupported' (426) raises VersionError.
    body = {"error": {"category": "VersionError", "code": "api_version_unsupported"}}
    with _client(_Recorder(426, body)) as client:
        with pytest.raises(VersionError) as excinfo:
            client.read_session(uuid.uuid4())
        assert excinfo.value.http_status == 426


# ---------------------------------------------------------------------------
# #5 base_url https enforcement (with a narrow opt-in) — both clients.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("client_cls", [AsyncControlClient, ControlClient])
def test_base_url_rejects_http_by_default(client_cls):
    # #5: a non-https base_url silently sent the Bearer token in cleartext; now rejected at
    # construction with no opt-in. Covers the async client AND the sync facade.
    with pytest.raises(ValueError, match="must use https"):
        client_cls(credential=bearer("t"), base_url="http://evil.test")


@pytest.mark.parametrize("client_cls", [AsyncControlClient, ControlClient])
def test_base_url_opt_in_never_allows_production_http(client_cls):
    # ABSOLUTE RULE: allow_insecure_http never permits cleartext to the production host.
    with pytest.raises(ValueError, match="production host"):
        client_cls(
            credential=bearer("t"), base_url="http://api.cephios.com", allow_insecure_http=True
        )


def test_base_url_opt_in_allows_non_prod_http_with_warning(caplog):
    # opt-in permits http to a NON-production self-hosted host (§7.1), but NEVER silently.
    with caplog.at_level(logging.WARNING):
        client = ControlClient(
            credential=bearer("t"), base_url="http://localhost:8080", allow_insecure_http=True
        )
    try:
        assert any("insecure http" in r.getMessage().lower() for r in caplog.records)
    finally:
        client.close()


def test_base_url_https_accepted_without_warning(caplog):
    with caplog.at_level(logging.WARNING):
        client = ControlClient(credential=bearer("t"), base_url="https://self-hosted.example.com")
    try:
        assert caplog.records == []
    finally:
        client.close()
