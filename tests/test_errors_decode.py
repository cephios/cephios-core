"""Full §14.2 twelve-category error decode (CONTRACT_SPEC.md §14.1–§14.3) — Commit 5b.

Two proof tiers:

1. The 9 published ``error_taxonomy`` vectors: each ``(category, code, http_status)`` tuple
   round-trips — a synthesized §14.1 envelope decodes to the right typed class whose
   ``http_status`` matches the vector. (Q-C2: the vector documents the typed-error RESPONSE
   shape; we construct the §14.1 envelope and decode it — no live round-trip.)

2. cephios-core's OWN unit tests for ALL twelve §14.2 categories. The go-bericht names three
   vector-less categories (NetworkError / IdempotencyError / InternalError, the Q-NEW-1 gap);
   verifying against the live error_taxonomy.json shows the gap is actually SIX categories —
   additionally AuthenticationError (401), NotOperationalError (501), KeyManagementError (422)
   have no vector either (the 9 tuples cover only Validation/Envelope/Version/Buffer/Consent/
   Authorization). All six vector-less categories are proven here by unit test. (Flagged in the
   commit body as a §11.1 / §17.4 catch: the go-bericht's "3" undercounts the live vector set.)
"""

from __future__ import annotations

import json

import pytest

from cephios_core.buffer import rejected_reason
from cephios_core.errors import (
    ERROR_CATEGORIES,
    AuthenticationError,
    BufferError,
    CephiosError,
    ConsentError,
    IdempotencyError,
    InternalError,
    KeyManagementError,
    NetworkError,
    NotOperationalError,
    ValidationError,
    VersionError,
    decode_error,
    decode_error_response,
    error_class_for_status,
)
from vector_loader import load_category


def _envelope(category: str, code: str, **extra: object) -> bytes:
    return json.dumps({"error": {"category": category, "code": code, **extra}}).encode()


# ---------------------------------------------------------------------------
# Tier 1 — the 9 published error_taxonomy tuples.
# ---------------------------------------------------------------------------

_TAXONOMY = load_category("error_taxonomy")
_TUPLES = [
    pytest.param(
        v["expected_output"]["error"]["category"],
        v["expected_output"]["error"]["code"],
        v["expected_output"]["error"]["http_status"],
        id=v["test_id"],
    )
    for v in _TAXONOMY
]


def test_error_taxonomy_vector_count():
    assert len(_TAXONOMY) == 9  # the published v1.0 error_taxonomy set


@pytest.mark.parametrize("category,code,http_status", _TUPLES)
def test_taxonomy_tuple_round_trips(category, code, http_status):
    # Decode a §14.1 envelope synthesized from the vector's (category, code) and assert the typed
    # class + its §14.2 http_status match the vector. RED-CAPABLE: a wrong category->class map or
    # a wrong http_status on the class flips this.
    decoded = decode_error(_envelope(category, code))
    assert decoded is not None
    assert type(decoded).__name__ == category
    assert decoded.category == category
    assert decoded.code == code
    assert decoded.http_status == http_status
    # decode_error_response (status-aware) yields the same typed class when the body is present.
    via_response = decode_error_response(http_status, _envelope(category, code))
    assert type(via_response) is type(decoded)
    assert via_response.code == code


# ---------------------------------------------------------------------------
# Tier 2 — all twelve §14.2 categories decode to the right class (covers the vector-less six).
# ---------------------------------------------------------------------------

# The six categories with NO error_taxonomy vector — proven only by these unit tests.
_VECTORLESS = {
    "AuthenticationError",
    "NotOperationalError",
    "NetworkError",
    "IdempotencyError",
    "KeyManagementError",
    "InternalError",
}


@pytest.mark.parametrize("category", sorted(ERROR_CATEGORIES))
def test_every_category_decodes_to_its_typed_class(category):
    cls = ERROR_CATEGORIES[category]
    decoded = decode_error(_envelope(category, "some_code"))
    assert decoded is not None
    assert type(decoded) is cls
    assert decoded.category == category
    assert decoded.code == "some_code"
    assert decoded.http_status == cls.http_status


def test_all_twelve_categories_present():
    assert len(ERROR_CATEGORIES) == 12  # the full §14.2 set


def test_vectorless_categories_are_exactly_the_six_unvectored():
    # Pin the gap explicitly: the categories NOT covered by an error_taxonomy vector.
    vectored = {v["expected_output"]["error"]["category"] for v in _TAXONOMY}
    assert set(ERROR_CATEGORIES) - vectored == _VECTORLESS


@pytest.mark.parametrize("cls,status", [
    (AuthenticationError, 401),
    (NotOperationalError, 501),
    (IdempotencyError, 409),
    (KeyManagementError, 422),
    (InternalError, 500),
])
def test_vectorless_http_statuses(cls, status):
    # The §14.2 statuses for the categories with no vector (NetworkError handled separately).
    assert cls.http_status == status
    decoded = decode_error(_envelope(cls.category, "c"))
    assert decoded is not None and decoded.http_status == status


def test_network_error_is_transport_level_no_status():
    # NetworkError (§14.2) is transport-level: no HTTP status. The control client raises it on a
    # transport failure (proven in test_control); here we pin the taxonomy property.
    assert NetworkError.http_status is None
    decoded = decode_error(_envelope("NetworkError", "transport_failure"))
    assert isinstance(decoded, NetworkError)
    assert decoded.http_status is None


# ---------------------------------------------------------------------------
# §14.1 fields, unparseable handling, status fallback, rejected_reason compatibility.
# ---------------------------------------------------------------------------


def test_decode_carries_details_and_request_id():
    body = _envelope(
        "AuthenticationError", "session_expired",
        message="re-authenticate", details={"expired_at": "2026-06-01T00:00:00Z"},
        request_id="018f0c00-0000-7000-8000-0000000000ff",
    )
    decoded = decode_error(body)
    assert isinstance(decoded, AuthenticationError)
    assert decoded.message == "re-authenticate"
    assert decoded.details == {"expired_at": "2026-06-01T00:00:00Z"}
    assert decoded.request_id == "018f0c00-0000-7000-8000-0000000000ff"


@pytest.mark.parametrize("body", [
    b"", b"not json", b'{"no_error": 1}', b'{"error": {"code": "x"}}',
    b'{"error": {"category": "ValidationError"}}', b'{"error": {"category": "Nope", "code": "x"}}',
])
def test_decode_error_returns_none_on_unparseable(body):
    assert decode_error(body) is None


def test_decode_error_response_falls_back_to_status_when_body_unparseable():
    # A non-2xx with no decodable §14.1 envelope still yields a typed error keyed on the status.
    assert isinstance(decode_error_response(409, b""), IdempotencyError)
    assert isinstance(decode_error_response(500, b"<html>oops</html>"), InternalError)
    assert isinstance(decode_error_response(401, b"nope"), AuthenticationError)
    # An unmapped status degrades to InternalError (never None, never untyped).
    assert isinstance(decode_error_response(418, b""), InternalError)


def test_decode_error_response_prefers_body_over_status():
    # A present §14.1 envelope wins over the status guess (status 500 body says ConsentError).
    decoded = decode_error_response(500, _envelope("ConsentError", "consent_revoked"))
    assert isinstance(decoded, ConsentError)
    assert decoded.code == "consent_revoked"


def test_error_class_for_status_ambiguous_400_403():
    # 400 + 403 are each shared by two categories; the fallback picks the general one.
    assert error_class_for_status(400) is ValidationError
    assert error_class_for_status(429) is BufferError
    assert error_class_for_status(426) is VersionError
    assert error_class_for_status(418) is None  # unmapped


def test_rejected_reason_still_works_on_decoded_error():
    # The Commit 5a uploader call site: decode_error -> rejected_reason must still map correctly.
    decoded = decode_error(_envelope("ValidationError", "batch_too_large"))
    assert isinstance(decoded, ValidationError)
    assert rejected_reason(decoded) == "rejected_batch_too_large"
    # An unparseable body -> None -> rejected_other (unchanged from C5a).
    assert rejected_reason(decode_error(b"garbage")) == "rejected_other"


def test_decoded_error_is_a_cephios_error():
    decoded = decode_error(_envelope("VersionError", "api_version_unsupported"))
    assert isinstance(decoded, CephiosError)
