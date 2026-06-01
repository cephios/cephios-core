"""Typed error taxonomy: vectors + the full §14.2 twelve-category mapping (CS §14)."""

from __future__ import annotations

from cephios_core.errors import (
    ERROR_CATEGORIES,
    AuthenticationError,
    AuthorizationError,
    BufferError,
    ConsentError,
    EnvelopeError,
    IdempotencyError,
    InternalError,
    KeyManagementError,
    NetworkError,
    NotOperationalError,
    ValidationError,
    VersionError,
)
from vector_loader import load_category

# CONTRACT_SPEC.md §14.2 — the full twelve-category status mapping (None = transport-level).
_EXPECTED_14_2 = {
    AuthenticationError: 401,
    AuthorizationError: 403,
    ConsentError: 403,
    ValidationError: 400,
    EnvelopeError: 400,
    NotOperationalError: 501,
    BufferError: 429,
    NetworkError: None,
    IdempotencyError: 409,
    KeyManagementError: 422,
    VersionError: 426,
    InternalError: 500,
}


def test_all_twelve_categories_present_with_correct_status():
    assert len(_EXPECTED_14_2) == 12
    for cls, status in _EXPECTED_14_2.items():
        assert cls.http_status == status
        assert ERROR_CATEGORIES[cls.category] is cls


def test_error_taxonomy_vectors_match():
    for v in load_category("error_taxonomy"):
        err = v["expected_output"]["error"]
        cls = ERROR_CATEGORIES[err["category"]]
        assert cls.http_status == err["http_status"]
        instance = cls(err["code"])
        assert instance.category == err["category"]
        assert instance.code == err["code"]
        assert instance.http_status == err["http_status"]
