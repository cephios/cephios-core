"""BufferRejected.reason fixed-vocabulary mapping (CONTRACT_SPEC.md §7.7.3 + §7.7.4).

A pure mapping unit test: each rejection class maps to its exact reason string, unknown
classes (and parse-failure / empty body, modeled as None) fall through to rejected_other,
and the result is ALWAYS one of the closed vocabulary. The load-bearing conformance property
is that the reason is NOT a string-template of the wire code (that would leak server detail
and unbound the set, §7.7.3).
"""

from __future__ import annotations

import pytest

from cephios_core.buffer import (
    REJECTED_BATCH_TOO_LARGE,
    REJECTED_MALFORMED,
    REJECTED_OTHER,
    REJECTED_REASONS,
    REJECTED_VERSION_UNSUPPORTED,
    rejected_reason,
)
from cephios_core.errors import (
    AuthorizationError,
    EnvelopeError,
    InternalError,
    ValidationError,
    VersionError,
)


def test_closed_vocabulary_is_exactly_four():
    assert REJECTED_REASONS == frozenset(
        {
            REJECTED_BATCH_TOO_LARGE,
            REJECTED_MALFORMED,
            REJECTED_VERSION_UNSUPPORTED,
            REJECTED_OTHER,
        }
    )


# (CephiosError instance, expected reason) — the §7.7.3 normative table.
# RED-CAPABLE: any wrong arrow in the production _REJECTION_REASON_MAP flips one of these.
_MAPPING = [
    (ValidationError("batch_too_large"), REJECTED_BATCH_TOO_LARGE),
    (EnvelopeError("malformed"), REJECTED_MALFORMED),
    (VersionError("envelope_version_unsupported"), REJECTED_VERSION_UNSUPPORTED),
    # "any other non-retryable code" -> rejected_other
    (ValidationError("consent_required"), REJECTED_OTHER),
    (AuthorizationError("tenant_mismatch"), REJECTED_OTHER),
    (InternalError("unexpected"), REJECTED_OTHER),
    # A code that belongs to a DIFFERENT category must NOT alias (keyed on (category, code)):
    (VersionError("malformed"), REJECTED_OTHER),
    (ValidationError("envelope_version_unsupported"), REJECTED_OTHER),
]


@pytest.mark.parametrize("error,expected", _MAPPING)
def test_rejected_reason_mapping(error, expected):
    assert rejected_reason(error) == expected


def test_none_maps_to_rejected_other():
    # Parse failure / empty body (no parseable CephiosError) -> rejected_other (§7.7.3).
    assert rejected_reason(None) == REJECTED_OTHER


def test_result_is_always_in_the_closed_set():
    for error, _ in _MAPPING:
        assert rejected_reason(error) in REJECTED_REASONS
    assert rejected_reason(None) in REJECTED_REASONS


def test_reason_is_not_a_templated_wire_code():
    # The reason MUST NOT be constructed by string-templating the wire code
    # ("rejected_" + code), which would produce "rejected_consent_required" etc.
    assert rejected_reason(ValidationError("consent_required")) == REJECTED_OTHER
    assert rejected_reason(ValidationError("consent_required")) != "rejected_consent_required"
