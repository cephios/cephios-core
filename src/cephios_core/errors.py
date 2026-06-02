"""Typed error hierarchy + the §14 wire decoder (CONTRACT_SPEC.md §14).

Every error is a :class:`CephiosError` carrying a machine-readable ``category`` (the
§14.2 category name), a machine-readable ``code`` (§14.3), the category's HTTP status, and
the optional §14.1 ``details`` / ``request_id`` context. ``NetworkError`` is a transport-level
condition with no HTTP status (``http_status`` is ``None``). The hierarchy mirrors §14 exactly
(all twelve categories) per the ratified Group 12 scope (MVP_MAP §4 Group 12).

:func:`decode_error` / :func:`decode_error_response` are the FULL §14.1 envelope decoder for
all twelve §14.2 categories (Commit 5b). They replace Commit 5a's minimal ``(category, code)``
decode that lived in ``ingest`` and fed :func:`cephios_core.buffer.rejected_reason`; that call
site is unchanged (``rejected_reason`` still reads ``.category`` / ``.code`` off the decoded
error) and ``ingest`` re-exports :func:`decode_error` for backward compatibility. Locating the
decoder with the taxonomy it decodes keeps "mirrors §14 exactly" a single-module IS property.
"""

from __future__ import annotations

import json

__all__ = [
    "CephiosError",
    "AuthenticationError",
    "AuthorizationError",
    "ConsentError",
    "ValidationError",
    "EnvelopeError",
    "NotOperationalError",
    "BufferError",
    "NetworkError",
    "IdempotencyError",
    "KeyManagementError",
    "VersionError",
    "InternalError",
    "ERROR_CATEGORIES",
    "decode_error",
    "decode_error_response",
    "error_class_for_status",
]


class CephiosError(Exception):
    """Base of the typed error hierarchy (CONTRACT_SPEC.md §14.1).

    Subclasses fix ``category`` (the §14.2 category name) and ``http_status`` (the
    §14.2 status, or ``None`` for transport-level errors). ``code`` is the §14.3
    machine-readable code for the specific condition.
    """

    category: str = "CephiosError"
    http_status: int | None = None

    def __init__(
        self,
        code: str,
        message: str = "",
        *,
        details: dict[str, object] | None = None,
        request_id: str | None = None,
    ) -> None:
        self.code = code
        self.message = message
        #: The §14.1 ``details`` object (category-specific context), or ``None``.
        self.details = details
        #: The §14.1 ``request_id`` (UUIDv7 for support correlation), or ``None``.
        self.request_id = request_id
        detail = f": {message}" if message else ""
        super().__init__(f"{self.category} '{code}'{detail}")


class AuthenticationError(CephiosError):
    category = "AuthenticationError"
    http_status = 401


class AuthorizationError(CephiosError):
    category = "AuthorizationError"
    http_status = 403


class ConsentError(CephiosError):
    category = "ConsentError"
    http_status = 403


class ValidationError(CephiosError):
    category = "ValidationError"
    http_status = 400


class EnvelopeError(CephiosError):
    category = "EnvelopeError"
    http_status = 400


class NotOperationalError(CephiosError):
    category = "NotOperationalError"
    http_status = 501


class BufferError(CephiosError):  # noqa: A001 (shadows builtin; this is the §14.2 wire category)
    category = "BufferError"
    http_status = 429


class NetworkError(CephiosError):
    category = "NetworkError"
    http_status = None  # transport-level (CONTRACT_SPEC.md §14.2)


class IdempotencyError(CephiosError):
    category = "IdempotencyError"
    http_status = 409


class KeyManagementError(CephiosError):
    category = "KeyManagementError"
    http_status = 422


class VersionError(CephiosError):
    category = "VersionError"
    http_status = 426


class InternalError(CephiosError):
    category = "InternalError"
    http_status = 500


# Category name -> error class, for taxonomy lookup (CONTRACT_SPEC.md §14.2).
ERROR_CATEGORIES: dict[str, type[CephiosError]] = {
    cls.category: cls
    for cls in (
        AuthenticationError,
        AuthorizationError,
        ConsentError,
        ValidationError,
        EnvelopeError,
        NotOperationalError,
        BufferError,
        NetworkError,
        IdempotencyError,
        KeyManagementError,
        VersionError,
        InternalError,
    )
}


# ---------------------------------------------------------------------------
# §14.1 wire decoder — the full twelve-category decode (Commit 5b).
# ---------------------------------------------------------------------------

# §14.2 representative class per HTTP status, for the body-unparseable fallback. HTTP 400
# (EnvelopeError + ValidationError) and 403 (ConsentError + AuthorizationError) are each shared
# by two categories; the §14.1 body normally disambiguates, so when there is no decodable body
# the fallback picks the more general category for that bare status. Transport-level NetworkError
# (no HTTP status) is NOT in this map — it is raised by the client on a transport failure, never
# decoded from a status (§14.2).
_STATUS_FALLBACK: dict[int, type[CephiosError]] = {
    400: ValidationError,
    401: AuthenticationError,
    403: AuthorizationError,
    409: IdempotencyError,
    422: KeyManagementError,
    426: VersionError,
    429: BufferError,
    500: InternalError,
    501: NotOperationalError,
}


def error_class_for_status(status_code: int) -> type[CephiosError] | None:
    """The representative §14.2 :class:`CephiosError` subclass for an HTTP status, or ``None``.

    Used only for the body-unparseable fallback in :func:`decode_error_response`; a present
    §14.1 envelope (``category``) always wins over this status-based guess (400 / 403 are
    ambiguous by status alone — see :data:`_STATUS_FALLBACK`).
    """
    return _STATUS_FALLBACK.get(status_code)


def decode_error(body: bytes | str) -> CephiosError | None:
    """Decode a §14.1 error envelope into its typed :class:`CephiosError`, or ``None``.

    Parses ``{"error": {"category", "code", "message"?, "details"?, "request_id"?}}`` (§14.1),
    maps ``category`` to its subclass via :data:`ERROR_CATEGORIES` (all twelve §14.2
    categories), and constructs the typed error carrying ``code`` + the optional ``message`` /
    ``details`` / ``request_id`` context. The constructed class fixes the §14.2 HTTP status.

    Returns ``None`` on ANY decode failure (not JSON, missing ``error`` / ``category`` /
    ``code``, unknown category, empty body). :func:`cephios_core.buffer.rejected_reason` maps a
    ``None`` to ``rejected_other`` (the §7.7.3 "parse failure or empty body" row), so the
    Commit 5a uploader call site is unchanged.
    """
    try:
        doc = json.loads(body)
        err = doc["error"]
        category = err["category"]
        code = err["code"]
    except (ValueError, KeyError, TypeError):
        return None
    cls = ERROR_CATEGORIES.get(category)
    if cls is None or not isinstance(err, dict):
        return None
    message = err.get("message", "")
    details = err.get("details")
    request_id = err.get("request_id")
    return cls(
        code,
        message if isinstance(message, str) else "",
        details=details if isinstance(details, dict) else None,
        request_id=request_id if isinstance(request_id, str) else None,
    )


def decode_error_response(status_code: int, body: bytes | str) -> CephiosError:
    """Full §14 decode of a non-2xx HTTP response into a typed :class:`CephiosError`.

    Prefers the §14.1 body envelope (:func:`decode_error`); if the body is absent or
    unparseable, falls back to a typed error keyed on the HTTP status (§14.2,
    :func:`error_class_for_status`). ALWAYS returns a typed error (never ``None``) — the
    control-plane / session / wrapped-DEK clients raise it directly, so a non-2xx never escapes
    as an untyped HTTP error. A status with no §14.2 mapping degrades to :class:`InternalError`.
    """
    decoded = decode_error(body)
    if decoded is not None:
        return decoded
    cls = _STATUS_FALLBACK.get(status_code, InternalError)
    return cls(
        "unparseable_error_body",
        f"HTTP {status_code} carried no decodable §14.1 error envelope",
    )
