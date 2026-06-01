"""Typed error hierarchy mirroring CONTRACT_SPEC.md §14.

Every error is a :class:`CephiosError` carrying a machine-readable ``category`` (the
§14.2 category name), a machine-readable ``code`` (§14.3), and the category's HTTP
status. ``NetworkError`` is a transport-level condition with no HTTP status
(``http_status`` is ``None``). The hierarchy mirrors §14 exactly (all twelve
categories) per the ratified Group 12 scope (MVP_MAP §4 Group 12).
"""

from __future__ import annotations

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
]


class CephiosError(Exception):
    """Base of the typed error hierarchy (CONTRACT_SPEC.md §14.1).

    Subclasses fix ``category`` (the §14.2 category name) and ``http_status`` (the
    §14.2 status, or ``None`` for transport-level errors). ``code`` is the §14.3
    machine-readable code for the specific condition.
    """

    category: str = "CephiosError"
    http_status: int | None = None

    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message
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
