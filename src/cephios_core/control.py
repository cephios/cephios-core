"""Control-plane + key-management wire surface (CONTRACT_SPEC.md §8, §9, §10.5).

The JSON, non-data-path counterpart to the §7 binary ingest client. It reuses the Commit 5a
transport primitives (the ``_AsyncBridge`` event-loop thread, the ``Credential`` /
``Authorization`` header, ``X-Cephios-API-Version`` pinned to the wire ``1.1``, httpx with its
default certificate verification) and layers the §8 / §9 / §10.5 request shapes + typed response
decoding on top. Async-first + sync facade, exactly as Commit 5a: :class:`AsyncControlClient` is
the real implementation; :class:`ControlClient` runs it on the private loop thread.

Surfaces:

- §9 sessions: open (idempotent on the client-generated ``session_id``), close (client always
  sends ``end_state: "closed"`` — ``timeout-closed`` is cloud-set only), metadata read.
- §8 wrapped-DEK distribution: §8.1 public-key upload, §8.2 wrapped-DEK upload, §8.3 fetch
  (the empty-array "not yet onboarded" case is a 200 success, NOT an error), §8.4 revoke. The
  32-byte / 76-byte values are base64url on the wire (:func:`_b64url_encode` /
  :func:`_b64url_decode`); the 76-byte envelope is C3's ``wrapped_dek`` crypto, carried opaque.
- §10.5 control-plane erasure: subject DELETE; ``erased`` and the idempotent ``already_erased``
  re-erase both parse as success (the latter carries no new proof row).

A non-2xx response is decoded into the correct typed :class:`~cephios_core.errors.CephiosError`
via the full §14 decoder (``decode_error_response``) and raised; a transport-level failure
raises :class:`~cephios_core.errors.NetworkError` (§14.2, no HTTP status).

Standing invariants (CLAUDE.md §9):

- KC / Model C (§9.8): the §8 flow carries ONLY public values — the X25519 public key, the
  SHA-256 of the auth-verification token, the public-key fingerprint, and the already-wrapped
  (encrypted) DEK envelope. It NEVER carries the master password, the private-key seed, or an
  unwrapped DEK. The 76-byte envelope is C3's ``wrapped_dek`` output, unchanged (ET).
- IS (§9.6): the public client surface + typed results mirror §8 / §9 / §10.5; the full
  twelve-category §14 decode (in ``errors``) is the ratified IS bar. Exports are deliberate.
- KC / TLS: certificate verification stays httpx-default; never disabled.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Final
from uuid import UUID

import httpx

from cephios_core.errors import NetworkError, decode_error_response
from cephios_core.ingest import (
    DEFAULT_BASE_URL,
    HEADER_API_VERSION,
    WIRE_API_VERSION,
    Credential,
    _AsyncBridge,
    _validate_base_url,
)

__all__ = [
    "WRAPPED_DEK_REVOKE_REASONS",
    "CLIENT_CLOSE_END_STATE",
    "SessionOpened",
    "SessionClosed",
    "SessionRecord",
    "PublicKeyRegistered",
    "WrappedDekUploaded",
    "WrappedDekRecord",
    "WrappedDekRevoked",
    "SubjectErased",
    "AsyncControlClient",
    "ControlClient",
]

#: §8.4 revoke reason — the closed enumeration. The client rejects anything else before sending.
WRAPPED_DEK_REVOKE_REASONS: Final[frozenset[str]] = frozenset(
    {"member-deactivated", "dek-rotated", "compromised"}
)

#: §9.2 client-initiated close always sends this end_state. The cloud sets "timeout-closed" via
#: the inactivity sweep; a conforming client never sends that value (§9.2).
CLIENT_CLOSE_END_STATE: Final = "closed"

_JSON_CONTENT_TYPE: Final = "application/json"


# ---------------------------------------------------------------------------
# base64url (§8 32-byte / 76-byte values).
# ---------------------------------------------------------------------------


def _b64url_encode(raw: bytes) -> str:
    """Encode bytes as unpadded base64url (the URL-safe, RFC 4648 §5 / JOSE convention).

    Padding is stripped on encode and re-added tolerantly on decode (:func:`_b64url_decode`),
    so the round-trip is padding-agnostic — the classic cross-implementation base64url pitfall.
    The v1.0 §8 vectors carry placeholder values (not real base64), so the exact padding the
    live server emits is not pinned by a vector; unpadded-encode + tolerant-decode interoperates
    with both styles. (Flagged: the one knob to flip if the server proves to require padding.)
    """
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    """Decode a base64url string, tolerating missing ``=`` padding."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


# ---------------------------------------------------------------------------
# Typed responses (§8 / §9 / §10.5 documented shapes).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SessionOpened:
    """§9.1 open response. ``idempotent`` is ``True`` for the retry of an already-open session
    (which carries no ``audit_entry_id``); a fresh open carries the open-event proof row id."""

    session_id: UUID
    state: str
    opened_at: str
    audit_entry_id: UUID | None
    idempotent: bool

    @classmethod
    def _parse(cls, doc: Mapping[str, Any]) -> SessionOpened:
        audit = doc.get("audit_entry_id")
        return cls(
            session_id=UUID(doc["session_id"]),
            state=doc["state"],
            opened_at=doc["opened_at"],
            audit_entry_id=UUID(audit) if audit else None,
            idempotent=bool(doc.get("idempotent", False)),
        )


@dataclass(frozen=True, slots=True)
class SessionClosed:
    """§9.2 close response (aggregated batch / byte counts + the close-event proof row id)."""

    session_id: UUID
    state: str
    closed_at: str
    total_batches: int
    total_envelope_bytes: int
    audit_entry_id: UUID

    @classmethod
    def _parse(cls, doc: Mapping[str, Any]) -> SessionClosed:
        return cls(
            session_id=UUID(doc["session_id"]),
            state=doc["state"],
            closed_at=doc["closed_at"],
            total_batches=int(doc["total_batches"]),
            total_envelope_bytes=int(doc["total_envelope_bytes"]),
            audit_entry_id=UUID(doc["audit_entry_id"]),
        )


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """§9.3 metadata read. The §9.3 record is loosely specified ("state, timestamps, byte
    counts, audit history references") and has no v1.0 vector, so ``session_id`` + ``state`` are
    surfaced typed and the complete record is kept in ``raw`` for the caller."""

    session_id: UUID
    state: str
    raw: Mapping[str, Any]

    @classmethod
    def _parse(cls, doc: Mapping[str, Any]) -> SessionRecord:
        return cls(session_id=UUID(doc["session_id"]), state=doc["state"], raw=doc)


@dataclass(frozen=True, slots=True)
class PublicKeyRegistered:
    """§8.1 public-key upload response."""

    member_id: UUID
    public_key_version: int
    registered_at: str

    @classmethod
    def _parse(cls, doc: Mapping[str, Any]) -> PublicKeyRegistered:
        return cls(
            member_id=UUID(doc["member_id"]),
            public_key_version=int(doc["public_key_version"]),
            registered_at=doc["registered_at"],
        )


@dataclass(frozen=True, slots=True)
class WrappedDekUploaded:
    """§8.2 wrapped-DEK upload response (note: audit_entry_id is NOT in the body, Q-G6-10)."""

    wrapped_dek_id: UUID
    for_member_id: UUID
    dek_version: int
    created_at: str

    @classmethod
    def _parse(cls, doc: Mapping[str, Any]) -> WrappedDekUploaded:
        return cls(
            wrapped_dek_id=UUID(doc["wrapped_dek_id"]),
            for_member_id=UUID(doc["for_member_id"]),
            dek_version=int(doc["dek_version"]),
            created_at=doc["created_at"],
        )


@dataclass(frozen=True, slots=True)
class WrappedDekRecord:
    """§8.3 fetch list element. ``wrapped_dek_envelope`` is decoded from base64url to the raw
    76-byte §6.3 envelope (C3 ``wrapped_dek.unwrap_dek`` consumes it; this layer is wire-only)."""

    wrapped_dek_id: UUID
    dek_version: int
    wrapped_dek_envelope: bytes
    created_at: str

    @classmethod
    def _parse(cls, doc: Mapping[str, Any]) -> WrappedDekRecord:
        return cls(
            wrapped_dek_id=UUID(doc["wrapped_dek_id"]),
            dek_version=int(doc["dek_version"]),
            wrapped_dek_envelope=_b64url_decode(doc["wrapped_dek_envelope"]),
            created_at=doc["created_at"],
        )


@dataclass(frozen=True, slots=True)
class WrappedDekRevoked:
    """§8.4 revoke response (the row is retained for audit; revoked_at is set, never deleted)."""

    wrapped_dek_id: UUID
    revoked_at: str

    @classmethod
    def _parse(cls, doc: Mapping[str, Any]) -> WrappedDekRevoked:
        return cls(wrapped_dek_id=UUID(doc["wrapped_dek_id"]), revoked_at=doc["revoked_at"])


@dataclass(frozen=True, slots=True)
class SubjectErased:
    """§10.5 erasure response. ``status`` is ``"erased"`` (carries ``erased_at`` + the
    ``subjects.erased`` proof-row ``audit_entry_id``) or the idempotent ``"already_erased"``
    (carries neither — no new proof row is written on re-erasure)."""

    subject_id: UUID
    status: str
    erased_at: str | None
    audit_entry_id: UUID | None

    @classmethod
    def _parse(cls, doc: Mapping[str, Any]) -> SubjectErased:
        audit = doc.get("audit_entry_id")
        return cls(
            subject_id=UUID(doc["subject_id"]),
            status=doc["status"],
            erased_at=doc.get("erased_at"),
            audit_entry_id=UUID(audit) if audit else None,
        )


# ---------------------------------------------------------------------------
# The async core.
# ---------------------------------------------------------------------------


class AsyncControlClient:
    """Async §8 / §9 / §10.5 client. The real implementation; :class:`ControlClient` is the
    synchronous facade. ``transport`` injects an ``httpx.MockTransport`` for offline tests."""

    def __init__(
        self,
        *,
        credential: Credential,
        base_url: str = DEFAULT_BASE_URL,
        api_version: str = WIRE_API_VERSION,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 30.0,
        allow_insecure_http: bool = False,
    ) -> None:
        _validate_base_url(base_url, allow_insecure_http)
        self._credential = credential
        self._api_version = api_version
        self._client = httpx.AsyncClient(
            base_url=base_url,
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """Send one control-plane request and return the parsed 2xx JSON body. On a non-2xx the
        full §14 decoder maps the response to its typed CephiosError, which is raised; a
        transport-level failure raises NetworkError (§14.2, no HTTP status)."""
        # X-Cephios-API-Version is sent on EVERY request (§15.1). The §8/§9/§10.5 SHAPE vectors
        # list only Content-Type + Authorization, but their header sets are non-exhaustive (as
        # the §7 ingest vector omitted Authorization); §15.1 mandates the version header.
        headers = {
            HEADER_API_VERSION: self._api_version,
            "Authorization": self._credential.header_value(),
        }
        content: bytes | None = None
        if json_body is not None:
            content = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = _JSON_CONTENT_TYPE
        try:
            response = await self._client.request(
                method, path, content=content, params=params, headers=headers
            )
        except httpx.TransportError as exc:
            raise NetworkError("transport_failure", str(exc)) from exc
        if 200 <= response.status_code < 300:
            return response.json()
        raise decode_error_response(response.status_code, response.content)

    # -- §9 sessions -------------------------------------------------------

    async def open_session(
        self,
        *,
        session_id: UUID,
        workspace_id: UUID,
        subject_id: UUID,
        consent_record_id: UUID,
        modality: str,
        schema_declaration: Mapping[str, Any],
        dek_version: int,
    ) -> SessionOpened:
        """§9.1 POST /v1/sessions. Idempotent on the client-generated ``session_id``: a retry
        returns the existing session (``idempotent: true``), not a new/failed open."""
        body = {
            "session_id": str(session_id),
            "workspace_id": str(workspace_id),
            "subject_id": str(subject_id),
            "consent_record_id": str(consent_record_id),
            "modality": modality,
            "schema_declaration": dict(schema_declaration),
            "dek_version": dek_version,
        }
        return SessionOpened._parse(await self._request("POST", "/v1/sessions", json_body=body))

    async def close_session(self, session_id: UUID) -> SessionClosed:
        """§9.2 POST /v1/sessions/{id}/close with ``end_state: "closed"`` (client-initiated)."""
        body = {"end_state": CLIENT_CLOSE_END_STATE}
        path = f"/v1/sessions/{session_id}/close"
        return SessionClosed._parse(await self._request("POST", path, json_body=body))

    async def read_session(self, session_id: UUID) -> SessionRecord:
        """§9.3 GET /v1/sessions/{id}."""
        return SessionRecord._parse(await self._request("GET", f"/v1/sessions/{session_id}"))

    # -- §8 wrapped-DEK distribution ---------------------------------------

    async def register_public_key(
        self,
        member_id: UUID,
        *,
        public_key_x25519: bytes,
        auth_verification_token_sha256: bytes,
        public_key_fingerprint: bytes,
    ) -> PublicKeyRegistered:
        """§8.1 POST /v1/members/{id}/public-key. Carries only public values, base64url-encoded
        (KC: no private-key seed, no password)."""
        body = {
            "public_key_x25519": _b64url_encode(public_key_x25519),
            "auth_verification_token_sha256": _b64url_encode(auth_verification_token_sha256),
            "public_key_algorithm": "X25519",
            "public_key_fingerprint": _b64url_encode(public_key_fingerprint),
        }
        path = f"/v1/members/{member_id}/public-key"
        return PublicKeyRegistered._parse(await self._request("POST", path, json_body=body))

    async def upload_wrapped_dek(
        self,
        tenant_id: UUID,
        *,
        for_member_id: UUID,
        dek_version: int,
        wrapped_dek_envelope: bytes,
        wrapped_by_member_id: UUID,
    ) -> WrappedDekUploaded:
        """§8.2 POST /v1/tenants/{id}/wrapped-deks. ``wrapped_dek_envelope`` is the C3 §6.3
        76-byte envelope, base64url-encoded (KC: the DEK is already wrapped — never plaintext)."""
        body = {
            "for_member_id": str(for_member_id),
            "dek_version": dek_version,
            "wrapped_dek_envelope": _b64url_encode(wrapped_dek_envelope),
            "wrapped_by_member_id": str(wrapped_by_member_id),
        }
        path = f"/v1/tenants/{tenant_id}/wrapped-deks"
        return WrappedDekUploaded._parse(await self._request("POST", path, json_body=body))

    async def fetch_wrapped_deks(
        self, member_id: UUID, *, dek_version: int | None = None
    ) -> list[WrappedDekRecord]:
        """§8.3 GET /v1/members/{id}/wrapped-deks[?dek_version=v]. An empty list is a SUCCESS —
        the member exists but is not yet onboarded with crypto access — NOT an error."""
        params = {"dek_version": dek_version} if dek_version is not None else None
        doc = await self._request("GET", f"/v1/members/{member_id}/wrapped-deks", params=params)
        return [WrappedDekRecord._parse(item) for item in doc["wrapped_deks"]]

    async def revoke_wrapped_dek(self, wrapped_dek_id: UUID, *, reason: str) -> WrappedDekRevoked:
        """§8.4 POST /v1/wrapped-deks/{id}/revoke. ``reason`` MUST be one of
        :data:`WRAPPED_DEK_REVOKE_REASONS` — rejected client-side otherwise."""
        if reason not in WRAPPED_DEK_REVOKE_REASONS:
            raise ValueError(
                f"reason {reason!r} not in the §8.4 enum {sorted(WRAPPED_DEK_REVOKE_REASONS)}"
            )
        path = f"/v1/wrapped-deks/{wrapped_dek_id}/revoke"
        return WrappedDekRevoked._parse(
            await self._request("POST", path, json_body={"reason": reason})
        )

    # -- §10.5 control-plane erasure ---------------------------------------

    async def erase_subject(self, subject_id: UUID) -> SubjectErased:
        """§10.5 DELETE /v1/subjects/{id}. ``erased`` and the idempotent ``already_erased`` both
        return 200 success; the tenant is taken from the session context, never the request."""
        return SubjectErased._parse(await self._request("DELETE", f"/v1/subjects/{subject_id}"))

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# The synchronous facade.
# ---------------------------------------------------------------------------


class ControlClient:
    """Synchronous facade over :class:`AsyncControlClient` (the application-facing surface).

    Each method runs the async request on the reused Commit 5a ``_AsyncBridge`` loop thread and
    blocks for the typed result. Usable as a context manager; :meth:`close` releases the pool +
    the loop thread."""

    def __init__(
        self,
        *,
        credential: Credential,
        base_url: str = DEFAULT_BASE_URL,
        api_version: str = WIRE_API_VERSION,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 30.0,
        allow_insecure_http: bool = False,
    ) -> None:
        # Construct (and validate base_url via) the async client FIRST, so a rejected base_url
        # raises before the _AsyncBridge loop thread starts — no orphaned daemon thread.
        self._async = AsyncControlClient(
            credential=credential,
            base_url=base_url,
            api_version=api_version,
            transport=transport,
            timeout=timeout,
            allow_insecure_http=allow_insecure_http,
        )
        self._bridge = _AsyncBridge()

    def open_session(
        self,
        *,
        session_id: UUID,
        workspace_id: UUID,
        subject_id: UUID,
        consent_record_id: UUID,
        modality: str,
        schema_declaration: Mapping[str, Any],
        dek_version: int,
    ) -> SessionOpened:
        return self._bridge.run(
            self._async.open_session(
                session_id=session_id,
                workspace_id=workspace_id,
                subject_id=subject_id,
                consent_record_id=consent_record_id,
                modality=modality,
                schema_declaration=schema_declaration,
                dek_version=dek_version,
            )
        )

    def close_session(self, session_id: UUID) -> SessionClosed:
        return self._bridge.run(self._async.close_session(session_id))

    def read_session(self, session_id: UUID) -> SessionRecord:
        return self._bridge.run(self._async.read_session(session_id))

    def register_public_key(
        self,
        member_id: UUID,
        *,
        public_key_x25519: bytes,
        auth_verification_token_sha256: bytes,
        public_key_fingerprint: bytes,
    ) -> PublicKeyRegistered:
        return self._bridge.run(
            self._async.register_public_key(
                member_id,
                public_key_x25519=public_key_x25519,
                auth_verification_token_sha256=auth_verification_token_sha256,
                public_key_fingerprint=public_key_fingerprint,
            )
        )

    def upload_wrapped_dek(
        self,
        tenant_id: UUID,
        *,
        for_member_id: UUID,
        dek_version: int,
        wrapped_dek_envelope: bytes,
        wrapped_by_member_id: UUID,
    ) -> WrappedDekUploaded:
        return self._bridge.run(
            self._async.upload_wrapped_dek(
                tenant_id,
                for_member_id=for_member_id,
                dek_version=dek_version,
                wrapped_dek_envelope=wrapped_dek_envelope,
                wrapped_by_member_id=wrapped_by_member_id,
            )
        )

    def fetch_wrapped_deks(
        self, member_id: UUID, *, dek_version: int | None = None
    ) -> list[WrappedDekRecord]:
        return self._bridge.run(self._async.fetch_wrapped_deks(member_id, dek_version=dek_version))

    def revoke_wrapped_dek(self, wrapped_dek_id: UUID, *, reason: str) -> WrappedDekRevoked:
        return self._bridge.run(self._async.revoke_wrapped_dek(wrapped_dek_id, reason=reason))

    def erase_subject(self, subject_id: UUID) -> SubjectErased:
        return self._bridge.run(self._async.erase_subject(subject_id))

    def close(self) -> None:
        """Close the connection pool and stop the loop thread. Idempotent."""
        try:
            self._bridge.run(self._async.aclose())
        finally:
            self._bridge.close()

    def __enter__(self) -> ControlClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
