"""HTTP ingestion client for ``POST /v1/ingest`` (CONTRACT_SPEC.md §7.1–§7.6).

This module is the durable data-path's *wire layer*: an async core built on
``httpx.AsyncClient`` plus a thin synchronous facade. The ratified shape is async-first +
sync facade — only the network I/O is async; the CPU-bound crypto (§6.4 envelope, the C3
``cephios_core.envelope`` module) and the durable buffer (§7.7, the C4
``cephios_core.buffer`` module, apsw/synchronous) stay synchronous. The synchronous
:class:`IngestClient` runs the async core on a private event loop on a background thread so a
persistent connection pool survives across the many sequential requests the §7.7.4 uploader
issues while draining the buffer.

What this layer does (§7.1–§7.6):

- Builds the request: ``POST {base}/v1/ingest`` with the five required headers (§7.2) —
  ``Content-Type: application/octet-stream``, ``Authorization`` (``Bearer`` session token or
  ``ApiKey`` api key), ``X-Cephios-API-Version`` (the WIRE version, pinned from the single
  :data:`WIRE_API_VERSION` constant, NOT a document revision), ``X-Cephios-Session-Id``
  (the §3.1 UUIDv7), ``X-Cephios-Batch-Sequence`` (the §7.2 monotonic non-negative int).
  The body is the RAW envelope bytes (§6.1) — no JSON wrapper, no base64 (§7.2).
- Classifies the response into an :class:`IngestOutcome` the §7.7.4 uploader dispositions:
  200 (``persisted``/``deduplicated``) → ACK; 429 → BACKPRESSURE (honor ``Retry-After``,
  §7.6); 5xx and transport-level failures → RETRYABLE (retain); other 4xx → REJECTED
  (non-retryable, emit-then-purge).
- Decodes a 4xx body MINIMALLY into a :class:`~cephios_core.errors.CephiosError` — just enough
  ``(category, code)`` for the buffer's :func:`~cephios_core.buffer.rejected_reason` mapping.
  The full §14.2 twelve-category decode + its ``error_taxonomy`` vectors are C5b; this is
  deliberately the minimal seam the uploader needs (see :func:`decode_error`).

Standing invariants (CLAUDE.md §9):

- KC / Model C (§9.8): the only credential on the wire is the session token / api key, sent
  over TLS. ``httpx`` verifies certificates by default and this module never disables that
  (no ``verify=False``). No plaintext, no DEK, no key material touches this layer — the body
  is opaque, already-encrypted envelope bytes (PT, §9.1; the envelope is constructed by the
  capture path BEFORE it reaches here).
- IS (§9.6): the public surface mirrors §7; exports are deliberate and minimal (``__all__``);
  the wire protocol version is pinned to ``1.0`` from a single constant.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Coroutine
from dataclasses import dataclass
from enum import Enum
from types import TracebackType
from typing import Any, Final, Protocol, TypeVar
from uuid import UUID

import httpx

from cephios_core.errors import ERROR_CATEGORIES, CephiosError

__all__ = [
    "DEFAULT_BASE_URL",
    "INGEST_PATH",
    "WIRE_API_VERSION",
    "OCTET_STREAM",
    "HEADER_API_VERSION",
    "HEADER_SESSION_ID",
    "HEADER_BATCH_SEQUENCE",
    "Credential",
    "bearer",
    "api_key",
    "Disposition",
    "IngestAck",
    "IngestOutcome",
    "BackoffPolicy",
    "decode_error",
    "parse_retry_after",
    "AsyncIngestClient",
    "IngestClient",
    "SupportsIngest",
]

# §7.1 endpoint. The base URL is overridable for self-hosted deployments; api.cephios.com is
# the production cloud.
DEFAULT_BASE_URL: Final = "https://api.cephios.com"
INGEST_PATH: Final = "/v1/ingest"

# §7.2 / §15.1 WIRE protocol version. Pinned here as the SINGLE source of truth and sent in
# X-Cephios-API-Version. This is the wire version (`1.0`), decoupled per §15.6 from the
# CONTRACT_SPEC document revision (currently 1.5) — the document revisions that introduced
# §7.7 / BufferRejected did NOT move this. Do NOT derive it from a doc-revision counter.
WIRE_API_VERSION: Final = "1.0"

OCTET_STREAM: Final = "application/octet-stream"  # §7.2 Content-Type

HEADER_API_VERSION: Final = "X-Cephios-API-Version"
HEADER_SESSION_ID: Final = "X-Cephios-Session-Id"
HEADER_BATCH_SEQUENCE: Final = "X-Cephios-Batch-Sequence"


# ---------------------------------------------------------------------------
# §7.2 Authorization — Bearer <session_token> OR ApiKey <api_key>.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Credential:
    """The §7.2 ``Authorization`` credential: a ``scheme`` + ``token`` pair.

    The two schemes the protocol defines are ``Bearer`` (a session token, §9) and ``ApiKey``
    (a service-member api key). Use :func:`bearer` / :func:`api_key` rather than constructing
    this directly. ``repr`` redacts the token so it does not leak through log/trace surfaces
    (KC, §9.8)."""

    scheme: str
    token: str

    def header_value(self) -> str:
        """The ``Authorization`` header value, e.g. ``"Bearer eyJ..."`` (§7.2)."""
        return f"{self.scheme} {self.token}"

    def __repr__(self) -> str:  # never render the secret token in a repr/trace (KC, §9.8)
        return f"Credential(scheme={self.scheme!r}, token='<redacted>')"


def bearer(session_token: str) -> Credential:
    """A ``Bearer <session_token>`` credential (§7.2 — the session-token scheme, §9)."""
    return Credential("Bearer", session_token)


def api_key(key: str) -> Credential:
    """An ``ApiKey <api_key>`` credential (§7.2 — the service-member scheme)."""
    return Credential("ApiKey", key)


# ---------------------------------------------------------------------------
# Response classification — the input to the §7.7.4 uploader disposition table.
# ---------------------------------------------------------------------------


class Disposition(Enum):
    """How the §7.7.4 uploader must treat a response (the disposition-table key).

    This is a CLIENT-SIDE classification of the wire response; it is NOT the §7.7.3 buffer
    event surface and NOT the §14 ``CephiosError`` category.
    """

    #: 200 ``persisted`` or ``deduplicated`` (§7.3). Both confirm cloud-side durability →
    #: acknowledge (purge) the buffered record.
    ACK = "ack"
    #: 429 ``BufferError`` (§7.6 + §14.2). Backpressure, NOT a rejection: retain the record,
    #: honor ``Retry-After`` + exponential backoff.
    BACKPRESSURE = "backpressure"
    #: 5xx (§7.3) or a transport-level failure (§14 ``NetworkError``). Retryable: retain +
    #: retry with backoff. Never emits ``BufferRejected``.
    RETRYABLE = "retryable"
    #: A non-retryable 4xx other than 429 (§7.7.4) — e.g. ``ValidationError 'batch_too_large'``.
    #: Emit ``BufferRejected`` then purge.
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class IngestAck:
    """A 200 acknowledgement (§7.3). ``status`` is ``"persisted"`` or ``"deduplicated"``."""

    status: str
    envelope_byte_count: int | None


@dataclass(frozen=True, slots=True)
class IngestOutcome:
    """The classified result of one ``POST /v1/ingest`` attempt.

    ``error`` carries the minimally-decoded :class:`~cephios_core.errors.CephiosError` for a
    REJECTED disposition (``None`` if the 4xx body could not be parsed → maps to
    ``rejected_other``). ``retry_after`` is the parsed §7.6 ``Retry-After`` seconds on a
    BACKPRESSURE disposition (``None`` if the header was absent/unparseable).
    """

    disposition: Disposition
    http_status: int | None = None
    ack: IngestAck | None = None
    error: CephiosError | None = None
    retry_after: float | None = None


# ---------------------------------------------------------------------------
# §14.1 minimal error decode — ONLY enough (category, code) for rejected_reason().
# ---------------------------------------------------------------------------


def decode_error(body: bytes) -> CephiosError | None:
    """Minimally decode a §14.1 error envelope into a :class:`CephiosError`, or ``None``.

    Reads ``{"error": {"category", "code", "message"?}}`` (§14.1), maps ``category`` to its
    class via :data:`~cephios_core.errors.ERROR_CATEGORIES`, and constructs ``cls(code,
    message)``. The result feeds :func:`~cephios_core.buffer.rejected_reason`, which needs only
    the ``(category, code)`` pair.

    Returns ``None`` on ANY decode failure (not JSON, missing ``error``/``category``/``code``,
    unknown category, empty body) — :func:`rejected_reason` maps ``None`` →
    ``rejected_other`` per the §7.7.3 "parse failure or empty body" row, so a malformed error
    body degrades safely rather than raising.

    BOUNDARY (C5a vs C5b): this is the MINIMAL decode the uploader needs. It does NOT validate
    ``http_status`` against the category, decode ``details`` / ``request_id``, or enforce the
    full §14.2 twelve-category / §14.3 code taxonomy — that full decoder and its
    ``error_taxonomy`` conformance vectors are C5b.
    """
    try:
        doc = json.loads(body)
        err = doc["error"]
        category = err["category"]
        code = err["code"]
    except (ValueError, KeyError, TypeError):
        return None
    cls = ERROR_CATEGORIES.get(category)
    if cls is None:
        return None
    message = err.get("message", "") if isinstance(err, dict) else ""
    return cls(code, message)


def parse_retry_after(value: str | None) -> float | None:
    """Parse a §7.6 ``Retry-After`` header value into non-negative seconds, or ``None``.

    §7.6 specifies ``Retry-After`` as "seconds to wait", so this parses the delta-seconds
    form. A negative or non-numeric value (including the RFC-7231 HTTP-date form) yields
    ``None`` — the uploader then falls back to its exponential backoff. (HTTP-date support is
    not required by §7.6 and is intentionally out of this minimal scope.)
    """
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except (ValueError, AttributeError):
        return None
    return seconds if seconds >= 0 else None


# ---------------------------------------------------------------------------
# §7.6 exponential backoff.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BackoffPolicy:
    """Exponential backoff for repeated 429 / 5xx retries (§7.6 + §7.3).

    ``delay(attempt)`` = ``min(base * factor**attempt, maximum)`` where ``attempt`` is the
    zero-based count of prior failed attempts. Deterministic (no jitter) so retries are
    reproducible in offline tests; a production deployment MAY layer jitter on top.
    """

    base_seconds: float = 0.5
    factor: float = 2.0
    maximum_seconds: float = 30.0

    def delay(self, attempt: int) -> float:
        """Backoff seconds for the given zero-based ``attempt`` (clamped to ``maximum``)."""
        if attempt < 0:
            attempt = 0
        return min(self.base_seconds * (self.factor**attempt), self.maximum_seconds)


# ---------------------------------------------------------------------------
# The async core.
# ---------------------------------------------------------------------------

_T = TypeVar("_T")


class AsyncIngestClient:
    """Async ``POST /v1/ingest`` client (§7.1–§7.6). The real implementation; the synchronous
    :class:`IngestClient` is a thin facade over it.

    ``transport`` lets tests inject an ``httpx.MockTransport`` (offline, deterministic — §B has
    no server and no outbound network). ``timeout`` bounds each request; the default is
    generous for multi-MiB batches (§7.5). Certificates are verified (httpx default); this
    client never sets ``verify=False`` (KC / TLS, §9.8).
    """

    def __init__(
        self,
        *,
        credential: Credential,
        base_url: str = DEFAULT_BASE_URL,
        api_version: str = WIRE_API_VERSION,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._credential = credential
        self._api_version = api_version
        self._client = httpx.AsyncClient(
            base_url=base_url,
            transport=transport,
            timeout=timeout,
            follow_redirects=False,  # redirects on the data path are unexpected — never follow
        )

    def _headers(self, session_id: UUID, batch_sequence: int) -> dict[str, str]:
        """The five required §7.2 headers for one ingest request."""
        if batch_sequence < 0:
            raise ValueError("batch_sequence must be a non-negative integer (§7.2)")
        return {
            "Content-Type": OCTET_STREAM,
            "Authorization": self._credential.header_value(),
            HEADER_API_VERSION: self._api_version,
            HEADER_SESSION_ID: str(session_id),
            HEADER_BATCH_SEQUENCE: str(batch_sequence),
        }

    async def ingest(
        self, session_id: UUID, batch_sequence: int, envelope: bytes
    ) -> IngestOutcome:
        """POST one envelope and classify the response into an :class:`IngestOutcome`.

        ``envelope`` is sent as the RAW octet-stream body (§7.2) with no JSON wrapper and no
        base64 — ``content=envelope`` passes the bytes through byte-faithfully (PT, §9.4). A
        transport-level failure (connection reset, timeout — §7.7.4's "connection reset after
        bytes sent but before response read") classifies as RETRYABLE so the record is retained
        and re-attempted, never purged on uncertain state.
        """
        headers = self._headers(session_id, batch_sequence)
        try:
            response = await self._client.post(INGEST_PATH, content=envelope, headers=headers)
        except httpx.TransportError:
            # Transport-level failure (§14 NetworkError): retryable, retain (§7.7.4).
            return IngestOutcome(disposition=Disposition.RETRYABLE, http_status=None)
        return self._classify(response)

    def _classify(self, response: httpx.Response) -> IngestOutcome:
        """Map an HTTP response to its §7.7.4 :class:`Disposition`."""
        status = response.status_code
        if status == 200:
            return IngestOutcome(
                disposition=Disposition.ACK, http_status=status, ack=self._parse_ack(response)
            )
        if status == 429:  # §7.6 backpressure — retain + honor Retry-After (NOT a rejection)
            return IngestOutcome(
                disposition=Disposition.BACKPRESSURE,
                http_status=status,
                retry_after=parse_retry_after(response.headers.get("Retry-After")),
            )
        if 400 <= status < 500:  # non-429 4xx → non-retryable rejection (§7.7.4)
            return IngestOutcome(
                disposition=Disposition.REJECTED,
                http_status=status,
                error=decode_error(response.content),
            )
        # 5xx is retryable (§7.3). Any other unexpected status (1xx/3xx/2xx-non-200) is treated
        # as retryable too — RETAIN rather than risk a silent loss on an unmodeled response.
        return IngestOutcome(disposition=Disposition.RETRYABLE, http_status=status)

    @staticmethod
    def _parse_ack(response: httpx.Response) -> IngestAck:
        """Parse a 200 body (§7.3) best-effort. A 200 is an ACK regardless of body shape:
        per §7.3 + ARCHITECTURE.md §5.4 the cloud commits the batch atomically BEFORE sending
        the response, so 200 itself confirms durability."""
        try:
            body = response.json()
            return IngestAck(
                status=str(body.get("status", "")),
                envelope_byte_count=body.get("envelope_byte_count"),
            )
        except (ValueError, AttributeError, TypeError):
            return IngestAck(status="", envelope_byte_count=None)

    async def aclose(self) -> None:
        """Close the underlying connection pool."""
        await self._client.aclose()


# ---------------------------------------------------------------------------
# The synchronous facade.
# ---------------------------------------------------------------------------


class _AsyncBridge:
    """Runs a private asyncio event loop on a daemon thread.

    A persistent ``httpx.AsyncClient`` (and its connection pool) must outlive the many
    sequential requests the §7.7.4 uploader issues; reusing one across throwaway
    ``asyncio.run`` loops is unsound (the pool binds to the loop it ran on). So the facade owns
    one long-lived loop on a background thread and dispatches every coroutine onto it via
    ``run_coroutine_threadsafe``. Stdlib only — no new dependency (the async runner choice is
    documented in the commit body; ``anyio`` is httpx's transitive backend but its API is not
    used here, so no runtime dep is added beyond httpx).
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._closed = False
        self._thread = threading.Thread(
            target=self._run, name="cephios-ingest-loop", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro: Coroutine[Any, Any, _T]) -> _T:
        """Run ``coro`` on the background loop and block until it completes."""
        if self._closed:
            coro.close()  # avoid an un-awaited-coroutine warning on a closed bridge
            raise RuntimeError("async bridge is closed")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def close(self) -> None:
        """Stop the loop and join the thread. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()
        self._loop.close()


class IngestClient:
    """Synchronous facade over :class:`AsyncIngestClient` (the application-facing wire client).

    The public surface the §7.7.4 uploader consumes. Each :meth:`ingest` call runs the async
    request on the facade's private event-loop thread and blocks for the result; the network
    I/O stays async, the call site stays synchronous (the ratified async-first + sync-facade
    shape). Usable as a context manager; :meth:`close` releases the pool and the loop thread.
    """

    def __init__(
        self,
        *,
        credential: Credential,
        base_url: str = DEFAULT_BASE_URL,
        api_version: str = WIRE_API_VERSION,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._bridge = _AsyncBridge()
        self._async = AsyncIngestClient(
            credential=credential,
            base_url=base_url,
            api_version=api_version,
            transport=transport,
            timeout=timeout,
        )

    def ingest(self, session_id: UUID, batch_sequence: int, envelope: bytes) -> IngestOutcome:
        """Synchronously POST one envelope (§7.2) and return its classified outcome."""
        return self._bridge.run(self._async.ingest(session_id, batch_sequence, envelope))

    def close(self) -> None:
        """Close the connection pool and stop the loop thread. Idempotent."""
        try:
            self._bridge.run(self._async.aclose())
        finally:
            self._bridge.close()

    def __enter__(self) -> IngestClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class SupportsIngest(Protocol):
    """The structural type the §7.7.4 uploader depends on — :class:`IngestClient` satisfies it.

    Declared as a Protocol so a test fake (scripted outcomes, no real httpx) and the real
    synchronous client are interchangeable under strict typing without a shared base class.
    """

    def ingest(
        self, session_id: UUID, batch_sequence: int, envelope: bytes
    ) -> IngestOutcome: ...
