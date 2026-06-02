"""The durable data path: capture (§7.7.1) + drain/disposition (§7.7.4).

This module closes the end-to-end key-custody chain and wires the §7.7.4 disposition table on
top of the C4 buffer (``cephios_core.buffer``) and the C5a wire client
(``cephios_core.ingest``). Two public entry points:

- :func:`capture` — the application-facing capture path (§7.7.1). It constructs the §6.4
  AES-256-GCM envelope via :func:`cephios_core.envelope.construct` (fresh-random nonce — the
  production path, NOT the conformance-only ``_construct_with_nonce``) and THEN writes the
  resulting ciphertext to the durable buffer. Plaintext is encrypted BEFORE the buffer write;
  the buffer only ever sees ciphertext (KC / Model C, §9.8; PT, §9.4).

- :class:`Uploader` — drains the buffer to ``POST /v1/ingest`` and applies the §7.7.4
  per-record disposition:

  * 200 ``persisted`` / ``deduplicated`` -> ``acknowledge`` (purge); both confirm durability.
  * 429 -> RETAIN; honor ``Retry-After`` + exponential backoff (§7.6). NOT a rejection.
  * 5xx / transport-level failure -> RETAIN; retry with backoff (§7.3). Never ``BufferRejected``.
  * other (non-429) 4xx -> ``emit_rejected`` (``BufferRejected``) THEN ``acknowledge`` (purge).

  The drain re-issues each buffered record with its ORIGINAL ``(session_id, batch_sequence)``
  (C4's stable durable key) so the cloud's structural dedupe (§7.2) returns ``deduplicated``
  on a retry rather than double-persisting (§7.7.4 idempotency).

Standing invariants (CLAUDE.md §9):

- KC (§9.8): :func:`capture` is the ONLY place plaintext + DEK meet, and it encrypts before
  the buffer write — the buffer surface has no plaintext/key parameter (proven structurally in
  C4). The wire body == the buffered bytes == the constructed envelope (PT, §9.4).
- ND (§9.2): the §7.7.4 disposition is never-silent. ACK purges; 429/5xx RETAIN (no loss);
  a non-retryable 4xx EMITS ``BufferRejected`` and only THEN purges — the emit-then-purge
  order (C4's guarantee) means a crash/raise between the two leaves the record buffered
  (re-uploaded → re-rejected → re-emitted; no silent loss). A persistent storage-write failure
  converts to the §7.7.2 ``BufferLost`` terminal latch, never a raw apsw exception
  (:class:`PermanentStorageLossError`, the WATCHPOINT-2 auto-trigger).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final
from uuid import UUID

import apsw

from cephios_core import envelope
from cephios_core.buffer import Buffer, BufferLost, SdkBufferError, rejected_reason
from cephios_core.errors import CephiosError
from cephios_core.ingest import BackoffPolicy, Disposition, IngestOutcome, SupportsIngest

__all__ = [
    "PermanentStorageLossError",
    "capture",
    "DrainSummary",
    "Uploader",
]


# ---------------------------------------------------------------------------
# WATCHPOINT 2 — automatic permanent-loss detection (§7.7.2 terminal trigger).
# ---------------------------------------------------------------------------


class PermanentStorageLossError(SdkBufferError):
    """A persistent buffer-storage write failure converted to the §7.7.2 terminal state.

    Raised by :func:`capture` AFTER it has driven the buffer into the permanent-loss latch via
    :meth:`Buffer.fail_permanently` (which emits the never-silent :class:`BufferLost` event).
    It is the synchronous, ergonomic signal to the caller that the capture was NOT durably
    buffered; the load-bearing never-silent guarantee is the ``BufferLost`` event, this raise
    is the convenience surface (§7.7.4). Subclasses :class:`~cephios_core.buffer.SdkBufferError`
    — an SDK-internal local condition, NEVER a §14 wire error (§7.7.5).
    """

    def __init__(self, event: BufferLost) -> None:
        self.event = event
        super().__init__(
            f"buffer storage failed permanently (reason={event.reason!r}); the buffer is now "
            f"in the §7.7.2 terminal-loss state — clear_terminal_latch() to recover"
        )


# The persistent-storage-failure trigger reason (§7.7.3 BufferLost.reason vocabulary).
_STORAGE_FAILURE: Final = "storage_failure"


def _write_durably(buffer: Buffer, session_id: UUID, batch_sequence: int, env: bytes) -> None:
    """Write ``env`` to the buffer, converting a PERSISTENT storage failure to the §7.7.2
    terminal latch instead of letting a raw apsw exception escape (WATCHPOINT 2).

    Where the persistent-vs-transient line is drawn: C4 already owns it. ``Buffer`` rides out
    the only known TRANSIENT condition — the reopen-window ``apsw.IOError`` after a kill — inside
    its bounded :meth:`Buffer._open_with_retry`, and deliberately leaves the steady-state
    ``write`` / ``_persist`` path UNWRAPPED so a normal-operation failure surfaces. Therefore
    any ``apsw.Error`` that propagates out of :meth:`Buffer.write` is, by C4's construction,
    POST-transient — a persistent steady-state ``_persist`` failure (disk full, I/O error,
    read-only / corrupt store). C5a converts it on first occurrence; it does NOT add its own
    retry (that would both duplicate C4's bounded-retry responsibility and risk acting on an
    apsw transaction left half-open by the failed commit).

    ``apsw.ConstraintError`` is the ONE exception that is re-raised unchanged: a duplicate
    ``(session_id, batch_sequence)`` primary-key conflict is an idempotency/logic condition
    (§7.2), not a durability failure, so converting it to ``BufferLost`` would be wrong. If the
    buffer is ALREADY latched, :meth:`Buffer.write` raises ``TerminalLatchError`` (an
    ``SdkBufferError``, not ``apsw.Error``) before touching storage — that surfaces unchanged,
    so a captured-after-loss call cleanly reports the terminal state.
    """
    try:
        buffer.write(session_id, batch_sequence, env)
    except apsw.ConstraintError:
        raise  # PK conflict on (session_id, batch_sequence): a logic/idempotency error, not loss
    except apsw.Error as exc:
        # Persistent steady-state storage failure → §7.7.2 permanent-loss. fail_permanently
        # emits the never-silent BufferLost to the application callback and persists the durable
        # latch; it is idempotent (a no-op if already latched). lost_record_count=0: a
        # buffer-wide storage-substrate failure has no determinable per-record count (§7.7.3),
        # and session_id is None (the loss is buffer-wide, not session-scoped).
        buffer.fail_permanently(_STORAGE_FAILURE, lost_record_count=0)
        raise PermanentStorageLossError(BufferLost(None, _STORAGE_FAILURE, 0)) from exc


# ---------------------------------------------------------------------------
# WATCHPOINT 1 — the public capture API (the end-to-end KC chain closes here).
# ---------------------------------------------------------------------------


def capture(
    buffer: Buffer,
    *,
    dek: bytes,
    session_id: UUID,
    batch_sequence: int,
    plaintext: bytes,
) -> bytes:
    """Capture one neural-data sample: encrypt, then durably buffer (§7.7.1). Returns the
    constructed envelope bytes.

    The end-to-end Model-C chain (§9.8): ``plaintext`` is encrypted under ``dek`` into a §6.4
    AES-256-GCM envelope with a FRESH RANDOM nonce (via :func:`cephios_core.envelope.construct`
    — the production path; never the conformance-only caller-supplied-nonce seam) and only the
    resulting ciphertext is written to the durable buffer under the §7.2 durable key
    ``(session_id, batch_sequence)``. Plaintext is therefore never at rest on the tenant's
    local disk and never reaches the wire (the uploader sends exactly these returned bytes —
    PT, §9.4).

    A persistent storage-write failure raises :class:`PermanentStorageLossError` after driving
    the §7.7.2 terminal latch + ``BufferLost`` (WATCHPOINT 2); it never leaks a raw apsw error.
    """
    env = envelope.construct(dek, plaintext)
    _write_durably(buffer, session_id, batch_sequence, env)
    return env


# ---------------------------------------------------------------------------
# The §7.7.4 uploader / drain.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DrainSummary:
    """The result of a :meth:`Uploader.drain` pass over the currently-buffered records.

    ``acknowledged`` — purged on a 200 ack. ``rejected`` — emit-then-purged on a non-retryable
    4xx. ``retained`` — still buffered (429/5xx/network did not clear within the attempt
    budget); a subsequent :meth:`Uploader.drain` re-attempts them with the same durable key.
    """

    acknowledged: int = 0
    rejected: int = 0
    retained: int = 0


class Uploader:
    """Drains the §7.7 durable buffer to ``POST /v1/ingest`` per the §7.7.4 disposition table.

    ``max_attempts`` bounds the POSTs per record per :meth:`drain` call so a sustained
    429/5xx does not spin forever inside one drain; the record is RETAINED (left buffered) when
    the budget is exhausted and re-attempted on the next drain — never purged on a non-ack
    (§7.7.4: "purged only after a server acknowledgement"). ``sleep`` is injectable so backoff
    waits are deterministic and instant in offline tests (§B — no real time, no real network).
    """

    def __init__(
        self,
        *,
        buffer: Buffer,
        client: SupportsIngest,
        backoff: BackoffPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 8,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self._buffer = buffer
        self._client = client
        self._backoff = backoff if backoff is not None else BackoffPolicy()
        self._sleep = sleep
        self._max_attempts = max_attempts

    def drain(self) -> DrainSummary:
        """Attempt to deliver every currently-buffered record once through the disposition
        table. Returns a :class:`DrainSummary`. Reads a FIFO snapshot via
        :meth:`Buffer.pending` (which surfaces records persisted before a restart with their
        original durable key), so a resumed process drains exactly what survived (§7.7.1)."""
        acknowledged = rejected = retained = 0
        for session_id, batch_sequence, env in self._buffer.pending():
            disposition = self._deliver_one(session_id, batch_sequence, env)
            if disposition is Disposition.ACK:
                acknowledged += 1
            elif disposition is Disposition.REJECTED:
                rejected += 1
            else:
                retained += 1
        return DrainSummary(acknowledged=acknowledged, rejected=rejected, retained=retained)

    def _deliver_one(self, session_id: UUID, batch_sequence: int, env: bytes) -> Disposition:
        """Deliver one record, retrying 429/5xx within the attempt budget. Returns the
        TERMINAL disposition for this drain pass (ACK / REJECTED, or BACKPRESSURE/RETRYABLE if
        the record was retained because the budget ran out)."""
        last = Disposition.RETRYABLE
        for attempt in range(self._max_attempts):
            outcome = self._client.ingest(session_id, batch_sequence, env)
            last = outcome.disposition

            if outcome.disposition is Disposition.ACK:
                # 200 persisted/deduplicated: both confirm cloud-side durability → purge (§7.7.4).
                self._buffer.acknowledge(session_id, batch_sequence)
                return Disposition.ACK

            if outcome.disposition is Disposition.REJECTED:
                # Non-retryable 4xx (§7.7.4): EMIT-THEN-PURGE. emit_rejected first (the
                # never-silent BufferRejected), THEN acknowledge (purge). C4 guarantees this
                # ordering is crash-safe: a raise between the two leaves the record buffered.
                self._reject(session_id, batch_sequence, outcome.error)
                return Disposition.REJECTED

            # BACKPRESSURE (429) or RETRYABLE (5xx / network): RETAIN. Wait, then retry with the
            # SAME durable key (cloud dedups the retry). No purge, no BufferRejected (§7.7.4).
            if attempt + 1 < self._max_attempts:
                self._sleep(self._wait_seconds(outcome, attempt))
        # Attempt budget exhausted on a non-ack: the record stays buffered, retried next drain.
        return last

    def _reject(self, session_id: UUID, batch_sequence: int, error: CephiosError | None) -> None:
        """Non-retryable disposition: emit ``BufferRejected`` (never-silent) THEN purge (§7.7.4).

        Order is load-bearing and is NOT a convenience: ``emit_rejected`` runs the event
        callback synchronously and does not purge; ``acknowledge`` purges. If the callback
        raises (the never-silent "panicking" option, §7.7.3), the exception propagates BEFORE
        ``acknowledge`` runs, so the record is retained and re-processed — never a silent loss.
        ``rejected_reason`` maps the decoded ``CephiosError`` to the fixed §7.7.3 vocabulary
        (``None`` → ``rejected_other``)."""
        self._buffer.emit_rejected(session_id, batch_sequence, rejected_reason(error))
        self._buffer.acknowledge(session_id, batch_sequence)

    def _wait_seconds(self, outcome: IngestOutcome, attempt: int) -> float:
        """Seconds to wait before the next retry. On a 429 honor ``Retry-After`` (§7.6) AND
        apply exponential backoff: ``max(retry_after, backoff(attempt))`` waits at least the
        server's requested delay while still growing on repeated 429s. On a 5xx/network
        RETRYABLE it is the exponential backoff alone (§7.3)."""
        backoff = self._backoff.delay(attempt)
        if outcome.disposition is Disposition.BACKPRESSURE and outcome.retry_after is not None:
            return max(outcome.retry_after, backoff)
        return backoff
