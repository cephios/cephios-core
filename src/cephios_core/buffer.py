"""SDK-side durable buffer (CONTRACT_SPEC.md §7.7).

This module is the Python reference implementation of the §7.7 SDK durable-buffer
contract: the §7.7.1 persist-before-ack durability obligation, the §7.7.2 backpressure
modes (block-and-signal / drop-oldest / permanent-loss), the §7.7.3 four-typed-event
taxonomy, and the §7.7.4 ``BufferRejected.reason`` fixed-vocabulary mapping that the
Commit 5 uploader will call. It is the operational realization of the ND (never-silent
durability) invariant (CLAUDE.md §9.2) in Python.

Standing invariants this module carries (CLAUDE.md §9):

- ND (never-silent durability, load-bearing): every backpressure activation, drop,
  per-record cloud rejection, and terminal-loss condition produces a typed event via
  the application-supplied callback. The callback is a *direct synchronous call* — there
  is no bounded queue / channel that could drop an event under load (the §7.7.3
  never-silent prohibition). A callback that raises propagates the exception (the
  "panicking" never-silent option of §7.7.3) rather than being swallowed. Re-entry from
  a callback into a buffer method on the same thread is detected by thread identity and
  rejected with :class:`ReentrantCallbackError` rather than deadlocking the non-reentrant
  lock — the Python analogue of the Go reference's goroutine-identity guard.

- PT (pass-through, §9.1): the envelope payload is bytes-opaque. :meth:`Buffer.write`
  takes ``envelope: bytes`` and stores / returns it byte-faithfully; no transform, no
  codec hop, no inspection on the write or read path (in == out).

- KC (key custody / Model C, §9.8): the buffer surface has no ``dek`` / ``plaintext`` /
  key parameter and imports no encryption primitive. Envelope construction (§6.4) happens
  BEFORE the buffer write (Commit 5 uploader); the buffer stores ciphertext only. Plaintext
  is never at rest on the tenant's local disk via this buffer (§7.7.1).

- IS (interface stability, §9.6): the public surface (:class:`Buffer`, :class:`BufferConfig`,
  :class:`Mode`, the four events, the reason vocabulary + :func:`rejected_reason`) mirrors
  §7.7 verbatim; exports are deliberate and minimal (``__all__``).

The four events and the SDK-internal exceptions are DISTINCT from the §14 ``CephiosError``
hierarchy (§7.7.5): the events are plain dataclasses (no HTTP status, no wire shape) and
the exceptions do not subclass ``CephiosError``. In particular :class:`BufferRejected` is
NOT the §14.2 ``BufferError`` HTTP-429 wire signal.

Storage primitive (§7.7.1 leaves this to the implementation; reviewer-ratified): apsw
(Another Python SQLite Wrapper) in WAL journal mode with ``synchronous=FULL``. apsw gives
literal control over commit timing, which makes the persist-before-ack property a
*commit-before-ack* property that is behaviorally red-capable (an uncommitted transaction
is rolled back on reopen — proven by the process-kill test).
"""

from __future__ import annotations

import enum
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Final, cast
from uuid import UUID

import apsw

from cephios_core.errors import CephiosError

# Module logger for the reopen-retry observability hook (§B Windows-CI verification): each caught
# transient reopen IOError logs the SQLITE extended result code at WARNING. stdlib only — no dep.
_log = logging.getLogger(__name__)

__all__ = [
    "Mode",
    "BufferConfig",
    "Buffer",
    "BufferEvent",
    "BufferPressure",
    "BufferDrop",
    "BufferRejected",
    "BufferLost",
    "REJECTED_BATCH_TOO_LARGE",
    "REJECTED_MALFORMED",
    "REJECTED_VERSION_UNSUPPORTED",
    "REJECTED_OTHER",
    "REJECTED_REASONS",
    "rejected_reason",
    "SdkBufferError",
    "BufferConfigError",
    "ReentrantCallbackError",
    "TerminalLatchError",
    "BufferClosedError",
]


# ---------------------------------------------------------------------------
# §7.7.3 BufferRejected.reason — the fixed, closed cross-SDK vocabulary.
# ---------------------------------------------------------------------------

REJECTED_BATCH_TOO_LARGE: Final = "rejected_batch_too_large"
REJECTED_MALFORMED: Final = "rejected_malformed"
REJECTED_VERSION_UNSUPPORTED: Final = "rejected_version_unsupported"
REJECTED_OTHER: Final = "rejected_other"

# The CLOSED set. An SDK MUST NOT emit a reason outside this set (§7.7.3).
REJECTED_REASONS: Final[frozenset[str]] = frozenset(
    {
        REJECTED_BATCH_TOO_LARGE,
        REJECTED_MALFORMED,
        REJECTED_VERSION_UNSUPPORTED,
        REJECTED_OTHER,
    }
)

# (category, code) -> reason. Keyed on the §14 (category, code) pair the spec table
# pairs explicitly — tighter than a code-only match (the Go oracle keys on code only;
# keying on (category, code) here is the spec-faithful reading per the §7.7.3 table and
# avoids e.g. a hypothetical non-EnvelopeError 'malformed' aliasing to rejected_malformed).
_REJECTION_REASON_MAP: Final[dict[tuple[str, str], str]] = {
    ("ValidationError", "batch_too_large"): REJECTED_BATCH_TOO_LARGE,
    ("EnvelopeError", "malformed"): REJECTED_MALFORMED,
    ("VersionError", "envelope_version_unsupported"): REJECTED_VERSION_UNSUPPORTED,
}


def rejected_reason(error: CephiosError | None) -> str:
    """Map a non-retryable cloud rejection to the fixed §7.7.3 ``BufferRejected.reason``.

    This is the pure mapping the Commit 5 uploader calls after it parses a non-retryable
    4xx (non-429) response into a typed :class:`~cephios_core.errors.CephiosError`. Per the
    §7.7.3 normative vocabulary table:

        ``ValidationError 'batch_too_large'``          -> ``rejected_batch_too_large``
        ``EnvelopeError 'malformed'``                  -> ``rejected_malformed``
        ``VersionError 'envelope_version_unsupported'``-> ``rejected_version_unsupported``
        any other non-retryable code / parse failure / empty body -> ``rejected_other``

    ``error is None`` models the "parse failure or empty body" row: the uploader could not
    parse a ``CephiosError`` envelope from the response, so the reason is ``rejected_other``.

    The result is ALWAYS one of :data:`REJECTED_REASONS`. The wire-level error code is never
    string-templated into the reason (``"rejected_" + code`` is non-conformant — it leaks
    server detail and unbounds the set, §7.7.3).
    """
    if error is None:
        return REJECTED_OTHER
    return _REJECTION_REASON_MAP.get((error.category, error.code), REJECTED_OTHER)


# ---------------------------------------------------------------------------
# §7.7.3 event taxonomy — four typed events. Plain frozen dataclasses, NOT
# CephiosError, NOT the §14 BufferError, no HTTP status, no wire shape (§7.7.5).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BufferEvent:
    """Base of the four §7.7.3 SDK-internal durability events.

    A sealed-ish marker so application code can ``isinstance(ev, BufferEvent)`` and switch
    over the closed set. Deliberately NOT a subclass of ``CephiosError`` (§7.7.5): these are
    client-side observable events, not wire errors.
    """


@dataclass(frozen=True, slots=True)
class BufferPressure(BufferEvent):
    """block-and-signal mode reached capacity; the writing thread is about to block (§7.7.3).

    Required payload (§7.7.3 table): ``session_id``, ``batch_sequence``, ``reason``,
    ``buffer_depth``.
    """

    session_id: UUID
    batch_sequence: int
    reason: str
    buffer_depth: int


@dataclass(frozen=True, slots=True)
class BufferDrop(BufferEvent):
    """drop-oldest mode dropped the oldest unsent record (§7.7.3). One event per dropped record.

    Required payload (§7.7.3 table): ``session_id``, ``batch_sequence`` of the dropped record,
    ``reason`` (e.g. ``"buffer_full"``).
    """

    session_id: UUID
    batch_sequence: int
    reason: str


@dataclass(frozen=True, slots=True)
class BufferRejected(BufferEvent):
    """A non-retryable cloud rejection (§7.7.4 4xx-non-429) purged a single record (§7.7.3).

    Per-record and NON-terminal: no latch, no tenant-ack. Required payload (§7.7.3 table):
    ``session_id``, ``batch_sequence`` of the rejected record, ``reason`` (from the closed
    :data:`REJECTED_REASONS` vocabulary; see :func:`rejected_reason`).
    """

    session_id: UUID
    batch_sequence: int
    reason: str


@dataclass(frozen=True, slots=True)
class BufferLost(BufferEvent):
    """Terminal permanent-loss condition (§7.7.2 / §7.7.3). Buffer-wide and latched.

    Required payload (§7.7.3 table): ``session_id`` (``None`` if the loss is buffer-wide),
    ``reason`` (e.g. ``"storage_failure"``, ``"journal_corruption"``,
    ``"loss_tolerance_exceeded"``), ``lost_record_count`` (where determinable, else 0).
    """

    session_id: UUID | None
    reason: str
    lost_record_count: int


# ---------------------------------------------------------------------------
# SDK-internal exceptions. NOT CephiosError (§7.7.5 distinction).
# ---------------------------------------------------------------------------


class SdkBufferError(Exception):
    """Base of the SDK-internal buffer exceptions.

    Distinct from :class:`~cephios_core.errors.CephiosError` (the §14 wire taxonomy): these
    are local operational conditions, never carried on the wire (§7.7.5).
    """


class BufferConfigError(SdkBufferError):
    """:class:`BufferConfig` failed validation (missing callback, bad capacity / low-water)."""


class ReentrantCallbackError(SdkBufferError):
    """A buffer method was called from inside an event callback on the same thread.

    The callback runs while the buffer's non-reentrant lock is held; a same-thread re-entry
    would deadlock. The buffer detects the re-entry by thread identity and raises this
    (loud, never-silent) instead of hanging. Handlers that need to drain / acknowledge must
    dispatch the work to a separate thread.
    """


class TerminalLatchError(SdkBufferError):
    """The buffer is in the §7.7.2 permanent-loss terminal state.

    The latch persists across process restarts; every public method raises this until
    :meth:`Buffer.clear_terminal_latch` is invoked (explicit tenant acknowledgement, §7.7.2).
    """


class BufferClosedError(SdkBufferError):
    """A buffer method was called after :meth:`Buffer.close`."""


# ---------------------------------------------------------------------------
# Configuration.
# ---------------------------------------------------------------------------


class Mode(enum.Enum):
    """§7.7.2 backpressure mode selected at construction."""

    #: Default (MUST, §7.7.2). At capacity, block subsequent writes AND emit BufferPressure;
    #: release below the low-water threshold.
    BLOCK_AND_SIGNAL = "block_and_signal"

    #: Opt-in (MAY, §7.7.2). At capacity, drop the oldest unsent record + emit one BufferDrop.
    DROP_OLDEST = "drop_oldest"


@dataclass(frozen=True, slots=True)
class BufferConfig:
    """Configuration for :class:`Buffer`.

    ``event_callback`` is mandatory: the never-silent obligation (§7.7.3) demands a delivery
    surface from construction time — the buffer refuses to start without one rather than
    silently dropping events.
    """

    storage_path: Path
    capacity_records: int
    event_callback: Callable[[BufferEvent], None]
    low_water_records: int = 0
    mode: Mode = Mode.BLOCK_AND_SIGNAL

    def _validate(self) -> None:
        if self.event_callback is None:
            raise BufferConfigError("event_callback is required (never-silent obligation, §7.7.3)")
        if not str(self.storage_path):
            raise BufferConfigError("storage_path must be a non-empty path")
        if self.capacity_records <= 0:
            raise BufferConfigError("capacity_records must be strictly positive")
        if self.mode is Mode.BLOCK_AND_SIGNAL:
            # 1 <= low_water < capacity. low_water = 0 would never wake a blocked writer
            # ("depth strictly below low_water" reduces to depth < 0); low_water >= capacity
            # would also never wake (waiters block at depth >= capacity).
            if self.low_water_records < 1 or self.low_water_records >= self.capacity_records:
                raise BufferConfigError(
                    "low_water_records must satisfy 1 <= low_water_records < capacity_records "
                    "in block-and-signal mode"
                )


# ---------------------------------------------------------------------------
# Durable storage schema.
# ---------------------------------------------------------------------------

# Applied on every open via CREATE TABLE IF NOT EXISTS. No migration framework — schema
# evolution is a §8 deviation requiring its own ratification.
_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS records (
    session_id     BLOB    NOT NULL,
    batch_sequence INTEGER NOT NULL,
    envelope       BLOB    NOT NULL,
    enqueued_at    INTEGER NOT NULL,
    PRIMARY KEY (session_id, batch_sequence)
);
CREATE INDEX IF NOT EXISTS records_fifo_idx ON records (enqueued_at);

CREATE TABLE IF NOT EXISTS terminal_latch (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    reason            TEXT    NOT NULL,
    lost_record_count INTEGER NOT NULL,
    latched_at        INTEGER NOT NULL,
    session_id        BLOB
);
"""


@dataclass(frozen=True, slots=True)
class _Terminal:
    """In-memory mirror of the persisted ``terminal_latch`` row."""

    reason: str
    lost_record_count: int
    session_id: UUID | None


# ---------------------------------------------------------------------------
# The buffer.
# ---------------------------------------------------------------------------


class Buffer:
    """Durable SDK buffer (§7.7).

    Thread-safe: all public methods serialize on an internal lock. Records are persisted to
    a local apsw (SQLite) database in WAL + ``synchronous=FULL`` mode; the durable key is
    ``(session_id, batch_sequence)`` (§7.2 / §7.7.1) and is stable across process restart so
    the resumed buffer re-issues the same key for cloud-side dedup.

    Construction opens the database, applies the durability PRAGMAs, installs the schema, and
    reads the persisted terminal latch (§7.7.2): if the latch is present (a prior process
    latched it and it survived restart), every public method raises :class:`TerminalLatchError`
    until :meth:`clear_terminal_latch`.
    """

    # Reopen retry backoff schedule (seconds) — the sleeps BETWEEN attempts. 4 sleeps => 5
    # attempts, total wait <= 0.75s. Rides out a TRANSIENT reopen IOError: a process killed
    # inside the BEGIN IMMEDIATE..COMMIT window dies holding the WAL write lock, and Windows
    # releases the dead writer's -wal/-shm locks ASYNCHRONOUSLY after the process object is
    # signaled, so a fast reopen can hit the SQLITE_IOERR SHM-lock family on the WAL attach.
    _REOPEN_BACKOFFS_S: ClassVar[tuple[float, ...]] = (0.05, 0.10, 0.20, 0.40)

    def __init__(self, config: BufferConfig) -> None:
        config._validate()
        self._config = config
        self._callback = config.event_callback
        self._capacity = config.capacity_records
        self._low_water = config.low_water_records
        self._mode = config.mode

        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._closed = False
        self._at_pressure = False
        # Thread identity currently inside the event callback, or None. Read at public-method
        # entry WITHOUT the lock (a plain attribute read is atomic under the GIL) so a
        # re-entrant call can short-circuit to ReentrantCallbackError before blocking on the
        # lock the in-flight callback still holds.
        self._callback_owner: int | None = None

        self._open_with_retry(str(config.storage_path))
        self._conn.execute(_SCHEMA)
        self._terminal: _Terminal | None = self._read_terminal()

    # -- connection setup ---------------------------------------------------

    def _open_with_retry(self, path: str) -> None:
        """Open the connection + apply the WAL/synchronous PRAGMAs, riding out a TRANSIENT
        reopen ``apsw.IOError`` (§7.7.1 robustness).

        Why this exists: a process killed/crashed inside the :meth:`_persist`
        ``BEGIN IMMEDIATE``..``COMMIT`` window dies holding the WAL write lock. On Windows the
        dead writer's ``-wal``/``-shm`` byte-range locks are released ASYNCHRONOUSLY after the
        process object is signaled, so a fast reopen-after-kill can hit the ``SQLITE_IOERR``
        SHM-lock family on ``PRAGMA journal_mode=WAL`` (the WAL attach), even though the durable
        bytes are intact (acked frames fsync'd, the uncommitted transaction rolled back). A
        reopen that throws instead of recovering makes the durable data momentarily UNREACHABLE
        on restart, against the spirit of §7.7.1. POSIX releases the locks synchronously on
        process death, so this is observed only on the Windows §B cells.

        Bounded: ``len(_REOPEN_BACKOFFS_S) + 1`` attempts, total wait <= ~0.75s. Catches
        ``apsw.IOError`` ONLY — a corrupt-db / auth / any other apsw error surfaces immediately.
        After the final attempt the last ``apsw.IOError`` is RE-RAISED unchanged, so a PERSISTENT
        disk failure (the SAME ``SQLITE_IOERR``) still surfaces, just delayed by the cap; a bad
        disk is never retried into silence. ``busy_timeout`` cannot help here — it only retries
        ``SQLITE_BUSY``/``LOCKED``, not ``SQLITE_IOERR`` — so this explicit retry is required.

        Scoped to the open + PRAGMA attach ONLY. The steady-state path (:meth:`write` /
        :meth:`_persist`) is deliberately NOT wrapped: a normal-operation IOError must surface.
        """
        backoffs = self._REOPEN_BACKOFFS_S
        for attempt in range(len(backoffs) + 1):
            conn = None
            try:
                conn = apsw.Connection(path)
                self._conn = conn
                self._apply_pragmas()
                self._restrict_file_modes(path)
                return
            except apsw.IOError as exc:
                # Close any half-opened handle so a partial connection does not accumulate; a
                # fresh apsw.Connection is created on the next attempt.
                if conn is not None:
                    try:
                        conn.close()
                    except apsw.Error:
                        pass
                if attempt == len(backoffs):
                    raise  # cap reached: re-raise the persistent IOError unchanged (real bad disk)
                # Observability hook for the §B Windows-CI logs: the SQLITE extended result code
                # (e.g. the SHM-lock subcode) on each transient retry. `extendedresult` is the
                # apsw 3.53 attribute; a synthetically-raised IOError lacks it -> None.
                _log.warning(
                    "cephios buffer reopen IOError (attempt %d/%d), retrying in %.0fms; "
                    "SQLITE extended result=%s",
                    attempt + 1,
                    len(backoffs) + 1,
                    backoffs[attempt] * 1000,
                    getattr(exc, "extendedresult", None),
                )
                time.sleep(backoffs[attempt])

    def _apply_pragmas(self) -> None:
        """Pin the §7.7.1 durability PRAGMAs on the production connection.

        ``synchronous=FULL`` (value 2) forces an fsync on every commit — the load-bearing
        persist-before-ack property. ``synchronous=NORMAL`` (1) only fsyncs on checkpoint and
        would silently weaken §7.7.1. The :func:`Buffer._read_pragma` read-back proves these
        took (the config-level red-capable proof).
        """
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")

    def _restrict_file_modes(self, path: str) -> None:
        """Restrict the buffer DB + its ``-wal``/``-shm`` side files to owner-only (0o600) on POSIX.

        apsw/SQLite create the main DB under the process umask (typically 0o644 — world-readable)
        and the ``-wal``/``-shm`` side files at WAL activation (``PRAGMA journal_mode=WAL`` in
        :meth:`_apply_pragmas`), so this runs AFTER the pragmas, once all three exist, and
        re-asserts the mode on every open (a buffer created before this hardening is tightened on
        its next open). The buffer holds only ciphertext (KC, §7.7.1); 0o600 additionally denies
        other local users the ``session_id`` / ``batch_sequence`` / enqueue-time METADATA.

        Setting modes only — no buffer semantics change. POSIX-only: on Windows
        (``os.name == "nt"``) file access is governed by ACLs and ``chmod`` is a no-op, so this is
        skipped and the buffer opens normally either way.
        """
        if os.name == "nt":
            return
        for sidecar in ("", "-wal", "-shm"):
            file = Path(path + sidecar)
            if file.exists():
                file.chmod(0o600)

    def _read_pragma(self, name: str) -> object:
        """Read a PRAGMA value off THIS buffer's production connection (introspection / proof).

        Reads from ``self._conn`` — the production connection — so the value reflects what the
        buffer actually runs under (a sibling connection would carry its own per-connection
        PRAGMA state and defeat the proof; that was the Go reference's fixed bug).
        """
        row = self._conn.execute(f"PRAGMA {name}").fetchone()
        return None if row is None else row[0]

    # -- re-entrancy + event delivery --------------------------------------

    def _guard_reentrancy(self) -> None:
        if self._callback_owner == threading.get_ident():
            raise ReentrantCallbackError(
                "re-entrant call from event callback (the callback must not invoke Buffer "
                "methods on the same thread; dispatch to another thread instead)"
            )

    def _emit(self, event: BufferEvent) -> None:
        """Deliver an event via the synchronous callback (caller holds the lock).

        Direct call — no bounded queue, nothing that can drop the event under load (§7.7.3
        never-silent). If the callback raises, the exception propagates (the "panicking"
        never-silent option); the buffer never swallows it. The callback owner is recorded so a
        same-thread re-entry is detected and rejected with :class:`ReentrantCallbackError`.
        """
        self._callback_owner = threading.get_ident()
        try:
            self._callback(event)
        finally:
            self._callback_owner = None

    # -- public API ---------------------------------------------------------

    def write(self, session_id: UUID, batch_sequence: int, envelope: bytes) -> None:
        """Persist a record durably, then acknowledge (return) to the application (§7.7.1).

        ``envelope`` is opaque, already-encrypted bytes (§6.4 envelope construction output) —
        there is no ``dek`` / ``plaintext`` parameter (KC, §9.8). The bytes are stored and
        returned byte-faithfully (PT, §9.1). The durable key is ``(session_id, batch_sequence)``
        (§7.2 / §7.7.1).

        The persist commits (fsync under ``synchronous=FULL``) BEFORE this method returns:
        the return IS the acknowledgement, so an acked record has already been made durable.

        Capacity handling per :class:`Mode`:

        - ``BLOCK_AND_SIGNAL``: at capacity, emit one :class:`BufferPressure` (debounced to one
          per capacity transition) and block until depth falls below ``low_water_records``.
        - ``DROP_OLDEST``: at capacity, drop the oldest unsent record and emit one
          :class:`BufferDrop` for it, then persist.

        Raises :class:`TerminalLatchError`, :class:`BufferClosedError`, or
        :class:`ReentrantCallbackError`.
        """
        if not isinstance(envelope, (bytes, bytearray)):
            raise TypeError("envelope must be bytes (already-encrypted §6.4 output)")
        self._guard_reentrancy()
        with self._cond:
            self._check_state()
            self._apply_capacity_mode(session_id, batch_sequence)
            self._persist(session_id, batch_sequence, bytes(envelope))

    def pending(self) -> list[tuple[UUID, int, bytes]]:
        """Return the buffered (unsent) records in FIFO order as ``(session_id, seq, envelope)``.

        Safe to call after a process restart: surfaces records persisted before the restart
        (§7.7.1) with their original durable key and byte-faithful envelope (PT, §9.1). The
        Commit 5 uploader consumes this to drain.
        """
        self._guard_reentrancy()
        with self._cond:
            self._check_state()
            return self._list()

    def depth(self) -> int:
        """Return the current number of unsent records buffered."""
        self._guard_reentrancy()
        with self._cond:
            self._check_state()
            return self._count()

    def acknowledge(self, session_id: UUID, batch_sequence: int) -> None:
        """Purge a record after the cloud confirms ``persisted`` / ``deduplicated`` (§7.7.4).

        Idempotent: acknowledging a non-existent key is a no-op. Wakes block-and-signal waiters
        so a drained buffer resumes blocked writes.
        """
        self._guard_reentrancy()
        with self._cond:
            self._check_state()
            self._remove(session_id, batch_sequence)
            self._cond.notify_all()

    def emit_rejected(self, session_id: UUID, batch_sequence: int, reason: str) -> None:
        """Emit a :class:`BufferRejected` event for a non-retryable rejection (§7.7.4).

        This is the never-silent signal the Commit 5 uploader fires when the cloud permanently
        refuses a record. It does NOT purge the record — the EMIT-THEN-PURGE ordering (§7.7.4)
        is: the uploader calls ``emit_rejected`` and only then :meth:`acknowledge`. A crash (or
        a raising callback) between emit and purge leaves the record buffered for the next
        restart (re-uploaded -> re-rejected -> re-emitted; no silent loss). Purging first and
        emitting second would lose both the data and the loss signal — the silent-loss pattern
        §7.7.3 / §7.7.4 exist to prevent.

        ``reason`` must be one of :data:`REJECTED_REASONS` (use :func:`rejected_reason` to
        derive it); a reason outside the closed vocabulary is rejected with ``ValueError`` so a
        string-templated wire code cannot leak onto the event surface (§7.7.3).
        """
        if reason not in REJECTED_REASONS:
            raise ValueError(
                f"reason {reason!r} is not in the closed §7.7.3 BufferRejected vocabulary "
                f"{sorted(REJECTED_REASONS)}; use rejected_reason() to map a CephiosError"
            )
        self._guard_reentrancy()
        with self._cond:
            self._check_state()
            self._emit(BufferRejected(session_id, batch_sequence, reason))

    def fail_permanently(
        self,
        reason: str,
        *,
        lost_record_count: int = 0,
        session_id: UUID | None = None,
    ) -> None:
        """Enter the §7.7.2 permanent-loss terminal state: emit :class:`BufferLost` + latch.

        Emits a :class:`BufferLost` event AND persists a durable latch that survives process
        restart. After this returns, every public method raises :class:`TerminalLatchError`
        until :meth:`clear_terminal_latch` (explicit tenant acknowledgement) — there is no
        silent recovery. Idempotent: if already latched this is a no-op.

        This is the signal + latch mechanism. Wiring an automatic trigger (the uploader drain
        detecting persistent storage write failures / journal corruption) lands in Commit 5;
        Commit 4 lands the detectable, durable terminal surface.
        """
        self._guard_reentrancy()
        with self._cond:
            if self._closed:
                raise BufferClosedError("buffer is closed")
            if self._terminal is not None:
                return
            terminal = _Terminal(
                reason=reason, lost_record_count=lost_record_count, session_id=session_id
            )
            self._set_terminal(terminal)
            self._terminal = terminal
            self._emit(BufferLost(session_id, reason, lost_record_count))
            self._cond.notify_all()  # wake blocked writes so they exit with TerminalLatchError

    def clear_terminal_latch(self) -> None:
        """Clear the §7.7.2 terminal latch (explicit tenant acknowledgement).

        After this returns, public methods no longer raise :class:`TerminalLatchError`. The
        clear is the only path out of the terminal state — required to prevent silent recovery.
        """
        self._guard_reentrancy()
        with self._cond:
            if self._closed:
                raise BufferClosedError("buffer is closed")
            self._clear_terminal()
            self._terminal = None

    def is_terminally_latched(self) -> bool:
        """Whether the buffer is in the §7.7.2 terminal-loss state (latch present)."""
        with self._lock:
            return self._terminal is not None

    def close(self) -> None:
        """Release the storage handle. Idempotent. Does NOT clear the terminal latch.

        A subsequent :class:`Buffer` opened at the same ``storage_path`` re-reads the latch.
        """
        self._guard_reentrancy()
        with self._cond:
            if self._closed:
                return
            self._closed = True
            self._cond.notify_all()  # wake blocked writes so they exit with BufferClosedError
            self._conn.close()

    # -- internal helpers (caller holds the lock) ---------------------------

    def _check_state(self) -> None:
        if self._closed:
            raise BufferClosedError("buffer is closed")
        if self._terminal is not None:
            raise TerminalLatchError(
                "buffer is in terminal-loss state; clear_terminal_latch() to recover"
            )

    def _apply_capacity_mode(self, session_id: UUID, batch_sequence: int) -> None:
        """Engage the configured backpressure mode if at/over capacity (caller holds the lock).

        After this returns the buffer has at least one free slot for the pending write.
        """
        if self._count() < self._capacity:
            return

        if self._mode is Mode.BLOCK_AND_SIGNAL:
            # Emit BufferPressure on the transition into capacity (debounced to one per
            # capacity hit, not one per blocked write), THEN block. Blocking without the
            # paired event is non-conformant (§7.7.2) — the emit and the block are inseparable.
            if not self._at_pressure:
                self._at_pressure = True
                self._emit(
                    BufferPressure(
                        session_id=session_id,
                        batch_sequence=batch_sequence,
                        reason="capacity_reached",
                        buffer_depth=self._count(),
                    )
                )
            # Wait until depth falls strictly below low-water. cond.wait releases the lock,
            # waits for a notify from acknowledge/close/fail_permanently, and re-acquires it.
            while True:
                if self._closed:
                    raise BufferClosedError("buffer is closed")
                if self._terminal is not None:
                    raise TerminalLatchError(
                        "buffer entered terminal-loss state while blocked; clear_terminal_latch()"
                    )
                if self._count() < self._low_water:
                    self._at_pressure = False
                    return
                self._cond.wait()
        else:  # Mode.DROP_OLDEST
            oldest = self._oldest()
            if oldest is None:
                return  # raced below capacity between count and oldest; slot is free
            drop_sid, drop_seq = oldest
            self._remove(drop_sid, drop_seq)
            self._emit(BufferDrop(drop_sid, drop_seq, "buffer_full"))

    # -- storage layer (caller holds the lock; apsw connection is single-owner) --

    def _persist(self, session_id: UUID, batch_sequence: int, envelope: bytes) -> None:
        """Durably commit one record. The COMMIT (fsync under synchronous=FULL) is the
        persist point that MUST precede the write() return (the ack). Split into an explicit
        BEGIN/INSERT/COMMIT so the commit is a single, isolatable step (see :meth:`_commit`)."""
        self._conn.execute("BEGIN IMMEDIATE")
        self._conn.execute(
            "INSERT INTO records (session_id, batch_sequence, envelope, enqueued_at) "
            "VALUES (?, ?, ?, ?)",
            (session_id.bytes, batch_sequence, envelope, time.time_ns()),
        )
        self._commit()

    def _commit(self) -> None:
        """Commit the open transaction — the durable persist point (fsync under FULL)."""
        self._conn.execute("COMMIT")

    def _list(self) -> list[tuple[UUID, int, bytes]]:
        rows = self._conn.execute(
            "SELECT session_id, batch_sequence, envelope FROM records "
            "ORDER BY enqueued_at ASC, batch_sequence ASC"
        ).fetchall()
        # apsw column values are a None|int|float|str|bytes union; the schema fixes these
        # columns to BLOB/INTEGER/BLOB so we cast to the known types.
        return [
            (UUID(bytes=cast(bytes, sid)), cast(int, seq), bytes(cast(bytes, env)))
            for sid, seq, env in rows
        ]

    def _oldest(self) -> tuple[UUID, int] | None:
        row = self._conn.execute(
            "SELECT session_id, batch_sequence FROM records "
            "ORDER BY enqueued_at ASC, batch_sequence ASC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return UUID(bytes=cast(bytes, row[0])), int(cast(int, row[1]))

    def _remove(self, session_id: UUID, batch_sequence: int) -> None:
        self._conn.execute(
            "DELETE FROM records WHERE session_id = ? AND batch_sequence = ?",
            (session_id.bytes, batch_sequence),
        )

    def _count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM records").fetchone()
        assert row is not None  # COUNT(*) always returns exactly one row
        return int(cast(int, row[0]))

    def _read_terminal(self) -> _Terminal | None:
        row = self._conn.execute(
            "SELECT reason, lost_record_count, session_id FROM terminal_latch WHERE id = 1"
        ).fetchone()
        if row is None:
            return None
        reason, lost_count, sid_bytes = row
        return _Terminal(
            reason=cast(str, reason),
            lost_record_count=int(cast(int, lost_count)),
            session_id=UUID(bytes=cast(bytes, sid_bytes)) if sid_bytes is not None else None,
        )

    def _set_terminal(self, terminal: _Terminal) -> None:
        sid_bytes = terminal.session_id.bytes if terminal.session_id is not None else None
        self._conn.execute("BEGIN IMMEDIATE")
        self._conn.execute(
            "INSERT OR REPLACE INTO terminal_latch "
            "(id, reason, lost_record_count, latched_at, session_id) VALUES (1, ?, ?, ?, ?)",
            (terminal.reason, terminal.lost_record_count, time.time_ns(), sid_bytes),
        )
        self._commit()

    def _clear_terminal(self) -> None:
        self._conn.execute("DELETE FROM terminal_latch WHERE id = 1")
