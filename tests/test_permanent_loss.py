"""Automatic permanent-loss detection — the §7.7.2 terminal auto-trigger (WATCHPOINT 2).

CONTRACT_SPEC.md §7.7.2 + CLAUDE.md §9.2 (ND): a PERSISTENT buffer-storage write failure on the
steady-state ``_persist`` path (disk full, I/O error OUTSIDE the bounded reopen window) MUST
convert to ``Buffer.fail_permanently(...)`` → ``BufferLost`` + a durable terminal latch — it
MUST NOT propagate as a raw apsw exception.

Where C5a detects it: :func:`cephios_core.uploader.capture` wraps :meth:`Buffer.write` in
``_write_durably``. The transient/persistent line is C4's: the bounded
``Buffer._open_with_retry`` rides out the only known transient (the reopen-window IOError after
a kill); ``write`` / ``_persist`` is deliberately unwrapped, so ANY ``apsw.Error`` escaping
``Buffer.write`` is post-transient = persistent by construction. Here a synthetic persistent
``_persist`` failure stands in for the bad disk (the real Windows lock-rundown timing is not
locally reproducible, per the C4 ``test_buffer_nd`` precedent).

RED-CAPABLE: with the auto-trigger removed (``_write_durably`` reduced to a bare
``buffer.write``), the raw ``apsw.FullError`` propagates out of ``capture`` and the
``pytest.raises(PermanentStorageLossError)`` below fails "DID NOT RAISE" with the apsw error
surfacing instead — verbatim capture in the commit body.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import apsw
import pytest

from cephios_core.buffer import (
    Buffer,
    BufferConfig,
    BufferEvent,
    BufferLost,
    Mode,
    TerminalLatchError,
)
from cephios_core.uploader import PermanentStorageLossError, capture

_DEK = os.urandom(32)
_SID = uuid.uuid4()


def _buffer(tmp_path: Path, events: list[BufferEvent]) -> Buffer:
    return Buffer(
        BufferConfig(
            storage_path=tmp_path / "buffer.db",
            capacity_records=8,
            low_water_records=4,
            mode=Mode.BLOCK_AND_SIGNAL,
            event_callback=events.append,
        )
    )


def test_persistent_persist_failure_converts_to_bufferlost(tmp_path, monkeypatch):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        # Inject a persistent storage failure on the records-table write (the _persist seam).
        # _set_terminal (the latch write) uses _commit directly, NOT _persist, so the latch can
        # still persist and BufferLost can still emit — the specified §7.7.2 scenario.
        def boom(self, session_id, batch_sequence, env):
            raise apsw.FullError("database or disk is full (synthetic persistent)")

        monkeypatch.setattr(Buffer, "_persist", boom)

        with pytest.raises(PermanentStorageLossError) as excinfo:
            capture(buffer, dek=_DEK, session_id=_SID, batch_sequence=0, plaintext=b"sample")

        # Converted, NOT propagated raw: the raised type is the SDK exception, the apsw error is
        # only its __cause__.
        assert isinstance(excinfo.value, PermanentStorageLossError)
        assert isinstance(excinfo.value.__cause__, apsw.FullError)

        # The never-silent BufferLost fired and the durable terminal latch is set (§7.7.2).
        lost = [e for e in events if isinstance(e, BufferLost)]
        assert len(lost) == 1
        assert lost[0].reason == "storage_failure"
        assert lost[0].session_id is None  # buffer-wide, not session-scoped
        assert buffer.is_terminally_latched()
    finally:
        buffer.close()


def test_no_raw_apsw_error_escapes_capture(tmp_path, monkeypatch):
    # The contract is specifically "NOT propagate as a raw apsw exception": capture must never
    # raise apsw.Error to the application.
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        def boom(self, session_id, batch_sequence, env):
            raise apsw.IOError("disk I/O error (synthetic persistent)")

        monkeypatch.setattr(Buffer, "_persist", boom)
        with pytest.raises(PermanentStorageLossError):
            capture(buffer, dek=_DEK, session_id=_SID, batch_sequence=0, plaintext=b"x")
        # The SDK exception is NOT an apsw error type — a raw apsw.Error can never reach the app.
        assert not issubclass(PermanentStorageLossError, apsw.Error)
    finally:
        buffer.close()


def test_terminal_latch_survives_and_blocks_subsequent_capture(tmp_path, monkeypatch):
    # After the auto-trigger latches, a subsequent capture surfaces the terminal state via
    # TerminalLatchError (Buffer.write._check_state runs before _persist) — no silent recovery.
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        monkeypatch.setattr(
            Buffer, "_persist",
            lambda self, s, b, e: (_ for _ in ()).throw(apsw.FullError("full")),
        )
        with pytest.raises(PermanentStorageLossError):
            capture(buffer, dek=_DEK, session_id=_SID, batch_sequence=0, plaintext=b"a")
        # Now latched: a second capture refuses with the terminal-state exception.
        with pytest.raises(TerminalLatchError):
            capture(buffer, dek=_DEK, session_id=_SID, batch_sequence=1, plaintext=b"b")
    finally:
        buffer.close()


def test_constraint_error_is_not_permanent_loss(tmp_path, monkeypatch):
    # A duplicate-PK ConstraintError is an idempotency/logic condition (§7.2), NOT a durability
    # failure: it must re-raise unchanged, and must NOT latch the buffer terminal.
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        def conflict(self, session_id, batch_sequence, env):
            raise apsw.ConstraintError("UNIQUE constraint failed: records primary key")

        monkeypatch.setattr(Buffer, "_persist", conflict)
        with pytest.raises(apsw.ConstraintError):
            capture(buffer, dek=_DEK, session_id=_SID, batch_sequence=0, plaintext=b"dup")
        assert not buffer.is_terminally_latched()
        assert not any(isinstance(e, BufferLost) for e in events)
    finally:
        buffer.close()
