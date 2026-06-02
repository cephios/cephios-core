"""Process-kill durability — the Group-8-deferred behavioral proof, landed (CS §7.7.1).

A child process opens the PRODUCTION buffer, writes + acks N records, then is killed
mid-life with proc.kill() (cross-OS: SIGKILL on POSIX / TerminateProcess on Windows — NOT
os.kill(pid, SIGKILL), which has no SIGKILL on Windows). The child never closes the buffer,
so there is no graceful flush. The parent reopens the same storage path and asserts the
acked records survived byte- and identity-faithfully, and that the §7.7.2 terminal latch
likewise survives a kill.

RED-CAPABILITY — read this carefully (a §17.4 / §11.2 proof-discipline point):

  The headline durability property is persist-before-ack. With apsw's literal commit
  control, "persist" is a COMMIT, so the property is *commit-before-ack* — and that IS
  catchable by a process kill: an uncommitted SQLite transaction is rolled back on reopen.
  test_process_kill_ack_before_commit_is_lossy injects the ack-before-commit mutation
  (_commit -> no-op) and shows the record does NOT survive the kill — the durability proof
  can go red.

  The go-bericht framed the kill red as "synchronous=NORMAL ... loses records after the
  kill." That specific red is NOT achievable with proc.kill and is deliberately NOT claimed
  here: proc.kill terminates the user-space process but not the kernel, so records that
  reached the page cache (which they do under synchronous=NORMAL — the WAL frames are
  write()'n, just not fsync'd) survive a process kill; only a power loss / kernel crash
  loses them. This is the exact Group-8 lesson the reference Go suite learned (it removed a
  SIGKILL-based sync=OFF test for being non-red-capable). So the synchronous=FULL SETTING is
  proven red-capably by the PRAGMA read-back (test_pragma_readback_* in test_buffer.py,
  red via _apply_pragmas -> OFF), and the kill test proves the behavioral commit-before-ack
  ordering (red via ack-before-commit). Together they cover §7.7.1 honestly; neither
  overclaims.
"""

from __future__ import annotations

import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from cephios_core.buffer import Buffer, BufferConfig, Mode, TerminalLatchError

# The child program. Shares the deterministic envelope function with the parent so the
# parent can assert byte-faithful survival. Uses only the public production surface (+ the
# documented _commit seam for the ack-before-commit red mutation).
_CHILD = r"""
import sys, time
from pathlib import Path
from uuid import UUID
from cephios_core.buffer import Buffer, BufferConfig, Mode

action = sys.argv[1]        # "write" | "write_ack_before_commit" | "terminal"
db_path = sys.argv[2]
ready_path = sys.argv[3]
n = int(sys.argv[4])
sid = UUID(sys.argv[5])

def envb(i):
    body = bytes(((i + k) & 0xFF) for k in range(60))
    return b"\xce\x0f\x01\x01" + body

buf = Buffer(BufferConfig(
    storage_path=Path(db_path),
    capacity_records=8192,
    low_water_records=4096,
    mode=Mode.BLOCK_AND_SIGNAL,
    event_callback=lambda ev: None,
))

if action == "write":
    for i in range(n):
        buf.write(sid, i, envb(i))
elif action == "write_ack_before_commit":
    # RED mutation: ack the application BEFORE the durable commit. With _commit a no-op the
    # INSERT stays in an open, uncommitted transaction; write() still returns (acks). N is 1
    # because a second BEGIN IMMEDIATE on an open transaction would error.
    buf._commit = lambda: None
    buf.write(sid, 0, envb(0))
elif action == "terminal":
    buf.fail_permanently("storage_failure", lost_record_count=5)
else:
    sys.exit(2)

# All writes have returned (acked). Signal readiness, then idle WITHOUT closing the buffer
# (no graceful flush) so the parent can kill mid-life.
Path(ready_path).write_text("ready")
time.sleep(60)
"""


def _envb(i: int) -> bytes:
    body = bytes(((i + k) & 0xFF) for k in range(60))
    return b"\xce\x0f\x01\x01" + body


def _spawn_and_kill(tmp_path, action: str, db_path: Path, n: int, sid: uuid.UUID) -> None:
    """Run the child, wait until it has written+acked, then proc.kill() it mid-life."""
    child_py = tmp_path / "nd_child.py"
    child_py.write_text(_CHILD)
    ready = tmp_path / "child.ready"
    argv = [sys.executable, str(child_py), action, str(db_path), str(ready), str(n), str(sid)]
    proc = subprocess.Popen(argv)
    try:
        deadline = time.monotonic() + 15
        while not ready.exists():
            if proc.poll() is not None:
                raise AssertionError(f"child exited early (rc={proc.returncode}) before write")
            if time.monotonic() > deadline:
                raise AssertionError("child did not become ready within 15s")
            time.sleep(0.02)
    finally:
        proc.kill()  # cross-OS hard kill (SIGKILL on POSIX, TerminateProcess on Windows)
        proc.wait()  # ensure the process is gone (OS releases its WAL/-shm locks) before reopen


def test_process_kill_durability_resume(tmp_path):
    # GREEN: N acked records survive a real proc.kill() and resume byte/identity-faithfully.
    db = tmp_path / "buffer.db"
    sid = uuid.uuid4()
    n = 20
    _spawn_and_kill(tmp_path, "write", db, n, sid)

    reopened = Buffer(
        BufferConfig(
            storage_path=db,
            capacity_records=8192,
            low_water_records=4096,
            mode=Mode.BLOCK_AND_SIGNAL,
            event_callback=lambda _ev: None,
        )
    )
    try:
        pending = reopened.pending()
        assert len(pending) == n, (
            f"acked records must survive proc.kill (§7.7.1); got {len(pending)}"
        )
        for i, (got_sid, got_seq, got_env) in enumerate(pending):
            assert got_sid == sid
            assert got_seq == i  # FIFO order preserved across the kill
            assert got_env == _envb(i)  # byte-faithful (PT) across the kill
    finally:
        reopened.close()


def test_process_kill_ack_before_commit_is_lossy(tmp_path):
    # RED-CAPABILITY LOCK: under the ack-before-commit mutation, the acked record does NOT
    # survive the kill — proving the durability proof above can go red. If this ever shows
    # the record surviving, the persist-before-ack ordering has stopped being load-bearing.
    db = tmp_path / "buffer.db"
    sid = uuid.uuid4()
    _spawn_and_kill(tmp_path, "write_ack_before_commit", db, 1, sid)

    reopened = Buffer(
        BufferConfig(
            storage_path=db,
            capacity_records=8192,
            low_water_records=4096,
            mode=Mode.BLOCK_AND_SIGNAL,
            event_callback=lambda _ev: None,
        )
    )
    try:
        assert reopened.pending() == [], (
            "ack-before-commit must lose the record after a kill (the uncommitted transaction "
            "rolls back) — this is what makes commit-before-ack load-bearing"
        )
    finally:
        reopened.close()


def test_process_kill_terminal_latch_survives(tmp_path):
    # The §7.7.2 permanent-loss latch must survive a real process kill and surface on reopen.
    db = tmp_path / "buffer.db"
    sid = uuid.uuid4()
    _spawn_and_kill(tmp_path, "terminal", db, 0, sid)

    reopened = Buffer(
        BufferConfig(
            storage_path=db,
            capacity_records=8,
            low_water_records=4,
            mode=Mode.BLOCK_AND_SIGNAL,
            event_callback=lambda _ev: None,
        )
    )
    try:
        assert reopened.is_terminally_latched()
        with pytest.raises(TerminalLatchError):
            reopened.write(sid, 0, b"\xce\x0f\x01\x01payload")
        reopened.clear_terminal_latch()  # explicit tenant-ack recovers
        reopened.write(sid, 0, b"\xce\x0f\x01\x01payload")
        assert reopened.depth() == 1
    finally:
        reopened.close()
