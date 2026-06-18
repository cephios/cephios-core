"""SDK durable buffer behavior (CONTRACT_SPEC.md §7.7.1-§7.7.4).

Covers the ND-load-bearing properties: persist-before-ack (commit-before-ack), the
config-level PRAGMA read-back (synchronous=FULL / WAL), durable-key stability across
restart, block-and-signal (block + emit), drop-oldest (drop + one event per record),
the permanent-loss latch surviving restart, never-silent delivery (no swallow / no
droppable queue), the re-entrancy guard, emit-then-purge ordering, and PT byte-faithfulness.

Each property is red-capable: the commit body records the verbatim red-then-green capture
produced by mutating the production seam under test (e.g. PRAGMA -> OFF, commit -> no-op,
emit -> suppressed). Durability uses a real temp FILE (never :memory:) so the WAL sidecars
and reopen semantics are exercised; the process-kill durability proof lives in
test_buffer_nd.py.
"""

from __future__ import annotations

import os
import threading
import uuid

import apsw
import pytest

from cephios_core.buffer import (
    Buffer,
    BufferClosedError,
    BufferConfig,
    BufferConfigError,
    BufferDrop,
    BufferEvent,
    BufferLost,
    BufferPressure,
    BufferRejected,
    Mode,
    ReentrantCallbackError,
    TerminalLatchError,
)


def _sid() -> uuid.UUID:
    return uuid.uuid4()


def _env(tag: int, size: int = 64) -> bytes:
    """Deterministic opaque envelope bytes carrying the §6.1 magic (opaque to the buffer)."""
    body = bytes(((tag + i) & 0xFF) for i in range(size - 4))
    return b"\xce\x0f\x01\x01" + body


class _Sink:
    """Records every delivered event (the application's never-silent observation surface)."""

    def __init__(self) -> None:
        self.events: list[BufferEvent] = []

    def __call__(self, event: BufferEvent) -> None:
        self.events.append(event)


def _open(tmp_path, **overrides) -> tuple[Buffer, _Sink]:
    sink = _Sink()
    cfg = BufferConfig(
        storage_path=tmp_path / "buffer.db",
        capacity_records=overrides.pop("capacity_records", 8),
        low_water_records=overrides.pop("low_water_records", 4),
        mode=overrides.pop("mode", Mode.BLOCK_AND_SIGNAL),
        event_callback=overrides.pop("event_callback", sink),
    )
    assert not overrides, f"unknown overrides: {overrides}"
    return Buffer(cfg), sink


# ---------------------------------------------------------------------------
# Config validation.
# ---------------------------------------------------------------------------


def test_config_requires_callback(tmp_path):
    # never-silent obligation (§7.7.3): a buffer cannot start without a delivery surface.
    with pytest.raises(BufferConfigError):
        Buffer(
            BufferConfig(
                storage_path=tmp_path / "b.db",
                capacity_records=8,
                low_water_records=4,
                event_callback=None,  # type: ignore[arg-type]
            )
        )


@pytest.mark.parametrize("capacity,low_water", [(0, 0), (8, 0), (8, 8), (8, 9)])
def test_config_rejects_bad_capacity_low_water(tmp_path, capacity, low_water):
    with pytest.raises(BufferConfigError):
        Buffer(
            BufferConfig(
                storage_path=tmp_path / "b.db",
                capacity_records=capacity,
                low_water_records=low_water,
                event_callback=lambda _ev: None,
            )
        )


# ---------------------------------------------------------------------------
# §7.7.1 persist-before-ack (commit-before-ack) + PT byte-faithfulness + KC opacity.
# ---------------------------------------------------------------------------


def test_persist_before_ack_visible_to_fresh_connection(tmp_path):
    # When write() returns (the ack), the record is already committed: a SEPARATE read-only
    # connection sees it. An ack-before-commit buffer would leave the row uncommitted and the
    # fresh connection would not see it. RED-CAPABLE via _commit -> no-op (see commit body).
    buf, _ = _open(tmp_path)
    sid = _sid()
    buf.write(sid, 0, _env(0))

    other = apsw.Connection(str(tmp_path / "buffer.db"), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        n = other.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    finally:
        other.close()
    assert n == 1, "record must be durably committed before write() acknowledges (§7.7.1)"
    buf.close()


def test_pt_byte_faithful_roundtrip(tmp_path):
    # PT (§9.1): in == out. The envelope bytes stored and returned are byte-identical.
    buf, _ = _open(tmp_path)
    sid = _sid()
    payloads = {i: _env(i, size=33 + i) for i in range(5)}
    for seq, env in payloads.items():
        buf.write(sid, seq, env)
    got = {seq: env for (_s, seq, env) in buf.pending()}
    assert got == payloads
    buf.close()


def test_empty_and_arbitrary_bytes_are_opaque(tmp_path):
    # The buffer is bytes-opaque (no §6.1 inspection / no transform): any bytes round-trip.
    buf, _ = _open(tmp_path)
    sid = _sid()
    raw = b"\x00\x01\x02not-an-envelope\xff"
    buf.write(sid, 0, raw)
    assert buf.pending()[0][2] == raw
    buf.close()


def test_write_rejects_non_bytes(tmp_path):
    buf, _ = _open(tmp_path)
    with pytest.raises(TypeError):
        buf.write(_sid(), 0, "plaintext-string")  # type: ignore[arg-type]
    buf.close()


# ---------------------------------------------------------------------------
# §7.7.1 config-level durability: PRAGMA read-back on the PRODUCTION connection.
# ---------------------------------------------------------------------------


def test_pragma_readback_wal_and_synchronous_full(tmp_path):
    # The load-bearing config-level proof. Read PRAGMAs off the buffer's OWN connection.
    # RED-CAPABLE via _apply_pragmas -> synchronous=OFF (see commit body): read-back != 2.
    buf, _ = _open(tmp_path)
    assert buf._read_pragma("journal_mode") == "wal"
    assert buf._read_pragma("synchronous") == 2  # 0=OFF 1=NORMAL 2=FULL
    assert buf._read_pragma("foreign_keys") == 1
    buf.close()


def test_wal_sidecar_files_created(tmp_path):
    # WAL mode materializes -wal / -shm sidecars next to the DB (pathlib, no /tmp hardcode).
    buf, _ = _open(tmp_path)
    buf.write(_sid(), 0, _env(0))
    names = {p.name for p in tmp_path.iterdir()}
    assert "buffer.db" in names
    assert "buffer.db-wal" in names
    buf.close()


# ---------------------------------------------------------------------------
# §7.7.1 durable-key stability across restart.
# ---------------------------------------------------------------------------


def test_identity_stable_across_restart(tmp_path):
    # The resumed buffer re-issues the SAME (session_id, batch_sequence) so cloud dedup works.
    # RED-CAPABLE via persist storing a mangled key (see commit body).
    sid = _sid()
    buf, _ = _open(tmp_path)
    for seq in range(3):
        buf.write(sid, seq, _env(seq))
    buf.close()

    reopened, _ = _open(tmp_path)
    keys = [(s, seq) for (s, seq, _e) in reopened.pending()]
    assert keys == [(sid, 0), (sid, 1), (sid, 2)]
    reopened.close()


# ---------------------------------------------------------------------------
# §7.7.4 acknowledge purges; idempotent.
# ---------------------------------------------------------------------------


def test_acknowledge_purges_and_is_idempotent(tmp_path):
    buf, _ = _open(tmp_path)
    sid = _sid()
    buf.write(sid, 0, _env(0))
    buf.write(sid, 1, _env(1))
    buf.acknowledge(sid, 0)
    assert [seq for (_s, seq, _e) in buf.pending()] == [1]
    buf.acknowledge(sid, 0)  # double-ack is a no-op
    buf.acknowledge(sid, 99)  # non-existent is a no-op
    assert buf.depth() == 1
    buf.close()


# ---------------------------------------------------------------------------
# §7.7.2 block-and-signal: at capacity, write BLOCKS and BufferPressure EMITS.
# ---------------------------------------------------------------------------


def test_block_and_signal_blocks_and_emits(tmp_path):
    # RED-CAPABLE via suppressing the BufferPressure emit (see commit body): a write that
    # blocks WITHOUT emitting is non-conformant (§7.7.2).
    buf, sink = _open(tmp_path, capacity_records=2, low_water_records=1)
    sid = _sid()
    buf.write(sid, 0, _env(0))
    buf.write(sid, 1, _env(1))  # now at capacity (2)

    started = threading.Event()
    finished = threading.Event()

    def blocked_write() -> None:
        started.set()
        buf.write(sid, 2, _env(2))  # must block until depth < low_water (1)
        finished.set()

    t = threading.Thread(target=blocked_write, daemon=True)
    t.start()
    started.wait(timeout=2)

    # The write must be blocked (not finished) AND BufferPressure must have been emitted.
    assert not finished.wait(timeout=0.3), "write must block at capacity (§7.7.2)"
    pressure = [e for e in sink.events if isinstance(e, BufferPressure)]
    assert len(pressure) == 1, "block-without-emit is non-conformant (§7.7.2)"
    assert pressure[0].reason == "capacity_reached"
    assert pressure[0].batch_sequence == 2
    assert pressure[0].buffer_depth == 2

    # Drain below low-water; the blocked write resumes and completes.
    buf.acknowledge(sid, 0)
    buf.acknowledge(sid, 1)
    assert finished.wait(timeout=2), "blocked write must resume once below low-water (§7.7.2)"
    t.join(timeout=2)
    assert {seq for (_s, seq, _e) in buf.pending()} == {2}
    buf.close()


def test_block_and_signal_close_releases_waiter(tmp_path):
    # close() must wake a blocked writer (never a silent hang); it exits with BufferClosedError.
    buf, _ = _open(tmp_path, capacity_records=2, low_water_records=1)
    sid = _sid()
    buf.write(sid, 0, _env(0))
    buf.write(sid, 1, _env(1))

    started = threading.Event()
    result: dict[str, BaseException | None] = {"err": None}

    def blocked_write() -> None:
        started.set()
        try:
            buf.write(sid, 2, _env(2))
        except BaseException as exc:  # noqa: BLE001 - capture the wake-up disposition
            result["err"] = exc

    t = threading.Thread(target=blocked_write, daemon=True)
    t.start()
    started.wait(timeout=2)
    assert not t.join(timeout=0.3) and t.is_alive()
    buf.close()
    t.join(timeout=2)
    assert isinstance(result["err"], BufferClosedError)


# ---------------------------------------------------------------------------
# §7.7.2 drop-oldest: drop the oldest unsent record + emit ONE BufferDrop per record.
# ---------------------------------------------------------------------------


def test_drop_oldest_drops_and_emits_one_per_record(tmp_path):
    # RED-CAPABLE via suppressing the BufferDrop emit (see commit body): a drop WITHOUT an
    # event is non-conformant (§7.7.2).
    buf, sink = _open(tmp_path, capacity_records=2, low_water_records=1, mode=Mode.DROP_OLDEST)
    sid = _sid()
    buf.write(sid, 0, _env(0))
    buf.write(sid, 1, _env(1))  # at capacity
    buf.write(sid, 2, _env(2))  # drops oldest (seq 0), emits one BufferDrop
    buf.write(sid, 3, _env(3))  # drops oldest (seq 1), emits one BufferDrop

    drops = [e for e in sink.events if isinstance(e, BufferDrop)]
    assert len(drops) == 2, "exactly one BufferDrop per dropped record (§7.7.2)"
    assert [(d.session_id, d.batch_sequence) for d in drops] == [(sid, 0), (sid, 1)]
    assert all(d.reason == "buffer_full" for d in drops)
    assert {seq for (_s, seq, _e) in buf.pending()} == {2, 3}
    buf.close()


# ---------------------------------------------------------------------------
# §7.7.2 permanent-loss: BufferLost + durable latch surviving restart; no silent recovery.
# ---------------------------------------------------------------------------


def test_permanent_loss_latch_survives_restart(tmp_path):
    # RED-CAPABLE via _set_terminal -> no-op (see commit body): without the durable latch the
    # reopened buffer would silently recover (Write succeeds) instead of surfacing terminal.
    buf, sink = _open(tmp_path)
    sid = _sid()
    buf.fail_permanently("storage_failure", lost_record_count=3, session_id=sid)

    lost = [e for e in sink.events if isinstance(e, BufferLost)]
    assert len(lost) == 1
    assert lost[0].reason == "storage_failure"
    assert lost[0].lost_record_count == 3
    assert lost[0].session_id == sid

    # Terminal surfaces on every op before restart...
    with pytest.raises(TerminalLatchError):
        buf.write(sid, 0, _env(0))
    buf.close()

    # ...and the latch SURVIVES restart (no silent recovery).
    reopened, _ = _open(tmp_path)
    assert reopened.is_terminally_latched()
    with pytest.raises(TerminalLatchError):
        reopened.write(sid, 0, _env(0))
    with pytest.raises(TerminalLatchError):
        reopened.pending()

    # Explicit tenant acknowledgement clears it (§7.7.2).
    reopened.clear_terminal_latch()
    reopened.write(sid, 0, _env(0))  # recovered
    assert reopened.depth() == 1
    reopened.close()


def test_fail_permanently_is_idempotent(tmp_path):
    buf, sink = _open(tmp_path)
    buf.fail_permanently("journal_corruption")
    buf.fail_permanently("journal_corruption")  # no-op
    assert len([e for e in sink.events if isinstance(e, BufferLost)]) == 1
    buf.close()


def test_permanent_loss_wakes_blocked_writer(tmp_path):
    # A blocked writer must be woken by fail_permanently and exit with TerminalLatchError.
    buf, _ = _open(tmp_path, capacity_records=2, low_water_records=1)
    sid = _sid()
    buf.write(sid, 0, _env(0))
    buf.write(sid, 1, _env(1))

    started = threading.Event()
    result: dict[str, BaseException | None] = {"err": None}

    def blocked_write() -> None:
        started.set()
        try:
            buf.write(sid, 2, _env(2))
        except BaseException as exc:  # noqa: BLE001
            result["err"] = exc

    t = threading.Thread(target=blocked_write, daemon=True)
    t.start()
    started.wait(timeout=2)
    assert t.is_alive()
    # fail_permanently is called from another thread (the blocked writer holds no lock while
    # waiting on the condition).
    buf.fail_permanently("loss_tolerance_exceeded")
    t.join(timeout=2)
    assert isinstance(result["err"], TerminalLatchError)
    buf.close()


# ---------------------------------------------------------------------------
# §7.7.4 BufferRejected emit-then-purge ordering.
# ---------------------------------------------------------------------------


def test_emit_rejected_does_not_purge(tmp_path):
    # emit_rejected emits the never-silent signal but does NOT purge — the C5 uploader purges
    # AFTER (emit-then-purge, §7.7.4). RED-CAPABLE via emit_rejected purging the record (then
    # the post-emit "still present" assertion fails).
    buf, sink = _open(tmp_path)
    sid = _sid()
    buf.write(sid, 0, _env(0))

    buf.emit_rejected(sid, 0, "rejected_batch_too_large")
    rejected = [e for e in sink.events if isinstance(e, BufferRejected)]
    assert len(rejected) == 1
    assert (rejected[0].session_id, rejected[0].batch_sequence) == (sid, 0)
    assert rejected[0].reason == "rejected_batch_too_large"
    # The record is STILL buffered after emit — the caller purges next.
    assert buf.depth() == 1, "emit_rejected must NOT purge (emit-then-purge ordering, §7.7.4)"

    buf.acknowledge(sid, 0)  # the explicit post-emit purge
    assert buf.depth() == 0
    buf.close()


def test_emit_rejected_raising_callback_leaves_record(tmp_path):
    # If the never-silent delivery raises (or a crash occurs) BETWEEN emit and purge, the
    # record must remain buffered (re-uploaded -> re-rejected -> re-emitted; no silent loss).
    boom = RuntimeError("handler refused")

    def raising(_ev: BufferEvent) -> None:
        raise boom

    buf, _ = _open(tmp_path, event_callback=raising)
    sid = _sid()
    buf.write(sid, 0, _env(0))
    with pytest.raises(RuntimeError):
        buf.emit_rejected(sid, 0, "rejected_malformed")
    # No purge happened (the caller never reached acknowledge): the record survives. depth()
    # emits no event, so the raising callback is not invoked on this read path.
    assert buf.depth() == 1
    buf.close()


def test_emit_rejected_validates_reason_vocabulary(tmp_path):
    # A reason outside the closed §7.7.3 set is rejected so a string-templated wire code
    # cannot leak onto the event surface.
    buf, _ = _open(tmp_path)
    with pytest.raises(ValueError):
        buf.emit_rejected(_sid(), 0, "rejected_some_server_code")
    buf.close()


# ---------------------------------------------------------------------------
# §7.7.3/§7.7.4 never-silent delivery: the callback is not swallowed and has no queue.
# ---------------------------------------------------------------------------


def test_never_silent_delivery_does_not_swallow(tmp_path):
    # RED-CAPABLE via _emit wrapping the callback in try/except: pass (a log-only / dropping
    # primitive): then the exception would NOT propagate and this test fails.
    boom = RuntimeError("delivery observed")

    def raising(_ev: BufferEvent) -> None:
        raise boom

    buf, _ = _open(
        tmp_path,
        capacity_records=2,
        low_water_records=1,
        mode=Mode.DROP_OLDEST,
        event_callback=raising,
    )
    sid = _sid()
    buf.write(sid, 0, _env(0))
    buf.write(sid, 1, _env(1))
    with pytest.raises(RuntimeError) as exc:
        buf.write(sid, 2, _env(2))  # triggers BufferDrop -> raising callback must propagate
    assert exc.value is boom
    buf.close()


# ---------------------------------------------------------------------------
# §7.7.4 re-entrancy: a callback re-entering the buffer is rejected, not deadlocked / silent.
# ---------------------------------------------------------------------------


def test_reentrant_callback_is_rejected(tmp_path):
    # The callback runs while the non-reentrant lock is held; a same-thread re-entry would
    # deadlock. The buffer detects it by thread identity and raises ReentrantCallbackError.
    captured: dict[str, BaseException | None] = {"err": None}
    buf_holder: dict[str, Buffer] = {}

    def reentrant(ev: BufferEvent) -> None:
        try:
            buf_holder["buf"].acknowledge(_sid(), 0)  # re-enter on the same thread
        except BaseException as exc:  # noqa: BLE001
            captured["err"] = exc

    buf, _ = _open(
        tmp_path,
        capacity_records=2,
        low_water_records=1,
        mode=Mode.DROP_OLDEST,
        event_callback=reentrant,
    )
    buf_holder["buf"] = buf
    sid = _sid()
    buf.write(sid, 0, _env(0))
    buf.write(sid, 1, _env(1))
    buf.write(sid, 2, _env(2))  # fires BufferDrop -> reentrant handler -> rejected
    assert isinstance(captured["err"], ReentrantCallbackError)
    # The buffer is NOT deadlocked: subsequent ops still work.
    assert buf.depth() == 2
    buf.close()


# ---------------------------------------------------------------------------
# Closed-state behavior.
# ---------------------------------------------------------------------------


def test_methods_raise_after_close(tmp_path):
    buf, _ = _open(tmp_path)
    buf.close()
    buf.close()  # idempotent
    sid = _sid()
    with pytest.raises(BufferClosedError):
        buf.write(sid, 0, _env(0))
    with pytest.raises(BufferClosedError):
        buf.pending()
    with pytest.raises(BufferClosedError):
        buf.acknowledge(sid, 0)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes; Windows uses ACLs, not chmod")
def test_buffer_files_are_owner_only_0o600(tmp_path):
    # #3: the SQLite DB and its -wal/-shm side files must be owner-only (0o600). The buffer
    # holds only ciphertext (KC §7.7.1), but world-readable files leak session_id /
    # batch_sequence / enqueue-time METADATA to other local users on a multi-user machine.
    # The -wal/-shm coverage is the load-bearing part: they are created at WAL activation.
    buf, _ = _open(tmp_path)
    try:
        buf.write(_sid(), 0, _env(0))  # exercise a write so the WAL sidecars are populated
        for suffix in ("", "-wal", "-shm"):
            p = tmp_path / ("buffer.db" + suffix)
            assert p.exists(), f"{p.name} should exist after a WAL write"
            mode = p.stat().st_mode & 0o777
            assert mode & 0o077 == 0, f"{p.name} mode {oct(mode)} not owner-only (want 0o600)"
    finally:
        buf.close()
