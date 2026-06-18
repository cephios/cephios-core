"""The §7.7.4 disposition table — the core of C5a (CONTRACT_SPEC.md §7.7.4).

Each property is isolated (§10.6): a ``_FakeClient`` returns SCRIPTED outcomes so the test
exercises the uploader's disposition logic against a real C4 ``Buffer`` (apsw) with no httpx /
network involved. The disposition table under test:

    200 ack       → acknowledge (purge)
    429           → RETAIN + honor Retry-After + backoff (NOT a rejection)
    5xx / network → RETAIN + retry with backoff
    other 4xx     → emit_rejected (BufferRejected) THEN acknowledge (purge)

The RED capability for each property is the inverse mutation; the verbatim red-then-green
captures are in the commit body. ``sleep`` is injected (recorded, never real) so backoff is
instant and deterministic.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from cephios_core.buffer import (
    REJECTED_REASONS,
    Buffer,
    BufferConfig,
    BufferEvent,
    BufferLost,
    BufferRejected,
    Mode,
)
from cephios_core.errors import EnvelopeError, ValidationError, VersionError
from cephios_core.ingest import BackoffPolicy, Disposition, IngestAck, IngestOutcome
from cephios_core.uploader import Uploader

# Opaque ciphertext stand-in; the disposition logic is content-blind (PT).
_ENV = b"\xce\x0f\x01\x01" + bytes(range(32))


class _FakeClient:
    """Returns scripted :class:`IngestOutcome`s in order, repeating the last once exhausted
    (so ``[bp]`` models "429 forever" and ``[bp, ack]`` models "429 then 200"). Records every
    ``ingest`` call's durable key so the idempotency property can be asserted."""

    def __init__(self, outcomes: list[IngestOutcome]) -> None:
        assert outcomes
        self._outcomes = outcomes
        self._i = 0
        self.calls: list[tuple[uuid.UUID, int, bytes]] = []

    def ingest(self, session_id: uuid.UUID, batch_sequence: int, envelope: bytes) -> IngestOutcome:
        self.calls.append((session_id, batch_sequence, envelope))
        outcome = self._outcomes[min(self._i, len(self._outcomes) - 1)]
        self._i += 1
        return outcome


def _ack(status: str = "persisted") -> IngestOutcome:
    return IngestOutcome(Disposition.ACK, http_status=200, ack=IngestAck(status, 36))


def _backpressure(retry_after: float | None) -> IngestOutcome:
    return IngestOutcome(Disposition.BACKPRESSURE, http_status=429, retry_after=retry_after)


def _retryable() -> IngestOutcome:
    return IngestOutcome(Disposition.RETRYABLE, http_status=503)


def _rejected(error: object | None) -> IngestOutcome:
    return IngestOutcome(Disposition.REJECTED, http_status=400, error=error)  # type: ignore[arg-type]


class _Sleeps:
    """Records injected backoff waits instead of actually sleeping."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _buffer(tmp_path: Path, events: list[BufferEvent]) -> Buffer:
    return Buffer(
        BufferConfig(
            storage_path=tmp_path / "buffer.db",
            capacity_records=64,
            low_water_records=32,
            mode=Mode.BLOCK_AND_SIGNAL,
            event_callback=events.append,
        )
    )


def _seed_one(buffer: Buffer) -> tuple[uuid.UUID, int]:
    sid, seq = uuid.uuid4(), 0
    buffer.write(sid, seq, _ENV)
    return sid, seq


# ---------------------------------------------------------------------------
# 200 persisted / deduplicated → acknowledge (purge).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["persisted", "deduplicated"])
def test_ack_purges_record(tmp_path, status):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        _seed_one(buffer)
        client = _FakeClient([_ack(status)])
        summary = Uploader(buffer=buffer, client=client).drain()
        assert buffer.depth() == 0  # purged on the ack
        assert summary.acknowledged == 1
        assert events == []  # no BufferRejected / BufferLost on a clean ack
    finally:
        buffer.close()


# ---------------------------------------------------------------------------
# 429 → RETAIN + honor Retry-After (NOT a rejection). The load-bearing 429 property.
# ---------------------------------------------------------------------------


def test_429_retains_record_and_honors_retry_after(tmp_path):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        _seed_one(buffer)
        client = _FakeClient([_backpressure(7.0)])  # 429 forever
        sleeps = _Sleeps()
        summary = Uploader(buffer=buffer, client=client, sleep=sleeps, max_attempts=2).drain()
        # The record MUST survive a 429: retained, NOT purged, NOT rejected (§7.6 / §7.7.4).
        assert buffer.depth() == 1
        assert summary.retained == 1 and summary.rejected == 0 and summary.acknowledged == 0
        assert not any(isinstance(e, (BufferRejected, BufferLost)) for e in events)
        # Retry-After honored: the single inter-attempt wait is >= the server's 7s.
        assert sleeps.calls == [7.0]
    finally:
        buffer.close()


def test_429_then_200_eventually_acks(tmp_path):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        _seed_one(buffer)
        client = _FakeClient([_backpressure(3.0), _ack()])
        sleeps = _Sleeps()
        summary = Uploader(buffer=buffer, client=client, sleep=sleeps, max_attempts=4).drain()
        assert buffer.depth() == 0  # eventually acked + purged
        assert summary.acknowledged == 1
        assert sleeps.calls == [3.0]  # waited once (the 429) before the 200
        assert events == []
    finally:
        buffer.close()


def test_retry_after_combines_with_backoff_floor(tmp_path):
    # When Retry-After (1s) is below the current backoff, wait the LARGER (honor both §7.6).
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        _seed_one(buffer)
        client = _FakeClient([_backpressure(1.0)])
        sleeps = _Sleeps()
        backoff = BackoffPolicy(base_seconds=5.0, factor=2.0, maximum_seconds=30.0)
        uploader = Uploader(
            buffer=buffer, client=client, sleep=sleeps, backoff=backoff, max_attempts=2
        )
        uploader.drain()
        assert sleeps.calls == [5.0]  # max(retry_after=1, backoff(0)=5) = 5
        assert buffer.depth() == 1
    finally:
        buffer.close()


def test_429_absurd_retry_after_is_clamped_to_backoff_ceiling(tmp_path):
    # Security #2 (CONTRACT_SPEC §7.6/§7.7.4): a hostile/misconfigured 429 carrying an absurd
    # Retry-After must NOT stall the drain unboundedly. The honored wait is clamped to the
    # backoff ceiling; the retain/retry semantics are unchanged (the record is NOT purged).
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        _seed_one(buffer)
        client = _FakeClient([_backpressure(999_999_999.0)])  # ~31-year Retry-After, "429 forever"
        sleeps = _Sleeps()
        backoff = BackoffPolicy(base_seconds=0.5, factor=2.0, maximum_seconds=30.0)
        uploader = Uploader(
            buffer=buffer, client=client, sleep=sleeps, backoff=backoff, max_attempts=2
        )
        uploader.drain()
        # The single inter-attempt wait is clamped to the ceiling, NOT ~1e9.
        assert sleeps.calls == [backoff.maximum_seconds]  # 30.0, not 999_999_999
        assert all(w <= backoff.maximum_seconds for w in sleeps.calls)
        # Retain semantics untouched: the record survives the 429 (not purged, not rejected).
        assert buffer.depth() == 1
        assert not any(isinstance(e, (BufferRejected, BufferLost)) for e in events)
    finally:
        buffer.close()


def test_429_small_retry_after_below_ceiling_is_honored_as_is(tmp_path):
    # The clamp is min(max(retry_after, backoff), ceiling), NOT a flat ceiling: a small valid
    # Retry-After below the ceiling is honored exactly, proving legitimate small waits survive.
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        _seed_one(buffer)
        client = _FakeClient([_backpressure(5.0)])  # 5s, well below the 30s ceiling
        sleeps = _Sleeps()
        backoff = BackoffPolicy(base_seconds=0.5, factor=2.0, maximum_seconds=30.0)
        uploader = Uploader(
            buffer=buffer, client=client, sleep=sleeps, backoff=backoff, max_attempts=2
        )
        uploader.drain()
        assert sleeps.calls == [5.0]  # max(retry_after=5, backoff(0)=0.5)=5, < ceiling 30 → honored
    finally:
        buffer.close()


# ---------------------------------------------------------------------------
# 5xx → RETAIN + retry with backoff.
# ---------------------------------------------------------------------------


def test_5xx_retains_and_retries(tmp_path):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        _seed_one(buffer)
        client = _FakeClient([_retryable()])  # 503 forever
        sleeps = _Sleeps()
        backoff = BackoffPolicy(base_seconds=0.5, factor=2.0, maximum_seconds=30.0)
        summary = Uploader(
            buffer=buffer, client=client, sleep=sleeps, backoff=backoff, max_attempts=3
        ).drain()
        assert buffer.depth() == 1  # retained across 5xx, never purged
        assert summary.retained == 1 and summary.rejected == 0
        assert not any(isinstance(e, BufferRejected) for e in events)
        assert sleeps.calls == [0.5, 1.0]  # 2 waits between 3 attempts (exponential)
        assert len(client.calls) == 3  # the budget was actually used
    finally:
        buffer.close()


def test_5xx_then_200_acks(tmp_path):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        _seed_one(buffer)
        client = _FakeClient([_retryable(), _ack()])
        summary = Uploader(buffer=buffer, client=client, sleep=_Sleeps(), max_attempts=3).drain()
        assert buffer.depth() == 0
        assert summary.acknowledged == 1
    finally:
        buffer.close()


# ---------------------------------------------------------------------------
# non-retryable 4xx → emit_rejected (BufferRejected) THEN acknowledge (purge).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error,expected_reason", [
    (ValidationError("batch_too_large"), "rejected_batch_too_large"),
    (EnvelopeError("malformed"), "rejected_malformed"),
    (VersionError("envelope_version_unsupported"), "rejected_version_unsupported"),
    (ValidationError("some_other_code"), "rejected_other"),  # other non-retryable code
    (None, "rejected_other"),                                # unparseable / empty 4xx body
])
def test_non_retryable_4xx_emits_then_purges(tmp_path, error, expected_reason):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        sid, seq = _seed_one(buffer)
        client = _FakeClient([_rejected(error)])
        summary = Uploader(buffer=buffer, client=client).drain()
        # Purged AND a BufferRejected fired with the §7.7.3 fixed-vocabulary reason.
        assert buffer.depth() == 0
        assert summary.rejected == 1 and summary.acknowledged == 0
        rejected = [e for e in events if isinstance(e, BufferRejected)]
        assert len(rejected) == 1
        assert rejected[0].session_id == sid and rejected[0].batch_sequence == seq
        assert rejected[0].reason == expected_reason
        # The reason is always one of the closed §7.7.3 vocabulary — never a templated wire code
        # (e.g. "some_other_code" maps to rejected_other, NOT "rejected_some_other_code").
        assert rejected[0].reason in REJECTED_REASONS
        assert not any(isinstance(e, BufferLost) for e in events)
    finally:
        buffer.close()


def test_reject_is_emit_then_purge_crash_safe(tmp_path):
    # EMIT-THEN-PURGE (§7.7.4, load-bearing): if the event callback raises during emit_rejected
    # (the never-silent "panicking" option), the exception propagates BEFORE acknowledge runs, so
    # the record is RETAINED — re-uploaded → re-rejected → re-emitted; no silent loss. RED: a
    # purge-before-emit ordering would lose the record despite the raise (see the inline
    # demonstration below + the commit-body capture).
    def raise_on_rejected(event: BufferEvent) -> None:
        if isinstance(event, BufferRejected):
            raise RuntimeError("application callback panics")

    buffer = Buffer(
        BufferConfig(
            storage_path=tmp_path / "buffer.db",
            capacity_records=8,
            low_water_records=4,
            mode=Mode.BLOCK_AND_SIGNAL,
            event_callback=raise_on_rejected,
        )
    )
    try:
        sid, seq = _seed_one(buffer)
        client = _FakeClient([_rejected(ValidationError("batch_too_large"))])
        with pytest.raises(RuntimeError, match="panics"):
            Uploader(buffer=buffer, client=client).drain()
        assert buffer.depth() == 1, "emit-then-purge: a raise in emit must retain the record"

        # RED demonstration (inline, not the production path): purge-FIRST then emit. With the
        # same panicking callback the record is GONE before the emit raises — silent loss.
        def purge_first_then_emit() -> None:
            buffer.acknowledge(sid, seq)  # WRONG order
            buffer.emit_rejected(sid, seq, "rejected_batch_too_large")

        with pytest.raises(RuntimeError, match="panics"):
            purge_first_then_emit()
        assert buffer.depth() == 0, "purge-before-emit loses the record — why the order matters"
    finally:
        buffer.close()


# ---------------------------------------------------------------------------
# §7.7.4 idempotency: a retry re-issues the SAME (session_id, batch_sequence).
# ---------------------------------------------------------------------------


def test_retry_reuses_original_durable_key(tmp_path):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        sid, seq = _seed_one(buffer)
        client = _FakeClient([_backpressure(0.0), _retryable(), _ack()])
        Uploader(buffer=buffer, client=client, sleep=_Sleeps(), max_attempts=4).drain()
        assert len(client.calls) == 3
        for call_sid, call_seq, call_env in client.calls:
            assert (call_sid, call_seq) == (sid, seq)  # stable key across retries (§7.7.4 dedup)
            assert call_env == _ENV  # same bytes re-issued (PT)
    finally:
        buffer.close()


def test_drain_resumes_records_persisted_before_restart(tmp_path):
    # The drain reads Buffer.pending(), which surfaces records that survived a restart with their
    # original durable key (§7.7.1) — so a resumed process re-issues exactly what was buffered.
    db = tmp_path / "buffer.db"
    events: list[BufferEvent] = []
    cfg = BufferConfig(
        storage_path=db, capacity_records=8, low_water_records=4,
        mode=Mode.BLOCK_AND_SIGNAL, event_callback=events.append,
    )
    pre = Buffer(cfg)
    sid = uuid.uuid4()
    pre.write(sid, 0, _ENV)
    pre.write(sid, 1, _ENV)
    pre.close()  # simulate process exit

    resumed = Buffer(cfg)
    try:
        assert resumed.depth() == 2  # survived the "restart"
        client = _FakeClient([_ack()])
        summary = Uploader(buffer=resumed, client=client).drain()
        assert summary.acknowledged == 2
        assert resumed.depth() == 0
        assert {(s, q) for s, q, _ in client.calls} == {(sid, 0), (sid, 1)}
    finally:
        resumed.close()


def test_max_attempts_must_be_positive(tmp_path):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        with pytest.raises(ValueError, match="max_attempts"):
            Uploader(buffer=buffer, client=_FakeClient([_ack()]), max_attempts=0)
    finally:
        buffer.close()
