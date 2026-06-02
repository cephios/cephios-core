"""End-to-end key custody — the capture path closes the KC chain (WATCHPOINT 1).

CLAUDE.md §9.8 (KC / Model C) + CONTRACT_SPEC.md §7.7.1 + §7.4: the application-facing capture
path constructs the §6.4 AES-256-GCM envelope (fresh-random nonce) and only THEN writes the
ciphertext to the durable buffer. This proves the end-to-end chain that C4 left structurally
plaintext-free:

  - a captured plaintext NEVER appears in the buffer DB at rest, nor on the wire;
  - the wire body == the buffered bytes == the constructed envelope (§7.4 pass-through);
  - the envelope uses a FRESH RANDOM nonce per capture (the production ``envelope.construct``,
    never the conformance-only ``_construct_with_nonce`` seam).

Offline + deterministic (§B): the drain runs through a real ``IngestClient`` over an
``httpx.MockTransport`` that captures the request body; no network, no server.
"""

from __future__ import annotations

import inspect
import os
import uuid
from pathlib import Path

import httpx

import cephios_core.uploader as uploader_mod
from cephios_core.buffer import Buffer, BufferConfig, BufferEvent, Mode
from cephios_core.envelope import deconstruct
from cephios_core.ingest import IngestClient, bearer
from cephios_core.uploader import Uploader, capture

# A recognizable plaintext we can grep the buffer/wire for. AES-256 DEK = 32 random bytes.
_PLAINTEXT = b"NEURAL-SAMPLE-PLAINTEXT-MUST-NOT-LEAK-0123456789-ABCDEFGHIJKLMNOP"
_DEK = os.urandom(32)
_SID = uuid.UUID("018f0c00-0000-7000-8000-000000000042")


def _buffer(tmp_path: Path, events: list[BufferEvent]) -> Buffer:
    return Buffer(
        BufferConfig(
            storage_path=tmp_path / "buffer.db",
            capacity_records=16,
            low_water_records=8,
            mode=Mode.BLOCK_AND_SIGNAL,
            event_callback=events.append,
        )
    )


def test_capture_encrypts_before_buffer_and_plaintext_never_at_rest(tmp_path):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        env = capture(buffer, dek=_DEK, session_id=_SID, batch_sequence=0, plaintext=_PLAINTEXT)

        # The returned bytes are a real §6.1 envelope that decrypts back to the plaintext.
        assert env[:2] == b"\xce\x0f"
        assert deconstruct(env, _DEK) == _PLAINTEXT

        # What the buffer holds == the constructed envelope, and the plaintext is NOT in it.
        pending = buffer.pending()
        assert len(pending) == 1
        sid, seq, buffered = pending[0]
        assert (sid, seq) == (_SID, 0)
        assert buffered == env, "buffered bytes must equal the constructed envelope (PT, §7.4)"
        assert _PLAINTEXT not in buffered
    finally:
        buffer.close()

    # The plaintext must not be at rest ANYWHERE in the on-disk SQLite files (main + WAL + shm).
    for db_file in tmp_path.glob("buffer.db*"):
        assert _PLAINTEXT not in db_file.read_bytes(), f"plaintext leaked into {db_file.name}"


def test_wire_body_equals_buffered_equals_constructed(tmp_path):
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    env = capture(buffer, dek=_DEK, session_id=_SID, batch_sequence=0, plaintext=_PLAINTEXT)
    buffered = buffer.pending()[0][2]

    wire_bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        wire_bodies.append(request.content)
        return httpx.Response(
            200, json={"status": "persisted", "envelope_byte_count": len(request.content)}
        )

    client = IngestClient(credential=bearer("tok"), transport=httpx.MockTransport(handler))
    try:
        Uploader(buffer=buffer, client=client).drain()
        depth_after_drain = buffer.depth()  # read before closing the buffer
    finally:
        client.close()
        buffer.close()

    assert len(wire_bodies) == 1
    wire = wire_bodies[0]
    # The chain: wire body == buffered bytes == constructed envelope (§7.4 pass-through).
    assert wire == buffered == env
    # The plaintext never reaches the wire; the wire body decrypts to it (it IS the ciphertext).
    assert _PLAINTEXT not in wire
    assert deconstruct(wire, _DEK) == _PLAINTEXT
    assert depth_after_drain == 0  # acked + purged after the 200


def test_capture_uses_fresh_random_nonce(tmp_path):
    # Two captures of the SAME plaintext under the SAME DEK must differ — a fresh random nonce
    # per §6.4. RED-CAPABLE: a deterministic / fixed nonce would make e1 == e2 (and would also
    # be the catastrophic nonce-reuse the production path forbids).
    events: list[BufferEvent] = []
    buffer = _buffer(tmp_path, events)
    try:
        e1 = capture(buffer, dek=_DEK, session_id=_SID, batch_sequence=0, plaintext=_PLAINTEXT)
        e2 = capture(buffer, dek=_DEK, session_id=_SID, batch_sequence=1, plaintext=_PLAINTEXT)
        assert e1 != e2
        assert e1[4:16] != e2[4:16]  # the 12-byte nonce field (offset 4..16) differs
    finally:
        buffer.close()


def test_capture_source_uses_public_construct_not_the_nonce_seam():
    # Structural guard: the capture path CALLS the public envelope.construct (fresh random
    # nonce), NOT the module-private _construct_with_nonce conformance seam. Check for the CALL
    # form ``_construct_with_nonce(`` so a doc-comment mention of the name (without a call paren)
    # does not trip the guard.
    src = inspect.getsource(uploader_mod)
    assert "_construct_with_nonce(" not in src
    assert "envelope.construct(" in src
