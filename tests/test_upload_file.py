"""upload_file() + chunk_plaintext / reassemble — the §9.1 ingest_mode='file' /
§7.5 file-upload ergonomic (INGEST-3a).

The §17 ``file_roundtrip`` conformance vector is exercised by
``cephios_core.conformance``; these tests prove ``upload_file`` chunks a finished
recording over the EXISTING ``capture()`` path (chunk -> encrypt -> durable
buffer, so the buffer holds CIPHERTEXT — KC/PT, §9.8/§9.4) and that the
chunker/reassembler round-trip is byte-identical (client-side; NO Cephios
decryption — R-RT-CLIENTSIDE)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from cephios_core import envelope
from cephios_core.buffer import Buffer, BufferConfig, Mode
from cephios_core.uploader import (
    DEFAULT_MAX_CHUNK_BYTES,
    chunk_plaintext,
    reassemble,
    upload_file,
)

# 32-byte test DEK — already unwrapped; upload_file does NOT unwrap (it takes the
# unwrapped session DEK, matching capture()'s contract).
_DEK = bytes(range(32))

# The three §17 file_roundtrip vector shapes: exact multiple, remainder, single chunk.
_CASES = [
    (bytes.fromhex("0011223344556677"), 4, 2),      # exact multiple -> 2 batches of 4
    (bytes.fromhex("00010203040506070809"), 4, 3),  # remainder      -> 4, 4, 2
    (bytes.fromhex("aabbcc"), 8, 1),                 # single chunk (< chunk size)
]


def _buffer(tmp_path: Path) -> Buffer:
    return Buffer(
        BufferConfig(
            storage_path=tmp_path / "buffer.db",
            capacity_records=64,
            low_water_records=32,
            mode=Mode.BLOCK_AND_SIGNAL,
            event_callback=lambda _e: None,
        )
    )


@pytest.mark.parametrize("data,max_chunk,n", _CASES)
def test_upload_file_chunks_over_capture_and_roundtrips(tmp_path, data, max_chunk, n):
    """upload_file slices the recording into n batches, encrypts each via capture()
    (buffer holds ciphertext, not plaintext), and decrypting + reassembling the
    buffered batches in batch_sequence order reproduces the input."""
    buffer = _buffer(tmp_path)
    try:
        sid = uuid.uuid4()
        envs = upload_file(buffer, dek=_DEK, session_id=sid, data=data, max_chunk_bytes=max_chunk)
        assert len(envs) == n
        assert buffer.depth() == n
        pending = sorted(buffer.pending(), key=lambda r: r[1])  # by batch_sequence
        assert [seq for (_sid, seq, _env) in pending] == list(range(n))
        # The buffer holds ciphertext envelopes (no plaintext at rest — KC/PT).
        for (_sid, _seq, env) in pending:
            assert env != data
        plaintexts = [envelope.deconstruct(env, _DEK) for (_sid, _seq, env) in pending]
        assert reassemble(plaintexts) == data  # client-side round-trip == input
        assert envs == [env for (_sid, _seq, env) in pending]  # returned == buffered
    finally:
        buffer.close()


def test_upload_file_accepts_a_path(tmp_path):
    """upload_file reads a filesystem path via pathlib (OS-agnostic — G12-D5 f)."""
    buffer = _buffer(tmp_path)
    try:
        data = bytes(range(10))
        rec = tmp_path / "recording.bin"
        rec.write_bytes(data)
        envs = upload_file(buffer, dek=_DEK, session_id=uuid.uuid4(), data=rec, max_chunk_bytes=4)
        assert len(envs) == 3
        plaintexts = [
            envelope.deconstruct(env, _DEK)
            for (_sid, _seq, env) in sorted(buffer.pending(), key=lambda r: r[1])
        ]
        assert reassemble(plaintexts) == data
    finally:
        buffer.close()


def test_chunk_plaintext_and_reassemble_are_inverse():
    """The pure §17 file_roundtrip property, no buffer: reassemble(chunk(f, n)) == f
    for exact-multiple / remainder / single-chunk inputs; empty -> zero batches."""
    for data, max_chunk, n in _CASES:
        chunks = chunk_plaintext(data, max_chunk)
        assert len(chunks) == n
        assert all(len(c) <= max_chunk for c in chunks)
        assert reassemble(chunks) == data
    assert chunk_plaintext(b"", 4) == []
    assert reassemble([]) == b""


def test_chunk_plaintext_rejects_nonpositive_chunk_size():
    with pytest.raises(ValueError):
        chunk_plaintext(b"abc", 0)


def test_default_chunk_size_is_within_batch_size_guidance():
    """DEFAULT_MAX_CHUNK_BYTES is the §7.5 throughput recommendation (1 MiB), within
    the 64 KiB–4 MiB recommended range and under the 16 MiB max."""
    assert DEFAULT_MAX_CHUNK_BYTES == 1 << 20
    assert 64 * 1024 <= DEFAULT_MAX_CHUNK_BYTES <= 4 * 1024 * 1024
