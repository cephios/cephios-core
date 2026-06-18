"""AES-256-GCM construct/deconstruct + the §6.5 ordered dispositions (CS §6.1/§6.4/§6.5)."""

from __future__ import annotations

import inspect

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cephios_core.envelope import _construct_with_nonce, construct, deconstruct
from cephios_core.errors import EnvelopeError, VersionError
from vector_loader import load_category, vector


def test_construct_matches_vector():
    v = vector("envelope_encryption", "envelope_encrypt_construct_001")
    dek = bytes.fromhex(v["input"]["dek_hex"])
    nonce = bytes.fromhex(v["input"]["nonce_hex"])
    pt = v["input"]["plaintext_utf8"].encode("utf-8")
    env = _construct_with_nonce(dek, pt, nonce)
    assert env.hex() == v["expected_output"]["envelope_hex"]
    assert len(env) == v["expected_output"]["envelope_byte_count"]


def test_construct_deconstruct_roundtrip():
    v = vector("envelope_encryption", "envelope_decrypt_deconstruct_001")
    env = bytes.fromhex(v["input"]["envelope_hex"])
    dek = bytes.fromhex(v["input"]["dek_hex"])
    assert deconstruct(env, dek).decode("utf-8") == v["expected_output"]["plaintext_utf8"]


def test_nonce_seam_default_is_fresh_random():
    dek = b"\x42" * 32
    pt = b"same plaintext"
    assert construct(dek, pt) != construct(dek, pt)  # fresh random nonce per call


def test_nonce_seam_not_reachable_from_default():
    # production construct() has no nonce parameter; the deterministic seam is separate
    assert "nonce" not in inspect.signature(construct).parameters
    assert "nonce" in inspect.signature(_construct_with_nonce).parameters


def test_construct_rejects_non_32_byte_dek():
    # #1 downgrade footgun: a 16-byte DEK must be REJECTED, not silently encrypted under
    # AES-128 while the header still advertises alg_id=0x01 (AES-256). The guard lives at the
    # single _construct_with_nonce encryption chokepoint, so construct() is covered too.
    short_dek = b"\x42" * 16
    with pytest.raises(ValueError, match="dek must be 32 bytes"):
        _construct_with_nonce(short_dek, b"plaintext", b"\x00" * 12)
    with pytest.raises(ValueError, match="dek must be 32 bytes"):
        construct(short_dek, b"plaintext")
    # a valid 32-byte DEK still constructs (no regression)
    assert len(construct(b"\x42" * 32, b"plaintext")) > 0


def test_deconstruct_rejects_non_32_byte_dek():
    # #1 import/replay side: an envelope AES-128-encrypted under a 16-byte DEK (but carrying
    # alg_id=0x01) must be REJECTED at deconstruct, not silently AES-128-decrypted. The guard
    # fires before the AES-256-GCM decrypt.
    short_dek = b"\x42" * 16
    nonce = b"\x00" * 12
    header = b"\xce\x0f\x01\x01" + nonce  # alg_id=0x01 header, but the body is AES-128
    aes128_env = header + AESGCM(short_dek).encrypt(nonce, b"plaintext", header)
    with pytest.raises(ValueError, match="dek must be 32 bytes"):
        deconstruct(aes128_env, short_dek)
    # a valid 32-byte-DEK envelope still deconstructs (no regression)
    dek32 = b"\x42" * 32
    assert deconstruct(construct(dek32, b"plaintext"), dek32) == b"plaintext"


# (category, test_id, error_type, expected_code) — each §6.5 disposition in isolation.
_DISPOSITIONS = [
    ("envelope_encryption", "envelope_malformed_magic_001", EnvelopeError, "malformed"),
    (
        "envelope_versioning",
        "envelope_versioning_version_unsupported_001",
        VersionError,
        "envelope_version_unsupported",
    ),
    (
        "envelope_versioning",
        "envelope_versioning_alg_unsupported_001",
        VersionError,
        "envelope_algorithm_unsupported",
    ),
    (
        "envelope_encryption",
        "envelope_auth_failed_wrong_dek_001",
        EnvelopeError,
        "authentication_failed",
    ),
    (
        "envelope_encryption",
        "envelope_auth_failed_tampered_001",
        EnvelopeError,
        "authentication_failed",
    ),
]


@pytest.mark.parametrize(("category", "test_id", "error_type", "code"), _DISPOSITIONS)
def test_deconstruct_dispositions(category, test_id, error_type, code):
    v = vector(category, test_id)
    env = bytes.fromhex(v["input"]["envelope_hex"])
    dek = bytes.fromhex(v["input"]["dek_hex"])
    with pytest.raises(error_type) as exc:
        deconstruct(env, dek)
    assert exc.value.code == code
    assert exc.value.category == v["expected_output"]["error"]["category"]
    assert exc.value.http_status == v["expected_output"]["error"]["http_status"]


def test_all_envelope_vectors_consumed():
    ids = {v["test_id"] for v in load_category("envelope_encryption")}
    ids |= {v["test_id"] for v in load_category("envelope_versioning")}
    covered = {"envelope_encrypt_construct_001", "envelope_decrypt_deconstruct_001"}
    covered |= {tid for _, tid, _, _ in _DISPOSITIONS}
    assert ids == covered
