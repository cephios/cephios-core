"""X25519-ECIES wrapped-DEK unwrap against the vector + wrap/unwrap round-trip (CS §6.3)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from cephios_core.errors import EnvelopeError
from cephios_core.wrapped_dek import unwrap_dek, wrap_dek
from vector_loader import vector


def test_unwrap_matches_vector():
    v = vector("wrapped_dek", "wrapped_dek_unwrap_001")
    env = bytes.fromhex(v["input"]["wrapped_dek_envelope_hex"])
    priv = bytes.fromhex(v["input"]["recipient_private_key_hex"])
    assert unwrap_dek(env, priv).hex() == v["expected_output"]["dek_hex"]
    assert len(env) == v["expected_output"]["wrap_envelope_byte_count"]


def test_corrupted_wrap_fails():
    v = vector("wrapped_dek", "wrapped_dek_unwrap_001")
    env = bytearray(bytes.fromhex(v["input"]["wrapped_dek_envelope_hex"]))
    priv = bytes.fromhex(v["input"]["recipient_private_key_hex"])
    env[40] ^= 0x01  # flip a byte inside the wrapped_dek region
    with pytest.raises(EnvelopeError) as exc:
        unwrap_dek(bytes(env), priv)
    assert exc.value.code == "authentication_failed"


def test_wrap_unwrap_roundtrip():
    # forward wrap is non-deterministic (fresh ephemeral §6.3 step 1); prove via round-trip
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    dek = b"\x42" * 32
    env = wrap_dek(pub_bytes, dek)
    assert len(env) == 76
    assert unwrap_dek(env, priv_bytes) == dek
    assert wrap_dek(pub_bytes, dek) != env  # non-deterministic
