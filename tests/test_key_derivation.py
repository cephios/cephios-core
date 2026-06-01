"""§17.4 reproduction of the published v1.0 key_derivation bootstrap bytes (CS §5.2/§5.3/§5.4)."""

from __future__ import annotations

import hashlib

from cephios_core.keyderiv import derive_member_keys, derive_salt, derive_seed_material
from vector_loader import vector


def _kd():
    v = vector("key_derivation", "key_derivation_argon2id_001")
    return v["input"], v["expected_output"]


def test_reproduce_all_six_fields():
    inp, exp = _kd()
    pw = inp["master_password_utf8"]
    uid = inp["user_id"]

    salt = derive_salt(uid)
    seed = derive_seed_material(pw, uid)
    keys = derive_member_keys(pw, uid)

    assert salt.hex() == exp["salt_hex"]
    assert seed.hex() == exp["seed_material_hex"]
    assert keys.x25519_private_key_seed.hex() == exp["x25519_private_key_seed_hex"]
    assert keys.x25519_public_key.hex() == exp["x25519_public_key_hex"]
    assert keys.auth_verification_token.hex() == exp["auth_verification_token_hex"]
    assert keys.auth_verification_token_sha256.hex() == exp["auth_verification_token_sha256_hex"]


def test_split_is_seed_halves():
    inp, _ = _kd()
    seed = derive_seed_material(inp["master_password_utf8"], inp["user_id"])
    keys = derive_member_keys(inp["master_password_utf8"], inp["user_id"])
    assert keys.x25519_private_key_seed == seed[0:32]
    assert keys.auth_verification_token == seed[32:64]


def test_sha256_token_is_stored_credential():
    inp, _ = _kd()
    keys = derive_member_keys(inp["master_password_utf8"], inp["user_id"])
    token = keys.auth_verification_token
    assert keys.auth_verification_token_sha256 == hashlib.sha256(token).digest()
