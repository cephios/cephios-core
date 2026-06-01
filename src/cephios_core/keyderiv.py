"""Client-side member-key derivation (CONTRACT_SPEC.md §5.2 + §5.3 + §5.4 step 6).

KEY CUSTODY (CLAUDE.md §9.8): the master password, the X25519 private-key seed, and the
auth-verification token are derived and held in process memory only. Nothing in this module
serializes, logs, persists, or transmits that material, and :class:`MemberKeyMaterial`
redacts its secret fields in ``repr``/``str`` so they cannot leak through logging.
"""

from __future__ import annotations

import hashlib

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

__all__ = [
    "MemberKeyMaterial",
    "derive_salt",
    "derive_seed_material",
    "derive_member_keys",
]

# CONTRACT_SPEC.md §5.2 salt prefix and §4.2/§5.3 Argon2id parameters (C1-pinned).
_SALT_PREFIX = b"cephios-member-salt-v1"
_SALT_LEN = 16
_ARGON2_VERSION = 19  # 0x13 = Argon2 v1.3 (RFC 9106), CS §4.2/§5.3 — passed explicitly.
_ARGON2_MEMORY_KIB = 65536
_ARGON2_TIME_COST = 3
_ARGON2_PARALLELISM = 4
_SEED_MATERIAL_LEN = 64


class MemberKeyMaterial:
    """Derived member key material (CONTRACT_SPEC.md §5.3/§5.4).

    ``x25519_private_key_seed`` and ``auth_verification_token`` are SECRET (key custody,
    CLAUDE.md §9.8). ``x25519_public_key`` and ``auth_verification_token_sha256`` are the
    shareable outputs uploaded to Cephios at signup (§5.4 steps 5-7). The ``repr`` redacts
    the two secret fields, and ``__slots__`` keeps the object out of an instance ``__dict__``.
    """

    __slots__ = (
        "x25519_private_key_seed",
        "x25519_public_key",
        "auth_verification_token",
        "auth_verification_token_sha256",
    )

    def __init__(
        self,
        *,
        x25519_private_key_seed: bytes,
        x25519_public_key: bytes,
        auth_verification_token: bytes,
        auth_verification_token_sha256: bytes,
    ) -> None:
        self.x25519_private_key_seed = x25519_private_key_seed
        self.x25519_public_key = x25519_public_key
        self.auth_verification_token = auth_verification_token
        self.auth_verification_token_sha256 = auth_verification_token_sha256

    def __repr__(self) -> str:
        return (
            "MemberKeyMaterial("
            f"x25519_public_key={self.x25519_public_key.hex()}, "
            f"auth_verification_token_sha256={self.auth_verification_token_sha256.hex()}, "
            "x25519_private_key_seed=<redacted>, auth_verification_token=<redacted>)"
        )


def derive_salt(user_id: str) -> bytes:
    """SHA-256("cephios-member-salt-v1" || user_id_utf8_bytes)[0:16] (CS §5.2).

    ``user_id`` is the canonical RFC 9562 lowercase-hyphenated UUID string (CS §5.2); its
    UTF-8 encoding is the salt input.
    """
    return hashlib.sha256(_SALT_PREFIX + user_id.encode("utf-8")).digest()[:_SALT_LEN]


def derive_seed_material(master_password: str, user_id: str) -> bytes:
    """Argon2id seed_material per CS §5.3 (64 bytes).

    The Argon2id parameters are passed EXPLICITLY (never relying on argon2-cffi defaults)
    so spec-vs-library drift is visible: version 0x13, m=65536, t=3, p=4, hash_len=64,
    type=ID. ``hash_secret_raw`` uses an empty Argon2 secret (pepper) and empty associated
    data by construction, matching the CS §4.2 "both empty" pin.
    """
    salt = derive_salt(user_id)
    return bytes(
        hash_secret_raw(
            secret=master_password.encode("utf-8"),
            salt=salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_KIB,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_SEED_MATERIAL_LEN,
            type=Type.ID,
            version=_ARGON2_VERSION,
        )
    )


def derive_member_keys(master_password: str, user_id: str) -> MemberKeyMaterial:
    """Full member-key derivation: CS §5.3 split + RFC 7748 public key + §5.4 step 6."""
    seed = derive_seed_material(master_password, user_id)
    private_key_seed = seed[0:32]
    auth_token = seed[32:64]
    private_key = X25519PrivateKey.from_private_bytes(private_key_seed)
    public_key = private_key.public_key().public_bytes_raw()
    auth_token_sha256 = hashlib.sha256(auth_token).digest()
    return MemberKeyMaterial(
        x25519_private_key_seed=private_key_seed,
        x25519_public_key=public_key,
        auth_verification_token=auth_token,
        auth_verification_token_sha256=auth_token_sha256,
    )
