"""X25519-ECIES wrapped-DEK envelope (CONTRACT_SPEC.md §6.3).

Layout (76 bytes): magic 0xCE 0xDE || version 0x01 || wrap_alg 0x01 ||
ephemeral_pub[32] || wrapped_dek[40]. The conformance direction is UNWRAP — forward
wrapping is non-deterministic (a fresh ephemeral per §6.3 step 1).
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

from cephios_core.errors import EnvelopeError

__all__ = [
    "WRAP_MAGIC",
    "WRAP_VERSION",
    "WRAP_ALG_X25519_ECIES",
    "unwrap_dek",
    "wrap_dek",
]

WRAP_MAGIC = b"\xce\xde"  # CONTRACT_SPEC.md §6.3 wrap-envelope magic
WRAP_VERSION = 0x01
WRAP_ALG_X25519_ECIES = 0x01  # §6.3 wrap_alg (MVP active)
_WRAP_ENVELOPE_SIZE = 76
_EPHEMERAL_PUB_OFFSET = 4
_EPHEMERAL_PUB_SIZE = 32
_WRAPPED_DEK_OFFSET = _EPHEMERAL_PUB_OFFSET + _EPHEMERAL_PUB_SIZE  # 36
_HKDF_INFO = b"cephios-dek-wrap-v1"
_KEK_LEN = 32
_DEK_LEN = 32


def _wrap_kek(
    shared_secret: bytes, recipient_public_key: bytes, ephemeral_public_key: bytes
) -> bytes:
    # CS §6.3 step 3: HKDF-SHA-256, salt = recipient_pub || ephemeral_pub, info pinned.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEK_LEN,
        salt=recipient_public_key + ephemeral_public_key,
        info=_HKDF_INFO,
    ).derive(shared_secret)


def unwrap_dek(wrap_envelope: bytes, recipient_private_key: bytes) -> bytes:
    """Unwrap a 76-byte X25519-ECIES envelope to the 32-byte DEK (CS §6.3).

    Deterministic on ``(wrap_envelope, recipient_private_key)`` — every conformant
    implementation unwraps the fixed reference envelope to the same DEK.
    """
    if len(wrap_envelope) != _WRAP_ENVELOPE_SIZE or wrap_envelope[0:2] != WRAP_MAGIC:
        raise EnvelopeError("malformed", "wrapped-DEK envelope magic/length invalid")
    if wrap_envelope[2] != WRAP_VERSION or wrap_envelope[3] != WRAP_ALG_X25519_ECIES:
        raise EnvelopeError("malformed", "wrapped-DEK version/wrap_alg unsupported")
    ephemeral_public_key = wrap_envelope[_EPHEMERAL_PUB_OFFSET:_WRAPPED_DEK_OFFSET]
    wrapped_dek = wrap_envelope[_WRAPPED_DEK_OFFSET:]
    private_key = X25519PrivateKey.from_private_bytes(recipient_private_key)
    recipient_public_key = private_key.public_key().public_bytes_raw()
    shared_secret = private_key.exchange(X25519PublicKey.from_public_bytes(ephemeral_public_key))
    kek = _wrap_kek(shared_secret, recipient_public_key, ephemeral_public_key)
    try:
        return aes_key_unwrap(kek, wrapped_dek)
    except InvalidUnwrap:
        raise EnvelopeError("authentication_failed", "AES-KW integrity check failed") from None


def wrap_dek(recipient_public_key: bytes, dek: bytes) -> bytes:
    """Wrap a 32-byte DEK under the recipient's X25519 public key (CS §6.3).

    Non-deterministic (fresh ephemeral per §6.3 step 1) — there is no fixed vector;
    correctness is proven by a wrap -> unwrap round-trip.
    """
    if len(dek) != _DEK_LEN:
        raise ValueError(f"dek must be {_DEK_LEN} bytes, got {len(dek)}")
    ephemeral_private_key = X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key().public_bytes_raw()
    recipient = X25519PublicKey.from_public_bytes(recipient_public_key)
    shared_secret = ephemeral_private_key.exchange(recipient)
    kek = _wrap_kek(shared_secret, recipient_public_key, ephemeral_public_key)
    wrapped_dek = aes_key_wrap(kek, dek)
    header = WRAP_MAGIC + bytes((WRAP_VERSION, WRAP_ALG_X25519_ECIES))
    return header + ephemeral_public_key + wrapped_dek
