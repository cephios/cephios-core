"""AES-256-GCM envelope format (CONTRACT_SPEC.md §6.1, §6.4, §6.5)."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cephios_core.errors import EnvelopeError, VersionError

__all__ = [
    "MAGIC",
    "VERSION",
    "ALG_AES_256_GCM",
    "construct",
    "deconstruct",
]

MAGIC = b"\xce\x0f"  # CONTRACT_SPEC.md §6.1 magic
VERSION = 0x01  # §6.1 envelope format version
ALG_AES_256_GCM = 0x01  # §6.2 alg_id (MVP active)
_HEADER_SIZE = 16
_NONCE_SIZE = 12
_TAG_SIZE = 16


def _header(nonce: bytes) -> bytes:
    return MAGIC + bytes((VERSION, ALG_AES_256_GCM)) + nonce


def construct(dek: bytes, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` under ``dek`` into a Cephios envelope (CS §6.4).

    A fresh 12-byte random nonce is generated per §6.4 step 2. This is the only
    production path and has no nonce parameter, so a caller cannot make it
    deterministic. For conformance-vector reproducibility use :func:`_construct_with_nonce`.

    ``dek`` MUST be a 32-byte AES-256 key (§6.2 alg_id 0x01); a wrong length raises
    ``ValueError`` rather than silently encrypting under a weaker AES variant.
    """
    return _construct_with_nonce(dek, plaintext, os.urandom(_NONCE_SIZE))


def _construct_with_nonce(dek: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    """Encrypt with a caller-supplied nonce (CS §6.4) — ADVANCED / conformance use only.

    Module-private (deliberately NOT in ``__all__``): a public caller-supplied-nonce function
    is a footgun — nonce reuse under the same DEK breaks AES-256-GCM catastrophically (key and
    plaintext recovery, not merely "weaker"). The caller is responsible for nonce uniqueness per
    (DEK, envelope) (§4.2). This seam exists ONLY so conformance vectors are reproducible;
    production code MUST use :func:`construct`, which generates a fresh random nonce.

    This is the single AES-256-GCM encryption chokepoint, so the 32-byte-DEK guard here
    covers both :func:`construct` and direct conformance callers: a non-32-byte ``dek`` would
    otherwise have ``AESGCM`` select AES-128/192 by key length while the header still writes
    alg_id 0x01 (AES-256), a silent downgrade.
    """
    if len(dek) != 32:
        raise ValueError(f"dek must be 32 bytes, got {len(dek)}")
    if len(nonce) != _NONCE_SIZE:
        raise ValueError(f"nonce must be {_NONCE_SIZE} bytes, got {len(nonce)}")
    header = _header(nonce)
    ciphertext_and_tag = AESGCM(dek).encrypt(nonce, plaintext, header)
    return header + ciphertext_and_tag


def deconstruct(envelope: bytes, dek: bytes) -> bytes:
    """Decrypt a Cephios envelope (CS §6.5) with the §6.5 ORDERED failure dispositions.

    magic mismatch -> EnvelopeError 'malformed';
    version != 0x01 -> VersionError 'envelope_version_unsupported';
    alg_id != 0x01  -> VersionError 'envelope_algorithm_unsupported';
    tag verification fails -> EnvelopeError 'authentication_failed'.

    ``dek`` MUST be a 32-byte AES-256 key; a wrong length raises ``ValueError`` (caller
    precondition) before the AES-256-GCM decrypt — symmetric with :func:`construct`, closing
    the AES-256->AES-128 downgrade on import/replay of a 16-byte-DEK envelope.
    """
    if len(envelope) < _HEADER_SIZE + _TAG_SIZE or envelope[0:2] != MAGIC:
        raise EnvelopeError("malformed", "envelope magic is not 0xCE 0x0F")
    if envelope[2] != VERSION:
        raise VersionError("envelope_version_unsupported", f"envelope version 0x{envelope[2]:02x}")
    if envelope[3] != ALG_AES_256_GCM:
        raise VersionError("envelope_algorithm_unsupported", f"envelope alg_id 0x{envelope[3]:02x}")
    if len(dek) != 32:
        raise ValueError(f"dek must be 32 bytes, got {len(dek)}")
    header = envelope[0:_HEADER_SIZE]
    nonce = envelope[4:_HEADER_SIZE]
    ciphertext_and_tag = envelope[_HEADER_SIZE:]
    try:
        return AESGCM(dek).decrypt(nonce, ciphertext_and_tag, header)
    except InvalidTag:
        raise EnvelopeError("authentication_failed", "AES-GCM tag verification failed") from None
