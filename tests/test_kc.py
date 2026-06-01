"""Key custody (CLAUDE.md §9.8): secret material does not leak through repr/str surfaces."""

from __future__ import annotations

from cephios_core.keyderiv import MemberKeyMaterial, derive_member_keys

_PW = "Cephios-Test-Vector-Pw-2026!"
_UID = "018f0c00-0000-7000-8000-000000000020"


def test_repr_redacts_secrets():
    keys = derive_member_keys(_PW, _UID)
    text = repr(keys)
    assert "<redacted>" in text
    # the two secret fields must NOT appear in repr/str
    assert keys.x25519_private_key_seed.hex() not in text
    assert keys.auth_verification_token.hex() not in text
    assert repr(keys) == str(keys)
    # the shareable public key may appear
    assert keys.x25519_public_key.hex() in text


def test_no_instance_dict_serialization_surface():
    keys = derive_member_keys(_PW, _UID)
    # __slots__ => no instance __dict__ to accidentally vars()/json-dump the secrets out
    assert not hasattr(keys, "__dict__")
    assert MemberKeyMaterial.__slots__
