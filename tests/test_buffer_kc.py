"""Key custody + §7.7.5 surface separation for the durable buffer (CLAUDE.md §9.8, CS §7.7).

KC (Model C): the buffer stores ENCRYPTED envelope bytes ONLY and NEVER sees plaintext or
key material. This is enforced STRUCTURALLY, not by runtime magic-byte inspection: the buffer
is bytes-opaque (PT, §9.1) and validating the §6.1 magic would (a) couple the buffer to the
envelope format and read as a transform-adjacent inspection, and (b) give no real guarantee
(plaintext could coincidentally start with 0xCE0F). The real guarantee is that the write
surface has no plaintext / DEK parameter and the module imports no encryption primitive, so
envelope construction (§6.4) provably happens BEFORE the buffer write (the C5 uploader).

§7.7.5 separation: the four events are plain dataclasses (no HTTP status, no wire shape) and
the SDK-internal exceptions are not CephiosError; in particular BufferRejected is NOT the §14
BufferError HTTP-429 wire signal.
"""

from __future__ import annotations

import inspect

import cephios_core.buffer as bufmod
from cephios_core.buffer import (
    BufferDrop,
    BufferLost,
    BufferPressure,
    BufferRejected,
    SdkBufferError,
    TerminalLatchError,
)
from cephios_core.errors import BufferError, CephiosError


def test_write_signature_has_no_plaintext_or_key_parameter():
    params = set(inspect.signature(bufmod.Buffer.write).parameters)
    # The write surface accepts only the durable key + opaque ciphertext bytes.
    assert params == {"self", "session_id", "batch_sequence", "envelope"}
    forbidden = {"plaintext", "sample", "dek", "key", "nonce", "password", "secret"}
    assert not (params & forbidden), f"buffer write surface leaks a plaintext/key param: {params}"


def test_no_public_method_takes_plaintext_or_key():
    forbidden = {"plaintext", "sample", "dek", "key", "nonce", "password", "secret"}
    for name, member in inspect.getmembers(bufmod.Buffer, predicate=inspect.isfunction):
        if name.startswith("_"):
            continue
        params = set(inspect.signature(member).parameters)
        assert not (params & forbidden), f"Buffer.{name} exposes a plaintext/key parameter"


def test_module_imports_no_encryption_primitive():
    # The buffer must not import the envelope / crypto path: construction precedes the write.
    src = inspect.getsource(bufmod)
    for banned in ("cephios_core.envelope", "from cryptography", "import cryptography", "AESGCM"):
        assert banned not in src, f"buffer.py must not reference {banned!r} (KC / ET ordering)"


def test_events_are_not_cephios_error():
    # §7.7.5: the SDK-internal events are NOT the §14 wire error taxonomy.
    for event_cls in (BufferPressure, BufferDrop, BufferRejected, BufferLost):
        assert not issubclass(event_cls, CephiosError)
        assert not issubclass(event_cls, Exception)
        # No HTTP-status / wire surface on the event payloads.
        fields = set(getattr(event_cls, "__dataclass_fields__", {}))
        assert not (fields & {"http_status", "status_code", "category", "code"})


def test_buffer_rejected_is_not_the_wire_buffer_error():
    # §7.7.5: BufferRejected (SDK-internal event) MUST NOT be conflated with the §14.2
    # BufferError HTTP-429 wire category.
    assert BufferRejected is not BufferError
    assert not issubclass(BufferRejected, BufferError)
    assert issubclass(BufferError, CephiosError)  # the wire one has an HTTP status
    assert BufferError.http_status == 429


def test_sdk_buffer_exceptions_are_not_cephios_error():
    # §7.7.5: SDK-internal operational exceptions are local, never carried on the wire.
    assert issubclass(SdkBufferError, Exception)
    assert not issubclass(SdkBufferError, CephiosError)
    assert issubclass(TerminalLatchError, SdkBufferError)
