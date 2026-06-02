# cephios-core

The Python reference implementation of **The Cephios Protocol, version 1.0** — the
language-independent wire protocol for end-to-end-encrypted neural-data capture and ingestion.

`cephios-core` implements the **client side** of the protocol (the device/SDK side that runs on
the tenant's own machine). It is verified against the published [conformance test-vector
suite](https://github.com/cephios/protocol-tests): it passes every §17.3 gated category — the six
100%-threshold categories (`envelope_encryption`, `wrapped_dek`, `key_derivation`,
`error_taxonomy`, `envelope_versioning`, `control_plane_erasure`) and `ingestion_idempotency`
(threshold ≥ 90%). `session_lifecycle` is executed and reported but is not a §17.3 gating criterion.

## Install

```bash
pip install cephios-core
```

Requires **Python 3.10+**. Runtime dependencies: `cryptography`, `httpx`, `argon2-cffi`, `apsw`.

## What it implements

Each surface is exposed from its own submodule (the top-level package deliberately exports only
`__version__`):

- **Argon2id member-key derivation** (`cephios_core.keyderiv`) — §5.2/§5.3 derivation of the
  X25519 private-key seed + auth-verification token from a master password, client-side only.
- **AES-256-GCM envelope** (`cephios_core.envelope`) — §6.1/§6.4/§6.5 `construct` (fresh random
  nonce) / `deconstruct`, with the 16-byte header bound as AEAD associated data.
- **X25519-ECIES wrapped DEK** (`cephios_core.wrapped_dek`) — §6.3 `wrap_dek` / `unwrap_dek` of
  the 76-byte wrapped-DEK envelope.
- **Durable ingestion buffer + uploader** (`cephios_core.buffer`, `cephios_core.ingest`,
  `cephios_core.uploader`) — the §7 HTTP ingestion path (`POST /v1/ingest`, raw octet-stream body)
  with a **persist-before-ack, never-silent** local buffer (four typed events —
  `BufferPressure` / `BufferDrop` / `BufferRejected` / `BufferLost`) and the §7.7.4 disposition
  uploader (200 → purge; 429 → retain + honor `Retry-After`; 5xx → retain + retry;
  non-retryable 4xx → emit-then-purge). The `capture()` path encrypts **before** the record
  reaches the buffer, so the buffer only ever holds ciphertext.
- **Control-plane + key-management client** (`cephios_core.control`) — §9 sessions
  (open / close / read), the §8 wrapped-DEK HTTP shapes (public-key upload, wrapped-DEK
  upload / fetch / revoke), and §10.5 subject erasure.
- **Typed error taxonomy** (`cephios_core.errors`) — the full §14 twelve-category `CephiosError`
  hierarchy and the §14.1 wire-error decoder.

The network client is async-first (`httpx.AsyncClient`) with a synchronous facade; the crypto and
the buffer are synchronous.

## Example

```python
import os
from cephios_core.envelope import construct, deconstruct

dek = os.urandom(32)                      # 32-byte AES-256 data-encryption key
plaintext = b"neural-sample-bytes"
envelope = construct(dek, plaintext)      # §6.4 — fresh random nonce per call
assert deconstruct(envelope, dek) == plaintext
```

## Conformance

The package ships a runner that executes the published v1.0 vectors and enforces the §17.3
thresholds, exiting non-zero if any gated category misses. The vectors are **not** bundled in the
wheel (they are the separate [cephios/protocol-tests](https://github.com/cephios/protocol-tests)
suite), so pass the vector directory explicitly:

```bash
cephios-conformance path/to/protocol-tests/v1.0
# equivalently: python -m cephios_core.conformance path/to/protocol-tests/v1.0
```

## Status & limits

This is an early (**0.1.0**) release. The client-side v1.0 surface above is implemented and passes
the published §17.3 conformance suite, but the public API may still evolve and the package is not
yet production-hardened. The buffer's durability is proven against a **process kill** (a real
SIGKILL of a subprocess mid-write, after which acked records survive on reopen); power-loss /
kernel-crash durability is not yet independently proven. The Cephios cloud/server is a separate
system and is **not** part of this package, and the realtime protocol (§11) is not implemented here.

## References

- Protocol specification: *The Cephios Protocol, version 1.0* (`CONTRACT_SPEC.md`).
- Conformance test-vector suite: [cephios/protocol-tests](https://github.com/cephios/protocol-tests).

## License

MIT — see [LICENSE](https://github.com/cephios/cephios-core/blob/main/LICENSE).
