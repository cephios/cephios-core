# cephios-core

The Python reference implementation of **The Cephios Protocol, version 1.0** — the
language-independent wire protocol for end-to-end-encrypted neural-data capture and ingestion.

> **Status: early scaffold (Group 12).** This repository currently contains only the package
> skeleton, packaging, and CI. The cryptographic and protocol surface described below is **not
> yet implemented** and lands in subsequent commits.

## Install

```bash
pip install cephios-core
```

(Not yet published to PyPI.)

## Scope

`cephios-core` will implement the client side of the Cephios Protocol, each piece verified against
the published conformance test-vector suite:

- Argon2id master-password key derivation (RFC 9106).
- AES-256-GCM envelope construction and deconstruction.
- X25519-ECIES wrapped-DEK handling.
- The HTTP ingestion path with a durable, never-silent client-side buffer.
- The typed error hierarchy.

None of this surface exists yet — see **Status** above.

## References

- Protocol specification: *The Cephios Protocol, version 1.0* (`CONTRACT_SPEC.md`).
- Conformance test-vector suite: [cephios/protocol-tests](https://github.com/cephios/protocol-tests).

## License

MIT — see [LICENSE](LICENSE).
