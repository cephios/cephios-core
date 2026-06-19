# Changelog

All notable changes to `cephios-core` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow this package's
Semantic Versioning.

## 0.3.0 - 2026-06-19

### Added
- `upload_file()` helper: chunk a finished recording into batches over the
  existing capture/ingest pipe (INGEST-3a), plus the §17 `file_roundtrip`
  conformance category.
- `allow_insecure_http` opt-in on the ingest and control clients (defaults
  `False`).

### Security
- Enforce a 32-byte DEK in envelope construct/deconstruct — closes a silent
  AES-256→AES-128 downgrade where a short key encrypted under AES-128 while the
  header advertised AES-256 (#1).
- Clamp the honored `Retry-After` wait to the backoff ceiling — a hostile or
  misconfigured 429 can no longer stall the drain indefinitely (#2).
- Create the durable-buffer files (`.db` / `-wal` / `-shm`) owner-only (`0o600`)
  on POSIX; no-op on Windows, which uses ACLs (#3).
- `unwrap_dek` raises a typed `EnvelopeError('malformed')` instead of a bare
  `ValueError` on a malformed / low-order ephemeral key (#4).
- Reject a non-`https` `base_url` at client construction; `http` to the
  production host is always refused, even with `allow_insecure_http` (#5).

### Changed
- Advertise wire version `1.1` (`X-Cephios-API-Version`) to match the
  `ingest_mode` spec minor and the server runtime.

## 0.1.0 - 2026-06-02

- Initial release.
