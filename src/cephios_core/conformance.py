"""Conformance runner — the §17.3 gate over the published v1.0 vector suite (CONTRACT_SPEC.md §17).

One runner executes the full vendored v1.0 suite (``tests/vectors/v1.0/``, SHA-pinned to
protocol-tests 9c195db by the C3 pin guard) and enforces the §17.3 per-category pass thresholds.
The seven categories proven piecemeal in Commits 3/4/5 are run together here, producing a §17.3
conformance report and a pass/fail exit code:

    envelope_encryption    100%   (offline crypto — C3 envelope)
    wrapped_dek            100%   (offline crypto unwrap + §8 wire shapes)
    key_derivation         100%   (offline crypto — C3 keyderiv)
    error_taxonomy         100%   (§14 typed-error decode — C5b)
    envelope_versioning    100%   (offline crypto — C3 §6.5 dispositions)
    control_plane_erasure  100%   (§10.5 wire shapes — C5b)
    ingestion_idempotency  >= 90% (§7 wire shapes — C5a; the ONLY non-100% threshold, 10% slack)

``session_lifecycle`` is in the §17.1 repository structure but NOT in the §17.3 conformance
criteria: the runner EXECUTES it and REPORTS its result, but it is UN-GATED — it never affects
the pass/fail exit code. (Stated per the go-bericht.)

The §17.3 ``error_taxonomy`` threshold is "100% of the 9 PINNED tuples"; the published suite has
no vector for the other six §14.2 categories (Authentication / NotOperational / Network /
Idempotency / KeyManagement / Internal — proven by cephios-core's own unit tests, Commit 5b).
That is the published set, NOT a gap to fill — the runner does NOT fail the gate for them.

Drive model:

- Offline-crypto categories: exercise C3 crypto directly; the vector's nonce/inputs make it
  deterministic (``_construct_with_nonce`` / ``deconstruct`` / ``unwrap_dek`` / ``derive_*``).
- Wire-shape categories: Q-C2 client semantics (ratified G12-D3) — construct the documented
  request and decode the documented response over ``httpx.MockTransport`` from the vector
  fixture; NO live server. Where a v1.0 vector field is a placeholder ("<base64url-encoded ...>")
  the runner resolves it to a deterministic real value of the right size so the typed
  decode/round-trip is exercised while the request method/path/body-keys still match the vector.

Standing invariants (CLAUDE.md §9): IS — the runner CLI + report shape are a deliberate public
surface; the §17.3 thresholds mirror the spec exactly. KC — the runner exercises only
ciphertext / public-key / shape paths; no plaintext or key material appears in the report.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

from cephios_core import __version__
from cephios_core.control import (
    ControlClient,
    PublicKeyRegistered,
    SessionClosed,
    SessionOpened,
    SubjectErased,
    WrappedDekRevoked,
    WrappedDekUploaded,
    _b64url_encode,
)
from cephios_core.envelope import _construct_with_nonce, deconstruct
from cephios_core.errors import CephiosError, decode_error_response
from cephios_core.ingest import Disposition, IngestClient, bearer
from cephios_core.keyderiv import derive_member_keys, derive_salt, derive_seed_material
from cephios_core.wrapped_dek import unwrap_dek

__all__ = [
    "PROTOCOL_VERSION",
    "THRESHOLDS",
    "GATED_CATEGORIES",
    "UNGATED_CATEGORIES",
    "ALL_CATEGORIES",
    "VectorResult",
    "CategoryResult",
    "SuiteReport",
    "default_vectors_dir",
    "run_suite",
    "main",
]

#: The wire protocol version this suite verifies (§15.1 / §15.6 — decoupled from doc revision).
PROTOCOL_VERSION = "1.0"

#: §17.3 per-category pass thresholds (fraction). The gated set.
THRESHOLDS: dict[str, float] = {
    "envelope_encryption": 1.0,
    "wrapped_dek": 1.0,
    "key_derivation": 1.0,
    "error_taxonomy": 1.0,
    "envelope_versioning": 1.0,
    "control_plane_erasure": 1.0,
    "ingestion_idempotency": 0.90,  # the ONLY non-100% threshold (§17.3 — 10% edge-case slack)
}
GATED_CATEGORIES: tuple[str, ...] = tuple(THRESHOLDS)
#: §17.1-structure category that is REPORTED but NOT in the §17.3 criteria — never gates.
UNGATED_CATEGORIES: tuple[str, ...] = ("session_lifecycle",)
ALL_CATEGORIES: tuple[str, ...] = GATED_CATEGORIES + UNGATED_CATEGORIES

_THRESHOLD_EPS = 1e-9  # float tolerance so 9/10 >= 0.90 compares cleanly


# ---------------------------------------------------------------------------
# Report model.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VectorResult:
    test_id: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CategoryResult:
    category: str
    threshold: float
    gated: bool
    results: list[VectorResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def pass_fraction(self) -> float:
        return self.passed / self.total if self.total else 1.0

    @property
    def meets_threshold(self) -> bool:
        return self.pass_fraction >= self.threshold - _THRESHOLD_EPS

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "passed": self.passed,
            "total": self.total,
            "threshold": self.threshold,
            "gated": self.gated,
            "meets_threshold": self.meets_threshold,
        }


@dataclass(frozen=True, slots=True)
class SuiteReport:
    categories: list[CategoryResult]

    @property
    def gated_pass(self) -> bool:
        """The §17.3 verdict: every GATED category meets its threshold (un-gated ignored)."""
        return all(c.meets_threshold for c in self.categories if c.gated)

    def to_dict(self) -> dict[str, Any]:
        # The §17.3 publish format: protocol version, runner version, per-category result counts.
        return {
            "protocol_version": PROTOCOL_VERSION,
            "runner": "cephios-core",
            "runner_version": __version__,
            "overall": "pass" if self.gated_pass else "fail",
            "categories": [c.to_dict() for c in self.categories],
        }


# ---------------------------------------------------------------------------
# Vector loading (module-relative default — CWD-independent; overridable).
# ---------------------------------------------------------------------------


def default_vectors_dir() -> Path:
    """The vendored ``tests/vectors/v1.0`` dir, resolved RELATIVE TO THIS MODULE (not the CWD),
    so the runner finds the SHA-pinned vectors regardless of the working directory a CI runner
    invokes it from. Overridable via the CLI positional argument / ``run_suite(vectors_dir=...)``
    for an installed package whose source tree is absent."""
    return Path(__file__).resolve().parents[2] / "tests" / "vectors" / "v1.0"


def _load(vectors_dir: Path, category: str) -> list[dict[str, Any]]:
    data = json.loads((vectors_dir / f"{category}.json").read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


# ---------------------------------------------------------------------------
# Placeholder resolution (§8 SHAPE-vector fields like "<base64url-encoded 76 bytes>").
# ---------------------------------------------------------------------------


def _is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("<") and value.endswith(">")


def _resolve_placeholder_b64(value: str) -> str:
    """A deterministic real base64url value of the size the placeholder names (76 / 32 / 16)."""
    size = 76 if "76" in value else 16 if "16" in value else 32
    return _b64url_encode(bytes(size))


def _resolve(obj: Any) -> Any:
    """Recursively replace placeholder strings with deterministic real base64url values, so a
    SHAPE vector's documented response/body parses through the real typed decode path."""
    if isinstance(obj, dict):
        return {k: _resolve(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve(v) for v in obj]
    if _is_placeholder(obj):
        return _resolve_placeholder_b64(obj)
    return obj


# ---------------------------------------------------------------------------
# Wire driving helpers (httpx.MockTransport — offline, no live server).
# ---------------------------------------------------------------------------


class _Recorder:
    def __init__(self, status: int, body: Any, headers: Mapping[str, str] | None = None) -> None:
        self._status, self._body, self._headers = status, body, dict(headers or {})
        self.request: httpx.Request | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.request = request
        return httpx.Response(self._status, json=self._body, headers=self._headers)


def _request_path_method_ok(request: httpx.Request | None, spec: Mapping[str, Any]) -> bool:
    if request is None:
        return False
    return request.method == str(spec["method"]) and request.url.path == str(spec["path"])


def _json_body_matches(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    """Placeholder-tolerant body match: key sets equal; concrete values equal; a placeholder
    field need only be present + non-empty (the client encoded SOME real value for it)."""
    if set(actual) != set(expected):
        return False
    for key, exp in expected.items():
        if _is_placeholder(exp):
            if not str(actual.get(key, "")):
                return False
        elif actual.get(key) != exp:
            return False
    return True


# ---------------------------------------------------------------------------
# Offline-crypto category checkers (C3).
# ---------------------------------------------------------------------------


def _check_envelope_encryption(vectors: Sequence[dict[str, Any]]) -> list[VectorResult]:
    out: list[VectorResult] = []
    for v in vectors:
        out.append(VectorResult(v["test_id"], *_one_envelope(v)))
    return out


def _one_envelope(v: dict[str, Any]) -> tuple[bool, str]:
    inp, exp = v["input"], v["expected_output"]
    op = inp["operation"]
    try:
        if op == "construct":
            env = _construct_with_nonce(
                bytes.fromhex(inp["dek_hex"]),
                inp["plaintext_utf8"].encode("utf-8"),
                bytes.fromhex(inp["nonce_hex"]),
            )
            ok = env.hex() == exp["envelope_hex"] and len(env) == exp["envelope_byte_count"]
            return ok, "" if ok else "envelope bytes mismatch"
        if op == "deconstruct":
            env = bytes.fromhex(inp["envelope_hex"])
            dek = bytes.fromhex(inp["dek_hex"])
            if "error" in exp:
                return _expect_error(lambda: deconstruct(env, dek), exp["error"])
            pt = deconstruct(env, dek).decode("utf-8")
            ok = pt == exp["plaintext_utf8"]
            return ok, "" if ok else "plaintext mismatch"
    except Exception as exc:  # noqa: BLE001 — any unexpected failure is a vector failure
        return False, f"unexpected {type(exc).__name__}: {exc}"
    return False, f"unknown operation {op!r}"


def _expect_error(thunk: Any, expected: Mapping[str, Any]) -> tuple[bool, str]:
    """Run ``thunk``; pass iff it raises a CephiosError with the expected category/code/status."""
    try:
        thunk()
    except CephiosError as exc:
        ok = (
            exc.category == expected["category"]
            and exc.code == expected["code"]
            and exc.http_status == expected.get("http_status", exc.http_status)
        )
        return ok, "" if ok else f"got {exc.category} {exc.code!r} ({exc.http_status})"
    except Exception as exc:  # noqa: BLE001
        return False, f"unexpected {type(exc).__name__}: {exc}"
    return False, "expected an error, none raised"


def _check_envelope_versioning(vectors: Sequence[dict[str, Any]]) -> list[VectorResult]:
    out: list[VectorResult] = []
    for v in vectors:
        env = bytes.fromhex(v["input"]["envelope_hex"])
        dek = bytes.fromhex(v["input"]["dek_hex"])
        ok, detail = _expect_error(
            lambda e=env, d=dek: deconstruct(e, d), v["expected_output"]["error"]
        )
        out.append(VectorResult(v["test_id"], ok, detail))
    return out


def _check_key_derivation(vectors: Sequence[dict[str, Any]]) -> list[VectorResult]:
    out: list[VectorResult] = []
    for v in vectors:
        inp, exp = v["input"], v["expected_output"]
        try:
            pw, uid = inp["master_password_utf8"], inp["user_id"]
            keys = derive_member_keys(pw, uid)
            ok = (
                derive_salt(uid).hex() == exp["salt_hex"]
                and derive_seed_material(pw, uid).hex() == exp["seed_material_hex"]
                and keys.x25519_private_key_seed.hex() == exp["x25519_private_key_seed_hex"]
                and keys.x25519_public_key.hex() == exp["x25519_public_key_hex"]
                and keys.auth_verification_token.hex() == exp["auth_verification_token_hex"]
                and keys.auth_verification_token_sha256.hex()
                == exp["auth_verification_token_sha256_hex"]
            )
            out.append(VectorResult(v["test_id"], ok, "" if ok else "derived field mismatch"))
        except Exception as exc:  # noqa: BLE001
            out.append(VectorResult(v["test_id"], False, f"unexpected {type(exc).__name__}: {exc}"))
    return out


# ---------------------------------------------------------------------------
# Wire-shape category checkers (C5a/C5b clients over MockTransport, Q-C2).
# ---------------------------------------------------------------------------


def _check_ingestion_idempotency(vectors: Sequence[dict[str, Any]]) -> list[VectorResult]:
    out: list[VectorResult] = []
    for v in vectors:
        req, resp = v["input"]["request"], v["expected_output"]["response"]
        out.append(VectorResult(v["test_id"], *_one_ingestion(req, resp)))
    return out


def _one_ingestion(req: Mapping[str, Any], resp: Mapping[str, Any]) -> tuple[bool, str]:
    try:
        sid = UUID(req["headers"]["X-Cephios-Session-Id"])
        seq = int(req["headers"]["X-Cephios-Batch-Sequence"])
        body = bytes.fromhex(req["body_hex"])
        rec = _Recorder(resp["status"], resp["body"], resp.get("headers"))
        with IngestClient(credential=bearer("t"), transport=httpx.MockTransport(rec)) as client:
            outcome = client.ingest(sid, seq, body)
        if not _request_path_method_ok(rec.request, req):
            return False, "request method/path mismatch"
        assert rec.request is not None
        if rec.request.headers.get("Content-Type") != req["headers"]["Content-Type"]:
            return False, "Content-Type mismatch"
        if rec.request.content != body:
            return False, "raw octet body mismatch"
        ok = outcome.disposition is Disposition.ACK and outcome.ack is not None and (
            outcome.ack.status == resp["body"]["status"]
        )
        return ok, "" if ok else f"disposition {outcome.disposition}"
    except Exception as exc:  # noqa: BLE001
        return False, f"unexpected {type(exc).__name__}: {exc}"


def _check_error_taxonomy(vectors: Sequence[dict[str, Any]]) -> list[VectorResult]:
    """error_taxonomy gates §14 typed-error DECODE compliance — the documented response is a
    typed error. We synthesize the §14.1 envelope from the vector's (category, code) and decode
    it via the §14 decoder (the request shapes — /v1/ingest, /v1/sessions, /v1/grants — are
    gated by ingestion_idempotency / session_lifecycle / the §14.2 status mapping)."""
    out: list[VectorResult] = []
    for v in vectors:
        err = v["expected_output"]["error"]
        body = json.dumps({"error": {"category": err["category"], "code": err["code"]}}).encode()
        decoded = decode_error_response(err["http_status"], body)
        ok = (
            type(decoded).__name__ == err["category"]
            and decoded.code == err["code"]
            and decoded.http_status == err["http_status"]
        )
        detail = "" if ok else f"got {type(decoded).__name__} {decoded.code!r}"
        out.append(VectorResult(v["test_id"], ok, detail))
    return out


def _check_control_plane_erasure(vectors: Sequence[dict[str, Any]]) -> list[VectorResult]:
    out: list[VectorResult] = []
    for v in vectors:
        req, resp = v["input"]["request"], v["expected_output"]["response"]
        out.append(VectorResult(v["test_id"], *_one_erasure(req, resp)))
    return out


def _one_erasure(req: Mapping[str, Any], resp: Mapping[str, Any]) -> tuple[bool, str]:
    try:
        subject_id = UUID(req["path"].split("/")[3])
        body = resp["body"]
        rec = _Recorder(resp["status"], body)
        with ControlClient(credential=bearer("t"), transport=httpx.MockTransport(rec)) as client:
            result = client.erase_subject(subject_id)
        if not _request_path_method_ok(rec.request, req):
            return False, "request method/path mismatch"
        ok = result.status == body["status"] and isinstance(result, SubjectErased)
        if body["status"] == "erased":
            ok = ok and result.audit_entry_id is not None and result.erased_at is not None
        else:  # already_erased: no new proof row
            ok = ok and result.audit_entry_id is None
        return ok, "" if ok else f"status {result.status!r}"
    except Exception as exc:  # noqa: BLE001
        return False, f"unexpected {type(exc).__name__}: {exc}"


def _check_session_lifecycle(vectors: Sequence[dict[str, Any]]) -> list[VectorResult]:
    out: list[VectorResult] = []
    for v in vectors:
        req, resp = v["input"]["request"], v["expected_output"]["response"]
        out.append(VectorResult(v["test_id"], *_one_session(req, resp)))
    return out


def _one_session(req: Mapping[str, Any], resp: Mapping[str, Any]) -> tuple[bool, str]:
    try:
        rec = _Recorder(resp["status"], resp["body"])
        transport = httpx.MockTransport(rec)
        if req["path"].endswith("/close"):
            sid = UUID(req["path"].split("/")[3])
            with ControlClient(credential=bearer("t"), transport=transport) as client:
                result: SessionOpened | SessionClosed = client.close_session(sid)
            shaped = isinstance(result, SessionClosed) and result.state == resp["body"]["state"]
        else:  # POST /v1/sessions — open
            b = req["body"]
            with ControlClient(credential=bearer("t"), transport=transport) as client:
                result = client.open_session(
                    session_id=UUID(b["session_id"]),
                    workspace_id=UUID(b["workspace_id"]),
                    subject_id=UUID(b["subject_id"]),
                    consent_record_id=UUID(b["consent_record_id"]),
                    modality=b["modality"],
                    schema_declaration=b["schema_declaration"],
                    dek_version=b["dek_version"],
                )
            shaped = isinstance(result, SessionOpened) and result.state == resp["body"]["state"]
        ok = _request_path_method_ok(rec.request, req) and shaped
        return ok, "" if ok else "request/response shape mismatch"
    except Exception as exc:  # noqa: BLE001
        return False, f"unexpected {type(exc).__name__}: {exc}"


def _check_wrapped_dek(vectors: Sequence[dict[str, Any]]) -> list[VectorResult]:
    """Mixed category: the crypto unwrap vector + the five §8 HTTP SHAPE vectors."""
    out: list[VectorResult] = []
    for v in vectors:
        inp = v["input"]
        if inp.get("operation") == "unwrap_dek":
            try:
                env = bytes.fromhex(inp["wrapped_dek_envelope_hex"])
                dek = unwrap_dek(env, bytes.fromhex(inp["recipient_private_key_hex"]))
                ok = (
                    dek.hex() == v["expected_output"]["dek_hex"]
                    and len(env) == v["expected_output"]["wrap_envelope_byte_count"]
                )
                out.append(VectorResult(v["test_id"], ok, "" if ok else "unwrap mismatch"))
            except Exception as exc:  # noqa: BLE001
                out.append(VectorResult(v["test_id"], False, f"unexpected {type(exc).__name__}"))
        else:
            ok, detail = _one_wrapped_dek_shape(inp, v["expected_output"])
            out.append(VectorResult(v["test_id"], ok, detail))
    return out


def _one_wrapped_dek_shape(inp: Mapping[str, Any], exp: Mapping[str, Any]) -> tuple[bool, str]:
    """Drive the §8 endpoint the vector documents; SHAPE vectors carry base64url placeholders,
    so the runner feeds deterministic real bytes for placeholder request fields and resolves
    placeholder response fields before the typed decode."""
    req = inp["request"]
    resp = exp["response"]
    method, path = req["method"], req["path"]
    rec = _Recorder(resp["status"], _resolve(resp["body"]))
    transport = httpx.MockTransport(rec)
    try:
        with ControlClient(credential=bearer("t"), transport=transport) as client:
            if path.endswith("/public-key"):
                member_id = UUID(path.split("/")[3])
                result: Any = client.register_public_key(
                    member_id, public_key_x25519=bytes(32),
                    auth_verification_token_sha256=bytes(32), public_key_fingerprint=bytes(32),
                )
                shaped = isinstance(result, PublicKeyRegistered) and result.member_id == member_id
            elif path.endswith("/revoke"):
                wrapped_dek_id = UUID(path.split("/")[3])
                result = client.revoke_wrapped_dek(wrapped_dek_id, reason=req["body"]["reason"])
                shaped = isinstance(result, WrappedDekRevoked)
            elif method == "POST" and path.endswith("/wrapped-deks"):
                tenant_id = UUID(path.split("/")[3])
                result = client.upload_wrapped_dek(
                    tenant_id, for_member_id=UUID(req["body"]["for_member_id"]),
                    dek_version=req["body"]["dek_version"], wrapped_dek_envelope=bytes(76),
                    wrapped_by_member_id=UUID("018f0c00-0000-7000-8000-0000000000aa"),
                )
                shaped = isinstance(result, WrappedDekUploaded)
            else:  # GET .../wrapped-deks (fetch — current or empty)
                member_id = UUID(path.split("/")[3])
                records = client.fetch_wrapped_deks(member_id)
                shaped = len(records) == len(resp["body"]["wrapped_deks"])
                result = records
        ok = _request_path_method_ok(rec.request, req) and shaped
        return ok, "" if ok else "request/response shape mismatch"
    except Exception as exc:  # noqa: BLE001
        return False, f"unexpected {type(exc).__name__}: {exc}"


_CHECKERS = {
    "envelope_encryption": _check_envelope_encryption,
    "envelope_versioning": _check_envelope_versioning,
    "key_derivation": _check_key_derivation,
    "wrapped_dek": _check_wrapped_dek,
    "ingestion_idempotency": _check_ingestion_idempotency,
    "error_taxonomy": _check_error_taxonomy,
    "control_plane_erasure": _check_control_plane_erasure,
    "session_lifecycle": _check_session_lifecycle,
}


# ---------------------------------------------------------------------------
# Suite + CLI.
# ---------------------------------------------------------------------------


def run_suite(vectors_dir: Path | None = None) -> SuiteReport:
    """Run every §17.1 category against the vendored vectors and build the §17.3 report."""
    vectors_dir = vectors_dir or default_vectors_dir()
    categories: list[CategoryResult] = []
    for category in ALL_CATEGORIES:
        gated = category in THRESHOLDS
        threshold = THRESHOLDS.get(category, 1.0)
        results = _CHECKERS[category](_load(vectors_dir, category))
        categories.append(
            CategoryResult(category=category, threshold=threshold, gated=gated, results=results)
        )
    return SuiteReport(categories=categories)


def _format_report(report: SuiteReport) -> str:
    lines = [
        f"Cephios conformance — protocol v{PROTOCOL_VERSION} — runner cephios-core {__version__}",
        f"{'category':<24} {'passed/total':>12} {'threshold':>10} {'gated':>6}  result",
        "-" * 72,
    ]
    for c in report.categories:
        thr = f"{int(c.threshold * 100)}%"
        verdict = "PASS" if c.meets_threshold else "FAIL"
        if not c.gated:
            verdict = "(report-only)"
        lines.append(
            f"{c.category:<24} {f'{c.passed}/{c.total}':>12} {thr:>10} "
            f"{('yes' if c.gated else 'no'):>6}  {verdict}"
        )
    lines.append("-" * 72)
    lines.append(f"§17.3 GATE: {'PASS' if report.gated_pass else 'FAIL'}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Exit 0 iff every GATED §17.3 category meets its threshold; non-zero
    otherwise. ``session_lifecycle`` is reported but never affects the exit code."""
    parser = argparse.ArgumentParser(description="Run the Cephios v1.0 §17.3 conformance suite.")
    parser.add_argument(
        "vectors_dir", nargs="?", default=None,
        help="path to the v1.0 vector directory (default: the vendored tests/vectors/v1.0)",
    )
    parser.add_argument("--json", action="store_true", help="emit the §17.3 report as JSON")
    args = parser.parse_args(argv)

    vectors_dir = Path(args.vectors_dir) if args.vectors_dir else default_vectors_dir()
    report = run_suite(vectors_dir)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_format_report(report))
    return 0 if report.gated_pass else 1


if __name__ == "__main__":  # `python -m cephios_core.conformance`
    sys.exit(main())
