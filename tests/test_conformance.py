"""The §17.3 conformance gate (CONTRACT_SPEC.md §17) — Commit 6.

Proves the runner (1) passes the full vendored v1.0 suite against the §17.3 thresholds, (2)
actually GATES — a single failing gated vector flips the exit code, (3) wires the per-category
thresholds correctly (the 90% ingestion slack is real, not all-100 / all-90), and (4) treats
session_lifecycle as reported-but-UN-gated. Offline + deterministic (the runner uses
MockTransport for wire categories; no live server).
"""

from __future__ import annotations

import json

import cephios_core.conformance as conf
from cephios_core.conformance import (
    THRESHOLDS,
    UNGATED_CATEGORIES,
    CategoryResult,
    VectorResult,
    default_vectors_dir,
    main,
    run_suite,
)


def _cat(category: str, passed: int, total: int, threshold: float, gated: bool) -> CategoryResult:
    results = [VectorResult(f"v{i}", i < passed) for i in range(total)]
    return CategoryResult(category=category, threshold=threshold, gated=gated, results=results)


# ---------------------------------------------------------------------------
# §17.3 thresholds mirror the spec exactly.
# ---------------------------------------------------------------------------


def test_thresholds_mirror_section_17_3():
    assert THRESHOLDS == {
        "envelope_encryption": 1.0,
        "wrapped_dek": 1.0,
        "key_derivation": 1.0,
        "error_taxonomy": 1.0,
        "envelope_versioning": 1.0,
        "control_plane_erasure": 1.0,
        "ingestion_idempotency": 0.90,  # the ONLY non-100% threshold
    }
    # session_lifecycle is in §17.1 structure but NOT a §17.3 gated criterion.
    assert "session_lifecycle" not in THRESHOLDS
    assert UNGATED_CATEGORIES == ("session_lifecycle",)


# ---------------------------------------------------------------------------
# The full vendored suite passes the gate.
# ---------------------------------------------------------------------------


def test_full_suite_passes_the_gate():
    report = run_suite()
    assert report.gated_pass, "the vendored v1.0 suite must pass the §17.3 gate"
    by_cat = {c.category: c for c in report.categories}

    # Every GATED category meets its threshold.
    for c in report.categories:
        if c.gated:
            assert c.meets_threshold, f"{c.category} below threshold: {c.passed}/{c.total}"

    # error_taxonomy gates exactly the 9 PINNED tuples (NOT the 12 §14.2 categories — the six
    # vector-less categories are not a gate failure).
    assert by_cat["error_taxonomy"].passed == 9 and by_cat["error_taxonomy"].total == 9

    # ingestion_idempotency is the only >=90% (not 100%) gated category.
    assert by_cat["ingestion_idempotency"].threshold == 0.90
    assert by_cat["ingestion_idempotency"].meets_threshold

    # session_lifecycle is executed + reported, but UN-gated.
    sess = by_cat["session_lifecycle"]
    assert sess.gated is False
    assert sess.total == 2 and sess.passed == 2  # it does in fact pass, but does not gate


def test_main_exits_zero_and_publishes_report():
    assert main([]) == 0  # human report, gate passes


def test_main_json_publish_format():
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["--json"])
    assert rc == 0
    doc = json.loads(buf.getvalue())
    assert doc["protocol_version"] == "1.0"
    assert doc["runner"] == "cephios-core"
    assert doc["overall"] == "pass"
    assert {c["category"] for c in doc["categories"]} == set(THRESHOLDS) | {"session_lifecycle"}


def test_default_vectors_dir_resolves_to_the_pinned_suite():
    d = default_vectors_dir()
    assert d.is_dir()
    for category in (*THRESHOLDS, "session_lifecycle"):
        assert (d / f"{category}.json").is_file()


# ---------------------------------------------------------------------------
# RED-CAPABLE: the gate actually gates (a failing gated vector -> non-zero exit).
# ---------------------------------------------------------------------------


def test_gate_fails_when_a_gated_category_regresses(monkeypatch):
    # Inject a real impl regression: corrupt the envelope construction the runner drives.
    # envelope_encryption drops below 100% -> the §17.3 gate FAILS (exit non-zero). RED: without
    # this, the gate is a rubber stamp.
    monkeypatch.setattr(conf, "_construct_with_nonce", lambda dek, pt, nonce: b"\x00" * 33)
    report = run_suite()
    env = next(c for c in report.categories if c.category == "envelope_encryption")
    assert env.passed < env.total  # the construct vector now fails
    assert env.meets_threshold is False
    assert report.gated_pass is False
    assert main([]) == 1  # non-zero exit — the gate gated


# ---------------------------------------------------------------------------
# RED-CAPABLE: the 90%-vs-100% per-category wiring is real (not all-100 / all-90).
# ---------------------------------------------------------------------------


def test_per_category_threshold_wiring():
    # A 90%-threshold category at 90% MEETS; the same 90% MISSES a 100% threshold.
    assert _cat("ingestion_idempotency", 9, 10, 0.90, True).meets_threshold is True
    assert _cat("envelope_encryption", 9, 10, 1.00, True).meets_threshold is False
    # A 100% gated category at 99% FAILS; a 90% category at 90% PASSES — proving they are NOT
    # all hard-coded to the same threshold.
    assert _cat("error_taxonomy", 99, 100, 1.00, True).meets_threshold is False
    assert _cat("ingestion_idempotency", 90, 100, 0.90, True).meets_threshold is True
    # An empty category is vacuously 100% (no vectors to fail).
    assert _cat("x", 0, 0, 1.0, True).meets_threshold is True


# ---------------------------------------------------------------------------
# RED-CAPABLE: session_lifecycle is un-gated (a failure does NOT fail the gate).
# ---------------------------------------------------------------------------


def test_session_lifecycle_failure_does_not_fail_the_gate(monkeypatch):
    # Force every session_lifecycle vector to fail; the exit code stays ZERO because the
    # category is reported-only. RED: if session_lifecycle were gated, this would exit non-zero.
    monkeypatch.setattr(conf, "_one_session", lambda req, resp: (False, "injected failure"))
    report = run_suite()
    sess = next(c for c in report.categories if c.category == "session_lifecycle")
    assert sess.passed == 0 and sess.total == 2  # all session vectors failing
    assert sess.meets_threshold is False
    assert report.gated_pass is True  # ... yet the GATE still passes (session is un-gated)
    assert main([]) == 0


def test_gated_category_failure_still_fails_even_with_session_passing(monkeypatch):
    # Symmetry check: a GATED category failing DOES fail the gate (so the prior test isn't just
    # "nothing ever fails"). Corrupt key_derivation.
    monkeypatch.setattr(conf, "derive_salt", lambda uid: b"\x00" * 16)
    report = run_suite()
    kd = next(c for c in report.categories if c.category == "key_derivation")
    assert kd.meets_threshold is False
    assert report.gated_pass is False
