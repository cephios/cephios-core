"""Guard: the vendored v1.0 vectors match the pinned SHA-256 manifest (no silent drift)."""

from __future__ import annotations

import hashlib
import json

from vector_loader import MANIFEST_PATH, VECTORS_DIR


def test_vendored_vectors_match_pin():
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    pinned = manifest["sha256"]
    on_disk = sorted(p.name for p in VECTORS_DIR.glob("*.json"))
    assert on_disk == sorted(pinned), "vendored file set differs from the pinned manifest"
    for name, expected in pinned.items():
        actual = hashlib.sha256((VECTORS_DIR / name).read_bytes()).hexdigest()
        assert actual == expected, f"{name} drifted from pinned upstream {manifest['commit']}"
