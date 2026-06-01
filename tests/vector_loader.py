"""Load the vendored, pinned Cephios Protocol v1.0 conformance vectors (see UPSTREAM.json)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_BASE = Path(__file__).parent / "vectors"
VECTORS_DIR = _BASE / "v1.0"
MANIFEST_PATH = _BASE / "UPSTREAM.json"


def load_category(category: str) -> list[dict[str, Any]]:
    """Return the list of vector objects for a category (e.g. ``key_derivation``)."""
    data = json.loads((VECTORS_DIR / f"{category}.json").read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


def vector(category: str, test_id: str) -> dict[str, Any]:
    """Return the single vector object with ``test_id`` from ``category``."""
    for item in load_category(category):
        if item["test_id"] == test_id:
            return item
    raise KeyError(f"vector {test_id!r} not found in {category}")
