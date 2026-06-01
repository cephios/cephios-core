"""Smoke test: the package imports and exposes a non-empty version string.

This is the green anchor for CI; it is not a conformance or crypto test (those arrive
in later Group 12 commits).
"""

import cephios_core


def test_import_and_version() -> None:
    assert isinstance(cephios_core.__version__, str)
    assert cephios_core.__version__
