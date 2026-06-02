"""cephios-core — the Python reference implementation of The Cephios Protocol v1.0.

This module is the single source of truth for the package version: hatchling reads
``__version__`` here via ``[tool.hatch.version]`` in ``pyproject.toml``. The protocol
surface itself (key derivation, envelope, wrapped-DEK, ingestion, buffer, errors) is
implemented in subsequent Group 12 commits; this scaffold deliberately exposes nothing
beyond the version so the public API can be added deliberately under the IS commitment.
"""

__version__ = "0.1.0"
