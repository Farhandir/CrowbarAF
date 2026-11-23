"""Small helpers shared by the analyzer modules."""

from __future__ import annotations


def _unique(items: list[str]) -> list[str]:
    """Deduplicates while preserving order."""
    return list(dict.fromkeys(items))
