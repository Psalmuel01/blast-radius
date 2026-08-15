"""Shared helpers for queries."""

from __future__ import annotations

from ..graph.model import parse_version


def sort_versions(versions) -> list[str]:
    """Sort semver strings ascending; unparseable ones sort last, by name."""
    cleaned = [v for v in versions if v]
    parsed = [(parse_version(v), v) for v in cleaned]
    ok = sorted([(p, v) for p, v in parsed if p is not None])
    bad = sorted(v for p, v in parsed if p is None)
    return [v for _, v in ok] + bad
