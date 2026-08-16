"""Typosquat heuristic tests.

The risk with this query is false positives: legitimate packages routinely sit
within edit distance 2 of each other. These tests pin the filters that keep
popular neighbours out of the results.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hydra_blast.graph.model import Entity, Graph, NS_PACKAGE, pkg_id  # noqa: E402
from hydra_blast.queries.typosquat import levenshtein, typosquat_candidates  # noqa: E402

NOW = datetime(2026, 8, 15, tzinfo=timezone.utc)


def add(graph, name, downloads, first_release=None):
    graph.add_entity(
        Entity(pkg_id(name), name, NS_PACKAGE,
               {"downloads": downloads, "first_release": first_release})
    )


def fixture():
    g = Graph()
    add(g, "chalk", 1_930_852_396, "2013-01-01T00:00:00Z")
    # Obvious squats: near-identical name, no downloads, brand new.
    recent = (NOW - timedelta(days=10)).isoformat().replace("+00:00", "Z")
    add(g, "chak", 12, recent)
    add(g, "chalkk", 3, recent)
    add(g, "ch4lk", 7, recent)          # homoglyph
    add(g, "chalk-js", 5, recent)       # padded name
    # Legitimate neighbours that must NOT be flagged.
    add(g, "chalk-template", 40_000_000, "2022-01-01T00:00:00Z")
    add(g, "colors", 900_000_000, "2011-01-01T00:00:00Z")
    return g


def test_flags_obvious_squats():
    result = typosquat_candidates(fixture(), "chalk", now=NOW)
    names = result.names()
    assert "chak" in names
    assert "chalkk" in names


def test_ignores_popular_neighbours():
    """A hugely popular near-name is a real package, not a squat."""
    result = typosquat_candidates(fixture(), "chalk", now=NOW)
    assert "chalk-template" not in result.names()


def test_detects_homoglyph_and_padding():
    rows = {r["package"]: r for r in typosquat_candidates(fixture(), "chalk", now=NOW).rows}
    assert rows["ch4lk"]["pattern"] == "homoglyph"
    assert rows["chalk-js"]["pattern"] == "padded-name"


def test_unrelated_names_excluded():
    assert "colors" not in typosquat_candidates(fixture(), "chalk", now=NOW).names()


def test_ranking_puts_closest_first():
    rows = typosquat_candidates(fixture(), "chalk", now=NOW).rows
    assert rows[0]["score"] >= rows[-1]["score"]


def test_levenshtein():
    assert levenshtein("chalk", "chalk") == 0
    assert levenshtein("chalk", "chak") == 1
    assert levenshtein("chalk", "ch4lk") == 1
    assert levenshtein("chalk", "totally-different", cap=3) > 3


def test_scoped_names_compared_without_scope():
    g = fixture()
    add(g, "@evil/chalk", 2, (NOW - timedelta(days=5)).isoformat().replace("+00:00", "Z"))
    assert "@evil/chalk" in typosquat_candidates(g, "chalk", now=NOW).names()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} test functions passed")
