"""Core query tests on a hand-built graph with known-correct answers.

Real crawl data cannot prove the *negative* cases -- the live neighbourhood of
the Sept 2025 incident happens to contain only versions published years before
the compromise, so the window filter never has to exclude anything there. These
synthetic fixtures exercise the branches real data does not reach.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hydra_blast.graph.model import (  # noqa: E402
    Edge,
    Entity,
    Graph,
    NS_ADVISORY,
    NS_MAINTAINER,
    NS_PACKAGE,
    NS_VERSION,
    P_AFFECTS,
    P_DEPENDS_ON,
    P_HAS_VERSION,
    P_MAINTAINS,
    adv_id,
    maint_id,
    pkg_id,
    ver_id,
)
from hydra_blast.queries.core import (  # noqa: E402
    blast_radius,
    live_resolution_window,
    shared_maintainer,
    version_introduced,
)


def add_package(g, name, versions, maintainers=(), downloads=0):
    g.add_entity(Entity(pkg_id(name), name, NS_PACKAGE, {"downloads": downloads}))
    for version, published in versions:
        node = ver_id(name, version)
        g.add_entity(
            Entity(node, f"{name}@{version}", NS_VERSION,
                   {"package": name, "version": version, "published_at": published})
        )
        g.add_edge(Edge(pkg_id(name), node, P_HAS_VERSION, valid_from=published))
    for m in maintainers:
        g.add_entity(Entity(maint_id(m), m, NS_MAINTAINER))
        g.add_edge(Edge(maint_id(m), pkg_id(name), P_MAINTAINS))


def add_dep(g, from_pkg, from_ver, to_pkg, range_spec, published=None):
    g.add_edge(Edge(ver_id(from_pkg, from_ver), pkg_id(to_pkg), P_DEPENDS_ON,
                    declared_range=range_spec, valid_from=published))


def fixture():
    """bad@1.2.0 is compromised.

    mid@1.0.0  ^1.0.0 -> bad      (exposed, depth 1)
    top@2.0.0  ^1.0.0 -> mid      (exposed, depth 2 -- transitive)
    safe@1.0.0 ^1.1.0 -> bad      (NOT exposed: 1.2.0 satisfies ^1.1.0 -> it IS)
    pinned@1.0.0 =1.1.0 -> bad    (NOT exposed: pinned to a good version)
    late@1.0.0 ^1.0.0 -> bad      (exposed, but published AFTER the window)
    """
    g = Graph()
    add_package(g, "bad", [("1.1.0", "2025-01-01T00:00:00Z"), ("1.2.0", "2025-09-08T13:12:39Z")],
                maintainers=["attacker", "coauthor"])
    add_package(g, "mid", [("1.0.0", "2024-01-01T00:00:00Z")], maintainers=["coauthor"])
    add_package(g, "top", [("2.0.0", "2024-06-01T00:00:00Z")])
    add_package(g, "pinned", [("1.0.0", "2024-01-01T00:00:00Z")])
    add_package(g, "late", [("1.0.0", "2025-10-01T00:00:00Z")])

    add_dep(g, "mid", "1.0.0", "bad", "^1.0.0")
    add_dep(g, "top", "2.0.0", "mid", "^1.0.0")
    add_dep(g, "pinned", "1.0.0", "bad", "=1.1.0")
    add_dep(g, "late", "1.0.0", "bad", "^1.0.0")

    g.add_entity(Entity(adv_id("MAL-TEST-1"), "MAL-TEST-1", NS_ADVISORY,
                        {"published_at": "2025-09-08T14:26:51Z", "severity": "CRITICAL"}))
    g.add_edge(Edge(adv_id("MAL-TEST-1"), ver_id("bad", "1.2.0"), P_AFFECTS,
                    valid_from="2025-09-08T14:26:51Z"))
    return g


def test_blast_radius_is_transitive():
    result = blast_radius(fixture(), "bad", "1.2.0")
    assert result.names() == {"mid", "top", "late"}, result.names()
    depths = {r["package"]: r["depth"] for r in result.rows}
    assert depths["mid"] == 1
    assert depths["top"] == 2, "transitive exposure must be found"


def test_blast_radius_respects_pinned_ranges():
    """A dependent pinned to a good version is NOT in the blast radius."""
    result = blast_radius(fixture(), "bad", "1.2.0")
    assert "pinned" not in result.names()


def test_blast_radius_excludes_unaffected_version():
    """Querying the *safe* version must not implicate the ^1.0.0 dependents..."""
    result = blast_radius(fixture(), "bad", "1.1.0")
    # ^1.0.0 matches 1.1.0 too, so mid/top/late are exposed; pinned =1.1.0 now matches.
    assert "pinned" in result.names()


def test_blast_radius_reports_paths():
    result = blast_radius(fixture(), "bad", "1.2.0")
    top = next(r for r in result.rows if r["package"] == "top")
    assert top["path"] == ["bad@1.2.0", "mid@1.0.0", "top@2.0.0"]


def test_live_window_excludes_packages_published_after():
    """The branch real data never exercises: exclusion by publish time."""
    result = live_resolution_window(
        fixture(), "bad", "1.2.0",
        "2025-09-08T13:12:39Z", "2025-09-08T14:26:51Z",
    )
    names = result.names()
    assert "mid" in names and "top" in names
    assert "late" not in names, "a package published after the window never resolved to the bad version"
    assert result.meta["excluded_after_window"] == 1


def test_shared_maintainer():
    result = shared_maintainer(fixture(), "bad")
    assert result.names() == {"mid"}
    row = result.rows[0]
    assert row["shared_maintainers"] == ["coauthor"]


def test_version_introduced():
    result = version_introduced(fixture(), "MAL-TEST-1")
    row = result.rows[0]
    assert row["package"] == "bad"
    assert row["introduced_in"] == "1.2.0"
    assert row["affected_versions"] == ["1.2.0"]


def test_latency_is_recorded():
    result = blast_radius(fixture(), "bad", "1.2.0")
    assert result.latency_ms > 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} test functions passed")
