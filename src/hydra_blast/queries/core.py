"""The core defender queries, all expressed as graph traversals.

Each returns a result carrying `latency_ms`, since query latency is a stated
scoring dimension.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from ..graph.model import (
    Edge,
    Graph,
    NS_PACKAGE,
    P_AFFECTS,
    P_DEPENDS_ON,
    P_HAS_VERSION,
    P_MAINTAINS,
    adv_id,
    maint_id,
    pkg_id,
    satisfies,
    ver_id,
)


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class QueryResult:
    query: str
    subject: str
    rows: list[dict] = field(default_factory=list)
    latency_ms: float = 0.0
    meta: dict[str, Any] = field(default_factory=dict)

    def names(self) -> set[str]:
        return {r["package"] for r in self.rows if r.get("package")}


# ---------------------------------------------------------------------------
# 1. Blast radius
# ---------------------------------------------------------------------------

def blast_radius(
    graph: Graph,
    package: str,
    version: str,
    *,
    max_depth: int = 10,
    include_paths: bool = True,
) -> QueryResult:
    """Transitive closure of versions exposed to `package@version`.

    Traversal: for the compromised version, walk `depends_on` edges *inbound*
    to find every version whose declared range the bad version satisfies, then
    repeat from each newly exposed version. Depth is the dependency distance,
    so depth 1 is a direct dependent.

    The range check is the crux: an inbound edge only counts if the compromised
    version actually satisfies the range that dependent declared.
    """
    started = _now_ms()
    target_package = pkg_id(package)

    # depth 0 is the compromised version itself.
    exposed: dict[str, dict] = {}
    # Frontier holds packages whose *versions* are newly exposed.
    frontier: list[tuple[str, str, int, list[str]]] = [(package, version, 0, [f"{package}@{version}"])]
    seen_versions: set[str] = {ver_id(package, version)}
    truncated = False

    while frontier:
        current_package, current_version, depth, path = frontier.pop()
        if depth >= max_depth:
            truncated = True
            continue

        # Who declares a dependency on this package, with a range that the
        # exposed version satisfies?
        for edge in graph.in_edges(pkg_id(current_package), P_DEPENDS_ON):
            if not satisfies(current_version, edge.declared_range):
                continue

            dependent_version_node = edge.source
            if dependent_version_node in seen_versions:
                continue
            entity = graph.entities.get(dependent_version_node)
            if entity is None:
                continue

            seen_versions.add(dependent_version_node)
            dep_package = entity.attrs.get("package")
            dep_version = entity.attrs.get("version")
            if not dep_package or not dep_version:
                continue

            new_path = path + [f"{dep_package}@{dep_version}"]
            record = exposed.get(dependent_version_node)
            if record is None or depth + 1 < record["depth"]:
                exposed[dependent_version_node] = {
                    "package": dep_package,
                    "version": dep_version,
                    "depth": depth + 1,
                    "via": f"{current_package}@{current_version}",
                    "declared_range": edge.declared_range,
                    "published_at": entity.attrs.get("published_at"),
                    "path": new_path if include_paths else None,
                }
            frontier.append((dep_package, dep_version, depth + 1, new_path))

    rows = sorted(exposed.values(), key=lambda r: (r["depth"], r["package"], r["version"]))
    latency = _now_ms() - started

    distinct_packages = {r["package"] for r in rows}
    return QueryResult(
        query="blast_radius",
        subject=f"{package}@{version}",
        rows=rows,
        latency_ms=latency,
        meta={
            "exposed_versions": len(rows),
            "exposed_packages": len(distinct_packages),
            "max_depth_reached": max((r["depth"] for r in rows), default=0),
            "truncated": truncated,
        },
    )


# ---------------------------------------------------------------------------
# 2. Shared maintainer
# ---------------------------------------------------------------------------

def shared_maintainer(graph: Graph, package: str) -> QueryResult:
    """Packages sharing at least one maintainer account with `package`.

    Traversal: Package <- maintains - Maintainer - maintains -> Package.
    This is the query that catches the *next* package an attacker can push to
    once they hold a credential, which is how the Sept 2025 npm campaign
    spread across 17 packages.
    """
    started = _now_ms()
    package_node = pkg_id(package)

    maintainers = [e.source for e in graph.in_edges(package_node, P_MAINTAINS)]
    hits: dict[str, dict] = {}
    for maintainer_node in maintainers:
        entity = graph.entities.get(maintainer_node)
        username = entity.name if entity else maintainer_node
        for edge in graph.out_edges(maintainer_node, P_MAINTAINS):
            if edge.target == package_node:
                continue
            other = graph.entities.get(edge.target)
            if other is None:
                continue
            row = hits.setdefault(
                edge.target,
                {
                    "package": other.name,
                    "shared_maintainers": [],
                    "downloads": other.attrs.get("downloads"),
                    "is_seed": other.attrs.get("is_seed", False),
                },
            )
            row["shared_maintainers"].append(username)

    rows = sorted(
        hits.values(),
        key=lambda r: (-len(r["shared_maintainers"]), -(r["downloads"] or 0), r["package"]),
    )
    return QueryResult(
        query="shared_maintainer",
        subject=package,
        rows=rows,
        latency_ms=_now_ms() - started,
        meta={
            "maintainers": [graph.entities[m].name for m in maintainers if m in graph.entities],
            "related_packages": len(rows),
        },
    )


# ---------------------------------------------------------------------------
# 3. Live-resolution window
# ---------------------------------------------------------------------------

def live_resolution_window(
    graph: Graph,
    package: str,
    version: str,
    window_start: str,
    window_end: str | None = None,
    *,
    max_depth: int = 10,
) -> QueryResult:
    """Which dependents would have resolved to the bad version *while it was live*.

    Blast radius answers "who could be exposed"; this answers "who actually was,
    during the window". A dependent version only counts if it already existed
    when the compromised version went live -- a package published after the
    advisory never resolved to the bad release.
    """
    started = _now_ms()
    start_dt = _parse_ts(window_start)
    end_dt = _parse_ts(window_end) if window_end else None

    radius = blast_radius(graph, package, version, max_depth=max_depth, include_paths=False)

    rows: list[dict] = []
    unknown_timestamp = 0
    for row in radius.rows:
        published = _parse_ts(row.get("published_at"))
        if published is None:
            unknown_timestamp += 1
            # Keep it, but mark it: absent timestamps are common for very old
            # releases and dropping them silently would understate exposure.
            rows.append({**row, "in_window": None, "reason": "unknown publish time"})
            continue
        # Existed before/at the moment the compromised version went live.
        if start_dt and published <= start_dt:
            rows.append({**row, "in_window": True, "reason": "published before compromise"})
        elif start_dt and end_dt and start_dt < published <= end_dt:
            rows.append({**row, "in_window": True, "reason": "published during window"})
        else:
            rows.append({**row, "in_window": False, "reason": "published after window"})

    in_window = [r for r in rows if r["in_window"] is True]
    return QueryResult(
        query="live_resolution_window",
        subject=f"{package}@{version}",
        rows=in_window,
        latency_ms=_now_ms() - started,
        meta={
            "window_start": window_start,
            "window_end": window_end,
            "in_window": len(in_window),
            "excluded_after_window": sum(1 for r in rows if r["in_window"] is False),
            "unknown_timestamp": unknown_timestamp,
            "candidates_considered": len(rows),
        },
    )


# ---------------------------------------------------------------------------
# 5. Version-introduced  (4, typosquat, lives in typosquat.py)
# ---------------------------------------------------------------------------

def version_introduced(graph: Graph, osv_id: str) -> QueryResult:
    """Which versions an advisory marks as affected, and the likely fix.

    Traversal: Advisory - affects -> Version, then compare against the
    package's ordered release list to name the first affected release and the
    first release after it (the de facto patched version).
    """
    started = _now_ms()
    advisory_node = adv_id(osv_id)
    affected_edges = list(graph.out_edges(advisory_node, P_AFFECTS))

    by_package: dict[str, list[str]] = {}
    for edge in affected_edges:
        entity = graph.entities.get(edge.target)
        if entity is None:
            continue
        package = entity.attrs.get("package")
        version = entity.attrs.get("version")
        if package and version:
            by_package.setdefault(package, []).append(version)

    from .util import sort_versions  # local import to avoid cycle

    rows = []
    for package, versions in sorted(by_package.items()):
        affected_sorted = sort_versions(versions)
        all_versions = sort_versions(
            [
                graph.entities[e.target].attrs.get("version")
                for e in graph.out_edges(pkg_id(package), P_HAS_VERSION)
                if e.target in graph.entities
                and graph.entities[e.target].attrs.get("version")
            ]
        )
        patched = None
        if affected_sorted and all_versions:
            last_bad = affected_sorted[-1]
            later = [v for v in all_versions if _version_gt(v, last_bad)]
            patched = later[0] if later else None
        rows.append(
            {
                "package": package,
                "introduced_in": affected_sorted[0] if affected_sorted else None,
                "affected_versions": affected_sorted,
                "likely_patched_in": patched,
                "total_releases": len(all_versions),
            }
        )

    advisory_entity = graph.entities.get(advisory_node)
    return QueryResult(
        query="version_introduced",
        subject=osv_id,
        rows=rows,
        latency_ms=_now_ms() - started,
        meta={
            "advisory_known": advisory_entity is not None,
            "published_at": advisory_entity.attrs.get("published_at") if advisory_entity else None,
            "severity": advisory_entity.attrs.get("severity") if advisory_entity else None,
        },
    )


def _version_gt(a: str, b: str) -> bool:
    from ..graph.model import parse_version

    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return False
    return pa > pb
