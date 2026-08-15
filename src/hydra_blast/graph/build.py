"""Turn crawl output into the typed graph.

Every edge carries the timestamps the time-window queries need, and dependency
edges keep the *declared range* rather than a resolved version -- resolution is
what the blast-radius query computes, so collapsing it here would throw away
the information the query exists to use.
"""

from __future__ import annotations

import logging

from ..ingest import sources
from ..ingest.crawler import CrawlResult
from .model import (
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

log = logging.getLogger(__name__)


def build_graph(crawl: CrawlResult, *, fetch_advisories: bool = True) -> Graph:
    graph = Graph()

    for record in crawl.packages.values():
        package_node = pkg_id(record.name)
        graph.add_entity(
            Entity(
                entity_id=package_node,
                name=record.name,
                namespace=NS_PACKAGE,
                attrs={
                    "ecosystem": "npm",
                    "downloads": record.downloads,
                    "repo_url": record.repo_url,
                    "description": record.description,
                    "latest_version": record.latest_version,
                    "hop": record.hop,
                    "is_seed": record.is_seed,
                    "first_release": record.first_release,
                },
            )
        )

        for username in record.maintainers:
            graph.add_entity(
                Entity(entity_id=maint_id(username), name=username, namespace=NS_MAINTAINER)
            )
            graph.add_edge(
                Edge(
                    source=maint_id(username),
                    target=package_node,
                    predicate=P_MAINTAINS,
                    context=f"{username} maintains {record.name}",
                )
            )

        for version, meta in record.versions.items():
            version_node = ver_id(record.name, version)
            published = meta.get("published_at")
            graph.add_entity(
                Entity(
                    entity_id=version_node,
                    name=f"{record.name}@{version}",
                    namespace=NS_VERSION,
                    attrs={
                        "package": record.name,
                        "version": version,
                        "published_at": published,
                        # Unpublished versions are exactly the compromised ones
                        # (npm pulled debug@4.4.2), so this flag matters.
                        "unpublished": bool(meta.get("unpublished")),
                    },
                )
            )
            graph.add_edge(
                Edge(
                    source=package_node,
                    target=version_node,
                    predicate=P_HAS_VERSION,
                    valid_from=published,
                    context=f"{record.name} has version {version}",
                )
            )

            # Version -> Package dependency, keyed by declared range.
            for dep_name, dep_range in (meta.get("dependencies") or {}).items():
                graph.add_edge(
                    Edge(
                        source=version_node,
                        target=pkg_id(dep_name),
                        predicate=P_DEPENDS_ON,
                        declared_range=dep_range,
                        valid_from=published,
                        context=f"{record.name}@{version} depends on {dep_name}@{dep_range}",
                    )
                )

    if fetch_advisories:
        _attach_advisory_nodes(crawl, graph)

    return graph


def _attach_advisory_nodes(crawl: CrawlResult, graph: Graph) -> None:
    """Advisory -> Version `affects` edges, from OSV's affected version lists."""
    seen: dict[str, dict] = {}
    for record in crawl.packages.values():
        for osv_id in record.advisories:
            advisory = seen.get(osv_id)
            if advisory is None:
                advisory = sources.fetch_advisory(osv_id)
                if not advisory:
                    continue
                seen[osv_id] = advisory

            published = advisory.get("published")
            severity = _severity_of(advisory)
            graph.add_entity(
                Entity(
                    entity_id=adv_id(osv_id),
                    name=osv_id,
                    namespace=NS_ADVISORY,
                    attrs={
                        "published_at": published,
                        "severity": severity,
                        "summary": (advisory.get("summary") or "")[:300],
                        "is_malware": osv_id.startswith("MAL-"),
                        "aliases": advisory.get("aliases") or [],
                    },
                )
            )

            affected = sources.affected_versions(advisory, record.name)
            if not affected:
                # OSV expresses impact either as an explicit `versions` list or
                # as introduced/fixed `ranges`. Range-only advisories (e.g.
                # GHSA-jmr9-qjv8-65gv) would otherwise attach to nothing, so
                # expand the range against the versions we actually know.
                affected = _versions_in_ranges(advisory, record, graph)

            for version in affected:
                version_node = ver_id(record.name, version)
                # The affected version may not be in `versions` if npm pulled
                # it; the crawler reconstructs those, but guard anyway.
                if version_node not in graph.entities:
                    graph.add_entity(
                        Entity(
                            entity_id=version_node,
                            name=f"{record.name}@{version}",
                            namespace=NS_VERSION,
                            attrs={
                                "package": record.name,
                                "version": version,
                                "published_at": None,
                                "unpublished": True,
                            },
                        )
                    )
                graph.add_edge(
                    Edge(
                        source=adv_id(osv_id),
                        target=version_node,
                        predicate=P_AFFECTS,
                        valid_from=published,
                        context=f"{osv_id} affects {record.name}@{version}",
                    )
                )


def _versions_in_ranges(advisory: dict, record, graph: Graph) -> list[str]:
    """Expand OSV introduced/fixed ranges into concrete known versions.

    A version is affected when introduced <= v < fixed (fixed may be absent,
    meaning "still affected").
    """
    from .model import parse_version

    pairs = sources.affected_introduced(advisory, record.name)
    if not pairs:
        return []

    matched: list[str] = []
    for version in record.versions:
        parsed = parse_version(version)
        if parsed is None:
            continue
        for introduced, fixed in pairs:
            low = parse_version(introduced) if introduced not in ("0", None) else (0, 0, 0)
            if low is None:
                continue
            if parsed < low:
                continue
            if fixed:
                high = parse_version(fixed)
                if high is not None and parsed >= high:
                    continue
            matched.append(version)
            break
    return sorted(set(matched))


def _severity_of(advisory: dict) -> str | None:
    database = advisory.get("database_specific") or {}
    if isinstance(database, dict) and database.get("severity"):
        return str(database["severity"])
    severity = advisory.get("severity")
    if isinstance(severity, list) and severity:
        entry = severity[0]
        if isinstance(entry, dict):
            return str(entry.get("score") or entry.get("type") or "")
    return None
