"""Bounded, impact-ranked crawl that materialises the dependency graph.

Strategy (see NOTES-plan.md): start from the confirmed compromised seeds, walk
*dependents* outward, and cap fan-out at each hop by download count. Ranking is
what keeps this tractable -- taking all of chalk's 130,085 dependents is not an
option, and the most-downloaded ones are where a compromise actually lands.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable

from ..config import CRAWL, SEED_ADVISORIES, SEEDS, CrawlConfig
from . import sources

log = logging.getLogger(__name__)


@dataclass
class PackageRecord:
    name: str
    hop: int
    downloads: int | None = None
    maintainers: list[str] = field(default_factory=list)
    repo_url: str | None = None
    description: str | None = None
    first_release: str | None = None
    latest_version: str | None = None
    # version -> {published_at, dependencies, unpublished}
    versions: dict[str, dict] = field(default_factory=dict)
    advisories: list[str] = field(default_factory=list)
    is_seed: bool = False


@dataclass
class CrawlResult:
    packages: dict[str, PackageRecord]
    # (dependent_package, dependency_package) pairs discovered via reverse deps.
    dependent_edges: set[tuple[str, str]]

    def stats(self) -> dict[str, int]:
        versions = sum(len(p.versions) for p in self.packages.values())
        unpublished = sum(
            1
            for p in self.packages.values()
            for v in p.versions.values()
            if v.get("unpublished")
        )
        return {
            "packages": len(self.packages),
            "versions": versions,
            "unpublished_versions": unpublished,
            "dependent_edges": len(self.dependent_edges),
            "advisories": len({a for p in self.packages.values() for a in p.advisories}),
        }


def _hydrate(record: PackageRecord, config: CrawlConfig = CRAWL) -> None:
    """Fill a record from the npm packument (versions, deps, maintainers)."""
    # Seeds arrive with no download count (they were never returned as some
    # other package's dependent), and typosquat scoring compares against the
    # target's downloads -- so fetch the stats the crawl did not supply.
    if record.downloads is None or record.first_release is None:
        stats = sources.fetch_package_stats(record.name) or {}
        if record.downloads is None:
            record.downloads = stats.get("downloads")
        record.first_release = record.first_release or stats.get("first_release_published_at")

    packument = sources.fetch_package(record.name)
    if not packument:
        return

    record.maintainers = sources.package_maintainers(packument)
    record.description = packument.get("description")
    dist_tags = packument.get("dist-tags") or {}
    record.latest_version = dist_tags.get("latest")

    repo = packument.get("repository")
    if isinstance(repo, dict):
        record.repo_url = repo.get("url")
    elif isinstance(repo, str):
        record.repo_url = repo

    for version, doc in sources.iter_versions(packument):
        record.versions[version] = {
            "published_at": sources.version_published_at(packument, version),
            "dependencies": sources.version_dependencies(doc),
            "unpublished": False,
        }

    # Versions npm removed but whose timestamps survive -- e.g. debug@4.4.2.
    # Without this the compromised release vanishes from the graph.
    for version, stamp in sources.unpublished_versions(packument).items():
        record.versions[version] = {
            "published_at": stamp,
            "dependencies": {},
            "unpublished": True,
        }

    _trim_versions(record, config)


def _trim_versions(record: PackageRecord, config: CrawlConfig) -> None:
    """Keep only the newest N versions of non-seed packages.

    Seeds keep everything: the compromised release is the query subject and can
    be an old version. Unpublished versions are always kept too -- they are the
    compromised ones, which is the whole reason they are reconstructed.
    """
    limit = config.max_versions_per_package
    if record.is_seed or limit <= 0 or len(record.versions) <= limit:
        return

    def sort_key(item):
        _, meta = item
        return meta.get("published_at") or ""

    always_keep = {v for v, m in record.versions.items() if m.get("unpublished")}
    ordered = sorted(record.versions.items(), key=sort_key, reverse=True)
    kept = {v for v, _ in ordered[:limit]} | always_keep
    record.versions = {v: m for v, m in record.versions.items() if v in kept}


def _fan_out(name: str, limit: int) -> list[tuple[str, int | None]]:
    """Top dependents of `name` as (package, downloads)."""
    out: list[tuple[str, int | None]] = []
    for entry in sources.fetch_dependents(name, limit):
        dep_name = entry.get("name")
        if isinstance(dep_name, str) and dep_name:
            out.append((dep_name, entry.get("downloads")))
    return out


def crawl(
    seeds: Iterable[str] = SEEDS,
    config: CrawlConfig = CRAWL,
    *,
    progress: bool = True,
) -> CrawlResult:
    packages: dict[str, PackageRecord] = {}
    dependent_edges: set[tuple[str, str]] = set()

    frontier = [
        PackageRecord(name=name, hop=0, is_seed=True) for name in sorted(set(seeds))
    ]
    for record in frontier:
        record.advisories = [SEED_ADVISORIES[record.name]] if record.name in SEED_ADVISORIES else []
        packages[record.name] = record

    for hop in range(config.max_hops + 1):
        if not frontier:
            break
        if progress:
            log.info("hop %d: hydrating %d package(s)", hop, len(frontier))

        for index, record in enumerate(frontier, start=1):
            try:
                _hydrate(record, config)
            except Exception as exc:  # noqa: BLE001 - one bad package must not
                # abort a multi-hour crawl. The HTTP layer already retries;
                # anything reaching here is unexpected, so log and continue.
                log.warning("hydrate failed for %s: %s", record.name, exc)
            if progress and index % 500 == 0:
                log.info("  hop %d: hydrated %d/%d", hop, index, len(frontier))

        if hop == config.max_hops:
            break

        limit = config.top_dependents_hop1 if hop == 0 else config.top_dependents_deeper
        next_frontier: list[PackageRecord] = []

        for record in frontier:
            if len(packages) >= config.max_packages:
                log.warning("hit max_packages=%d, stopping fan-out", config.max_packages)
                break
            for dep_name, downloads in _fan_out(record.name, limit):
                dependent_edges.add((dep_name, record.name))
                if dep_name in packages:
                    continue
                if len(packages) >= config.max_packages:
                    break
                new_record = PackageRecord(
                    name=dep_name, hop=hop + 1, downloads=downloads
                )
                packages[dep_name] = new_record
                next_frontier.append(new_record)

        frontier = next_frontier
        if progress:
            log.info("hop %d -> discovered %d new package(s)", hop, len(next_frontier))

    _attach_advisories(packages)
    return CrawlResult(packages=packages, dependent_edges=dependent_edges)


def _attach_advisories(packages: dict[str, PackageRecord]) -> None:
    """Batch-query OSV so downstream packages carry their own advisories too.

    The eval holds out recent advisories, so the graph needs advisory coverage
    across the whole crawl, not just the seeds.
    """
    names = sorted(packages)
    found = sources.query_advisories_batch(names)
    for name, ids in found.items():
        record = packages.get(name)
        if record is None:
            continue
        record.advisories = sorted(set(record.advisories) | set(ids))
