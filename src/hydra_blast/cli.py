"""Command-line interface -- the demo surface.

    python -m hydra_blast crawl --hops 2
    python -m hydra_blast blast debug@4.4.2
    python -m hydra_blast maintainer debug
    python -m hydra_blast window debug@4.4.2 --advisory MAL-2025-46974
    python -m hydra_blast typosquat chalk
    python -m hydra_blast sync
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .config import CRAWL, GRAPH_PATH, SEED_ADVISORIES, SEEDS, CrawlConfig
from .graph.build import build_graph
from .graph.model import Graph
from .ingest.crawler import crawl as run_crawl
from .queries.core import (
    blast_radius,
    live_resolution_window,
    shared_maintainer,
    version_introduced,
)
from .queries.typosquat import typosquat_candidates


def _load_graph(path: Path) -> Graph:
    if not path.exists():
        sys.exit(
            f"No graph at {path}. Build one first:\n"
            f"  python -m hydra_blast crawl --hops 2"
        )
    return Graph.load(path)


def _split_spec(spec: str) -> tuple[str, str | None]:
    """Split `name@version`, tolerating scoped names like @scope/pkg@1.0.0."""
    if spec.startswith("@"):
        head, sep, tail = spec[1:].partition("@")
        return ("@" + head, tail or None) if sep else (spec, None)
    name, sep, version = spec.partition("@")
    return (name, version or None) if sep else (spec, None)


def _emit(result, as_json: bool, limit: int) -> None:
    if as_json:
        print(json.dumps(
            {
                "query": result.query,
                "subject": result.subject,
                "latency_ms": round(result.latency_ms, 2),
                "meta": result.meta,
                "rows": result.rows[:limit],
            },
            indent=2,
        ))
        return

    print(f"\n  {result.query}  <{result.subject}>")
    print(f"  {result.latency_ms:.1f} ms")
    for key, value in result.meta.items():
        print(f"    {key}: {value}")
    if not result.rows:
        print("\n  (no results)")
        return
    print(f"\n  showing {min(limit, len(result.rows))} of {len(result.rows)}:")
    for row in result.rows[:limit]:
        primary = row.get("package", "?")
        detail = []
        for field in ("version", "depth", "declared_range", "score", "edit_distance",
                      "shared_maintainers", "introduced_in", "likely_patched_in", "reason"):
            if row.get(field) not in (None, [], ""):
                detail.append(f"{field}={row[field]}")
        print(f"    {primary:40s} {' '.join(detail)}")
    print()


def cmd_crawl(args) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    config = CrawlConfig(
        max_hops=args.hops,
        top_dependents_hop1=args.top1,
        top_dependents_deeper=args.topn,
        max_packages=args.max_packages,
    )
    seeds = args.seeds or SEEDS
    print(f"crawling {len(seeds)} seed(s), hops={config.max_hops}, "
          f"top1={config.top_dependents_hop1}, topn={config.top_dependents_deeper}")
    if config.max_hops >= 2 and config.top_dependents_hop1 >= 100:
        # Measured: hop 2 expands to ~11k packages at ~1/sec. Worth saying so
        # before someone walks away expecting a five-minute job.
        print("  note: a full 2-hop crawl fetches ~12k packages and takes hours.\n"
              "        for a quick start try:  --hops 1 --top1 40\n"
              "        (responses are cached, so re-running resumes cheaply)")
    # stdout is buffered while logging writes to stderr; flush so these lines
    # appear before the crawl's own progress output rather than after it.
    sys.stdout.flush()
    result = run_crawl(seeds=seeds, config=config)
    print("crawl:", result.stats())
    graph = build_graph(result)
    print("graph:", graph.stats())

    # Refuse to silently replace a substantially larger graph -- a quick test
    # crawl should never destroy hours of crawling.
    if args.graph.exists() and not args.force:
        try:
            existing = Graph.load(args.graph)
        except Exception:  # noqa: BLE001 - unreadable graph is fine to replace
            existing = None
        if existing is not None and len(existing.edges) > len(graph.edges) * 2:
            sys.exit(
                f"refusing to overwrite {args.graph}: it holds "
                f"{len(existing.edges):,} edges, the new graph has "
                f"{len(graph.edges):,}.\n"
                f"  pass --force to replace it, or --graph <other-path> to keep both."
            )

    graph.save(args.graph)
    print(f"saved -> {args.graph}")


def cmd_blast(args) -> None:
    graph = _load_graph(args.graph)
    package, version = _split_spec(args.spec)
    if not version:
        sys.exit("blast needs a version: e.g. debug@4.4.2")
    _emit(blast_radius(graph, package, version, max_depth=args.depth), args.json, args.limit)


def cmd_maintainer(args) -> None:
    graph = _load_graph(args.graph)
    package, _ = _split_spec(args.spec)
    _emit(shared_maintainer(graph, package), args.json, args.limit)


def cmd_window(args) -> None:
    graph = _load_graph(args.graph)
    package, version = _split_spec(args.spec)
    if not version:
        sys.exit("window needs a version: e.g. debug@4.4.2")

    start, end = args.start, args.end
    if args.advisory and not (start and end):
        # Derive the window from the graph: version publish -> advisory publish.
        from .graph.model import adv_id, ver_id

        version_entity = graph.entities.get(ver_id(package, version))
        advisory_entity = graph.entities.get(adv_id(args.advisory))
        start = start or (version_entity.attrs.get("published_at") if version_entity else None)
        end = end or (advisory_entity.attrs.get("published_at") if advisory_entity else None)
    if not start:
        sys.exit("need --start or an --advisory whose window can be derived")
    print(f"  window: {start} -> {end or 'open'}")
    _emit(live_resolution_window(graph, package, version, start, end, max_depth=args.depth),
          args.json, args.limit)


def cmd_typosquat(args) -> None:
    graph = _load_graph(args.graph)
    package, _ = _split_spec(args.spec)
    _emit(typosquat_candidates(graph, package, max_distance=args.distance), args.json, args.limit)


def cmd_introduced(args) -> None:
    graph = _load_graph(args.graph)
    _emit(version_introduced(graph, args.advisory), args.json, args.limit)


def cmd_sync(args) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    from .graph.hydra import HydraClient, sync_graph

    # Check credentials before the graph: a missing API key reported as
    # "no graph found" sends people down the wrong path entirely.
    from .graph.hydra import HydraError

    try:
        client = HydraClient.from_env()
    except HydraError as exc:
        sys.exit(str(exc))
    if args.database:
        client.database = args.database

    graph = _load_graph(args.graph)
    # State the destination up front: writing a graph into the wrong database
    # is silent and annoying to undo.
    print(f"syncing {len(graph.edges)} edges -> HydraDB database '{client.database}'"
          f"{' (from --database)' if args.database else ' (from HYDRA_DB_DATABASE)'}")
    summary = sync_graph(graph, client, batch_size=args.batch_size,
                         max_batches=args.max_batches, wait=args.wait,
                         workers=args.workers)
    print("sync:", summary)


def cmd_seeds(args) -> None:
    for name in SEEDS:
        print(f"  {name:18s} {SEED_ADVISORIES[name]}")


def main(argv=None) -> None:
    # Shared flags are attached to every subparser as well as the root, so
    # `blast debug@4.4.2 --limit 5` works as naturally as the other order.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--graph", type=Path, default=GRAPH_PATH, help="graph file")
    common.add_argument("--json", action="store_true", help="emit JSON")
    common.add_argument("--limit", type=int, default=20, help="rows to show")

    parser = argparse.ArgumentParser(prog="hydra_blast", description=__doc__,
                                     parents=[common],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub_kwargs = {"parents": [common]}

    p = sub.add_parser("crawl", help="build the graph from the compromised seeds", **sub_kwargs)
    p.add_argument("--hops", type=int, default=CRAWL.max_hops)
    p.add_argument("--top1", type=int, default=CRAWL.top_dependents_hop1)
    p.add_argument("--topn", type=int, default=CRAWL.top_dependents_deeper)
    p.add_argument("--max-packages", type=int, default=CRAWL.max_packages)
    p.add_argument("--seeds", nargs="*", help="override the seed list")
    p.add_argument("--force", action="store_true",
                   help="overwrite an existing larger graph")
    p.set_defaults(func=cmd_crawl)

    p = sub.add_parser("blast", help="transitive blast radius of a bad version", **sub_kwargs)
    p.add_argument("spec", help="package@version, e.g. debug@4.4.2")
    p.add_argument("--depth", type=int, default=10)
    p.set_defaults(func=cmd_blast)

    p = sub.add_parser("maintainer", help="packages sharing a maintainer", **sub_kwargs)
    p.add_argument("spec")
    p.set_defaults(func=cmd_maintainer)

    p = sub.add_parser("window", help="who resolved to the bad version while it was live", **sub_kwargs)
    p.add_argument("spec")
    p.add_argument("--advisory", help="derive the window from this advisory")
    p.add_argument("--start")
    p.add_argument("--end")
    p.add_argument("--depth", type=int, default=10)
    p.set_defaults(func=cmd_window)

    p = sub.add_parser("typosquat", help="plausible typosquat candidates", **sub_kwargs)
    p.add_argument("spec")
    p.add_argument("--distance", type=int, default=2)
    p.set_defaults(func=cmd_typosquat)

    p = sub.add_parser("introduced", help="which version introduced an advisory", **sub_kwargs)
    p.add_argument("advisory")
    p.set_defaults(func=cmd_introduced)

    p = sub.add_parser("sync", help="push the graph into HydraDB", **sub_kwargs)
    p.add_argument("--batch-size", type=int, default=400)
    p.add_argument("--max-batches", type=int)
    p.add_argument("--database")
    p.add_argument("--wait", action="store_true")
    p.add_argument("--workers", type=int, default=4,
                   help="parallel ingest requests (default 4; 1 = sequential)")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("seeds", help="list the confirmed compromised seeds", **sub_kwargs)
    p.set_defaults(func=cmd_seeds)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
