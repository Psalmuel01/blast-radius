"""Evaluation harness: score precision/recall/latency on held-out advisories.

Advisories published on or after `--cutoff` are held out, and the graph is
rebuilt without them before anything is scored.

**What "held out" means here.** Only the advisory *knowledge* is removed: the
Advisory node and its `affects` edges -- i.e. the assertion "this version is
compromised". The compromised Version node itself stays, along with every
dependency edge, because `blast_radius` traverses *from* that version. Deleting
it would turn the test into "can you find a package that does not exist", which
is not the defensive question. The question is: given a version the system was
never told was bad, does it still resolve the exposure correctly?

Two things are measured, and they answer different questions:

  * **Detection recall** -- with the advisory removed, is the affected version
    still present and reachable in the graph, so an analyst handed a fresh
    advisory can pivot from it immediately?
  * **Direct-exposure agreement** -- does the traversal find the dependents
    that a brute-force scan of every manifest says are directly exposed?
    Ground truth is computed independently of the traversal, so this is a real
    check rather than the query grading its own homework.

    Note this scores **depth-1 (direct) exposure only**, not the full
    transitive closure that `blast_radius` computes. `--transitive` adds a
    slower multi-hop brute-force check that scores the full closure.

Usage:
    python eval/run_eval.py --cutoff 2025-09-01
    python eval/run_eval.py --cutoff 2025-09-01 --transitive
    python eval/run_eval.py --cutoff 2025-09-01 --no-holdout   # score in-graph
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hydra_blast.config import GRAPH_PATH  # noqa: E402
from hydra_blast.graph.model import (  # noqa: E402
    Edge,
    Entity,
    Graph,
    NS_ADVISORY,
    P_AFFECTS,
    P_DEPENDS_ON,
    adv_id,
    pkg_id,
    satisfies,
    ver_id,
)
from hydra_blast.queries.core import blast_radius, live_resolution_window  # noqa: E402


def parse_ts(value):
    """Parse a timestamp, always returning tz-aware UTC.

    Some OSV records carry no offset; mixing those with tz-aware values raises
    on comparison, so naive values are assumed UTC.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def brute_force_exposed(graph: Graph, package: str, version: str) -> set[str]:
    """Ground truth for direct exposure, computed WITHOUT the traversal.

    Scans every dependency edge in the graph and asks the semver question
    directly. Independent of blast_radius(), so agreement is meaningful.

    Returns *package names* -- the edge source is a Version entity, so the
    owning package has to be read from its attrs. (Using the version entity's
    display name here instead compares package names against `name@version`
    strings, which silently scores 0.)
    """
    exposed = set()
    target = pkg_id(package)
    for edge in graph.edges:
        if edge.predicate != P_DEPENDS_ON or edge.target != target:
            continue
        if satisfies(version, edge.declared_range):
            entity = graph.entities.get(edge.source)
            if entity:
                owner = entity.attrs.get("package")
                if owner:
                    exposed.add(owner)
    return exposed


def rebuild_without(graph: Graph, held_out_ids: set[str]) -> Graph:
    """Rebuild the graph with the held-out advisories' knowledge removed.

    Drops the Advisory entities and their `affects` edges, and nothing else.
    Version nodes, dependency edges and maintainer edges are all preserved --
    see the module docstring on why removing the compromised version itself
    would test the wrong thing.
    """
    held_nodes = {adv_id(osv_id) for osv_id in held_out_ids}
    rebuilt = Graph()

    for entity in graph.entities.values():
        if entity.entity_id in held_nodes:
            continue
        rebuilt.add_entity(
            Entity(
                entity_id=entity.entity_id,
                name=entity.name,
                namespace=entity.namespace,
                attrs=dict(entity.attrs),
            )
        )

    for edge in graph.edges:
        if edge.source in held_nodes or edge.target in held_nodes:
            continue
        rebuilt.add_edge(
            Edge(
                source=edge.source,
                target=edge.target,
                predicate=edge.predicate,
                declared_range=edge.declared_range,
                valid_from=edge.valid_from,
                valid_to=edge.valid_to,
                context=edge.context,
            )
        )
    return rebuilt


def brute_force_transitive(graph: Graph, package: str, version: str, max_depth: int = 10) -> set[str]:
    """Full transitive closure by repeated brute-force scan.

    Deliberately naive and slower than `blast_radius`: it rescans every edge at
    each level rather than using the adjacency index, so agreement between the
    two is meaningful rather than circular.
    """
    exposed_versions: set[str] = set()
    frontier = {(package, version)}
    seen = {f"{package}@{version}"}

    for _ in range(max_depth):
        if not frontier:
            break
        next_frontier: set[tuple[str, str]] = set()
        for pkg, ver in frontier:
            target = pkg_id(pkg)
            for edge in graph.edges:
                if edge.predicate != P_DEPENDS_ON or edge.target != target:
                    continue
                if not satisfies(ver, edge.declared_range):
                    continue
                entity = graph.entities.get(edge.source)
                if entity is None:
                    continue
                owner = entity.attrs.get("package")
                owner_version = entity.attrs.get("version")
                if not owner or not owner_version:
                    continue
                key = f"{owner}@{owner_version}"
                if key in seen:
                    continue
                seen.add(key)
                exposed_versions.add(owner)
                next_frontier.add((owner, owner_version))
        frontier = next_frontier
    return exposed_versions


def score(predicted: set, actual: set) -> dict:
    if not predicted and not actual:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "tp": 0, "fp": 0, "fn": 0}
    tp = len(predicted & actual)
    fp = len(predicted - actual)
    fn = len(actual - predicted)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp, "fp": fp, "fn": fn,
    }


def evaluate(
    graph: Graph,
    cutoff: str,
    *,
    limit: int | None = None,
    holdout: bool = True,
    transitive: bool = False,
) -> dict:
    cutoff_dt = parse_ts(cutoff) or datetime(2025, 9, 1, tzinfo=timezone.utc)

    held_out = []
    for entity in graph.by_namespace(NS_ADVISORY):
        published = parse_ts(entity.attrs.get("published_at"))
        if published and published >= cutoff_dt:
            held_out.append(entity)
    held_out.sort(key=lambda e: e.attrs.get("published_at") or "")
    if limit:
        held_out = held_out[:limit]

    # Capture what each held-out advisory affects BEFORE removing it, since
    # that mapping is the answer key.
    answer_key: list[tuple[str, list]] = []
    for advisory in held_out:
        affected = [
            graph.entities[e.target]
            for e in graph.out_edges(advisory.entity_id, P_AFFECTS)
            if e.target in graph.entities
        ]
        answer_key.append((advisory.name, affected))

    # Rebuild the graph without the held-out advisories' knowledge. The
    # compromised Version nodes survive; only the advisories and their
    # `affects` edges are removed.
    scoring_graph = (
        rebuild_without(graph, {name for name, _ in answer_key}) if holdout else graph
    )

    detection_hits = 0
    detection_misses = []
    radius_scores = []
    transitive_scores = []
    latencies = {"blast_radius": [], "live_resolution_window": []}
    per_advisory = []

    for advisory, affected in zip(held_out, [a for _, a in answer_key]):
        if not affected:
            detection_misses.append({"advisory": advisory.name, "why": "no affected version in graph"})
            continue

        for version_entity in affected:
            package = version_entity.attrs.get("package")
            version = version_entity.attrs.get("version")
            if not package or not version:
                continue

            # Detection: with the advisory removed, is the compromised version
            # still present in the graph so an analyst can pivot from it?
            if ver_id(package, version) in scoring_graph.entities:
                detection_hits += 1
            else:
                detection_misses.append({"advisory": advisory.name, "why": f"{package}@{version} absent"})
                continue

            started = time.perf_counter()
            result = blast_radius(scoring_graph, package, version)
            latencies["blast_radius"].append((time.perf_counter() - started) * 1000)

            predicted_direct = {r["package"] for r in result.rows if r["depth"] == 1}
            actual_direct = brute_force_exposed(scoring_graph, package, version)
            scored = score(predicted_direct, actual_direct)
            # An advisory with no dependents in the crawled subgraph scores a
            # trivial 1.0/1.0 -- empty predicted correctly matches empty actual.
            # That is a real result but not a real *detection*, so track the two
            # populations separately rather than averaging them together.
            scored["nontrivial"] = bool(actual_direct)
            radius_scores.append(scored)

            row = {
                "advisory": advisory.name,
                "package": f"{package}@{version}",
                "exposed_versions": result.meta["exposed_versions"],
                "exposed_packages": result.meta["exposed_packages"],
                "direct_precision": scored["precision"],
                "direct_recall": scored["recall"],
                "latency_ms": round(result.latency_ms, 2),
            }

            if transitive:
                predicted_all = {r["package"] for r in result.rows}
                actual_all = brute_force_transitive(scoring_graph, package, version)
                scored_all = score(predicted_all, actual_all)
                scored_all["nontrivial"] = bool(actual_all)
                transitive_scores.append(scored_all)
                row["transitive_precision"] = scored_all["precision"]
                row["transitive_recall"] = scored_all["recall"]

            window_start = version_entity.attrs.get("published_at")
            # The advisory is held out, so its publish time is taken from the
            # answer key rather than from the scoring graph.
            window_end = advisory.attrs.get("published_at")
            if window_start:
                started = time.perf_counter()
                live_resolution_window(scoring_graph, package, version, window_start, window_end)
                latencies["live_resolution_window"].append((time.perf_counter() - started) * 1000)

            per_advisory.append(row)

    def summarise(values):
        if not values:
            return {}
        ordered = sorted(values)
        return {
            "count": len(values),
            "mean_ms": round(statistics.mean(values), 2),
            "p50_ms": round(ordered[len(ordered) // 2], 2),
            "p95_ms": round(ordered[int(len(ordered) * 0.95) - 1] if len(ordered) > 1 else ordered[0], 2),
            "max_ms": round(max(values), 2),
        }

    nontrivial = [s for s in radius_scores if s.get('nontrivial')]
    nontrivial_transitive = [s for s in transitive_scores if s.get('nontrivial')]

    def mean_of(scores, key):
        return round(statistics.mean([s[key] for s in scores]), 4) if scores else 0.0

    report = {
        "cutoff": cutoff,
        "holdout": holdout,
        "held_out_advisories": len(held_out),
        "graph_edges_scored": len(scoring_graph.edges),
        "graph_edges_full": len(graph.edges),
        "detection": {
            "hits": detection_hits,
            "misses": len(detection_misses),
            "recall": round(detection_hits / (detection_hits + len(detection_misses)), 4)
            if (detection_hits + len(detection_misses)) else 0.0,
            "miss_detail": detection_misses[:10],
        },
        # Named for exactly what it measures: depth-1 exposure only. The full
        # transitive closure is scored separately under `transitive_exposure`.
        "direct_exposure": {
            "precision": mean_of(radius_scores, "precision"),
            "recall": mean_of(radius_scores, "recall"),
            "f1": mean_of(radius_scores, "f1"),
            "evaluated": len(radius_scores),
            "scope": "depth-1 dependents only",
            # How much of that average is a real detection test. An advisory
            # with no dependents in scope scores 1.0/1.0 for correctly finding
            # nothing, which is true but trivial -- averaging it with genuine
            # detections inflates the headline number.
            "with_real_exposure": len(nontrivial),
            "with_zero_exposure": len(radius_scores) - len(nontrivial),
            "precision_real_only": mean_of(nontrivial, "precision"),
            "recall_real_only": mean_of(nontrivial, "recall"),
            "f1_real_only": mean_of(nontrivial, "f1"),
        },
        "latency": {k: summarise(v) for k, v in latencies.items()},
        "per_advisory": per_advisory,
    }

    if transitive:
        report["transitive_exposure"] = {
            "precision": mean_of(transitive_scores, "precision"),
            "recall": mean_of(transitive_scores, "recall"),
            "f1": mean_of(transitive_scores, "f1"),
            "evaluated": len(transitive_scores),
            "scope": "full transitive closure",
            "with_real_exposure": len(nontrivial_transitive),
            "with_zero_exposure": len(transitive_scores) - len(nontrivial_transitive),
            "precision_real_only": mean_of(nontrivial_transitive, "precision"),
            "recall_real_only": mean_of(nontrivial_transitive, "recall"),
        }
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--graph", type=Path, default=GRAPH_PATH)
    parser.add_argument("--cutoff", default="2025-09-01")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--no-holdout", action="store_true",
                        help="score against the full graph instead of removing advisories")
    parser.add_argument("--transitive", action="store_true",
                        help="also score the full transitive closure (slower)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    if not args.graph.exists():
        sys.exit(f"no graph at {args.graph}; run `python -m hydra_blast crawl` first")

    graph = Graph.load(args.graph)
    report = evaluate(graph, args.cutoff, limit=args.limit,
                      holdout=not args.no_holdout, transitive=args.transitive)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"\n  eval  cutoff={report['cutoff']}  graph={args.graph.name}")
        mode = ("advisories removed from the graph before scoring"
                if report["holdout"] else "scored in-graph (--no-holdout)")
        print(f"  held-out advisories: {report['held_out_advisories']}  [{mode}]")
        print(f"  edges: {report['graph_edges_scored']:,} scored "
              f"of {report['graph_edges_full']:,} total")
        d = report["detection"]
        print(f"\n  detection         recall={d['recall']}  hits={d['hits']}  misses={d['misses']}")
        b = report["direct_exposure"]
        print(f"  direct exposure   precision={b['precision']}  recall={b['recall']}  "
              f"f1={b['f1']}  (n={b['evaluated']}, depth-1 only)")
        print(f"    of which {b['with_real_exposure']} advisor"
              f"{'y has' if b['with_real_exposure'] == 1 else 'ies have'} real exposure "
              f"to detect (precision={b['precision_real_only']} "
              f"recall={b['recall_real_only']}),")
        print(f"    and {b['with_zero_exposure']} have no dependents in this graph "
              f"-- correctly reported as zero, but a trivial pass.")
        t = report.get("transitive_exposure")
        if t:
            print(f"  transitive        precision={t['precision']}  recall={t['recall']}  "
                  f"f1={t['f1']}  (n={t['evaluated']}, full closure)")
            print(f"    of which {t['with_real_exposure']} with real exposure "
                  f"(precision={t['precision_real_only']} recall={t['recall_real_only']})")
        print("\n  latency:")
        for name, stats in report["latency"].items():
            if stats:
                print(f"    {name:24s} p50={stats['p50_ms']}ms  p95={stats['p95_ms']}ms  max={stats['max_ms']}ms")
        if report["per_advisory"]:
            print("\n  per advisory:")
            for row in report["per_advisory"][:12]:
                print(f"    {row['advisory']:18s} {row['package']:22s} "
                      f"exposed={row['exposed_packages']:4d} pkgs  "
                      f"P={row['direct_precision']} R={row['direct_recall']}  {row['latency_ms']}ms")
        print()

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2))
        print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
