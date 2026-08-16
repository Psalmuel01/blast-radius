#!/usr/bin/env bash
# Demo script for the 3-minute video, in the order the brief asks for:
#   problem -> project -> demo -> HydraDB.
#
# Usage:  ./scripts/demo.sh          (pauses between steps)
#         ./scripts/demo.sh --fast   (no pauses)

set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src

PAUSE=${1:-}
step() {
  echo
  echo "──────────────────────────────────────────────────────────────"
  echo "  $1"
  echo "──────────────────────────────────────────────────────────────"
  [ "$PAUSE" = "--fast" ] || read -r -p "  [enter]" _
}

step "THE PROBLEM: 17 npm packages were compromised on 2025-09-08."
python3 -m hydra_blast seeds

step "debug@4.4.2 shipped a crypto-stealing payload. npm has since UNPUBLISHED it."
echo "  It is gone from the registry's version list -- but its timestamp survives,"
echo "  which is the only reason we can still reconstruct what it reached."
python3 - <<'PY'
import sys; sys.path.insert(0, "src")
from hydra_blast.ingest.sources import fetch_package, unpublished_versions
p = fetch_package("debug")
print("  in registry 'versions':", "4.4.2" in (p.get("versions") or {}))
print("  recovered from 'time' :", unpublished_versions(p).get("4.4.2"))
PY

step "QUERY 1 -- BLAST RADIUS: what did the bad version actually reach?"
python3 -m hydra_blast blast debug@4.4.2 --limit 8

step "THE SAME QUERY, TRAVERSING EDGES FETCHED FROM HYDRADB"
echo "  --from-hydra pulls the typed graph back out of HydraDB at query time"
echo "  and runs the identical traversal over it. Same answer, real round trip."
python3 -m hydra_blast blast debug@4.4.2 --from-hydra --limit 8

step "QUERY 2 -- SHARED MAINTAINER: what else can that account publish to?"
python3 -m hydra_blast maintainer chalk --limit 8

step "QUERY 3 -- LIVE WINDOW: who resolved to it while it was live?"
echo "  The window is derived from the graph itself:"
echo "  version published 13:12:39Z -> advisory published 14:26:51Z = 74 minutes."
python3 -m hydra_blast window debug@4.4.2 --advisory MAL-2025-46974 --limit 6

step "QUERY 4 -- TYPOSQUATS"
python3 -m hydra_blast typosquat chalk --limit 8

step "QUERY 5 -- WHICH VERSION INTRODUCED IT, AND WHAT FIXED IT?"
python3 -m hydra_blast introduced MAL-2025-46974

step "EVALUATION: scored against held-out advisories, ground truth computed"
echo "  independently of the traversal (brute-force manifest scan)."
python3 eval/run_eval.py --cutoff 2025-09-01

step "HYDRADB: the same graph, queried in natural language."
echo "  Note graph_context.query_paths -- our explicit typed triplets come back,"
echo "  with namespaces, predicates, and real npm timestamps."
python3 - <<'PY'
import sys, json; sys.path.insert(0, "src")
from hydra_blast.graph.hydra import HydraClient
c = HydraClient.from_env()
r = c.query("which packages depend on debug", mode="hybrid", level="thinking")
paths = ((r.get("data") or {}).get("graph_context") or {}).get("query_paths") or []
for p in paths[:1]:
    for t in (p.get("triplets") or [])[:3]:
        s, rel, tgt = t.get("source", {}), t.get("relation", {}), t.get("target", {})
        print(f"  ({s.get('namespace')}) {s.get('name')} "
              f"-[{rel.get('canonical_predicate')}]-> {tgt.get('name')}")
        print(f"      temporal: {rel.get('temporal_details')}")
PY

echo
echo "  Done."
