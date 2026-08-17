#!/usr/bin/env bash
# Run the FULL HydraDB read once and capture the result for the demo.
#
# Reading every source takes minutes, which is too slow to show live -- and
# showing a deliberately partial read instead would be precisely the failure
# this tool exists to catch. So the full read is run here, once, and the
# demo displays the confirmed output with the real wall time stated.
#
#   ./scripts/capture_parity.sh          -> writes docs/hydra-parity.txt

set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src

mkdir -p docs
OUT=docs/hydra-parity.txt

echo "Running the full HydraDB read (all sources, no cap). This takes minutes."

python3 - <<'PY' | tee "$OUT"
import sys, time
sys.path.insert(0, "src")
from pathlib import Path
from hydra_blast.graph.model import Graph
from hydra_blast.graph.hydra import HydraClient, load_graph_from_hydra
from hydra_blast.queries.core import blast_radius

client = HydraClient.from_env()
started = time.time()
hydra_graph = load_graph_from_hydra(client, progress=False, workers=8)
fetch_s = time.time() - started

local_graph = Graph.load(Path("data/graph.json"))
hydra_result = blast_radius(hydra_graph, "debug", "4.4.2")
local_result = blast_radius(local_graph, "debug", "4.4.2")

same = (
    sorted((r["package"], r["version"]) for r in hydra_result.rows)
    == sorted((r["package"], r["version"]) for r in local_result.rows)
)

print(f"  $ python3 -m hydra_blast blast debug@4.4.2 --from-hydra")
print()
print(f"  read {hydra_graph.provenance.get('sources_read')} sources from HydraDB "
      f"'{client.database}'")
print(f"  loaded {len(hydra_graph.edges):,} edges in {fetch_s/60:.1f} min "
      f"({fetch_s:.0f}s, no cap, nothing skipped)")
print()
print(f"  blast_radius  <debug@4.4.2>   {hydra_result.latency_ms:.1f} ms")
print(f"    exposed_versions: {hydra_result.meta['exposed_versions']}")
print(f"    exposed_packages: {hydra_result.meta['exposed_packages']}")
print(f"    max_depth_reached: {hydra_result.meta['max_depth_reached']}")
print()
print(f"  local graph:  {local_result.meta['exposed_packages']} packages / "
      f"{local_result.meta['exposed_versions']} versions "
      f"({local_result.latency_ms:.1f} ms)")
print(f"  identical to HydraDB result: {same}")
PY

echo
echo "captured -> $OUT"
