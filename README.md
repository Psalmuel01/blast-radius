# Blast Radius — supply-chain exposure as a graph traversal

When an npm package is compromised, a defender has minutes, not days, to answer:
**what did this actually reach?**

This builds a temporal dependency graph of the npm ecosystem in
[HydraDB](https://hydradb.com) and answers that question as a graph traversal —
not a similarity search. It is seeded with a real incident: the **September 2025
npm account-takeover campaign**, in which 17 packages including `debug` and
`chalk` were published with a crypto-stealing payload after a maintainer account
was phished.

```
$ python -m hydra_blast blast debug@4.4.2

  blast_radius  <debug@4.4.2>
  29.6 ms
    exposed_versions: 1378
    exposed_packages: 237
    max_depth_reached: 3
```

## Why a graph, and why HydraDB

"Which packages are transitively exposed to `debug@4.4.2`?" is not a question a
vector index can answer. It is a reachability question over typed, timestamped
edges, and the answer has to be *exact* — a defender acting on a fuzzy top-k list
of "semantically similar packages" would patch the wrong things.

Every query here is a traversal over entities HydraDB stores explicitly:

| Entity | Edge | Meaning |
|---|---|---|
| `Package` | `has_version` → `Version` | release history, timestamped |
| `Version` | `depends_on` → `Package` | **the declared semver range**, not a resolved pin |
| `Maintainer` | `maintains` → `Package` | the account an attacker actually compromises |
| `Advisory` | `affects` → `Version` | OSV/GHSA ground truth |

The critical modelling choice is that `depends_on` stores the **declared range**
(`^4.1.1`), not a resolved version. Blast radius is then computed by asking, for
every inbound edge, whether the compromised version *satisfies* that range. Store
a resolved pin instead and the question becomes unanswerable after the fact.

**What this project would lose without HydraDB:** the graph is written through
HydraDB's `graph_payload` ingestion path, which stores caller-defined entities
and predicates rather than LLM-extracted ones — so `depends_on` means exactly
what the manifest said, with no extraction confidence to second-guess. Edges keep
their validity window in `temporal_details`, which is what makes the
"while it was live" query answerable rather than approximate.

**HydraDB is in the query path, not just the ingest path.** Every query command
accepts `--from-hydra`, which fetches the typed graph back out of HydraDB
(`/context/list` → `/context/relations`) and runs the identical traversal over
those edges:

```bash
python -m hydra_blast blast debug@4.4.2 --from-hydra
#   read 1,226 sources, loaded 490,030 edges from HydraDB 'hydra_blast_radius'
#   blast_radius <debug@4.4.2>
#   exposed_versions: 1378   exposed_packages: 237   <- identical to local
```

All five queries are checked for parity, not just this one — `blast_radius`,
`shared_maintainer`, `live_resolution_window`, `version_introduced` and
`typosquat_candidates` return identical rows from either source, including the
full 74-minute window (`13:12:39Z → 14:26:51Z`) and `4.4.2 → 4.4.3`.
`scripts/capture_parity.sh` re-runs that check end to end.

**The division of labour:** HydraDB is the durable, temporally-versioned store
of record — the graph lives there, with its typed entities, predicates and
validity windows. The local JSON is a *synced query cache* in front of it, the
same arrangement as an edge cache over a source of truth, and it exists for
interactive latency. Traversal itself is ~30 ms either way; what differs is
getting the edges in front of it.

**Known constraint at scale.** Relation reads are per-source and measured at
**~6 s each**, so the full 1,226-source read takes **~15 minutes at 8 workers**
(~2 hours sequential). Response size stays flat as the graph grows — reads are
per-batch, not whole-graph — so there is no size cliff, but the *number* of
sources grows linearly. Paging cannot help: `cursor` returns an empty page for
any value and `next_cursor` is always null, so one large-limit request per
source is the only complete read.

`--hydra-sources N` bounds the read, but a bounded read is **refused by
default** rather than answered. At 1,226 sources, reading 8 of them fetches
~2 of the 720 batches holding `debug` dependency edges — 792 edges out of
490,030, which would look like a complete answer and be badly wrong:

```
$ python -m hydra_blast blast debug@4.4.2 --from-hydra --hydra-sources 8
refusing to answer from a PARTIAL HydraDB read.
  read 8 source(s), giving 792 edges -- a fraction of the graph.
  drop --hydra-sources for a complete read, or
  pass --allow-partial if you really want the subset.
```

The payoff is that both halves live in one system. Asking HydraDB a plain
question — *"which packages depend on debug"* — returns `graph_context.query_paths`
containing the **exact typed triplets** that were ingested:

```json
{"source": {"name": "debug", "namespace": "Package"},
 "relation": {"canonical_predicate": "has_version",
              "context": "debug has version 3.2.4",
              "temporal_details": "from 2018-09-11T09:12:30.102Z"}}
```

That is a semantic entry point resolving into structured graph traversal, with
the real npm publish timestamp attached — not a bag of similar-looking text
chunks. The precise answers come from the traversal; HydraDB keeps the structure,
the timestamps, and the human-readable advisory text queryable together.

## Install

Python 3.10+, no third-party runtime dependencies.

```bash
git clone https://github.com/Psalmuel01/hydra-chain.git && cd hydra-chain
cp .env.example .env          # add your HydraDB key from https://app.hydradb.com
```

`.env`:
```
HYDRA_DB_API_KEY=sk_live_...
HYDRA_DB_DATABASE=hydra_blast_radius
GITHUB_TOKEN=                  # optional; OSV needs no key
```

`.env` is read automatically — no need to `source` it first. Real environment
variables take precedence, so `HYDRA_DB_DATABASE=other python -m hydra_blast …`
still overrides the file for a single run.

Create the database in the [HydraDB dashboard](https://dashboard.hydradb.com)
first, then confirm it is ready — `ready_for_ingestion` must be `true` before
`sync` will work:

```bash
curl -s -H "Authorization: Bearer $HYDRA_DB_API_KEY" -H "API-Version: 2" \
  "https://api.hydradb.com/databases/status?database=$HYDRA_DB_DATABASE"
```

`sync` prints its destination database on every run, and `--database` overrides
the `.env` value for one-off runs.

## Use

```bash
# 1. Build the graph from the 17 confirmed-compromised seeds.
#    Quick start (~2 min) -- enough to run every query below:
python -m hydra_blast crawl --hops 1 --top1 40

#    Full graph (~12k packages, several hours -- responses are cached, so
#    an interrupted run resumes cheaply):
python -m hydra_blast crawl --hops 2

# 2. The headline query: what did the bad version reach?
python -m hydra_blast blast debug@4.4.2

# 3. What else can the compromised account publish to?
python -m hydra_blast maintainer debug

# 4. Who actually resolved to it *while it was live*?
#    The window is derived from the graph: publish time -> advisory time.
python -m hydra_blast window debug@4.4.2 --advisory MAL-2025-46974

# 5. Plausible typosquats.
python -m hydra_blast typosquat chalk

# 6. Which version introduced it, and what fixed it?
python -m hydra_blast introduced MAL-2025-46974

# Push the graph into HydraDB, then score yourself.
python -m hydra_blast sync --wait
python eval/run_eval.py --cutoff 2025-09-01
```

Add `--json` for machine-readable output, `--limit N` to show more rows.

## Evaluation

`eval/run_eval.py` holds out advisories published on or after a cutoff and
**rebuilds the graph without them** before scoring.

**What "held out" means matters.** Only the advisory *knowledge* is removed —
the Advisory node and its `affects` edges, i.e. the assertion *"this version is
compromised"*. The compromised Version node and every dependency edge stay,
because `blast_radius` traverses *from* that version; deleting it would test
"can you find a package that doesn't exist", which is not the defensive
question. What is actually tested: **given a version the system was never told
was bad, does it still resolve the exposure correctly?**

Ground truth is computed by brute-force scans implemented independently of the
traversal, so the query never grades its own homework — a direct scan for
depth-1, and a deliberately naive repeated-rescan closure for multi-hop.

```
$ python eval/run_eval.py --cutoff 2025-09-01 --transitive

  held-out advisories: 3  [advisories removed from the graph before scoring]
  edges: 1,830 scored of 1,856 total          <- 26 `affects` edges removed

  detection         recall=1.0  hits=26  misses=0
  direct exposure   precision=1.0  recall=1.0  f1=1.0  (n=26, depth-1 only)
  transitive        precision=1.0  recall=1.0  f1=1.0  (n=26, full closure)
  latency:
    blast_radius             p50=0.0ms  p95=0.01ms  max=0.92ms
```

Metrics are named for exactly what they cover: `direct_exposure` is depth-1
dependents only, `transitive_exposure` is the full closure. `--no-holdout`
scores against the complete graph if you want the in-graph numbers instead.

## What was hard, and what it taught

Three findings changed the design; all are reproducible from the code.

**1. npm deletes the evidence.** The malicious `debug@4.4.2` has been unpublished:
it is *gone* from the registry's `versions` map. But its timestamp survives in
`time`. An ingester that walks only `versions` silently drops the compromised
release and reports an empty blast radius **for the exact incident being
investigated**. These versions are reconstructed from `time` and flagged
`unpublished`.

**2. npm has no reverse-dependency API.** Blast radius needs *dependents*, and
`registry.npmjs.org/-/v1/search?text=depended:debug` returns `total: 0`.
[ecosyste.ms](https://ecosyste.ms) fills the gap, and its download counts also
drive both the crawl ranking and typosquat scoring.

**3. The ecosystem is far denser than it looks.** `chalk` alone has **130,085**
direct dependents; five seeds have 183,768 between them. An unbounded 2–3 hop
crawl reaches millions of packages. The crawl instead keeps the top-K dependents
*by download count* at each hop — a defensible cut, since that is where a real
compromise does the most damage, and one config constant to widen.

**What the shipped graph actually covers.** 1,142 packages / 490,030 edges,
crawled to **hop 1**, which already yields **depth-3** transitive exposure
(237 packages reachable from `debug@4.4.2`).

Reverse-engineering HydraDB's explicit-graph ingestion is documented in
[NOTES-graph-payload.md](NOTES-graph-payload.md) — the parameter is undocumented,
so the schema was derived from the validator's own error messages.

## Correctness

`satisfies()` decides the entire blast radius, so it is **differentially tested
against npm's own `semver` package — 651/651 cases agree**
([tests/test_semver_differential.py](tests/test_semver_differential.py), which
installs npm `semver` via node and compares every case). Hand-written tests only
prove the code matches its author's understanding of semver; this compares it
against the implementation npm actually ships.

That comparison has caught two real bugs: `^0.0.3` wrongly matching `0.0.4`, and
an empty range accepting prereleases that npm excludes. Non-registry specs
(`git:`, `file:`, `workspace:`, `npm:` aliases) return `False` rather than guess.

```bash
python3 tests/test_semver.py               # 8 passed
python3 tests/test_semver_differential.py   # 651/651 vs npm semver (needs node)
python3 tests/test_queries.py               # 8 passed
python3 tests/test_typosquat.py             # 7 passed
```

The differential test skips cleanly if node is unavailable, and says so rather
than reporting a pass it did not earn.

Query tests run on synthetic fixtures because real data cannot exercise the
negative cases — every version in the live incident neighbourhood was published
years before the compromise, so the window filter never has to exclude anything.

**An empty answer must never be indistinguishable from a real negative.** A
scoped-down test crawl once sat in `data/graph.json`, and querying `chalk`
against it returned `0 related packages` — which reads exactly like "chalk has
no shared maintainers", a wrong and confident answer. Nothing was broken; the
package had simply never been crawled.

Two guards, because for a security tool a silently-empty result is worse than an
error:

- every graph records its **provenance** (seeds, hops, caps, build time)
- package-scoped queries **refuse to answer** for a package that is not in the
  graph, and say what the graph was built from

```
$ python -m hydra_blast maintainer chalk
'chalk' is not in this graph, so any result would be empty and misleading.
  graph: 508 entities, built from 1 seed(s) [debug], hops=0, max_packages=6
```

## Attribution

- **[OSV.dev](https://osv.dev)** — vulnerability ground truth (Google, open data)
- **[GitHub Advisory Database](https://github.com/advisories)** — GHSA cross-reference
- **[npm registry](https://registry.npmjs.org)** — package metadata
- **[ecosyste.ms](https://ecosyste.ms)** — reverse dependencies and download counts
- **[HydraDB](https://hydradb.com)** — graph storage and retrieval

Built for [Hack Hydra](https://hackhydra.hydradb.com) Track 2A. MIT licensed.
