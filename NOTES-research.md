# Research findings (Day 0 — pre-build verification)

Everything below was verified against live APIs, not assumed from the scope doc.

## 1. HydraDB API model — scope doc §5 was right to flag itself as stale

Verified from the real SDK (`hydradb-sdk==2.1.2`, wheel unpacked and read) plus
docs.hydradb.com. There is **no Neo4j-style node/edge CRUD API**.

Base URL `https://api.hydradb.com`, headers `Authorization: Bearer <key>` +
`API-Version: 2`. Env var `HYDRA_DB_API_KEY`. All responses wrap as
`{success, data, error, meta}` — payload is under `.data`.

Relevant primitives:

| Purpose | Endpoint / SDK |
|---|---|
| Ingest | `POST /context/ingest` (`context.ingest`) |
| Query | `POST /query` — `hybrid`/`text`, `fast`/`thinking` |
| Read graph | `GET /context/relations` (`context.relations`) |
| Enumerate | `POST /context/list` |
| Poll indexing | `GET /context/status` → `graph_creation`/`completed` |

### The key find: `graph_payload`

`context.ingest` accepts an **undocumented** `graph_payload` parameter
(`src: hydra_db/context/client.py:116`). It appears in **no** prose doc and **no**
cookbook — found only by reading the wheel. Wire format is a multipart form field
carrying a **JSON string** (`hydra_db/context/raw_client.py:197`).

Read-side types confirm the graph is genuinely typed, not just text-derived:
- `GraphEntity` → `entity_id`, `identifier`, `name`, `namespace`
- `GraphTripletWithEvidence` → `source`, `target`, `relations[]`
- `GraphRelationEvidence` → `canonical_predicate`, `confidence`, `context`

**`canonical_predicate`'s own docstring gives `depends_on` as an example.** HydraDB's
graph model natively expects exactly the predicate shape this project needs.

> ⚠️ **Unverified — needs an API key.** `graph_payload`'s exact accepted schema is
> undocumented. Design keeps ingestion behind one adapter so the fallback (encode
> triplets as structured text and let extraction build the graph) is a contained
> change, not a rewrite.

## 2. Seed incident — better than the scope doc's suggestion

Scope doc §4.4 suggested TanStack/Mistral/UiPath. I found a stronger cluster:
the **September 2025 npm account-takeover campaign**, confirmed live in OSV as a
contiguous `MAL-2025-469xx` block — **17/17 seeds confirmed**:

```
debug MAL-2025-46974   chalk MAL-2025-46969   ansi-styles MAL-2025-46967
color-convert 46971    supports-color 46981   strip-ansi 46980
wrap-ansi 46983        chalk-template 46970   is-arrayish 46977
error-ex 46975         simple-swizzle 46978   color-name 46972
backslash 46968        ansi-regex 46966       slice-ansi 46979
color-string 46973     has-ansi 46976
```

Why this beats the original suggestion: these are among the most-depended-upon
packages on npm (`debug` alone: 46,672 dependent packages, 2.76B downloads), so the
blast radius is genuinely dense rather than a toy subgraph.

`GHSA-4x49-vf9v-38px`: `debug` npm account taken over via phishing on 8 Sep 2025;
`4.4.2` published functionally identical to the prior patch but with a crypto-
redirect payload. Browser/bundled contexts affected; server/CLI not.

### Real temporal ground truth for the live-window query
- `debug@4.4.2` published: **2025-09-08T13:12:39.973Z** (npm `time`)
- `MAL-2025-46974` published: **2025-09-08T14:26:51Z** (OSV)
- → **~74-minute live window**, from real timestamps, not synthetic.

## 3. Reverse dependencies — the gap the scope doc left unspecified

Blast radius needs *dependents*, and **npm has no reverse-dependency API**:
`registry.npmjs.org/-/v1/search?text=depended:debug` returns `total: 0`.

**Solution — ecosyste.ms** (verified working, no key):
- `packages.ecosyste.ms/api/v1/registries/npmjs.org/packages/debug`
  → `dependent_packages_count`, `downloads`
- `.../packages/debug/dependent_packages?per_page=N` → paginated real dependents

Also supplies **download counts**, which feed typosquat scoring (§6.4) — low
downloads + recent registration + name-similarity.

## 4. Other verified details
- `debug@4.4.2` has **no** `dependencies` field — ingestion must not assume it exists.
- OSV `affected[]` may use an explicit `versions` list with `ranges: null`
  (as `MAL-2025-46974` does) — handle both forms.
- npm per-package metadata carries `maintainers` (`debug` → `qix`, `tootallnate`),
  covering the shared-maintainer query. `qix` is the phished account, so the
  shared-maintainer query has a real, meaningful answer here.
