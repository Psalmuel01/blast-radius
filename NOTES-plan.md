# Build plan (resolved against verified data)

## The scoping problem I hit, and the fix

Scope doc §4.4 says "2-3 hops of dependencies and dependents → tens of thousands of
nodes." Measured against real data, that is **wrong by orders of magnitude**:

| seed | direct dependents |
|---|---|
| chalk | 130,085 |
| debug | 46,672 |
| ansi-styles | 4,466 |
| color-name | 2,520 |
| backslash | 25 |

5 of 17 seeds → **183,768 dependents at hop 1 alone**. Unbounded 2–3 hop BFS lands in
the millions and would eat the whole 5-day window in ingestion.

**Fix — impact-ranked bounded fan-out.** `ecosyste.ms` supports
`?sort=downloads&order=desc` (verified). At each hop take the top-K dependents by
downloads instead of all of them:

- hop 1: top 300/seed · hop 2: top 40/node · hop 3: skipped by default
- → roughly 15–25k packages: matches the doc's *intent* and stays tractable.

This is a **defensible** cut, not just a convenient one: ranking by downloads keeps
the dependents where a real compromise does the most damage. Recall is measured
against held-out advisories (§7), and the cap is one config constant, so it can be
raised if the eval shows recall loss.

## Ecosystem: npm (per §4, not doing PyPI)

## Data sources (all verified live, no key needed except GitHub)
- **npm registry** — versions, per-version `dependencies`, `maintainers`, `time`
- **OSV.dev** — advisory ground truth; `/v1/querybatch` for bulk
- **ecosyste.ms** — reverse deps + downloads (fills npm's missing reverse-dep API)
- **GHSA** — cross-reference (needs token; optional, OSV already carries GHSA ids)

## Logical schema → HydraDB triplets
Entities are namespaced (`Package`, `Version`, `Maintainer`, `Advisory`), edges carry
`canonical_predicate` + timestamps, so every §6 query is a **graph traversal**:

| predicate | source → target | carries |
|---|---|---|
| `depends_on` | Version → Package | declared semver range |
| `has_version` | Package → Version | `published_at` |
| `maintains` | Maintainer → Package | — |
| `affects` | Advisory → Version | `published_at` |

Timestamps on every edge — the live-window query (§6.3) needs them, and append-only
temporal edges are HydraDB's advertised differentiator (§5).

## Order of work (mirrors §3, adjusted for what I verified)
1. **Ingestion** — crawler w/ cache + backoff; ranked fan-out above.
2. **Graph build** — triplet encoder behind one adapter (see `graph_payload` risk).
3. **Core queries** — blast radius → shared maintainer → live window. Graded core.
4. **Typosquat + eval** — Levenshtein ≤2 filtered by low downloads/recent
   registration (both fields present in the ecosyste.ms payload).
5. **Buffer** — README, demo, submission. No new features.

## Verified-real demo spine
`debug@4.4.2` published `13:12:39.973Z`, advisory `14:26:51Z` → **74-minute live
window** on 2025-09-08.

Shared-maintainer ground truth, verified against the registry (2026-08-16):
`qix` — the phished account — maintains **7** of the 17 seeds (`debug`,
`color-convert`, `error-ex`, `is-arrayish`, `simple-swizzle`, `backslash`,
`color-string`), and `sindresorhus` maintains **10** (`chalk`, `ansi-styles`,
`strip-ansi`, `supports-color`, `error-ex`, `ansi-regex`, `slice-ansi`,
`has-ansi`, `wrap-ansi`, `chalk-template`). `qix` does **not** maintain `chalk`.
So blast radius / shared maintainer / live window all have true answers to
score against.

## Open risk
`graph_payload` schema is undocumented and **unverified without an API key** — the
one blocker. Ingestion sits behind a single adapter so the documented-path fallback
(structured text + auto-extraction) is a contained swap.
