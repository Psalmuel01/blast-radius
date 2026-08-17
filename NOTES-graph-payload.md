# `graph_payload`: the verified schema (reverse-engineered)

`context.ingest` accepts an **undocumented** `graph_payload` parameter that writes
an *explicit, caller-defined* graph — no LLM extraction, no guessing at predicates.
This is the difference between "vector search over package blobs" and a real
graph-native traversal, so it is worth the dig.

It appears in **no** prose doc, **no** API reference page, and **none** of the 12
cookbooks. The error message points at
`https://docs.hydradb.com/api-reference/v2/endpoint/ingest`, which **404s**. The
schema below was derived empirically by walking the validator's own error messages.

## Verified schema

```jsonc
// graph_payload: JSON string, multipart form field.
// Top level maps SOURCE ID -> graph payload for that source.
{
  "<source_id>": {
    // entities: a MAP of entity_key -> entity. NOT a list.
    // (A list fails the *outer* parser with a misleading "invalid JSON" error.)
    "entities": {
      "pkg:debug": { "name": "debug", "namespace": "Package" },
      "pkg:ms":    { "name": "ms",    "namespace": "Package" }
    },
    // relations: non-empty LIST. Field is `predicate` — NOT `canonical_predicate`
    // (that name only appears on the READ side).
    "relations": [
      { "source": "pkg:debug", "target": "pkg:ms", "predicate": "depends_on" }
    ]
  }
}
```

**`graph_payload` cannot be sent alone.** It enriches a source document, so the
request must also carry `documents` (file) or `app_knowledge` (JSON array). For
`app_knowledge`, `content` is an **object**, not a string:

```jsonc
[{ "id": "<source_id>", "title": "...", "content": { "text": "..." }, "source": "npm" }]
```

The `id` here **must match** the `graph_payload` key.

## Confirmed round-trip

Ingest → poll `GET /context/status` → `indexing_status: "completed"` →
`GET /context/relations?id=<source_id>` returned exactly the edge supplied:

```json
{"source": {"name": "debug", "namespace": "Package"},
 "target": {"name": "ms",    "namespace": "Package"},
 "relations": [{"canonical_predicate": "depends_on", "raw_predicate": "depends_on",
                "confidence": 0.8, "context": "debug depends_on ms",
                "temporal_details": null, "timestamp": "..."}]}
```

Notes:
- Our `predicate` surfaces as **both** `canonical_predicate` and `raw_predicate`.
- `namespace` round-trips intact → entity typing (Package/Version/Maintainer/
  Advisory) is preserved, which is what makes typed traversal possible.
- `entity_id` is server-assigned (md5-looking); our keys are join handles only.
## Relation fields: what is *accepted* vs what actually *persists*

Accepted-at-ingest and stored are different things. Verified by round-trip:

| field | accepted | persists | notes |
|---|---|---|---|
| `predicate` | yes | yes | reads back as `canonical_predicate` + `raw_predicate` |
| `context` | yes | **yes, verbatim** | free-text carrier — reliable |
| `temporal_details` | **string only** | **yes, verbatim** | an *object* fails the outer parser |
| `timestamp` | yes | **no — overwritten** | replaced by server ingest time |
| `confidence` | yes | **no — coerced** | sent 0.99, stored 0.8 |
| `properties` | yes | **no — dropped silently** | accepted then discarded |
| `metadata` | yes | **no — dropped silently** | accepted then discarded |

**Consequence for this project:** `context` and `temporal_details` are the only
dependable places to put the declared semver range and the live window. Do not
trust `properties`/`metadata` (silently lost) or `timestamp` (rewritten). The
local graph stays the source of truth for exact times; HydraDB carries the
traversable structure plus these two string attributes.

## Entity names are normalised on ingest (not just lower-cased)

HydraDB rewrites entity names, and not reversibly. Two distinct behaviours,
both found by round-tripping a 490k-edge graph and comparing edge-by-edge:

1. **Lower-casing.** `MAL-2025-46974` reads back as `mal-2025-46974`. Handled by
   upper-casing advisory ids on read.
2. **Separator stripping / entity resolution.** The seed package **`ansi-styles`
   reads back as `ansistyles`** — which is a *different real npm package*. It is
   not applied uniformly: `strip-ansi`, `wrap-ansi`, `ansi-regex` and
   `supports-color` all keep their hyphens in the same database.

The second is the dangerous one for this project: a compromised seed package is
silently renamed to a different real package, so every edge touching it resolves
to the wrong entity id on read and looks *missing*. Measured effect on a
490,030-edge graph: **483,519 edges read back (−6,511, 1.3%)**, and
`blast_radius(debug@4.4.2)` returned 1,350 versions from HydraDB versus 1,378
locally.

**Implication:** entity *names* cannot be used as join keys across the HydraDB
round trip. The local graph stays authoritative for identity; HydraDB round
trips are verified with the name-normalisation accounted for, and any parity
claim has to be re-measured at scale rather than assumed from a small sample.

## Gotchas that cost time
1. `entities` as a list → outer "invalid graph_payload JSON" error that points at
   the *whole* payload, not the offending field. Misleading; it must be a map.
2. `canonical_predicate` on write → `predicate is required`. Write and read field
   names differ.
3. Both validation layers report through the same `INVALID_INPUT` code, so an
   error moving from the generic message to a field-specific one is real progress.
4. A `202` means *queued*, not indexed — always poll `/context/status`.
