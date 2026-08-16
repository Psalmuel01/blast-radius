"""Typed graph model: entities, edges, and semver range logic.

Entity ids are stable, human-readable strings (`pkg:debug`, `ver:debug@4.4.2`)
so the local graph and the HydraDB graph can be joined without a lookup table.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable, Iterator

# Entity namespaces. These round-trip through HydraDB intact, which is what
# makes typed traversal (rather than blob similarity) possible.
NS_PACKAGE = "Package"
NS_VERSION = "Version"
NS_MAINTAINER = "Maintainer"
NS_ADVISORY = "Advisory"

# Edge predicates.
P_DEPENDS_ON = "depends_on"
P_HAS_VERSION = "has_version"
P_MAINTAINS = "maintains"
P_AFFECTS = "affects"


def pkg_id(name: str) -> str:
    return f"pkg:{name}"


def ver_id(name: str, version: str) -> str:
    return f"ver:{name}@{version}"


def maint_id(username: str) -> str:
    return f"maint:{username}"


def adv_id(osv_id: str) -> str:
    return f"adv:{osv_id}"


@dataclass
class Entity:
    entity_id: str
    name: str
    namespace: str
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    predicate: str
    # Declared semver range for depends_on edges.
    declared_range: str | None = None
    # Timestamp this edge became true (version publish time, advisory publish).
    valid_from: str | None = None
    # Timestamp it stopped being true (e.g. version unpublished/patched).
    valid_to: str | None = None
    context: str | None = None

    def __post_init__(self) -> None:
        # Registry data occasionally supplies a non-string range (a legacy
        # nested dependency object). The key must stay hashable, so coerce
        # here rather than letting it reach add_edge and abort the build.
        if self.declared_range is not None and not isinstance(self.declared_range, str):
            spec = self.declared_range
            version = spec.get("version") if isinstance(spec, dict) else None
            self.declared_range = version if isinstance(version, str) else None

    def key(self) -> tuple[str, str, str, str | None]:
        return (self.source, self.target, self.predicate, self.declared_range)


# ---------------------------------------------------------------------------
# semver range matching
#
# Deliberately a focused subset: the ranges that actually dominate npm
# manifests (^, ~, *, x, ranges, ||, comparators). A full semver implementation
# is out of scope for the build window, and `satisfies` is honest about what it
# cannot parse rather than guessing -- a wrong match here means a wrong blast
# radius, which is the one thing that must not happen silently.
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


def parse_version(version: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.match(version.strip())
    if not match:
        return None
    return tuple(int(g) for g in match.groups())  # type: ignore[return-value]


def _is_prerelease(version: str) -> bool:
    return "-" in version.split("+")[0]


def _cmp(a: tuple[int, int, int], b: tuple[int, int, int]) -> int:
    return (a > b) - (a < b)


def _satisfies_single(version: tuple[int, int, int], raw: str) -> bool:
    spec = raw.strip()
    if spec in ("", "*", "x", "X", "latest"):
        return True

    # Hyphen range: "1.2.3 - 2.3.4"
    if " - " in spec:
        low, high = spec.split(" - ", 1)
        lo, hi = parse_version(low), parse_version(high)
        return bool(lo and hi and _cmp(version, lo) >= 0 and _cmp(version, hi) <= 0)

    # Space-separated comparator conjunction: ">=1.2.0 <2.0.0"
    parts = spec.split()
    if len(parts) > 1:
        return all(_satisfies_single(version, p) for p in parts)

    for op in (">=", "<=", ">", "<", "=", "^", "~"):
        if spec.startswith(op):
            rest = spec[len(op) :].strip()
            if rest.endswith((".x", ".X", ".*")):
                rest = rest[:-2] + ".0"
            target = parse_version(rest)
            if target is None:
                # Partial like "^1" or "~1.2".
                nums = [int(n) for n in re.findall(r"\d+", rest)[:3]]
                if not nums:
                    return False
                nums += [0] * (3 - len(nums))
                target = (nums[0], nums[1], nums[2])
            if op == ">=":
                return _cmp(version, target) >= 0
            if op == "<=":
                return _cmp(version, target) <= 0
            if op == ">":
                return _cmp(version, target) > 0
            if op == "<":
                return _cmp(version, target) < 0
            if op == "=":
                return _cmp(version, target) == 0
            if op == "^":
                # Caret: no left-most non-zero digit change.
                if _cmp(version, target) < 0:
                    return False
                if target[0] > 0:
                    return version[0] == target[0]
                if target[1] > 0:
                    return version[0] == 0 and version[1] == target[1]
                # ^0.0.x pins the patch exactly -- every 0.0.z release may break.
                return version == target
            if op == "~":
                # Tilde: patch-level changes within the same minor.
                if _cmp(version, target) < 0:
                    return False
                return version[0] == target[0] and version[1] == target[1]

    # Bare / partial version: "1.2.3", "1.2", "1", "1.2.x"
    if spec.endswith((".x", ".X", ".*")):
        spec = spec[:-2]
    nums = [int(n) for n in re.findall(r"\d+", spec)]
    if not nums:
        return False
    if len(nums) == 3:
        return version == (nums[0], nums[1], nums[2])
    if len(nums) == 2:
        return version[0] == nums[0] and version[1] == nums[1]
    return version[0] == nums[0]


def satisfies(version: str, range_spec: str | None) -> bool:
    """Does `version` satisfy the declared npm range?

    Returns False for anything unparseable (git URLs, `npm:` aliases, `file:`
    specs, workspace protocols) rather than guessing.
    """
    if range_spec is None:
        return False
    spec = range_spec.strip()
    if not spec:
        # An empty range means "any version" -- but npm still excludes
        # prereleases unless the range asks for one, so this cannot short
        # -circuit before the prerelease check below.
        return not _is_prerelease(version)
    # Non-registry specs: cannot resolve to a registry version.
    if any(
        spec.startswith(p)
        for p in ("git", "http", "file:", "link:", "workspace:", "npm:", "github:")
    ):
        return False
    parsed = parse_version(version)
    if parsed is None:
        return False
    # Prereleases only match if the range mentions one.
    if _is_prerelease(version) and "-" not in spec:
        return False
    return any(_satisfies_single(parsed, alt) for alt in spec.split("||"))


# ---------------------------------------------------------------------------


@dataclass
class Graph:
    entities: dict[str, Entity] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    # How this graph was built (seeds, hops, caps). Without it a scoped-down
    # test crawl is indistinguishable from a real one once saved, and queries
    # silently return empty for packages that were simply never crawled.
    provenance: dict = field(default_factory=dict)
    _edge_keys: set = field(default_factory=set, repr=False)
    # Adjacency built on demand.
    _out: dict[str, list[int]] = field(default_factory=dict, repr=False)
    _in: dict[str, list[int]] = field(default_factory=dict, repr=False)

    def add_entity(self, entity: Entity) -> None:
        existing = self.entities.get(entity.entity_id)
        if existing is None:
            self.entities[entity.entity_id] = entity
        else:
            existing.attrs.update({k: v for k, v in entity.attrs.items() if v is not None})

    def add_edge(self, edge: Edge) -> None:
        key = edge.key()
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        index = len(self.edges)
        self.edges.append(edge)
        self._out.setdefault(edge.source, []).append(index)
        self._in.setdefault(edge.target, []).append(index)

    def out_edges(self, entity_id: str, predicate: str | None = None) -> Iterator[Edge]:
        for i in self._out.get(entity_id, ()):
            edge = self.edges[i]
            if predicate is None or edge.predicate == predicate:
                yield edge

    def in_edges(self, entity_id: str, predicate: str | None = None) -> Iterator[Edge]:
        for i in self._in.get(entity_id, ()):
            edge = self.edges[i]
            if predicate is None or edge.predicate == predicate:
                yield edge

    def by_namespace(self, namespace: str) -> Iterator[Entity]:
        for entity in self.entities.values():
            if entity.namespace == namespace:
                yield entity

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entity in self.entities.values():
            counts[entity.namespace] = counts.get(entity.namespace, 0) + 1
        for edge in self.edges:
            counts[edge.predicate] = counts.get(edge.predicate, 0) + 1
        counts["entities"] = len(self.entities)
        counts["edges"] = len(self.edges)
        return counts

    def save(self, path) -> None:
        payload = {
            "provenance": self.provenance,
            "entities": [asdict(e) for e in self.entities.values()],
            "edges": [asdict(e) for e in self.edges],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload))

    @classmethod
    def load(cls, path) -> "Graph":
        data = json.loads(path.read_text())
        graph = cls()
        graph.provenance = data.get("provenance") or {}
        for raw in data.get("entities", []):
            graph.add_entity(Entity(**raw))
        for raw in data.get("edges", []):
            raw.pop("key", None)
            graph.add_edge(Edge(**raw))
        return graph

    def describes(self) -> str:
        """One-line summary of how this graph was built."""
        p = self.provenance
        if not p:
            return "provenance unknown (built before provenance was recorded)"
        seeds = p.get("seeds") or []
        seed_text = f"{len(seeds)} seed(s)"
        if 0 < len(seeds) <= 4:
            seed_text += f" [{', '.join(seeds)}]"
        return (
            f"{seed_text}, hops={p.get('max_hops')}, "
            f"top1={p.get('top_dependents_hop1')}, "
            f"max_packages={p.get('max_packages')}"
        )
