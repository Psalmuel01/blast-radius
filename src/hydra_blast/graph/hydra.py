"""Push the typed graph into HydraDB via the explicit `graph_payload` path.

Schema notes (reverse-engineered and verified -- see NOTES-graph-payload.md):
  * `graph_payload` maps source_id -> {entities: MAP, relations: LIST}
  * relations use `predicate` on write, read back as `canonical_predicate`
  * it cannot be sent alone; a source document must accompany it
  * only `context` and `temporal_details` persist as edge attributes;
    `properties`/`metadata` are silently dropped and `timestamp` is overwritten

Because of that last point the declared range and validity window are encoded
into `context` and `temporal_details`, which do survive.
"""

from __future__ import annotations

import http.client
import json
import logging
import re
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from ..config import HYDRA_API_VERSION, HYDRA_BASE_URL, hydra_api_key, hydra_database
from .model import (
    Edge,
    Entity,
    Graph,
    NS_ADVISORY,
    NS_MAINTAINER,
    NS_PACKAGE,
    NS_VERSION,
    P_AFFECTS,
    P_HAS_VERSION,
    adv_id,
    maint_id,
    pkg_id,
    ver_id,
)

log = logging.getLogger(__name__)


class HydraError(RuntimeError):
    pass


@dataclass
class HydraClient:
    api_key: str
    database: str
    base_url: str = HYDRA_BASE_URL

    @classmethod
    def from_env(cls) -> "HydraClient":
        key = hydra_api_key()
        if not key:
            raise HydraError(
                "HYDRA_DB_API_KEY is not set. Copy .env.example to .env and add "
                "a key from https://app.hydradb.com"
            )
        return cls(api_key=key, database=hydra_database())

    # -- transport ---------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "API-Version": HYDRA_API_VERSION,
        }

    def _get(self, path: str, *, retries: int = 3) -> dict:
        # Large relation payloads arrive in several chunks and a single read()
        # can return short, raising IncompleteRead. Read until the stream ends
        # and retry, since a truncated body is a transport fault, not a 4xx.
        last: Exception | None = None
        for attempt in range(retries):
            request = urllib.request.Request(self.base_url + path, headers=self._headers())
            try:
                with urllib.request.urlopen(request, timeout=120) as response:
                    # response.read() with no argument reads to EOF and handles
                    # chunked transfer correctly. Reading in fixed blocks and
                    # stopping on a short read truncates the body mid-JSON,
                    # which surfaced as bogus "Unterminated string" errors.
                    return json.loads(response.read().decode())
            except (http.client.IncompleteRead, urllib.error.URLError,
                    TimeoutError, json.JSONDecodeError, OSError) as exc:
                last = exc
                if attempt < retries - 1:
                    time.sleep(0.5 * (2 ** attempt))
        raise HydraError(f"GET {path} failed: {last}")

    def _post_multipart(self, path: str, fields: dict[str, str]) -> dict:
        boundary = uuid.uuid4().hex
        parts = [
            f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'
            for key, value in fields.items()
        ]
        body = ("".join(parts) + f"--{boundary}--\r\n").encode()
        headers = self._headers()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            detail = (exc.read() or b"").decode()
            try:
                message = json.loads(detail)["error"]["message"]
            except Exception:
                message = detail[:300]
            raise HydraError(f"HTTP {exc.code}: {message}") from exc

    # -- ingestion ---------------------------------------------------------

    def ingest_batch(self, source_id: str, entities: dict, relations: list[dict], text: str) -> dict:
        payload = {source_id: {"entities": entities, "relations": relations}}
        knowledge = [
            {
                "id": source_id,
                "title": source_id,
                "content": {"text": text},
                "source": "npm",
            }
        ]
        return self._post_multipart(
            "/context/ingest",
            {
                "database": self.database,
                "type": "knowledge",
                "graph_payload": json.dumps(payload),
                "app_knowledge": json.dumps(knowledge),
                "upsert": "true",
            },
        )

    def wait_indexed(self, source_id: str, *, timeout: float = 300.0) -> str:
        """Poll until terminal. A 202 means queued, not indexed."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self._get(
                f"/context/status?database={self.database}&id={source_id}"
            ).get("data") or {}
            statuses = data.get("statuses") or []
            state = statuses[0].get("indexing_status") if statuses else ""
            if state in ("completed", "errored"):
                return state
            time.sleep(5)
        return "timeout"

    def relations(self, source_id: str | None = None, limit: int = 200) -> list[dict]:
        """Relations for one source (or the whole database).

        Pass a `limit` comfortably above the expected edge count: measured
        behaviour is that a too-small limit under-fetches and sets
        `is_truncated`, and there is no working way to page past it (see the
        comment below), so one large request is the only complete read.
        """
        path = f"/context/relations?database={self.database}&limit={limit}"
        if source_id:
            path += f"&id={source_id}"
        data = self._get(path).get("data") or {}
        relations = data.get("relations") or []
        if data.get("is_truncated"):
            # Measured behaviour: `limit` under-fetches and sets is_truncated,
            # while `cursor` returns an empty page for *any* value (it is not an
            # offset) and `next_cursor` is always null. So there is no way to
            # page -- the only reliable read is a single large-limit request.
            log.warning(
                "relations for %s truncated at limit=%d; raise the limit",
                source_id or "<database>", limit,
            )
        return relations

    def list_sources(self, *, page_size: int = 100) -> list[str]:
        """All knowledge source ids in the database (paginated)."""
        ids: list[str] = []
        page = 1
        while True:
            body = json.dumps(
                {
                    "database": self.database,
                    "type": "knowledge",
                    "page": page,
                    "page_size": page_size,
                }
            ).encode()
            headers = self._headers()
            headers["Content-Type"] = "application/json"
            request = urllib.request.Request(
                self.base_url + "/context/list", data=body, headers=headers
            )
            try:
                with urllib.request.urlopen(request, timeout=120) as response:
                    data = json.loads(response.read().decode()).get("data") or {}
            except urllib.error.HTTPError as exc:
                detail = (exc.read() or b"").decode()
                raise HydraError(f"HTTP {exc.code}: {detail[:300]}") from exc

            sources = data.get("sources") or []
            for source in sources:
                source_id = source.get("id") or source.get("source_id")
                if source_id:
                    ids.append(str(source_id))
            if len(sources) < page_size:
                break
            page += 1
        return ids

    def query(self, text: str, *, mode: str = "hybrid", level: str = "fast") -> dict:
        body = json.dumps(
            {
                "database": self.database,
                "query": text,
                "query_by": mode,
                "type": "knowledge",
                "recall_mode": level,
            }
        ).encode()
        headers = self._headers()
        headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + "/query", data=body, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            detail = (exc.read() or b"").decode()
            raise HydraError(f"HTTP {exc.code}: {detail[:300]}") from exc


# ---------------------------------------------------------------------------
# HydraDB -> Graph  (the read path: queries traverse data fetched from HydraDB)
# ---------------------------------------------------------------------------

# `context` is written as "<pkg>@<ver> depends on <dep>@<range> (declared range <range>)".
# The declared range is what blast radius needs, and `context` is one of only two
# edge attributes HydraDB persists verbatim, so it is parsed back out here.
_RANGE_RE = re.compile(r"\(declared range (.+?)\)\s*$")

# temporal_details is written as "from <ts>", "until <ts>" or "<from>..<to>".
_FROM_RE = re.compile(r"^from (.+)$")
_UNTIL_RE = re.compile(r"^until (.+)$")


def _decode_temporal(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    if ".." in value:
        start, _, end = value.partition("..")
        return start.strip() or None, end.strip() or None
    match = _FROM_RE.match(value)
    if match:
        return match.group(1).strip(), None
    match = _UNTIL_RE.match(value)
    if match:
        return None, match.group(1).strip()
    return None, None


def _entity_id_for(name: str, namespace: str) -> str:
    """Rebuild our stable local ids from the name/namespace HydraDB returns.

    HydraDB normalises entity names to lower case, which matters for advisory
    ids: `MAL-2025-46974` comes back as `mal-2025-46974` and a case-sensitive
    lookup then misses. OSV/GHSA ids are conventionally upper case, so restore
    that; npm package names are already lower case by registry rule.
    """
    if namespace == NS_VERSION and "@" in name:
        package, _, version = name.rpartition("@")
        return ver_id(package, version)
    if namespace == NS_MAINTAINER:
        return maint_id(name)
    if namespace == NS_ADVISORY:
        return adv_id(name.upper())
    return pkg_id(name)


def load_graph_from_hydra(
    client: HydraClient | None = None,
    *,
    source_ids: list[str] | None = None,
    limit_per_source: int = 5000,
    workers: int = 8,
    progress: bool = True,
) -> Graph:
    """Rebuild the typed graph by reading relations back out of HydraDB.

    This is the query-time read path: the traversal runs over edges fetched
    from HydraDB rather than a local file, so HydraDB is the store of record
    for the graded queries and not merely an export target.

    Entities and predicates come back exactly as ingested (HydraDB preserves
    `namespace` and `canonical_predicate`), and the declared semver range is
    recovered from `context`, which persists verbatim.
    """
    client = client or HydraClient.from_env()
    ids = source_ids or client.list_sources()
    if progress:
        log.info("reading %d source(s) from HydraDB database '%s'", len(ids), client.database)

    graph = Graph()

    def fetch(source_id: str):
        try:
            return client.relations(source_id=source_id, limit=limit_per_source)
        except HydraError as exc:
            log.warning("relations fetch failed for %s: %s", source_id, exc)
            return []

    groups: list[dict] = []
    if workers > 1 and len(ids) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(fetch, ids):
                groups.extend(result)
    else:
        for source_id in ids:
            groups.extend(fetch(source_id))

    for group in groups:
        source = group.get("source") or {}
        target = group.get("target") or {}
        source_name, source_ns = source.get("name"), source.get("namespace")
        target_name, target_ns = target.get("name"), target.get("namespace")
        if not (source_name and target_name and source_ns and target_ns):
            continue

        source_id_local = _entity_id_for(source_name, source_ns)
        target_id_local = _entity_id_for(target_name, target_ns)

        for node_id, name, namespace in (
            (source_id_local, source_name, source_ns),
            (target_id_local, target_name, target_ns),
        ):
            attrs: dict = {}
            if namespace == NS_VERSION and "@" in name:
                package, _, version = name.rpartition("@")
                attrs = {"package": package, "version": version}
            elif namespace == NS_ADVISORY:
                # Match the id casing so `introduced MAL-...` resolves.
                name = name.upper()
            graph.add_entity(Entity(node_id, name, namespace, attrs))

        for relation in group.get("relations") or []:
            predicate = relation.get("canonical_predicate") or relation.get("raw_predicate")
            if not predicate:
                continue
            context = relation.get("context") or ""
            range_match = _RANGE_RE.search(context)
            valid_from, valid_to = _decode_temporal(relation.get("temporal_details"))

            graph.add_edge(
                Edge(
                    source=source_id_local,
                    target=target_id_local,
                    predicate=predicate,
                    declared_range=range_match.group(1) if range_match else None,
                    valid_from=valid_from,
                    valid_to=valid_to,
                    context=context or None,
                )
            )

    # HydraDB stores entity name/namespace but not our free-form attrs, so the
    # timestamps the queries need are recovered from the edges that carry them:
    #   has_version.valid_from -> Version.published_at   (live-window start)
    #   affects.valid_from     -> Advisory.published_at  (live-window end,
    #                                                     and version_introduced)
    for edge in graph.edges:
        if not edge.valid_from:
            continue
        if edge.predicate == P_HAS_VERSION:
            entity = graph.entities.get(edge.target)
            if entity is not None and not entity.attrs.get("published_at"):
                entity.attrs["published_at"] = edge.valid_from
        elif edge.predicate == P_AFFECTS:
            entity = graph.entities.get(edge.source)
            if entity is not None and not entity.attrs.get("published_at"):
                entity.attrs["published_at"] = edge.valid_from

    return graph


# ---------------------------------------------------------------------------
# Graph -> payload encoding
# ---------------------------------------------------------------------------

def _edge_context(edge: Edge) -> str:
    """Human-readable edge context. This field persists verbatim."""
    if edge.context:
        base = edge.context
    else:
        base = f"{edge.source} {edge.predicate} {edge.target}"
    if edge.declared_range:
        base += f" (declared range {edge.declared_range})"
    return base[:500]


def _edge_temporal(edge: Edge) -> str | None:
    """Validity window as a STRING -- an object fails the outer parser."""
    if edge.valid_from and edge.valid_to:
        return f"{edge.valid_from}..{edge.valid_to}"
    if edge.valid_from:
        return f"from {edge.valid_from}"
    if edge.valid_to:
        return f"until {edge.valid_to}"
    return None


def _synthesise_entity(node_id: str) -> dict | None:
    """Minimal entity for an id that has no node of its own.

    Our ids are `pkg:<name>` / `ver:<name>@<v>` / `maint:` / `adv:`, so the
    name and namespace can be recovered from the id itself.
    """
    prefix, _, rest = node_id.partition(":")
    if not rest:
        return None
    if prefix == "pkg":
        return {"name": rest, "namespace": NS_PACKAGE}
    if prefix == "ver":
        return {"name": rest, "namespace": NS_VERSION}
    if prefix == "maint":
        return {"name": rest, "namespace": NS_MAINTAINER}
    if prefix == "adv":
        return {"name": rest, "namespace": NS_ADVISORY}
    return None


def encode_batches(graph: Graph, *, batch_size: int = 400, prefix: str = "npm-graph") -> list[tuple[str, dict, list[dict], str]]:
    """Split the graph into per-source ingest batches.

    Batching keeps individual payloads small enough to index reliably and gives
    the query layer meaningful source ids to fetch relations by.
    """
    batches: list[tuple[str, dict, list[dict], str]] = []
    edges = graph.edges
    for start in range(0, len(edges), batch_size):
        chunk = edges[start : start + batch_size]
        entities: dict[str, dict] = {}
        relations: list[dict] = []
        lines: list[str] = []

        for edge in chunk:
            for node_id in (edge.source, edge.target):
                if node_id in entities:
                    continue
                entity = graph.entities.get(node_id)
                if entity is not None:
                    entities[node_id] = {"name": entity.name, "namespace": entity.namespace}
                    continue
                # A dependency target outside the crawl boundary (e.g. debug ->
                # ms when ms was never fetched) has no entity of its own.
                # Synthesise a minimal Package node instead of dropping the
                # edge: these are real declared dependencies, and skipping them
                # silently lost 1,021 of 1,215 depends_on edges.
                synthetic = _synthesise_entity(node_id)
                if synthetic is not None:
                    entities[node_id] = synthetic

            if edge.source not in entities or edge.target not in entities:
                continue

            relation = {
                "source": edge.source,
                "target": edge.target,
                "predicate": edge.predicate,
                "context": _edge_context(edge),
            }
            temporal = _edge_temporal(edge)
            if temporal:
                relation["temporal_details"] = temporal
            relations.append(relation)
            lines.append(_edge_context(edge))

        if relations:
            source_id = f"{prefix}-{start // batch_size:04d}"
            batches.append((source_id, entities, relations, "\n".join(lines)[:20000]))
    return batches


def sync_graph(
    graph: Graph,
    client: HydraClient | None = None,
    *,
    batch_size: int = 400,
    max_batches: int | None = None,
    wait: bool = False,
    progress: bool = True,
    workers: int = 4,
) -> dict:
    """Ingest the whole graph, returning a summary."""
    client = client or HydraClient.from_env()
    batches = encode_batches(graph, batch_size=batch_size)
    if max_batches is not None:
        batches = batches[:max_batches]

    sent = 0
    failed = 0
    started = time.time()

    def _send(batch):
        source_id, entities, relations, text = batch
        try:
            client.ingest_batch(source_id, entities, relations, text)
            return True, source_id, None
        except HydraError as exc:
            return False, source_id, str(exc)
        except OSError as exc:
            return False, source_id, f"{type(exc).__name__}: {exc}"

    if workers > 1:
        # Bounded parallelism: ~1.6s/batch sequentially means a large graph
        # takes far too long, but an unbounded fan-out is rude to the API.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for ok, source_id, error in pool.map(_send, batches):
                if ok:
                    sent += 1
                    if progress and sent % 25 == 0:
                        log.info("ingested %d/%d batches", sent, len(batches))
                else:
                    failed += 1
                    log.warning("batch %s failed: %s", source_id, error)
    else:
        for batch in batches:
            ok, source_id, error = _send(batch)
            if ok:
                sent += 1
                if progress and sent % 25 == 0:
                    log.info("ingested %d/%d batches", sent, len(batches))
            else:
                failed += 1
                log.warning("batch %s failed: %s", source_id, error)

    summary = {
        "batches": len(batches),
        "sent": sent,
        "failed": failed,
        "edges": sum(len(b[2]) for b in batches),
        "seconds": round(time.time() - started, 1),
    }
    if wait and batches:
        summary["final_status"] = client.wait_indexed(batches[-1][0])
    return summary
