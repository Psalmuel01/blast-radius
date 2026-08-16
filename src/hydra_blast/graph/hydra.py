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

import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from ..config import HYDRA_API_VERSION, HYDRA_BASE_URL, hydra_api_key, hydra_database
from .model import Edge, Graph

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

    def _get(self, path: str) -> dict:
        request = urllib.request.Request(self.base_url + path, headers=self._headers())
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode())

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
        path = f"/context/relations?database={self.database}&limit={limit}"
        if source_id:
            path += f"&id={source_id}"
        return (self._get(path).get("data") or {}).get("relations") or []

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
                if entity is None:
                    continue
                entities[node_id] = {"name": entity.name, "namespace": entity.namespace}

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
