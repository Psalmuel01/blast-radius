"""Read-only web UI for hydra-blast.

Deliberately a thin wrapper: it imports the existing query functions and calls
them against the existing local graph. It defines no query logic of its own,
writes nothing, and never touches HydraDB -- so it cannot affect anything
already verified in docs/hydra-parity.txt.

Stdlib only (http.server), matching the project's "no third-party runtime
dependencies" claim -- no Flask/Streamlit install required.

    python3 webui/server.py            # http://127.0.0.1:8000
    python3 webui/server.py --port 8080
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from hydra_blast.config import GRAPH_PATH, SEEDS, SEED_ADVISORIES  # noqa: E402
from hydra_blast.graph.model import Graph, adv_id, pkg_id, ver_id  # noqa: E402
from hydra_blast.queries.core import (  # noqa: E402
    blast_radius,
    live_resolution_window,
    shared_maintainer,
    version_introduced,
)
from hydra_blast.queries.typosquat import typosquat_candidates  # noqa: E402

INDEX_HTML = REPO_ROOT / "webui" / "index.html"


@lru_cache(maxsize=1)
def load_graph() -> Graph:
    """Load the local graph once and keep it in memory."""
    if not GRAPH_PATH.exists():
        raise FileNotFoundError(
            f"no graph at {GRAPH_PATH} -- run `python3 -m hydra_blast crawl` first"
        )
    return Graph.load(GRAPH_PATH)


def _seed_options(graph: Graph) -> list[dict]:
    """Seeds present in the graph, with their compromised version if known."""
    options = []
    for name in SEEDS:
        if pkg_id(name) not in graph.entities:
            continue
        advisory = SEED_ADVISORIES.get(name)
        compromised = None
        if advisory:
            node = graph.entities.get(adv_id(advisory))
            if node is not None:
                for edge in graph.out_edges(adv_id(advisory), "affects"):
                    target = graph.entities.get(edge.target)
                    if target and target.attrs.get("package") == name:
                        compromised = target.attrs.get("version")
                        break
        options.append({"package": name, "advisory": advisory, "version": compromised})
    return options


def _result_payload(result) -> dict:
    return {
        "query": result.query,
        "subject": result.subject,
        "latency_ms": round(result.latency_ms, 2),
        "meta": result.meta,
        "rows": result.rows[:500],
        "total_rows": len(result.rows),
    }


def run_query(kind: str, params: dict) -> dict:
    """Dispatch to the existing query functions. No logic lives here."""
    graph = load_graph()
    package = (params.get("package") or "").strip()
    version = (params.get("version") or "").strip()

    if kind in {"blast", "maintainer", "window", "typosquat"}:
        if not package:
            raise ValueError("package is required")
        if pkg_id(package) not in graph.entities:
            raise ValueError(
                f"'{package}' is not in this graph "
                f"({len(graph.entities):,} entities, {graph.describes()})"
            )

    if kind == "blast":
        if not version:
            raise ValueError("version is required, e.g. 4.4.2")
        return _result_payload(blast_radius(graph, package, version))

    if kind == "maintainer":
        return _result_payload(shared_maintainer(graph, package))

    if kind == "typosquat":
        return _result_payload(typosquat_candidates(graph, package))

    if kind == "window":
        if not version:
            raise ValueError("version is required, e.g. 4.4.2")
        advisory = (params.get("advisory") or "").strip()
        start = end = None
        if advisory:
            version_entity = graph.entities.get(ver_id(package, version))
            advisory_entity = graph.entities.get(adv_id(advisory))
            start = version_entity.attrs.get("published_at") if version_entity else None
            end = advisory_entity.attrs.get("published_at") if advisory_entity else None
        start = start or (params.get("start") or "").strip() or None
        end = end or (params.get("end") or "").strip() or None
        if not start:
            raise ValueError("need an advisory (to derive the window) or an explicit start")
        return _result_payload(live_resolution_window(graph, package, version, start, end))

    if kind == "introduced":
        advisory = (params.get("advisory") or "").strip()
        if not advisory:
            raise ValueError("advisory id is required, e.g. MAL-2025-46974")
        return _result_payload(version_introduced(graph, advisory))

    raise ValueError(f"unknown query '{kind}'")


class Handler(BaseHTTPRequestHandler):
    server_version = "hydra-blast-ui"

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        parsed = urlparse(self.path)
        route = parsed.path

        if route in ("/", "/index.html"):
            try:
                self._send(200, INDEX_HTML.read_bytes(), "text/html; charset=utf-8")
            except OSError:
                self._send_json(500, {"error": "index.html missing"})
            return

        if route == "/api/meta":
            try:
                graph = load_graph()
            except Exception as exc:  # noqa: BLE001 - surfaced to the page
                self._send_json(500, {"error": str(exc)})
                return
            self._send_json(200, {
                "stats": graph.stats(),
                "provenance": graph.describes(),
                "seeds": _seed_options(graph),
                "advisories": sorted(
                    {e.name for e in graph.by_namespace("Advisory")}
                )[:200],
            })
            return

        if route == "/api/query":
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            kind = params.get("kind", "")
            try:
                self._send_json(200, run_query(kind, params))
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001 - never 500 silently
                traceback.print_exc()
                self._send_json(500, {"error": f"{type(exc).__name__}: {exc}"})
            return

        self._send_json(404, {"error": "not found"})

    def log_message(self, fmt: str, *args) -> None:
        # One tidy line per request instead of the default noise.
        sys.stderr.write("  %s\n" % (fmt % args))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    try:
        graph = load_graph()
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"cannot start: {exc}")

    print(f"  graph: {len(graph.entities):,} entities / {len(graph.edges):,} edges")
    print(f"  serving http://{args.host}:{args.port}  (read-only, ctrl-c to stop)")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
