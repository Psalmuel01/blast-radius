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
import gzip
import json
import os
import re
import sys
import time
import urllib.request
import traceback
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from hydra_blast.config import GRAPH_PATH, SEEDS, SEED_ADVISORIES  # noqa: E402
from hydra_blast.graph.model import (  # noqa: E402
    NS_ADVISORY,
    P_AFFECTS,
    Graph,
    adv_id,
    pkg_id,
    ver_id,
)
from hydra_blast.queries.core import (  # noqa: E402
    blast_radius,
    live_resolution_window,
    shared_maintainer,
    version_introduced,
)
from hydra_blast.queries.typosquat import typosquat_candidates  # noqa: E402

INDEX_HTML = REPO_ROOT / "webui" / "index.html"
PARITY_FILE = REPO_ROOT / "docs" / "hydra-parity.txt"

# data/graph.json is ~128 MB and gitignored, so a deployed clone has no graph.
# It is published as a gzipped GitHub Release asset (7.6 MB, byte-identical on
# decompression) and fetched on first boot. Override for a fork or a new graph.
GRAPH_URL = os.environ.get(
    "HYDRA_GRAPH_URL",
    "https://github.com/Psalmuel01/blast-radius/releases/download/graph-v1/graph.json.gz",
)


def ensure_graph(url: str = GRAPH_URL) -> None:
    """Download the graph if it is not already on disk.

    Stdlib only. Streams to a temporary file and moves it into place, so an
    interrupted download cannot leave a half-written graph that then fails to
    parse on the next boot.
    """
    if GRAPH_PATH.exists():
        return
    if not url:
        raise FileNotFoundError(
            f"no graph at {GRAPH_PATH} and HYDRA_GRAPH_URL is unset -- run "
            f"`python3 -m hydra_blast crawl --hops 1 --top1 40` to build one"
        )

    GRAPH_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"  graph.json not found locally, downloading from release: {url}", flush=True)

    tmp = GRAPH_PATH.with_suffix(".json.part")
    started = time.time()
    try:
        with urllib.request.urlopen(url, timeout=300) as response:
            total = int(response.headers.get("Content-Length") or 0)
            if total:
                print(f"  ~{total / 1048576:.1f} MB compressed, decompressing on the fly",
                      flush=True)
            # Release assets are served gzipped; decompress as we stream so the
            # full 128 MB never has to sit in memory at once.
            decompressor = gzip.GzipFile(fileobj=response)
            read = 0
            with open(tmp, "wb") as out:
                while True:
                    chunk = decompressor.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
                    read += len(chunk)
                    if read % (32 << 20) < (1 << 20):
                        print(f"    {read / 1048576:.0f} MB written…", flush=True)
        tmp.replace(GRAPH_PATH)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise

    size = GRAPH_PATH.stat().st_size / 1048576
    print(f"  graph ready: {size:.1f} MB in {time.time() - started:.1f}s", flush=True)


@lru_cache(maxsize=1)
def load_graph() -> Graph:
    """Load the local graph once and keep it in memory."""
    if not GRAPH_PATH.exists():
        raise FileNotFoundError(
            f"no graph at {GRAPH_PATH} -- run `python3 -m hydra_blast crawl` first"
        )
    return Graph.load(GRAPH_PATH)


# ---------------------------------------------------------------------------
# Honesty marker: re-verify against the captured artifact rather than claim it
# ---------------------------------------------------------------------------

def _parse_parity_expectations() -> dict | None:
    """Pull the recorded blast-radius numbers out of docs/hydra-parity.txt.

    The artifact is the record of a full HydraDB read. Parsing it means the
    badge in the UI reflects an actual comparison instead of a hardcoded
    promise -- if the graph or the query drifts, the badge goes red on its own.
    """
    if not PARITY_FILE.exists():
        return None
    text = PARITY_FILE.read_text()
    versions = re.search(r"exposed_versions:\s*(\d+)", text)
    packages = re.search(r"exposed_packages:\s*(\d+)", text)
    depth = re.search(r"max_depth_reached:\s*(\d+)", text)
    subject = re.search(r"blast\s+(\S+)@(\S+)\s+--from-hydra", text)
    if not (versions and packages):
        return None
    return {
        "package": subject.group(1) if subject else "debug",
        "version": subject.group(2) if subject else "4.4.2",
        "exposed_versions": int(versions.group(1)),
        "exposed_packages": int(packages.group(1)),
        "max_depth_reached": int(depth.group(1)) if depth else None,
    }


def verify_against_parity() -> dict:
    """Run the recorded query now and compare with what the artifact recorded."""
    expected = _parse_parity_expectations()
    if expected is None:
        return {"status": "unavailable", "reason": "docs/hydra-parity.txt not found"}

    try:
        result = blast_radius(load_graph(), expected["package"], expected["version"])
    except Exception as exc:  # noqa: BLE001 - reported, never raised to the page
        return {"status": "error", "reason": f"{type(exc).__name__}: {exc}"}

    actual = {
        "exposed_versions": result.meta["exposed_versions"],
        "exposed_packages": result.meta["exposed_packages"],
        "max_depth_reached": result.meta["max_depth_reached"],
    }
    mismatches = {
        key: {"expected": expected[key], "actual": actual[key]}
        for key in actual
        if expected.get(key) is not None and expected[key] != actual[key]
    }
    return {
        "status": "match" if not mismatches else "mismatch",
        "subject": f"{expected['package']}@{expected['version']}",
        "expected": {k: expected[k] for k in actual},
        "actual": actual,
        "mismatches": mismatches,
        "latency_ms": round(result.latency_ms, 2),
    }


# ---------------------------------------------------------------------------


def _seed_options(graph: Graph) -> list[dict]:
    """Seeds present in the graph, with their compromised version if known."""
    options = []
    for name in SEEDS:
        if pkg_id(name) not in graph.entities:
            continue
        advisory = SEED_ADVISORIES.get(name)
        compromised = None
        if advisory and adv_id(advisory) in graph.entities:
            for edge in graph.out_edges(adv_id(advisory), P_AFFECTS):
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
            # Same shape as the CLI's fail-loudly message: an empty result for
            # an uncrawled package is indistinguishable from a real negative.
            raise ValueError(
                f"'{package}' is not in this graph, so any result would be "
                f"empty and misleading.\n"
                f"graph: {len(graph.entities):,} entities, built from "
                f"{graph.describes()}"
            )

    if kind == "blast":
        if not version:
            raise ValueError("blast needs a version: e.g. debug@4.4.2")
        return _result_payload(blast_radius(graph, package, version))

    if kind == "maintainer":
        return _result_payload(shared_maintainer(graph, package))

    if kind == "typosquat":
        return _result_payload(typosquat_candidates(graph, package))

    if kind == "window":
        if not version:
            raise ValueError("window needs a version: e.g. debug@4.4.2")
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
            raise ValueError("need --start or an --advisory whose window can be derived")
        return _result_payload(live_resolution_window(graph, package, version, start, end))

    if kind == "introduced":
        advisory = (params.get("advisory") or "").strip()
        if not advisory:
            raise ValueError("introduced needs an advisory id: e.g. MAL-2025-46974")
        return _result_payload(version_introduced(graph, advisory))

    raise ValueError(f"unknown query '{kind}'")


class Handler(BaseHTTPRequestHandler):
    server_version = "hydra-blast-ui"

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
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
                "advisories": sorted({e.name for e in graph.by_namespace(NS_ADVISORY)}),
            })
            return

        if route == "/api/verify":
            self._send_json(200, verify_against_parity())
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
        sys.stderr.write("  %s\n" % (fmt % args))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    # Hosts inject the port via $PORT and require binding 0.0.0.0; locally the
    # defaults keep it on loopback so the dev server is not exposed on the LAN.
    on_host = bool(os.environ.get("PORT"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
    parser.add_argument("--host", default=os.environ.get(
        "HOST", "0.0.0.0" if on_host else "127.0.0.1"))
    args = parser.parse_args()

    try:
        ensure_graph()
        graph = load_graph()
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"cannot start: {exc}")

    check = verify_against_parity()
    print(f"  graph: {len(graph.entities):,} entities / {len(graph.edges):,} edges")
    print(f"  parity check vs docs/hydra-parity.txt: {check.get('status')}")
    print(f"  serving http://{args.host}:{args.port}  (read-only, ctrl-c to stop)")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
