"""Cached HTTP with polite backoff.

OSV documents no rate limit but asks for backoff and bounded parallelism;
ecosyste.ms and the npm registry are free community infrastructure. Responses
are cached on disk so re-running the crawl costs nothing upstream -- which
matters a lot when iterating on graph construction.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any

from ..config import CACHE_DIR, CRAWL

log = logging.getLogger(__name__)

# Retrying these is what backoff is for; anything else is a real error.
_RETRY_STATUS = {429, 500, 502, 503, 504}


def _cache_path(key: str):
    digest = hashlib.sha256(key.encode()).hexdigest()[:24]
    bucket = CACHE_DIR / digest[:2]
    bucket.mkdir(parents=True, exist_ok=True)
    return bucket / f"{digest}.json"


def _read_cache(key: str) -> Any | None:
    path = _cache_path(key)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None  # Corrupt cache entry: treat as a miss and refetch.


def _write_cache(key: str, value: Any) -> None:
    try:
        _cache_path(key).write_text(json.dumps(value))
    except OSError as exc:
        log.debug("cache write failed for %s: %s", key, exc)


def request_json(
    url: str,
    *,
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
    use_cache: bool = True,
) -> Any | None:
    """GET/POST JSON with retries. Returns None on 404 or exhausted retries."""
    cache_key = url if payload is None else f"{url}::{json.dumps(payload, sort_keys=True)}"
    if use_cache:
        cached = _read_cache(cache_key)
        if cached is not None:
            return cached

    body = json.dumps(payload).encode() if payload is not None else None
    req_headers = {"User-Agent": CRAWL.user_agent, "Accept": "application/json"}
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)

    last_error: str | None = None
    for attempt in range(CRAWL.max_retries):
        request = urllib.request.Request(url, data=body, headers=req_headers)
        try:
            with urllib.request.urlopen(request, timeout=CRAWL.request_timeout) as response:
                data = json.loads(response.read().decode())
            if use_cache:
                _write_cache(cache_key, data)
            return data
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # Genuinely absent (unpublished package, unknown advisory).
                if use_cache:
                    _write_cache(cache_key, None)
                return None
            last_error = f"HTTP {exc.code}"
            if exc.code not in _RETRY_STATUS:
                log.warning("%s -> %s (not retryable)", url, last_error)
                return None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = str(exc)

        if attempt < CRAWL.max_retries - 1:
            time.sleep(CRAWL.backoff_base * (2**attempt))

    log.warning("giving up on %s after %d attempts (%s)", url, CRAWL.max_retries, last_error)
    return None
