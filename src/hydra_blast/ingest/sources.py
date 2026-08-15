"""Clients for npm, OSV, and ecosyste.ms.

Each function encodes a quirk verified against the live API rather than assumed
from documentation -- see NOTES-research.md.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Iterator

from ..config import ECOSYSTEMS_API, ECOSYSTEM, NPM_REGISTRY, OSV_API
from .http import request_json


def _quote(name: str) -> str:
    # Scoped packages (@scope/name) must keep the slash encoded for the registry.
    return urllib.parse.quote(name, safe="")


# --------------------------------------------------------------------------
# npm registry
# --------------------------------------------------------------------------

def fetch_package(name: str) -> dict | None:
    """Full npm packument: all versions, per-version deps, maintainers, times."""
    return request_json(f"{NPM_REGISTRY}/{_quote(name)}")


def iter_versions(packument: dict) -> Iterator[tuple[str, dict]]:
    versions = packument.get("versions") or {}
    if isinstance(versions, dict):
        yield from versions.items()


def version_dependencies(version_doc: dict) -> dict[str, str]:
    """Runtime dependencies for one version.

    `debug@4.4.2` -- the headline compromised version -- has *no* `dependencies`
    key at all, so this must never assume the field exists.
    """
    deps = version_doc.get("dependencies")
    return dict(deps) if isinstance(deps, dict) else {}


def package_maintainers(packument: dict) -> list[str]:
    out: list[str] = []
    for entry in packument.get("maintainers") or []:
        if isinstance(entry, dict) and entry.get("name"):
            out.append(str(entry["name"]))
        elif isinstance(entry, str):
            # Older packuments store "name <email>".
            out.append(entry.split("<")[0].strip())
    return out


def version_published_at(packument: dict, version: str) -> str | None:
    """Publish timestamp; the live-window query is built on these."""
    time_map = packument.get("time")
    if isinstance(time_map, dict):
        stamp = time_map.get(version)
        if isinstance(stamp, str):
            return stamp
    return None


# Keys in the packument `time` map that aren't versions.
_TIME_META_KEYS = {"created", "modified", "unpublished"}


def unpublished_versions(packument: dict) -> dict[str, str]:
    """Versions present in `time` but absent from `versions` -- i.e. removed.

    This matters more than it looks. npm has since unpublished the malicious
    `debug@4.4.2`: it is gone from `versions`, yet `time` still records
    `2025-09-08T13:12:39.973Z`. A naive ingester walking only `versions` drops
    the compromised release entirely and reports an empty blast radius for the
    exact incident we care about.

    The surviving `time` entry is the only registry evidence that the version
    ever existed, so we reconstruct these as first-class nodes and mark them
    `unpublished`.
    """
    time_map = packument.get("time")
    if not isinstance(time_map, dict):
        return {}
    known = set((packument.get("versions") or {}).keys())
    return {
        version: stamp
        for version, stamp in time_map.items()
        if version not in known
        and version not in _TIME_META_KEYS
        and isinstance(stamp, str)
    }


# --------------------------------------------------------------------------
# OSV
# --------------------------------------------------------------------------

def query_advisories(name: str, version: str | None = None) -> list[dict]:
    payload: dict[str, Any] = {"package": {"name": name, "ecosystem": ECOSYSTEM}}
    if version:
        payload["version"] = version
    data = request_json(f"{OSV_API}/query", payload=payload)
    return (data or {}).get("vulns") or []


def query_advisories_batch(names: list[str]) -> dict[str, list[str]]:
    """Batch advisory IDs per package (OSV allows up to 1000 per request)."""
    results: dict[str, list[str]] = {}
    for start in range(0, len(names), 1000):
        chunk = names[start : start + 1000]
        payload = {
            "queries": [{"package": {"name": n, "ecosystem": ECOSYSTEM}} for n in chunk]
        }
        data = request_json(f"{OSV_API}/querybatch", payload=payload)
        for name, entry in zip(chunk, (data or {}).get("results") or []):
            ids = [v["id"] for v in (entry or {}).get("vulns") or [] if v.get("id")]
            if ids:
                results[name] = ids
    return results


def fetch_advisory(osv_id: str) -> dict | None:
    return request_json(f"{OSV_API}/vulns/{osv_id}")


def affected_versions(advisory: dict, package_name: str) -> list[str]:
    """Explicit affected versions for a package.

    OSV expresses impact either as an explicit `versions` list or as `ranges`.
    MAL-2025-46974 uses `versions: ["4.4.2"]` with `ranges: null`, so both
    shapes have to be handled.
    """
    out: list[str] = []
    for affected in advisory.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name")
        if pkg != package_name:
            continue
        for version in affected.get("versions") or []:
            if isinstance(version, str):
                out.append(version)
    return sorted(set(out))


def affected_introduced(advisory: dict, package_name: str) -> list[tuple[str, str | None]]:
    """(introduced, fixed) pairs from OSV ranges -- powers `version-introduced`."""
    pairs: list[tuple[str, str | None]] = []
    for affected in advisory.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name")
        if pkg != package_name:
            continue
        for rng in affected.get("ranges") or []:
            introduced: str | None = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event and introduced is not None:
                    pairs.append((introduced, event["fixed"]))
                    introduced = None
            if introduced is not None:
                pairs.append((introduced, None))
    return pairs


# --------------------------------------------------------------------------
# ecosyste.ms -- reverse dependencies (npm has no reverse-dependency API)
# --------------------------------------------------------------------------

def fetch_package_stats(name: str) -> dict | None:
    return request_json(f"{ECOSYSTEMS_API}/packages/{_quote(name)}")


def fetch_dependents(name: str, limit: int) -> list[dict]:
    """Top-N dependents ranked by downloads.

    Ranking is the whole point: `chalk` has 130,085 dependents and taking them
    all is intractable, while the most-downloaded ones are where a real
    compromise actually propagates.
    """
    collected: list[dict] = []
    per_page = min(100, max(1, limit))
    page = 1
    while len(collected) < limit:
        url = (
            f"{ECOSYSTEMS_API}/packages/{_quote(name)}/dependent_packages"
            f"?per_page={per_page}&page={page}&sort=downloads&order=desc"
        )
        batch = request_json(url)
        if not isinstance(batch, list) or not batch:
            break
        collected.extend(batch)
        if len(batch) < per_page:
            break
        page += 1
    return collected[:limit]
