"""Typosquat candidate detection.

Deliberately a heuristic (the scope calls for exactly that): edit distance over
package names, filtered by the signals that separate a squat from a legitimate
neighbour -- low downloads, recent registration, no release history.

Name similarity alone is far too noisy: `chalk`/`chalks`, `debug`/`debag` and
hundreds of legitimate scoped forks all sit within edit distance 2.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from ..graph.model import Graph, NS_PACKAGE
from .core import QueryResult


def levenshtein(a: str, b: str, *, cap: int = 3) -> int:
    """Edit distance with early exit once `cap` is exceeded."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if len(a) > len(b):
        a, b = b, a

    previous = list(range(len(a) + 1))
    for j, cb in enumerate(b, start=1):
        current = [j]
        best = j
        for i, ca in enumerate(a, start=1):
            cost = 0 if ca == cb else 1
            value = min(previous[i] + 1, current[i - 1] + 1, previous[i - 1] + cost)
            current.append(value)
            best = min(best, value)
        previous = current
        if best > cap:
            return cap + 1
    return previous[-1]


def _strip_scope(name: str) -> str:
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def _is_confusable(a: str, b: str) -> tuple[bool, str | None]:
    """Structural squat patterns that edit distance alone misses/overcounts."""
    if a == b:
        return False, None
    # Separator swap: node-fetch vs node_fetch vs nodefetch
    norm_a = a.replace("-", "").replace("_", "").replace(".", "")
    norm_b = b.replace("-", "").replace("_", "").replace(".", "")
    if norm_a == norm_b:
        return True, "separator-variant"
    # Common digit/letter homoglyphs
    table = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e"})
    if norm_a.translate(table) == norm_b.translate(table):
        return True, "homoglyph"
    # Prefix/suffix padding: "chalk" vs "chalk-js", "node-chalk"
    for pad in ("js", "node", "npm", "lib", "cli", "core"):
        for cand in (f"{b}-{pad}", f"{pad}-{b}", f"{b}{pad}", f"{pad}{b}"):
            if a == cand:
                return True, "padded-name"
    return False, None


def typosquat_candidates(
    graph: Graph,
    package: str,
    *,
    max_distance: int = 2,
    downloads_ratio: float = 0.01,
    recent_days: int = 365,
    now: datetime | None = None,
) -> QueryResult:
    """Plausible typosquats of `package` among packages in the graph.

    Scoring combines name proximity with the risk signals: a near-identical name
    is only interesting when the package is also obscure and/or new.
    """
    started = time.perf_counter() * 1000.0
    now = now or datetime.now(timezone.utc)

    target_entity = graph.entities.get(f"pkg:{package}")
    target_downloads = (target_entity.attrs.get("downloads") if target_entity else None) or 0
    bare_target = _strip_scope(package)

    rows = []
    for entity in graph.by_namespace(NS_PACKAGE):
        name = entity.name
        if name == package:
            continue
        bare = _strip_scope(name)

        distance = levenshtein(bare, bare_target, cap=max_distance)
        confusable, pattern = _is_confusable(bare, bare_target)
        if distance > max_distance and not confusable:
            continue

        downloads = entity.attrs.get("downloads") or 0
        # A hugely popular near-name is a legitimate neighbour, not a squat.
        suspicious_downloads = (
            target_downloads == 0 or downloads < target_downloads * downloads_ratio
        )

        first_release = entity.attrs.get("first_release")
        age_days = None
        if first_release:
            try:
                published = datetime.fromisoformat(first_release.replace("Z", "+00:00"))
                age_days = (now - published).days
            except ValueError:
                age_days = None
        recent = age_days is not None and age_days <= recent_days

        if not suspicious_downloads and not recent:
            continue

        # Score: closer name + lower downloads + newer = more suspicious.
        score = 0.0
        score += max(0.0, 1.0 - (distance / (max_distance + 1))) * 0.5
        if confusable:
            score += 0.25
        if suspicious_downloads:
            score += 0.15
        if recent:
            score += 0.10

        rows.append(
            {
                "package": name,
                "edit_distance": distance if distance <= max_distance else None,
                "pattern": pattern,
                "downloads": downloads,
                "age_days": age_days,
                "score": round(min(score, 1.0), 3),
            }
        )

    rows.sort(key=lambda r: (-r["score"], r["downloads"], r["package"]))
    return QueryResult(
        query="typosquat_candidates",
        subject=package,
        rows=rows,
        latency_ms=time.perf_counter() * 1000.0 - started,
        meta={
            "target_downloads": target_downloads,
            "candidates": len(rows),
            "max_distance": max_distance,
        },
    )
