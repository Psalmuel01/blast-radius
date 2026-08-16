"""Configuration and the verified seed set.

The seeds below are the September 2025 npm account-takeover cluster. Every entry
was confirmed present in OSV as a MAL-2025-469xx advisory before being written
here (see NOTES-research.md) -- none of these are guesses.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
CACHE_DIR = DATA_DIR / "cache"
GRAPH_PATH = DATA_DIR / "graph.json"

ECOSYSTEM = "npm"

# Seed package -> the OSV malware advisory confirming its compromise.
SEED_ADVISORIES: dict[str, str] = {
    "debug": "MAL-2025-46974",
    "chalk": "MAL-2025-46969",
    "ansi-styles": "MAL-2025-46967",
    "color-convert": "MAL-2025-46971",
    "supports-color": "MAL-2025-46981",
    "strip-ansi": "MAL-2025-46980",
    "wrap-ansi": "MAL-2025-46983",
    "chalk-template": "MAL-2025-46970",
    "is-arrayish": "MAL-2025-46977",
    "error-ex": "MAL-2025-46975",
    "simple-swizzle": "MAL-2025-46978",
    "color-name": "MAL-2025-46972",
    "backslash": "MAL-2025-46968",
    "ansi-regex": "MAL-2025-46966",
    "slice-ansi": "MAL-2025-46979",
    "color-string": "MAL-2025-46973",
    "has-ansi": "MAL-2025-46976",
}

SEEDS: list[str] = sorted(SEED_ADVISORIES)


@dataclass(frozen=True)
class CrawlConfig:
    """Bounded, impact-ranked crawl.

    Measured reality: 5 of the 17 seeds have 183,768 direct dependents between
    them (chalk alone has 130,085). An unbounded 2-3 hop BFS -- which the scope
    doc suggests -- reaches millions of nodes and cannot finish in the build
    window. Instead each hop keeps the top-K dependents *ranked by downloads*,
    which preserves the packages where a real compromise does the most damage.

    These are the knobs to turn if the eval shows recall loss.
    """

    max_hops: int = 2
    top_dependents_hop1: int = 300
    top_dependents_deeper: int = 40
    max_packages: int = 25_000
    request_timeout: float = 30.0
    max_retries: int = 4
    backoff_base: float = 0.8
    user_agent: str = "hydra-blast-radius/0.1 (Hack Hydra 2026; +https://github.com/)"


CRAWL = CrawlConfig()

NPM_REGISTRY = "https://registry.npmjs.org"
OSV_API = "https://api.osv.dev/v1"
ECOSYSTEMS_API = "https://packages.ecosyste.ms/api/v1/registries/npmjs.org"

HYDRA_BASE_URL = "https://api.hydradb.com"
HYDRA_API_VERSION = "2"


def _load_dotenv(path=REPO_ROOT / ".env") -> None:
    """Read .env into the environment if it hasn't been exported already.

    A .env file is inert on its own -- the shell has to source it. Requiring
    `set -a && . ./.env` before every command is an easy thing to forget and
    surfaces as a confusing "API key is not set" even though the key is right
    there in the file. Real environment variables always win, so exporting for
    CI or a one-off override still overrides this.
    """
    if not path.exists():
        return
    try:
        content = path.read_text()
    except OSError:
        return
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in os.environ:
            continue  # already set in the real environment: leave it alone
        value = value.strip().strip('"').strip("'")
        if value:
            os.environ[key] = value


_load_dotenv()


def hydra_api_key() -> str | None:
    return os.environ.get("HYDRA_DB_API_KEY") or None


def hydra_database() -> str:
    return os.environ.get("HYDRA_DB_DATABASE", "hydra_blast_radius")


def github_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or None
