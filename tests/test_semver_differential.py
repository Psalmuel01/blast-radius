"""Differential test: our `satisfies()` vs npm's own `semver` package.

`satisfies()` decides the entire blast radius -- if it is wrong, the transitive
closure is wrong and every precision/recall number is meaningless. Hand-written
tests only prove the implementation agrees with *my* understanding of semver,
so this compares it against the reference implementation npm actually uses.

Requires node + npm. Skips cleanly (exit 0) if either is unavailable, so it
never breaks a run on a machine without node -- but then it proves nothing, and
says so rather than reporting a pass.

    python3 tests/test_semver_differential.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hydra_blast.graph.model import satisfies  # noqa: E402

# Versions and ranges chosen to cover the forms that actually appear in npm
# manifests, plus the edge cases most likely to be implemented wrongly:
# caret on 0.x and 0.0.x, tilde with partial versions, unions, hyphen ranges,
# prereleases, and bare/partial versions.
VERSIONS = [
    "0.0.1", "0.0.3", "0.0.4", "0.1.0", "0.2.0", "0.2.5", "0.3.0",
    "1.0.0", "1.2.3", "1.9.9", "2.0.0", "2.3.4", "3.0.0",
    "4.4.1", "4.4.2", "4.4.3", "5.0.0", "5.6.1", "10.1.0",
    "1.0.0-alpha", "5.0.0-beta.1",
]

RANGES = [
    "^4.0.0", "^4.4.0", "^4.4.2", "^1.0.0", "^0.2.0", "^0.0.3", "^0.1.0",
    "~4.4.1", "~4.4", "~1.2", "~0.2.0",
    ">=4.0.0", ">4.0.0", "<=4.4.2", "<2.0.0", "=4.4.2",
    ">=4.0.0 <5.0.0", ">=1.0.0 <2.0.0",
    "4.x", "4.4.x", "0.1.x", "1", "4", "*", "",
    "1.2.3 - 2.3.4", "0.0.1 - 0.2.0",
    "^1.0.0 || ^2.0.0", "^3.0.0 || ^4.0.0", "<1.0.0 || >=5.0.0",
    ">=5.0.0-alpha",
]


def node_available() -> bool:
    return bool(shutil.which("node") and shutil.which("npm"))


def reference_results(cases: list[tuple[str, str]]) -> list[bool] | None:
    """Run npm's semver.satisfies over every case; None if node is unavailable."""
    workdir = Path(tempfile.mkdtemp(prefix="semver-diff-"))
    try:
        install = subprocess.run(
            ["npm", "install", "semver", "--silent", "--no-fund", "--no-audit"],
            cwd=workdir, capture_output=True, text=True, timeout=180,
        )
        if install.returncode != 0:
            print(f"  npm install failed: {install.stderr.strip()[:200]}")
            return None

        script = (
            "const s=require('semver');"
            "const cases=JSON.parse(process.argv[1]);"
            "console.log(JSON.stringify(cases.map(([v,r])=>s.satisfies(v,r))));"
        )
        result = subprocess.run(
            ["node", "-e", script, json.dumps(cases)],
            cwd=workdir, capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"  node failed: {result.stderr.strip()[:200]}")
            return None
        return json.loads(result.stdout)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> int:
    cases = [(v, r) for v in VERSIONS for r in RANGES]

    if not node_available():
        print("  SKIPPED: node/npm not found -- differential test proves nothing here.")
        print("  Install node to verify satisfies() against npm's reference semver.")
        return 0

    print(f"  comparing {len(cases)} (version, range) cases against npm semver...")
    expected = reference_results(cases)
    if expected is None:
        print("  SKIPPED: could not run the reference implementation.")
        return 0

    mismatches = []
    for (version, range_spec), reference in zip(cases, expected):
        ours = satisfies(version, range_spec)
        if ours != reference:
            mismatches.append((version, range_spec, reference, ours))

    total = len(cases)
    agreed = total - len(mismatches)
    print(f"  {agreed}/{total} cases agree with npm semver")

    if mismatches:
        print(f"\n  {len(mismatches)} MISMATCH(ES):")
        for version, range_spec, reference, ours in mismatches[:25]:
            print(f"    version={version:14s} range={range_spec:18s} "
                  f"npm={str(reference):5s} ours={ours}")
        return 1

    print("  no mismatches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
