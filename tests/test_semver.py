"""Semver range tests.

This is the correctness core of blast radius: if `satisfies` is wrong, the
transitive closure is wrong, and precision/recall both suffer. Cases are drawn
from the range styles that actually appear in npm manifests.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hydra_blast.graph.model import parse_version, satisfies  # noqa: E402


def check(version, spec, expected):
    got = satisfies(version, spec)
    assert got is expected, f"satisfies({version!r}, {spec!r}) == {got}, want {expected}"


def test_caret():
    check("4.4.2", "^4.0.0", True)
    check("4.4.2", "^4.4.0", True)
    check("5.0.0", "^4.0.0", False)
    check("4.3.9", "^4.4.0", False)
    # Caret on 0.x pins the minor.
    check("0.2.5", "^0.2.0", True)
    check("0.3.0", "^0.2.0", False)
    # Caret on 0.0.x pins exactly.
    check("0.0.3", "^0.0.3", True)
    check("0.0.4", "^0.0.3", False)


def test_tilde():
    check("4.4.9", "~4.4.0", True)
    check("4.5.0", "~4.4.0", False)
    check("4.4.0", "~4.4", True)


def test_exact_and_wildcards():
    check("4.4.2", "4.4.2", True)
    check("4.4.3", "4.4.2", False)
    check("4.4.2", "*", True)
    check("4.4.2", "", True)
    check("4.4.2", "4.4.x", True)
    check("4.5.0", "4.4.x", False)
    check("4.9.9", "4", True)


def test_comparators_and_unions():
    check("4.4.2", ">=4.0.0", True)
    check("3.9.9", ">=4.0.0", False)
    check("4.4.2", ">=4.0.0 <5.0.0", True)
    check("5.0.1", ">=4.0.0 <5.0.0", False)
    check("4.4.2", "^3.0.0 || ^4.0.0", True)
    check("2.0.0", "^3.0.0 || ^4.0.0", False)
    check("1.5.0", "1.2.3 - 2.3.4", True)
    check("2.4.0", "1.2.3 - 2.3.4", False)


def test_non_registry_specs_never_match():
    # These cannot resolve to a registry version; guessing here would inflate
    # the blast radius with edges that do not exist.
    for spec in (
        "git+https://github.com/x/y.git",
        "file:../local",
        "workspace:*",
        "npm:other-pkg@^1.0.0",
        "github:user/repo",
    ):
        check("4.4.2", spec, False)


def test_prerelease_excluded_unless_requested():
    check("5.0.0-beta.1", "^5.0.0", False)
    check("5.0.0-beta.1", ">=5.0.0-alpha", True)


def test_unparseable_inputs():
    assert parse_version("not-a-version") is None
    check("not-a-version", "^1.0.0", False)
    assert satisfies("1.0.0", None) is False


def test_the_real_incident():
    """debug@4.4.2 -- the actual compromised version."""
    # Typical declared ranges that WOULD have resolved to the bad version.
    for spec in ("^4.0.0", "^4.4.0", "~4.4.1", ">=4.0.0", "*", "4.x"):
        check("4.4.2", spec, True)
    # Ranges that would not.
    for spec in ("^3.0.0", "4.4.1", "~4.3.0", "<4.4.2"):
        check("4.4.2", spec, False)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} test functions passed")
