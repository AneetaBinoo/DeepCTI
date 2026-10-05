"""Ecosystem-aware version comparison shared by labelling (scripts/data/label_d7.py) and the runtime.

Never compare versions as strings. Debian/Ubuntu use dpkg semantics (python-debian), PyPI uses PEP 440,
Maven uses Maven ComparableVersion semantics, vendor products use a lenient semver-like order (via `univers`).
"""

from __future__ import annotations

from functools import lru_cache

from debian.debian_support import Version as DebVersion
from univers.versions import GenericVersion, MavenVersion, PypiVersion, SemverVersion

DEB = ("deb-debian", "deb-ubuntu", "deb")


@lru_cache(maxsize=65536)
def parse(ecosystem: str, version: str):
    v = str(version).strip()
    if ecosystem in DEB:
        return DebVersion(v)
    if ecosystem == "pypi":
        return PypiVersion(v)
    if ecosystem == "maven":
        return MavenVersion(v)
    try:
        return SemverVersion(v)
    except Exception:  # noqa: BLE001 - vendor strings such as "9.0.40.0" or "2.426.3"
        return GenericVersion(v)


def compare(ecosystem: str, a: str, b: str) -> int:
    va, vb = parse(ecosystem, a), parse(ecosystem, b)
    return (va > vb) - (va < vb)


def lt(ecosystem: str, a: str, b: str) -> bool:
    return compare(ecosystem, a, b) < 0


def classify(ecosystem: str, version: str, ranges: list[dict]) -> tuple[bool, bool]:
    """(in_affected_range, fix_applied) for one installed version against affected ranges.

    A range is {"introduced": x or "0"/"" (unbounded), "fixed": y or ""/None (no fix)}, half-open [x, y).
    fix_applied: not in any range and at/above the fix of a range whose introduction it has passed.
    Versions below every introduction are neither in range nor 'fixed' (vulnerable code never present).
    """
    in_range, fixed = False, False
    for r in ranges or []:
        lo = r.get("introduced")
        hi = r.get("fixed")
        above_lo = lo in (None, "", "0") or compare(ecosystem, version, str(lo)) >= 0
        below_hi = hi in (None, "") or compare(ecosystem, version, str(hi)) < 0
        if above_lo and below_hi:
            in_range = True
        elif above_lo and not below_hi:
            fixed = True
    return in_range, (fixed and not in_range)
