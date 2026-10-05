"""Deterministic extraction of observations from tool output (plan §5.3 step 1).

Raw facts are *version facts* and direct atom observations. Version-dependent atoms
(``in_affected_range``, ``fix_applied``) are derived from a version fact and the case program
(fixed version from the trusted tracker). A derived observation inherits the trust and the
independence group of the version source; if the program itself is untrusted (compiled from
advisory text) the derived observation is downgraded to a hint (trust U).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from debian.debian_support import Version

from ..core.belnap import Observation, Source, content_hash
from ..core.decision import CONFIG, FIX, IN_RANGE, PRESENT
from ..env.host import ToolResult

# Which atoms a source class may assert (binding table; anything else is rejected).
BINDINGS: dict[str, set[str]] = {
    "pkgdb": {PRESENT, "version"},
    "fs": {"version", CONFIG},
    "proc": {"version"},
    "cmdb": {PRESENT, "version"},
    "scanner": {PRESENT, IN_RANGE},
    "change": {"change_approved", "rollback_available", "in_maintenance_window"},
}


def source_class(source: Source) -> str:
    return "scanner" if source.name.startswith("scanner:") else source.name


@dataclass
class CaseProgram:
    cve: str
    src_package: str
    binaries: list[str]
    release: str
    status: str | None = None  # tracker status
    fixed_version: str | None = None  # None: no fix (open); "0": not affected in release
    precondition: dict | None = None
    trusted: bool = False
    provenance: str = ""
    upstream_ranges: list[dict] = field(default_factory=list)  # from compiled advisories

    def known(self) -> bool:
        return self.status is not None or self.fixed_version is not None or bool(self.upstream_ranges)

    def derive(self, version: str) -> tuple[bool, bool] | None:
        """(in_affected_range, fix_applied) for an installed version, or None if undecidable."""
        try:
            v = Version(version)
        except ValueError:
            return None
        if self.status is not None or self.fixed_version is not None:
            if self.fixed_version == "0":
                return False, False
            if self.fixed_version in (None, ""):
                if self.status in ("open", "undetermined"):
                    return True, False
                return None
            fixed = Version(self.fixed_version)
            return v < fixed, v >= fixed
        if self.upstream_ranges:  # naive upstream comparison (the backport trap)
            up = Version(v.upstream_version or "0")
            for r in self.upstream_ranges:
                lo, hi = r.get("introduced"), r.get("fixed")
                try:
                    if (lo in (None, "", "0") or up >= Version(lo)) and (hi in (None, "") or up < Version(hi)):
                        return True, False
                except ValueError:
                    continue
            return False, bool(self.upstream_ranges)
        return None


def program_from_vex(result: ToolResult, case: dict) -> CaseProgram | None:
    s = result.structured
    if result.status != "ok" or not isinstance(s, dict) or "fixed_version" not in s:
        return None
    status = s.get("status")
    if status == "not-listed":
        return None
    return CaseProgram(
        cve=case["cve"], src_package=case["src_package"], binaries=list(case.get("binary_packages", [])),
        release=case["release"], status=status, fixed_version=s.get("fixed_version"),
        precondition=s.get("config_precondition"), trusted=result.source.trust == "T",
        provenance=f"vex_lookup:{result.call_id}",
    )


@dataclass(frozen=True)
class VersionFact:
    source: Source
    version: str
    package: str
    t: float
    h: str
    evidence_id: str


def obs(atom: str, positive: bool, result: ToolResult, detail: str = "", source: Source | None = None) -> Observation:
    return Observation(atom, positive, source or result.source, result.t, result.h, result.call_id, detail)


def _belongs(name: str | None, case: dict) -> bool:
    return bool(name) and (name == case["src_package"] or name in case.get("binary_packages", []))


def parse_result(result: ToolResult, case: dict, program: CaseProgram | None) -> tuple[list[Observation], list[VersionFact]]:
    """Observations and version facts from structured tool output."""
    if result.status != "ok" or result.structured is None:
        return [], []
    s, tool = result.structured, result.tool
    out: list[Observation] = []
    facts: list[VersionFact] = []
    if tool == "pkg_query":
        hits = [p for p in s.get("installed", []) if p.get("source") == case["src_package"]]
        if hits:
            out.append(obs(PRESENT, True, result, "dpkg: installed"))
            for p in hits:
                facts.append(VersionFact(result.source, p["version"], p["package"], result.t, result.h, result.call_id))
        elif s.get("query") == case["src_package"]:
            out.append(obs(PRESENT, False, result, "dpkg: no binary of source installed"))
    elif tool == "cmdb_lookup":
        sw = [x for x in s.get("software", []) or [] if _belongs(x.get("name"), case)]
        if sw:
            out.append(obs(PRESENT, True, result, "cmdb lists component"))
            for x in sw:
                if x.get("version"):
                    facts.append(VersionFact(result.source, str(x["version"]), x["name"], result.t, result.h,
                                             result.call_id))
        elif s.get("software") is not None:
            out.append(obs(PRESENT, False, result, "cmdb does not list component"))
    elif tool == "run_scanner":
        findings = [f for f in s.get("findings", []) if _belongs(f.get("package"), case)]
        if findings:
            out.append(obs(PRESENT, True, result, "scanner finding"))
            out.append(obs(IN_RANGE, True, result, "scanner finding"))
        else:
            out.append(obs(IN_RANGE, False, result, "no scanner finding"))
    elif tool == "config_get" and program and program.precondition:
        pre = program.precondition
        if s.get("key", "").lower() == str(pre.get("key", "")).lower() and s.get("files"):
            enabled = _predicate_from_matches(pre, s.get("matches", []))
            if enabled is not None:
                src = result.source if program.trusted else Source(result.source.name, "U", result.source.group)
                out.append(obs(CONFIG, enabled, result, f"config predicate {pre.get('predicate')}", source=src))
    elif tool == "request_approval":
        out.append(obs("change_approved", bool(s.get("approved")), result))
        out.append(obs("rollback_available", bool(s.get("rollback_available")), result))
        out.append(obs("in_maintenance_window", bool(s.get("maintenance_window_open")), result))
    return out, facts


def _predicate_from_matches(pre: dict, matches: list[dict]) -> bool | None:
    pred = pre.get("predicate") or {}
    kind, key = pred.get("kind"), str(pre.get("key"))
    if kind == "module_enabled":
        return any(m.get("line") == 0 for m in matches)
    values = []
    for m in matches:
        if m.get("line", 0) <= 0:
            continue
        mm = re.match(rf"^{re.escape(key)}\s*(?:=\s*|\s+|$)(.*)$", m["text"], flags=re.IGNORECASE)
        if mm:
            values.append(mm.group(1).strip().strip('"'))
    if kind == "directive_present":
        return bool(values)
    if kind == "directive_absent":
        return not values
    last = values[-1] if values else pred.get("default")
    if kind == "value_equals":
        return last is not None and str(last).lower() == str(pred.get("value")).lower()
    if kind == "value_not_equals":
        return last is None or str(last).lower() != str(pred.get("value")).lower()
    return None


def derive_from_facts(facts: list[VersionFact], program: CaseProgram | None) -> list[Observation]:
    """present / in_affected_range / fix_applied observations from version facts and the program."""
    out: list[Observation] = []
    groups: dict[tuple, list[VersionFact]] = {}
    for f in facts:
        if "version" in BINDINGS.get(source_class(f.source), set()):
            groups.setdefault((f.source, f.evidence_id, f.t), []).append(f)
    # one combined derivation per (source, tool call): in range if ANY binary is, fixed only if ALL are
    for (source, evidence_id, t), items in sorted(groups.items(), key=lambda kv: (kv[0][2], kv[0][1])):
        versions = sorted({f"{f.package}={f.version}" for f in items})
        h = content_hash(f"{items[0].h}|{versions}")
        out.append(Observation(PRESENT, True, source, t, h, evidence_id, f"versions {versions}"))
        if program is None or not program.known():
            continue
        derived = [program.derive(f.version) for f in items]
        if any(d is None for d in derived):
            continue
        a = any(d[0] for d in derived)
        x = all(d[1] for d in derived)
        src = source if program.trusted else Source(source.name, "U", source.group)
        ph = content_hash(f"{h}|{program.provenance}|{program.fixed_version}|{program.upstream_ranges}")
        detail = f"{versions} vs fixed {program.fixed_version or program.upstream_ranges}"
        out.append(Observation(IN_RANGE, a, src, t, ph, evidence_id, detail))
        out.append(Observation(FIX, x, src, t, ph, evidence_id, detail))
    return out
