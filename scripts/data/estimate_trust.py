"""Estimate source error rates and trust classes on the DEV split only (plan §3.2), and VOI priors.

Writes config/source_profiles.yaml and config/priors.yaml. Threshold (documented, fixed before any
test run): a noisy source is TRUSTED iff its Wilson 95% upper bounds on both the false-positive and
the false-negative rate are ≤ 0.10 with n ≥ 20 in each denominator.
"""

from __future__ import annotations

import math
from pathlib import Path

import yaml
from debian.debian_support import Version

from deepcti.env.host import scanner_findings, source_name, installed
from deepcti.eval import data

ROOT = Path(__file__).resolve().parents[2]
THRESHOLD = 0.10
MIN_N = 20


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return float("nan"), 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def rate(k: int, n: int) -> dict:
    p, lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": None if n == 0 else round(p, 4), "ci95": [round(lo, 4), round(hi, 4)]}


def main() -> None:
    cases = data.load_cases("dev")
    labels = data.load_labels("dev")
    counts: dict[str, dict[str, list[int]]] = {}
    pri = {"present": [0, 0], "vuln": 0, "fixed": 0, "notaff": 0, "cfg": [0, 0], "svc": [0, 0]}
    for case in cases:
        atoms = labels[case["case_id"]]["atoms"]
        truth_a = bool(atoms.get("in_affected_range"))
        fx = data.fixture(case["host_id"])
        for name in ("trivy", "grype", "osv"):
            if name not in fx.scans:
                continue
            hits = [f for f in scanner_findings(name, fx.scans[name], case["cve"])
                    if f.get("package") == case["src_package"] or f.get("package") in case.get("binary_packages", [])]
            c = counts.setdefault(f"scanner:{name}", {"fp": [0, 0], "fn": [0, 0]})
            if truth_a:
                c["fn"][1] += 1
                c["fn"][0] += not hits
            else:
                c["fp"][1] += 1
                c["fp"][0] += bool(hits)
        # CMDB: presence and version-derived range claims
        meta = data.cve_meta().get(case["cve"], {})
        entry = (meta.get("debian") or {}).get(case["release"]) or {}
        names = {case["src_package"], *case.get("binary_packages", [])}
        sw = [x for x in fx.host.get("cmdb", {}).get("software", []) if x.get("name") in names]
        c = counts.setdefault("cmdb", {"fp": [0, 0], "fn": [0, 0]})
        truth_p = bool(atoms.get("present"))
        if truth_p:
            c["fn"][1] += 1
            c["fn"][0] += not sw
        else:
            c["fp"][1] += 1
            c["fp"][0] += bool(sw)
        if truth_p and sw and entry.get("fixed_version") not in (None, "", "0"):
            cv = counts.setdefault("cmdb_version", {"err": [0, 0]})
            claim_a = any(Version(str(x["version"])) < Version(entry["fixed_version"]) for x in sw if x.get("version"))
            cv["err"][1] += 1
            cv["err"][0] += claim_a != truth_a
        # priors
        pri["present"][1] += 1
        pri["present"][0] += truth_p
        if truth_p:
            if atoms.get("fix_applied"):
                pri["fixed"] += 1
            elif truth_a:
                pri["vuln"] += 1
            else:
                pri["notaff"] += 1
            pkgs = {n for n, st in fx.packages.items() if installed(st) and source_name(st) == case["src_package"]}
            pri["svc"][1] += 1
            pri["svc"][0] += any(s.get("package") in pkgs for s in fx.host.get("services", {}).values())
        if atoms.get("req_config") and truth_p:
            pri["cfg"][1] += 1
            pri["cfg"][0] += bool(atoms.get("vuln_config_enabled"))

    sources = {}
    for name, c in sorted(counts.items()):
        if name == "cmdb_version":
            continue
        fp, fn = rate(*c["fp"]), rate(*c["fn"])
        trusted = (c["fp"][1] >= MIN_N and c["fn"][1] >= MIN_N and fp["ci95"][1] <= THRESHOLD
                   and fn["ci95"][1] <= THRESHOLD)
        if name == "cmdb" and "cmdb_version" in counts:
            ve = rate(*counts["cmdb_version"]["err"])
            trusted = trusted and ve["n"] >= MIN_N and ve["ci95"][1] <= THRESHOLD
        else:
            ve = None
        sources[name] = {"trust": "T" if trusted else "U", "fp": fp["rate"], "fn": fn["rate"],
                         "fp_detail": fp, "fn_detail": fn, **({"version_error": ve} if ve else {})}
    n_present = max(1, pri["present"][0])
    out = {
        "estimated_on": "dev",
        "n_cases": len(cases),
        "rule": f"trusted iff Wilson95 upper bounds of FP and FN <= {THRESHOLD} with n >= {MIN_N} each "
                "(CMDB additionally: version-derived range error)",
        "sources": sources,
    }
    (ROOT / "config" / "source_profiles.yaml").write_text(yaml.safe_dump(out, sort_keys=False), encoding="utf-8")
    priors = {
        "estimated_on": "dev",
        "p_present": round(pri["present"][0] / max(1, pri["present"][1]), 4),
        "status": {k: round((pri[k] + 1) / (pri["present"][0] + 3), 4) for k in ("vuln", "fixed", "notaff")},  # Laplace
        "p_config_enabled": round((pri["cfg"][0] + 1) / (pri["cfg"][1] + 2), 4),  # Laplace
        "q_service": round((pri["svc"][0] + 1) / (pri["svc"][1] + 2), 4),
    }
    (ROOT / "config" / "priors.yaml").write_text(yaml.safe_dump(priors, sort_keys=False), encoding="utf-8")
    print(yaml.safe_dump(out, sort_keys=False))
    print(yaml.safe_dump(priors, sort_keys=False))


if __name__ == "__main__":
    main()
