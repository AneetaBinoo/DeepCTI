"""Per-ecosystem trust classes and VOI priors on the D7 DEV split only (same rule as v2: trusted iff Wilson-95
upper bounds of FP and FN <= 0.10 with n >= 20 each). Writes config/source_profiles_v3.yaml and
config/priors_v3.yaml, both keyed by ecosystem.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts" / "data"))

from estimate_trust import MIN_N, THRESHOLD, rate  # noqa: E402

from deepcti.env.host import HostEnv, scanner_findings  # noqa: E402
from deepcti.eval import data  # noqa: E402


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits", default="dev")
    ap.add_argument("--suffix", default="")  # e.g. "b" -> config/source_profiles_v3b.yaml (priors untouched)
    args = ap.parse_args()
    data.set_dataset("d7")
    cases, labels = [], {}
    for sp in args.splits.split(","):
        cases += data.load_cases(sp)
        labels.update(data.load_labels(sp))
    counts: dict[str, dict] = defaultdict(lambda: defaultdict(lambda: {"fp": [0, 0], "fn": [0, 0]}))
    pri: dict[str, dict] = defaultdict(lambda: {"present": [0, 0], "vuln": 0, "fixed": 0, "notaff": 0,
                                                "cfg": [0, 0], "svc": [0, 0]})
    for case in cases:
        eco = case.get("ecosystem", "deb-debian")
        atoms = labels[case["case_id"]]["atoms"]
        truth_a, truth_p = bool(atoms.get("in_affected_range")), bool(atoms.get("present"))
        fx = data.fixture(case["host_id"])
        env = HostEnv(case, fx, data.cve_meta().get(case["cve"], {}), data.preconditions(), {})
        names = {n.lower() for n in env.names()}
        for name in ("trivy", "grype", "osv"):
            if name not in fx.scans or fx.scans[name] is None:
                continue
            hits = [f for f in scanner_findings(name, fx.scans[name], case["cve"])
                    if str(f.get("package", "")).lower() in names
                    or str(f.get("package", "")).lower().split(":")[-1] in names]
            c = counts[eco][f"scanner:{name}"]
            key, bad = ("fn", not hits) if truth_a else ("fp", bool(hits))
            c[key][1] += 1
            c[key][0] += bad
        sw = [x for x in fx.host.get("cmdb", {}).get("software", []) if str(x.get("name", "")).lower() in names]
        c = counts[eco]["cmdb"]
        key, bad = ("fn", not sw) if truth_p else ("fp", bool(sw))
        c[key][1] += 1
        c[key][0] += bad
        p = pri[eco]
        p["present"][1] += 1
        p["present"][0] += truth_p
        if truth_p:
            if atoms.get("fix_applied"):
                p["fixed"] += 1
            elif truth_a:
                p["vuln"] += 1
            else:
                p["notaff"] += 1
            p["svc"][1] += 1
            p["svc"][0] += bool(env.running_versions() or any(
                s.get("package") in env.src_binaries(case["src_package"]) for s in env.services.values()))
        if atoms.get("req_config") and truth_p:
            p["cfg"][1] += 1
            p["cfg"][0] += bool(atoms.get("vuln_config_enabled"))
    by_eco, priors = {}, {}
    for eco, srcs in sorted(counts.items()):
        out = {}
        for name, c in sorted(srcs.items()):
            fp, fn = rate(*c["fp"]), rate(*c["fn"])
            trusted = (c["fp"][1] >= MIN_N and c["fn"][1] >= MIN_N and fp["ci95"][1] <= THRESHOLD
                       and fn["ci95"][1] <= THRESHOLD)
            out[name] = {"trust": "T" if trusted else "U", "fp": fp["rate"], "fn": fn["rate"], "fp_detail": fp,
                         "fn_detail": fn}
        by_eco[eco] = out
        p = pri[eco]
        n_present = p["present"][0]
        priors[eco] = {
            "p_present": round(p["present"][0] / max(1, p["present"][1]), 4),
            "status": {k: round((p[k] + 1) / (n_present + 3), 4) for k in ("vuln", "fixed", "notaff")},
            "p_config_enabled": round((p["cfg"][0] + 1) / (p["cfg"][1] + 2), 4),
            "q_service": round((p["svc"][0] + 1) / (p["svc"][1] + 2), 4),
        }
    rule = f"trusted iff Wilson95 upper bounds of FP and FN <= {THRESHOLD} with n >= {MIN_N} each (per ecosystem)"
    (ROOT / "config" / f"source_profiles_v3{args.suffix}.yaml").write_text(
        yaml.safe_dump({"estimated_on": f"d7 {args.splits}", "rule": rule, "by_ecosystem": by_eco}, sort_keys=False))
    if not args.suffix:
        (ROOT / "config" / "priors_v3.yaml").write_text(
            yaml.safe_dump({"estimated_on": "d7 dev", "by_ecosystem": priors}, sort_keys=False))
    for eco, srcs in by_eco.items():
        print(eco, {k: (v["trust"], v["fp"], v["fn"]) for k, v in srcs.items()})
    print(yaml.safe_dump(priors, sort_keys=False))


if __name__ == "__main__":
    main()
