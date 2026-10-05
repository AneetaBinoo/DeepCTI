"""Independent audit (V3_AUDIT.md): D7 test results integrity and label/world consistency.

  PYTHONPATH=src .venv/bin/python tests/v3/audit_v3_integrity.py
Read-only. Recomputes world atoms for every D7 test case through HostEnv exactly as the runner builds it
(per arm) and compares with the sealed labels; then scans raw runs for duplicates, errors, budget overruns,
invalid outputs and label/world mismatches.
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from deepcti.env.host import HostEnv  # noqa: E402
from deepcti.eval import data  # noqa: E402
from deepcti.eval.metrics import episode_metrics, label_from_world  # noqa: E402

ATOMS = ("present", "in_affected_range", "fix_applied", "vuln_config_enabled", "req_config")


def world_check() -> None:
    data.set_dataset("d7")
    labels = data.load_labels("test", allow_sealed=True)
    cases = data.load_cases("test")
    bad = collections.Counter()
    ex = []
    for c in cases:
        for arm in ("tracker", "withheld", "blind"):
            env = HostEnv(c, data.fixture(c["host_id"]), data.cve_meta().get(c["cve"], {}), data.preconditions(),
                          data.advisories(c["cve"]), tracker_available=arm == "tracker",
                          scanners_available=arm != "blind")
            w = env.world_atoms()
            lab = labels[c["case_id"]]
            st = label_from_world(w)[0]
            diffs = [a for a in ATOMS if a in lab["atoms"] and bool(w.get(a)) != bool(lab["atoms"][a])]
            if st != lab["label"]["status"] or diffs:
                bad[(c["ecosystem"], arm)] += 1
                if len(ex) < 10:
                    ex.append((c["case_id"], arm, st, lab["label"]["status"], diffs))
    print(f"world/label check: {len(cases)} cases x 3 arms; mismatches: {dict(bad) or 0}")
    for e in ex:
        print("  ", e)
    print("label dist:", collections.Counter((c["ecosystem"], labels[c["case_id"]]["label"]["status"]) for c in cases))


def runs_check() -> None:
    data.set_dataset("d7")
    labels = data.load_labels("test", allow_sealed=True)
    ids = {c["case_id"]: c for c in data.load_cases("test")}
    for exp in ("X2", "X2I", "X3", "X5"):
        for p in sorted((ROOT / "runs/d7/test" / exp).glob("*.jsonl")):
            recs = [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
            keys = collections.Counter(r["key"] for r in recs)
            dup = sum(v - 1 for v in keys.values() if v > 1)
            err = sum(bool(r.get("error")) for r in recs)
            infra = sum((r.get("usage") or {}).get("infra_errors", 0) > 0 for r in recs)
            over = sum(r["cost"] > r["budget"] + 1e-9 for r in recs if not r.get("error"))
            tdec_over = sum((r.get("t_decision") or 0) > r["budget"] + 1e-9 for r in recs if not r.get("error"))
            notcase = sum(r["case_id"] not in ids for r in recs)
            inval = collections.Counter()
            mism = collections.Counter()
            for r in recs:
                if r.get("error"):
                    continue
                m = episode_metrics(r, labels)
                if m["invalid"]:
                    inval[r["system"]] += 1
                if m["label_world_mismatch"]:
                    mism[r["system"]] += 1
            print(f"{exp}/{p.stem}: n={len(recs)} dup={dup} err={err} infra={infra} cost>budget={over} "
                  f"t_dec>budget={tdec_over} unknown_case={notcase} invalid={dict(inval)} world_mismatch={dict(mism)}")


def leakage_check(n: int = 60) -> None:
    """Search prompts/traces of LLM systems for case_id, variant tags, host_id, label words tied to the case."""
    pat_tpl = r"{cid}|\bV[1-8]\b-|variant|temporal_holdout|label_provenance|D7-CVE"
    hits = collections.Counter()
    seen = collections.Counter()
    for exp, sysn in (("X2", "S3"), ("X2I", "S3I"), ("X2", "DCv21"), ("X2", "S2")):
        for p in sorted((ROOT / "runs/d7/test" / exp).glob("*.jsonl")):
            for line in p.read_text().splitlines():
                r = json.loads(line)
                if r["system"] != sysn or seen[(exp, sysn, p.stem)] >= n:
                    continue
                seen[(exp, sysn, p.stem)] += 1
                blob = json.dumps({k: v for k, v in r.items() if k in ("trace", "calls", "extra", "explanation")})
                for tok in (r["case_id"], r["host_id"], "label_provenance", "temporal_holdout", "D7-CVE", "\"V" + r["variant"][1:] + "\""):
                    if tok in blob:
                        hits[(exp, sysn, tok if tok not in (r["case_id"], r["host_id"]) else ("case_id" if tok == r["case_id"] else "host_id"))] += 1
    print("leakage token hits in traces (sampled):", dict(hits), "sampled:", sum(seen.values()))


if __name__ == "__main__":
    world_check()
    runs_check()
    leakage_check()
