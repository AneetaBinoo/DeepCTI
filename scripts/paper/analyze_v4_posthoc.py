"""prereg-v4 POST HOC analyses for H18 (prereg/DEVIATIONS.md D25; docs/audit/V4_AUDIT.md C1/M1/M2).

1. corrected contrast: X6 (decoy) vs X6C (same code, no decoy), paired on (case, model, system);
2. exposure-conditioned: X6 episodes whose decoy line appeared in a tool output at or before the decision
   time, vs the same (case, model, system) in X6C;
3. decoy direction: whether the decoy version implies a different (in-range, fixed) pair than the installed one;
4. by ecosystem.
Output: results/v4/POSTHOC_V4.md, results/v4/tables/h18_posthoc.csv
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts" / "paper"))

from analyze import cluster_bootstrap, cluster_signflip  # noqa: E402

from deepcti.core import versions  # noqa: E402
from deepcti.eval import data  # noqa: E402
from deepcti.eval.metrics import episode_metrics  # noqa: E402

OUT = ROOT / "results" / "v4"
D7_MODELS = ["gemma4_31b", "granite41_30b", "granite41_8b", "llama31_8b", "mistral_medium_128b", "mistral_small_24b",
             "qwen3_14b", "qwen3_4b"]


def seen_before_decision(r: dict) -> bool:
    d = r.get("decoy")
    if not d:
        return False
    td = r.get("t_decision")
    for t in r.get("trace", []):
        out = str(t.get("output", ""))
        if (td is None or (t.get("t") is not None and t["t"] <= td)) and d["decoy_version"] in out \
                and ("See also:" in out or "Synced with" in out):
            return True
    return False


def load(exp: str) -> pd.DataFrame:
    data.set_dataset("d7")
    labels = data.load_labels("test", allow_sealed=True)
    cases = {c["case_id"]: c for c in data.load_cases("test")}
    meta = data.cve_meta()
    rows = []
    for path in sorted((ROOT / "runs" / "d7" / "test" / exp).glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("error") or r["case_id"] not in labels or r["model"] not in D7_MODELS:
                continue
            m = episode_metrics(r, labels)
            c = cases[r["case_id"]]
            d = r.get("decoy") or {}
            other = None
            if d:
                rng = (meta.get(r["cve"]) or {}).get("ranges") or []
                eco = c["ecosystem"]
                if eco == "vendor":
                    other = versions.classify(eco, d["decoy_version"], rng) != versions.classify(eco, d["true_version"], rng)
                else:
                    other = True  # deb: decoy = the fixed version on a vulnerable host
            rows.append({"case_id": r["case_id"], "cve": r["cve"], "model": r["model"], "system": r["system"],
                         "ecosystem": c["ecosystem"], "loss": m["loss"], "seen": seen_before_decision(r),
                         "other_status": other})
    df = pd.DataFrame(rows)
    assert not df.duplicated(["case_id", "model", "system"]).any(), f"duplicate records in {exp}"
    return df


def paired(a: pd.DataFrame, b: pd.DataFrame) -> dict:
    k = ["case_id", "model", "system"]
    m = a.set_index(k)[["loss", "cve"]].join(b.set_index(k)[["loss"]], rsuffix="_c", how="inner").reset_index()
    if m.empty:
        return {"n": 0}
    m["d"] = m["loss"] - m["loss_c"]
    lo, hi, _ = cluster_bootstrap(m, lambda s: s["d"].mean(), n=10000)
    return {"n": len(m), "cves": int(m["cve"].nunique()), "loss_decoy": round(float(m["loss"].mean()), 4),
            "loss_clean": round(float(m["loss_c"].mean()), 4), "diff": round(float(m["d"].mean()), 4),
            "lo": round(lo, 4), "hi": round(hi, 4), "p_signflip": round(cluster_signflip(m), 4)}


def main() -> None:
    x6, x6c = load("X6"), load("X6C")
    rows = []
    for s in ("DC", "DC_noverify", "S3"):
        a, b = x6[x6["system"] == s], x6c[x6c["system"] == s]
        rows.append({"analysis": "X6 vs X6C (same code)", "system": s, "share_seen": round(float(a["seen"].mean()), 3),
                     **paired(a, b)})
        rows.append({"analysis": "exposed before decision", "system": s, **paired(a[a["seen"]], b)})
        rows.append({"analysis": "decoy implies other status", "system": s, **paired(a[a["other_status"] == True], b)})  # noqa: E712
        for eco in sorted(a["ecosystem"].unique()):
            rows.append({"analysis": f"ecosystem={eco}", "system": s, **paired(a[a["ecosystem"] == eco], b)})
    t = pd.DataFrame(rows)
    (OUT / "tables").mkdir(parents=True, exist_ok=True)
    t.to_csv(OUT / "tables" / "h18_posthoc.csv", index=False)
    n_models = sorted(set(x6["model"]) & set(x6c["model"]))
    md = ["# prereg-v4 POST HOC — H18 corrected analyses (DEVIATIONS D25)", "",
          f"Models with both X6 and X6C: {len(n_models)} ({', '.join(n_models)}).",
          f"Share of vendor decoys implying a different status: "
          f"{x6[(x6['ecosystem'] == 'vendor') & (x6['system'] == 'DC')]['other_status'].mean():.3f}", "",
          t.to_markdown(index=False), ""]
    (OUT / "POSTHOC_V4.md").write_text("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
