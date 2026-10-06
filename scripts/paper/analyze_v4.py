"""prereg-v4 confirmatory analysis (prereg/PREREGISTRATION_V4.md): H17 and H18 on D7 test, plus the H16 verdict
read from results/v4/h16/h16.json (scripts/e11/h16/run_h16.py) and descriptive panel tables.

  python scripts/paper/analyze_v4.py
Outputs: results/v4/ANALYSIS_V4.md, results/v4/tables/*.csv
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

from deepcti.eval import data  # noqa: E402
from deepcti.eval.metrics import episode_metrics  # noqa: E402

OUT = ROOT / "results" / "v4"
D7_MODELS = ["gemma4_31b", "granite41_30b", "granite41_8b", "llama31_8b", "mistral_medium_128b", "mistral_small_24b",
             "qwen3_14b", "qwen3_4b"]  # the pre-registered H17/H18 panel (GLM-4.5-Air is descriptive only)
N_BOOT = 10000
DER_MARGIN = 0.01  # H17: DER may not rise by more than this (upper 95% bound)
H18_MARGIN = 0.05  # H18: decoys may not raise DC loss by more than this (upper 95% bound)


def load(exp: str) -> pd.DataFrame:
    data.set_dataset("d7")
    labels = data.load_labels("test", allow_sealed=True)
    rows = []
    for path in sorted((ROOT / "runs" / "d7" / "test" / exp).glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("error") or r["case_id"] not in labels:
                continue
            m = episode_metrics(r, labels)
            d = r.get("decoy") or {}
            rows.append({"case_id": r["case_id"], "cve": r["cve"], "system": r["system"], "model": r["model"],
                         "arm": r["arm"], "loss": m["loss"], "dangerous": float(m["dangerous"]),
                         "affected": m["gold"] == "affected", "covered": float(m["covered"]), "cost": r["cost"],
                         "decoy": d.get("decoy_version"), "decoy_seen": _seen(r), "decoy_accepted": _accepted(r)})
    return pd.DataFrame(rows)


def _seen(r: dict) -> bool:
    d = r.get("decoy")
    if not d:
        return False
    return any(("See also:" in str(t.get("output", "")) or "Synced with" in str(t.get("output", "")))
               and d["decoy_version"] in str(t.get("output", "")) for t in r.get("trace", []))


def _accepted(r: dict) -> bool:
    d = r.get("decoy")
    if not d:
        return False
    verdicts = ((r.get("extra") or {}).get("final_state") or {}).get("verdicts") or []
    return any(v.get("accepted") and str(v.get("value")) == d["decoy_version"] for v in verdicts)


def paired(a: pd.DataFrame, b: pd.DataFrame, col: str) -> dict:
    k = ["case_id", "model"]
    m = a.set_index(k)[[col, "cve"]].join(b.set_index(k)[[col]], rsuffix="_b", how="inner").reset_index()
    m["d"] = m[col] - m[f"{col}_b"]
    lo, hi, _ = cluster_bootstrap(m, lambda s: s["d"].mean(), n=N_BOOT)
    return {"n": len(m), "cves": int(m["cve"].nunique()), "a": float(m[col].mean()), "b": float(m[f"{col}_b"].mean()),
            "diff": float(m["d"].mean()), "lo": lo, "hi": hi, "p_signflip": cluster_signflip(m)}


def main() -> None:
    (OUT / "tables").mkdir(parents=True, exist_ok=True)
    md = ["# prereg-v4 analysis (scripts/paper/analyze_v4.py)", ""]
    res = {}
    # H16 (from the E11 pipeline)
    h16p = OUT / "h16" / "h16.json"
    if h16p.exists():
        h16 = json.loads(h16p.read_text())
        res["H16"] = h16
        md += ["## H16 — DCv21b note faithfulness non-inferior to DC (fresh sample, margin −0.02)", "",
               f"- DCv21b {h16['faithfulness_DCv21b']:.3f} vs DC {h16['faithfulness_DC']:.3f}; difference "
               f"{h16['diff']:+.3f} [{h16['lo']:+.3f}, {h16['hi']:+.3f}] ({h16['n_pairs']} pairs, "
               f"{h16['n_claims_DCv21b']}/{h16['n_claims_DC']} claims, {h16['n_cves']} CVEs); "
               f"**{'supported' if h16['H16_holds'] else 'not supported'}**", ""]
    x2 = load("X2")
    x2 = x2[x2["model"].isin(D7_MODELS)]
    # H17: DCt vs DC, withheld arm
    x7 = load("X7")
    if not x7.empty:
        a = x7[(x7["system"] == "DCt") & x7["model"].isin(D7_MODELS)]
        b = x2[(x2["system"] == "DC") & (x2["arm"] == "withheld")]
        loss = paired(a, b, "loss")
        der = paired(a[a["affected"]], b[b["affected"]], "dangerous")
        cov = paired(a, b, "covered")
        ok = loss["hi"] < 0 and der["hi"] <= DER_MARGIN
        res["H17"] = {"loss": loss, "der": der, "coverage": cov, "supported": bool(ok)}
        md += ["## H17 — DCt (scanner trust estimated on dev+calib) vs DC, D7 test withheld arm", "",
               f"- loss DCt {loss['a']:.3f} vs DC {loss['b']:.3f}: {loss['diff']:+.3f} [{loss['lo']:+.3f}, "
               f"{loss['hi']:+.3f}], sign-flip p = {loss['p_signflip']:.4g} (n = {loss['n']}, {loss['cves']} CVEs)",
               f"- DER DCt {der['a']:.3f} vs DC {der['b']:.3f}: {der['diff']:+.3f} [{der['lo']:+.3f}, {der['hi']:+.3f}]"
               f" (margin {DER_MARGIN})",
               f"- coverage DCt {cov['a']:.3f} vs DC {cov['b']:.3f}",
               f"- **{'supported' if ok else 'not supported'}**", ""]
        t = pd.concat([a.assign(sys="DCt"), b[b["model"].isin(a["model"].unique())].assign(sys="DC")]).groupby(
            ["sys", "model"]).agg(n=("loss", "size"), loss=("loss", "mean"), coverage=("covered", "mean")).round(4)
        t.to_csv(OUT / "tables" / "h17_by_model.csv")
        md += [t.to_markdown(), ""]
    # H18: decoys
    x6 = load("X6")
    if not x6.empty:
        x6 = x6[x6["model"].isin(D7_MODELS)]
        b_all = x2[x2["arm"] == "tracker"]
        rows = []
        for s in ("DC", "DC_noverify", "S3"):
            p = paired(x6[x6["system"] == s], b_all[b_all["system"] == s], "loss")
            sub = x6[x6["system"] == s]
            rows.append({"system": s, **{k: p[k] for k in ("n", "cves", "a", "b", "diff", "lo", "hi", "p_signflip")},
                         "seen": float(sub["decoy_seen"].mean()), "accepted": float(sub["decoy_accepted"].mean())})
        t = pd.DataFrame(rows).rename(columns={"a": "loss_decoy", "b": "loss_clean"}).round(4)
        t.to_csv(OUT / "tables" / "h18.csv", index=False)
        dc = t[t["system"] == "DC"].iloc[0]
        ok = dc["hi"] < H18_MARGIN
        res["H18"] = {"rows": rows, "supported": bool(ok)}
        md += ["## H18 — decoy version mentions in read documents (tracker arm): DC loss non-inferior to clean", "",
               t.to_markdown(index=False), "",
               f"- DC decoy − clean {dc['diff']:+.3f} [{dc['lo']:+.3f}, {dc['hi']:+.3f}], margin {H18_MARGIN}: "
               f"**{'supported' if ok else 'not supported'}**", ""]
    (OUT / "analysis_v4.json").write_text(json.dumps(res, indent=1, default=float))
    (OUT / "ANALYSIS_V4.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
