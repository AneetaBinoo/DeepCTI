"""Post-hoc / exploratory v3 analyses (prereg/DEVIATIONS.md D15, D19–D23). Not part of the pre-registered families.

  python scripts/paper/analyze_v3_posthoc.py
Outputs: results/v3/test/POSTHOC.md + tables/posthoc_*.csv
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts" / "paper"))

from analyze import cluster_bootstrap, cluster_signflip  # noqa: E402

from deepcti.eval import data  # noqa: E402
from deepcti.eval.metrics import episode_metrics  # noqa: E402

OUT = ROOT / "results" / "v3" / "test"
SIZE = {"qwen3_4b": 4, "llama31_8b": 8, "granite41_8b": 8, "qwen3_14b": 14, "mistral_small_24b": 24,
        "granite41_30b": 30, "gemma4_31b": 31, "nemotron_super_49b": 49, "mistral_medium_128b": 128}


def load(dataset: str, exp: str) -> pd.DataFrame:
    data.set_dataset(dataset)
    labels = data.load_labels("test", allow_sealed=True)
    base = ROOT / "runs" / ("" if dataset == "d1" else dataset) / "test" / exp
    rows = []
    for path in sorted(base.glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("error") or r["case_id"] not in labels:
                continue
            m = episode_metrics(r, labels)
            rows.append({"case_id": r["case_id"], "cve": r["cve"], "system": r["system"], "model": r["model"],
                         "arm": r["arm"], "loss": m["loss"], "correct": m["correct"], "dangerous": m["dangerous"],
                         "gold": m["gold"], "pred": m["pred"], "covered": m["covered"], "cost": r["cost"]})
    return pd.DataFrame(rows)


def table(df: pd.DataFrame, by: list[str]) -> pd.DataFrame:
    g = df.groupby(by)
    t = g.agg(n=("loss", "size"), acc=("correct", "mean"), coverage=("covered", "mean"), loss=("loss", "mean"),
              cost=("cost", "mean"))
    der = df[df["gold"] == "affected"].groupby(by)["dangerous"].mean().rename("DER")
    return t.join(der).round(4)


def main() -> None:
    md = ["# Post-hoc / exploratory v3 analyses (scripts/paper/analyze_v3_posthoc.py)", "",
          "Nothing here belongs to a pre-registered hypothesis family; see prereg/DEVIATIONS.md.", ""]
    # X2V: verifier fixes (D21), vendor cases
    x2v = load("d7", "X2V")
    x2 = load("d7", "X2")
    if not x2v.empty:
        x2_v = x2[x2["case_id"].isin(x2v["case_id"].unique()) & x2["system"].isin(["DC", "DCv21", "DC_noverify", "S1p"])]
        both = pd.concat([x2_v.assign(verifier="pre-registered"), x2v.assign(verifier="fixed (D21)")])
        t = table(both, ["arm", "system", "verifier"])
        t.to_csv(OUT / "tables" / "posthoc_x2v.csv")
        md += ["## X2V — vendor cases with the fixed verifier (D21) vs the pre-registered run", "", t.to_markdown(), ""]
    # X2I: Inspect AI react (S3I) vs our S3
    x2i = load("d7", "X2I")
    if not x2i.empty:
        s3 = x2[(x2["system"] == "S3") & x2["model"].isin(x2i["model"].unique()) & x2["arm"].isin(["tracker", "withheld"])]
        both = pd.concat([x2i, s3])
        t = table(both, ["arm", "model", "system"])
        piv = both.pivot_table(index=["arm", "model", "case_id"], columns="system", values="pred", aggfunc="first").dropna()
        t.to_csv(OUT / "tables" / "posthoc_s3i.csv")
        md += ["## S3I (Inspect AI react) vs S3 on D7", "", t.to_markdown(), "",
               f"Decision agreement S3I = S3: {float((piv['S3'] == piv['S3I']).mean()):.3f} (n = {len(piv)})", ""]
    # Panel scaling: S3 loss vs model size, D1 (E2) and D7 (X2); DC for reference
    for ds, exp in (("d1", "E2"), ("d7", "X2")):
        df = load(ds, exp)
        if df.empty:
            continue
        sub = df[df["system"].isin(["S3", "DC"])]
        t = sub.groupby(["arm", "system", "model"]).agg(n=("loss", "size"), loss=("loss", "mean"),
                                                        acc=("correct", "mean")).round(4).reset_index()
        t["size_b"] = t["model"].map(SIZE)
        t = t.sort_values(["arm", "system", "size_b"])
        t.to_csv(OUT / "tables" / f"posthoc_scaling_{ds}.csv", index=False)
        md += [f"## Scaling — {ds.upper()} {exp}: S3 (ReAct) and DC loss by model (incl. addendum models)", "",
               t.to_markdown(index=False), ""]
        # matched comparison: largest model's S3 vs DC on the cases it ran
        for big in ("mistral_medium_128b", "nemotron_super_49b", "granite41_30b"):
            for arm in sorted(sub["arm"].unique()):
                a = sub[(sub["model"] == big) & (sub["system"] == "S3") & (sub["arm"] == arm)].set_index("case_id")
                b = sub[(sub["system"] == "DC") & (sub["arm"] == arm)].groupby("case_id").agg(
                    loss=("loss", "mean"), cve=("cve", "first"))
                common = a.index.intersection(b.index)
                if len(common) < 30:
                    continue
                d = pd.DataFrame({"cve": b.loc[common, "cve"], "d": a.loc[common, "loss"] - b.loc[common, "loss"]})
                lo, hi, _ = cluster_bootstrap(d, lambda s: s["d"].mean(), n=2000)
                md.append(f"- {ds.upper()} {arm}: S3[{big}] − DC loss on {len(common)} matched cases: "
                          f"{d['d'].mean():.3f} [{lo:.3f}, {hi:.3f}], sign-flip p = {cluster_signflip(d):.4g}")
        md.append("")
    (OUT / "POSTHOC.md").write_text("\n".join(md))
    print(OUT / "POSTHOC.md")
    _ = np


if __name__ == "__main__":
    main()
