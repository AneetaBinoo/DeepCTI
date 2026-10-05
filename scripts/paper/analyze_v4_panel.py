"""prereg-v4 §2 descriptive panel completion (no hypotheses): GLM-4.5-Air (D1 E2; D7 X2, X5) and
Mistral-Medium-128B (D1 E5, E9; D7 X2V), next to the existing panel.

  python scripts/paper/analyze_v4_panel.py      -> results/v4/PANEL_V4.md, results/v4/tables/panel_*.csv
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "paper"))

from figures import frame  # noqa: E402

OUT = ROOT / "results" / "v4"


def summary(df: pd.DataFrame, by: list[str]) -> pd.DataFrame:
    t = df.groupby(by).agg(n=("loss", "size"), loss=("loss", "mean"), acc=("correct", "mean"))
    der = df[df["gold"] == "affected"].groupby(by)["dangerous"].mean().rename("DER")
    return t.join(der).round(4)


def main() -> None:
    (OUT / "tables").mkdir(parents=True, exist_ok=True)
    md = ["# prereg-v4 descriptive panel completion (scripts/paper/analyze_v4_panel.py)", "",
          "Descriptive only (prereg/PREREGISTRATION_V4.md §2); not part of any hypothesis family.", ""]
    e2 = frame("d1", "E2")
    if (e2["model"] == "glm45_air").any():
        t = summary(e2[e2["system"].isin(["DC", "S3", "S2"])], ["arm", "system", "model"]).reset_index()
        t = t[t["system"].isin(["DC", "S2", "S3"])]
        t.to_csv(OUT / "tables" / "panel_d1_e2.csv", index=False)
        md += ["## D1 E2 (all models, incl. GLM-4.5-Air)", "", t.to_markdown(index=False), ""]
    x2 = frame("d7", "X2")
    if (x2["model"] == "glm45_air").any():
        t = summary(x2[x2["system"].isin(["DC", "S3", "S2"])], ["arm", "system", "model"]).reset_index()
        t.to_csv(OUT / "tables" / "panel_d7_x2.csv", index=False)
        md += ["## D7 X2 (all models, incl. GLM-4.5-Air)", "", t.to_markdown(index=False), ""]
    x5 = frame("d7", "X5")
    if (x5["model"] == "glm45_air").any():
        import json
        eps = {}
        for line in (ROOT / "data" / "drift_d7" / "test.jsonl").read_text().splitlines():
            if line.strip():
                e = json.loads(line)
                eps[e["episode_id"]] = e
        g = x5[x5["model"] == "glm45_air"]
        t = summary(g.assign(kind=g["drift"].map(lambda e: eps.get(e, {}).get("kind"))), ["kind", "system"]).reset_index()
        t.to_csv(OUT / "tables" / "panel_glm_x5.csv", index=False)
        md += ["## D7 X5 drift, GLM-4.5-Air", "", t.to_markdown(index=False), ""]
    e5 = frame("d1", "E5")
    mm = e5[e5["model"] == "mistral_medium_128b"]
    if not mm.empty:
        t = mm.groupby(["system", "policy"]).agg(n=("udar", "size"), udar=("udar", "mean")).round(4).reset_index()
        t.to_csv(OUT / "tables" / "panel_mm_e5.csv", index=False)
        md += ["## D1 E5 (D3 security), Mistral-Medium-128B: share of episodes with an unauthorized disruptive "
               "execution", "", t.to_markdown(index=False), ""]
    e9 = frame("d1", "E9")
    if not e9.empty:
        p = e9.groupby(["model", "system", "case_id"])["correct"].agg(["all", "size"]).reset_index()
        t = p.groupby(["model", "system"]).agg(cases=("all", "size"), pass_k=("all", "mean"),
                                               seeds=("size", "max")).round(4).reset_index()
        t.to_csv(OUT / "tables" / "panel_e9.csv", index=False)
        md += ["## D1 E9 pass^k (T = 0.7), all models", "", t.to_markdown(index=False), ""]
    x2v = frame("d7", "X2V")
    if (x2v["model"] == "mistral_medium_128b").any():
        t = summary(x2v, ["arm", "system", "model"]).reset_index()
        t.to_csv(OUT / "tables" / "panel_x2v.csv", index=False)
        pooled = summary(x2v, ["arm", "system"]).reset_index()
        md += ["## D7 X2V (vendor cases, fixed verifier D21), pooled over 8 models", "", pooled.to_markdown(index=False), ""]
    (OUT / "PANEL_V4.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
