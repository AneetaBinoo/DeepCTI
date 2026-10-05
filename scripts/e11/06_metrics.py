"""E11 step 6: response-quality metrics per system x (model) x arm with CVE-clustered bootstrap CIs (PROTOCOL.md §6).

Outputs: claim_scores.csv, episode_scores.csv, metrics_system_arm.csv, metrics_system_model_arm.csv,
metrics_system.csv, metrics_by_correctness.csv, metrics_per_judge.csv.
"""

from __future__ import annotations

import json
from collections import defaultdict

import numpy as np
import pandas as pd
from common import OUT, read_jsonl

from deepcti.eval.data import load_labels
from deepcti.judge.llm import eligible
from deepcti.judge.perturb import status_match

COARSE = {"affected": "A", "not_affected": "N", "fixed": "N", "under_investigation": "U", "none": "none"}
from deepcti.judge.stats import ratio_ci, ratio_diff_ci


def soft(labels: dict[str, str], judges: list[str], target: tuple[str, ...]) -> float:
    xs = [labels[j] in target for j in judges if j in labels]
    return float(np.mean(xs)) if xs else float("nan")


def main() -> None:
    val = json.loads((OUT / "validated_judges.json").read_text())
    validated = val["validated"]
    episodes = pd.DataFrame(read_jsonl(OUT / "episodes.jsonl"))
    claims = read_jsonl(OUT / "claims.jsonl")
    lab: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    for r in read_jsonl(OUT / "judgments.jsonl"):
        if r["label"]:
            lab[(r["cid"], r["mode"])][r["judge"]] = r["label"]
    st: dict[str, dict[str, str]] = defaultdict(dict)
    for r in read_jsonl(OUT / "status_judgments.jsonl"):
        if r["asserted_status"]:
            st[r["key"]][r["judge"]] = r["asserted_status"]
    ep_ids = {r["key"]: set(r["call_ids"]) for r in episodes.to_dict("records")}

    crow = []
    for c in claims:
        E = [j for j in validated if eligible(j, c["model"])]
        main = lab[(c["cid"], "main")]
        row = {"cid": c["cid"], "key": c["key"], "model": c["model"], "system": c["system"], "arm": c["arm"],
               "cve": c["cve"], "n_judges": sum(j in main for j in E), "one": 1.0,
               "sup": soft(main, E, ("supported",)), "con": soft(main, E, ("contradicted",)),
               "nie": soft(main, E, ("not_in_evidence",)), "has_cite": bool(c["call_ids"]),
               "status_claim": status_match(c["claim"]) is not None}
        row["hal"] = row["con"] + row["nie"]
        if c["system"] == "DC":
            row["sup_nostate"] = soft(lab[(c["cid"], "dc_nostate")], E, ("supported",))
        if c["call_ids"]:
            exists = all(x in ep_ids[c["key"]] for x in c["call_ids"])
            row["cite_exists"] = float(exists)
            row["cite_valid"] = soft(lab[(c["cid"], "cited")], E, ("supported",)) if exists else 0.0
            row["cite_contra"] = soft(lab[(c["cid"], "cited")], E, ("contradicted",)) if exists else 0.0
            row["cite_n_ids"] = len(c["call_ids"])
            row["cite_n_exist"] = sum(x in ep_ids[c["key"]] for x in c["call_ids"])
        for j in E:  # per-judge (sensitivity)
            row[f"sup__{j}"] = float(main[j] == "supported") if j in main else np.nan
        crow.append(row)
    cdf = pd.DataFrame(crow)
    n_unjudged = int((cdf.n_judges == 0).sum())
    cdf = cdf[cdf.n_judges > 0].copy()
    cdf.to_csv(OUT / "claim_scores.csv", index=False)

    labels = load_labels("test", allow_sealed=True)
    erow = []
    for e in episodes.to_dict("records"):
        E = [j for j in validated if eligible(j, e["model"])]
        s = st.get(e["key"], {})
        xs = [s[j] == e["status"] for j in E if j in s]
        xc = [COARSE[s[j]] == COARSE.get(e["status"], "?") for j in E if j in s]
        gold = labels[e["case_id"]]["label"]["status"]
        erow.append({"key": e["key"], "model": e["model"], "system": e["system"], "arm": e["arm"], "cve": e["cve"],
                     "status": e["status"], "gold": gold, "correct": e["status"] == gold, "error": e["error"],
                     "has_expl": bool(e["explanation"].strip()), "n_claims": e["n_claims"],
                     "n_chars": e["n_chars"], "n_words": e["n_words"], "one": 1.0,
                     "consistent": float(np.mean(xs)) if xs else np.nan,
                     "consistent_coarse": float(np.mean(xc)) if xc else np.nan,
                     "asserted_none": float(np.mean([s[j] == "none" for j in E if j in s])) if xs else np.nan,
                     "no_claim": float(e["n_claims"] == 0)})
    edf = pd.DataFrame(erow)
    edf.to_csv(OUT / "episode_scores.csv", index=False)
    cdf = cdf.merge(edf[["key", "correct"]], on="key", how="left")

    def cell_metrics(cg: pd.DataFrame, eg: pd.DataFrame) -> dict:
        out = {"n_episodes": len(eg), "n_cves": eg.cve.nunique(), "n_no_claim": int(eg.no_claim.sum()),
               "n_claims": len(cg)}
        for name, num, df, den in [("faithfulness", "sup", cg, "one"), ("hallucination", "hal", cg, "one"),
                                   ("contradicted", "con", cg, "one"), ("not_in_evidence", "nie", cg, "one")]:
            out[name], out[name + "_lo"], out[name + "_hi"] = ratio_ci(df, "cve", num, den)
        ec = eg[eg.consistent.notna()]
        out["consistency"], out["consistency_lo"], out["consistency_hi"] = ratio_ci(ec, "cve", "consistent", "one")
        out["asserted_none"] = ec.asserted_none.mean()
        out["consistency_coarse"], out["consistency_coarse_lo"], out["consistency_coarse_hi"] = ratio_ci(
            ec, "cve", "consistent_coarse", "one")
        cc = cg[cg.has_cite]
        out["share_claims_cited"] = cg.has_cite.mean() if len(cg) else np.nan
        out["n_cited_claims"] = len(cc)
        if len(cc):
            out["cite_id_exist"] = cc.cite_n_exist.sum() / cc.cite_n_ids.sum()
            out["citation_validity"], out["citation_validity_lo"], out["citation_validity_hi"] = ratio_ci(
                cc, "cve", "cite_valid", "one")
            out["citation_contradicted"], out["citation_contradicted_lo"], out["citation_contradicted_hi"] = ratio_ci(
                cc, "cve", "cite_contra", "one")
        if "sup_nostate" in cg and cg.sup_nostate.notna().any():
            dn = cg[cg.sup_nostate.notna()]
            out["faithfulness_nostate"], out["faithfulness_nostate_lo"], out["faithfulness_nostate_hi"] = ratio_ci(
                dn, "cve", "sup_nostate", "one")
        out["claims_per_episode"] = len(cg) / max(1, len(eg))
        out["chars_mean"], out["chars_lo"], out["chars_hi"] = ratio_ci(eg, "cve", "n_chars", "one")
        out["words_mean"] = eg.n_words.mean()
        return out

    def table(keys: list[str]) -> pd.DataFrame:
        rows = []
        for k, eg in edf[~edf.error].groupby(keys):
            k = k if isinstance(k, tuple) else (k,)
            cg = cdf
            for col, val in zip(keys, k):
                cg = cg[cg[col] == val]
            rows.append({**dict(zip(keys, k)), **cell_metrics(cg, eg)})
        return pd.DataFrame(rows)

    t1 = table(["system", "arm"])
    t1.to_csv(OUT / "metrics_system_arm.csv", index=False)
    table(["system", "model", "arm"]).to_csv(OUT / "metrics_system_model_arm.csv", index=False)
    table(["system"]).to_csv(OUT / "metrics_system.csv", index=False)
    table(["system", "correct"]).to_csv(OUT / "metrics_by_correctness.csv", index=False)
    table(["system", "arm", "correct"]).to_csv(OUT / "metrics_by_arm_correctness.csv", index=False)
    trow = []  # post hoc: status/conclusion claims vs factual-detail claims
    for (sy, a, sc), cg in cdf.groupby(["system", "arm", "status_claim"]):
        r = {"system": sy, "arm": a, "status_claim": sc, "n_claims": len(cg)}
        for name, num in [("faithfulness", "sup"), ("contradicted", "con"), ("not_in_evidence", "nie")]:
            r[name], r[name + "_lo"], r[name + "_hi"] = ratio_ci(cg, "cve", num, "one")
        trow.append(r)
    pd.DataFrame(trow).to_csv(OUT / "metrics_by_claim_type.csv", index=False)
    drow = []  # secondary: DC minus each baseline, paired CVE-clustered bootstrap
    eok = edf[~edf.error & edf.consistent.notna()]
    for a in ("tracker", "withheld"):
        for b in ("S2", "S3", "S4", "S5"):
            r = {"arm": a, "baseline": b}
            r["d_faithfulness"], r["d_faithfulness_lo"], r["d_faithfulness_hi"] = ratio_diff_ci(
                cdf[(cdf.system == "DC") & (cdf.arm == a)], cdf[(cdf.system == b) & (cdf.arm == a)], "cve", "sup", "one")
            r["d_consistency"], r["d_consistency_lo"], r["d_consistency_hi"] = ratio_diff_ci(
                eok[(eok.system == "DC") & (eok.arm == a)], eok[(eok.system == b) & (eok.arm == a)], "cve",
                "consistent", "one")
            drow.append(r)
    pd.DataFrame(drow).to_csv(OUT / "diff_dc_vs_baselines.csv", index=False)
    jrow = []  # per-judge sensitivity of the DC-minus-baseline faithfulness difference
    for j in validated:
        col = f"sup__{j}"
        d = cdf[cdf[col].notna()].copy()
        d["x"] = d[col]
        for a in ("tracker", "withheld"):
            for b in ("S2", "S3", "S4", "S5"):
                est, lo, hi = ratio_diff_ci(d[(d.system == "DC") & (d.arm == a)], d[(d.system == b) & (d.arm == a)],
                                            "cve", "x", "one")
                jrow.append({"judge": j, "arm": a, "baseline": b, "d_faithfulness": est, "lo": lo, "hi": hi})
    pd.DataFrame(jrow).to_csv(OUT / "diff_dc_vs_baselines_per_judge.csv", index=False)
    # which tools DC's cited ids point to, by citation validity (soft score >= 0.5 = valid)
    from common import load_sampled_records
    recs = load_sampled_records()
    tool_of = {(k, c["id"]): c["tool"] for k, r in recs.items() if r["system"] == "DC" for c in r["calls"]}
    trows = []
    for c in claims:
        if c["system"] != "DC" or not c["call_ids"]:
            continue
        sc = cdf[cdf.cid == c["cid"]]
        if sc.empty:
            continue
        valid = bool(sc.iloc[0].cite_valid >= 0.5)
        for cid_ in c["call_ids"]:
            trows.append({"arm": c["arm"], "valid": valid, "tool": tool_of.get((c["key"], cid_), "missing"),
                          "status_claim": bool(sc.iloc[0].status_claim)})
    pd.DataFrame(trows).groupby(["arm", "valid", "status_claim", "tool"]).size().rename("n_cited_ids").reset_index() \
        .to_csv(OUT / "dc_citation_tools.csv", index=False)

    prow = []
    for (s, a), cg in cdf.groupby(["system", "arm"]):
        for j in validated:
            col = f"sup__{j}"
            if col not in cg:
                continue
            d = cg[cg[col].notna()]
            if len(d):
                est, lo, hi = ratio_ci(d.assign(x=d[col]), "cve", "x", "one")
                prow.append({"system": s, "arm": a, "judge": j, "n_claims": len(d), "faithfulness": est,
                             "lo": lo, "hi": hi})
    pd.DataFrame(prow).to_csv(OUT / "metrics_per_judge.csv", index=False)
    print("validated judges", validated, "claims without eligible validated judge", n_unjudged)
    cols = ["system", "arm", "n_episodes", "n_claims", "faithfulness", "faithfulness_lo", "faithfulness_hi",
            "contradicted", "not_in_evidence", "consistency", "citation_validity", "chars_mean"]
    print(t1[[c for c in cols if c in t1]].to_string(index=False))


if __name__ == "__main__":
    main()
