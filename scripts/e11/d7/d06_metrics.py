"""E11-D7 step 6: metrics and the H15 test (DCv21 − DC analyst-note faithfulness, paired, CVE-clustered).

Outputs (results/v3/e11_d7): claim_scores.csv, episode_scores.csv, metrics_system_arm.csv,
metrics_system_model_arm.csv, metrics_system.csv, metrics_v21_by_outcome.csv, metrics_by_correctness.csv,
h15_test.csv (primary + secondary paired differences), h15_per_judge.csv, h15.json.
"""

from __future__ import annotations

import json
from collections import defaultdict

import numpy as np
import pandas as pd
from common_d7 import OUT, VALIDATED, read_jsonl

from deepcti.eval.data import load_labels
from deepcti.judge.d7 import eligible_d7
from deepcti.judge.paired import signflip_ratio_diff
from deepcti.judge.perturb import status_match
from deepcti.judge.stats import ratio_ci, ratio_diff_ci

COARSE = {"affected": "A", "not_affected": "N", "fixed": "N", "under_investigation": "U", "none": "none"}
MARGIN = -0.02  # H15 non-inferiority margin (pre-registered "≥", lower CI bound > −0.02)


def soft(labels: dict[str, str], judges: list[str], target: tuple[str, ...]) -> float:
    xs = [labels[j] in target for j in judges if j in labels]
    return float(np.mean(xs)) if xs else float("nan")


def build() -> tuple[pd.DataFrame, pd.DataFrame]:
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
    ep = {r["key"]: r for r in episodes.to_dict("records")}
    crow = []
    for c in claims:
        E = [j for j in VALIDATED if eligible_d7(j, c["model"])]
        main = lab[(c["cid"], "main")]
        e = ep[c["key"]]
        row = {"cid": c["cid"], "key": c["key"], "model": c["model"], "system": c["system"], "arm": c["arm"],
               "cve": c["cve"], "case_id": e["case_id"], "vs_outcome": e["vs_outcome"],
               "n_judges": sum(j in main for j in E), "one": 1.0,
               "sup": soft(main, E, ("supported",)), "con": soft(main, E, ("contradicted",)),
               "nie": soft(main, E, ("not_in_evidence",)), "has_cite": bool(c["call_ids"]),
               "status_claim": status_match(c["claim"]) is not None, "fidelity_ok": c["fidelity_ok"]}
        row["hal"] = row["con"] + row["nie"]
        alt = lab[(c["cid"], "dc_nostate" if c["system"] == "DC" else "v21_state")]
        row["sup_alt"] = soft(alt, E, ("supported",))  # DC: without [state]; DCv21: with [state]
        if c["call_ids"]:
            ids = set(e["call_ids"])
            exists = all(x in ids for x in c["call_ids"])
            row["cite_exists"] = float(exists)
            row["cite_valid"] = soft(lab[(c["cid"], "cited")], E, ("supported",)) if exists else 0.0
            row["cite_contra"] = soft(lab[(c["cid"], "cited")], E, ("contradicted",)) if exists else 0.0
            row["cite_n_ids"] = len(c["call_ids"])
            row["cite_n_exist"] = sum(x in ids for x in c["call_ids"])
        for j in E:
            row[f"sup__{j}"] = float(main[j] == "supported") if j in main else np.nan
        crow.append(row)
    cdf = pd.DataFrame(crow)
    labels = load_labels("test", allow_sealed=True)
    erow = []
    for e in episodes.to_dict("records"):
        E = [j for j in VALIDATED if eligible_d7(j, e["model"])]
        s = st.get(e["key"], {})
        xs = [s[j] == e["status"] for j in E if j in s]
        xc = [COARSE[s[j]] == COARSE.get(e["status"], "?") for j in E if j in s]
        gold = labels[e["case_id"]]["label"]["status"]
        erow.append({"key": e["key"], "model": e["model"], "system": e["system"], "arm": e["arm"], "cve": e["cve"],
                     "case_id": e["case_id"], "variant": e["variant"], "status": e["status"], "gold": gold,
                     "correct": e["status"] == gold, "error": bool(e["error"]),
                     "replay_mismatch": bool(e["replay_mismatch"]), "vs_outcome": e["vs_outcome"],
                     "fallback": float(e["vs_outcome"] == "fallback"), "has_expl": bool(e["explanation"].strip()),
                     "n_claims": e["n_claims"], "n_chars": e["n_chars"], "n_words": e["n_words"], "one": 1.0,
                     "consistent": float(np.mean(xs)) if xs else np.nan,
                     "consistent_coarse": float(np.mean(xc)) if xc else np.nan,
                     "asserted_none": float(np.mean([s[j] == "none" for j in E if j in s])) if xs else np.nan,
                     "no_claim": float(e["n_claims"] == 0)})
    edf = pd.DataFrame(erow)
    cdf = cdf.merge(edf[["key", "correct"]], on="key", how="left")
    return cdf, edf


def cell_metrics(cg: pd.DataFrame, eg: pd.DataFrame) -> dict:
    out = {"n_episodes": len(eg), "n_cves": eg.cve.nunique(), "n_no_claim": int(eg.no_claim.sum()),
           "n_claims": len(cg), "share_fallback": eg.fallback.mean() if len(eg) else np.nan}
    for name, num in [("faithfulness", "sup"), ("hallucination", "hal"), ("contradicted", "con"),
                      ("not_in_evidence", "nie")]:
        out[name], out[name + "_lo"], out[name + "_hi"] = ratio_ci(cg, "cve", num, "one") if len(cg) else (np.nan,) * 3
    ca = cg[cg.sup_alt.notna()]
    if len(ca):
        out["faithfulness_alt_state"], out["faithfulness_alt_state_lo"], out["faithfulness_alt_state_hi"] = ratio_ci(
            ca, "cve", "sup_alt", "one")
    ec = eg[eg.consistent.notna()]
    if len(ec):
        out["consistency"], out["consistency_lo"], out["consistency_hi"] = ratio_ci(ec, "cve", "consistent", "one")
        out["consistency_coarse"] = ec.consistent_coarse.mean()
        out["asserted_none"] = ec.asserted_none.mean()
    cc = cg[cg.has_cite] if len(cg) else cg
    out["share_claims_cited"] = cg.has_cite.mean() if len(cg) else np.nan
    out["n_cited_claims"] = len(cc)
    if len(cc):
        out["cite_id_exist"] = cc.cite_n_exist.sum() / cc.cite_n_ids.sum()
        out["citation_validity"], out["citation_validity_lo"], out["citation_validity_hi"] = ratio_ci(
            cc, "cve", "cite_valid", "one")
        out["citation_contradicted"] = cc.cite_contra.mean()
    out["claims_per_episode"] = len(cg) / max(1, len(eg))
    out["chars_mean"] = eg.n_chars.mean()
    out["words_mean"] = eg.n_words.mean()
    return out


def table(cdf: pd.DataFrame, edf: pd.DataFrame, keys: list[str]) -> pd.DataFrame:
    rows = []
    for k, eg in edf.groupby(keys):
        k = k if isinstance(k, tuple) else (k,)
        m = np.ones(len(cdf), bool)
        for col, val in zip(keys, k):
            m &= (cdf[col] == val).to_numpy()
        rows.append({**dict(zip(keys, k)), **cell_metrics(cdf[m], eg)})
    return pd.DataFrame(rows)


def paired_diff(a: pd.DataFrame, b: pd.DataFrame, num: str, label: str, **extra) -> dict:
    est, lo, hi = ratio_diff_ci(a, b, "cve", num, "one")
    _, p = signflip_ratio_diff(a, b, "cve", num, "one")
    return {"contrast": label, "metric": num, **extra, "n_a": len(a), "n_b": len(b),
            "cves": len(set(a.cve) | set(b.cve)), "v21": a[num].sum() / a["one"].sum(),
            "dc": b[num].sum() / b["one"].sum(), "diff": est, "lo": lo, "hi": hi, "p_signflip": p}


def main() -> None:
    cdf, edf = build()
    n_unjudged = int((cdf.n_judges == 0).sum())
    cdf = cdf[cdf.n_judges > 0].copy()
    cdf.to_csv(OUT / "claim_scores.csv", index=False)
    edf.to_csv(OUT / "episode_scores.csv", index=False)
    ok = edf[~edf.error & ~edf.replay_mismatch]
    # pairs: (case_id, model, arm) with both systems present and usable
    pk = ok.groupby(["case_id", "model", "arm"]).system.nunique()
    pairs = set(pk[pk == 2].index)
    ok = ok[[t in pairs for t in zip(ok.case_id, ok.model, ok.arm)]]
    cdf = cdf[cdf.key.isin(set(ok.key))]
    cdf = cdf.merge(ok[["key", "case_id"]].rename(columns={"case_id": "case_id_e"}), on="key")

    table(cdf, ok, ["system", "arm"]).to_csv(OUT / "metrics_system_arm.csv", index=False)
    table(cdf, ok, ["system", "model", "arm"]).to_csv(OUT / "metrics_system_model_arm.csv", index=False)
    t_sys = table(cdf, ok, ["system"])
    t_sys.to_csv(OUT / "metrics_system.csv", index=False)
    table(cdf, ok, ["system", "correct"]).to_csv(OUT / "metrics_by_correctness.csv", index=False)
    v = ok[ok.system == "DCv21"]
    vo = pd.concat([table(cdf[cdf.system == "DCv21"], v, ["vs_outcome"]),
                    table(cdf[cdf.system == "DCv21"], v, ["arm", "vs_outcome"])])
    vo.to_csv(OUT / "metrics_v21_by_outcome.csv", index=False)

    A, B = cdf[cdf.system == "DCv21"], cdf[cdf.system == "DC"]
    EA, EB = ok[ok.system == "DCv21"], ok[ok.system == "DC"]
    rows = [paired_diff(A, B, "sup", "PRIMARY H15 pooled (all arms, all models)")]
    for num in ("hal", "con", "nie"):
        rows.append(paired_diff(A, B, num, "pooled"))
    rows.append(paired_diff(EA[EA.consistent.notna()], EB[EB.consistent.notna()], "consistent", "pooled"))
    AC, BC = A[A.has_cite], B[B.has_cite]
    rows.append(paired_diff(AC, BC, "cite_valid", "pooled (cited claims)"))
    for arm in ("tracker", "withheld", "blind"):
        rows.append(paired_diff(A[A.arm == arm], B[B.arm == arm], "sup", f"arm={arm}", arm=arm))
        rows.append(paired_diff(EA[(EA.arm == arm) & EA.consistent.notna()],
                                EB[(EB.arm == arm) & EB.consistent.notna()], "consistent", f"arm={arm}", arm=arm))
    for m in sorted(cdf.model.unique()):
        rows.append(paired_diff(A[A.model == m], B[B.model == m], "sup", f"model={m}", model=m))
    # excluding DCv21 fallback notes: drop the whole pair (paired) and, separately, only the fallback notes
    fb_pairs = set(zip(EA[EA.vs_outcome == "fallback"].case_id, EA[EA.vs_outcome == "fallback"].model,
                       EA[EA.vs_outcome == "fallback"].arm))
    keep = lambda d: d[[t not in fb_pairs for t in zip(d.case_id_e, d.model, d.arm)]]
    rows.append(paired_diff(keep(A), keep(B), "sup", "pooled, pairs with a DCv21 fallback note dropped"))
    rows.append(paired_diff(A[A.vs_outcome != "fallback"], B, "sup", "pooled, DCv21 fallback notes dropped (unpaired)"))
    for o in ("first_pass", "repaired", "fallback"):
        sub = set(zip(EA[EA.vs_outcome == o].case_id, EA[EA.vs_outcome == o].model, EA[EA.vs_outcome == o].arm))
        pick = lambda d: d[[t in sub for t in zip(d.case_id_e, d.model, d.arm)]]
        if len(pick(A)) and len(pick(B)):
            rows.append(paired_diff(pick(A), pick(B), "sup", f"pairs where DCv21 note is {o}"))
    # evidence sensitivities: both without [state]; both with [state]
    a_alt = A.assign(x=A.sup)
    b_alt = B[B.sup_alt.notna()].assign(x=lambda d: d.sup_alt)
    if len(b_alt):
        rows.append(paired_diff(a_alt, b_alt, "x", "sens: neither judged with [state] (DC nostate)"))
    a2 = A[A.sup_alt.notna()].assign(x=lambda d: d.sup_alt)
    if len(a2):
        rows.append(paired_diff(a2, B.assign(x=B.sup), "x", "sens: both judged with [state] (DCv21 + state)"))
    a3, b3 = A[A.fidelity_ok], B[B.fidelity_ok]
    rows.append(paired_diff(a3, b3, "sup", "sens: claims passing extraction-fidelity check"))
    a4, b4 = A[~A.status_claim], B[~B.status_claim]
    rows.append(paired_diff(a4, b4, "sup", "post hoc: factual-detail claims only (no status word)"))
    a5, b5 = A[A.status_claim], B[B.status_claim]
    rows.append(paired_diff(a5, b5, "sup", "post hoc: status/conclusion claims only"))
    h = pd.DataFrame(rows)
    h.to_csv(OUT / "h15_test.csv", index=False)
    jrow = []
    for j in VALIDATED:
        col = f"sup__{j}"
        if col not in cdf:
            continue
        d = cdf[cdf[col].notna()].assign(x=lambda x: x[col])
        jrow.append({"judge": j, **paired_diff(d[d.system == "DCv21"], d[d.system == "DC"], "x", f"judge={j}")})
    pd.DataFrame(jrow).to_csv(OUT / "h15_per_judge.csv", index=False)
    prim = h.iloc[0].to_dict()
    res = {"margin": MARGIN, "diff": prim["diff"], "lo": prim["lo"], "hi": prim["hi"], "p_signflip": prim["p_signflip"],
           "faithfulness_DCv21": prim["v21"], "faithfulness_DC": prim["dc"], "n_claims_DCv21": prim["n_a"],
           "n_claims_DC": prim["n_b"], "n_cves": prim["cves"], "n_pairs": len(pairs),
           "n_pairs_per_arm": {a: sum(1 for t in pairs if t[2] == a) for a in ("tracker", "withheld", "blind")},
           "H15_holds": bool(prim["lo"] > MARGIN), "claims_without_eligible_validated_judge": n_unjudged,
           "share_fallback_DCv21": float(EA.fallback.mean())}
    (OUT / "h15.json").write_text(json.dumps(res, indent=1))
    print(json.dumps(res, indent=1))
    print(h[["contrast", "metric", "v21", "dc", "diff", "lo", "hi", "p_signflip"]].to_string(index=False))
    print(t_sys.T.to_string())


if __name__ == "__main__":
    main()
