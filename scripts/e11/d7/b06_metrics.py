"""E11-D7b step 6 (POST HOC, D23): metrics and paired tests for DCv21b vs DC and DCv21b vs DCv21.

Uses d06_metrics.build / table / paired_diff UNCHANGED (same soft labels, eligibility, metric definitions, CVE-
clustered bootstrap with 2,000 resamples seed 0, CVE-clustered sign-flip with 10,000 draws seed 0, margin −0.02)
on the union of the E11-D7 inputs (DC, DCv21: results/v3/e11_d7, cached judgements reused) and the DCv21b inputs
(results/v3/e11_d7b). Pairing: (case_id, model, arm) with both systems present and usable.

Check: the DCv21 − DC primary row recomputed here must equal results/v3/e11_d7/h15.json.
Outputs (results/v3/e11_d7b): claim_scores.csv, episode_scores.csv, metrics_system.csv, metrics_system_arm.csv,
metrics_system_model_arm.csv, metrics_by_correctness.csv, metrics_v21b_by_outcome.csv, h15b_test.csv,
h15b_per_judge.csv, h15b.json, status_readings.csv.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import d06_metrics as M
import numpy as np
import pandas as pd
from common_d7 import VALIDATED, read_jsonl, write_jsonl
from common_d7b import OUT_A, OUT_B, SYSTEM_B

from deepcti.judge.d7 import eligible_d7

MARGIN = M.MARGIN  # −0.02, as H15
FILES = ("episodes.jsonl", "claims.jsonl", "judgments.jsonl", "status_judgments.jsonl")


def build_merged() -> tuple[pd.DataFrame, pd.DataFrame]:
    """d06_metrics.build() on the concatenation of the E11-D7 and E11-D7b input files."""
    with tempfile.TemporaryDirectory() as td:
        for f in FILES:
            write_jsonl(Path(td) / f, read_jsonl(OUT_A / f) + read_jsonl(OUT_B / f))
        saved, M.OUT = M.OUT, Path(td)
        try:
            return M.build()
        finally:
            M.OUT = saved


def pdiff(a: pd.DataFrame, b: pd.DataFrame, num: str, label: str, sa: str, sb: str, **extra) -> dict:
    r = M.paired_diff(a, b, num, label, **extra)
    r["a"], r["b"] = r.pop("v21"), r.pop("dc")
    return {"system_a": sa, "system_b": sb, **r}


def contrasts(cdf: pd.DataFrame, ok: pd.DataFrame, sa: str, sb: str) -> list[dict]:
    """d06_metrics.main's contrast list with (DCv21, DC) replaced by (sa, sb)."""
    pk = ok[ok.system.isin([sa, sb])].groupby(["case_id", "model", "arm"]).system.nunique()
    pairs = set(pk[pk == 2].index)
    ok = ok[ok.system.isin([sa, sb]) & pd.Series([t in pairs for t in zip(ok.case_id, ok.model, ok.arm)],
                                                    index=ok.index)]
    cdf = cdf[cdf.key.isin(set(ok.key))]
    A, B = cdf[cdf.system == sa], cdf[cdf.system == sb]
    EA, EB = ok[ok.system == sa], ok[ok.system == sb]
    P = lambda a, b, num, label, **kw: pdiff(a, b, num, label, sa, sb, **kw)  # noqa: E731
    first = ("POST HOC H15b pooled (all arms, all models)" if (sa, sb) == (SYSTEM_B, "DC") else
             "pre-registered H15 pooled (reproduction from cached judgements)" if (sa, sb) == ("DCv21", "DC") else
             "pooled (all arms, all models)")
    rows = [P(A, B, "sup", first)]
    for num in ("hal", "con", "nie"):
        rows.append(P(A, B, num, "pooled"))
    rows.append(P(EA[EA.consistent.notna()], EB[EB.consistent.notna()], "consistent", "pooled"))
    rows.append(P(A[A.has_cite], B[B.has_cite], "cite_valid", "pooled (cited claims)"))
    for arm in ("tracker", "withheld", "blind"):
        rows.append(P(A[A.arm == arm], B[B.arm == arm], "sup", f"arm={arm}", arm=arm))
        rows.append(P(EA[(EA.arm == arm) & EA.consistent.notna()], EB[(EB.arm == arm) & EB.consistent.notna()],
                      "consistent", f"arm={arm}", arm=arm))
    for m in sorted(cdf.model.unique()):
        rows.append(P(A[A.model == m], B[B.model == m], "sup", f"model={m}", model=m))
    fb = EA[EA.vs_outcome == "fallback"]
    fb_pairs = set(zip(fb.case_id, fb.model, fb.arm))
    keep = lambda d: d[[t not in fb_pairs for t in zip(d.case_id_e, d.model, d.arm)]]  # noqa: E731
    rows.append(P(keep(A), keep(B), "sup", f"pooled, pairs with a {sa} fallback note dropped"))
    rows.append(P(A[A.vs_outcome != "fallback"], B, "sup", f"pooled, {sa} fallback notes dropped (unpaired)"))
    for o in ("first_pass", "repaired", "fallback"):
        sub = set(zip(EA[EA.vs_outcome == o].case_id, EA[EA.vs_outcome == o].model, EA[EA.vs_outcome == o].arm))
        pick = lambda d: d[[t in sub for t in zip(d.case_id_e, d.model, d.arm)]]  # noqa: E731
        if len(pick(A)) and len(pick(B)):
            rows.append(P(pick(A), pick(B), "sup", f"pairs where {sa} note is {o}"))
    if sb == "DC":  # evidence sensitivities as H15: neither with [state]; both with [state]
        b_alt = B[B.sup_alt.notna()].assign(x=lambda d: d.sup_alt)
        if len(b_alt):
            rows.append(P(A.assign(x=A.sup), b_alt, "x", "sens: neither judged with [state] (DC nostate)"))
        a2 = A[A.sup_alt.notna()].assign(x=lambda d: d.sup_alt)
        if len(a2):
            rows.append(P(a2, B.assign(x=B.sup), "x", f"sens: both judged with [state] ({sa} + state)"))
    else:  # both DCv21-type: primary = neither with [state]; both with [state]
        a2, b2 = (d[d.sup_alt.notna()].assign(x=lambda x: x.sup_alt) for d in (A, B))
        if len(a2) and len(b2):
            rows.append(P(a2, b2, "x", "sens: both judged with [state]"))
    rows.append(P(A[A.fidelity_ok], B[B.fidelity_ok], "sup", "sens: claims passing extraction-fidelity check"))
    rows.append(P(A[~A.status_claim], B[~B.status_claim], "sup", "factual-detail claims only (no status word)"))
    rows.append(P(A[A.status_claim], B[B.status_claim], "sup", "status/conclusion claims only"))
    jrows = []
    for j in VALIDATED:
        col = f"sup__{j}"
        if col not in cdf:
            continue
        d = cdf[cdf[col].notna()].assign(x=lambda x: x[col])
        jrows.append({"judge": j, **pdiff(d[d.system == sa], d[d.system == sb], "x", f"judge={j}", sa, sb)})
    return rows, jrows, len(pairs), {a: sum(1 for t in pairs if t[2] == a) for a in ("tracker", "withheld", "blind")}


def status_readings(edf: pd.DataFrame) -> pd.DataFrame:
    """Post hoc (as the E11-D7 Finding): distribution of eligible-judge status readings by decided status."""
    st = read_jsonl(OUT_A / "status_judgments.jsonl") + read_jsonl(OUT_B / "status_judgments.jsonl")
    ep = edf.set_index("key")
    rows = []
    for r in st:
        if not r["asserted_status"] or r["key"] not in ep.index:
            continue
        e = ep.loc[r["key"]]
        if eligible_d7(r["judge"], e.model):
            rows.append({"system": e.system, "decided": e.status, "read": r["asserted_status"]})
    d = pd.DataFrame(rows)
    t = d.groupby(["system", "decided", "read"]).size().rename("n").reset_index()
    t["share"] = t.n / t.groupby(["system", "decided"]).n.transform("sum")
    return t


def main() -> None:
    cdf, edf = build_merged()
    n_unjudged = int((cdf.n_judges == 0).sum())
    cdf = cdf[cdf.n_judges > 0].copy()
    ok = edf[~edf.error & ~edf.replay_mismatch]
    # three-way usable triples (all three systems present) for the descriptive tables
    pk = ok.groupby(["case_id", "model", "arm"]).system.nunique()
    trip = set(pk[pk == 3].index)
    ok = ok[[t in trip for t in zip(ok.case_id, ok.model, ok.arm)]]
    cdf = cdf[cdf.key.isin(set(ok.key))]
    cdf = cdf.merge(ok[["key", "case_id"]].rename(columns={"case_id": "case_id_e"}), on="key")
    cdf.to_csv(OUT_B / "claim_scores.csv", index=False)
    ok.to_csv(OUT_B / "episode_scores.csv", index=False)

    M.table(cdf, ok, ["system", "arm"]).to_csv(OUT_B / "metrics_system_arm.csv", index=False)
    M.table(cdf, ok, ["system", "model", "arm"]).to_csv(OUT_B / "metrics_system_model_arm.csv", index=False)
    t_sys = M.table(cdf, ok, ["system"])
    t_sys.to_csv(OUT_B / "metrics_system.csv", index=False)
    M.table(cdf, ok, ["system", "correct"]).to_csv(OUT_B / "metrics_by_correctness.csv", index=False)
    vb = ok[ok.system == SYSTEM_B]
    cb = cdf[cdf.system == SYSTEM_B]
    pd.concat([M.table(cb, vb, ["vs_outcome"]), M.table(cb, vb, ["arm", "vs_outcome"])]) \
        .to_csv(OUT_B / "metrics_v21b_by_outcome.csv", index=False)
    status_readings(ok).to_csv(OUT_B / "status_readings.csv", index=False)

    allrows, alljrows, res = [], [], {}
    for sa, sb in ((SYSTEM_B, "DC"), (SYSTEM_B, "DCv21"), ("DCv21", "DC")):
        rows, jrows, n_pairs, per_arm = contrasts(cdf, ok, sa, sb)
        allrows += rows
        alljrows += jrows
        p = rows[0]
        res[f"{sa}_vs_{sb}"] = {"diff": p["diff"], "lo": p["lo"], "hi": p["hi"], "p_signflip": p["p_signflip"],
                                f"faithfulness_{sa}": p["a"], f"faithfulness_{sb}": p["b"],
                                f"n_claims_{sa}": p["n_a"], f"n_claims_{sb}": p["n_b"], "n_cves": p["cves"],
                                "n_pairs": n_pairs, "n_pairs_per_arm": per_arm,
                                "noninferior_at_margin": bool(p["lo"] > MARGIN)}
    h = pd.DataFrame(allrows)
    h.to_csv(OUT_B / "h15b_test.csv", index=False)
    pd.DataFrame(alljrows).to_csv(OUT_B / "h15b_per_judge.csv", index=False)
    # reproduction check of the pre-registered H15 result from the reused judgements
    h15 = json.loads((OUT_A / "h15.json").read_text())
    rep = res["DCv21_vs_DC"]
    res["h15_reproduced"] = bool(all(np.isclose(rep[k], h15[k]) for k in ("diff", "lo", "hi", "p_signflip"))
                                 and rep["n_claims_DCv21"] == h15["n_claims_DCv21"]
                                 and rep["n_claims_DC"] == h15["n_claims_DC"])
    res.update({"label": "POST HOC (DEVIATIONS D23); not a pre-registered test", "margin": MARGIN,
                "claims_without_eligible_validated_judge": n_unjudged,
                "share_fallback_DCv21b": float(vb.fallback.mean()),
                "n_triples_all_three_systems": len(trip)})
    (OUT_B / "h15b.json").write_text(json.dumps(res, indent=1))
    print(json.dumps(res, indent=1))
    print(h[["system_a", "system_b", "contrast", "metric", "a", "b", "diff", "lo", "hi", "p_signflip"]]
          .to_string(index=False))
    print(t_sys.T.to_string())
    assert res["h15_reproduced"], "DCv21 − DC recomputed here does not match results/v3/e11_d7/h15.json"


if __name__ == "__main__":
    main()
