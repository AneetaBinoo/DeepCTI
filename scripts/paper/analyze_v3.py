"""prereg-v3 analyses on D7 (DeepCTI-Live-X). Every number from raw logs.

  python scripts/paper/analyze_v3.py --split dev  --suffix _pilot
  python scripts/paper/analyze_v3.py --split test --allow-sealed     # only after tag prereg-v3
Outputs: results/v3/<split>/{tables/,ANALYSIS_V3.md}
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts" / "paper"))

from analyze import cluster_bootstrap, cluster_signflip, holm  # noqa: E402

from deepcti.core import versions  # noqa: E402
from deepcti.core.belnap import Belnap  # noqa: E402
from deepcti.core.decision import decide_values  # noqa: E402
from deepcti.env.host import HostEnv  # noqa: E402
from deepcti.eval import data  # noqa: E402
from deepcti.eval.metrics import episode_metrics, macro_f1  # noqa: E402

OUT = ROOT / "results" / "v3"
PRIMARY: dict[str, dict] = {}


def raw(split: str, exp: str) -> list[dict]:
    out = []
    for path in sorted((ROOT / "runs" / "d7" / split / exp).glob("*.jsonl")):
        out += [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return out


def frame(split: str, exp: str, allow: bool) -> tuple[pd.DataFrame, dict]:
    data.set_dataset("d7")
    labels = data.load_labels(split, allow_sealed=allow)
    cases = {c["case_id"]: c for c in data.load_cases(split)}
    rows, recs = [], {}
    for r in raw(split, exp):
        recs[r["key"]] = r
        if r.get("error"):
            rows.append({"key": r["key"], "system": r["system"], "model": r["model"], "error": True})
            continue
        m = episode_metrics(r, labels)
        c = cases.get(r["case_id"], {})
        rows.append({"key": r["key"], "case_id": r["case_id"], "cve": r["cve"], "ecosystem": c.get("ecosystem"),
                     "variant": r.get("variant"), "temporal_holdout": bool(c.get("temporal_holdout")),
                     "system": r["system"], "model": r["model"], "arm": r["arm"], "budget": r["budget"],
                     "drift": r.get("drift", ""), "cost": r["cost"], "t_decision": r.get("t_decision"),
                     "llm_calls": r["usage"]["calls"], "error": False, **m})
    df = pd.DataFrame(rows)
    if not df.empty and "label_world_mismatch" in df:
        bad = df["label_world_mismatch"].fillna(False).astype(bool)
        if bad.any():
            print(f"WARNING {exp}: {int(bad.sum())} label/world mismatches excluded", file=sys.stderr)
            df = df[~bad]
    return df, recs


def write(df: pd.DataFrame, name: str, split: str) -> None:
    path = OUT / split / "tables" / f"{name}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path)


def agg(df: pd.DataFrame, by: list[str]) -> pd.DataFrame:
    ok = df[~df["error"]]
    g = ok.groupby(by, dropna=False)
    t = g.agg(n=("correct", "size"), acc=("correct", "mean"), coverage=("covered", "mean"), loss=("loss", "mean"),
              invalid=("invalid", "mean"), cost=("cost", "mean"), llm_calls=("llm_calls", "mean"))
    der = ok[ok["gold"] == "affected"].groupby(by, dropna=False)["dangerous"].mean().rename("DER")
    f1 = g.apply(lambda x: macro_f1(x["gold"], x["pred"]), include_groups=False).rename("sel_macroF1")
    return t.join(der).join(f1).round(4)


def paired(df: pd.DataFrame, a: str, b: str, filt, value: str = "loss", avg_models: bool = True) -> pd.DataFrame:
    sub = df[filt & df["system"].isin([a, b]) & ~df["error"]]
    piv = sub.pivot_table(index=["case_id", "model"], columns="system", values=value).dropna()
    if a not in piv or b not in piv:
        return pd.DataFrame()
    if avg_models:
        piv = piv.groupby(level="case_id").mean()
        ids = piv.index
    else:
        ids = piv.index.get_level_values(0)
    cve = df.drop_duplicates("case_id").set_index("case_id")["cve"]
    return pd.DataFrame({"cve": [cve.get(c, c) for c in ids], "d": (piv[a] - piv[b]).to_numpy()})


def test(name: str, d: pd.DataFrame, primary: bool, **extra) -> None:
    if d.empty:
        PRIMARY[name] = {"estimate": float("nan"), "p": 1.0, "n": 0, "primary": primary, "note": "no data", **extra}
        return
    lo, hi, _ = cluster_bootstrap(d, lambda s: s["d"].mean(), n=4000)
    PRIMARY[name] = {"estimate": float(d["d"].mean()), "ci95": [lo, hi], "p": cluster_signflip(d), "n": len(d),
                     "n_cves": int(d["cve"].nunique()), "primary": primary, **extra}


# ----------------------------------------------------------------------------- X2 main
def x2(split: str, suffix: str, allow: bool, md: list[str]) -> None:
    df, recs = frame(split, "X2" + suffix, allow)
    if df.empty:
        return
    t = agg(df, ["arm", "system"])
    write(t, "x2_by_arm_system", split)
    write(agg(df, ["arm", "ecosystem", "system"]), "x2_by_ecosystem", split)
    write(agg(df, ["arm", "system", "model"]), "x2_by_model", split)
    write(agg(df, ["arm", "system", "variant"]), "x2_by_variant", split)
    write(agg(df, ["arm", "system", "temporal_holdout"]), "x2_by_holdout", split)
    md += ["## X2 — D7 main study (pooled over models)", "", t.to_markdown(), ""]
    e = agg(df, ["arm", "ecosystem", "system"]).reset_index()
    md += ["By ecosystem (loss):", "",
           e.pivot_table(index=["arm", "ecosystem"], columns="system", values="loss").round(3).to_markdown(), ""]
    # H9: withheld arm, DC vs S3 (replication of H1 on D7)
    test("H9 withheld DC−S3 loss", paired(df, "DC", "S3", df["arm"] == "withheld"), True)
    # H10: LLM role — vendor ecosystem (unstructured-only version evidence), tracker arm, DC vs S1′
    vend = (df["arm"] == "tracker") & (df["ecosystem"] == "vendor")
    dc = df[vend & (df["system"] == "DC")].groupby("case_id")["loss"].mean()
    s1p = df[vend & (df["system"] == "S1p")].groupby("case_id")["loss"].mean()
    j = pd.concat([dc.rename("DC"), s1p.rename("S1p")], axis=1).dropna()
    cve = df.drop_duplicates("case_id").set_index("case_id")["cve"]
    test("H10 vendor/tracker DC−S1′ loss (LLM extraction value)",
         pd.DataFrame({"cve": [cve.get(c) for c in j.index], "d": (j["DC"] - j["S1p"]).to_numpy()}), True)
    # H11: verified extraction — accepted-fact error rate, DC (verified) vs DC_noverify, all arms
    ext = extraction(split, recs)
    if not ext.empty:
        write(ext, "x2_extraction", split)
        s = ext.groupby(["system", "source"]).agg(proposals=("accepted", "size"), accepted=("accepted", "mean"),
                                                  accepted_error=("wrong", lambda x: float("nan")))
        rate = ext[ext["accepted"]].groupby(["system", "source"])["wrong"].mean().rename("accepted_error_rate")
        md += ["Verified extraction (facts proposed by the LLM; wrong = value not equal to any true on-disk or "
               "running version of the component):", "",
               s.drop(columns="accepted_error").join(rate).round(4).to_markdown(), ""]
        a = ext[ext["accepted"]]
        per = a.groupby(["case_id", "system"])["wrong"].mean().unstack()
        if {"DC", "DC_noverify"} <= set(per.columns):
            per = per.dropna(subset=["DC", "DC_noverify"])
            test("H11 accepted-fact error DC−DC_noverify",
                 pd.DataFrame({"cve": [cve.get(c) for c in per.index], "d": (per["DC"] - per["DC_noverify"]).to_numpy()}),
                 True)


def extraction(split: str, recs: dict) -> pd.DataFrame:
    """Accepted/rejected LLM version proposals vs the true instance versions of the host."""
    data.set_dataset("d7")
    cases = {c["case_id"]: c for c in data.load_cases(split)}
    rows = []
    truth_cache: dict[str, set] = {}
    for r in recs.values():
        if r.get("error") or r["system"] not in ("DC", "DCv21", "DC_noverify"):
            continue
        verdicts = ((r.get("extra") or {}).get("final_state") or {}).get("verdicts") or []
        if not verdicts:
            continue
        c = cases.get(r["case_id"])
        if c is None:
            continue
        if r["case_id"] not in truth_cache:
            env = HostEnv(c, data.fixture(c["host_id"]), data.cve_meta().get(c["cve"], {}), data.preconditions(), {})
            if env.is_deb():
                vs = {env.packages[b]["Version"] for b in env.src_binaries(c["src_package"])}
                vs |= {str(s["loaded_version"]) for s in env.services.values() if s.get("loaded_version")}
            else:
                vs = {str(i["version"]) for i in env.instances()} | set(env.running_versions())
            truth_cache[r["case_id"]] = vs
        truth = truth_cache[r["case_id"]]
        calls = {x["id"]: x for x in r.get("calls", [])}
        for v in verdicts:
            src = calls.get(v.get("call_id"), {}).get("source", "?")
            eco = c.get("ecosystem")
            wrong = not any(_same(eco, v.get("value", ""), t) for t in truth)
            rows.append({"case_id": r["case_id"], "system": r["system"], "model": r["model"], "source": src,
                         "accepted": bool(v.get("accepted")), "wrong": bool(wrong), "reason": v.get("reason")})
    return pd.DataFrame(rows)


def _same(eco: str, a: str, b: str) -> bool:
    try:
        return versions.compare(eco or "vendor", a, b) == 0
    except Exception:  # noqa: BLE001
        return str(a).strip() == str(b).strip()


# ----------------------------------------------------------------------------- X3 acquisition
def x3(split: str, suffix: str, allow: bool, md: list[str]) -> None:
    df, recs = frame(split, "X3" + suffix, allow)
    if df.empty:
        return
    t = df[~df["error"]].groupby(["arm", "system", "budget"]).agg(
        loss=("loss", "mean"), cost=("cost", "mean"), cost_to_decision=("t_decision", "mean"),
        acc=("correct", "mean"), cov=("covered", "mean"), n=("loss", "size")).round(3)
    write(t, "x3_acquisition", split)
    md += ["## X3 — acquisition on D7 (withheld: noisy scanners; blind: no feeds)", "", t.to_markdown(), ""]
    top = (df["budget"] == df["budget"].max()) & (df["arm"] == "withheld")
    d = paired(df, "DC", "DC_checklist", top, value="t_decision", avg_models=False)
    dl = paired(df, "DC", "DC_checklist", top, value="loss", avg_models=False)
    ub = float(np.percentile(cluster_bootstrap(dl, lambda s: s["d"].mean(), n=4000)[2], 95)) if not dl.empty else math.nan
    test("H14 withheld DC−DC_checklist cost-to-decision (max budget)", d, True,
         loss_diff=float(dl["d"].mean()) if not dl.empty else math.nan, loss_upper95=ub,
         loss_non_inferior=bool(ub < 0.05))


# ----------------------------------------------------------------------------- X5 drift (independent v2.1 test)
def x5(split: str, suffix: str, allow: bool, md: list[str]) -> None:
    df, _ = frame(split, "X5" + suffix, allow)
    if df.empty:
        return
    eps = {e["episode_id"]: e for e in data.read_jsonl(ROOT / "data" / "drift_d7" / f"{split}.jsonl")}
    df["kind"] = df["drift"].map(lambda e: eps.get(e, {}).get("kind"))
    t = df[~df["error"]].groupby(["kind", "system"]).agg(n=("loss", "size"), acc=("correct", "mean"),
                                                        loss=("loss", "mean"), DER=("dangerous", "mean"),
                                                        cost=("cost", "mean")).round(3)
    write(t, "x5_drift", split)
    md += ["## X5 — independent drift test on D7 (DC v2.1)", "", t.to_markdown(), ""]
    unr = df["kind"] == "upgrade_no_restart"
    sub = df[unr & df["system"].isin(["DCv21", "DC"]) & ~df["error"]]
    piv = sub.pivot_table(index=["drift", "model"], columns="system", values="loss").dropna()
    if {"DC", "DCv21"} <= set(piv.columns):
        cases = {c["case_id"]: c["cve"] for c in data.load_cases(split)}
        d = pd.DataFrame({"cve": [cases.get(eps[e]["case_id"]) for e in piv.index.get_level_values(0)],
                          "d": (piv["DCv21"] - piv["DC"]).to_numpy()})
        test("H13 D7 upgrade_no_restart DCv21−DC loss", d, True)


# ----------------------------------------------------------------------------- LTT (H12)
def ltt(split: str, suffix: str, allow: bool, md: list[str], arm: str = "blind", alpha_list=(0.01, 0.05, 0.1),
        delta: float = 0.1, resplits: int = 200) -> None:
    from scipy import stats as st
    frames = []
    for sp in ("calib", split):
        data.set_dataset("d7")
        labels = data.load_labels(sp, allow_sealed=allow and sp == "test")
        for r in raw(sp, "X2" + suffix):
            if r["system"] != "DC" or r["arm"] != arm or r.get("error") or r["case_id"] not in labels:
                continue
            gold = labels[r["case_id"]]["label"]["status"]
            stt = (r.get("extra") or {}).get("assessed_state", {}).get("state", {})
            vals = {}
            for atom in ("present", "in_affected_range", "fix_applied", "vuln_config_enabled"):
                a = stt.get(atom)
                vals[atom] = Belnap.N if not a else Belnap.from_support(a["kappa_pos"] + a["hints_pos"],
                                                                        a["kappa_neg"] + a["hints_neg"])
            dec = decide_values(vals, False)
            if r["status"] != "under_investigation":
                hint, score = r["status"], math.inf
            else:
                hint = dec.status
                margins = []
                for atom, pos in dec.required:
                    a = stt.get(atom) or {"kappa_pos": 0, "kappa_neg": 0, "hints_pos": 0, "hints_neg": 0}
                    agree = (a["kappa_pos"] + a["hints_pos"]) if pos else (a["kappa_neg"] + a["hints_neg"])
                    dis = (a["kappa_neg"] + a["hints_neg"]) if pos else (a["kappa_pos"] + a["hints_pos"])
                    margins.append(agree - dis)
                score = min(margins) if margins else 0
            frames.append({"split": sp, "case_id": r["case_id"], "cve": r["cve"], "model": r["model"], "gold": gold,
                           "base": r["status"], "hint": hint, "score": score})
    df = pd.DataFrame(frames)
    if df.empty or df["split"].nunique() < 2:
        md += [f"LTT ({arm}) NOT RUN: need DC {arm}-arm records on calib and {split}.", ""]
        return

    def released(s, lam):
        return np.where(s["score"] >= lam, s["hint"], "under_investigation")

    def risk(s, lam):
        return float(np.mean((s["gold"] == "affected") & np.isin(released(s, lam), ["not_affected", "fixed"])))

    def hb(rhat, n, alpha):
        def h1(a, b):
            a = min(max(a, 1e-12), 1 - 1e-12)
            return a * math.log(a / b) + (1 - a) * math.log((1 - a) / (1 - b))
        hoeff = math.exp(-n * h1(min(rhat, alpha), alpha)) if rhat < alpha else 1.0
        return min(hoeff, math.e * st.binom.cdf(math.ceil(n * rhat), n, alpha), 1.0)

    def choose(s, alpha):
        lams = sorted({x for x in s["score"].unique() if np.isfinite(x)} | {math.inf}, reverse=True)
        best = math.inf
        for lam in lams:
            if hb(risk(s, lam), len(s), alpha) <= delta:
                best = lam
            else:
                break
        return best

    rng = np.random.default_rng(20261005)
    rows, gains = [], []
    for model, g in df.groupby("model"):
        cves = g["cve"].unique()
        for alpha in alpha_list:
            real, cov = [], []
            for _ in range(resplits):
                perm = rng.permutation(cves)
                cal = set(perm[: int(0.4 * len(perm))])
                lam = choose(g[g["cve"].isin(cal)], alpha)
                ev = g[~g["cve"].isin(cal)]
                real.append(risk(ev, lam))
                cov.append(float(np.mean(released(ev, lam) != "under_investigation")))
            base_cov = float(np.mean(g["base"] != "under_investigation"))
            rows.append({"model": model, "alpha": alpha, "frac_risk_le_alpha": float(np.mean(np.array(real) <= alpha)),
                         "mean_risk": float(np.mean(real)), "mean_coverage": float(np.mean(cov)),
                         "base_coverage": base_cov})
            if alpha == 0.05:
                gains.append({"model": model, "frac": float(np.mean(np.array(real) <= alpha)),
                              "gain": float(np.mean(cov)) - base_cov})
    t = pd.DataFrame(rows).round(4)
    write(t, f"ltt_{arm}", split)
    md += [f"## LTT on D7 ({arm} arm; calib+{split} pooled, 200 CVE re-splits, δ = 0.1)", "", t.to_markdown(index=False), ""]
    if gains and arm == "blind":
        gd = pd.DataFrame(gains)
        PRIMARY["H12 LTT blind α=0.05: min frac of splits with risk ≤ α (≥ 0.9) and mean coverage gain"] = {
            "estimate": float(gd["gain"].mean()), "min_frac": float(gd["frac"].min()),
            "criterion_met": bool(gd["frac"].min() >= 0.9 and gd["gain"].mean() > 0),
            "p": 0.0 if (gd["frac"].min() >= 0.9 and gd["gain"].mean() > 0) else 1.0, "primary": True,
            "note": "criterion test (not a p-value); p encodes pass(0)/fail(1) for the Holm table"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", required=True)
    ap.add_argument("--suffix", default="")
    ap.add_argument("--allow-sealed", action="store_true")
    args = ap.parse_args()
    md = [f"# DeepCTI v3 (D7) analysis — split `{args.split}` (scripts/paper/analyze_v3.py)", ""]
    x2(args.split, args.suffix, args.allow_sealed, md)
    x3(args.split, args.suffix, args.allow_sealed, md)
    x5(args.split, args.suffix, args.allow_sealed, md)
    for arm in ("blind", "withheld"):
        ltt(args.split, args.suffix, args.allow_sealed, md, arm=arm)
    if PRIMARY:
        prim = {k: v["p"] for k, v in PRIMARY.items() if v.get("primary")}
        adj = holm(prim)
        t = pd.DataFrame([{"test": k, **{kk: vv for kk, vv in v.items() if kk != "primary"}, "p_holm": adj.get(k)}
                          for k, v in PRIMARY.items()])
        write(t, "hypotheses_v3", args.split)
        md.insert(2, "## Pre-registered hypotheses H9–H14 (Holm over the primary family)\n\n"
                  + t.round(4).to_markdown(index=False) + "\n")
    out = OUT / args.split / f"ANALYSIS_V3{args.suffix}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(md), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
