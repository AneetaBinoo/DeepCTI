"""Independent recomputation of prereg-v3 H9-H14 on D7 test (auditor script, V3_AUDIT.md).

  PYTHONPATH=src .venv/bin/python tests/v3/recompute_hypotheses_v3.py
Own loading, loss, pairing, CVE-clustered sign-flip (two- and one-sided, 20000 flips, seed 7) and bootstrap
(5000, seed 11); own LTT loop (seed 99). Uses sealed labels (tag prereg-v3 exists). Read-only.
"""
from __future__ import annotations

import collections
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from deepcti.core import versions  # noqa: E402
from deepcti.core.belnap import Belnap  # noqa: E402
from deepcti.core.decision import decide_values, decide_world  # noqa: E402
from deepcti.env.host import HostEnv  # noqa: E402
from deepcti.eval import data  # noqa: E402

L = {("affected", "affected"): 0, ("affected", "not_affected"): 10, ("affected", "fixed"): 10,
     ("not_affected", "affected"): 1, ("not_affected", "not_affected"): 0, ("not_affected", "fixed"): .2,
     ("fixed", "affected"): 1, ("fixed", "not_affected"): .2, ("fixed", "fixed"): 0}
DROP = ("trace", "calls", "history")


def load(split: str, exp: str, keep_calls=False):
    out = []
    for p in sorted((ROOT / "runs/d7" / split / exp).glob("*.jsonl")):
        for line in p.open():
            r = json.loads(line)
            if not keep_calls:
                for k in DROP:
                    r.pop(k, None)
            out.append(r)
    return out


def loss(gold, r):
    pred = r.get("status") if r.get("parse_ok") else None
    if pred not in ("affected", "not_affected", "fixed"):
        return 0.5  # UI and invalid
    return L[(gold, pred)]


def signflip(d: pd.DataFrame, n=20000, seed=7):
    per = d.groupby("cve")["d"].mean().to_numpy()
    rng = np.random.default_rng(seed)
    null = (rng.choice([-1.0, 1.0], size=(n, len(per))) * per).mean(axis=1)
    obs = per.mean()
    two = (1 + np.sum(np.abs(null) >= abs(obs) - 1e-12)) / (n + 1)
    one = (1 + np.sum(null <= obs + 1e-12)) / (n + 1)  # H: d < 0
    return float(two), float(one)


def boot(d: pd.DataFrame, n=5000, seed=11, q=(2.5, 97.5)):
    g = {c: x["d"].to_numpy() for c, x in d.groupby("cve")}
    keys = list(g)
    rng = np.random.default_rng(seed)
    st = []
    for _ in range(n):
        pick = rng.choice(len(keys), len(keys))
        st.append(np.concatenate([g[keys[i]] for i in pick]).mean())
    return [float(np.percentile(st, x)) for x in q]


def report(name, d):
    two, one = signflip(d)
    lo, hi = boot(d)
    print(f"{name}: est={d['d'].mean():.4f} CI95=[{lo:.4f},{hi:.4f}] p2={two:.5f} p1={one:.5f} n={len(d)} "
          f"cves={d['cve'].nunique()}")
    return {"test": name, "estimate": d["d"].mean(), "p_two": two, "p_one": one, "n": len(d),
            "n_cves": d["cve"].nunique()}


def main():
    data.set_dataset("d7")
    lab = data.load_labels("test", allow_sealed=True)
    cases = {c["case_id"]: c for c in data.load_cases("test")}
    res = []
    # ---------------- X2
    x2 = load("test", "X2", keep_calls=True)
    rows = [{"case": r["case_id"], "cve": r["cve"], "eco": cases[r["case_id"]]["ecosystem"], "arm": r["arm"],
             "sys": r["system"], "model": r["model"], "loss": loss(lab[r["case_id"]]["label"]["status"], r)}
            for r in x2 if not r.get("error")]
    df = pd.DataFrame(rows)
    # H9: withheld, DC vs S3, per case averaged over models (pairs restricted to models having both)
    w = df[(df.arm == "withheld") & df.sys.isin(["DC", "S3"])].pivot_table(
        index=["case", "model"], columns="sys", values="loss").dropna().groupby(level=0).mean()
    d = pd.DataFrame({"cve": [cases[c]["cve"] for c in w.index], "d": w["DC"] - w["S3"]})
    res.append(report("H9 withheld DC-S3 loss", d))
    # H10: vendor, tracker arm, DC (mean over models) vs S1p (LLM-free, one run)
    v = df[(df.arm == "tracker") & (df.eco == "vendor")]
    dc = v[v.sys == "DC"].groupby("case")["loss"].mean()
    s1 = v[v.sys == "S1p"].groupby("case")["loss"].mean()
    j = pd.concat([dc, s1], axis=1, keys=["DC", "S1p"]).dropna()
    d = pd.DataFrame({"cve": [cases[c]["cve"] for c in j.index], "d": j["DC"] - j["S1p"]})
    res.append(report("H10 vendor/tracker DC-S1p loss", d))
    # H10 sensitivity: other ecosystems
    for eco in ("deb-ubuntu", "pypi", "maven"):
        v = df[(df.arm == "tracker") & (df.eco == eco)]
        j = pd.concat([v[v.sys == "DC"].groupby("case")["loss"].mean(), v[v.sys == "S1p"].groupby("case")["loss"].mean()],
                      axis=1, keys=["DC", "S1p"]).dropna()
        print(f"   (sens) tracker {eco}: DC-S1p = {(j['DC'] - j['S1p']).mean():.4f} over {len(j)} cases")
    # H11: accepted-fact error, DC vs DC_noverify
    truth = {}
    facts = []
    for r in x2:
        if r.get("error") or r["system"] not in ("DC", "DC_noverify", "DCv21"):
            continue
        ver = ((r.get("extra") or {}).get("final_state") or {}).get("verdicts") or []
        if not ver:
            continue
        c = cases[r["case_id"]]
        if c["case_id"] not in truth:
            env = HostEnv(c, data.fixture(c["host_id"]), data.cve_meta().get(c["cve"], {}), data.preconditions(), {})
            if env.is_deb():
                t = {env.packages[b]["Version"] for b in env.src_binaries(c["src_package"])}
                t |= {str(s["loaded_version"]) for s in env.services.values() if s.get("loaded_version")}
            else:
                t = {str(i["version"]) for i in env.instances()} | set(env.running_versions())
            truth[c["case_id"]] = t
        src = {x["id"]: x["source"] for x in r["calls"]}
        for v_ in ver:
            val = str(v_.get("value", ""))

            def same(a, b, eco=c["ecosystem"]):
                try:
                    return versions.compare(eco, a, b) == 0
                except Exception:  # noqa: BLE001
                    return a.strip() == b.strip()
            facts.append({"case": r["case_id"], "cve": r["cve"], "eco": c["ecosystem"], "sys": r["system"],
                          "model": r["model"], "arm": r["arm"], "src": src.get(v_.get("call_id"), "?"),
                          "acc": bool(v_.get("accepted")), "wrong": not any(same(val, t) for t in truth[r["case_id"]]),
                          "val": val, "truth": sorted(truth[r["case_id"]]), "reason": v_.get("reason")})
    f = pd.DataFrame(facts)
    a = f[f.acc]
    per = a.groupby(["case", "sys"])["wrong"].mean().unstack().dropna(subset=["DC", "DC_noverify"])
    d = pd.DataFrame({"cve": [cases[c]["cve"] for c in per.index], "d": per["DC"] - per["DC_noverify"]})
    res.append(report("H11 accepted-fact error DC-DC_noverify (fact-weighted per case)", d))
    # sensitivity: per case averaged over models (each model-case error rate first)
    pm = a.groupby(["case", "model", "sys"])["wrong"].mean().unstack().dropna(subset=["DC", "DC_noverify"])
    pm = pm.groupby(level=0)[["DC", "DC_noverify"]].mean()
    d2 = pd.DataFrame({"cve": [cases[c]["cve"] for c in pm.index], "d": pm["DC"] - pm["DC_noverify"]})
    report("   (sens) H11 model-averaged per case", d2)
    print("   accepted-error by sys x eco x src:\n", a.groupby(["sys", "eco", "src"])["wrong"].agg(["mean", "size"]).round(3).to_string())
    f.to_csv(ROOT / "tests/v3/_h11_facts.csv.tmp", index=False) if False else None
    wrong_dc = a[(a.sys == "DC") & a.wrong]
    print("   sample DC accepted-but-wrong facts:")
    for _, x in wrong_dc.sample(min(8, len(wrong_dc)), random_state=1).iterrows():
        print("     ", x["case"], x["src"], repr(x["val"]), x["truth"], x["reason"])
    # ---------------- X3 H14
    x3 = load("test", "X3")
    rows = [{"case": r["case_id"], "cve": r["cve"], "arm": r["arm"], "sys": r["system"], "model": r["model"],
             "budget": r["budget"], "t": r.get("t_decision"), "loss": loss(lab[r["case_id"]]["label"]["status"], r)}
            for r in x3 if not r.get("error")]
    x = pd.DataFrame(rows)
    top = x[(x.arm == "withheld") & (x.budget == x.budget.max()) & x.sys.isin(["DC", "DC_checklist"])]
    pv = top.pivot_table(index=["case", "model"], columns="sys", values="t").dropna()
    d = pd.DataFrame({"cve": [cases[c]["cve"] for c in pv.index.get_level_values(0)], "d": pv["DC"] - pv["DC_checklist"]})
    res.append(report("H14 withheld max-budget DC-DC_checklist cost-to-decision", d))
    pl = top.pivot_table(index=["case", "model"], columns="sys", values="loss").dropna()
    dl = pd.DataFrame({"cve": [cases[c]["cve"] for c in pl.index.get_level_values(0)], "d": pl["DC"] - pl["DC_checklist"]})
    print(f"   H14 loss diff={dl['d'].mean():.4f}, one-sided 95% UB={boot(dl, q=(95,))[0]:.4f}, "
          f"cases with any loss diff={int((dl['d'] != 0).sum())}")
    for s in ("DC_entropy", "DC_llmchoose", "DC_random", "S3"):
        q = x[(x.arm == "withheld") & (x.budget == x.budget.max()) & (x.sys == s)]
        print(f"   withheld@60 {s}: mean t_decision={q['t'].mean():.3f} loss={q['loss'].mean():.3f}")
    # ---------------- X5 H13
    eps = {json.loads(l)["episode_id"]: json.loads(l) for l in (ROOT / "data/drift_d7/test.jsonl").open()}
    x5 = load("test", "X5")
    rows = []
    for r in x5:
        if r.get("error"):
            continue
        g = decide_world(r["world_at_decision"], bool(r["world_at_decision"].get("req_config"))).status
        e = eps[r["drift"]]
        rows.append({"ep": r["drift"], "kind": e["kind"], "eco": e["ecosystem"], "cve": r["cve"], "sys": r["system"],
                     "model": r["model"], "loss": loss(g, r)})
    x = pd.DataFrame(rows)
    u = x[(x.kind == "upgrade_no_restart") & x.sys.isin(["DC", "DCv21"])]
    pv = u.pivot_table(index=["ep", "model"], columns="sys", values="loss").dropna()
    d = pd.DataFrame({"cve": [eps[e]["case_id"].split("-")[1] + "-" + eps[e]["case_id"].split("-")[2] + "-" +
                              eps[e]["case_id"].split("-")[3] for e in pv.index.get_level_values(0)],
                      "d": pv["DCv21"] - pv["DC"]})
    res.append(report("H13 upgrade_no_restart DCv21-DC loss", d))
    for eco in ("deb-ubuntu", "vendor"):
        q = u[u.eco == eco].pivot_table(index=["ep", "model"], columns="sys", values="loss").dropna()
        print(f"   (sens) H13 {eco}: DCv21-DC = {(q['DCv21'] - q['DC']).mean():.3f} (n={len(q)})")
    # ---------------- H12 LTT (blind)
    h12()
    # Holm
    ps = sorted([(r["test"], r["p_two"]) for r in res], key=lambda t: t[1])
    m = len(ps) + 1  # + H12 criterion
    run = 0
    print("Holm (5 p-values + H12 criterion counted as m=6):")
    for i, (k, p) in enumerate(ps):
        run = max(run, min(1, (m - i - 1) * p)) if False else max(run, min(1, (m - i) * p))
        print(f"   {k}: p={p:.5f} p_holm<= {run:.5f}")


def h12(alpha=0.05, delta=0.1, R=200, seed=99):
    rows = []
    for sp in ("calib", "test"):
        lab = data.load_labels(sp, allow_sealed=sp == "test")
        for r in load(sp, "X2"):
            if r["system"] != "DC" or r["arm"] != "blind" or r.get("error") or r["case_id"] not in lab:
                continue
            st = (r.get("extra") or {}).get("assessed_state", {}).get("state", {})
            vals = {}
            for at in ("present", "in_affected_range", "fix_applied", "vuln_config_enabled"):
                a = st.get(at)
                vals[at] = Belnap.N if not a else Belnap.from_support(a["kappa_pos"] + a["hints_pos"], a["kappa_neg"] + a["hints_neg"])
            dec = decide_values(vals, False)
            if r["status"] != "under_investigation":
                hint, score = r["status"], math.inf
            else:
                hint = dec.status
                ms = []
                for at, pos in dec.required:
                    a = st.get(at) or {"kappa_pos": 0, "kappa_neg": 0, "hints_pos": 0, "hints_neg": 0}
                    p_, n_ = a["kappa_pos"] + a["hints_pos"], a["kappa_neg"] + a["hints_neg"]
                    ms.append((p_ - n_) if pos else (n_ - p_))
                score = min(ms) if ms else 0
            rows.append((r["model"], r["cve"], lab[r["case_id"]]["label"]["status"], r["status"], hint, score))
    df = pd.DataFrame(rows, columns=["model", "cve", "gold", "base", "hint", "score"])
    from scipy.stats import binom
    rng = np.random.default_rng(seed)

    def rel(s, lam):
        return np.where(s.score.to_numpy() >= lam, s.hint.to_numpy(), "under_investigation")

    def risk(s, lam):
        r_ = rel(s, lam)
        return float(np.mean((s.gold.to_numpy() == "affected") & ((r_ == "not_affected") | (r_ == "fixed"))))

    def pval(rh, n):
        # Hoeffding-Bentkus
        def kl(a, b):
            a = min(max(a, 1e-12), 1 - 1e-12)
            return a * math.log(a / b) + (1 - a) * math.log((1 - a) / (1 - b))
        h = math.exp(-n * kl(min(rh, alpha), alpha)) if rh < alpha else 1.0
        return min(h, math.e * binom.cdf(math.ceil(n * rh), n, alpha))

    out = []
    for model, g in df.groupby("model"):
        cves = g.cve.unique()
        fr, cov = [], []
        for _ in range(R):
            perm = rng.permutation(cves)
            cal = g[g.cve.isin(perm[: int(0.4 * len(perm))])]
            ev = g[~g.cve.isin(perm[: int(0.4 * len(perm))])]
            lam = math.inf
            for l_ in sorted({s for s in cal.score if np.isfinite(s)} | {math.inf}, reverse=True):
                if pval(risk(cal, l_), len(cal)) <= delta:
                    lam = l_
                else:
                    break
            fr.append(risk(ev, lam) <= alpha)
            cov.append(np.mean(rel(ev, lam) != "under_investigation"))
        out.append((model, np.mean(fr), np.mean(cov) - np.mean(g.base != "under_investigation"),
                    np.mean(g.base != "under_investigation")))
    o = pd.DataFrame(out, columns=["model", "frac", "gain", "base_cov"])
    print(o.round(4).to_string(index=False))
    print(f"H12: min frac={o.frac.min():.3f} (>=0.9?) mean gain={o.gain.mean():.4f} (>0?) -> "
          f"criterion {'MET' if o.frac.min() >= 0.9 and o.gain.mean() > 0 else 'NOT met'}; "
          f"every-model gain>0: {bool((o.gain > 0).all())}")


if __name__ == "__main__":
    main()
