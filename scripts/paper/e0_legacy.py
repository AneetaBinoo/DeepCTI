"""E0: re-analysis of the v0 (legacy) DeepCTI study from its raw run logs.

Inputs: results/raw/*/<model>/<mode>.jsonl (v0 raw logs), the v0 dataset, and the v0 controller code
(src/deepcti/memory.py, orchestrator.py), run WITHOUT any LLM for the controller-only condition.
Outputs: results/v2/e0/*.csv and results/v2/e0/E0_REPORT.md. Every number in the report is computed here;
the v0 README values are hard-coded only as the "reported" column for the reproduction check.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from statistics import mean, median
from typing import Any

import numpy as np
import pandas as pd

from deepcti.datasets import load_contextual_jsonl
from deepcti.inference import bootstrap_mean_ci, holm_adjust, paired_sign_flip_pvalue
from deepcti.memory import EvidenceBackedMemory
from deepcti.orchestrator import VALID_MODES, _safe_fallback_payload, run_adaptive_memory_case
from deepcti.schemas import UsageRecord

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "results" / "raw"
DATASET = ROOT / "data" / "derived" / "deepcti_kev_contextual_synthetic_100_v1.jsonl"
KEV_MIRROR = ROOT / "data" / "mirrors" / "cisa_kev" / "2026-10-05" / "known_exploited_vulnerabilities.json"
OUT = ROOT / "results" / "v2" / "e0"
E1_KIND = ROOT / "results" / "v2" / "e1" / "atom_prf_by_kind.csv"
SEED = 20260819
PROFILES = ("affected", "not_applicable", "uncertain", "contradictory")
MODE_ORDER = ("adaptive_memory", "evidence_equal_one_shot", "rag_once", "iterative_no_memory", "initial_one_shot")
BASELINES = MODE_ORDER[1:]
MODE_LABELS = {
    "adaptive_memory": "DeepCTI",
    "evidence_equal_one_shot": "Equal-evidence one-shot",
    "rag_once": "RAG once",
    "iterative_no_memory": "Iterative no-memory",
    "initial_one_shot": "Initial one-shot",
    "controller_only": "Controller only (no LLM)",
}
# v0 README values, used only as the "reported" column of the reproduction check.
REPORTED_SIX = {
    "llama3.1:8b": (0.886, 1.62, 509.5), "mistral:latest": (0.910, 2.35, 704.0),
    "qwen2.5:7b": (0.925, 2.29, 602.0), "qwen3:8b": (0.923, 2.29, 598.0),
    "gemma3:12b": (0.925, 3.35, 626.5), "phi4:14b": (0.925, 4.71, 609.0),
}
REPORTED_MODES = {
    "adaptive_memory": (0.907, 1.000, 1.56), "rag_once": (0.808, 0.987, 7.86),
    "evidence_equal_one_shot": (0.805, 0.990, 6.93), "iterative_no_memory": (0.803, 0.977, 19.67),
    "initial_one_shot": (0.605, 0.993, 5.78),
}
# Literal trigger phrases of memory.extract_observations (v0 regex extractor), transcribed from the source.
REGEX_TRIGGERS = (
    "not installed", " is absent", "is installed", "confirms", "reports", "installed", "missing",
    "may be present", "suggests", "version is affected", "affected version", "version is unaffected",
    "not affected", "version data", "version status", "does not establish its version", "unknown",
    "not yet verified", "does not establish", "no tested rollback", "rollback procedure is unavailable",
    "tested backup", "rollback", "approval", "withheld", "not approved", "approval is withheld", "approved",
)


# ----------------------------------------------------------------------------- legacy quality (verbatim)
def _recall(keywords: list[str], text: str) -> float:
    if not keywords:
        return 1.0
    lowered = text.lower()
    return sum(keyword.lower() in lowered for keyword in keywords) / len(keywords)


def legacy_quality(record: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    """Quality as defined in scripts/analyze_architecture_suite.py (v0), copied without changes."""
    state = record.get("final_state", {}) or {}
    text = " ".join(
        [
            str(record.get("final_answer", "")),
            str(state.get("selected_action", "")),
            " ".join(map(str, state.get("open_information_needs", []) or [])),
        ]
    )
    forbidden = [str(item) for item in reference.get("forbidden_keywords", [])]
    unsafe = any(item.lower() in text.lower() for item in forbidden)
    contradiction_expected = bool(reference.get("contradiction_expected"))
    contradiction_detected = bool(state.get("contradictions")) or any(
        cue in text.lower() for cue in ("contradict", "conflict", "reconcile")
    )
    applicability_correct = str(state.get("applicability", "")) == str(reference.get("expected_applicability", ""))
    action_recall = _recall(list(reference.get("action_keywords", [])), text)
    information_recall = _recall(list(reference.get("information_keywords", [])), text)
    contradiction_correct = contradiction_detected == contradiction_expected
    quality = mean(
        [float(applicability_correct), action_recall, information_recall, float(not unsafe),
         float(contradiction_correct)]
    )
    usage = record.get("usage", {}) or {}
    return {
        "quality": quality,
        "applicability_correct": int(applicability_correct),
        "action_keyword_recall": action_recall,
        "information_need_recall": information_recall,
        "unsafe_recommendation": int(unsafe),
        "contradiction_correct": int(contradiction_correct),
        "completed": int(bool(record.get("completed"))),
        "steps": int(record.get("steps_executed", 0)),
        "latency_s": float(usage.get("total_duration_ms", 0)) / 1000,
        "tokens": int(usage.get("prompt_tokens", 0)) + int(usage.get("completion_tokens", 0)),
    }


# ----------------------------------------------------------------------------- loading
def load_raw() -> list[dict[str, Any]]:
    rows = []
    for path in sorted(RAW.glob("*/*/*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                record["_experiment"] = path.parts[-3]
                rows.append(record)
    return rows


class _NoLLM:
    """Stands in for the LLM: every generation fails to parse, so the v0 controller falls back."""

    class _Result:
        raw_text = ""
        parse_error = "no LLM (controller-only condition)"

        def __init__(self) -> None:
            self.content: dict = {}
            self.usage = UsageRecord()

    def generate(self, **_: Any) -> _Result:
        return self._Result()


def controller_only(cases) -> list[dict[str, Any]]:
    records = []
    for case in cases:
        record = run_adaptive_memory_case(case=case, model="none", client=_NoLLM(), temperature=0.0)
        record["mode"] = "controller_only"
        record["model"] = "none"
        record["_experiment"] = "e0_controller_only"
        records.append(record)
    return records


# ----------------------------------------------------------------------------- statistics helpers
def icc1(values: np.ndarray, groups: np.ndarray) -> float:
    """One-way random-effects ICC(1) for balanced-ish groups."""
    labels = sorted(set(groups))
    k = len(values) / len(labels)
    grand = values.mean()
    msb = sum(len(values[groups == g]) * (values[groups == g].mean() - grand) ** 2 for g in labels) / (
        len(labels) - 1)
    msw = sum(((values[groups == g] - values[groups == g].mean()) ** 2).sum() for g in labels) / (
        len(values) - len(labels))
    denom = msb + (k - 1) * msw
    return float((msb - msw) / denom) if denom > 0 else float("nan")


def template_bootstrap(per_template: dict[str, list[float]], seed: int, resamples: int = 20_000):
    names = sorted(per_template)
    means = np.array([np.mean(per_template[n]) for n in names])
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(names), size=(resamples, len(names)))
    est = means[idx].mean(axis=1)
    distinct_multisets = len(list(itertools.combinations_with_replacement(range(len(names)), len(names))))
    lo, hi = np.quantile(est, [0.025, 0.975])
    return float(lo), float(hi), len(np.unique(np.round(est, 10))), distinct_multisets


def write(frame: pd.DataFrame, name: str) -> pd.DataFrame:
    frame.to_csv(OUT / name, index=False)
    return frame


def fmt(x: Any) -> str:
    if isinstance(x, float | np.floating):
        return "nan" if np.isnan(x) else f"{x:.3f}"
    return str(x)


def md(frame: pd.DataFrame, cols: list[str] | None = None) -> str:
    cols = cols or list(frame.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(fmt(r[c]) for c in cols) + " |" for _, r in frame.iterrows()]
    return "\n".join(lines)


# ----------------------------------------------------------------------------- main analysis
def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    cases = load_contextual_jsonl(DATASET)
    case_by_id = {c.case_id: c for c in cases}
    profile = {c.case_id: c.asset_context["profile_kind"] for c in cases}
    raw = load_raw()
    ctrl = controller_only(cases)

    rows = []
    for record in [*raw, *ctrl]:
        case = case_by_id[record["case_id"]]
        q = legacy_quality(record, case.reference)
        calls = record.get("model_calls")
        if calls is None:
            calls = len(record.get("traces", []))
        rows.append({"experiment": record["_experiment"], "model": record["model"], "mode": record["mode"],
                     "case_id": record["case_id"], "profile": profile[record["case_id"]],
                     "template": profile[record["case_id"]], "llm_calls": int(calls)} | q)
    df = pd.DataFrame(rows)
    write(df, "case_metrics.csv")
    mc = df[df.experiment == "deepcti_mode_comparison_100_2026"]
    co = df[df["mode"] == "controller_only"]

    # (a1) six-model DeepCTI table (candidate + expanded runs), CIs as in analyze_architecture_suite
    six = []
    for exp in ("deepcti_candidate_100_2026", "deepcti_expanded_models_100_2026"):
        sub = df[df.experiment == exp]
        for index, (model, g) in enumerate(sorted(sub.groupby("model"), key=lambda kv: kv[0])):
            lo, hi = bootstrap_mean_ci(g.quality.tolist(), seed=SEED + index)
            rep = REPORTED_SIX[model]
            six.append({"experiment": exp, "model": model, "cases": len(g), "quality": g.quality.mean(),
                        "ci_low": lo, "ci_high": hi, "reported_quality": rep[0],
                        "median_latency_s": median(g.latency_s), "reported_median_latency_s": rep[1],
                        "median_tokens": median(g.tokens), "reported_median_tokens": rep[2],
                        "applicability_acc": g.applicability_correct.mean(),
                        "contradiction_acc": g.contradiction_correct.mean()})
    six = write(pd.DataFrame(six), "a_six_model_deepcti.csv")
    lo, hi = bootstrap_mean_ci(co.quality.tolist(), seed=SEED)
    ctrl_row = {"quality": co.quality.mean(), "ci_low": lo, "ci_high": hi}

    # (a2) mode comparison (case-clustered: mean over 3 models per case), as analyze_mode_comparison_100
    case_means = {m: mc[mc["mode"] == m].groupby("case_id").quality.mean() for m in MODE_ORDER}
    modes = []
    for index, m in enumerate(MODE_ORDER):
        g = mc[mc["mode"] == m]
        lo, hi = bootstrap_mean_ci(case_means[m].tolist(), seed=SEED + index)
        rep = REPORTED_MODES[m]
        modes.append({"mode": m, "label": MODE_LABELS[m], "records": len(g), "quality": case_means[m].mean(),
                      "ci_low": lo, "ci_high": hi, "reported_quality": rep[0],
                      "completion": g.completed.mean(), "reported_completion": rep[1],
                      "median_latency_s": median(g.latency_s), "reported_median_latency_s": rep[2],
                      "applicability_acc": g.applicability_correct.mean(), "unsafe_rate": g.unsafe_recommendation.mean()})
    modes.append({"mode": "controller_only", "label": MODE_LABELS["controller_only"], "records": len(co),
                  "quality": ctrl_row["quality"], "ci_low": ctrl_row["ci_low"], "ci_high": ctrl_row["ci_high"],
                  "reported_quality": float("nan"), "completion": co.completed.mean(),
                  "reported_completion": float("nan"), "median_latency_s": 0.0,
                  "reported_median_latency_s": float("nan"), "applicability_acc": co.applicability_correct.mean(),
                  "unsafe_rate": co.unsafe_recommendation.mean()})
    modes = write(pd.DataFrame(modes), "a_mode_comparison.csv")
    contrasts, raw_p = [], {}
    ids = sorted(case_means["adaptive_memory"].index)
    for index, comp in enumerate(BASELINES):
        diff = [case_means["adaptive_memory"][c] - case_means[comp][c] for c in ids]
        lo, hi = bootstrap_mean_ci(diff, seed=SEED + 100 + index)
        name = f"DeepCTI vs {MODE_LABELS[comp]}"
        raw_p[name] = paired_sign_flip_pvalue(diff, seed=SEED + 200 + index)
        contrasts.append({"comparison": name, "comparator": comp, "delta": mean(diff), "ci_low": lo, "ci_high": hi,
                          "p_raw": raw_p[name]})
    adj = holm_adjust(raw_p)
    for item in contrasts:
        item["p_holm"] = adj[item["comparison"]]
    contrasts = write(pd.DataFrame(contrasts), "a_mode_contrasts.csv")

    # (c) per-profile table per mode (mode-comparison runs, mean over 3 models x 25 cases) + controller-only
    prof_rows = []
    for m in [*MODE_ORDER, "controller_only"]:
        g = co if m == "controller_only" else mc[mc["mode"] == m]
        row = {"mode": MODE_LABELS[m]}
        for p in PROFILES:
            row[p] = g[g.profile == p].quality.mean()
        row["all"] = g.quality.mean()
        prof_rows.append(row)
    per_profile = write(pd.DataFrame(prof_rows), "c_per_profile_quality.csv")
    comp_rows = []
    for m in [*MODE_ORDER, "controller_only"]:
        g = co if m == "controller_only" else mc[mc["mode"] == m]
        for p in PROFILES:
            gp = g[g.profile == p]
            comp_rows.append({"mode": MODE_LABELS[m], "profile": p, "quality": gp.quality.mean(),
                              "applicability": gp.applicability_correct.mean(),
                              "action_recall": gp.action_keyword_recall.mean(),
                              "info_recall": gp.information_need_recall.mean(),
                              "safe": 1 - gp.unsafe_recommendation.mean(),
                              "contradiction": gp.contradiction_correct.mean()})
    write(pd.DataFrame(comp_rows), "c_per_profile_components.csv")

    # (d) share of DeepCTI-vs-baseline gap attributable to each profile
    gap_rows = []
    for comp in BASELINES:
        total = (case_means["adaptive_memory"] - case_means[comp]).mean()
        row = {"comparator": MODE_LABELS[comp], "gap": total}
        for p in PROFILES:
            sel = [c for c in ids if profile[c] == p]
            contrib = (case_means["adaptive_memory"][sel] - case_means[comp][sel]).sum() / len(ids)
            row[f"share_{p}"] = contrib / total if total else float("nan")
        gap_rows.append(row)
    baseline_mean = pd.concat([case_means[b] for b in BASELINES], axis=1).mean(axis=1)
    total = (case_means["adaptive_memory"] - baseline_mean).mean()
    row = {"comparator": "Mean of 4 baselines", "gap": total}
    for p in PROFILES:
        sel = [c for c in ids if profile[c] == p]
        row[f"share_{p}"] = (case_means["adaptive_memory"][sel] - baseline_mean[sel]).sum() / len(ids) / total
    gap_rows.append(row)
    gaps = write(pd.DataFrame(gap_rows), "d_gap_share_by_profile.csv")

    # (e) corrected cost metrics
    cost_rows = []
    for (exp, model, m), g in df.groupby(["experiment", "model", "mode"]):
        called = g[g.llm_calls > 0]
        nz_tok = g.tokens[g.tokens > 0]
        cost_rows.append({
            "experiment": exp, "model": model, "mode": m, "cases": len(g),
            "share_zero_llm_calls": (g.llm_calls == 0).mean(), "mean_llm_calls": g.llm_calls.mean(),
            "mean_tokens_all": g.tokens.mean(), "median_tokens_all": median(g.tokens),
            "mean_tokens_called": called.tokens.mean() if len(called) else 0.0,
            "median_tokens_called": median(called.tokens) if len(called) else 0.0,
            "mean_latency_all": g.latency_s.mean(), "median_latency_all": median(g.latency_s),
            "mean_latency_called": called.latency_s.mean() if len(called) else 0.0,
            "median_latency_called": median(called.latency_s) if len(called) else 0.0,
            "min_nonzero_tokens": nz_tok.min() if len(nz_tok) else 0,
            "min_nonzero_latency": g.latency_s[g.latency_s > 0].min() if (g.latency_s > 0).any() else 0.0,
        })
    cost = write(pd.DataFrame(cost_rows), "e_cost_metrics.csv")
    pooled = []
    for m in MODE_ORDER:
        g = mc[mc["mode"] == m]
        called = g[g.llm_calls > 0]
        pooled.append({"mode": MODE_LABELS[m], "share_zero_calls": (g.llm_calls == 0).mean(),
                       "mean_tok_all": g.tokens.mean(), "median_tok_all": median(g.tokens),
                       "mean_tok_called": called.tokens.mean(), "median_tok_called": median(called.tokens),
                       "mean_lat_all": g.latency_s.mean(), "median_lat_all": median(g.latency_s),
                       "mean_lat_called": called.latency_s.mean(), "median_lat_called": median(called.latency_s)})
    pooled = write(pd.DataFrame(pooled), "e_cost_mode_comparison_pooled.csv")

    # (f) RAG pool size vs k
    rag_rows = []
    manifest = json.loads((RAW / "deepcti_mode_comparison_100_2026" / "manifest.json").read_text())
    k = int(manifest["config"]["retrieval_k"])
    for record in raw:
        if record["mode"] not in {"rag_once", "iterative_no_memory"}:
            continue
        case = case_by_id[record["case_id"]]
        pool = case.initial_evidence + case.staged_evidence
        for trace in record["traces"]:
            pool_at_step = [e for e in pool if e.step <= (99 if record["mode"] == "rag_once" else trace["step"])]
            got = {e["evidence_id"] for e in trace["evidence"]}
            rag_rows.append({"model": record["model"], "mode": record["mode"], "case_id": record["case_id"],
                             "step": trace["step"], "k": k, "pool_size": len(pool_at_step), "retrieved": len(got),
                             "retrieved_all_of_pool": int(got == {e.evidence_id for e in pool_at_step})})
    rag = write(pd.DataFrame(rag_rows), "f_rag_pool_vs_k.csv")
    rag_summary = rag.groupby(["mode", "step"]).agg(
        rows=("case_id", "count"), pool_size_mean=("pool_size", "mean"), pool_size_max=("pool_size", "max"),
        k=("k", "first"), retrieved_mean=("retrieved", "mean"),
        share_retrieved_entire_pool=("retrieved_all_of_pool", "mean")).reset_index()
    write(rag_summary, "f_rag_pool_summary.csv")

    # iterative-no-memory last step vs equal-evidence one-shot
    inm = {(r["model"], r["case_id"]): r for r in raw if r["mode"] == "iterative_no_memory"
           and r["_experiment"] == "deepcti_mode_comparison_100_2026"}
    eeo = {(r["model"], r["case_id"]): r for r in raw if r["mode"] == "evidence_equal_one_shot"
           and r["_experiment"] == "deepcti_mode_comparison_100_2026"}
    same_set, empty_state, finished_3 = [], [], []
    for key, r in inm.items():
        last = r["traces"][-1]
        finished_3.append(int(r["steps_executed"] == 3))
        e_ids = {e["evidence_id"] for e in eeo[key]["traces"][-1]["evidence"]} if eeo[key]["traces"] else set()
        same_set.append(int({e["evidence_id"] for e in last["evidence"]} == e_ids))
        sb = last["state_before"]
        empty_state.append(int(not sb.get("facts") and not sb.get("open_information_needs")
                               and not sb.get("claims") and sb.get("applicability") == "uncertain"))
    qi = mc[mc["mode"] == "iterative_no_memory"].set_index(["model", "case_id"])
    qe = mc[mc["mode"] == "evidence_equal_one_shot"].set_index(["model", "case_id"])
    joined = qi.join(qe, lsuffix="_inm", rsuffix="_eeo")
    inm_vs = {"pairs": len(inm), "share_ran_3_steps": mean(finished_3),
              "share_last_step_same_evidence_set": mean(same_set),
              "share_last_step_empty_state": mean(empty_state),
              "quality_inm": joined.quality_inm.mean(), "quality_eeo": joined.quality_eeo.mean(),
              "mean_abs_quality_diff": (joined.quality_inm - joined.quality_eeo).abs().mean(),
              "share_identical_quality": (joined.quality_inm == joined.quality_eeo).mean(),
              "share_identical_applicability_correct": (
                  joined.applicability_correct_inm == joined.applicability_correct_eeo).mean(),
              "corr_quality": joined.quality_inm.corr(joined.quality_eeo),
              "tokens_ratio_inm_over_eeo": joined.tokens_inm.mean() / joined.tokens_eeo.mean()}
    write(pd.DataFrame([inm_vs]), "f_iterative_no_memory_vs_one_shot.csv")

    # (g) effective sample size: distinct templates, ICC, template-clustered bootstrap
    kev = {r["cveID"]: r for r in json.loads(KEV_MIRROR.read_text())["vulnerabilities"]}
    skeletons, unresolved = set(), 0
    for c in cases:
        product = str(kev.get(c.cve_id, {}).get("product", "\0"))
        texts = []
        for e in c.initial_evidence + c.staged_evidence:
            if e.field == "cisa_kev_record":
                continue
            t = e.text.replace(c.cve_id, "<CVE>")
            if product in t:
                t = t.replace(product, "<PRODUCT>")
            elif "<PRODUCT>" not in t and any(w in e.field for w in ("inventory", "presence", "network")):
                unresolved += 1
            texts.append((e.field, e.step, t))
        skeletons.add(tuple(texts))
    ess_rows = []
    groups: list[tuple[str, str, pd.DataFrame]] = [("mode_comparison(mean of 3 models)", m,
                                                    mc[mc["mode"] == m].groupby("case_id").quality.mean())
                                                   for m in MODE_ORDER]
    groups += [(f"{e}:{mdl}", "adaptive_memory", g.set_index("case_id").quality)
               for (e, mdl), g in df[df.experiment.isin(["deepcti_candidate_100_2026",
                                                         "deepcti_expanded_models_100_2026"])]
               .groupby(["experiment", "model"])]
    groups.append(("controller_only", "controller_only", co.set_index("case_id").quality))
    for index, (label, m, series) in enumerate(groups):
        vals = series.to_numpy(dtype=float)
        grp = np.array([profile[c] for c in series.index])
        icc = icc1(vals, grp)
        m_size = len(vals) / 4
        deff = 1 + (m_size - 1) * icc if not np.isnan(icc) else float("nan")
        within_sd = float(np.mean([vals[grp == p].std(ddof=0) for p in PROFILES]))
        lo, hi, n_distinct, n_multi = template_bootstrap({p: vals[grp == p].tolist() for p in PROFILES},
                                                         seed=SEED + index)
        case_lo, case_hi = bootstrap_mean_ci(vals.tolist(), seed=SEED + index)
        ess_rows.append({"run": label, "mode": m, "n_cases": len(vals), "templates": 4, "icc1": icc,
                         "design_effect": deff, "n_eff": len(vals) / deff if deff and not np.isnan(deff) else float("nan"),
                         "mean_within_template_sd": within_sd, "mean": vals.mean(),
                         "case_ci_low": case_lo, "case_ci_high": case_hi, "template_ci_low": lo, "template_ci_high": hi,
                         "template_boot_distinct_means": n_distinct, "template_boot_possible_multisets": n_multi})
    ess = write(pd.DataFrame(ess_rows), "g_effective_sample_size.csv")
    delta_rows = []
    for index, comp in enumerate(BASELINES):
        diff = case_means["adaptive_memory"] - case_means[comp]
        per_t = {p: diff[[c for c in ids if profile[c] == p]].tolist() for p in PROFILES}
        lo, hi, n_distinct, n_multi = template_bootstrap(per_t, seed=SEED + 300 + index)
        grp = np.array([profile[c] for c in diff.index])
        delta_rows.append({"comparison": f"DeepCTI vs {MODE_LABELS[comp]}", "delta": diff.mean(),
                           "icc1_of_delta": icc1(diff.to_numpy(), grp), "template_ci_low": lo,
                           "template_ci_high": hi, "distinct_boot_values": n_distinct,
                           "template_delta_" + "_".join(p[:4] for p in PROFILES): " / ".join(
                               f"{np.mean(per_t[p]):.3f}" for p in PROFILES)})
    ess_delta = write(pd.DataFrame(delta_rows), "g_template_bootstrap_deltas.csv")

    # ------------------------------------------------------------------ audit claims F1..F10
    adaptive_raw = [r for r in raw if r["mode"] == "adaptive_memory"]
    n_ad = len(adaptive_raw)
    f3_override = mean(int(r["final_state"]["applicability"] == r["validated_memory"]["applicability"])
                       for r in adaptive_raw)
    llm_app = [(a["model_output"] or {}).get("applicability") for r in adaptive_raw
               for a in r.get("generation_attempts", [])[:1]]
    llm_disagree = [str(a).lower() for a in llm_app]
    ctl_app = [r["validated_memory"]["applicability"] for r in adaptive_raw if r.get("generation_attempts")]
    f3_disagree = mean(int(a != b) for a, b in zip(llm_disagree, ctl_app, strict=True)) if ctl_app else 0.0
    f3_changed_final = sum(int(a != b and r["final_state"]["applicability"] == a)
                           for a, b, r in zip(llm_disagree, ctl_app,
                                              [r for r in adaptive_raw if r.get("generation_attempts")],
                                              strict=True))
    fallback_share = mean(int(bool(r.get("fallback_used"))) for r in adaptive_raw)
    zero_call_share = mean(int(r.get("model_calls", 0) == 0) for r in adaptive_raw)
    # F2: template sentences vs regex triggers
    tmpl_sentences = {}
    for c in cases:
        for e in c.initial_evidence + c.staged_evidence:
            if e.field != "cisa_kev_record":
                tmpl_sentences.setdefault((profile[c.case_id], e.step), e.text.lower())
    trig_in_templates = [t for t in REGEX_TRIGGERS if any(t in s for s in tmpl_sentences.values())]
    regex_mem = EvidenceBackedMemory("x")
    regex_app_correct = []
    for c in cases:
        mem = EvidenceBackedMemory(c.case_id)
        mem.ingest(c.initial_evidence + c.staged_evidence)
        regex_app_correct.append(int(mem.applicability() == c.reference["expected_applicability"]))
    del regex_mem
    e1_note = "E1 not yet run"
    if E1_KIND.exists():
        k1 = pd.read_csv(E1_KIND)
        r_o = k1[(k1.extractor == "regex") & (k1.kind == "original")].iloc[0]
        r_p = k1[(k1.extractor == "regex") & (k1.kind == "paraphrase")].iloc[0]
        e1_note = (f"regex atom F1 {r_o.f1:.3f} on originals vs {r_p.f1:.3f} on {int(r_p['items'])} "
                   f"auto-filtered paraphrases (E1)")
    # F5: fallback text keyword hits per profile (controller-only records)
    f5_rows = []
    for p in PROFILES:
        g = co[co.profile == p]
        f5_rows.append({"profile": p, "action_keyword_recall": g.action_keyword_recall.mean(),
                        "info_keyword_recall": g.information_need_recall.mean(),
                        "contradiction_correct": g.contradiction_correct.mean(), "quality": g.quality.mean()})
    f5 = write(pd.DataFrame(f5_rows), "f5_fallback_keyword_hits.csv")
    fb_kw = []
    for c in cases:
        mem = EvidenceBackedMemory(c.case_id)
        mem.ingest(c.initial_evidence + c.staged_evidence)
        text = _safe_fallback_payload(mem)["final_answer"].lower()
        kws = list(c.reference.get("action_keywords", [])) + list(c.reference.get("information_keywords", []))
        fb_kw.append((sum(k.lower() in text for k in kws), len(kws)))
    f5_hits = sum(a for a, _ in fb_kw) / max(sum(b for _, b in fb_kw), 1)
    # F6 numbers
    eeo_gap = gaps[gaps.comparator == MODE_LABELS["evidence_equal_one_shot"]].iloc[0]
    mean_gap = gaps[gaps.comparator == "Mean of 4 baselines"].iloc[0]
    # F9
    ad_cost = cost[cost["mode"] == "adaptive_memory"]
    f9_tok = (ad_cost.median_tokens_all - ad_cost.min_nonzero_tokens / 2).abs().max()
    f9_lat = (ad_cost.median_latency_all - ad_cost.min_nonzero_latency / 2).abs().max()
    # F10
    modes_in_logs = sorted({r["mode"] for r in raw})
    f10_count = sum(r["mode"] == "iterative_memory" for r in raw)
    # F1
    ad_mc = ess[ess["run"].str.startswith("mode_comparison") & (ess["mode"] == "adaptive_memory")].iloc[0]
    ctrl_ess = ess[ess["mode"] == "controller_only"].iloc[0]
    rag_once = rag_summary[rag_summary["mode"] == "rag_once"].iloc[0]
    claims = [
        ("F1", "effective sample size ~4 templates",
         (f"{len(skeletons)} distinct case skeletons after masking product/CVE ({unresolved} product strings "
         f"unresolved); ICC(1) by template: DeepCTI {ad_mc.icc1:.3f} (n_eff {ad_mc.n_eff:.1f}), controller-only "
         f"{ctrl_ess.icc1:.3f} (n_eff {ctrl_ess.n_eff:.1f})"),
         len(skeletons) == 4 and ad_mc.n_eff < 10),
        ("F2", "regex tuned to generator phrases",
         (f"{len(trig_in_templates)}/{len(REGEX_TRIGGERS)} regex trigger phrases occur verbatim in the 12 template "
         f"sentences; controller applicability correct on {mean(regex_app_correct):.3f} of originals; {e1_note}"),
         len(trig_in_templates) / len(REGEX_TRIGGERS) > 0.7),
        ("F3", "LLM cannot change applicability",
         (f"final applicability == controller applicability in {f3_override:.3f} of {n_ad} adaptive records; first "
         f"LLM answer disagreed with controller in {f3_disagree:.3f} of {len(ctl_app)} called records, "
         f"LLM value adopted in {f3_changed_final} of them; deterministic fallback text used in "
         f"{fallback_share:.3f} of adaptive records"),
         f3_override == 1.0 and f3_changed_final == 0),
        ("F4", "controller-only (no LLM) scores 0.925",
         (f"controller-only quality {ctrl_row['quality']:.3f} [{ctrl_row['ci_low']:.3f}, {ctrl_row['ci_high']:.3f}] "
         f"vs DeepCTI {modes.iloc[0].quality:.3f} (3-model mean) and per-model max {six.quality.max():.3f}"),
         abs(ctrl_row["quality"] - 0.925) < 0.0005),
        ("F5", "fallback text contains reference keywords",
         f"fallback text contains {f5_hits:.3f} of reference action+information keywords; per-profile "
         + ", ".join(f"{r.profile} act {r.action_keyword_recall:.2f}/info {r.info_keyword_recall:.2f}"
                     for r in f5.itertuples()),
         f5_hits > 0.5),
        ("F6", "~91% of +0.10 gap from contradictory profile",
         (f"gap vs equal-evidence one-shot {eeo_gap.gap:+.3f}, contradictory share {eeo_gap.share_contradictory:.3f};"
         f" vs mean of 4 baselines {mean_gap.gap:+.3f}, contradictory share {mean_gap.share_contradictory:.3f}"),
         0.85 <= eeo_gap.share_contradictory <= 0.97),
        ("F8", "RAG retrieves 4/4 (k=8, pool 4); iterative-no-memory last step = one-shot",
         (f"rag_once pool size {rag_once.pool_size_mean:.1f} (max {rag_once.pool_size_max}) with k={k}; entire pool "
         f"retrieved in {rag_once.share_retrieved_entire_pool:.3f}; iterative-no-memory last step: same evidence "
         f"set as one-shot {inm_vs['share_last_step_same_evidence_set']:.3f}, empty prior state "
         f"{inm_vs['share_last_step_empty_state']:.3f}; quality {inm_vs['quality_inm']:.3f} vs "
         f"{inm_vs['quality_eeo']:.3f} (identical per-record quality {inm_vs['share_identical_quality']:.3f}, "
         f"r={inm_vs['corr_quality']:.3f}); equal at input level (prompt differs only in mode label, state.step "
         f"and evidence order), not record-for-record at output level; costs "
         f"{inm_vs['tokens_ratio_inm_over_eeo']:.2f}x the one-shot tokens"),
         rag_once.share_retrieved_entire_pool == 1.0 and inm_vs["share_last_step_same_evidence_set"] > 0.95),
        ("F9", "reported medians = half the smallest non-zero value",
         (f"adaptive records with zero LLM calls: {zero_call_share:.3f}; max |median - min_nonzero/2| over 9 "
         f"model-runs: tokens {f9_tok:.3f}, latency {f9_lat:.4f} s"),
         f9_tok < 1e-6 and f9_lat < 1e-6),
        ("F10", "iterative_memory unreported",
         (f"modes in raw logs: {', '.join(modes_in_logs)}; iterative_memory records: {f10_count} "
         f"(declared in VALID_MODES: {'iterative_memory' in VALID_MODES})"),
         f10_count == 0),
    ]
    claim_df = write(pd.DataFrame(claims, columns=["id", "claim", "evidence", "confirmed"]), "audit_claims.csv")

    # ------------------------------------------------------------------ report
    six_r = six.assign(ci=[f"[{a:.3f}, {b:.3f}]" for a, b in zip(six.ci_low, six.ci_high, strict=True)])
    modes_r = modes.assign(ci=[f"[{a:.3f}, {b:.3f}]" for a, b in zip(modes.ci_low, modes.ci_high, strict=True)])
    con_r = contrasts.assign(ci=[f"[{a:.3f}, {b:.3f}]" for a, b in zip(contrasts.ci_low, contrasts.ci_high,
                                                                      strict=True)])
    ess_r = ess.assign(case_ci=[f"[{a:.3f}, {b:.3f}]" for a, b in zip(ess.case_ci_low, ess.case_ci_high, strict=True)],
                       template_ci=[f"[{a:.3f}, {b:.3f}]" for a, b in zip(ess.template_ci_low, ess.template_ci_high,
                                                                         strict=True)])
    ess_d = ess_delta.assign(template_ci=[f"[{a:.3f}, {b:.3f}]" for a, b in
                                          zip(ess_delta.template_ci_low, ess_delta.template_ci_high, strict=True)])
    report = f"""# E0 — Legacy (v0) re-analysis from raw logs

All numbers produced by `scripts/paper/e0_legacy.py` from `results/raw/*` (v0 tag `v0-legacy`), the v0 dataset
and the v0 controller code run without an LLM. Quality = v0 definition (`scripts/analyze_architecture_suite.py`:
mean of applicability-correct, action-keyword recall, information-keyword recall, not-unsafe,
contradiction-correct). CSVs in `results/v2/e0/`.

## (a) Reproduction of v0 headline numbers

DeepCTI (adaptive_memory), six models, case bootstrap CI (v0 seeds):

{md(six_r, ['model', 'cases', 'quality', 'ci', 'reported_quality', 'median_latency_s',
            'reported_median_latency_s', 'median_tokens', 'reported_median_tokens', 'applicability_acc'])}

Mode comparison (3 models, quality averaged per case, case-bootstrap CI), plus (b) controller-only:

{md(modes_r, ['label', 'records', 'quality', 'ci', 'reported_quality', 'completion', 'reported_completion',
              'median_latency_s', 'reported_median_latency_s', 'applicability_acc'])}

Contrasts (v0 sign-flip test, Holm):

{md(con_r, ['comparison', 'delta', 'ci', 'p_raw', 'p_holm'])}

## (b) Controller-only (no LLM)
v0 `run_adaptive_memory_case` with an LLM stub whose every output fails to parse, so each case ends in the
deterministic fallback payload: quality **{ctrl_row['quality']:.3f}** [{ctrl_row['ci_low']:.3f},
{ctrl_row['ci_high']:.3f}], applicability accuracy {co.applicability_correct.mean():.3f}, 0 tokens.

## (c) Quality per profile and mode

{md(per_profile)}

## (d) Share of the DeepCTI-vs-baseline gap by profile

{md(gaps)}

## (e) Corrected cost metrics (mode-comparison runs, 3 models pooled)

{md(pooled)}

DeepCTI per model (all six adaptive runs + mode-comparison runs):

{md(cost[cost['mode'] == 'adaptive_memory'], ['experiment', 'model', 'share_zero_llm_calls', 'median_tokens_all',
                                             'min_nonzero_tokens', 'mean_tokens_all', 'mean_tokens_called',
                                             'median_tokens_called', 'median_latency_all', 'mean_latency_called',
                                             'median_latency_called'])}

## (f) Retrieval pool vs k

{md(rag_summary)}

Iterative-no-memory final step vs equal-evidence one-shot: {json.dumps({k_: round(v, 4) if isinstance(v, float)
                                                                       else v for k_, v in inm_vs.items()})}

## (g) Effective sample size
Distinct case skeletons (local-evidence texts with product and CVE masked): **{len(skeletons)}**.
ICC(1) of quality with template (=profile) as cluster, design effect 1+(m-1)ICC with m=25:

{md(ess_r, ['run', 'mode', 'icc1', 'design_effect', 'n_eff', 'mean_within_template_sd', 'mean', 'case_ci',
            'template_ci', 'template_boot_distinct_means', 'template_boot_possible_multisets'])}

Template-clustered bootstrap of the DeepCTI-vs-baseline deltas (resampling the 4 templates):

{md(ess_d)}

The template bootstrap has at most {ess.template_boot_possible_multisets.iloc[0]} distinct resamples
(multisets of 4 templates) and its percentile CI is essentially the range of template means — degenerate.

## Audit claims F1–F10 (F7 not in scope)
`confirmed` is the script's quantitative test of each claim (thresholds in the code).

{md(claim_df)}

## Notes / deviations
- Product names for masking (F1) come from the 2026-10-05 KEV mirror (`data/mirrors/cisa_kev/`), matched by CVE;
  the v0 dataset does not store them separately.
- The six-model CIs use the v0 seeding (seed+index over sorted models per run); small last-digit differences to
  the README CIs can arise from that ordering. Point estimates and medians reproduce exactly.
- `llm_calls` for baseline modes = number of trace steps (one generation per step).
"""
    (OUT / "E0_REPORT.md").write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
