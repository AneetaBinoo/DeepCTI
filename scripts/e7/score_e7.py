"""Score E7 runs with VEX-Bench's OWN parser and metrics code.

Run with the eval venv (needs scikit-learn):
  data/external/vex-bench/.venv-eval/bin/python scripts/e7/score_e7.py

For each (system, model): builds parsed.jsonl rows exactly like
evaluate/parse.py::_parse_run (parse_category -> to_binary, RunStats token
fields), then calls evaluate.metrics.compute_metrics (binary F1 with
'exploitable' positive = "status F1"; multiclass macro-F1 over ground-truth
categories = "justification macro-F1"; mean/stdev over runs).
"""

import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "data/external/vex-bench/src"))
from evaluate.metrics import compute_metrics  # noqa: E402
from evaluate.result_parser import normalize_ground_truth, parse_category, to_binary  # noqa: E402

RUNS = ROOT / "runs/e7"
OUT = ROOT / "results/v2/e7"
SEEDS = [0, 1, 2]
tasks = [json.loads(l) for l in (OUT / "subset_tasks.jsonl").read_text().splitlines() if l.strip()]


def ms(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return None, None
    return statistics.mean(vals), (statistics.stdev(vals) if len(vals) > 1 else 0.0)


def build_rows(system, model):
    rows, per_case = [], []
    for t in tasks:
        for seed in SEEDS:
            run_id = f"run_{seed + 1:03d}"
            d = RUNS / system / model / t["task_id"] / run_id
            row = {"task_id": t["task_id"], "run_id": run_id, "cve_id": t["cve_id"],
                   "ground_truth": normalize_ground_truth(t["ground_truth"]),
                   "ground_truth_category": t.get("ground_truth_category"),
                   "predicted": None, "predicted_category": None, "reasoning": None, "status": "ok",
                   "steps": None, "completed": False, "input_tokens": None, "cached_input_tokens": None,
                   "cache_write_tokens": None, "output_tokens": None, "reasoning_tokens": None, "cost_usd": None}
            meta = json.loads((d / "meta.json").read_text()) if (d / "meta.json").exists() else None
            if not (d / "result.json").exists():
                row["status"] = "no_dir" if not d.exists() else "no_result"
            else:
                cat, reasoning = parse_category((d / "result.json").read_text())
                if cat is None:
                    row["status"] = "parse_fail"
                else:
                    row.update(predicted=to_binary(cat), predicted_category=cat, reasoning=reasoning, completed=True)
            if meta:
                row.update(steps=meta["turns"], input_tokens=meta["prompt_tokens"], cached_input_tokens=0,
                           cache_write_tokens=0, output_tokens=meta["completion_tokens"], reasoning_tokens=0)
            rows.append(row)
            if system == "A":
                abst = row["predicted_category"] in (None, "uncertain")
            else:
                abst = bool(meta and meta.get("abstained"))
            per_case.append({
                "system": system, "model": model, "task_id": t["task_id"], "seed": seed,
                "language": t["metadata"]["language"], "gt": row["ground_truth"], "gt_category": row["ground_truth_category"],
                "pred": row["predicted"], "pred_category": row["predicted_category"], "status": row["status"],
                "abstained": abst, "tool_calls": meta["tool_calls"] if meta else None,
                "turns": meta["turns"] if meta else None,
                "tokens": (meta["prompt_tokens"] + meta["completion_tokens"]) if meta else None,
                "seconds": meta["seconds"] if meta else None, "end_reason": meta["end_reason"] if meta else None,
                "rule": meta.get("rule") if meta else None,
                "state": json.dumps(meta.get("state")) if meta and meta.get("state") else None,
                "proposals": meta.get("proposals") if meta else None,
                "verifier_searches": meta.get("verifier_searches") if meta else None,
            })
    return rows, per_case


summary, all_cases, metrics_all = [], [], {}
for system in ["A", "B"]:
    for model in ["gemma_4_31b", "qwen3_14b"]:
        if not (RUNS / system / model).exists():
            continue
        rows, per_case = build_rows(system, model)
        m = compute_metrics(rows)
        dd = OUT / "vexbench_format" / system / model
        dd.mkdir(parents=True, exist_ok=True)
        (dd / "parsed.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        (dd / "metrics.json").write_text(json.dumps(m, indent=2))
        metrics_all[f"{system}/{model}"] = m
        all_cases += per_case
        by_seed = defaultdict(list)
        for c in per_case:
            by_seed[c["seed"]].append(c)
        abst = ms([sum(c["abstained"] for c in cs) / len(cs) for cs in by_seed.values()])
        tools = ms([statistics.mean([c["tool_calls"] for c in cs if c["tool_calls"] is not None]) for cs in by_seed.values() if any(c["tool_calls"] is not None for c in cs)])
        toks = ms([statistics.mean([c["tokens"] for c in cs if c["tokens"] is not None]) for cs in by_seed.values() if any(c["tokens"] is not None for c in cs)])
        done = sum(1 for c in per_case if c["status"] == "ok")
        # selective accuracy on non-abstained answers (category level and binary)
        ans = [c for c in per_case if not c["abstained"] and c["pred"] is not None]
        summary.append({
            "system": system, "model": model, "n_tasks": len(tasks), "n_runs": m["n_runs"],
            "cases_answered": f"{done}/{len(per_case)}",
            "status_f1_mean": m["binary"]["f1"]["mean"], "status_f1_sd": m["binary"]["f1"]["std"],
            "status_precision_mean": m["binary"]["precision"]["mean"], "status_recall_mean": m["binary"]["recall"]["mean"],
            "status_accuracy_mean": m["binary"]["accuracy"]["mean"], "status_accuracy_sd": m["binary"]["accuracy"]["std"],
            "justif_macro_f1_mean": m["multiclass"]["macro_f1"]["mean"], "justif_macro_f1_sd": m["multiclass"]["macro_f1"]["std"],
            "justif_accuracy_mean": m["multiclass"]["accuracy"]["mean"], "justif_accuracy_sd": m["multiclass"]["accuracy"]["std"],
            "abstention_mean": abst[0], "abstention_sd": abst[1],
            "selective_status_acc": (sum(c["pred"] == c["gt"] for c in ans) / len(ans)) if ans else None,
            "selective_category_acc": (sum(c["pred_category"] == c["gt_category"] for c in ans) / len(ans)) if ans else None,
            "tool_calls_mean": tools[0], "tool_calls_sd": tools[1],
            "tokens_per_case_mean": toks[0], "tokens_per_case_sd": toks[1],
            "binary_totals": json.dumps(m["binary"]["totals"]),
        })

with (OUT / "e7_summary.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
    w.writeheader()
    w.writerows(summary)
with (OUT / "e7_per_case.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(all_cases[0].keys()))
    w.writeheader()
    w.writerows(all_cases)

# paired per-seed deltas (B - A) using the same metric code on each single run
deltas = []
for model in ["gemma_4_31b", "qwen3_14b"]:
    if f"A/{model}" not in metrics_all or f"B/{model}" not in metrics_all:
        continue
    for seed in SEEDS:
        per = {}
        for system in ["A", "B"]:
            rows = [json.loads(l) for l in (OUT / "vexbench_format" / system / model / "parsed.jsonl").read_text().splitlines()]
            per[system] = compute_metrics([r for r in rows if r["run_id"] == f"run_{seed + 1:03d}"])
        deltas.append({"model": model, "seed": seed,
                       "status_f1_A": per["A"]["binary"]["f1"]["mean"], "status_f1_B": per["B"]["binary"]["f1"]["mean"],
                       "macro_f1_A": per["A"]["multiclass"]["macro_f1"]["mean"], "macro_f1_B": per["B"]["multiclass"]["macro_f1"]["mean"]})
with (OUT / "e7_per_seed.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(deltas[0].keys()) if deltas else ["model"])
    w.writeheader()
    w.writerows(deltas)

# B diagnostics: decision-rule usage, atom states, end reasons, proposals
diag = {}
for model in ["gemma_4_31b", "qwen3_14b"]:
    cs = [c for c in all_cases if c["system"] == "B" and c["model"] == model and c["rule"]]
    if not cs:
        continue
    st = Counter()
    for c in cs:
        for k, v in json.loads(c["state"]).items():
            st[f"{k}={v}"] += 1
    acc_rej = Counter()
    for t in tasks:
        for seed in SEEDS:
            p = RUNS / "B" / model / t["task_id"] / f"run_{seed + 1:03d}" / "trace.json"
            if p.exists():
                ex = json.loads(p.read_text())["extra"]
                acc_rej["accepted"] += len(ex.get("accepted", []))
                acc_rej["rejected"] += len(ex.get("rejected", []))
                for r in ex.get("rejected", []):
                    acc_rej["rej:" + r["reason"].split(":")[0].split("(")[0].strip()[:60]] += 1
    diag[model] = {"rules": dict(Counter(c["rule"] for c in cs)), "end_reasons": dict(Counter(c["end_reason"] for c in cs)),
                   "atom_states": dict(sorted(st.items())), "proposals": dict(acc_rej.most_common(25)),
                   "pred_category": dict(Counter(c["pred_category"] for c in cs))}
for model in ["gemma_4_31b", "qwen3_14b"]:
    cs = [c for c in all_cases if c["system"] == "A" and c["model"] == model]
    if cs:
        diag.setdefault("A_" + model, {})["pred_category"] = dict(Counter(c["pred_category"] for c in cs))
        diag["A_" + model]["end_reasons"] = dict(Counter(c["end_reason"] for c in cs))
diag["gt_category"] = dict(Counter(t["ground_truth_category"] for t in tasks))
(OUT / "e7_diagnostics.json").write_text(json.dumps(diag, indent=1))

for s in summary:
    print(f"{s['system']} {s['model']:12s} answered={s['cases_answered']} statusF1={s['status_f1_mean']:.3f}±{s['status_f1_sd']:.3f} "
          f"macroF1={s['justif_macro_f1_mean']:.3f}±{s['justif_macro_f1_sd']:.3f} abst={s['abstention_mean']:.3f} "
          f"tools={s['tool_calls_mean']:.1f} tok={s['tokens_per_case_mean']:.0f}")
print(json.dumps(deltas, indent=0))

# paired task-level bootstrap of B - A (metric averaged over the 3 seeds), 1000 resamples, rng seed 0
import random  # noqa: E402

boot = []
for model in ["gemma_4_31b", "qwen3_14b"]:
    if f"A/{model}" not in metrics_all or f"B/{model}" not in metrics_all:
        continue
    rows = {s: [json.loads(l) for l in (OUT / "vexbench_format" / s / model / "parsed.jsonl").read_text().splitlines()] for s in ["A", "B"]}
    by = {s: defaultdict(list) for s in rows}
    for s in rows:
        for r in rows[s]:
            by[s][r["task_id"]].append(r)
    tids = sorted(by["A"])
    rng = random.Random(0)

    def score(sample):
        out = {}
        for s in ["A", "B"]:
            rr = []
            for i, t in enumerate(sample):
                for r in by[s][t]:
                    rr.append({**r, "task_id": f"{t}#{i}"})
            m = compute_metrics(rr)
            out[s] = (m["binary"]["f1"]["mean"], m["multiclass"]["macro_f1"]["mean"])
        return out["B"][0] - out["A"][0], out["B"][1] - out["A"][1]

    d0 = score(tids)
    ds = [score([rng.choice(tids) for _ in tids]) for _ in range(1000)]
    for k, name in [(0, "status_f1"), (1, "justif_macro_f1")]:
        v = sorted(x[k] for x in ds)
        boot.append({"model": model, "metric": name, "delta_B_minus_A": d0[k], "ci95_lo": v[25], "ci95_hi": v[974],
                     "p_boot_delta_le_0": sum(x[k] <= 0 for x in ds) / len(ds)})
with (OUT / "e7_bootstrap.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["model", "metric", "delta_B_minus_A", "ci95_lo", "ci95_hi", "p_boot_delta_le_0"])
    w.writeheader()
    w.writerows(boot)
for b in boot:
    print(b)
