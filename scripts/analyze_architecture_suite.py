from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Any

from deepcti.datasets import load_contextual_jsonl
from deepcti.inference import bootstrap_mean_ci, holm_adjust, paired_sign_flip_pvalue


def _load_runs(root: Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    records = {}
    for path in root.glob("*/*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                records[(str(row["model"]), str(row["mode"]), str(row["case_id"]))] = row
    return records


def _recall(keywords: list[str], text: str) -> float:
    if not keywords:
        return 1.0
    lowered = text.lower()
    return sum(keyword.lower() in lowered for keyword in keywords) / len(keywords)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--baseline-run-root", type=Path)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260819)
    parser.add_argument("--case-limit", type=int)
    parser.add_argument("--primary-mode", default="iterative_memory")
    parser.add_argument(
        "--model",
        action="append",
        dest="selected_models",
        help="Restrict analysis to a model; repeat this option for multiple models.",
    )
    args = parser.parse_args()

    loaded_cases = load_contextual_jsonl(args.dataset)
    if args.case_limit is not None:
        loaded_cases = loaded_cases[: args.case_limit]
    cases = {case.case_id: case for case in loaded_cases}
    records = _load_runs(args.baseline_run_root) if args.baseline_run_root else {}
    records.update(_load_runs(args.run_root))
    if args.selected_models:
        selected_models = set(args.selected_models)
        records = {key: row for key, row in records.items() if key[0] in selected_models}
        missing_models = selected_models - {key[0] for key in records}
        if missing_models:
            raise ValueError(f"No records found for requested models: {sorted(missing_models)}")
    models = sorted({key[0] for key in records})
    modes = sorted({key[1] for key in records})
    expected = {(model, mode, case_id) for model in models for mode in modes for case_id in cases}
    if set(records) != expected:
        missing = sorted(expected - set(records))
        extra = sorted(set(records) - expected)
        raise ValueError(f"Architecture matrix is incomplete; missing={missing[:10]} extra={extra[:10]}")

    rows = []
    for (model, mode, case_id), record in sorted(records.items()):
        reference = cases[case_id].reference
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
        applicability_correct = str(state.get("applicability", "")) == str(
            reference.get("expected_applicability", "")
        )
        action_recall = _recall(list(reference.get("action_keywords", [])), text)
        information_recall = _recall(list(reference.get("information_keywords", [])), text)
        contradiction_correct = contradiction_detected == contradiction_expected
        quality = mean(
            [
                float(applicability_correct),
                action_recall,
                information_recall,
                float(not unsafe),
                float(contradiction_correct),
            ]
        )
        rows.append(
            {
                "model": model,
                "mode": mode,
                "case_id": case_id,
                "profile_kind": cases[case_id].asset_context.get("profile_kind", ""),
                "quality": quality,
                "applicability_correct": int(applicability_correct),
                "action_keyword_recall": action_recall,
                "information_need_recall": information_recall,
                "unsafe_recommendation": int(unsafe),
                "contradiction_correct": int(contradiction_correct),
                "completed": int(bool(record.get("completed"))),
                "steps": int(record.get("steps_executed", 0)),
                "latency_s": float(record.get("usage", {}).get("total_duration_ms", 0)) / 1000,
                "tokens": int(record.get("usage", {}).get("prompt_tokens", 0))
                + int(record.get("usage", {}).get("completion_tokens", 0)),
                "supported_fraction": float(
                    record.get("final_claim_metrics", {}).get("supported_fraction", 0)
                ),
            }
        )

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["model"], row["mode"])].append(row)
    summaries = []
    for index, ((model, mode), items) in enumerate(sorted(grouped.items())):
        quality = [float(item["quality"]) for item in items]
        summaries.append(
            {
                "model": model,
                "mode": mode,
                "cases": len(items),
                "mean_quality": mean(quality),
                "quality_ci95": bootstrap_mean_ci(quality, seed=args.seed + index),
                "applicability_accuracy": mean(float(item["applicability_correct"]) for item in items),
                "unsafe_rate": mean(float(item["unsafe_recommendation"]) for item in items),
                "contradiction_accuracy": mean(float(item["contradiction_correct"]) for item in items),
                "completion_rate": mean(float(item["completed"]) for item in items),
                "median_steps": median(float(item["steps"]) for item in items),
                "median_latency_s": median(float(item["latency_s"]) for item in items),
                "median_tokens": median(float(item["tokens"]) for item in items),
            }
        )

    comparisons = []
    raw_p = {}
    by_key = {(row["model"], row["mode"], row["case_id"]): row for row in rows}
    for model in models:
        for comparator in ("evidence_equal_one_shot", "iterative_no_memory", "rag_once"):
            required_keys = {
                (model, mode, case_id)
                for mode in (args.primary_mode, comparator)
                for case_id in cases
            }
            if not required_keys.issubset(by_key):
                continue
            differences = [
                float(by_key[(model, args.primary_mode, case_id)]["quality"])
                - float(by_key[(model, comparator, case_id)]["quality"])
                for case_id in sorted(cases)
            ]
            name = f"{model}:{args.primary_mode}-vs-{comparator}"
            p_value = paired_sign_flip_pvalue(differences, seed=args.seed + len(comparisons))
            raw_p[name] = p_value
            comparisons.append(
                {
                    "comparison": name,
                    "mean_delta": mean(differences),
                    "delta_ci95": bootstrap_mean_ci(differences, seed=args.seed + 100 + len(comparisons)),
                    "p_raw": p_value,
                }
            )
    adjusted = holm_adjust(raw_p)
    for item in comparisons:
        item["p_holm"] = adjusted[item["comparison"]]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "architecture_case_metrics.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    payload = {"summaries": summaries, "comparisons": comparisons, "case_rows": rows}
    (args.output_dir / "architecture_results.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
