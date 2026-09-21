from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Any

from deepcti.inference import bootstrap_mean_ci, holm_adjust, paired_sign_flip_pvalue

EXPERIMENT_ID = "deepcti_mode_comparison_100_2026"
PRIMARY_MODE = "adaptive_memory"
MODE_ORDER = (
    "adaptive_memory",
    "evidence_equal_one_shot",
    "rag_once",
    "iterative_no_memory",
    "initial_one_shot",
)
MODE_LABELS = {
    "adaptive_memory": "DeepCTI",
    "evidence_equal_one_shot": "Equal-evidence one-shot",
    "rag_once": "RAG once",
    "iterative_no_memory": "Iterative no-memory",
    "initial_one_shot": "Initial one-shot",
}
EXPECTED_MODELS = {"llama3.1:8b", "qwen2.5:7b", "mistral:latest"}
EXPECTED_CASES = 100
EXPECTED_RECORDS = EXPECTED_CASES * len(EXPECTED_MODELS) * len(MODE_ORDER)
SEED = 20260819


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    analysis = root / "analysis" / EXPERIMENT_ID
    metrics_path = analysis / "architecture_case_metrics.csv"
    rows = list(csv.DictReader(metrics_path.open(encoding="utf-8")))
    keys = {(row["model"], row["mode"], row["case_id"]) for row in rows}
    models = {row["model"] for row in rows}
    modes = {row["mode"] for row in rows}
    cases = {row["case_id"] for row in rows}
    if len(rows) != EXPECTED_RECORDS or len(keys) != EXPECTED_RECORDS:
        raise ValueError(f"Expected {EXPECTED_RECORDS} unique records; got {len(rows)} rows/{len(keys)} keys.")
    if models != EXPECTED_MODELS or modes != set(MODE_ORDER) or len(cases) != EXPECTED_CASES:
        raise ValueError(
            f"Unexpected matrix dimensions: models={sorted(models)}, modes={sorted(modes)}, "
            f"cases={len(cases)}."
        )

    by_mode_case: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    by_mode: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_mode_case[(row["mode"], row["case_id"])].append(row)
        by_mode[row["mode"]].append(row)
    if any(len(items) != len(EXPECTED_MODELS) for items in by_mode_case.values()):
        raise ValueError("Every mode/case cluster must contain exactly one record from each model.")

    case_means: dict[str, dict[str, float]] = defaultdict(dict)
    summaries: list[dict[str, Any]] = []
    for index, mode in enumerate(MODE_ORDER):
        clustered = []
        for case_id in sorted(cases):
            value = mean(float(row["quality"]) for row in by_mode_case[(mode, case_id)])
            case_means[mode][case_id] = value
            clustered.append(value)
        ci_low, ci_high = bootstrap_mean_ci(clustered, seed=SEED + index)
        mode_rows = by_mode[mode]
        summaries.append(
            {
                "mode": mode,
                "display_mode": MODE_LABELS[mode],
                "matched_cases": EXPECTED_CASES,
                "models": len(EXPECTED_MODELS),
                "records": len(mode_rows),
                "mean_quality": mean(clustered),
                "cluster_ci_low": ci_low,
                "cluster_ci_high": ci_high,
                "applicability_accuracy": mean(float(row["applicability_correct"]) for row in mode_rows),
                "unsafe_rate": mean(float(row["unsafe_recommendation"]) for row in mode_rows),
                "completion_rate": mean(float(row["completed"]) for row in mode_rows),
                "median_latency_s": median(float(row["latency_s"]) for row in mode_rows),
            }
        )

    comparisons: list[dict[str, Any]] = []
    raw_p: dict[str, float] = {}
    for index, comparator in enumerate(mode for mode in MODE_ORDER if mode != PRIMARY_MODE):
        differences = [
            case_means[PRIMARY_MODE][case_id] - case_means[comparator][case_id]
            for case_id in sorted(cases)
        ]
        ci_low, ci_high = bootstrap_mean_ci(differences, seed=SEED + 100 + index)
        name = f"DeepCTI vs {MODE_LABELS[comparator]}"
        p_raw = paired_sign_flip_pvalue(differences, seed=SEED + 200 + index)
        raw_p[name] = p_raw
        comparisons.append(
            {
                "comparison": name,
                "comparator_mode": comparator,
                "matched_cases": EXPECTED_CASES,
                "mean_delta": mean(differences),
                "cluster_ci_low": ci_low,
                "cluster_ci_high": ci_high,
                "p_raw": p_raw,
            }
        )
    adjusted = holm_adjust(raw_p)
    for item in comparisons:
        item["p_holm"] = adjusted[item["comparison"]]

    payload = {
        "experiment_id": EXPERIMENT_ID,
        "design": {
            "matched_cases": EXPECTED_CASES,
            "models": sorted(EXPECTED_MODELS),
            "modes": list(MODE_ORDER),
            "records": EXPECTED_RECORDS,
            "unit_of_resampling": "case; quality first averaged across the three models",
            "label_status": "deterministic synthetic labels; not independently expert annotated",
        },
        "summaries": summaries,
        "comparisons": comparisons,
    }
    (analysis / "mode_comparison_case_clustered.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    write_csv(analysis / "mode_comparison_summary.csv", summaries)
    write_csv(analysis / "mode_comparison_contrasts.csv", comparisons)


if __name__ == "__main__":
    main()
