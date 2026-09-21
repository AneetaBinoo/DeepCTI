from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deepcti.datasets import load_contextual_jsonl
from deepcti.io import file_sha256

EXPERIMENT_ID = "deepcti_mode_comparison_100_2026"
MODELS = ("llama3.1:8b", "qwen2.5:7b", "mistral:latest")
MODES = (
    "adaptive_memory",
    "evidence_equal_one_shot",
    "rag_once",
    "iterative_no_memory",
    "initial_one_shot",
)
EXPECTED_RECORDS = 100 * len(MODELS) * len(MODES)


def write_status(path: Path, *, stage: str, status: str, details: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "updated_at": datetime.now(UTC).isoformat(),
                "stage": stage,
                "status": status,
                "details": details,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def count_records(run_root: Path) -> tuple[int, int]:
    keys: set[tuple[str, str, str]] = set()
    lines = 0
    for path in run_root.glob("*/*.jsonl"):
        for raw in path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            lines += 1
            row = json.loads(raw)
            keys.add((str(row["model"]), str(row["mode"]), str(row["case_id"])))
    return lines, len(keys)


def run(command: list[str], *, root: Path) -> None:
    print("RUN", subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, cwd=root, check=True)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    config = root / "config" / "mode_comparison_100.yaml"
    dataset = root / "data" / "derived" / "deepcti_kev_contextual_synthetic_100_v1.jsonl"
    run_root = root / "runs" / EXPERIMENT_ID
    analysis = root / "analysis" / EXPERIMENT_ID
    status_path = analysis / "RUN_STATUS.json"
    cases = load_contextual_jsonl(dataset)
    details: dict[str, Any] = {
        "experiment_id": EXPERIMENT_ID,
        "cases": len(cases),
        "models": list(MODELS),
        "modes": list(MODES),
        "expected_records": EXPECTED_RECORDS,
        "dataset_sha256": file_sha256(dataset),
        "label_status": "deterministic synthetic labels; not independently expert annotated",
    }
    try:
        if len(cases) != 100 or len({case.case_id for case in cases}) != 100:
            raise ValueError("The frozen mode-comparison dataset must contain 100 unique cases.")
        write_status(status_path, stage="ollama_matrix", status="running", details=details)
        run(
            [
                sys.executable,
                "-m",
                "deepcti.cli",
                "run",
                "--config",
                str(config),
                "--max-cases",
                "100",
                "--resume",
            ],
            root=root,
        )
        lines, unique = count_records(run_root)
        details.update({"jsonl_records": lines, "unique_records": unique})
        if lines != EXPECTED_RECORDS or unique != EXPECTED_RECORDS:
            raise ValueError(
                f"Incomplete experiment matrix: lines={lines}, unique={unique}, "
                f"expected={EXPECTED_RECORDS}."
            )
        write_status(status_path, stage="analysis", status="running", details=details)
        run(
            [
                sys.executable,
                str(root / "scripts" / "analyze_architecture_suite.py"),
                "--run-root",
                str(run_root),
                "--dataset",
                str(dataset),
                "--output-dir",
                str(analysis),
                "--seed",
                "20260819",
                "--case-limit",
                "100",
                "--primary-mode",
                "adaptive_memory",
            ],
            root=root,
        )
        required = (
            analysis / "architecture_results.json",
            analysis / "architecture_case_metrics.csv",
        )
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise FileNotFoundError(f"Missing analysis outputs: {missing}")
        write_status(status_path, stage="complete", status="complete", details=details)
        print(f"COMPLETE records={unique}/{EXPECTED_RECORDS}", flush=True)
    except Exception as exc:
        try:
            lines, unique = count_records(run_root)
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            lines, unique = 0, 0
        details.update(
            {
                "jsonl_records": lines,
                "unique_records": unique,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        write_status(status_path, stage="failed", status="failed", details=details)
        raise


if __name__ == "__main__":
    main()
