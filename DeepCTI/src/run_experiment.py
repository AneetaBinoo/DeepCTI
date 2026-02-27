from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List

from .config import Settings
from .ingest import load_cases, Case
from .orchestrator import run_case


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run stepwise CTI deep-research prototype experiments")
    p.add_argument("--mode", choices=["iterative", "one_shot", "no_memory", "all"], default="iterative")
    p.add_argument("--max-cases", type=int, default=None, help="Run only first N cases")
    p.add_argument("--case-ids", nargs="*", default=None, help="Specific case IDs to run")
    p.add_argument("--data-path", type=str, default=None)
    p.add_argument("--outputs-dir", type=str, default=None)
    p.add_argument(
        "--models",
        nargs="*",
        default=None,
        help='List of Ollama models to run, e.g. --models "phi3:mini" "mistral:7b" "llama3.1:8b"',
    )
    return p.parse_args()


def _filter_cases(cases: List[Case], max_cases: int | None = None, case_ids: List[str] | None = None) -> List[Case]:
    out = cases
    if case_ids:
        wanted = set(case_ids)
        out = [c for c in out if c.case_id in wanted]
    if max_cases is not None:
        out = out[:max_cases]
    return out


def _collect_final_report(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_summary_csv(base_dir: Path, mode: str, cases: List[Case]) -> None:
    rows = []
    for c in cases:
        fp = base_dir / mode / c.case_id / "final_report.json"
        if not fp.exists():
            continue
        rep = _collect_final_report(fp)
        rows.append(
            {
                "case_id": c.case_id,
                "mode": mode,
                "final_decision_support": rep.get("final_decision_support"),
                "ground_truth_overlap": rep.get("ground_truth_overlap"),
                "avg_step_expected_update_overlap": rep.get("avg_step_expected_update_overlap"),
            }
        )

    if not rows:
        return

    out_path = base_dir / f"summary_{mode}.csv"
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _sanitize_model_tag(model_name: str) -> str:
    return model_name.replace(":", "_").replace("/", "_").replace("\\", "_")


def main() -> None:
    args = _parse_args()

    base_settings = Settings()

    if args.data_path:
        base_settings.data_path = Path(args.data_path).expanduser().resolve()
    if args.outputs_dir:
        base_settings.outputs_dir = Path(args.outputs_dir).expanduser().resolve()

    cases = load_cases(
        str(base_settings.data_path),
        scenario_cols=base_settings.scenario_cols,
        expected_update_cols=base_settings.expected_update_cols,
        exclude_from_baseline=base_settings.exclude_from_baseline,
        ground_truth_col=base_settings.ground_truth_col,
        question_col=base_settings.question_col,
    )
    cases = _filter_cases(cases, max_cases=args.max_cases, case_ids=args.case_ids)

    modes = ["iterative", "no_memory", "one_shot"] if args.mode == "all" else [args.mode]
    models_to_run = args.models if args.models else [base_settings.ollama_model]

    print(f"Loaded {len(cases)} cases from {base_settings.data_path}")
    print(f"Modes: {modes}")
    print(f"Models: {models_to_run}")

    for model_name in models_to_run:
        settings = Settings()

        if args.data_path:
            settings.data_path = Path(args.data_path).expanduser().resolve()

        settings.ollama_model = model_name

        model_tag = _sanitize_model_tag(model_name)
        if args.outputs_dir:
            settings.outputs_dir = Path(args.outputs_dir).expanduser().resolve() / f"ollama_{model_tag}"
        else:
            settings.outputs_dir = settings.project_root / f"outputs_ollama_{model_tag}"

        settings.chroma_dir = settings.outputs_dir / "chroma_store"

        settings.outputs_dir.mkdir(parents=True, exist_ok=True)
        settings.chroma_dir.mkdir(parents=True, exist_ok=True)

        print("\n" + "=" * 80)
        print(f"[MODEL] Running model: {model_name}")
        print(f"Outputs: {settings.outputs_dir}")
        print(f"Run metadata: {settings.run_metadata}")
        print("=" * 80)

        meta = {
            "data_path": str(settings.data_path),
            "outputs_dir": str(settings.outputs_dir),
            "modes": modes,
            "run_metadata": settings.run_metadata,
            "num_cases": len(cases),
            "case_ids": [c.case_id for c in cases],
        }
        (settings.outputs_dir / "run_metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        for mode in modes:
            for c in cases:
                print(f"[{model_name}][{mode}] Running {c.case_id} | updates={len(c.scenario_updates)}")
                run_case(
                    settings,
                    c.case_id,
                    c.baseline,
                    c.scenario_updates,
                    expected_updates=c.expected_updates,
                    ground_truth=c.ground_truth,
                    question=c.question,
                    mode=mode,
                )
            _write_summary_csv(settings.outputs_dir, mode, cases)

    print("Done. Check model-specific output folders and summary CSVs.")


if __name__ == "__main__":
    main()