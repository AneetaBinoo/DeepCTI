from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from datetime import UTC, datetime

from .config import ExperimentConfig
from .datasets import (
    build_kev_seed_cases,
    fetch_public_benchmarks,
    load_athenabench_cases,
    load_cisa_kev,
    load_contextual_jsonl,
    load_legacy_xlsx,
)
from .io import append_jsonl, file_sha256, write_json
from .ollama import MockClient, OllamaClient
from .orchestrator import run_athenabench_model_only_case, run_case


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="deepcti")
    commands = root.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("fetch-data", help="Download versionable public benchmark inputs.")
    fetch.add_argument("--data-root", default="data")
    kev = commands.add_parser("build-kev-seeds", help="Create unannotated KEV seed cases.")
    kev.add_argument("--kev", default="data/public/cisa_kev.json")
    kev.add_argument("--output", default="data/derived/kev_seed_cases.json")
    kev.add_argument("--limit", type=int)
    run = commands.add_parser("run", help="Run the controlled experiment.")
    run.add_argument("--config", default="config/experiment.yaml")
    run.add_argument("--mock", action="store_true")
    run.add_argument("--max-cases", type=int)
    run.add_argument("--case-start", type=int, default=0)
    run.add_argument("--models", nargs="*")
    run.add_argument("--modes", nargs="*")
    run.add_argument("--overwrite", action="store_true")
    run.add_argument("--resume", action="store_true")
    check = commands.add_parser("ollama-models", help="List models visible through the Ollama API.")
    check.add_argument("--url", default="http://127.0.0.1:11434")
    return root


def select_cases(cases: Sequence, *, start: int, maximum: int | None) -> list:
    if start < 0:
        raise ValueError("--case-start must be non-negative.")
    if maximum is not None and maximum <= 0:
        raise ValueError("--max-cases must be positive.")
    selected = list(cases[start:])
    return selected[:maximum] if maximum is not None else selected


def main() -> None:
    args = parser().parse_args()
    if args.command == "fetch-data":
        print(
            json.dumps(
                {key: str(value) for key, value in fetch_public_benchmarks(args.data_root).items()}, indent=2
            )
        )
        return
    if args.command == "build-kev-seeds":
        cases = build_kev_seed_cases(load_cisa_kev(args.kev), limit=args.limit)
        write_json(args.output, cases)
        print(f"Wrote {len(cases)} KEV seed cases to {args.output}")
        return
    if args.command == "ollama-models":
        print(json.dumps(OllamaClient(args.url).models(), indent=2))
        return

    config = ExperimentConfig.load(args.config)
    if config.dataset_kind == "legacy_xlsx":
        cases = load_legacy_xlsx(config.dataset_path)
    elif config.dataset_kind == "athenabench_rms":
        cases = load_athenabench_cases(
            config.dataset_path,
            attack_corpus_path=config.attack_corpus_path,
            attack_retrieval_k=config.attack_retrieval_k,
        )
    elif config.dataset_kind == "contextual_jsonl":
        cases = load_contextual_jsonl(config.dataset_path)
    else:
        raise ValueError(f"Unsupported experiment dataset: {config.dataset_kind}")
    cases = select_cases(cases, start=args.case_start, maximum=args.max_cases)
    models = tuple(args.models or config.models)
    modes = tuple(args.modes or config.modes)
    client = (
        MockClient() if args.mock else OllamaClient(config.ollama_url, num_predict=config.max_output_tokens)
    )
    inventory = client.models()
    selected_inventory = [
        item for item in inventory if item.get("name") in models or item.get("model") in models
    ]
    run_root = config.output_dir / config.experiment_id
    write_json(
        run_root / "manifest.json",
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "config": config.__dict__,
            "case_count": len(cases),
            "case_selection": {
                "start_zero_based": args.case_start,
                "maximum": args.max_cases,
                "case_ids": [case.case_id for case in cases],
            },
            "models": models,
            "modes": modes,
            "mock": bool(args.mock),
            "model_inventory": selected_inventory,
            "dataset_sha256": file_sha256(config.dataset_path),
            "attack_corpus_sha256": file_sha256(config.attack_corpus_path)
            if config.attack_corpus_path
            else None,
            "reference_isolation": "Answers and benchmark technique metadata are scoring-only.",
        },
    )
    for model in models:
        for mode in modes:
            output = run_root / model.replace(":", "_") / f"{mode}.jsonl"
            if output.exists():
                if args.overwrite and args.resume:
                    raise ValueError("Choose either --overwrite or --resume, not both.")
                if not args.overwrite and not args.resume:
                    raise FileExistsError(f"Refusing to overwrite existing run: {output}")
                if args.overwrite:
                    output.unlink()
            completed_ids: set[str] = set()
            if args.resume and output.exists():
                with output.open(encoding="utf-8") as handle:
                    completed_ids = {
                        str(record.get("case_id"))
                        for line in handle
                        if line.strip()
                        for record in [json.loads(line)]
                    }
            for case in cases:
                if case.case_id in completed_ids:
                    print(f"[{model}][{mode}] {case.case_id} skipped=resume")
                    continue
                if config.condition == "athenabench_model_only":
                    if mode != "benchmark_direct":
                        raise ValueError(
                            "The AthenaBench model-only condition requires benchmark_direct mode."
                        )
                    result = run_athenabench_model_only_case(
                        case=case,
                        model=model,
                        client=client,
                        temperature=config.temperature,
                    )
                else:
                    result = run_case(
                        case=case,
                        mode=mode,
                        model=model,
                        client=client,
                        retrieval_k=config.retrieval_k,
                        max_steps=config.max_steps,
                        temperature=config.temperature,
                    )
                append_jsonl(output, result)
                print(f"[{model}][{mode}] {case.case_id} completed={result['completed']}")


if __name__ == "__main__":
    main()
