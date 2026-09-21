from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ExperimentConfig:
    experiment_id: str
    condition: str
    seed: int
    models: tuple[str, ...]
    modes: tuple[str, ...]
    max_steps: int
    retrieval_k: int
    temperature: float
    max_output_tokens: int
    ollama_url: str
    dataset_kind: str
    dataset_path: Path
    attack_corpus_path: Path | None
    attack_retrieval_k: int
    output_dir: Path

    @classmethod
    def load(cls, path: str | Path) -> ExperimentConfig:
        config_path = Path(path).resolve()
        raw: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        root = config_path.parent.parent
        dataset_path = Path(raw["dataset"]["path"])
        raw_attack_path = raw["dataset"].get("attack_corpus_path")
        attack_path = Path(raw_attack_path) if raw_attack_path else None
        output_dir = Path(raw.get("output_dir", "runs"))
        return cls(
            experiment_id=str(raw["experiment_id"]),
            condition=str(raw.get("condition", "deepcti_grounded")),
            seed=int(raw["seed"]),
            models=tuple(raw["models"]),
            modes=tuple(raw["modes"]),
            max_steps=int(raw["max_steps"]),
            retrieval_k=int(raw["retrieval_k"]),
            temperature=float(raw["temperature"]),
            max_output_tokens=int(raw.get("max_output_tokens", 2048)),
            ollama_url=str(raw["ollama_url"]).rstrip("/"),
            dataset_kind=str(raw["dataset"]["kind"]),
            dataset_path=(root / dataset_path).resolve() if not dataset_path.is_absolute() else dataset_path,
            attack_corpus_path=(root / attack_path).resolve()
            if attack_path is not None and not attack_path.is_absolute()
            else attack_path,
            attack_retrieval_k=int(raw["dataset"].get("attack_retrieval_k", 8)),
            output_dir=(root / output_dir).resolve() if not output_dir.is_absolute() else output_dir,
        )
