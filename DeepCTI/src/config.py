from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
from typing import Tuple


def _env_path(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    return Path(raw).expanduser().resolve() if raw else default.resolve()


@dataclass
class Settings:
    """Runtime configuration for stepwise CTI deep-research prototype."""

    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parents[1])

    # Data / outputs
    data_path: Path = field(init=False)
    outputs_dir: Path = field(init=False)
    chroma_dir: Path = field(init=False)
    chroma_collection: str = field(default_factory=lambda: os.getenv("CHROMA_COLLECTION", "evidence"))

    # LLM mode: "ollama" or "openai"
    llm_mode: str = field(default_factory=lambda: os.getenv("LLM_MODE", "ollama").strip().lower())

    # Ollama
    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.1:8b"))

    # OpenAI (optional)
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openai_model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini"))

    # Experiment controls
    retrieval_k_baseline: int = field(default_factory=lambda: int(os.getenv("RETRIEVAL_K_BASELINE", "10")))
    retrieval_k_step: int = field(default_factory=lambda: int(os.getenv("RETRIEVAL_K_STEP", "12")))
    inner_loop_max_iters: int = field(default_factory=lambda: int(os.getenv("INNER_LOOP_MAX_ITERS", "1")))
    llm_timeout_sec: int = field(default_factory=lambda: int(os.getenv("LLM_TIMEOUT_SEC", "180")))
    max_cases: int | None = field(default=None)
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "0") == "1")

    # Dataset schema columns
    scenario_cols: Tuple[str, str, str] = (
        "Scenario Step 1: New Info Arrives",
        "Scenario Step 2: New Info Arrives",
        "Scenario Step 3: New Info Arrives",
    )
    expected_update_cols: Tuple[str, str, str] = (
        "Scenario Step 1: Expected Update",
        "Scenario Step 2: Expected Update",
        "Scenario Step 3: Expected Update",
    )
    ground_truth_col: str = "Ground_truth"
    question_col: str = "Questions"

    # Columns excluded from baseline evidence ingestion
    exclude_from_baseline: tuple[str, ...] = (
        "Scenario Notes ",
    )

    def __post_init__(self) -> None:
        default_data = self.project_root / "data" / "evaluation" / "LocalIntel_Eval_Dataset_1.xlsx"
        self.data_path = _env_path("DATA_PATH", default_data)

        # Separate outputs by model + mode for reproducibility
        model_tag = (self.ollama_model if self.llm_mode == "ollama" else self.openai_model).replace(":", "_").replace("/", "_")
        default_outputs = self.project_root / f"outputs_{self.llm_mode}_{model_tag}"
        self.outputs_dir = _env_path("OUTPUTS_DIR", default_outputs)

        default_chroma = self.outputs_dir / "chroma_store"
        self.chroma_dir = _env_path("CHROMA_DIR", default_chroma)

    @property
    def run_metadata(self) -> dict:
        return {
            "llm_mode": self.llm_mode,
            "ollama_model": self.ollama_model,
            "openai_model": self.openai_model,
            "retrieval_k_baseline": self.retrieval_k_baseline,
            "retrieval_k_step": self.retrieval_k_step,
            "inner_loop_max_iters": self.inner_loop_max_iters,
        }