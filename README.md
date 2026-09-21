# DeepCTI

DeepCTI combines public vulnerability information with local asset evidence to produce mitigation guidance. It records the current decision state, identifies missing or conflicting facts, and processes evidence in stages. A local Ollama model writes the analyst-facing response only after the controller resolves the decision state.

The repository includes the source code, 100-case dataset, experiment settings, raw run records, analysis files, figures, and result workbook. Ollama models and model checkpoints are not included.

## Pipeline

1. Load public CTI and local observations with evidence IDs and provenance.
2. Update the evidence-backed state for product presence, affected version, rollback capability, approval, and conflicts.
3. Determine applicability, information needs, and allowed actions with fixed controller rules.
4. Generate a response when the state is resolved.
5. Validate the response. One repair attempt is allowed before a safe fallback is returned.

The paper uses the name **DeepCTI** for the `adaptive_memory` execution mode.

## Project layout

```text
DeepCTI_Project/
├── config/                  Experiment settings
├── data/derived/            100-case dataset
├── results/
│   ├── raw/                 JSONL run records and manifests
│   ├── analysis/            Case metrics and statistical results
│   ├── figures/             PNG and PDF figures
│   ├── spreadsheet/         Result workbook
│   └── summary_tables/      CSV result tables
├── scripts/                 Experiment and analysis scripts
├── src/deepcti/             Python package
├── tests/                   Tests
├── pyproject.toml           Package settings
└── requirements.txt         Pinned dependencies
```

## Dataset

The dataset is stored at `data/derived/deepcti_kev_contextual_synthetic_100_v1.jsonl`. It contains 100 cases based on CISA Known Exploited Vulnerabilities records. The cases are evenly divided among affected, not-applicable, uncertain, and contradictory local contexts.

The local contexts and reference labels are deterministic synthetic fixtures. They have not been independently annotated by security analysts.

## Experiments

| Experiment | Design | Records |
|---|---|---:|
| `deepcti_candidate_100_2026` | 100 cases × 3 models × DeepCTI | 300 |
| `deepcti_expanded_models_100_2026` | 100 cases × 3 additional models × DeepCTI | 300 |
| `deepcti_mode_comparison_100_2026` | 100 cases × 3 models × 5 modes | 1,500 |

The raw results contain 2,100 unique model, mode, and case combinations. All 600 DeepCTI records completed. The mode comparison retains 16 baseline records that did not complete normally.

### DeepCTI across six models

| Model | Mean quality (95% CI) | Median latency (s) | Median tokens |
|---|---:|---:|---:|
| Llama 3.1 8B | 0.886 [0.862, 0.909] | 1.62 | 509.5 |
| Mistral | 0.910 [0.884, 0.934] | 2.35 | 704.0 |
| Qwen 2.5 7B | 0.925 [0.898, 0.949] | 2.29 | 602.0 |
| Qwen 3 8B | 0.923 [0.897, 0.948] | 2.29 | 598.0 |
| Gemma 3 12B | 0.925 [0.898, 0.949] | 3.35 | 626.5 |
| Phi-4 14B | 0.925 [0.898, 0.949] | 4.71 | 609.0 |

### Execution-mode comparison

| Mode | Mean quality (case-clustered 95% CI) | Completion | Median latency (s) |
|---|---:|---:|---:|
| DeepCTI | 0.907 [0.883, 0.930] | 1.000 | 1.56 |
| RAG once | 0.808 [0.783, 0.832] | 0.987 | 7.86 |
| Equal-evidence one-shot | 0.805 [0.774, 0.835] | 0.990 | 6.93 |
| Iterative no-memory | 0.803 [0.776, 0.829] | 0.977 | 19.67 |
| Initial one-shot | 0.605 [0.563, 0.644] | 0.993 | 5.78 |

Applicability accuracy and unsafe-action rate are checks against the benchmark references and forbidden-action terms. They are not general safety measures. Detailed results are under `results/analysis/` and `results/raw/`.

## Setup

Requirements:

- Python 3.11 or newer
- Ollama at `http://127.0.0.1:11434`
- The model tags listed in the experiment configurations

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e . --no-deps
```

The experiments used `llama3.1:8b`, `qwen2.5:7b`, `mistral:latest`, `qwen3:8b`, `gemma3:12b`, and `phi4:14b`. Install these models separately through Ollama.

## Run

Original three-model evaluation:

```powershell
python -m deepcti.cli run --config config/deepcti_candidate_100.yaml --max-cases 100 --resume
```

Additional three-model evaluation:

```powershell
python -m deepcti.cli run --config config/deepcti_expanded_models_100.yaml --max-cases 100 --resume
```

Five-mode comparison:

```powershell
python scripts/run_mode_comparison_100.py
python scripts/analyze_mode_comparison_100.py
```

Completed records are skipped when `--resume` is used.

## Tests

```powershell
python -m pytest -q -p no:cacheprovider
python -m ruff check --no-cache .
```
