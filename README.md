# DeepCTI: An Agentic Framework for Cyber Threat Intelligence Mitigation

This repository contains the code, dataset, prompts, evaluation scripts, and aggregated results for the paper:

**DeepCTI: An Agentic LLM Framework for Cyber Threat Intelligence Mitigation**

DeepCTI is an agentic cyber threat intelligence mitigation-analysis framework. It uses iterative evidence retrieval, memory, reasoning, verification, and report synthesis to generate evidence-grounded mitigation recommendations for SOC analysts.


## Embedding models used

The evaluator uses the same family of sentence embedding models discussed in the meeting:

- `sentence-transformers/all-MiniLM-L6-v2`
- `sentence-transformers/all-mpnet-base-v2`
- `intfloat/e5-base-v2`

These models are used consistently for both generated text and reference text so that cosine similarity is computed in the same embedding manifold.

## Main output files

After evaluation, check:

- `summary_by_mode.csv`
- `semantic_similarity_by_embedding_and_mode.csv`
- `thresholded_match_f1.csv`
- `thresholded_match_f1_pivot.csv`
- `summary_by_llm_model_and_mode.csv`
- `iteration_distribution.csv`
- `paper_ready_tables.tex`

## Important interpretation

Cosine similarity is a continuous semantic-alignment score. It is not an F1 score.

F1 is computed only after thresholding cosine similarity into binary match / non-match labels. The code also creates negative controls by pairing generated outputs with the wrong reference target so that TP, FP, FN, and TN are meaningful.

## Install

```powershell
.\Run.cmd
```


## Full all-model run

Requires Ollama running.

```powershell
.\Run_All.cmd
```
# DeepCTI Artifact


"DeepCTI: An Agentic Framework for Cyber Threat Intelligence Mitigation"

## Contents

- `src/`: DeepCTI implementation and evaluation code
- `data/`: anonymized 100-case mitigation-analysis dataset
- `prompts/`: prompt templates for each execution mode
- `results/`: aggregated results reported in the paper
- `scripts/`: commands for installation and reproduction

## Setup

```powershell
pip install -r requirements.txt
## Manual one-command full run in PowerShell

```powershell
$env:PYTHONPATH="$PWD\src"; foreach ($m in @("gemma4:e4b","llama3.1:8b","qwen2.5:14b","mistral-nemo:12b","gemma3:12b","deepseek-r1:8b")) { $safe=$m.Replace(":","_").Replace(".","").Replace("-","_"); ollama pull $m; python -m deepcti.run_experiment --data-path ".\DeepCTI_LocalIntel_Eval_Dataset_Enhanced_References_100cases.xlsx" --out-dir "runs\$safe`_suggested_full" --models $m --modes one_shot,no_memory,iterative --no-resume; Get-Content "runs\$safe`_suggested_full\predictions.jsonl" | Add-Content "runs\combined_all_models_predictions.jsonl" }; python -m deepcti.evaluate_suggested --predictions "runs\combined_all_models_predictions.jsonl" --out-dir "runs\combined_suggested_eval"
```
