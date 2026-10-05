#!/usr/bin/env bash
# Regenerate every E11 output (results/v3/e11). LLM calls are cached in results/v3/e11/cache/*.jsonl, so a rerun
# with the caches present reproduces the outputs exactly without contacting the endpoints.
set -euo pipefail
cd "$(dirname "$0")"
PY=../../.venv/bin/python
LOG=../../logs/e11
mkdir -p "$LOG"
$PY 01_sample.py      2>&1 | tee "$LOG/01_sample.log"
$PY 02_extract.py     2>&1 | tee "$LOG/02_extract.log"
$PY 03_judge.py       2>&1 | tee "$LOG/03_judge.log"
$PY 04_perturb.py     2>&1 | tee "$LOG/04_perturb.log"
$PY 05_validate.py    2>&1 | tee "$LOG/05_validate.log"
$PY 06_metrics.py     2>&1 | tee "$LOG/06_metrics.log"
$PY 07_dc_records.py  2>&1 | tee "$LOG/07_dc_records.log"
$PY 08_report.py      2>&1 | tee "$LOG/08_report.log"
