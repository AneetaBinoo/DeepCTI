#!/usr/bin/env bash
# Regenerate every E11-on-D7 (H15) output in results/v3/e11_d7. LLM calls are cached in results/v3/e11_d7/cache/,
# so a rerun with the caches present reproduces the outputs without contacting the judge endpoints.
set -euo pipefail
cd "$(dirname "$0")"
PY=../../../.venv/bin/python
LOG=../../../logs/e11d7
mkdir -p "$LOG"
$PY d01_sample.py                      2>&1 | tee "$LOG/01_sample.log"
$PY d02_extract.py                     2>&1 | tee "$LOG/02_extract.log"
$PY d03_judge.py --stages primary      2>&1 | tee "$LOG/03_judge_primary.log"
$PY d03_judge.py --stages sensitivity  2>&1 | tee "$LOG/03_judge_sensitivity.log"
$PY d04_transfer_check.py              2>&1 | tee "$LOG/04_transfer.log"
$PY d06_metrics.py                     2>&1 | tee "$LOG/06_metrics.log"
$PY d07_records.py                     2>&1 | tee "$LOG/07_records.log"
$PY d08_report.py                      2>&1 | tee "$LOG/08_report.log"
