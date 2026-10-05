#!/usr/bin/env bash
# POST HOC (prereg/DEVIATIONS.md D23): regenerate every E11-D7b output in results/v3/e11_d7b — DCv21b vs DC / DCv21
# on exactly the H15 sample triples, with the unchanged E11-D7 pipeline. DCv21b LLM calls are cached in
# results/v3/e11_d7b/cache/; DC/DCv21 judgements are reused from results/v3/e11_d7 (never re-judged). With the caches
# present a rerun reproduces the outputs without contacting the judge endpoints.
set -euo pipefail
cd "$(dirname "$0")"
PY=../../../.venv/bin/python
LOG=../../../logs/e11d7b
mkdir -p "$LOG" ../../../results/v3/e11_d7b
$PY b02_extract.py                     2>&1 | tee "$LOG/02_extract.log"
$PY b03_judge.py --stages primary      2>&1 | tee "$LOG/03_judge_primary.log"
$PY b03_judge.py --stages sensitivity  2>&1 | tee "$LOG/03_judge_sensitivity.log"
$PY b06_metrics.py                     2>&1 | tee "$LOG/06_metrics.log"
$PY b07_records.py                     2>&1 | tee "$LOG/07_records.log"
$PY b08_report.py                      2>&1 | tee "$LOG/08_report.log"
