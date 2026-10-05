#!/usr/bin/env bash
# Run experiment blocks for one model sequentially (resumable). Usage: queue.sh <split> <model> "<EXP[:limit]> ..."
set -uo pipefail
cd "$(dirname "$0")/../.."
split="$1"; model="$2"; blocks="$3"
mkdir -p logs/runs
for b in $blocks; do
  exp="${b%%:*}"; lim=""; [[ "$b" == *:* ]] && lim="--limit ${b##*:}"
  for attempt in 1 2 3; do
    echo "[$(date -u +%FT%TZ)] START $split $exp $model $lim (attempt $attempt)"
    .venv/bin/python scripts/run/run_experiment.py --exp "$exp" --split "$split" --model "$model" $lim \
      >> "logs/runs/${split}_${exp}_${model}.log" 2>&1 && { echo "[$(date -u +%FT%TZ)] DONE $exp"; break; }
    echo "[$(date -u +%FT%TZ)] FAILED $exp attempt $attempt (see logs/runs/${split}_${exp}_${model}.log)"; sleep 30
  done
done
echo "[$(date -u +%FT%TZ)] QUEUE FINISHED $split $model"
