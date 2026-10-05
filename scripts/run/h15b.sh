#!/usr/bin/env bash
# X2B (DCv21b) for the small models once fix_small has served them, then Granite-30B + Nemotron for judging.
set -uo pipefail
cd "$(dirname "$0")/../.."
VLLM_PY=/home/student/.conda/envs/falcon/bin/python
until grep -q "small-model fix runs launched" logs/runs/fix_small.log 2>/dev/null; do sleep 60; done
for m in qwen3_4b granite41_8b qwen3_14b mistral_small_24b; do
  until grep -q "QUEUE FINISHED test $m" "logs/runs/queue_fix_$m.log" 2>/dev/null; do sleep 30; done
  scripts/run/queue.sh test "$m" X2B "--dataset d7 --spec v3" 2>&1 | tee -a "logs/runs/queue_x2b_$m.log"
done
for w in qwen3_4b granite_41_8b qwen3_14b mistral_small_24b; do tmux kill-window -t "deepcti_vllm:$w" 2>/dev/null; done
sleep 20
scripts/serve/launch_models.sh packed granite_41_30b
scripts/serve/launch_models.sh packed nemotron_super_49b
until curl -s -m 3 localhost:8322/v1/models | grep -q granite_41_30b; do sleep 20; done
scripts/run/queue.sh test granite41_30b X2B "--dataset d7 --spec v3" 2>&1 | tee -a logs/runs/queue_x2b_granite41_30b.log
until curl -s -m 3 localhost:8313/v1/models | grep -q nemotron; do sleep 20; done
echo "[$(date -u +%FT%TZ)] H15B GENERATION DONE; judges up"
