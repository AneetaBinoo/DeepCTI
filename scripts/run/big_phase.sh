#!/usr/bin/env bash
# Big-model phase: Mistral-Medium-128B on GPUs 0,1 once the small models' D7 calib runs are done;
# GLM-4.5-Air on GPUs 3,4 once Nemotron's addendum (GPU 4) and the E11-D7 judging (GPU 3) are done.
set -uo pipefail
cd "$(dirname "$0")/../.."
wait_for() { until grep -q "QUEUE FINISHED $1" "$2" 2>/dev/null; do sleep 60; done; }
run_model() {  # $1 model name
  m="$1"
  scripts/run/queue.sh test "$m" "E2 E4" 2>&1 | tee -a "logs/runs/queue_big_$m.log"
  scripts/run/queue.sh test "$m" "X4" "--spec v3" 2>&1 | tee -a "logs/runs/queue_big_$m.log"
  scripts/run/queue.sh test "$m" "X2 X5" "--dataset d7 --spec v3" 2>&1 | tee -a "logs/runs/queue_big_$m.log"
  scripts/run/queue.sh calib "$m" "X2" "--dataset d7 --spec v3" 2>&1 | tee -a "logs/runs/queue_big_$m.log"
  echo "[$(date -u +%FT%TZ)] BIG DONE $m" | tee -a "logs/runs/queue_big_$m.log"
}
if [[ "$1" == "medium" ]]; then
  wait_for "calib qwen3_14b" logs/runs/queue_d7c_qwen3_14b.log
  wait_for "calib mistral_small_24b" logs/runs/queue_d7c_mistral_small_24b.log
  for w in qwen3_4b granite_41_8b qwen3_14b mistral_small_24b; do tmux kill-window -t "deepcti_vllm:$w" 2>/dev/null; done
  sleep 20
  scripts/serve/launch_models.sh big mistral_medium_128b
  until curl -s -m 3 localhost:8319/v1/models | grep -q mistral_medium; do sleep 30; done
  run_model mistral_medium_128b
elif [[ "$1" == "glm" ]]; then
  wait_for "test nemotron_super_49b" logs/runs/queue_x4_nemotron_super_49b.log
  until [ -f results/v3/e11_d7/E11_D7_REPORT.md ]; do sleep 60; done
  for w in granite_41_30b nemotron_super_49b; do tmux kill-window -t "deepcti_vllm:$w" 2>/dev/null; done
  sleep 20
  scripts/serve/launch_models.sh big glm_45_air
  until curl -s -m 3 localhost:8315/v1/models | grep -q glm_45_air; do sleep 30; done
  run_model glm45_air
fi
