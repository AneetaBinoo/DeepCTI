#!/usr/bin/env bash
# prereg-v4 runs. Usage: v4_phase.sh <role>
#   served:  queue for an already-served model ($2)            -> X2C X6 X7 on D7 test
#   mm:      Mistral-Medium: X2C X6 X7 X2V (D7) + E5 E9 (D1)
#   swap:    after mm: small models on GPUs 0,1 (X2C X6 X7), then GLM-4.5-Air on GPUs 0,1 (D1 E2; D7 X2 X5)
#   judge:   H16 judging once all 8 generators' X2C records exist
set -uo pipefail
cd "$(dirname "$0")/../.."
D7="--dataset d7 --spec v3"
V4="X2C X6 X7"
SMALL=(qwen3_4b granite41_8b qwen3_14b mistral_small_24b)
SERVED=(qwen3_4b granite_41_8b qwen3_14b mistral_small_24b)
PORTS=(8302 8321 8309 8310)
log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a logs/runs/v4_phase.log; }
case "$1" in
  served)
    scripts/run/queue.sh test "$2" "$V4" "$D7"; log "V4 DONE $2" ;;
  mm)
    scripts/run/queue.sh test mistral_medium_128b "$V4 X2V" "$D7"
    scripts/run/queue.sh test mistral_medium_128b "E5 E9"
    log "V4 DONE mistral_medium_128b" ;;
  swap)
    until grep -q "V4 DONE mistral_medium_128b" logs/runs/v4_phase.log 2>/dev/null; do sleep 60; done
    tmux kill-window -t deepcti_vllm:mistral_medium_128b 2>/dev/null; sleep 30
    for n in "${SERVED[@]}"; do scripts/serve/launch_models.sh packed "$n"; done
    for i in 0 1 2 3; do
      until curl -s -m 3 "localhost:${PORTS[$i]}/v1/models" | grep -q "${SERVED[$i]}"; do sleep 20; done
    done
    log "small models up"
    for m in "${SMALL[@]}"; do (scripts/run/queue.sh test "$m" "$V4" "$D7"; log "V4 DONE $m") & done
    wait
    for n in "${SERVED[@]}"; do tmux kill-window -t "deepcti_vllm:$n" 2>/dev/null; done; sleep 30
    GPUS=0,1 scripts/serve/launch_models.sh big glm_45_air
    until curl -s -m 3 localhost:8315/v1/models | grep -q glm_45_air; do sleep 30; done
    log "GLM up"
    scripts/run/queue.sh test glm45_air "E2"
    scripts/run/queue.sh test glm45_air "X2 X5" "$D7"
    log "V4 DONE glm45_air" ;;
  judge)
    for m in gemma4_31b granite41_30b llama31_8b mistral_medium_128b "${SMALL[@]}"; do
      until grep -q "V4 DONE $m" logs/runs/v4_phase.log 2>/dev/null; do sleep 60; done
    done
    log "H16 judging start"
    mkdir -p logs/h16
    .venv/bin/python scripts/e11/h16/run_h16.py 2>&1 | tee logs/h16/run_h16.log
    log "H16 DONE" ;;
esac
