#!/usr/bin/env bash
# Launch the full pre-registered test matrix in tmux session deepcti_test (one window per model queue).
set -euo pipefail
cd "$(dirname "$0")/../.."
git tag -l prereg-v1 | grep -q prereg-v1 || { echo "tag prereg-v1 missing"; exit 1; }
S=deepcti_test
tmux has-session -t $S 2>/dev/null || tmux new-session -d -s $S -n info
q() { tmux new-window -t $S -n "$1_$2" "bash -lc 'scripts/run/queue.sh $1 $2 \"$3\" 2>&1 | tee -a logs/runs/queue_$1_$2.log; scripts/run/queue.sh calib $2 E2 2>&1 | tee -a logs/runs/queue_calib_$2.log; exec bash'"; }
q test none              "E2 E4 E5 E3"
q test qwen3_14b         "E2 E4 E5 KM E9 ABL E3:200"
q test gemma4_31b        "E2 E4 E5 E9"
q test mistral_small_24b "E2 E4 E9 ABL E3:200"
q test llama31_8b        "E2 E4 E5 E9"
q test granite41_8b      "E2 E4 E9"
q test qwen3_4b          "E2 E4 E9"
