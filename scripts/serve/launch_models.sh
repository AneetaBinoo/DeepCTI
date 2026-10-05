#!/usr/bin/env bash
# Launch the local DeepCTI v2 model panel in a tmux session (one window per model).
# Gemma-4-31B (port 8103, GPU 2) and Llama-3.1-8B (remote :8008) are served elsewhere.
set -euo pipefail
VLLM_PY="${VLLM_PYTHON:-/home/student/.conda/envs/falcon/bin/python}"
LOG_DIR="$(cd "$(dirname "$0")/../.." && pwd)/logs/vllm"
SESSION=deepcti_vllm
mkdir -p "$LOG_DIR"
# name|hf_id|gpu|port|extra args
MODELS=(
  "qwen3_4b|Qwen/Qwen3-4B|0|8302|--enable-auto-tool-choice --tool-call-parser hermes --reasoning-parser qwen3"
  "granite_41_8b|ibm-granite/granite-4.1-8b|1|8321|--enable-auto-tool-choice --tool-call-parser granite4"
  "qwen3_14b|Qwen/Qwen3-14B|3|8309|--enable-auto-tool-choice --tool-call-parser hermes --reasoning-parser qwen3"
  "mistral_small_24b|mistralai/Mistral-Small-3.2-24B-Instruct-2506|4|8310|--enable-auto-tool-choice --tool-call-parser mistral --tokenizer-mode mistral --config-format mistral --load-format mistral --limit-mm-per-prompt {\\\"image\\\":0}"
)
tmux has-session -t "$SESSION" 2>/dev/null || tmux new-session -d -s "$SESSION" -n init
for spec in "${MODELS[@]}"; do
  IFS='|' read -r name hf gpu port extra <<< "$spec"
  if [[ -n "${1:-}" && "$1" != "$name" ]]; then continue; fi
  cmd="CUDA_VISIBLE_DEVICES=$gpu VLLM_USE_FLASHINFER_SAMPLER=0 $VLLM_PY -m vllm.entrypoints.openai.api_server \
--model $hf --served-model-name $name --port $port --host 0.0.0.0 --max-model-len 32768 \
--gpu-memory-utilization 0.85 --enable-prefix-caching --seed 20261005 $extra 2>&1 | tee $LOG_DIR/$name.log"
  tmux new-window -t "$SESSION" -n "$name" "bash -lc '$cmd; exec bash'"
done
