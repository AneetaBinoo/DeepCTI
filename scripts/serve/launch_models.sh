#!/usr/bin/env bash
# Launch the local DeepCTI model panel in tmux session deepcti_vllm (one window per model).
# Gemma-4-31B (port 8103, GPU 2) and Llama-3.1-8B (remote :8008) are served elsewhere.
# Usage: launch_models.sh <layout> [name]   layouts: packed (default), big
set -euo pipefail
VLLM_PY="${VLLM_PYTHON:-/home/student/.conda/envs/falcon/bin/python}"
LOG_DIR="$(cd "$(dirname "$0")/../.." && pwd)/logs/vllm"
SESSION=deepcti_vllm
LAYOUT="${1:-packed}"
mkdir -p "$LOG_DIR"
# name|hf_id|gpus|port|gpu_mem_util|extra args
PACKED=(
  "qwen3_4b|Qwen/Qwen3-4B|0|8302|0.18|--enable-auto-tool-choice --tool-call-parser hermes --reasoning-parser qwen3"
  "granite_41_8b|ibm-granite/granite-4.1-8b|0|8321|0.25|--enable-auto-tool-choice --tool-call-parser granite4"
  "qwen3_14b|Qwen/Qwen3-14B|0|8309|0.45|--enable-auto-tool-choice --tool-call-parser hermes --reasoning-parser qwen3"
  "mistral_small_24b|mistralai/Mistral-Small-3.2-24B-Instruct-2506|1|8310|0.90|--enable-auto-tool-choice --tool-call-parser mistral --tokenizer-mode mistral --config-format mistral --load-format mistral --limit-mm-per-prompt {\\\"image\\\":0}"
  "granite_41_30b|ibm-granite/granite-4.1-30b|3|8322|0.90|--enable-auto-tool-choice --tool-call-parser granite4"
  "nemotron_super_49b|nvidia/Llama-3.3-Nemotron-Super-49B-v1|4|8313|0.92|--trust-remote-code --enable-auto-tool-choice --tool-call-parser llama3_json --chat-template /storage/data/DeepCTI/config/chat_templates/tool_chat_template_llama3.1_json.jinja"
)
BIG=(
  "mistral_medium_128b|mistralai/Mistral-Medium-3.5-128B|0,1|8319|0.92|--enable-auto-tool-choice --tool-call-parser mistral --tokenizer-mode mistral --config-format mistral --load-format mistral --limit-mm-per-prompt {\\\"image\\\":0}"
  "glm_45_air|zai-org/GLM-4.5-Air|3,4|8315|0.92|--trust-remote-code --enable-auto-tool-choice --tool-call-parser glm45 --reasoning-parser glm45"
)
if [[ "$LAYOUT" == big ]]; then SPECS=("${BIG[@]}"); else SPECS=("${PACKED[@]}"); fi
tmux has-session -t "$SESSION" 2>/dev/null || tmux new-session -d -s "$SESSION" -n init
for spec in "${SPECS[@]}"; do
  IFS='|' read -r name hf gpus port util extra <<< "$spec"
  if [[ -n "${2:-}" && "$2" != "$name" ]]; then continue; fi
  tp=$(awk -F',' '{print NF}' <<< "$gpus")
  cmd="CUDA_VISIBLE_DEVICES=$gpus VLLM_USE_FLASHINFER_SAMPLER=0 $VLLM_PY -m vllm.entrypoints.openai.api_server \
--model $hf --served-model-name $name --port $port --host 0.0.0.0 --max-model-len 32768 --tensor-parallel-size $tp \
--gpu-memory-utilization $util --enable-prefix-caching --seed 20261005 $extra 2>&1 | tee $LOG_DIR/$name.log"
  tmux new-window -t "$SESSION" -n "$name" "bash -lc '$cmd; exec bash'"
  # start instances that share a GPU one after another (each checks free memory at startup)
  if [[ "$gpus" == "0" ]]; then
    until grep -qE "Application startup complete|Error|error" "$LOG_DIR/$name.log" 2>/dev/null; do sleep 5; done
  fi
done
