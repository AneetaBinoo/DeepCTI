#!/usr/bin/env bash
# Re-run X5 (D20) and X2V (D21) for the small-model panel once GPUs 3/4 are free.
set -uo pipefail
cd "$(dirname "$0")/../.."
VLLM_PY=/home/student/.conda/envs/falcon/bin/python
serve() {  # name hf gpu port util extra
  tmux new-window -t deepcti_vllm -n "$1" "bash -lc 'CUDA_VISIBLE_DEVICES=$3 VLLM_USE_FLASHINFER_SAMPLER=0 $VLLM_PY -m vllm.entrypoints.openai.api_server --model $2 --served-model-name $1 --port $4 --host 0.0.0.0 --max-model-len 32768 --gpu-memory-utilization $5 --enable-prefix-caching --seed 20261005 $6 2>&1 | tee logs/vllm/$1.log; exec bash'"
  until curl -s -m 3 "localhost:$4/v1/models" | grep -q "$1"; do sleep 20; done
}
until grep -q "QUEUE FINISHED test nemotron_super_49b" logs/runs/queue_x4_nemotron_super_49b.log 2>/dev/null; do sleep 60; done
until [ -f results/v3/e11_d7/E11_D7_REPORT.md ]; do sleep 60; done
until grep -q "QUEUE FINISHED test granite41_30b" logs/runs/queue_fix_granite41_30b.log 2>/dev/null; do sleep 60; done
tmux kill-window -t deepcti_vllm:nemotron_super_49b; tmux kill-window -t deepcti_vllm:granite_41_30b; sleep 20
serve qwen3_4b Qwen/Qwen3-4B 4 8302 0.18 "--enable-auto-tool-choice --tool-call-parser hermes --reasoning-parser qwen3"
serve granite_41_8b ibm-granite/granite-4.1-8b 4 8321 0.25 "--enable-auto-tool-choice --tool-call-parser granite4"
serve qwen3_14b Qwen/Qwen3-14B 4 8309 0.45 "--enable-auto-tool-choice --tool-call-parser hermes --reasoning-parser qwen3"
scripts/serve/launch_models.sh packed mistral_small_24b_gpu3 2>/dev/null || true
tmux new-window -t deepcti_vllm -n mistral_small_24b "bash -lc 'CUDA_VISIBLE_DEVICES=3 VLLM_USE_FLASHINFER_SAMPLER=0 $VLLM_PY -m vllm.entrypoints.openai.api_server --model mistralai/Mistral-Small-3.2-24B-Instruct-2506 --served-model-name mistral_small_24b --port 8310 --host 0.0.0.0 --max-model-len 32768 --gpu-memory-utilization 0.90 --enable-prefix-caching --seed 20261005 --enable-auto-tool-choice --tool-call-parser mistral --tokenizer-mode mistral --config-format mistral --load-format mistral --limit-mm-per-prompt {\\\"image\\\":0} 2>&1 | tee logs/vllm/mistral_small_24b.log; exec bash'"
until curl -s -m 3 localhost:8310/v1/models | grep -q mistral_small_24b; do sleep 20; done
for m in qwen3_4b granite41_8b qwen3_14b mistral_small_24b; do
  tmux new-window -t deepcti_v3 -n "fix_$m" "bash -lc 'scripts/run/queue.sh test $m \"X5 X2V\" \"--dataset d7 --spec v3\" 2>&1 | tee -a logs/runs/queue_fix_$m.log; exec bash'"
done
echo "[$(date -u +%FT%TZ)] small-model fix runs launched"
