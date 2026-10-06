# Paper 2 — hardware and serving (recorded 2026-10-06, Phase 0)

## Experiment node (local)
- **CPU / RAM:** 128 logical CPUs (AMD EPYC 9555, 64 cores); 503 GB RAM.
- **GPUs:** 5 × NVIDIA H200 NVL (143,771 MiB each); driver 610.57.04.
- **Serving stack:** vLLM 0.23.0 with torch 2.11.0+cu130 (CUDA 13.0), in the conda env
  `/home/student/.conda/envs/falcon`. `scripts/serve/launch_models.sh` reads its Python path from `$VLLM_PYTHON`.
- **GPU 2:** the pre-existing Gemma-4-31B server (the plan's "server B"). It is owned by the user and must
  never be stopped. It serves `google/gemma-4-31B-it` as `gemma_4_31b` on port 8103, with
  `max_model_len` 262,144. Tool parsing follows `config/models.yaml`.
- **Free for Paper 2:** GPUs 0, 1, 3 and 4 (all Paper 1 servers were shut down on 2026-10-06).
  - The plan's TP2 Mistral-Medium-3.5-128B fits on GPUs 0+1, as it did in Paper 1 (D19).
  - The plan's "H200 #2" (Qwen3-14B and the query encoder) and "H200 #3" (Granite-30B judge or a second
    Qwen3-14B replica) map to GPUs 3 and 4.

## Remote endpoint ("server A")
- **Model:** Llama-3.1-8B-Instruct (`meta-llama/Llama-3.1-8B-Instruct`), reached through the base URL in
  `config/models.yaml`. The API key is in the gitignored `.env` as `LLAMA8B_API_KEY`.
- **Context:** `max_model_len` is 16,384. This is smaller than the plan's 64k assumption, so long
  BrowseComp-Plus transcripts will need truncation or summarization for Llama.
- **Hardware, vLLM version and tool parser:** not visible from here. `config/models.yaml` assumes the
  server's `llama3_json` tool parser.
- **Known issue (Paper 1 D8a):** single tool call per turn.

## Implications for the plan's compute estimates
- One more H200 is free than the plan assumed, because Gemma's server is local.
- Llama's 16k context caps its BrowseComp-Plus episodes. Measure in Phase 5 before freezing $Q_{\max}$ for
  Llama.
