# INQ Phase 0 — inventory and reuse audit (branch `inq-phase-0-inventory`, 2026-10-06)

## Acceptance criteria (plan §11, Phase 0)
1. Record the hardware of servers A and B and of the H200 node in `docs/inquiry/HARDWARE.md`. **Done**,
   but server A's hardware is not visible: it is a remote endpoint.
2. Install and pin LLM Reasoners; check its licence and its MCTS against a vLLM endpoint. **Partly done.**
   - Licence (Apache-2.0), API and endpoint support are verified.
   - **Installation is deferred to Phase 4.** It is pip `llm-reasoners` 1.0.2 and pulls in torch, transformers
     and bitsandbytes.
   - `OpenAIModel` has no `base_url` argument and no log-likelihoods. A thin vLLM `LanguageModel` subclass
     will be needed.
3. Confirm `runs/` is complete against the manifests. **Done**: `docs/inquiry/RUNS_INVENTORY.md`, from
   `scripts/inquiry/check_runs.py`.
4. List the reusable modules and their tests, and confirm the test suite is green. **Done**:
   `docs/inquiry/REUSE_INVENTORY.md`; pytest gives 188 passed, 3 xfailed.
5. Verify the external benchmarks and libraries. **Done**: `docs/VERIFICATION_LOG.md` → "Paper 2 (inquiry) —
   external resource checks".
6. `REUSE_INVENTORY.md` maps every §2 item to a path and a status. **Done.**

## What was reused / what is new
- **Reused, read-only:**
  - Paper 1 run manifests and logs;
  - `config/models.yaml`;
  - the serving scripts;
  - all modules listed in `REUSE_INVENTORY.md`.
- **New:**
  - `scripts/inquiry/check_runs.py`;
  - `docs/inquiry/{HARDWARE,REUSE_INVENTORY,RUNS_INVENTORY}.md`;
  - the plan file `INQUIRY_EXPERIMENT_PLAN.md`, saved verbatim with an errata block.

## Deviations from the plan and findings that change it
1. **Missing artefacts:**
   - `scripts/fig_*.py` and `softstyle.py` do not exist.
   - `results/v3/test/tables/x4_by_kind.csv` does not exist; its numbers are in `ADDENDUM.md`.
   - Paper 1 has no numbered propositions.

   These are recorded in the errata block of the plan.
2. **Hardware:**
   - The node has five H200s, and Gemma ("server B") is local on GPU 2. One more GPU is free than the plan
     assumed.
   - Llama-3.1-8B ("server A") is remote, with a **16k context**. It will need context management on
     BrowseComp-Plus.
3. **BrowseComp-Plus:**
   - Public under MIT, ungated, 830 queries and 100,195 documents.
   - Queries and answers are XOR-encrypted with the BrowseComp canary, so **decrypted text must never be
     committed**.
   - Download sizes, all needing your approval:
     - the full set: about 9.8 GB;
     - the Qwen3-Embedding-8B index alone: 1.64 GB;
     - the Qwen3-Embedding-8B query encoder: 15.2 GB;
     - the official judge, which loads Qwen3-32B in-process: about 65.5 GB.
   - The ACL 2026 title differs from the arXiv title; cite the ACL version.
4. **BED-LLM:** the code is public (MIT) but covers 20 Questions only, which is exactly what E1 needs. It
   launches its own vLLM, so a small patch is needed to point it at our endpoints.
5. **SeekerGym:** paper only; no code or data has been released. E5's completeness-conformal baseline must
   be re-implemented from the paper, or dropped.
6. **Search-R1 (B10):**
   - Checkpoints of 13.6–131 GB need approval.
   - The 3B (Qwen2.5-3B, research-only licence) and Llama-3.2 bases have licence caveats; prefer 7B, 14B or 32B.
   - Its BrowseComp-Plus client runs the model in-process, not through an endpoint.
7. **Unlicensed code (UoT, TIPS, CaRT, CA-BED, Active Task Disambiguation):** these repositories declare no
   licence. Re-implement the methods from their papers; do not copy their code.
8. **Related work:** all twelve plan names resolve to real papers.
   - CA-BED and ASIG are workshop papers.
   - CaRT's venue is unverified; cite it as arXiv.
   - Question's Gambit (arXiv 2609.14412) reports results on BrowseComp-Plus and is directly relevant.
9. **Run logs:** every test block is complete (0 errors, 0 duplicate keys). The incomplete v2 dev/calib
   `_final` partial runs are not used.

## Open decisions for the authors before Phase 3
- Approve the BrowseComp-Plus download. Choose either the full set (9.8 GB) or the subset of corpus,
  queries and Qwen3-Embedding-8B index (about 6.2 GB), plus the 15.2 GB query encoder.
- Choose the judge: the official Qwen3-32B in-process judge, or our validated judges through endpoints.
- Decide whether to include Search-R1 (B10), and which checkpoint.
