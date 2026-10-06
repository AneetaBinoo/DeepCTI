# DeepCTI — phase reports (consolidated, v2–v4)

The pasted plan was truncated before §12 (phase list), so phases follow the plan's dependency order. All work
is on branch `v2-experiment` (single branch instead of `phase-N-<slug>` branches: data, code and audit agents
worked concurrently in one tree; commits mark the phase boundaries). Legacy state tagged `v0-legacy`.

## Phase 0 — setup, verification, related work
* venv `.venv` (Python 3.13; inspect_ai 0.3.276, cedarpy 4.12.1, hypothesis, python-debian, scipy, statsmodels).
* Model panel on vLLM 0.23.0: Gemma-4-31B (existing server, GPU 2), Llama-3.1-8B (remote, key in gitignored
  `.env`), Qwen3-4B / Granite-4.1-8B / Qwen3-14B / Mistral-Small-3.2-24B launched by `scripts/serve/launch_models.sh`
  in tmux `deepcti_vllm` (GPUs 0, 1, 3, 4).
* `docs/VERIFICATION_LOG.md`: theorem constants (EC² published constant rests on a flawed Golovin–Krause proof;
  citable 4(1+2 ln(1/p_min)) is our derivation from Al-Thani et al.), LTT HB p-value, pass^k, model cards and
  cutoffs (binding: Granite-4.1 release 2026-04-29 → temporal hold-out ≥ 2026-05-01), libraries, data sources.
* `docs/RELATED_WORK_CHECK.md`: **STRONG overlap for C2** (TMA-NM, arXiv 2606.24322; Pandey et al., arXiv
  2609.34245 — k-of-n independent-principal corroboration for agent actions) and for C5 at method level
  ("Safe to Stop?", 2609.09678). C2 must be repositioned on the four-valued state, Cedar compilation with a
  linter for the T4 fragment, and the deployed-VEX setting. C1 (Belnap state gating agents), C3 (EC²/DRD tool
  selection for LLM agents) appear open.

## Phase 1 — formal model (C1)
`src/deepcti/core/{belnap,decision}.py`. Property tests (`tests/properties/`): T1 order independence and
idempotence, T2 monotonicity, T3 exhaustive decision soundness (4^4 × req_C), T5 non-interference.

## Phase 2 — epistemic authorization (C2)
`src/deepcti/policy/pdp.py`: Cedar policies P0–P3 (+P3k3) rendered from one table, evaluated with cedarpy and a
Python reference (disagreement raises), JSON-AST linter for the positive-threshold fragment. T4 adversarial
property test (`tests/properties/test_quorum_t4.py`).

## Phase 3 — VOI (C3)
`src/deepcti/acquisition/voi.py`: EC² (exact for deterministic tests, likelihood-weighted for noisy ones —
no guarantee claimed there), entropy baseline, exact DP optimum, model-level regret.

## Phase 4 — data (D1, D2, D3, D4, D6)
Deviation: no Docker/root on this host → hosts are rootfs fixtures (real dpkg DB from official slim images,
real snapshot versions, real changelog headers where available, real Trivy/Grype/OSV-Scanner reports; simulated
process table and change system). 906 D1 cases / 192 CVEs / 32 source packages (bookworm, trixie; bullseye no
longer in the tracker JSON). Test 453 cases, 48% temporal hold-out. V5 (config-gated) is thin (7 cases).
D2 redesigned after results audit B3 as "drift since the last assessment". D4 paraphrases filtered by an LLM
judge (no human filter). No human label audit (κ) — out of reach in this session.

## Phase 5 — extraction
Deterministic parsers, derived atoms with provenance, span verifier with source-specific grammar (changelog
header line; process start line), advisory compiler (untrusted → hints only).

## Phase 6 — environment, systems, harness
Deviation: Inspect AI is installed but not used as the harness (its sandboxes require Docker); a minimal
OpenAI-tool-calling harness with complete mediation through the PDP replaces it (`src/deepcti/agents/`).
*Update (v3):* Inspect AI's `react()` agent was later added as a third-party baseline (S3I,
`src/deepcti/inspect_harness/s3i.py`), with our mediated tools in place of a sandbox.

## Audits
* Code audit R1 (`docs/audit/CODE_AUDIT_R1.md`): 9 bugs fixed with regression tests (linter scope form, T5
  changelog forging via carriers, budget accounting, apply_patch scope and mixed versions, drift removal,
  scanner parse failures, precondition service, trust shadowing, DP zero-mass).
* Results audit R1 (`docs/audit/RESULTS_AUDIT_R1.md`): Holm never applied (fixed: sign-flip tests + Holm/BH),
  E4 could not observe drift (fixed: D2 redesign), metric definition fixes, stale pilots superseded.

## Phase 7 — pre-registration and test runs
See `prereg/PREREGISTRATION.md` (tag `prereg-v1`) and `prereg/DEVIATIONS.md`.

## Phase 8 — v2 test results (prereg-v1)
`results/v2/REPORT.md`. The run produced 98,057 episode records with 0 errors.
- Supported: H1 (withheld arm, DC − S3 loss −1.585), H2 and H4. H4 was weak, because the attacks barely moved S3.
- H0 equivalence holds.
- H3 not supported; H5 vacuous.
- Main findings:
  - DC's decisions equal those of the LLM-free S1′.
  - Restart-blindness on upgrade-without-restart drift.
  - Evidence gating removes unauthorized disruptive actions.

Results audit R2 and a report fact-check followed (`docs/audit/`).

## Phase 9 — v3 improvement round (prereg-v2, prereg-v3)
Plan: `docs/V3_PLAN.md`. Report: `results/v3/REPORT_V3.md`.
- **D7 DeepCTI-Live-X**: 822 hosts, 141 CVEs, 4 ecosystems (`data/d7/BUILD_REPORT.md`).
- **DC v2.1**: instance-aware evidence (H7/H8 on D2; H13 on fresh D7 drift).
- **Validated synthesis** and the E11 note-quality pipeline. H15 failed because of a prompt defect; the
  neutral-prompt DCv21b was post hoc (D23).
- **S3I** (Inspect AI) baseline, plus panel extension: Granite-30B, Nemotron-49B and Mistral-Medium-128B.
- **GLMM** in R.
- The adaptive-attack workstream (D3b) was stopped and not resumed. GLM-4.5-Air was cancelled for
  compute (D22).
- Audit `docs/audit/V3_AUDIT.md` led to:
  - re-running the non-deb drift physics (D20);
  - post-hoc verifier fixes, X2V (D21).

## Phase 10 — paper figures
`scripts/paper/figures.py` writes nine vector figures from run logs and result tables into `paper/figs/`. The
colour palette was checked with the dataviz validator.

## Phase 11 — v4 confirmations (prereg-v4)
Report: `results/v4/REPORT_V4.md`.
- **H16 supported:** DCv21b on a fresh, disjoint sample, faithfulness +0.044.
- **H17 supported:** trust estimated on dev+calib; withheld loss 0.344 → 0.207, coverage 0.31 → 0.73.
- **H18:** decoy version lines are inert for DC. The pre-registered baseline was confounded, so a same-code
  control was added (D25). Exposure was low.
- **Panel completion:** GLM-4.5-Air (D1 E2, D7 X2/X5) and Mistral-Medium (E5, E9, X2V).
- **Audits:** the V4 code audit (`docs/audit/V4_AUDIT.md`) and a paper fact-check
  (`docs/audit/PAPER_FACTCHECK.md`).
- **Deviations:** D26 is an analysis-script crash fix; D27 is a note on `priors_v3.yaml` reproducibility.
- **Operational incident:** the three models sharing GPU 0 started concurrently and two failed out of memory.
  The launcher readiness check matched "error" in normal log lines; it was fixed in
  `scripts/serve/launch_models.sh`.

## Phase 12 — paper rewrite
`paper/main.tex` was rewritten around the pre-registered D1/D7 evaluation; the v0 text is kept in
`paper/main_v0.tex`. The paper is 10 pages including references, built with tectonic. The v2/v3 numbers in the paper were fact-checked against generated files (`docs/audit/PAPER_FACTCHECK.md`), and
the corrections are listed in `results/v4/REPORT_V4.md` §5. The v4 numbers were taken from `results/v4/` and
checked in `docs/audit/DOCS_FACTCHECK.md`.
