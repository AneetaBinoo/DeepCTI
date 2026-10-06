# DeepCTI

DeepCTI decides whether a CVE affects a specific host (a VEX status: *affected*, *not affected* with a
justification, *fixed*, or *under investigation*). It also decides whether an agent may run a disruptive
remediation. Both decisions are made by an explicit **evidence state**, not by an LLM's reasoning trace:

- **Evidence state.** A provenance-tracked four-valued (Belnap) state over decision atoms (`present`,
  `in_affected_range`, `fix_applied`, `vuln_config_enabled`, plus change atoms). Support is counted in
  *independence groups* of *trusted* sources, inside freshness windows.
- **Decision table.** A deterministic VEX table abstains, with an explanation, on missing (N) or
  conflicting (B) evidence.
- **Acquisition.** EC² value-of-information chooses the next tool call.
- **Verified extraction.** An LLM proposes facts from unstructured text with verbatim spans, and a grammar
  verifier admits them. Untrusted text, including LLM-compiled advisories, yields hints only.
- **Risk-controlled release.** Learn-then-Test releases hint-based decisions at a bounded dangerous-error
  risk.
- **Authorization.** Every tool call passes a Cedar policy decision point. P0 permits everything and P1
  checks arguments only. The evidence-gated P2/P3 additionally require corroborated support for each gating
  atom of a disruptive tool (κ⁺ ≥ k independent trusted groups). A linter restricts these permits to the
  fragment for which the guarantee holds.
- **Validated synthesis.** The analyst note gets one repair attempt, then a deterministic fallback.

The paper is `paper/main.tex`, built as `paper/main.pdf`: 10 pages in IEEE conference format, including
references. The original v0 manuscript and its 100-case study are kept as legacy material; see the Legacy
section below.

## Headline results

Pre-registered results are on sealed test splits under four pre-registrations, tagged `prereg-v1` to
`prereg-v4`. Post-hoc analyses are labelled as such in the reports, and the LTT analysis pools calibration and
test records by design. The runs comprise about 270k test and calibration episodes with 0 error records. The
panel has ten open models from 4B to 128B. All are served with vLLM except Llama-3.1-8B, which runs on a
remote OpenAI-compatible endpoint. Full reports: `results/v2/REPORT.md`, `results/v3/REPORT_V3.md` and
`results/v4/REPORT_V4.md`.

| Finding | Evidence |
|---|---|
| Without a vulnerability feed, DeepCTI has far lower decision loss than ReAct agents, with 0 dangerous errors | H1 (D1, 6 models): −1.585 [−1.760, −1.418]; H9 (D7, 8 models): −0.883 [−1.030, −0.740] |
| ReAct agents mostly fail by **missing** vulnerabilities | D1 S3 DER 0.34 (tracker) / 0.49 (withheld); reliability pass^5 ranges from 0.98 to 0.00 across models |
| With a feed, DeepCTI matches a tracker lookup on D1 and beats it on D7 | H0 (D1, equivalence); D7 loss 0.030 vs 0.147 |
| The LLM adds value only where evidence is unstructured, and through risk-controlled release | H10: vendor software −0.205 vs the LLM-free controller (tracker arm). H12: LTT raises blind-arm coverage from 0.31 to 0.50–0.91 at realised risk 1.4–1.9% |
| Verification lowers the error of accepted facts | H11: −2.7 pp |
| Evidence-gated authorization removes unauthorized disruptive actions | ReAct 5–6% → 0% under P3 (3 v1 models, benign and injected-text D3 episodes); the forged-group (k, m) grid shows the guarantee's boundary |
| **Failure 1: restart-blindness** (package upgraded on disk, old binary still running) | DC loss 9.67; repaired by instance-aware v2.1 (H7: 0.42; independent D7 test H13: 0.45 vs 5.04) |
| **Failure 2: conservative trust** (scanners discarded when trust was estimated on 42 CVEs) | repaired by estimating on dev+calib (H17: withheld loss 0.344 → 0.207, coverage 0.31 → 0.73, DER 0) |
| **Failure 3: a synthesis-prompt defect** made H15 fail | corrected prompt, plus a stricter status check (DCv21b), confirmed on a fresh sample (H16: faithfulness +0.044 [+0.014, +0.073]) |
| Hypotheses that did not hold | H3 (EC² vs checklist on D1: acquisition is trivial there), H15 (above), H5 (vacuous) |
| Known weaknesses | the D3 injection attacks barely moved baselines; H18 decoys are inert but rarely seen before the decision; Gemma-31B ReAct beats DC in the D7 withheld arm (loss 0.291 vs 0.344, but DER 0.05 vs 0); no human label audit |

## Benchmarks

| Set | Content |
|---|---|
| **D1** DeepCTI-Live | 906 Debian cases, 192 CVEs, 32 source packages. Root file systems from official images with real package versions and changelogs (where none was available, a synthesized entry in the real header format, flagged `changelog_synthesized`), and real Trivy/Grype/OSV-Scanner reports. Labels from the Debian security tracker. Test split: 453 cases, 96 CVEs, 48% temporal hold-out. |
| **D2** drift | Drift since a previous assessment: upgrade with or without restart, rollback, removal, config enable. |
| **D3** adversarial | Injected advisory/CMDB text and forged trusted groups (m = 1..3). |
| **D7** DeepCTI-Live-X | 822 cases, 141 CVEs, in Ubuntu, PyPI, Maven (including nested fat-jar copies) and vendor software whose version exists only in text. Labels from the Ubuntu tracker, OSV ranges and vendor advisories. Test split: 414 cases, 70 CVEs. |
| **X5** | Fresh drift episodes on D7 test hosts. |

Data contracts: `docs/DATA_CONTRACT.md` (D1) and `docs/DATA_CONTRACT_V3.md` (D7). Build reports live in
`data/*/BUILD_REPORT.md`. Test labels and world files are sealed in `data/sealed/*.jsonl`, which is gitignored;
their SHA-256 files are tracked. Host file systems (`data/*/hosts/`), base images, raw mirrors, scanner binaries
and raw run logs (`runs/`) are also gitignored and live only on the experiment machine. Rebuilding them uses the
builders in `scripts/data/` (`build_d1.py`, `build_d2_d3.py`, `build_d7.py`, `build_drift_v3.py`, scanner
runners and labelers) and needs network access to the mirrored sources.

## Repository layout

```text
config/          models.yaml (served models), trust profiles (source_profiles*.yaml), priors, config preconditions
policies/        Cedar policies P0–P3, P3k3 (generated by deepcti.policy.pdp)
prompts/         shared frozen prompt cores (core_spec.md, core_spec_v3.md)
prereg/          PREREGISTRATION.md (v1), _V2, _V3, _V4 with file hashes; DEVIATIONS.md (D1–D27)
src/deepcti/
  core/          belnap.py (evidence state), decision.py (VEX table, instance-aware v2.1), versions.py
  policy/        pdp.py (Cedar PDP, reference evaluator, fragment linter)
  acquisition/   voi.py (EC², entropy, DP optimum)
  extraction/    parsers.py, verifier.py (span and grammar verification)
  env/           host.py (rootfs host environment, tools, drift, attacks, decoys), catalog.py
  agents/        systems.py (S0–S5, DC and variants), mediator.py (complete mediation)
  eval/          runner.py, metrics.py (decision loss, DER, UDAR), data.py
  judge/         E11 note-quality judging (LLM judges, perturbation validation, paired stats)
  inspect_harness/  S3I baseline on Inspect AI's react() agent
  vexbench/      evidence-state wrapper for the VEX-Bench transfer study (E7)
  legacy_eval/   v0 evaluation code used for the E0/E1 legacy re-analysis
  llm/           OpenAI-compatible client for vLLM endpoints
scripts/
  data/          dataset builders, scanners, labelers, trust estimation, H16 sampler
  run/           run_experiment.py (all blocks), queue.sh, phase scripts, prereg freezing
  serve/         launch_models.sh (vLLM panel in tmux)
  paper/         analyze*.py (pre-registered and post-hoc analyses), figures.py (paper figures)
  e11/           note-quality pipeline (D1; d7/ for H15/H15b; h16/ for H16)
  e7/            VEX-Bench transfer study
  stats/         GLMM (R/lme4)
results/v2 v3 v4 generated reports and tables (see "Reports" below)
paper/           main.tex, main.pdf, figs/ (vector PDFs from scripts/paper/figures.py), main_v0.tex (legacy)
docs/            plans, data contracts, verification log, related-work check, audits
tests/           unit and property tests (tests/properties: T1–T4; T5 non-interference in tests/v2), regression tests from audits
```

## Reports and audits

| File | Content |
|---|---|
| `results/v2/REPORT.md` | prereg-v1: D1–D3, six models, H0–H6 |
| `results/v3/REPORT_V3.md` | prereg-v2/v3: panel extension, DC v2.1, D7, H7–H15, post-hoc DCv21b |
| `results/v4/REPORT_V4.md` | prereg-v4: H16–H18, GLM-4.5-Air and Mistral-Medium panel completion, corrections to earlier reports |
| `results/*/test/ANALYSIS*.md`, `results/v4/ANALYSIS_V4.md` | full generated analysis output |
| `prereg/DEVIATIONS.md` | every change after a pre-registration tag |
| `docs/audit/` | code audits (R1, R2, V3, V4), results audits (R1, R2), paper fact-check |
| `docs/VERIFICATION_LOG.md` | checked theorem constants, library behaviour, model cut-offs, VEX-Bench protocol |
| `docs/RELATED_WORK_CHECK.md` | closest prior work (TMA-NM, Pandey et al., Safe to Stop?) with verified citations |

## Setup

The experiments ran on Linux with Python 3.13 and vLLM 0.23.0 (separate conda env). Five H200 GPUs were
available, one of which hosted Gemma-4-31B on a pre-existing server.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-experiments.txt   # pinned experiment environment
.venv/bin/pip install -e . --no-deps
```

- `requirements-experiments.txt` pins the environment used for v2–v4.
- `requirements.txt` holds the v0 legacy dependencies.
- vLLM 0.23.0 runs in a separate conda env. `scripts/serve/launch_models.sh` uses `$VLLM_PYTHON`; the default
  is a machine-specific path. The Nemotron chat template path in that script is absolute and must be adapted.
- R 4.5.3 with lme4 2.0.6 for the GLMM lives in a local conda env (`.renv`, not tracked). Create one with
  `conda create -p .renv -c conda-forge r-base r-lme4 r-blme`.
- The paper build uses tectonic (`.texenv/bin/tectonic`; `conda create -p .texenv -c conda-forge tectonic`).
- E7 needs VEX-Bench cloned to `data/external/vex-bench` at commit `80cddea`; see `docs/VERIFICATION_LOG.md` →
  VEX-Bench. It is not tracked.

Models are served with OpenAI-compatible vLLM endpoints listed in `config/models.yaml`. The local panel is
launched with:

```bash
VLLM_PYTHON=/path/to/vllm/python scripts/serve/launch_models.sh packed   # Qwen3-4B, Granite-4.1-8B, Qwen3-14B, Mistral-24B, Granite-30B, Nemotron-49B
scripts/serve/launch_models.sh big mistral_medium_128b                     # TP2 on GPUs 0,1
GPUS=0,1 scripts/serve/launch_models.sh big glm_45_air                     # GLM-4.5-Air, TP2
```

The launcher uses served-model names, such as `glm_45_air` and `granite_41_8b`. `run_experiment.py --model`
uses the keys of `config/models.yaml`, such as `glm45_air` and `granite41_8b`. Gemma-4-31B is expected on a
separately started server at port 8103. The remote Llama-3.1-8B endpoint (an internal address in
`config/models.yaml`) needs `LLAMA8B_API_KEY` in the gitignored `.env`.

## Reproduce

```bash
# one experiment block (test runs refuse to start unless HEAD descends from the required prereg tag)
.venv/bin/python scripts/run/run_experiment.py --exp E2 --split test --model qwen3_14b
.venv/bin/python scripts/run/run_experiment.py --exp X2 --split test --model qwen3_14b --dataset d7 --spec v3
scripts/run/queue.sh test <model> "X2C X6 X6C X7" "--dataset d7 --spec v3"    # resumable, 3 retries

# analyses (read sealed labels; allowed only after the tags)
.venv/bin/python scripts/paper/analyze.py --split test --allow-sealed       # prereg-v1 (H0–H6)
.venv/bin/python scripts/paper/analyze_addendum.py --split test --allow-sealed   # prereg-v2 (H7–H8)
.venv/bin/python scripts/paper/analyze_v3.py --split test --allow-sealed    # prereg-v3 (H9–H14, LTT)
.venv/bin/python scripts/paper/analyze_v3_posthoc.py                         # X2V, S3I, scaling (post hoc)
scripts/e11/run_all.sh                                                        # E11 note quality on D1
.venv/bin/python scripts/stats/export_long.py && .renv/bin/Rscript scripts/stats/glmm.R   # GLMM
.venv/bin/python scripts/e7/run_e7.py --model <model>                         # VEX-Bench transfer (E7)
scripts/e11/d7/run_all_d7.sh; scripts/e11/d7/run_all_d7b.sh                 # H15, post-hoc DCv21b
.venv/bin/python scripts/e11/h16/run_h16.py                                  # H16
.venv/bin/python scripts/paper/analyze_v4.py                                 # prereg-v4 (H16–H18)
.venv/bin/python scripts/paper/analyze_v4_posthoc.py                         # H18 same-code control (D25)
.venv/bin/python scripts/paper/analyze_v4_panel.py                           # GLM / Mistral-Medium panel

# figures and paper
.venv/bin/python scripts/paper/figures.py      # writes paper/figs/*.pdf and *.png
cd paper && ../.texenv/bin/tectonic main.tex
```

Tests:

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider      # 188 passed, 3 xfailed
.venv/bin/ruff check --select F,E9 src/deepcti          # clean; style rules and some data scripts are not lint-clean
```

## Limitations

- Tools are simulated over the root file systems. There are no containers; apart from the three scanners, no
  software was executed on the fixtures.
- D7 jars contain metadata only, and process tables are simulated.
- Labels come from trackers and advisories without a human audit.
- The injection attacks were too weak to discriminate defences.
- Note quality is judged by validated LLM judges, not by humans.
- On VEX-Bench (62 of 75 tasks), the evidence-state wrapper did not beat the plain harness.

See the paper's limitations section and `results/v4/REPORT_V4.md` §6.

## Legacy (v0)

The first version of this project evaluated an Ollama-based pipeline on 100 synthetic, KEV-derived cases
with a lexical composite quality score. That study's files are kept for reference only:
- the original manuscript: `paper/main_v0.tex`;
- code: `src/deepcti/{cli,orchestrator,memory,verifier,ollama,...}.py`;
- configs: `config/deepcti_*_100.yaml`;
- data: `data/derived/`;
- results: `results/raw/`, `results/summary_tables/`, `results/spreadsheet/`.

The v2 legacy re-analysis (E0, `results/v2/e0/E0_REPORT.md`) showed the v0 evaluation to be uninformative: a
controller-only baseline scores 0.925 vs DeepCTI's 0.907, and the effective sample is about four templates.
Its numbers should not be cited as evidence for the current design.
