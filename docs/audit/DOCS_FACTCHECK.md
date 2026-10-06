# Fact-check of the updated documentation (2026-10-06)

Auditor: independent, read-only. The only file written is this one. `data/sealed/` was not read. No process or tmux
session was started or stopped (pytest and ruff were run once, read-only, to check the README's test claim).

Scope:
1. `README.md` (whole file)
2. `results/v4/REPORT_V4.md` (whole file)
3. the "Update 2026-10-06" banners in `results/v2/REPORT.md` and `results/v3/REPORT_V3.md`
4. `docs/PHASE_REPORTS.md`: Phase 6 "Update (v3)" note and Phases 8–12
5. `docs/V3_PLAN.md` §3 "Outcome"
6. the "Resolution" sections of `docs/audit/V4_AUDIT.md` and `docs/audit/PAPER_FACTCHECK.md`

Sources (abbreviations):
- **A2**: `results/v2/test/ANALYSIS.md`; **T2/x**: `results/v2/test/tables/x.csv`; **R2**: `results/v2/REPORT.md` body
- **A3**: `results/v3/test/ANALYSIS_V3.md`; **ADD**: `results/v3/test/ADDENDUM.md`; **PH3**: `results/v3/test/POSTHOC.md`; **T3/x**: `results/v3/test/tables/x.csv`
- **A4**: `results/v4/ANALYSIS_V4.md` / `analysis_v4.json`; **PH4**: `results/v4/POSTHOC_V4.md` / `tables/h18_posthoc.csv`; **P4**: `results/v4/PANEL_V4.md` / `tables/panel_*.csv`; **H16**: `results/v4/h16/{h16.json,metrics_system.csv}`, `logs/h16/run_h16.log`
- **PR4**: `prereg/PREREGISTRATION_V4.md`; **DEV**: `prereg/DEVIATIONS.md`; **V4A**: `docs/audit/V4_AUDIT.md` body; **PFC**: `docs/audit/PAPER_FACTCHECK.md` §1
- **BR1/BR7**: `data/d1/BUILD_REPORT.md`, `data/d7/BUILD_REPORT.md`
- **runs**: direct counts over `runs/**.jsonl` with `.venv/bin/python` (no labels needed unless stated; label-dependent numbers were recomputed only through `scripts/paper/figures.py::frame`, which the analysis scripts themselves use)

Verdicts: **OK**, **WRONG** (contradicted by a source), **IMPRECISE** (true in substance but mis-scoped, ambiguous
or mis-rounded), **UNSUPPORTED** (no source in the repo), **STALE/MISSING** (README setup/reproduction problems).

---

## 1. Non-OK items (ordered by severity)

| # | Where | Claim | Verdict | Evidence | Suggested wording |
|---|---|---|---|---|---|
| 1 | REPORT_V4 §4 (D3 table, row "S3+P0 / P1") | forged trusted groups m1/m2/m3: "4.7% / 4.7% / 4.7%" for both P0 and P1 | **WRONG** for P1 | `runs/test/E5/mistral_medium_128b.jsonl` via `figures.frame('d1','E5')`: S3+P0 m1/m2/m3 = 0.0469/0.0469/0.0469; **S3+P1 = 0.0312/0.0469/0.0469**; benign 0, injected (u_static, u_adaptive) 0.0156 for both. Pooled P0 0.0286, P1 0.026 match P4 `panel_mm_e5.csv` | Split the row: "S3+P0: 0% / 1.6% / 4.7%, 4.7%, 4.7%"; "S3+P1: 0% / 1.6% / 3.1%, 4.7%, 4.7%" |
| 2 | REPORT_V4 §4, X2V paragraph | "With v3 as run (7 models), the gap was 0.146 vs 0.084 (DC vs DC_noverify)" | **WRONG** (mixes two analyses) | T3/posthoc_x2v.csv: the pre-registered run ("as run") is **8 models** (n = 672): DC 0.1458 vs DC_noverify 0.0838. The **7-model** figure is the v3 post-hoc X2V with the fixed verifier: DC 0.1148 vs 0.0864. Same in REPORT_V3 §3 item 3 | "In the pre-registered X2 run (8 models, verifier before D21) the gap was 0.146 vs 0.084; v3's post-hoc X2V (7 models) gave 0.115 vs 0.086." |
| 3 | REPORT_V4 §3 (H18 text) | "No system ever adopted a decoy version as an accepted fact." | **IMPRECISE / UNSUPPORTED for S3** | A4 H18 `accepted` = 0 for S3, but V4A m1: S3 records no verdicts, so 0 is by construction; for DC_noverify "accepted" means *proposed*; the match is exact (epochs not normalised). `analyze_v4_posthoc.py` does not recompute "accepted" at all. Same sentence in `paper/main.tex` §V-G | "Neither DC nor DC_noverify ever recorded the decoy version as a fact (exact string match); S3 records no facts, so adoption is not measured for it." |
| 4 | V4_AUDIT Resolution, row m1 | "'Accepted' is reported for DC and DC_noverify only, since S3 records no verdicts." | **UNSUPPORTED** | `scripts/paper/analyze_v4_posthoc.py` has no `accepted` column; the frozen A4 table still prints `accepted 0` for S3; REPORT_V4 and the paper state it for "no system" (item 3). The epoch normalisation suggested in V4A m1 was not implemented | "Exposure is now counted only at or before the decision (`seen_before_decision`). 'Accepted' is not recomputed post hoc; the frozen A4 value for S3 is 0 by construction and REPORT_V4/paper restrict the claim to DC and DC_noverify." (and then fix item 3) |
| 5 | PAPER_FACTCHECK Resolution | "Every item in §1 was fixed in paper/main.tex" | **WRONG** (three minor items unchanged) | `paper/main.tex` L345 still "exposes a distribution tracker/VEX feed" (PFC item 42); L483–484 still "only in release notes, README files and banners" (item 41); L217–218 still "only tool executions write to it" (item 43); L358 still defines DCv21b as "DCv21 with a neutral synthesis prompt" without the stricter check (item 22; partly covered by L308). Spot checks of items 1–21, 23–40 found them fixed | "All items in §1 except the minor items 41–43 (and the DCv21b definition at L358, item 22) were fixed..." |
| 6 | PHASE_REPORTS Phase 12 | "All numbers were fact-checked against generated files" | **IMPRECISE** | PAPER_FACTCHECK Resolution itself: the v4 results (H16–H18, GLM, Mistral-Medium) "were not re-checked by this independent pass"; this pass found the paper's "No system ever adopted" sentence (item 3) | "The v1–v3 numbers were fact-checked against generated files (`docs/audit/PAPER_FACTCHECK.md`); the v4 numbers added afterwards were taken from `results/v4/` and checked in `docs/audit/DOCS_FACTCHECK.md`. Corrections that affect earlier reports are listed in REPORT_V4 §5." |
| 7 | REPORT_V4 §3 (H18 corrected analysis) | "X6−X2 therefore mixes the decoy effect with a code change of about 0.03 loss per model on vendor cases" | **IMPRECISE** (denominator) | V4A C1: "six flips in 104 cases per model is about 0.03 of mean loss" (all decoy cases, not vendor only). Observed from A4/PH4: X2 clean 0.0673 vs X6C clean 0.0415 → **0.026 over all 104 decoy cases**; deb loss is 0 in both, so on the 46 vendor cases it is ≈ 0.058. DEV D25 has the same wording | "...a code change worth about 0.026 loss over the 104 decoy cases (≈ 0.06 on the 46 vendor cases)" |
| 8 | V3_PLAN §3 G3 | "Verified extraction matters only for vendor software: H10 −0.205 (tracker arm) and H11 −2.7 pp accepted-fact error." | **IMPRECISE** | H11 pools LLM proposals from deb-ubuntu (3,087 DC proposals) and vendor (2,037) cases (T3/x2_extraction.csv); only the *decision* gain (H10) is vendor-specific | "Verified extraction changes decisions only for vendor software (H10 −0.205, tracker arm); across deb and vendor proposals it lowers accepted-fact error by 2.7 pp (H11)." |
| 9 | README "Headline results", row 3 | "With a feed, DeepCTI is equivalent to a tracker lookup — H0" | **IMPRECISE** (D1 only) | H0 is D1 (A2). On D7's tracker arm DC (0.030) is better than the S1 lookup (0.147) and S1′ (0.071) (A3 X2 table) | "With a feed, DeepCTI matches a tracker lookup on D1 (H0) and beats it on D7 (loss 0.030 vs 0.147)." |
| 10 | README "Headline results", intro | "All results are on sealed test splits under four pre-registrations" | **IMPRECISE** | Post-hoc analyses (DCv21b in v3, X2V, X6C, E10, GLMM), the LTT pools calib and test records, and E7 runs on VEX-Bench | "All confirmatory results are on sealed test splits under four pre-registrations...; post-hoc and exploratory analyses are labelled as such." |
| 11 | README "Headline results", Known weaknesses | "Gemma-31B ReAct beats DC on D7 without a feed" | **IMPRECISE** | P4/T3: withheld arm S3 0.291 (DER 0.047) vs DC 0.344 (DER 0); in the blind arm (also no feed) S3 0.365 > DC 0.344 | "Gemma-31B ReAct has lower loss than DC in the D7 withheld arm (0.29 vs 0.34, but DER 0.05 vs 0)" |
| 12 | README intro, "Authorization" bullet | "Cedar policies (P0–P3) gate disruptive tools on corroborated support (κ⁺ ≥ k ...)" | **IMPRECISE** | `policies/P0.cedar` "no gating"; P1 checks `args_ok` only; P2 κ⁺ ≥ 1, P3 κ⁺ ≥ 2 on world atoms (P3k3: 3) (`src/deepcti/policy/pdp.py`) | "Cedar policies P2/P3 gate disruptive tools on corroborated support (κ⁺ ≥ k independent trusted groups; P0 = no gating, P1 = argument checks only, as baselines)." |
| 13 | README "Headline results", authorization row | "ReAct 5–6% → 0% under P3" | **IMPRECISE** (scope) | T2/e5_benign.csv, 3 v1 models: S3+P0 benign 5.2%, S3+P1 6.3%, S3+P3 0%. Over the 5-model E5 panel S3+P3 has 1/2,304 (Nemotron, m3 forgery ≥ k) | "ReAct 5–6% (3 v1 models, benign episodes) → 0% under P3" |
| 14 | README Benchmarks, D1 | "real package versions and changelogs" | **IMPRECISE** | BR1 item 14: 111 hosts have a synthesized changelog entry in real header format (`changelog_synthesized`); dpkg status is extended with target stanzas (DATA_CONTRACT) | "...real package versions and changelog entries (111 hosts carry a synthesized entry in the real header format)" |
| 15 | README Benchmarks paragraph | "Test labels are sealed in `data/sealed/`, which is gitignored" | **IMPRECISE** | `.gitignore`: only `data/sealed/*.jsonl`; `data/sealed/SHA256` and `D7_SHA256` are tracked | "Test labels (`data/sealed/*.jsonl`) are gitignored; their SHA-256 hashes are committed." |
| 16 | README layout, tests | "tests/properties: T1–T5" | **IMPRECISE** | `tests/properties/` holds T1–T4 (+VOI); T5 non-interference is in `tests/v2/test_env_controller.py` (L218) | "tests/properties (T1–T4), T5 in tests/v2/test_env_controller.py" |
| 17 | README Limitations | "There are no containers, and no host software is executed." | **IMPRECISE** | Trivy/Grype/OSV-Scanner were really run on every fixture (BR1, BR7); the paper now says "only the scanners ran on the file systems" | "...no host software is executed (the three scanners ran once per fixture, offline)." |
| 18 | README Tests | `.venv/bin/ruff check src scripts` (listed next to "188 passed") | **IMPRECISE** | Ruff 0.16.3 reports **213 findings** (103 RUF100 unused-noqa, 27 ISC004, 13 FURB167, 11 BLE001, 11 I001, ...) | Add "(currently 213 style findings, none functional)" or fix them / restrict the rule set |
| 19 | README Setup, model panel | "ten open models ..., served with vLLM"; "OpenAI-compatible vLLM endpoints" | **IMPRECISE** | `config/models.yaml`: Llama-3.1-8B is a remote endpoint whose revision/server is not exposed; Gemma-4-31B runs on a pre-existing server | "...served through OpenAI-compatible endpoints (vLLM 0.23.0 locally; Llama-3.1-8B on a remote server)" |
| 20 | REPORT_V4 §3 (H17) | "DC's and DCt's decisions are identical across all 8 models" | **IMPRECISE** (ambiguous) | runs: each system's statuses are identical across models (0 of 414 cases vary for DC in X2 withheld, 0 for DCt in X7), but DC and DCt differ from each other on 856/1,248 deb and 544/768 maven pairs | "Each system's decisions are identical across the 8 models (DC and DCt each form one replicate repeated 8 times), so n overstates the information." |
| 21 | REPORT_V4 §3 (H17) | "For pypi the scanners' false-negative rate is 10.5% ... so DCt does not trust them" | **IMPRECISE** | `config/source_profiles_v3b.yaml`: pypi FN 4/38 = 10.5%, Wilson-95 upper bound 0.241; the rule is on the upper bound (≤ 0.10), not the point rate. Vendor FN 30/30 | "For pypi the scanners missed 4 of 38 affected cases (10.5%, Wilson upper bound 24%), and for vendor software 30 of 30, so the rule does not trust them." |
| 22 | REPORT_V4 §5 item 2 | prereg-v2 "used the v3 prompt, which tells every system to check running services" | **IMPRECISE** (minor) | `prompts/core_spec_v3.md` rule 3: "A running service keeps executing the version it was started with: an upgrade on disk without a restart does not fix a running process." | "...which states for every system that an upgrade on disk does not fix a running process" |
| 23 | V4_AUDIT Resolution, row m4 | m4 resolved by reporting CVE overlap and replay | **IMPRECISE** (incomplete) | V4A m4 also flagged the DC arm's older code (3/99 vendor triples differ X2 vs X2V) and suggested a sensitivity run with X2V records; no such analysis exists | Add: "The code-version difference of the DC arm (3/99 vendor triples) is noted but no sensitivity analysis was run." |
| 24 | README "Headline results", Failure 3 | "corrected prompt confirmed on a fresh sample (H16 ...)" | **IMPRECISE** (minor) | DEV D23: DCv21b = neutral prompt **plus** a validator check rejecting notes that assert another status | "corrected prompt and stricter note check (DCv21b) confirmed..." |
| 25 | REPORT_V4 §2, X6 row | "decoy version lines in read documents" | **IMPRECISE** (minor) | PR4 H18 wording; V4A M1: deb changelogs are read only after the decision, roundcube decoys sit past the 8,000-char cap, Jenkins files are never proposed to DC | "decoy version lines in documents that state the installed version (deb changelog, vendor version files)" |

### README: stale or missing for a new user

| # | Problem | Evidence | Fix |
|---|---|---|---|
| S1 | `requirements-experiments.txt` and `results/v4/REPORT_V4.md` are **untracked** (`git status: ??`), yet README tells users to install from / read them | git status | Commit both before publishing the README |
| S2 | `data/external/vex-bench/` is untracked and not mentioned; `scripts/e7/*` hard-code it | `scripts/e7/run_e7.py:12,29`; `results/v2/e7/E7_REPORT.md` (VEX-Bench commit `80cddea`) | Gitignore it and add a line: "E7 needs VEX-Bench at commit 80cddea in `data/external/vex-bench` (`scripts/e7/download_subset.py`)" |
| S3 | `launch_models.sh` defaults to a machine-specific interpreter `/home/student/.conda/envs/falcon/bin/python` | script L6 (`VLLM_PYTHON` override) | Document `VLLM_PYTHON=/path/to/vllm/env/python` |
| S4 | The Nemotron entry uses an absolute chat-template path `/storage/data/DeepCTI/config/chat_templates/...` | script PACKED list | Make it relative to the repo, or note it |
| S5 | Gemma-4-31B (port 8103) is not launched by the script and no command is given | script header comment; `config/models.yaml` | Add the vLLM command or say the user must serve it on :8103 |
| S6 | The remote Llama endpoint is an internal address (`10.116.34.176:8008`) | `config/models.yaml` | Say that `base_url` must be changed for another site |
| S7 | GLM-4.5-Air: the launcher name is `glm_45_air`, the runner model key is `glm45_air`; `launch_models.sh big glm45_air` silently launches nothing | script BIG list vs `config/models.yaml` | Add `scripts/serve/launch_models.sh big glm_45_air   # TP2 on GPUs 3,4` |
| S8 | Reproduction needs the gitignored host fixtures (`data/d1/hosts`, `data/d7/hosts`), mirrors, scanner binaries (`tools/bin`, gitignored) and sealed labels; README only says they "live on the experiment machine" | `.gitignore`; BR1/BR7 build tables | Point to the builders (`scripts/data/build_d1.py`, `build_d7.py`, `run_scanners*.py`, `mirror_*.py`) and state that analyses need `runs/` and sealed labels |
| S9 | R/lme4 env (`.renv`, gitignored) has no setup instructions | DEV D14: R 4.5.3, lme4 2.0.6, blme | Add the versions and the `scripts/stats/` commands (`export_long.py`, `glmm.R`) |
| S10 | Reproduce omits some generators of committed reports: `scripts/paper/analyze_v3_posthoc.py` (PH3), `scripts/e11/run_all.sh` (D1 E11), `scripts/e7/*` (E7), `scripts/stats/*` (GLMM) | file listing | Add one line each |
| S11 | Layout omits `src/deepcti/vexbench/` (E7 wrapper) and `legacy_eval/` | `ls src/deepcti` | Add to the layout block |

---

## 2. Claim-by-claim log

### 2.1 README.md

| Claim | Verdict | Source |
|---|---|---|
| VEX statuses; atoms present / in_affected_range / fix_applied / vuln_config_enabled + change atoms; independence groups of trusted sources; freshness windows | OK | `src/deepcti/core/belnap.py`, `decision.py`, `agents/mediator.py` |
| Decision table abstains on N or B with explanation | OK | `decision.py` |
| EC² chooses the next tool call | OK | `acquisition/voi.py` |
| Verified extraction; untrusted text and LLM-compiled advisories are hints | OK | `extraction/verifier.py`; DEV D10 |
| LTT releases hint-based decisions at bounded risk | OK | A3 LTT; `analyze_v3.py` |
| Cedar P0–P3 gate on κ⁺ ≥ k; linter | IMPRECISE (#12) | `policies/*.cedar`, `pdp.py` |
| Validated synthesis: one repair, deterministic fallback | OK | DEV D16 |
| Paper is 10 pages incl. references, IEEE conference | OK | `pypdf`: 10 pages; `\documentclass[conference]{IEEEtran}` |
| Four pre-registrations tagged prereg-v1..v4 | OK | `git tag -l` |
| "All results are on sealed test splits" | IMPRECISE (#10) | |
| About 270k episodes, 0 error records | OK | runs: 270,029 records in runs/{test,calib}, runs/d7/{test,calib}, 0 with `error` |
| Ten open models from 4B to 128B | OK | `config/models.yaml` (10 entries, 4–128B) |
| "served with vLLM" | IMPRECISE (#19) | |
| H1 (D1, 6 models) −1.585 [−1.760, −1.418] | OK | A2 hypotheses |
| H9 (D7, 8 models) −0.883 [−1.030, −0.740] | OK | A3 |
| 0 dangerous errors for DC | OK | A2/A3 DER 0 in E2/X2 |
| D1 S3 DER 0.34 / 0.49 | OK | R2 §3 (0.337 / 0.485) |
| pass^5 from 0.98 to 0.00 | OK | P4 `panel_e9.csv` |
| With a feed DC ≡ tracker lookup (H0) | IMPRECISE (#9) | |
| H10 −0.205 vs LLM-free controller, vendor, tracker arm | OK | A3 |
| H12 coverage 0.31 → 0.50–0.91, realised risk 1.4–1.9% | OK | T3/ltt_blind.csv α = 0.05 (0.4995–0.9084; 0.0137–0.0187) |
| H11 −2.7 pp | OK | A3 (−0.0269) |
| ReAct 5–6% → 0% under P3 | IMPRECISE (#13) | |
| Guarantee tight in (k, m) grid | OK | R2 §4 item 3 |
| Failure 1: DC loss 9.67; H7 0.42; H13 0.45 vs 5.04 | OK | ADD X4 (9.673, 0.42); T3/x5_drift.csv (0.445 vs 5.038) |
| Failure 2: trust on 42 CVEs; H17 0.344 → 0.207, coverage 0.31 → 0.73, DER 0 | OK | BR7 (dev 42 CVEs); A4 |
| Failure 3: H16 +0.044 [+0.014, +0.073] | OK (wording #24) | A4 / H16 |
| Did not hold: H3, H15, H5 vacuous | OK | A2, A3 |
| Known weaknesses (attacks weak; decoys rarely seen; Gemma; no label audit) | OK except Gemma scope (#11) | R2 §4.3; PH4; P4 |
| D1: 906 cases, 192 CVEs, 32 source packages; test 453 / 96 CVEs / 48% | OK | BR1 |
| D1 "real ... changelogs" | IMPRECISE (#14) | |
| D1 real Trivy/Grype/OSV reports; Debian tracker labels | OK | BR1 |
| D2 kinds (upgrade ± restart, rollback, removal, config enable) | OK | `scripts/data/build_d2_d3.py` L49 |
| D3 injected advisory/CMDB text, forged groups m = 1..3 | OK | `build_d2_d3.py` (u_static/u_adaptive carriers advisory:nvd/osv, cmdb_notes; m1–m3) |
| D7: 822 cases, 141 CVEs; Ubuntu/PyPI/Maven (fat-jar)/vendor; labels Ubuntu tracker, OSV, vendor advisories; test 414 / 70 CVEs | OK | BR7 |
| X5 fresh drift on D7 test hosts | OK | DEV D20 |
| Data contracts paths; `data/*/BUILD_REPORT.md` | OK | files exist |
| `data/sealed/` gitignored | IMPRECISE (#15) | |
| Hosts and runs gitignored | OK | `.gitignore` (`data/d1/hosts/`, `data/d7/hosts/`, `runs/`) |
| Every path in the layout block exists | OK | checked with `test -e` (all present) |
| `policies/` generated by `deepcti.policy.pdp` | OK | headers of P1–P3k3; P0 also rendered by `render_cedar` |
| DEVIATIONS D1–D27 | OK | 28 rows: D1–D27 plus D8a |
| tests/properties T1–T5 | IMPRECISE (#16) | |
| Reports table (v2: prereg-v1, D1–D3, six models, H0–H6; v3: H7–H15 + DCv21b; v4: H16–H18, GLM/MM) | OK | report headers |
| docs/audit contents; VERIFICATION_LOG topics; RELATED_WORK_CHECK (TMA-NM, Pandey, Safe to Stop?) | OK | file headings |
| Python 3.13, vLLM 0.23.0 separate env | OK | `.venv/bin/python --version` 3.13.11; `config/models.yaml` header; VERIFICATION_LOG |
| Five H200 GPUs, one hosting Gemma-4-31B | OK | `nvidia-smi`: 5 × H200 NVL; models.yaml (GPU 2, :8103) |
| Setup commands (`venv`, `pip install -r requirements-experiments.txt`, `pip install -e . --no-deps`) | OK as commands; file untracked (S1) | `pyproject.toml` exists; requirements file pins pytest, ruff, inspect_ai, cedarpy |
| `requirements.txt` holds v0 deps; `.renv`; `.texenv/bin/tectonic` | OK (`.renv` has no instructions, S9) | files exist |
| `launch_models.sh packed` = Qwen3-4B, Granite-8B, Qwen3-14B, Mistral-24B, Granite-30B, Nemotron-49B | OK | PACKED list |
| `launch_models.sh big mistral_medium_128b` TP2; `GPUS=0,1` override | OK | BIG list, `GPUS` override, `tp` from GPU count |
| `LLAMA8B_API_KEY` in gitignored `.env` | OK | models.yaml `api_key_env`; `.gitignore` |
| `run_experiment.py --exp --split --model [--dataset d7 --spec v3]` | OK | argparse L208–215 |
| test runs refuse unless HEAD descends from the tag | OK | `require_prereg` (`merge-base --is-ancestor`) |
| `queue.sh test <model> "<blocks>" "<extra>"`, resumable, 3 retries | OK | queue.sh signature and loop |
| `analyze.py / analyze_addendum.py / analyze_v3.py --split test --allow-sealed` | OK | argparse |
| `run_all_d7.sh`, `run_all_d7b.sh`, `run_h16.py`, `analyze_v4*.py` (no args) | OK | files |
| `figures.py` writes `paper/figs/*.pdf` and `*.png` | OK | `save()` |
| `cd paper && ../.texenv/bin/tectonic main.tex` | OK | binary exists (tracked) |
| pytest: 188 passed, 3 xfailed | OK | ran: "188 passed, 3 xfailed in 20.5s" |
| ruff check | IMPRECISE (#18) | |
| Limitations (simulated tools; metadata-only jars; simulated process tables; no human audit; weak attacks; LLM judges; VEX-Bench 62/75 negative) | OK except "no host software is executed" (#17) | BR7; R2 §4.6; E7_REPORT |
| Legacy: Ollama pipeline, 100 KEV-derived cases, lexical composite score | OK | `paper/main_v0.tex` L602–604; E0_REPORT |
| Legacy paths (`main_v0.tex`, `src/deepcti/{cli,orchestrator,memory,verifier,ollama}.py`, `config/deepcti_*_100.yaml`, `data/derived/`, `results/{raw,summary_tables,spreadsheet}/`) | OK | all exist |
| "The v2 results audit (`results/v2/e0/E0_REPORT.md`)" | IMPRECISE (minor) | E0 is the legacy re-analysis, not one of the results audits (`docs/audit/RESULTS_AUDIT_*`). Suggest "The v2 legacy re-analysis E0 (...)" |
| controller-only 0.925 vs DeepCTI 0.907; about four templates | OK | E0_REPORT (a), (g) |

### 2.2 results/v4/REPORT_V4.md

| Claim | Verdict | Source |
|---|---|---|
| Source files and generating scripts | OK | file headers |
| prereg-v4 tag at commit 55c0960 | OK | `git rev-parse prereg-v4` |
| Deviations after the tag D25–D27 | OK | DEV (D24 is the prereg itself) |
| §1 three open items from REPORT_V3 §4; MM E5/E9/X2V; GLM D1 E2, D7 X2, X5; GLM cancelled in v3 (D22) | OK | REPORT_V3 §4; PR4 §2; DEV D22 |
| X2C 504 = 168 cases × 3 arms, 21 per generator | OK | PR4 H16; runs 504 |
| X7 3,312 (8 models, withheld) | OK | runs |
| X6 2,496; 104 cases (58 deb, 46 vendor); DC, DC_noverify, S3; tracker; 8 models | OK (wording #25) | runs; PH4 (464/8, 368/8) |
| X6C 2,496 | OK | runs |
| MM: E5 3,072, E9 1,500, X2V 756 (5,328) | OK | runs |
| GLM: E2 4,530, X2 6,210, X5 640 (11,380) | OK | runs |
| 0 error records; 270,029 total over runs/test, runs/calib, runs/d7/test, runs/d7/calib, excluding pilots | OK | runs |
| H16 +0.044 [+0.014, +0.073], p = 0.0046, 504 pairs, 70 CVEs, rule lo > −0.02, supported | OK | A4 / h16.json |
| H17 −0.137 [−0.167, −0.107], DER diff 0 [0, 0], n = 3,312, 70 CVEs, rule, supported | OK | A4 |
| H18 −0.026 [−0.050, −0.006], rule hi < +0.05 | OK | A4 |
| H16 faithfulness 0.744 vs 0.700 (2,026 / 1,914 claims) | OK | h16.json |
| Consistency 0.988 vs 0.961 | OK | metrics_system.csv (0.9884 / 0.9606) |
| Fallback 6.0% | OK | 0.0595 |
| 0 replay mismatches, 0 extraction errors, 5 of 25,230 judge errors | OK | `logs/h16/run_h16.log`; judgments.jsonl (25,230 lines, 5 with error) |
| No shared case with H15, 65 of 70 CVEs overlap | OK | recomputed: 0/168 cases, 65 CVEs shared (the H15 sample has 65 CVEs) |
| DCt trusts scanners for deb-ubuntu and maven | OK | source_profiles_v3b.yaml |
| pypi FN 10.5%, vendor 100% | IMPRECISE (#21) | |
| Loss 0.344 → 0.207, coverage 0.312 → 0.734, DER 0 | OK | A4 |
| "DC's and DCt's decisions are identical across all 8 models"; CI CVE-clustered | IMPRECISE (#20) | |
| C1: 7 of 8 models' X2 predates D21 | OK | V4A C1 |
| "about 0.03 loss per model on vendor cases" | IMPRECISE (#7) | |
| X6−X6C table: DC −0.0006 [−0.0019, 0]; DC_noverify 0; S3 −0.017 [−0.131, +0.101]; n = 832 | OK | PH4 |
| Exposed: DC −0.005 (n = 96, 3 CVEs); DC_noverify 0 (96); S3 −0.260 [−0.478, −0.025] (88) | OK | PH4 |
| Other-status stratum: 93 of 104 (58 deb, 35 of 46 vendor); DC 0, DC_noverify 0, S3 +0.022 [−0.083, +0.130] | OK | PH4 (744/8; 0.761 × 46 = 35) |
| "No system ever adopted a decoy version" | IMPRECISE/UNSUPPORTED (#3) | |
| DC saw decoy before deciding in 11.5% | OK | PH4 share_seen 0.115 (96/832) |
| deb changelog read only after deciding; one vendor product's decoy past the 8,000-char cap; 24% same-status vendor decoys | OK | V4A M1 (roundcube), M2 (11/46 = 23.9%); PH4 0.761 |
| "Exposed" S3 contrast conditions on a post-treatment variable | OK | design |
| GLM table (all 15 cells) | OK | P4 `panel_d1_e2.csv`, `panel_d7_x2.csv` |
| GLM drift: DCv21 0.025, DC 5.055, S3 3.530, S2 0.148; rollback DC 0.025, S3 5.013 | OK | `panel_glm_x5.csv` (S2 0.1475) |
| MM D3 table | WRONG for S3+P1 m1 (#1); other cells OK | runs E5 |
| E9 pass^5 values (9 models), T = 0.7, 150 cases; DC 1.0 for all nine | OK | `panel_e9.csv` |
| Nemotron generic template; 25.5% of D1 E2 S3 episodes without a tool call | OK | runs: 231/906 |
| X2V all 8 models: DC 0.113, DC_noverify 0.084, DCv21 0.144 | OK | P4 pooled X2V |
| "With v3 as run (7 models), 0.146 vs 0.084" | WRONG (#2) | |
| §5.1 Gemma S3 0.291 vs DC 0.344, DER 0.047 vs 0; blind 0.365 vs 0.344 | OK | P4 / T3 x2_by_model |
| §5.2 S3 7.564 (v2 prompt, 6 models) vs 3.979 (v3 prompt, 9 models) | OK (wording #22) | A2 E4; ADD X4 (n = 270 = 30 × 9) |
| §5.3 +34% / +79% tool cost on D7 X5; "+8%" is the main D7 study | OK | T3/x5_drift.csv (2.806→3.766, 3.691→6.594); A3 (3.707→4.009, 5.203→5.652) |
| §5.4 H10 tracker arm only; DC = S1′ in feed-less arms | OK | A3 by ecosystem (vendor withheld/blind 0.351 both) |
| §5.5 H2 −0.26446 → −0.264; paper H1, H10 CI, H13 bound fixed | OK | T2/hypotheses.csv; `paper/main.tex` (1.58, [−0.26, −0.14], [−6.30, −3.02]) |
| §6 open items; D3b not resumed; priors_v3 D27 (vendor q_service) | OK | DEV D27 |

### 2.3 Banners in results/v2/REPORT.md and results/v3/REPORT_V3.md

| Claim | Verdict | Source |
|---|---|---|
| v2: restart-blindness (§4.2) repaired by DC v2.1 (H7; independent D7 test H13) | OK | ADD; A3 |
| v2: D7 added (prereg-v3); v4 confirmations H16–H18 | OK | PR3, PR4 |
| v2: H2 is −0.264 (−0.26446), not −0.265 | OK | T2/hypotheses.csv −0.2644628 |
| v2: 7.564 under the original prompt; prereg-v2 rerun with v3 prompt 3.979 | OK | A2 E4; ADD |
| v3: H16 +0.044 [+0.014, +0.073] | OK | A4 |
| v3: H17 withheld loss 0.344 → 0.207 | OK | A4 |
| v3: X2V now 8 models: DC 0.113 vs DC_noverify 0.084 | OK | P4 |
| v3: Gemma-31B ReAct beats DC on D7 without a feed (0.291 vs 0.344) | OK (scope as in #11: withheld arm) | P4 |
| v3: D2 ReAct 3.979 used the v3 prompt | OK | ADD; PR2 |
| v3: "+8%" is the main D7 study; drift +34–79% | OK | A3; T3/x5_drift.csv |
| v3: H10 vendor tracker arm only; DC = S1′ in feed-less arms | OK | A3 |

### 2.4 docs/PHASE_REPORTS.md (Phase 6 update, Phases 8–12)

| Claim | Verdict | Source |
|---|---|---|
| Phase 6: Inspect AI `react()` added as S3I (`src/deepcti/inspect_harness/s3i.py`), mediated tools instead of a sandbox | OK | s3i.py L159 `react(`; DEV D15 |
| Phase 8: 98,057 records, 0 errors | OK | R2 §1 |
| Phase 8: H1 −1.585, H2, H4 supported; H4 weak; H0 holds; H3 not supported; H5 vacuous | OK | A2; R2 §2 |
| Phase 8: DC = S1′; restart-blindness; gating removes unauthorized actions | OK | R2 §4 |
| Phase 8: results audit R2 and report fact-check followed | OK | `docs/audit/RESULTS_AUDIT_R2.md`; R2 header |
| Phase 9: D7 822 hosts / 141 CVEs / 4 ecosystems | OK | BR7 |
| Phase 9: DC v2.1 (H7/H8 on D2; H13 on D7) | OK | ADD; A3 |
| Phase 9: H15 failed (prompt defect), DCv21b post hoc (D23) | OK | DEV D23 |
| Phase 9: S3I; panel Granite-30B, Nemotron-49B, Mistral-Medium-128B; GLMM in R | OK | DEV D14, D15, D19, D22 |
| Phase 9: D3b stopped; GLM cancelled for compute (D22) | OK | REPORT_V3 §1; DEV D22 |
| Phase 9: V3 audit → D20 drift physics re-run, D21 verifier fixes / X2V | OK | DEV D20, D21 |
| Phase 10: nine vector figures from run logs and tables; palette validated | OK | `figures.py` default list (9 names); `paper/figs/` 9 PDFs; docstring |
| Phase 11: H16 +0.044; H17 0.344 → 0.207, coverage 0.31 → 0.73; H18 inert, confounded baseline, X6C (D25), low exposure | OK | A4; PH4; DEV D25 |
| Phase 11: panel completion (GLM: D1 E2, D7 X2/X5; MM: E5, E9, X2V) | OK | P4 |
| Phase 11: D26 crash fix; D27 priors note | OK | DEV |
| Phase 11: incident: three models on GPU 0 started concurrently, two failed out of memory; readiness check matched "error"; fixed | OK | `logs/vllm/{qwen3_4b,granite_41_8b}.fail1.log` ("No available memory for the cache blocks"); commit 139ef71 changes the grep from `Error\|error` to `Engine core initialization failed` |
| Phase 12: rewrite; v0 kept in `main_v0.tex`; 10 pages incl. references; tectonic | OK | pypdf 10 pages |
| Phase 12: "All numbers were fact-checked against generated files" | IMPRECISE (#6) | |

### 2.5 docs/V3_PLAN.md §3 Outcome

| Item | Verdict | Source |
|---|---|---|
| G1 822 cases, 141 CVEs, 4 ecosystems; 41 config-gated (21 in test) | OK | BR7 (V5 41, test 21) |
| G2 E11 pipeline; D1 judges validated by error injection; H15 failed; DCv21b post hoc then H16 +0.044 | OK | E11 reports; A4 |
| G3 | IMPRECISE (#8) | |
| G4 S3I agrees 80.6%; panel incl. GLM (v4, descriptive); SecGPT not run | OK | REPORT_V3 §3 item 8; P4 |
| G5 D3b stopped; v2 E5 stands; H18 not an attack study | OK | |
| G6 H7 −9.25; H13 −4.59; more abstention after restarts; +34–79% tool cost on drift | OK | ADD; A3; T3/x5_drift.csv |
| G7 H14 −0.35; entropy-greedy cheaper (4.20 vs 5.34) | OK | A3 X3 |
| G8 GLMM agrees with H1 | OK | DEV D14 |
| G9 H12 coverage 0.31 → 0.50–0.91 at 1.4–1.9% | OK | T3/ltt_blind.csv |
| new: trust on dev+calib (H17 0.344 → 0.207, coverage 0.31 → 0.73) | OK | A4 |

### 2.6 Resolution sections

**docs/audit/V4_AUDIT.md**

| Row | Verdict | Source |
|---|---|---|
| C1: X6C added; X6−X2 reported unchanged and flagged; X6−X6C DC −0.0006 [−0.0019, 0]; D25; posthoc script; paper §V-G | OK | PH4; DEV D25; paper §V subsection G "Trust estimation and decoys" |
| M1: 11.5% exposure (n = 96, 3 CVEs); H18 framed as "inert for DC" | OK | PH4 |
| M2: 93 of 104 imply a different status; direction-restricted contrast 0 for DC | OK | PH4 |
| m1: exposure counted at or before the decision | OK | `seen_before_decision` in analyze_v4_posthoc.py |
| m1: "Accepted reported for DC and DC_noverify only" | UNSUPPORTED (#4) | |
| m2: no action; note does not enter loss/DER | OK | V4A m2 |
| m3: deb 856/1,248, maven 544/768 differ; pypi 0/624, vendor 0/672 | OK | recomputed from runs (X7 DCt vs X2 DC withheld) |
| m4: CVE overlap 65/70 and 0 replay mismatches reported | OK, but incomplete (#23) | REPORT_V4 §3; run_h16.log |
| m5: analysis after all 8 models finished (02:25); 0 duplicate keys in X2C/X6/X7 (6,312 records); posthoc asserts uniqueness | OK | runs: 504 + 2,496 + 3,312 = 6,312, 0 duplicates; DEV D26 at 02:25; `assert not df.duplicated(...)` |
| priors_v3 → D27 | OK | DEV D27 |

**docs/audit/PAPER_FACTCHECK.md**

| Claim | Verdict | Source |
|---|---|---|
| "Every item in §1 was fixed" | WRONG (#5) | items 41, 42, 43 unchanged; item 22 partly |
| Gemma exception; H10, drift-cost and S3I scope | OK | main.tex (Gemma-31B ×4; "1.50"; "abstains more") |
| Model count ten; deviation count updated | OK | main.tex "ten" ×4; "28 entries" = D1–D27 + D8a |
| Rounding fixed | OK | 1.58, [−0.26, −0.14], [−6.30, −3.02], −0.264 |
| LTT risk definition, P1 vs P2/P3, blocking-N, process view, verifier, S1′, groups, authorization boundary, fixture, judges, statistics, conclusion | OK (spot-checked) | main.tex L282–284, L290, L189–196, L271, L391–394, L668–669, L689 |
| VEX-Bench (with negative E7) and Wu & Rus cited | OK | main.tex L156–159, L660; bib `vexbench2026`, `wu2026safetostop` |
| Still open: li2025drift, cutler2024cedar metadata; eight unverified references | OK (as stated) | |
| v4 results added afterwards, not re-checked by that pass | OK; this file covers them for the reports, and found item #3 in the paper |
