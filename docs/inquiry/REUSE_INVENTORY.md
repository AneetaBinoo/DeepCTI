# Paper 2 — reuse inventory (Phase 0, 2026-10-06)

Status values:
- **ready**: usable as is;
- **extend**: usable, but the plan's change is needed;
- **extract**: the logic exists but must be lifted into a library;
- **missing**: the plan refers to something that does not exist.

Test-suite baseline on branch `inq-phase-0-inventory`: `pytest` gives 188 passed, 3 xfailed.

## 2.1 Code

| Plan item | Path (verified) | Status | Notes |
|---|---|---|---|
| Belnap state | `src/deepcti/core/belnap.py`: `Observation` (l.59), `EvidenceLog` (l.78), `compute_state` (l.146), `val` (l.192) | extend | Atom keys are free strings, so claim IDs work. Property tests in `tests/properties/test_belnap_props.py` |
| VEX decision | `src/deepcti/core/decision.py`: `decide_values`, `decide_world`, `decide_instance_aware` | ready | Exhaustive test in `tests/properties/test_decision_exhaustive.py` |
| VOI | `src/deepcti/acquisition/voi.py`: `Belief` (l.112), `_edge_weight` (l.139), `ec2_score` (l.148), `entropy_score` (l.165), `select_test` (l.180), `optimal_expected_cost` (l.191), `policy_expected_cost` (l.233) | extend | Needs the ⊥ region and expansion term. `tests/properties/test_voi.py` has 9 tests |
| Verifier / parsers | `src/deepcti/extraction/verifier.py` (`verify`), `parsers.py` (`parse_result`, `derive_from_facts`, `CaseProgram`, `program_from_vex`) | extend | QA "claim in document" verifier is new |
| Controller / baselines | `src/deepcti/agents/systems.py`: `ControllerConfig` (l.228), `Controller` (l.248), `_llm_choose` (l.538), `run_direct` (l.695), `run_react` (l.721) | extend | Refactor the loop into `inquiry/loop.py` |
| Mediator / environment | `src/deepcti/agents/mediator.py`; `src/deepcti/env/host.py` (`HostEnv`, `world_atoms`, `apply_decoys`, drift, attacks) | extend | The open read-only query interface is new |
| S3I | `src/deepcti/inspect_harness/s3i.py` | ready | |
| VEX-Bench harness | `src/deepcti/vexbench/` (`agent.py`, `tools.py`, `verifier.py`, `advisory.py`); checkout `data/external/vex-bench` @ 80cddea (untracked) | extend | The plan's path `results/v2/e7/` holds results, not the checkout |
| Judges | `src/deepcti/judge/` (`llm.py`, `prompts.py`, `perturb.py`, `paired.py`, `stats.py`, `d7.py`); `results/v3/e11/validated_judges.json` | ready | Validated judges: Gemma-4-31B, Granite-4.1-30B, Nemotron-49B |
| LLM client / serving | `src/deepcti/llm/client.py`, `config/models.yaml`, `config/chat_templates/`, `scripts/serve/launch_models.sh` | ready | Launcher fixes from 2026-10-06 (readiness check, `GPUS` override) |
| LTT / Hoeffding–Bentkus | `scripts/paper/analyze_v3.py::ltt` (nested `hb`, l.277), `scripts/paper/analyze.py` (nested `hb_pvalue`, l.512) | extract | Must become `inquiry/stopping.py`. Keep the Paper 1 scripts unchanged; they are hash-frozen |
| Statistics | `scripts/paper/analyze.py` (`cluster_bootstrap` l.39, `cluster_signflip` l.68); `scripts/stats/glmm.R`, `export_long.py`; R env `.renv` (R 4.5.3, lme4 2.0.6) | ready | `glmm.R` is specific to E2; E0 gets its own R script |
| Data builders, trust | `scripts/data/*` (`build_d7.py`, `label_d7.py`, `select_d7.py`, `run_scanners_d7.py`, `estimate_trust_v3.py`, …) | ready | D8 needs a new CVE selection and network access to the mirrors |
| Figure style | `scripts/paper/figures.py` | ready | **missing:** `scripts/fig_*.py` and `softstyle.py` do not exist |

## 2.2 Data

| Plan item | Path | Status | Notes |
|---|---|---|---|
| D1, D7 (incl. test labels) | `data/d1`, `data/d7`, `data/sealed/{test_labels,d7_test_labels}.jsonl` | ready | Unsealed for Paper 1, so they are development data for Paper 2 |
| D2 drift | `data/d2/{test,…}.jsonl`, `data/sealed/d2_test_world.jsonl` | ready | |
| X5 drift (D7) | `data/drift_d7/`, `data/sealed/drift_d7_test_world.jsonl` | ready | |
| D6 advisory tuples | `data/d6/{dev,calib,test}.jsonl` | ready | 3,000 rows in total (1,504 in test) |
| Source profiles | `config/source_profiles.yaml`, `_v3.yaml`, `_v3b.yaml` | ready | |
| Priors | `config/priors.yaml`, `priors_v3.yaml` | ready | `priors_v3` vendor `q_service` is not reproducible by current code (D27) |
| Mirrors | `data/mirrors/*` (NVD, OSV, Debian/Ubuntu trackers, vendor) | ready | Raw parts are gitignored and local |
| VEX-Bench | `data/external/vex-bench` @ 80cddea | ready | Untracked; protocol in `docs/VERIFICATION_LOG.md` → VEX-Bench |

## 2.3 Paper 1 results cited

| Plan item | Path | Status |
|---|---|---|
| ReAct misses and per-model loss | `results/v2/test/tables/e2_by_system.csv`, `results/v4/tables/panel_*.csv` | ready |
| Restart-blindness | `results/v3/test/ADDENDUM.md` (X4 table) and `results/v3/test/tables/x5_drift.csv` | ready (**`x4_by_kind.csv` missing**) |
| Acquisition on D7 | `results/v3/test/tables/x3_acquisition.csv` | ready |
| D1 regret | `results/v2/test/tables/e3_regret_model.csv` | ready |
| LTT | `results/v3/test/tables/ltt_blind.csv` | ready |
| VEX-Bench E7 | `results/v2/e7/` | ready |
| Judge validation | `results/v3/e11/validated_judges.json` | ready |

## 2.4 Run logs
`docs/inquiry/RUNS_INVENTORY.md` (from `scripts/inquiry/check_runs.py`):
- 171 non-pilot manifests, 276,359 records, 0 error records, 0 duplicate keys.
- Every **test** block is complete.
- Incomplete blocks are v2 dev/calib "_final" partial runs only. They are not used and not regenerated.
- The E0 audit uses the non-attack test blocks (≈213k episodes) as its primary input and the calib blocks as
  replication. E5 and KM (attacks) are excluded.
