# E0 — Legacy (v0) re-analysis from raw logs

All numbers produced by `scripts/paper/e0_legacy.py` from `results/raw/*` (v0 tag `v0-legacy`), the v0 dataset
and the v0 controller code run without an LLM. Quality = v0 definition (`scripts/analyze_architecture_suite.py`:
mean of applicability-correct, action-keyword recall, information-keyword recall, not-unsafe,
contradiction-correct). CSVs in `results/v2/e0/`.

## (a) Reproduction of v0 headline numbers

DeepCTI (adaptive_memory), six models, case bootstrap CI (v0 seeds):

| model | cases | quality | ci | reported_quality | median_latency_s | reported_median_latency_s | median_tokens | reported_median_tokens | applicability_acc |
|---|---|---|---|---|---|---|---|---|---|
| llama3.1:8b | 100 | 0.886 | [0.863, 0.909] | 0.886 | 1.624 | 1.620 | 509.500 | 509.500 | 1.000 |
| mistral:latest | 100 | 0.910 | [0.884, 0.935] | 0.910 | 2.349 | 2.350 | 704.000 | 704.000 | 1.000 |
| qwen2.5:7b | 100 | 0.925 | [0.898, 0.949] | 0.925 | 2.287 | 2.290 | 602.000 | 602.000 | 1.000 |
| gemma3:12b | 100 | 0.925 | [0.898, 0.949] | 0.925 | 3.350 | 3.350 | 626.500 | 626.500 | 1.000 |
| phi4:14b | 100 | 0.925 | [0.898, 0.949] | 0.925 | 4.706 | 4.710 | 609.000 | 609.000 | 1.000 |
| qwen3:8b | 100 | 0.923 | [0.897, 0.948] | 0.923 | 2.294 | 2.290 | 598.000 | 598.000 | 1.000 |

Mode comparison (3 models, quality averaged per case, case-bootstrap CI), plus (b) controller-only:

| label | records | quality | ci | reported_quality | completion | reported_completion | median_latency_s | reported_median_latency_s | applicability_acc |
|---|---|---|---|---|---|---|---|---|---|
| DeepCTI | 300 | 0.907 | [0.883, 0.930] | 0.907 | 1.000 | 1.000 | 1.563 | 1.560 | 1.000 |
| Equal-evidence one-shot | 300 | 0.805 | [0.774, 0.835] | 0.805 | 0.990 | 0.990 | 6.928 | 6.930 | 0.680 |
| RAG once | 300 | 0.808 | [0.783, 0.832] | 0.808 | 0.987 | 0.987 | 7.857 | 7.860 | 0.693 |
| Iterative no-memory | 300 | 0.803 | [0.776, 0.829] | 0.803 | 0.977 | 0.977 | 19.673 | 19.670 | 0.647 |
| Initial one-shot | 300 | 0.605 | [0.563, 0.644] | 0.605 | 0.993 | 0.993 | 5.779 | 5.780 | 0.290 |
| Controller only (no LLM) | 100 | 0.925 | [0.898, 0.949] | nan | 1.000 | nan | 0.000 | nan | 1.000 |

Contrasts (v0 sign-flip test, Holm):

| comparison | delta | ci | p_raw | p_holm |
|---|---|---|---|---|
| DeepCTI vs Equal-evidence one-shot | 0.102 | [0.070, 0.137] | 0.000 | 0.000 |
| DeepCTI vs RAG once | 0.099 | [0.073, 0.127] | 0.000 | 0.000 |
| DeepCTI vs Iterative no-memory | 0.104 | [0.077, 0.133] | 0.000 | 0.000 |
| DeepCTI vs Initial one-shot | 0.302 | [0.251, 0.355] | 0.000 | 0.000 |

## (b) Controller-only (no LLM)
v0 `run_adaptive_memory_case` with an LLM stub whose every output fails to parse, so each case ends in the
deterministic fallback payload: quality **0.925** [0.898,
0.949], applicability accuracy 1.000, 0 tokens.

## (c) Quality per profile and mode

| mode | affected | not_applicable | uncertain | contradictory | all |
|---|---|---|---|---|---|
| DeepCTI | 0.983 | 0.945 | 0.700 | 1.000 | 0.907 |
| Equal-evidence one-shot | 0.936 | 0.948 | 0.708 | 0.627 | 0.805 |
| RAG once | 0.913 | 0.925 | 0.706 | 0.687 | 0.808 |
| Iterative no-memory | 0.899 | 0.943 | 0.694 | 0.676 | 0.803 |
| Initial one-shot | 0.757 | 0.748 | 0.652 | 0.263 | 0.605 |
| Controller only (no LLM) | 1.000 | 1.000 | 0.700 | 1.000 | 0.925 |

## (d) Share of the DeepCTI-vs-baseline gap by profile

| comparator | gap | share_affected | share_not_applicable | share_uncertain | share_contradictory |
|---|---|---|---|---|---|
| Equal-evidence one-shot | 0.102 | 0.114 | -0.007 | -0.020 | 0.912 |
| RAG once | 0.099 | 0.175 | 0.050 | -0.015 | 0.789 |
| Iterative no-memory | 0.104 | 0.202 | 0.006 | 0.014 | 0.778 |
| Initial one-shot | 0.302 | 0.187 | 0.163 | 0.039 | 0.611 |
| Mean of 4 baselines | 0.152 | 0.175 | 0.089 | 0.016 | 0.719 |

## (e) Corrected cost metrics (mode-comparison runs, 3 models pooled)

| mode | share_zero_calls | mean_tok_all | median_tok_all | mean_tok_called | median_tok_called | mean_lat_all | median_lat_all | mean_lat_called | median_lat_called |
|---|---|---|---|---|---|---|---|---|---|
| DeepCTI | 0.500 | 899.443 | 509.500 | 1798.887 | 1506.500 | 5.347 | 1.563 | 10.694 | 5.156 |
| Equal-evidence one-shot | 0.000 | 1459.307 | 1411.500 | 1459.307 | 1411.500 | 8.546 | 6.928 | 8.546 | 6.928 |
| RAG once | 0.000 | 1444.853 | 1390.500 | 1444.853 | 1390.500 | 131.656 | 7.857 | 131.656 | 7.857 |
| Iterative no-memory | 0.000 | 3859.807 | 3644.000 | 3859.807 | 3644.000 | 24.333 | 19.673 | 24.333 | 19.673 |
| Initial one-shot | 0.000 | 1157.500 | 1108.500 | 1157.500 | 1108.500 | 6.017 | 5.779 | 6.017 | 5.779 |

DeepCTI per model (all six adaptive runs + mode-comparison runs):

| experiment | model | share_zero_llm_calls | median_tokens_all | min_nonzero_tokens | mean_tokens_all | mean_tokens_called | median_tokens_called | median_latency_all | mean_latency_called | median_latency_called |
|---|---|---|---|---|---|---|---|---|---|---|
| deepcti_candidate_100_2026 | llama3.1:8b | 0.500 | 509.500 | 1019 | 697.150 | 1394.300 | 1344.500 | 1.624 | 23.479 | 17.902 |
| deepcti_candidate_100_2026 | mistral:latest | 0.500 | 704.000 | 1408 | 1115.340 | 2230.680 | 1858.000 | 2.349 | 8.051 | 6.563 |
| deepcti_candidate_100_2026 | qwen2.5:7b | 0.500 | 602.000 | 1204 | 885.840 | 1771.680 | 1544.000 | 2.287 | 6.198 | 5.052 |
| deepcti_expanded_models_100_2026 | gemma3:12b | 0.500 | 626.500 | 1253 | 971.700 | 1943.400 | 1802.500 | 3.350 | 14.454 | 13.467 |
| deepcti_expanded_models_100_2026 | phi4:14b | 0.500 | 609.000 | 1218 | 960.850 | 1921.700 | 1552.000 | 4.706 | 29.872 | 11.572 |
| deepcti_expanded_models_100_2026 | qwen3:8b | 0.500 | 598.000 | 1196 | 820.300 | 1640.600 | 1634.000 | 2.294 | 14.341 | 7.005 |
| deepcti_mode_comparison_100_2026 | llama3.1:8b | 0.500 | 509.500 | 1019 | 697.150 | 1394.300 | 1344.500 | 1.563 | 4.788 | 3.815 |
| deepcti_mode_comparison_100_2026 | mistral:latest | 0.500 | 704.000 | 1408 | 1115.340 | 2230.680 | 1858.000 | 2.298 | 7.995 | 6.458 |
| deepcti_mode_comparison_100_2026 | qwen2.5:7b | 0.500 | 602.000 | 1204 | 885.840 | 1771.680 | 1544.000 | 2.063 | 19.298 | 4.750 |

## (f) Retrieval pool vs k

| mode | step | rows | pool_size_mean | pool_size_max | k | retrieved_mean | share_retrieved_entire_pool |
|---|---|---|---|---|---|---|---|
| iterative_no_memory | 0 | 300 | 2.000 | 2 | 8 | 2.000 | 1.000 |
| iterative_no_memory | 1 | 299 | 3.000 | 3 | 8 | 3.000 | 1.000 |
| iterative_no_memory | 2 | 297 | 4.000 | 4 | 8 | 4.000 | 1.000 |
| rag_once | 2 | 300 | 4.000 | 4 | 8 | 4.000 | 1.000 |

Iterative-no-memory final step vs equal-evidence one-shot: {"pairs": 300, "share_ran_3_steps": 0.99, "share_last_step_same_evidence_set": 0.99, "share_last_step_empty_state": 1, "quality_inm": 0.8029, "quality_eeo": 0.8047, "mean_abs_quality_diff": 0.0891, "share_identical_quality": 0.4633, "share_identical_applicability_correct": 0.86, "corr_quality": 0.6673, "tokens_ratio_inm_over_eeo": 2.645}

## (g) Effective sample size
Distinct case skeletons (local-evidence texts with product and CVE masked): **4**.
ICC(1) of quality with template (=profile) as cluster, design effect 1+(m-1)ICC with m=25:

| run | mode | icc1 | design_effect | n_eff | mean_within_template_sd | mean | case_ci | template_ci | template_boot_distinct_means | template_boot_possible_multisets |
|---|---|---|---|---|---|---|---|---|---|---|
| mode_comparison(mean of 3 models) | adaptive_memory | 0.986 | 24.664 | 4.055 | 0.011 | 0.907 | [0.883, 0.930] | [0.771, 0.991] | 35 | 35 |
| mode_comparison(mean of 3 models) | evidence_equal_one_shot | 0.860 | 21.634 | 4.622 | 0.056 | 0.805 | [0.774, 0.835] | [0.667, 0.942] | 35 | 35 |
| mode_comparison(mean of 3 models) | rag_once | 0.825 | 20.798 | 4.808 | 0.054 | 0.808 | [0.783, 0.832] | [0.696, 0.919] | 35 | 35 |
| mode_comparison(mean of 3 models) | iterative_no_memory | 0.832 | 20.961 | 4.771 | 0.056 | 0.803 | [0.776, 0.829] | [0.685, 0.921] | 35 | 35 |
| mode_comparison(mean of 3 models) | initial_one_shot | 0.955 | 23.923 | 4.180 | 0.049 | 0.605 | [0.563, 0.644] | [0.384, 0.753] | 35 | 35 |
| deepcti_candidate_100_2026:llama3.1:8b | adaptive_memory | 0.936 | 23.470 | 4.261 | 0.024 | 0.886 | [0.863, 0.909] | [0.762, 0.974] | 25 | 35 |
| deepcti_candidate_100_2026:mistral:latest | adaptive_memory | 0.942 | 23.611 | 4.235 | 0.017 | 0.910 | [0.884, 0.935] | [0.775, 1.000] | 15 | 35 |
| deepcti_candidate_100_2026:qwen2.5:7b | adaptive_memory | 1.000 | 25.000 | 4.000 | 0.000 | 0.925 | [0.898, 0.949] | [0.775, 1.000] | 5 | 35 |
| deepcti_expanded_models_100_2026:gemma3:12b | adaptive_memory | 1.000 | 25.000 | 4.000 | 0.000 | 0.925 | [0.898, 0.949] | [0.775, 1.000] | 5 | 35 |
| deepcti_expanded_models_100_2026:phi4:14b | adaptive_memory | 1.000 | 25.000 | 4.000 | 0.000 | 0.925 | [0.898, 0.949] | [0.775, 1.000] | 5 | 35 |
| deepcti_expanded_models_100_2026:qwen3:8b | adaptive_memory | 0.991 | 24.794 | 4.033 | 0.007 | 0.923 | [0.897, 0.947] | [0.775, 1.000] | 15 | 35 |
| controller_only | controller_only | 1.000 | 25.000 | 4.000 | 0.000 | 0.925 | [0.898, 0.949] | [0.775, 1.000] | 5 | 35 |

Template-clustered bootstrap of the DeepCTI-vs-baseline deltas (resampling the 4 templates):

| comparison | delta | icc1_of_delta | template_ci_low | template_ci_high | distinct_boot_values | template_delta_affe_not__unce_cont | template_ci |
|---|---|---|---|---|---|---|---|
| DeepCTI vs Equal-evidence one-shot | 0.102 | 0.879 | -0.005 | 0.279 | 35 | 0.047 / -0.003 / -0.008 / 0.373 | [-0.005, 0.279] |
| DeepCTI vs RAG once | 0.099 | 0.853 | 0.007 | 0.240 | 35 | 0.069 / 0.020 / -0.006 / 0.313 | [0.007, 0.240] |
| DeepCTI vs Iterative no-memory | 0.104 | 0.855 | 0.004 | 0.244 | 35 | 0.084 / 0.003 / 0.006 / 0.324 | [0.004, 0.244] |
| DeepCTI vs Initial one-shot | 0.302 | 0.968 | 0.092 | 0.602 | 35 | 0.225 / 0.197 / 0.048 / 0.737 | [0.092, 0.602] |

The template bootstrap has at most 35 distinct resamples
(multisets of 4 templates) and its percentile CI is essentially the range of template means — degenerate.

## Audit claims F1–F10 (F7 not in scope)
`confirmed` is the script's quantitative test of each claim (thresholds in the code).

| id | claim | evidence | confirmed |
|---|---|---|---|
| F1 | effective sample size ~4 templates | 4 distinct case skeletons after masking product/CVE (0 product strings unresolved); ICC(1) by template: DeepCTI 0.986 (n_eff 4.1), controller-only 1.000 (n_eff 4.0) | True |
| F2 | regex tuned to generator phrases | 22/28 regex trigger phrases occur verbatim in the 12 template sentences; controller applicability correct on 1.000 of originals; regex atom F1 1.000 on originals vs 0.339 on 1451 auto-filtered paraphrases (E1) | True |
| F3 | LLM cannot change applicability | final applicability == controller applicability in 1.000 of 900 adaptive records; first LLM answer disagreed with controller in 0.018 of 450 called records, LLM value adopted in 0 of them; deterministic fallback text used in 0.579 of adaptive records | True |
| F4 | controller-only (no LLM) scores 0.925 | controller-only quality 0.925 [0.898, 0.949] vs DeepCTI 0.907 (3-model mean) and per-model max 0.925 | True |
| F5 | fallback text contains reference keywords | fallback text contains 0.923 of reference action+information keywords; per-profile affected act 1.00/info 1.00, not_applicable act 1.00/info 1.00, uncertain act 0.50/info 1.00, contradictory act 1.00/info 1.00 | True |
| F6 | ~91% of +0.10 gap from contradictory profile | gap vs equal-evidence one-shot +0.102, contradictory share 0.912; vs mean of 4 baselines +0.152, contradictory share 0.719 | True |
| F8 | RAG retrieves 4/4 (k=8, pool 4); iterative-no-memory last step = one-shot | rag_once pool size 4.0 (max 4) with k=8; entire pool retrieved in 1.000; iterative-no-memory last step: same evidence set as one-shot 0.990, empty prior state 1.000; quality 0.803 vs 0.805 (identical per-record quality 0.463, r=0.667); equal at input level (prompt differs only in mode label, state.step and evidence order), not record-for-record at output level; costs 2.64x the one-shot tokens | True |
| F9 | reported medians = half the smallest non-zero value | adaptive records with zero LLM calls: 0.500; max |median - min_nonzero/2| over 9 model-runs: tokens 0.000, latency 0.0000 s | True |
| F10 | iterative_memory unreported | modes in raw logs: adaptive_memory, evidence_equal_one_shot, initial_one_shot, iterative_no_memory, rag_once; iterative_memory records: 0 (declared in VALID_MODES: True) | True |

## Notes / deviations
- Product names for masking (F1) come from the 2026-10-05 KEV mirror (`data/mirrors/cisa_kev/`), matched by CVE;
  the v0 dataset does not store them separately.
- The six-model CIs use the v0 seeding (seed+index over sorted models per run); small last-digit differences to
  the README CIs can arise from that ordering. Point estimates and medians reproduce exactly.
- `llm_calls` for baseline modes = number of trace steps (one generation per step).
