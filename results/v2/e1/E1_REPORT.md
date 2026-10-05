# E1 — Extraction robustness on `legacy-para` (auto-filtered)

All numbers produced by `scripts/paper/e1_extraction.py` (data: `scripts/data/build_legacy_para.py`).

## Data
- Distinct v0 evidence sentences: 157 from 12 sentence templates (4 profiles x 3 steps); KEV public records excluded (v0 regex yields no atoms on them).
- Paraphrases: 1570 generated (qwen3_14b, mistral_small_24b; 5 each, T=0.7, seed 20261005); kept 1451 (92.4%); judge-rejected 112, unparsed 0, duplicates 7.
- **Filtering: AUTOMATICALLY FILTERED by LLM judge (gemma_4_31b); NOT human-verified (deviation from plan: human filtering not possible in this run).**
- Gold atoms = v0 regex on the ORIGINAL sentence. Caveat: this gold inherits regex conventions (e.g. "approved maintenance window" yields no change_approval atom; a scanner sentence on "the installed version" yields no product_presence atom), so LLM atoms that are semantically defensible can count as FP. `decision_f1` restricts scoring to product_presence/version_status, the fields applicability depends on.
- Items scored: 1608 (originals + kept paraphrases). Items per distance bin: 0 (original): 157, [0,0.4): 119, [0.4,0.55): 406, [0.55,0.7): 662, [0.7,1]: 264.

Kept-paraphrase distance by generator:

| generator | count | mean | 25% | 50% | 75% | max |
|---|---|---|---|---|---|---|
| mistral_small_24b | 724.000 | 0.624 | 0.571 | 0.632 | 0.697 | 0.875 |
| qwen3_14b | 727.000 | 0.538 | 0.462 | 0.533 | 0.619 | 0.870 |

Per-template counts (cluster structure; paraphrases of one sentence are not independent, CIs bootstrap original sentences, 1000 resamples):

| template_id | kind | sentences | items | para_kept_rate |
|---|---|---|---|---|
| affected:s0 | original | 19 | 19 | 0.984 |
| affected:s0 | paraphrase | 19 | 187 | 0.984 |
| affected:s1 | original | 25 | 25 | 0.964 |
| affected:s1 | paraphrase | 25 | 241 | 0.964 |
| affected:s2 | original | 1 | 1 | 1.000 |
| affected:s2 | paraphrase | 1 | 10 | 1.000 |
| contradictory:s0 | original | 18 | 18 | 0.811 |
| contradictory:s0 | paraphrase | 17 | 146 | 0.811 |
| contradictory:s1 | original | 25 | 25 | 0.968 |
| contradictory:s1 | paraphrase | 25 | 242 | 0.968 |
| contradictory:s2 | original | 1 | 1 | 0.800 |
| contradictory:s2 | paraphrase | 1 | 8 | 0.800 |
| not_applicable:s0 | original | 19 | 19 | 0.879 |
| not_applicable:s0 | paraphrase | 19 | 167 | 0.879 |
| not_applicable:s1 | original | 19 | 19 | 0.947 |
| not_applicable:s1 | paraphrase | 19 | 180 | 0.947 |
| not_applicable:s2 | original | 1 | 1 | 1.000 |
| not_applicable:s2 | paraphrase | 1 | 10 | 1.000 |
| uncertain:s0 | original | 14 | 14 | 0.821 |
| uncertain:s0 | paraphrase | 14 | 115 | 0.821 |
| uncertain:s1 | original | 14 | 14 | 0.964 |
| uncertain:s1 | paraphrase | 14 | 135 | 0.964 |
| uncertain:s2 | original | 1 | 1 | 1.000 |
| uncertain:s2 | paraphrase | 1 | 10 | 1.000 |

## Atom-level P/R/F1 vs gold

| extractor | model | kind | items | precision | recall | f1 | f1_ci | decision_f1 | exact_match_rate | error_rate |
|---|---|---|---|---|---|---|---|---|---|---|
| regex | regex_v0 | original | 157 | 1.000 | 1.000 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 0.000 |
| regex | regex_v0 | paraphrase | 1451 | 0.920 | 0.208 | 0.339 | [0.310, 0.371] | 0.338 | 0.198 | 0.000 |
| llm | qwen3_4b | original | 157 | 0.749 | 0.882 | 0.810 | [0.753, 0.861] | 0.813 | 0.682 | 0.000 |
| llm | qwen3_4b | paraphrase | 1451 | 0.754 | 0.947 | 0.840 | [0.810, 0.871] | 0.854 | 0.628 | 0.000 |
| llm | granite_41_8b | original | 157 | 0.796 | 1.000 | 0.886 | [0.861, 0.913] | 0.889 | 0.669 | 0.000 |
| llm | granite_41_8b | paraphrase | 1451 | 0.788 | 0.990 | 0.878 | [0.852, 0.904] | 0.880 | 0.664 | 0.000 |
| llm | llama31_8b | original | 157 | 0.741 | 0.931 | 0.825 | [0.778, 0.871] | 0.827 | 0.669 | 0.000 |
| llm | llama31_8b | paraphrase | 1451 | 0.792 | 0.945 | 0.862 | [0.832, 0.889] | 0.866 | 0.700 | 0.000 |
| llm | qwen3_14b | original | 157 | 0.796 | 1.000 | 0.886 | [0.862, 0.911] | 0.889 | 0.669 | 0.000 |
| llm | qwen3_14b | paraphrase | 1451 | 0.801 | 0.980 | 0.881 | [0.857, 0.905] | 0.884 | 0.675 | 0.000 |
| llm | mistral_small_24b | original | 157 | 0.883 | 0.970 | 0.925 | [0.901, 0.946] | 0.926 | 0.796 | 0.000 |
| llm | mistral_small_24b | paraphrase | 1451 | 0.858 | 0.959 | 0.906 | [0.884, 0.926] | 0.909 | 0.772 | 0.000 |
| llm | gemma_4_31b | original | 157 | 0.793 | 1.000 | 0.885 | [0.858, 0.908] | 0.885 | 0.662 | 0.000 |
| llm | gemma_4_31b | paraphrase | 1451 | 0.797 | 0.995 | 0.885 | [0.860, 0.910] | 0.887 | 0.672 | 0.000 |
| llm_verified | qwen3_4b | original | 157 | 0.867 | 0.675 | 0.759 | [0.700, 0.814] | 0.755 | 0.682 | 0.000 |
| llm_verified | qwen3_4b | paraphrase | 1451 | 0.957 | 0.773 | 0.855 | [0.824, 0.883] | 0.856 | 0.748 | 0.000 |
| llm_verified | granite_41_8b | original | 157 | 0.995 | 0.906 | 0.948 | [0.922, 0.971] | 0.950 | 0.892 | 0.000 |
| llm_verified | granite_41_8b | paraphrase | 1451 | 0.928 | 0.855 | 0.890 | [0.865, 0.911] | 0.892 | 0.775 | 0.000 |
| llm_verified | llama31_8b | original | 157 | 0.993 | 0.704 | 0.824 | [0.770, 0.873] | 0.827 | 0.701 | 0.000 |
| llm_verified | llama31_8b | paraphrase | 1451 | 0.962 | 0.560 | 0.708 | [0.674, 0.739] | 0.708 | 0.480 | 0.000 |
| llm_verified | qwen3_14b | original | 157 | 1.000 | 0.882 | 0.937 | [0.906, 0.964] | 0.936 | 0.879 | 0.000 |
| llm_verified | qwen3_14b | paraphrase | 1451 | 0.979 | 0.798 | 0.879 | [0.850, 0.906] | 0.880 | 0.771 | 0.000 |
| llm_verified | mistral_small_24b | original | 157 | 1.000 | 0.877 | 0.934 | [0.910, 0.957] | 0.933 | 0.847 | 0.000 |
| llm_verified | mistral_small_24b | paraphrase | 1451 | 0.965 | 0.849 | 0.904 | [0.876, 0.928] | 0.905 | 0.826 | 0.000 |
| llm_verified | gemma_4_31b | original | 157 | 0.795 | 0.995 | 0.884 | [0.857, 0.910] | 0.884 | 0.662 | 0.000 |
| llm_verified | gemma_4_31b | paraphrase | 1451 | 0.823 | 0.963 | 0.887 | [0.864, 0.910] | 0.890 | 0.689 | 0.000 |

v0 regex: F1 1.000 on originals vs 0.339 on paraphrases (recall 1.000 -> 0.208).

### F1 by paraphrase distance (figure: `atom_f1_vs_distance.png`)

| extractor | model | 0 (original) | [0,0.4) | [0.4,0.55) | [0.55,0.7) | [0.7,1] |
|---|---|---|---|---|---|---|
| regex | regex_v0 | 1.000 | 0.734 | 0.463 | 0.316 | 0.054 |
| llm | qwen3_4b | 0.810 | 0.867 | 0.804 | 0.842 | 0.870 |
| llm | granite_41_8b | 0.886 | 0.884 | 0.830 | 0.878 | 0.933 |
| llm | llama31_8b | 0.825 | 0.879 | 0.832 | 0.869 | 0.877 |
| llm | qwen3_14b | 0.886 | 0.878 | 0.838 | 0.887 | 0.922 |
| llm | mistral_small_24b | 0.925 | 0.916 | 0.890 | 0.906 | 0.923 |
| llm | gemma_4_31b | 0.885 | 0.878 | 0.836 | 0.887 | 0.941 |
| llm_verified | qwen3_4b | 0.759 | 0.904 | 0.884 | 0.853 | 0.809 |
| llm_verified | granite_41_8b | 0.948 | 0.733 | 0.871 | 0.917 | 0.901 |
| llm_verified | llama31_8b | 0.824 | 0.694 | 0.757 | 0.712 | 0.648 |
| llm_verified | qwen3_14b | 0.937 | 0.911 | 0.905 | 0.872 | 0.858 |
| llm_verified | mistral_small_24b | 0.934 | 0.959 | 0.922 | 0.904 | 0.866 |
| llm_verified | gemma_4_31b | 0.884 | 0.869 | 0.849 | 0.892 | 0.931 |

### F1 on paraphrases by paraphrase generator

| extractor | model | generator | items | f1 | decision_f1 |
|---|---|---|---|---|---|
| regex | regex_v0 | qwen3_14b | 727 | 0.458 | 0.459 |
| regex | regex_v0 | mistral_small_24b | 724 | 0.206 | 0.202 |
| llm | qwen3_4b | qwen3_14b | 727 | 0.850 | 0.863 |
| llm | qwen3_4b | mistral_small_24b | 724 | 0.829 | 0.845 |
| llm | granite_41_8b | qwen3_14b | 727 | 0.881 | 0.882 |
| llm | granite_41_8b | mistral_small_24b | 724 | 0.875 | 0.877 |
| llm | llama31_8b | qwen3_14b | 727 | 0.878 | 0.882 |
| llm | llama31_8b | mistral_small_24b | 724 | 0.846 | 0.850 |
| llm | qwen3_14b | qwen3_14b | 727 | 0.879 | 0.882 |
| llm | qwen3_14b | mistral_small_24b | 724 | 0.884 | 0.886 |
| llm | mistral_small_24b | qwen3_14b | 727 | 0.915 | 0.919 |
| llm | mistral_small_24b | mistral_small_24b | 724 | 0.897 | 0.899 |
| llm | gemma_4_31b | qwen3_14b | 727 | 0.880 | 0.882 |
| llm | gemma_4_31b | mistral_small_24b | 724 | 0.890 | 0.892 |
| llm_verified | qwen3_4b | qwen3_14b | 727 | 0.874 | 0.875 |
| llm_verified | qwen3_4b | mistral_small_24b | 724 | 0.835 | 0.836 |
| llm_verified | granite_41_8b | qwen3_14b | 727 | 0.881 | 0.883 |
| llm_verified | granite_41_8b | mistral_small_24b | 724 | 0.898 | 0.901 |
| llm_verified | llama31_8b | qwen3_14b | 727 | 0.733 | 0.733 |
| llm_verified | llama31_8b | mistral_small_24b | 724 | 0.683 | 0.683 |
| llm_verified | qwen3_14b | qwen3_14b | 727 | 0.894 | 0.895 |
| llm_verified | qwen3_14b | mistral_small_24b | 724 | 0.865 | 0.864 |
| llm_verified | mistral_small_24b | qwen3_14b | 727 | 0.902 | 0.903 |
| llm_verified | mistral_small_24b | mistral_small_24b | 724 | 0.906 | 0.907 |
| llm_verified | gemma_4_31b | qwen3_14b | 727 | 0.884 | 0.885 |
| llm_verified | gemma_4_31b | mistral_small_24b | 724 | 0.891 | 0.894 |

## Span verifier
Acceptance = verbatim span (case-insensitive, whitespace-normalised) AND >= 3 tokens AND same-LLM re-classification of the span alone returns the same value. Error = atom not in gold.

| model | kind | proposed_atoms | pass_verbatim | pass_len3 | acceptance_rate | proposed_error_rate | accepted_error_rate | rejected_error_rate | correct_atoms_rejected_share |
|---|---|---|---|---|---|---|---|---|---|
| qwen3_4b | original | 216 | 0.991 | 0.870 | 0.731 | 0.227 | 0.133 | 0.483 | 0.180 |
| qwen3_4b | paraphrase | 2283 | 0.964 | 0.958 | 0.665 | 0.229 | 0.043 | 0.596 | 0.175 |
| granite_41_8b | original | 238 | 0.971 | 0.815 | 0.777 | 0.151 | 0.005 | 0.660 | 0.089 |
| granite_41_8b | paraphrase | 2281 | 0.936 | 0.868 | 0.758 | 0.196 | 0.072 | 0.583 | 0.125 |
| llama31_8b | original | 241 | 0.996 | 0.834 | 0.598 | 0.228 | 0.007 | 0.557 | 0.231 |
| llama31_8b | paraphrase | 2015 | 0.975 | 0.848 | 0.542 | 0.222 | 0.038 | 0.440 | 0.330 |
| qwen3_14b | original | 251 | 0.940 | 0.936 | 0.713 | 0.207 | 0.000 | 0.722 | 0.101 |
| qwen3_14b | paraphrase | 2236 | 0.943 | 0.938 | 0.685 | 0.181 | 0.021 | 0.528 | 0.182 |
| mistral_small_24b | original | 206 | 0.995 | 0.995 | 0.864 | 0.126 | 0.000 | 0.929 | 0.011 |
| mistral_small_24b | paraphrase | 2053 | 0.964 | 0.964 | 0.805 | 0.137 | 0.035 | 0.561 | 0.099 |
| gemma_4_31b | original | 255 | 1.000 | 0.996 | 0.996 | 0.208 | 0.205 | 1.000 | 0.000 |
| gemma_4_31b | paraphrase | 2240 | 0.989 | 0.988 | 0.982 | 0.176 | 0.177 | 0.122 | 0.020 |

## Downstream applicability (v0 controller slot logic on each extractor's atoms)
Original: the 100 v0 cases. Paraphrase: 10 variants per case, each sentence replaced by a kept paraphrase (seeded; cases with a sentence that has no kept paraphrase are skipped). `none/no_atoms` is the floor of an extractor that returns nothing (the controller then defaults to "uncertain"). Accuracy vs v0 reference `expected_applicability`; CI = bootstrap over cases.

| extractor | model | kind | case_variants | applicability_accuracy | ci | acc_affected | acc_not_applicable | acc_uncertain | acc_contradictory |
|---|---|---|---|---|---|---|---|---|---|
| none | no_atoms | original | 100 | 0.500 | [0.400, 0.600] | 0.000 | 0.000 | 1.000 | 1.000 |
| none | no_atoms | paraphrase | 990 | 0.495 | [0.404, 0.586] | 0.000 | 0.000 | 1.000 | 1.000 |
| regex | regex_v0 | original | 100 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 1.000 | 1.000 |
| regex | regex_v0 | paraphrase | 990 | 0.473 | [0.420, 0.528] | 0.048 | 0.484 | 0.816 | 0.546 |
| llm | qwen3_4b | original | 100 | 0.840 | [0.760, 0.910] | 1.000 | 1.000 | 1.000 | 0.360 |
| llm | qwen3_4b | paraphrase | 990 | 0.943 | [0.923, 0.961] | 1.000 | 1.000 | 0.904 | 0.867 |
| llm | granite_41_8b | original | 100 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 1.000 | 1.000 |
| llm | granite_41_8b | paraphrase | 990 | 0.981 | [0.971, 0.990] | 1.000 | 1.000 | 0.984 | 0.938 |
| llm | llama31_8b | original | 100 | 0.860 | [0.790, 0.930] | 1.000 | 1.000 | 1.000 | 0.440 |
| llm | llama31_8b | paraphrase | 990 | 0.894 | [0.866, 0.921] | 1.000 | 1.000 | 0.828 | 0.742 |
| llm | qwen3_14b | original | 100 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 1.000 | 1.000 |
| llm | qwen3_14b | paraphrase | 990 | 0.986 | [0.977, 0.993] | 1.000 | 1.000 | 1.000 | 0.942 |
| llm | mistral_small_24b | original | 100 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 1.000 | 1.000 |
| llm | mistral_small_24b | paraphrase | 990 | 0.963 | [0.946, 0.978] | 1.000 | 1.000 | 0.996 | 0.850 |
| llm | gemma_4_31b | original | 100 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 1.000 | 1.000 |
| llm | gemma_4_31b | paraphrase | 990 | 0.995 | [0.989, 0.999] | 1.000 | 1.000 | 1.000 | 0.979 |
| llm_verified | qwen3_4b | original | 100 | 0.780 | [0.690, 0.850] | 1.000 | 1.000 | 1.000 | 0.120 |
| llm_verified | qwen3_4b | paraphrase | 990 | 0.874 | [0.845, 0.900] | 0.728 | 1.000 | 0.980 | 0.783 |
| llm_verified | granite_41_8b | original | 100 | 0.870 | [0.800, 0.930] | 1.000 | 1.000 | 1.000 | 0.480 |
| llm_verified | granite_41_8b | paraphrase | 990 | 0.852 | [0.814, 0.888] | 0.660 | 1.000 | 0.992 | 0.750 |
| llm_verified | llama31_8b | original | 100 | 0.790 | [0.710, 0.860] | 1.000 | 1.000 | 1.000 | 0.160 |
| llm_verified | llama31_8b | paraphrase | 990 | 0.684 | [0.633, 0.733] | 0.428 | 0.892 | 0.900 | 0.508 |
| llm_verified | qwen3_14b | original | 100 | 0.950 | [0.910, 0.990] | 1.000 | 1.000 | 1.000 | 0.800 |
| llm_verified | qwen3_14b | paraphrase | 990 | 0.860 | [0.823, 0.893] | 0.632 | 1.000 | 1.000 | 0.804 |
| llm_verified | mistral_small_24b | original | 100 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 1.000 | 1.000 |
| llm_verified | mistral_small_24b | paraphrase | 990 | 0.932 | [0.914, 0.951] | 0.888 | 1.000 | 0.996 | 0.842 |
| llm_verified | gemma_4_31b | original | 100 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 1.000 | 1.000 |
| llm_verified | gemma_4_31b | paraphrase | 990 | 0.989 | [0.980, 0.996] | 1.000 | 1.000 | 1.000 | 0.954 |

## Most frequent error patterns (pooled over the 6 LLMs; full list in `error_patterns.csv`)

| extractor | error | template_id | atom | count |
|---|---|---|---|---|
| llm | FP | affected:s1 | product_presence=installed | 1555 |
| llm | FP | contradictory:s1 | version_status=affected | 741 |
| llm | FP | contradictory:s1 | version_status=unknown | 320 |
| llm | FN | contradictory:s1 | product_presence=installed | 203 |
| llm | FP | contradictory:s1 | product_presence=potential | 203 |
| llm | FP | affected:s2 | change_approval=approved | 66 |
| llm_verified | FN | uncertain:s0 | version_status=unknown | 529 |
| llm_verified | FN | uncertain:s0 | product_presence=unknown | 466 |
| llm_verified | FP | affected:s1 | product_presence=installed | 436 |
| llm_verified | FN | affected:s1 | version_status=affected | 359 |
| llm_verified | FN | contradictory:s1 | product_presence=installed | 338 |
| llm_verified | FP | contradictory:s1 | version_status=affected | 191 |
| regex | FN | affected:s1 | version_status=affected | 216 |
| regex | FN | contradictory:s1 | product_presence=installed | 170 |
| regex | FN | affected:s0 | version_status=unknown | 167 |
| regex | FN | uncertain:s1 | version_status=unknown | 135 |
| regex | FN | not_applicable:s1 | product_presence=not_installed | 128 |
| regex | FN | affected:s0 | product_presence=installed | 117 |

## Deviations
- Paraphrase filtering was automatic (gemma_4_31b judge), not human; dataset labelled `auto_llm_judge`.
- Qwen3 models (4B and 14B) run with `enable_thinking=false`.
- LLM extractors receive the evidence record type (field name) as context, as the v0 regex does.
- Gold is regex-derived (see caveat above); applicability accuracy is the semantics-level check.
