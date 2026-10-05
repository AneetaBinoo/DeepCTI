# E11 — Analyst-response quality (validated synthesis, gap G2)

All numbers below are produced by `scripts/e11/*.py` (run `scripts/e11/run_all.sh`; LLM calls are cached in `results/v3/e11/cache/`). Analysis rules were fixed in `PROTOCOL.md` before system-level results were computed.

## Key findings

1. **Judge validation.** Five cross-family judges labelled 7119 claims; Fleiss κ = 0.61 (3-class), 0.64 (supported vs not). In the perturbation test (300 injected errors, 150 controls; 279–291 and 144–146 scored per judge after the leave-one-out filter) gemma-4-31B recall 0.983 / false alarm 0.034, Granite-4.1-30B recall 0.857 / false alarm 0.014, Nemotron-Super-49B recall 0.921 / false alarm 0.055 passed the pre-specified rule (recall ≥ 0.85, false alarm ≤ 0.10); Mistral-Small-24B (0.793 / 0.048), Qwen3-14B (0.707 / 0.034) failed (invented-id recall Mistral-Small-24B 0.589, Qwen3-14B 0.225). Every scored claim has at least 2 eligible validated judges. Granite-4.1-30B passes narrowly (recall CI lower bound 0.811).
2. **Faithfulness.** With the tracker, DC's notes are 92.0 [89.6, 94.3]% supported, statistically indistinguishable from the ReAct baselines S3–S5 (91.7–92.8%) and above one-shot S2 (85.6 [82.6, 88.3]%). Without the tracker every system drops (DC 79.0 [76.5, 81.6]%, baselines 79.3–83.8%). Hallucination (contradicted + not in evidence) is therefore 8.0% (DC, tracker) to 21.0% (DC, withheld). Paired differences DC − S3/S4/S5 with the tracker are 0.3 [-2.9, 3.5], 0.2 [-2.8, 3.1], -0.8 [-3.9, 2.4] pp (DC − S2: 6.4 [2.5, 10.6] pp). In the withheld arm the sign depends on the judge: gemma-4-31B and Nemotron-Super-49B rate DC below all four baselines, Granite-4.1-30B above all four (§5), so no ordering of DC against the baselines is claimed there.
3. **The note follows the decision.** Explanation–decision consistency is 97.6 [96.1, 99.0]% for DC (the decision is fixed before the LLM writes) vs 74.1 [69.4, 78.5]% for S2 and 88.5–89.4% for S3–S5. DC episodes with any judge reading a different status from the note: 9 (llama31_8b/tracker: 9); inspection shows llama31_8b notes asserting both 'affected' and 'fix applied'.
4. **Citations exist but are often insufficient.** 89.3% of all 5436 DC notes cite call ids and 99.49% of cited ids exist, but only 21.4 [16.5, 26.8]% (tracker) and 53.9 [46.9, 60.9]% (withheld) of DC's cited claims are supported by the cited outputs alone. With the tracker, 348 of 352 ids cited in DC claims point to package-query outputs, including 270 of the 274 ids behind invalid citations. Typical invalid cases (from `claims.jsonl`): '…is within the affected version range [c002]', '…the fix … has been verified to be present in the system [c002]' — the cited output is the installed-version record, while the range/fix conclusion also needs the tracker's fixed version, which is not cited. Cited outputs contradict the claim in 0.7% (tracker) and 19.5% (withheld) of cited claims.
5. **Unfaithful notes accompany wrong decisions.** Pooled over arms, faithfulness is DC 89.1% when the decision is correct vs 70.1% when wrong; S2 91.5% when the decision is correct vs 73.1% when wrong; S3 92.4% when the decision is correct vs 74.6% when wrong; S4 94.7% when the decision is correct vs 77.2% when wrong; S5 93.1% when the decision is correct vs 73.8% when wrong.
6. **Validation / repair / fallback.** The v2 DC records contain no response-validation, repair or fallback information, and the v2 code had none (single LLM call). The paper's 'validated synthesis' (§III-D) was not exercised in v2; the rates above are what a post-hoc validator measures, not what a deployed one did (§4).
7. **DC's evidence view matters.** Judged against the raw tool outputs only (without the controller state DC's prompt contained), DC faithfulness falls to 81.3 [78.1, 84.4]% (tracker) and 61.1 [57.2, 65.3]% (withheld), i.e. a sizeable share of DC claims is supported only through the controller's belief state (atom values, source groups), not directly by a tool output. Against raw outputs alone DC would rank below the baselines; which view is right depends on whether the verified state counts as evidence for the analyst.

## 1. Setup

- Episodes: 1800 frozen v2 test episodes (`runs/test/E2`), 180 distinct cases (83 CVEs), stratified by variant; 180 episodes per system x arm pooled over the six generators (30 cases per generator, all 5 systems x 2 arms on each). Episodes with a recorded error: 0. Evidence replay mismatches: 0 (every replayed tool output equals its recorded prefix, id and status).
- Claims: 7123 atomic claims extracted (gemma-4-31B; Granite-4.1-30B for gemma-generated episodes); 35 episodes yielded no claim ({'S2': 1, 'S3': 12, 'S4': 11, 'S5': 11}). Extraction fidelity check (every version string and call id in a claim occurs in the source explanation): 99.97% of claims.
- Judges: five candidate judges from five families (gemma, mistral, qwen, granite, llama-lineage Nemotron), per-claim calls with JSON-schema output at temperature 0; a judge is never applied to episodes generated by its own family. The DC primary evidence includes the controller evidence state that DC's response prompt received; a no-state sensitivity is reported.

## 2. Judge validation (no humans)

### 2a. Inter-judge agreement

| what | scheme | judges | n_items | kappa | pct_agree |
|---|---|---|---|---|---|
| claim_label | 3-class | all 5 candidates | 7119 | 0.613 | 81.6% (all 5 agree) |
| claim_label | binary | all 5 candidates | 7119 | 0.640 | 82.5% (all 5 agree) |
| asserted_status | 5-class | all 5 candidates | 1800 | 0.912 | 89.7% (all 5 agree) |
| asserted_status | binary | all 5 candidates | 1800 | 0.984 | 99.1% (all 5 agree) |
| claim_label | 3-class | 3 validated | 7121 | 0.609 | 86.0% (all 3 agree) |
| claim_label | binary | 3 validated | 7121 | 0.635 | 86.9% (all 3 agree) |
| asserted_status | 5-class | 3 validated | 1800 | 0.899 | 91.0% (all 3 agree) |
| asserted_status | binary | 3 validated | 1800 | 0.982 | 99.2% (all 3 agree) |
(For asserted status, `binary` = affected vs any other answer.)


Pairwise Cohen κ on claim labels:

| pair | 3-class | binary |
|---|---|---|
| gemma_4_31b~granite_41_30b | 0.636 | 0.655 |
| gemma_4_31b~mistral_small_24b | 0.582 | 0.600 |
| gemma_4_31b~nemotron_super_49b | 0.598 | 0.633 |
| gemma_4_31b~qwen3_14b | 0.625 | 0.665 |
| granite_41_30b~nemotron_super_49b | 0.597 | 0.620 |
| mistral_small_24b~granite_41_30b | 0.642 | 0.661 |
| mistral_small_24b~nemotron_super_49b | 0.591 | 0.606 |
| mistral_small_24b~qwen3_14b | 0.599 | 0.630 |
| qwen3_14b~granite_41_30b | 0.644 | 0.670 |
| qwen3_14b~nemotron_super_49b | 0.628 | 0.666 |

Label distribution per judge (all claims, main mode):

| judge | contradicted | not_in_evidence | supported |
|---|---|---|---|
| gemma_4_31b | 10.7% | 5.0% | 84.2% |
| granite_41_30b | 6.9% | 2.9% | 90.2% |
| mistral_small_24b | 7.4% | 4.5% | 88.2% |
| nemotron_super_49b | 10.1% | 5.9% | 84.0% |
| qwen3_14b | 8.4% | 4.9% | 86.7% |

### 2b. Perturbation test

Injected errors: 300 (flipped_polarity: 75, invented_id: 75, wrong_status: 75, wrong_version: 75); untouched controls: 150. Scored per judge on items whose base claim is supported by >= 3 of the other 4 judges (leave-one-out). Rule (pre-specified): recall >= 0.85 and false alarm <= 0.10.

| judge | n_injected | recall [95% Wilson] | n_controls | false alarm [95% Wilson] | judge_errors | passes |
|---|---|---|---|---|---|---|
| gemma_4_31b | 290 | 0.983 [0.960, 0.993] | 145 | 0.034 [0.015, 0.078] | 0 | **yes** |
| mistral_small_24b | 290 | 0.793 [0.743, 0.836] | 145 | 0.048 [0.024, 0.096] | 0 | no |
| qwen3_14b | 287 | 0.707 [0.652, 0.757] | 146 | 0.034 [0.015, 0.078] | 0 | no |
| granite_41_30b | 279 | 0.857 [0.811, 0.893] | 144 | 0.014 [0.004, 0.049] | 0 | **yes** |
| nemotron_super_49b | 291 | 0.921 [0.884, 0.947] | 146 | 0.055 [0.028, 0.104] | 0 | **yes** |

Flag rate by edit type (for `control` this is the false-alarm rate):

| judge | control | flipped_polarity | invented_id | wrong_status | wrong_version |
|---|---|---|---|---|---|
| gemma_4_31b | 0.034 | 0.986 | 1.000 | 0.958 | 0.987 |
| granite_41_30b | 0.014 | 0.914 | 0.739 | 0.909 | 0.865 |
| mistral_small_24b | 0.048 | 0.873 | 0.589 | 0.806 | 0.905 |
| nemotron_super_49b | 0.055 | 0.875 | 0.959 | 0.972 | 0.880 |
| qwen3_14b | 0.034 | 0.878 | 0.225 | 0.882 | 0.838 |

**Validated judges: gemma_4_31b, granite_41_30b, nemotron_super_49b** (at least two pass).

## 3. Response quality per system x arm (pooled over generators)

Soft labels: each claim scores the fraction of eligible validated judges (validated and not of the generator's family) giving a label. Percentages with 95% CVE-clustered bootstrap CIs (2,000 resamples).

| system | arm | episodes | claims | faithfulness % | contradicted % | not in evidence % | expl.–decision consistency % | chars (mean) | claims/ep. |
|---|---|---|---|---|---|---|---|---|---|
| DC | tracker | 180 | 697 | 92.0 [89.6, 94.3] | 5.6 [3.6, 7.8] | 2.4 [1.2, 3.9] | 95.3 [92.2, 97.9] | 346 | 3.87 |
| DC | withheld | 180 | 727 | 79.0 [76.5, 81.6] | 13.9 [12.1, 15.7] | 7.1 [5.5, 8.8] | 100.0 [100.0, 100.0] | 358 | 4.04 |
| S2 | tracker | 180 | 992 | 85.6 [82.6, 88.3] | 12.9 [10.2, 15.8] | 1.5 [0.7, 2.5] | 73.0 [67.1, 78.9] | 360 | 5.51 |
| S2 | withheld | 180 | 978 | 82.3 [79.7, 84.8] | 14.3 [11.8, 16.8] | 3.3 [2.2, 4.6] | 75.2 [69.7, 80.4] | 370 | 5.43 |
| S3 | tracker | 180 | 620 | 91.7 [89.3, 93.9] | 6.6 [4.7, 8.7] | 1.7 [0.7, 3.1] | 93.1 [90.1, 95.8] | 190 | 3.44 |
| S3 | withheld | 180 | 605 | 80.9 [77.2, 84.4] | 8.7 [6.1, 11.7] | 10.4 [7.5, 13.5] | 83.9 [78.7, 88.5] | 201 | 3.36 |
| S4 | tracker | 180 | 575 | 91.8 [89.5, 94.1] | 6.3 [4.4, 8.2] | 1.9 [0.8, 3.4] | 90.9 [87.1, 94.3] | 165 | 3.19 |
| S4 | withheld | 180 | 573 | 83.8 [80.4, 87.1] | 6.7 [4.2, 9.8] | 9.5 [7.0, 12.2] | 87.5 [82.5, 92.1] | 183 | 3.18 |
| S5 | tracker | 180 | 687 | 92.8 [90.5, 94.9] | 5.5 [3.9, 7.3] | 1.7 [0.9, 2.8] | 93.1 [89.7, 96.2] | 229 | 3.82 |
| S5 | withheld | 180 | 669 | 79.3 [75.5, 83.2] | 9.6 [6.7, 13.1] | 11.0 [8.0, 14.2] | 85.6 [80.5, 90.2] | 239 | 3.72 |

Hallucination rate = contradicted + not in evidence = 100 − faithfulness.

Pooled over arms:

| system | episodes | claims | faithfulness % | hallucination % | consistency % | asserts no status % |
|---|---|---|---|---|---|---|
| DC | 360 | 1424 | 85.4 [83.7, 86.9] | 14.6 [13.1, 16.3] | 97.6 [96.1, 99.0] | 1.2 |
| S2 | 360 | 1970 | 84.0 [81.6, 86.2] | 16.0 [13.8, 18.4] | 74.1 [69.4, 78.5] | 3.6 |
| S3 | 360 | 1225 | 86.4 [83.9, 88.8] | 13.6 [11.2, 16.1] | 88.5 [85.1, 91.4] | 4.8 |
| S4 | 360 | 1148 | 87.8 [85.6, 89.9] | 12.2 [10.1, 14.4] | 89.2 [86.0, 92.0] | 4.5 |
| S5 | 360 | 1356 | 86.1 [83.8, 88.5] | 13.9 [11.5, 16.2] | 89.4 [86.2, 92.2] | 4.2 |

### Citation validity

| system | arm | claims citing a call id | share of claims citing % | cited ids that exist % | citation validity % (ids exist AND cited outputs support the claim) |
|---|---|---|---|---|---|
| DC | tracker | 352 | 50.5 | 98.9 | 21.4 [16.5, 26.8] |
| DC | withheld | 250 | 34.4 | 100.0 | 53.9 [46.9, 60.9] |
| S2 | tracker | 27 | 2.7 | 100.0 | 92.6 [81.5, 100.0] |
| S2 | withheld | 26 | 2.7 | 100.0 | 96.2 [91.9, 100.0] |
| S4 | tracker | 2 | 0.3 | 100.0 | 16.7 [–, –] |

### DC sensitivity: evidence without the controller state

| arm | faithfulness % (tool outputs + [state], primary) | faithfulness % (tool outputs only) |
|---|---|---|
| tracker | 92.0 [89.6, 94.3] | 81.3 [78.1, 84.4] |
| withheld | 79.0 [76.5, 81.6] | 61.1 [57.2, 65.3] |

### Per generator (faithfulness %, point estimates; CIs in `metrics_system_model_arm.csv`)

| system | arm | gemma4_31b | granite41_8b | llama31_8b | mistral_small_24b | qwen3_14b | qwen3_4b |
|---|---|---|---|---|---|---|---|
| DC | tracker | 88.5 | 91.5 | 80.7 | 99.5 | 92.8 | 98.6 |
| DC | withheld | 91.2 | 74.3 | 79.1 | 75.8 | 79.2 | 77.8 |
| S2 | tracker | 97.9 | 82.3 | 82.8 | 84.2 | 89.3 | 74.8 |
| S2 | withheld | 90.0 | 72.8 | 80.4 | 90.6 | 88.2 | 70.9 |
| S3 | tracker | 97.0 | 87.0 | 81.2 | 97.8 | 98.8 | 82.4 |
| S3 | withheld | 89.5 | 61.5 | 82.1 | 87.4 | 91.3 | 72.5 |
| S4 | tracker | 97.9 | 88.3 | 88.6 | 96.1 | 93.6 | 83.5 |
| S4 | withheld | 91.0 | 77.4 | 77.3 | 87.6 | 90.9 | 73.7 |
| S5 | tracker | 96.8 | 90.0 | 91.5 | 97.9 | 96.7 | 83.3 |
| S5 | withheld | 87.5 | 63.7 | 77.3 | 93.0 | 88.0 | 69.8 |

Explanation–decision consistency % per generator:

| system | arm | gemma4_31b | granite41_8b | llama31_8b | mistral_small_24b | qwen3_14b | qwen3_4b |
|---|---|---|---|---|---|---|---|
| DC | tracker | 100.0 | 100.0 | 71.7 | 100.0 | 100.0 | 100.0 |
| DC | withheld | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 |
| S2 | tracker | 100.0 | 81.7 | 61.7 | 73.3 | 75.6 | 45.6 |
| S2 | withheld | 90.0 | 68.3 | 88.3 | 72.2 | 87.8 | 44.4 |
| S3 | tracker | 100.0 | 90.0 | 88.3 | 95.6 | 98.9 | 85.6 |
| S3 | withheld | 96.7 | 96.7 | 66.7 | 90.0 | 93.3 | 60.0 |
| S4 | tracker | 100.0 | 86.7 | 96.7 | 88.9 | 90.0 | 83.3 |
| S4 | withheld | 100.0 | 90.0 | 75.0 | 86.7 | 93.3 | 80.0 |
| S5 | tracker | 100.0 | 95.0 | 81.7 | 98.9 | 95.6 | 87.8 |
| S5 | withheld | 96.7 | 90.0 | 70.0 | 92.2 | 88.9 | 75.6 |

### Faithfulness by decision correctness (submitted status vs sealed test label)

| system | decision correct | episodes | claims | faithfulness % | consistency % |
|---|---|---|---|---|---|
| DC | False | 59 | 279 | 70.1 [65.7, 74.3] | 100.0 [100.0, 100.0] |
| DC | True | 301 | 1145 | 89.1 [87.0, 91.1] | 97.2 [95.3, 98.8] |
| S2 | False | 127 | 807 | 73.1 [69.4, 76.8] | 55.8 [45.7, 65.5] |
| S2 | True | 233 | 1163 | 91.5 [89.0, 93.8] | 84.0 [79.6, 88.5] |
| S3 | False | 116 | 414 | 74.6 [70.0, 79.0] | 73.7 [65.9, 80.7] |
| S3 | True | 244 | 811 | 92.4 [90.4, 94.3] | 95.5 [92.5, 98.0] |
| S4 | False | 130 | 449 | 77.2 [73.3, 80.8] | 74.4 [67.2, 81.8] |
| S4 | True | 230 | 699 | 94.7 [92.7, 96.3] | 97.6 [95.6, 99.2] |
| S5 | False | 118 | 486 | 73.8 [69.3, 78.2] | 73.3 [65.9, 80.3] |
| S5 | True | 242 | 870 | 93.1 [90.8, 95.1] | 97.2 [95.0, 98.9] |

### Per-judge sensitivity (faithfulness %, each validated judge on the episodes it is eligible for)

| system | arm | gemma_4_31b | granite_41_30b | nemotron_super_49b |
|---|---|---|---|---|
| DC | tracker | 92.0 | 95.0 | 92.2 |
| DC | withheld | 68.3 | 92.2 | 76.3 |
| S2 | tracker | 80.9 | 88.3 | 85.3 |
| S2 | withheld | 77.8 | 87.3 | 81.9 |
| S3 | tracker | 89.6 | 94.9 | 90.9 |
| S3 | withheld | 75.2 | 88.8 | 79.0 |
| S4 | tracker | 89.5 | 94.0 | 91.1 |
| S4 | withheld | 76.5 | 89.7 | 83.7 |
| S5 | tracker | 91.2 | 95.9 | 91.0 |
| S5 | withheld | 74.6 | 86.7 | 77.9 |

## 4. DC validation / repair / fallback in the raw records

- Searched every DC test record (5436 episodes: 6 generators x 2 arms x 453 cases) for fields matching `repair|fallback|valid|retry|regenerat` (outside `calls`/`trace`): **0 such fields**. The v2 records contain **no information about response validation, repair or fallback**, and the v2 DC code path that produced them (`Controller._explain`) issues one LLM call with no citation/claim check, no repair attempt and no deterministic fallback. Repair and fallback rates on real data therefore cannot be reported from v2; the claim/citation checks in §3 are what such a validator would have measured post hoc.
- What the records do contain is the verdict log of the *extraction* verifier (a different stage: LLM version-extraction proposals checked against the tool output): installed_version|accepted=True|accepted: 2407; installed_version|accepted=False|span does not name the case component: 40.
- Deterministic checks over all DC explanations: empty 0; with >= 1 call-id citation 4853 (89.3%); cited call ids that exist in the episode 6843/6878 (99.49%); explanations that hit the 200-token limit (episodes whose only LLM call was the explanation and whose usage records a length truncation) 0/2652.

| generator | arm | with citation % | cited ids existing | hit token limit |
|---|---|---|---|---|
| gemma4_31b | tracker | 100.0 | 455/455 | 0/442 |
| gemma4_31b | withheld | 100.0 | 839/839 | 0/0 |
| granite41_8b | tracker | 100.0 | 437/469 | 0/442 |
| granite41_8b | withheld | 100.0 | 925/925 | 0/0 |
| llama31_8b | tracker | 61.1 | 278/280 | 0/442 |
| llama31_8b | withheld | 51.7 | 381/381 | 0/0 |
| mistral_small_24b | tracker | 100.0 | 455/455 | 0/442 |
| mistral_small_24b | withheld | 100.0 | 897/897 | 0/0 |
| qwen3_14b | tracker | 100.0 | 455/455 | 0/442 |
| qwen3_14b | withheld | 100.0 | 844/844 | 0/0 |
| qwen3_4b | tracker | 89.8 | 408/409 | 0/442 |
| qwen3_4b | withheld | 68.7 | 469/469 | 0/0 |

## 5. Secondary and post-hoc analyses (not pre-specified; see PROTOCOL.md, Deviations)

### DC minus each baseline (paired by case within generator; CVE-clustered paired bootstrap)

| arm | baseline | Δ faithfulness DC − baseline (pp) | Δ consistency DC − baseline (pp) |
|---|---|---|---|
| tracker | S2 | 6.4 [2.5, 10.6] | 22.3 [16.1, 28.6] |
| tracker | S3 | 0.3 [-2.9, 3.5] | 2.2 [-1.6, 6.1] |
| tracker | S4 | 0.2 [-2.8, 3.1] | 4.4 [-0.1, 9.1] |
| tracker | S5 | -0.8 [-3.9, 2.4] | 2.1 [-1.9, 6.3] |
| withheld | S2 | -3.4 [-6.4, -0.1] | 24.8 [19.6, 30.3] |
| withheld | S3 | -1.9 [-5.8, 2.2] | 16.1 [11.5, 21.3] |
| withheld | S4 | -4.9 [-8.5, -1.0] | 12.5 [7.9, 17.5] |
| withheld | S5 | -0.4 [-4.1, 3.7] | 14.4 [9.8, 19.5] |

Per validated judge (Δ faithfulness, pp):

| arm | baseline | gemma_4_31b | granite_41_30b | nemotron_super_49b |
|---|---|---|---|---|
| tracker | S2 | +11.0 [+6.4, +15.4] | +6.7 [+3.0, +10.5] | +6.9 [+1.7, +11.8] |
| tracker | S3 | +2.3 [-2.1, +6.7] | +0.1 [-3.3, +3.2] | +1.3 [-2.3, +4.8] |
| tracker | S4 | +2.4 [-1.6, +6.3] | +1.0 [-2.4, +4.1] | +1.1 [-2.3, +4.2] |
| tracker | S5 | +0.7 [-3.9, +5.2] | -0.9 [-4.0, +2.0] | +1.2 [-2.3, +4.5] |
| withheld | S2 | -9.5 [-14.4, -4.7] | +4.9 [+1.0, +8.6] | -5.6 [-10.5, -0.7] |
| withheld | S3 | -7.0 [-12.4, -1.3] | +3.4 [-1.0, +7.6] | -2.7 [-8.4, +3.3] |
| withheld | S4 | -8.2 [-13.5, -2.5] | +2.5 [-1.4, +6.4] | -7.4 [-13.3, -1.3] |
| withheld | S5 | -6.4 [-11.2, -1.3] | +5.5 [+1.4, +9.9] | -1.6 [-7.1, +4.2] |

### Coarse explanation–decision consistency (fixed and not_affected merged)

| system | arm | strict % (primary) | coarse % | asserts no status % |
|---|---|---|---|---|
| DC | tracker | 95.3 [92.2, 97.9] | 95.3 [92.2, 97.9] | 2.5 |
| DC | withheld | 100.0 [100.0, 100.0] | 100.0 [100.0, 100.0] | 0.0 |
| S2 | tracker | 73.0 [67.1, 78.9] | 91.7 [88.0, 95.2] | 4.8 |
| S2 | withheld | 75.2 [69.7, 80.4] | 92.9 [89.3, 95.9] | 2.3 |
| S3 | tracker | 93.1 [90.1, 95.8] | 96.2 [93.9, 98.1] | 2.4 |
| S3 | withheld | 83.9 [78.7, 88.5] | 86.1 [81.2, 90.4] | 7.2 |
| S4 | tracker | 90.9 [87.1, 94.3] | 95.1 [92.2, 97.5] | 3.1 |
| S4 | withheld | 87.5 [82.5, 92.1] | 89.9 [85.4, 94.0] | 6.0 |
| S5 | tracker | 93.1 [89.7, 96.2] | 96.6 [94.2, 98.5] | 2.0 |
| S5 | withheld | 85.6 [80.5, 90.2] | 90.7 [86.6, 94.4] | 6.3 |

### Citation failures: contradicted vs insufficient

| system | arm | cited claims | valid % | cited outputs contradict the claim % |
|---|---|---|---|---|
| DC | tracker | 352 | 21.4 [16.5, 26.8] | 0.7 [0.2, 1.4] |
| DC | withheld | 250 | 53.9 [46.9, 60.9] | 19.5 [13.8, 25.4] |
| S2 | tracker | 27 | 92.6 [81.5, 100.0] | 1.9 [0.0, 6.2] |
| S2 | withheld | 26 | 96.2 [91.9, 100.0] | 0.0 [0.0, 0.0] |
| S4 | tracker | 2 | 16.7 [–, –] | 0.0 [–, –] |
The remainder (100 − valid − contradicted, plus missing ids) is *insufficient*: the cited outputs exist but do not by themselves establish the claim.

### Status/conclusion claims vs factual-detail claims

| system | arm | claim type | claims | faithfulness % | contradicted % | not in evidence % |
|---|---|---|---|---|---|---|
| DC | tracker | factual detail | 534 | 90.6 [87.9, 93.2] | 6.7 [4.3, 9.3] | 2.7 [1.4, 4.3] |
| DC | tracker | status/conclusion | 163 | 96.5 [93.8, 98.9] | 2.1 [0.3, 4.5] | 1.3 [0.2, 3.1] |
| DC | withheld | factual detail | 555 | 78.9 [76.2, 81.6] | 13.1 [11.1, 14.9] | 8.0 [6.2, 10.0] |
| DC | withheld | status/conclusion | 172 | 79.4 [74.8, 84.2] | 16.6 [12.2, 20.8] | 4.1 [2.5, 5.8] |
| S2 | tracker | factual detail | 798 | 87.9 [84.8, 90.7] | 10.7 [8.0, 13.7] | 1.4 [0.5, 2.5] |
| S2 | tracker | status/conclusion | 194 | 76.2 [70.6, 81.7] | 21.7 [16.0, 27.7] | 2.1 [0.4, 4.1] |
| S2 | withheld | factual detail | 751 | 86.3 [83.8, 88.8] | 10.2 [7.9, 12.7] | 3.5 [2.3, 4.7] |
| S2 | withheld | status/conclusion | 227 | 69.2 [63.3, 74.9] | 27.9 [22.1, 33.7] | 2.9 [1.3, 4.7] |
| S3 | tracker | factual detail | 505 | 92.6 [90.4, 94.7] | 5.8 [3.9, 7.9] | 1.6 [0.6, 3.0] |
| S3 | tracker | status/conclusion | 115 | 87.7 [81.8, 92.7] | 10.1 [6.0, 15.0] | 2.2 [0.0, 5.5] |
| S3 | withheld | factual detail | 450 | 84.8 [81.1, 88.5] | 6.9 [4.5, 9.6] | 8.3 [5.3, 11.6] |
| S3 | withheld | status/conclusion | 155 | 69.6 [61.6, 77.4] | 13.8 [8.4, 19.4] | 16.7 [10.5, 23.7] |
| S4 | tracker | factual detail | 453 | 94.6 [92.7, 96.3] | 3.4 [2.1, 4.7] | 2.0 [0.8, 3.5] |
| S4 | tracker | status/conclusion | 122 | 81.4 [74.9, 87.4] | 16.9 [11.3, 23.3] | 1.6 [0.0, 3.8] |
| S4 | withheld | factual detail | 429 | 89.4 [86.4, 92.0] | 5.3 [3.0, 8.0] | 5.3 [3.6, 7.3] |
| S4 | withheld | status/conclusion | 144 | 67.4 [60.0, 74.6] | 10.8 [5.4, 17.8] | 21.9 [15.6, 28.2] |
| S5 | tracker | factual detail | 569 | 93.6 [91.4, 95.6] | 4.7 [3.0, 6.6] | 1.6 [0.7, 2.6] |
| S5 | tracker | status/conclusion | 118 | 88.6 [83.2, 93.2] | 9.2 [5.2, 13.8] | 2.3 [0.4, 4.7] |
| S5 | withheld | factual detail | 512 | 81.8 [78.0, 85.3] | 7.9 [5.3, 10.9] | 10.3 [7.2, 13.5] |
| S5 | withheld | status/conclusion | 157 | 71.3 [63.0, 79.3] | 15.3 [8.9, 22.8] | 13.4 [8.7, 18.5] |

### By arm x decision correctness

| system | arm | decision correct | episodes | faithfulness % | contradicted % | consistency % |
|---|---|---|---|---|---|---|
| DC | tracker | True | 180 | 92.0 [89.6, 94.3] | 5.6 [3.6, 7.8] | 95.3 [92.2, 97.9] |
| DC | withheld | False | 59 | 70.1 [65.7, 74.3] | 17.6 [14.5, 20.8] | 100.0 [100.0, 100.0] |
| DC | withheld | True | 121 | 84.5 [81.0, 88.1] | 11.7 [9.2, 13.9] | 100.0 [100.0, 100.0] |
| S2 | tracker | False | 49 | 69.3 [63.3, 75.0] | 28.8 [23.1, 34.6] | 42.2 [29.2, 56.6] |
| S2 | tracker | True | 131 | 92.7 [89.9, 95.1] | 5.9 [3.7, 8.7] | 84.5 [78.4, 89.8] |
| S2 | withheld | False | 78 | 75.4 [71.4, 79.3] | 20.0 [16.1, 23.9] | 64.3 [53.8, 75.1] |
| S2 | withheld | True | 102 | 89.8 [86.3, 93.0] | 8.3 [5.5, 11.3] | 83.5 [77.5, 89.3] |
| S3 | tracker | False | 38 | 72.4 [66.1, 78.8] | 22.4 [16.8, 29.0] | 77.6 [67.1, 87.0] |
| S3 | tracker | True | 142 | 96.7 [94.8, 98.2] | 2.5 [1.3, 4.1] | 97.2 [94.6, 99.1] |
| S3 | withheld | False | 78 | 75.5 [69.7, 81.3] | 11.6 [7.5, 16.2] | 71.8 [61.7, 81.0] |
| S3 | withheld | True | 102 | 85.8 [82.4, 89.4] | 6.0 [3.4, 9.3] | 93.1 [88.2, 97.2] |
| S4 | tracker | False | 43 | 75.2 [70.5, 80.6] | 20.5 [15.4, 25.8] | 65.9 [53.3, 78.1] |
| S4 | tracker | True | 137 | 97.8 [96.5, 98.9] | 1.1 [0.5, 1.9] | 98.8 [96.7, 100.0] |
| S4 | withheld | False | 87 | 78.2 [73.1, 82.9] | 8.2 [5.1, 12.1] | 78.5 [69.5, 86.8] |
| S4 | withheld | True | 93 | 89.8 [86.0, 93.7] | 5.1 [1.8, 9.0] | 95.9 [92.0, 99.1] |
| S5 | tracker | False | 35 | 75.6 [70.2, 80.9] | 20.0 [15.4, 25.0] | 73.3 [60.8, 85.4] |
| S5 | tracker | True | 145 | 97.3 [95.8, 98.6] | 1.6 [0.8, 2.6] | 97.9 [95.7, 99.8] |
| S5 | withheld | False | 83 | 73.0 [67.2, 78.6] | 13.1 [8.6, 18.1] | 73.3 [64.5, 82.1] |
| S5 | withheld | True | 97 | 86.0 [81.5, 90.2] | 6.0 [2.5, 10.0] | 96.0 [92.4, 99.2] |

## 6. Limitations

- No human labels. Judge validity rests on (a) agreement among five cross-family judges and (b) recall of synthetic, deterministic edits; the edits are minimal and lexical (version bump, negation, status swap, absent id), so recall on subtler real errors (wrong reasoning, partially supported claims) may be lower. Perturbed items that all five judges still label supported (candidate non-errors): 1 (flipped_polarity: 0, invented_id: 0, wrong_status: 1, wrong_version: 0). Some edits are ungrammatical (e.g. double negation).
- The main metric averages 3 validated judges whose levels differ (per-judge tables in §3 and §5); Granite-4.1-30B labels the most claims supported and Granite-4.1-30B passes the rule only narrowly, so absolute faithfulness levels carry judge uncertainty beyond the bootstrap CIs, which cover only CVE sampling.
- Claims are extracted by one LLM (gemma-4-31B, or Granite-4.1-30B for gemma-generated notes), which is also a judge for non-gemma episodes; extraction was checked only for lexical fidelity (versions and ids copied from the note). 75 wrong-version perturbations come from S2–S5 only because DC notes rarely contain version strings.
- Notes are scored against the outputs the system observed (S2 2,500 chars per output; S3–S5 3,000; DC 3,000 plus the controller evidence state). A claim that is true of the host but absent from those outputs counts as not in evidence; 'supported' does not mean the decision is correct.
- The sample is 180 cases (83 CVEs), 30 per generator; per-generator cells have wide CIs (`metrics_system_model_arm.csv`). Recorded explanations were capped at 1,500 characters by the v2 runner.
- Temperature-0 judging is not bit-deterministic under vLLM batching; reported numbers are fixed by the response cache (`cache/`), see PROTOCOL.md Deviations 4.
- Status-claim vs detail split, coarse consistency, citation-contradiction split, per-judge differences and DC-minus-baseline differences are post hoc / secondary.

## Files

`PROTOCOL.md` (pre-specified rules), `sample.csv`, `episodes.jsonl`, `claims.jsonl`, `judgments.jsonl`, `status_judgments.jsonl`, `perturbations.jsonl`, `perturb_judgments.jsonl`, `agreement.csv`, `judge_label_distribution.csv`, `judge_validation.csv`, `judge_validation_by_type.csv`, `validated_judges.json`, `claim_scores.csv`, `episode_scores.csv`, `metrics_system_arm.csv`, `metrics_system.csv`, `metrics_system_model_arm.csv`, `metrics_by_correctness.csv`, `metrics_by_arm_correctness.csv`, `metrics_by_claim_type.csv`, `metrics_per_judge.csv`, `diff_dc_vs_baselines.csv`, `diff_dc_vs_baselines_per_judge.csv`, `dc_citation_tools.csv`, `dc_records.csv`, `dc_records_fields.json`, `cache/` (all LLM responses). Code: `src/deepcti/judge/`, `scripts/e11/`, tests `tests/v3/test_e11_*.py`.
