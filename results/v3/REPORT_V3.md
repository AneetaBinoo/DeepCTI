# DeepCTI v3 — experiment improvement round (2026-10-05)

Numbers come from generated files only:
- results/v3/test/ANALYSIS_V3.md (D7, prereg-v3), results/v3/test/ADDENDUM.md (prereg-v2), results/v3/test/POSTHOC.md;
- results/v3/e11/E11_REPORT.md, results/v3/e11_d7/E11_D7_REPORT.md, results/v3/e11_d7b/E11_D7B_REPORT.md;
- results/v3/glmm_e2.md, results/v3/s3i_dev_validation.md.

Plan and gap analysis: docs/V3_PLAN.md. Pre-registrations: prereg/PREREGISTRATION_V2.md (tag `prereg-v2`) and
prereg/PREREGISTRATION_V3.md (tag `prereg-v3`). Every post-tag change: prereg/DEVIATIONS.md (D12–D23).
Audits: docs/audit/V3_AUDIT.md. Runs: 248,465 episode records across v2 and v3, 0 error records.

## 1. What the v0 paper needed and what was done

| Gap in `paper/main.tex` (v0) | v3 action |
|---|---|
| 100 template cases; Debian-only in v2; a tracker lookup solves most of v2 | **D7 DeepCTI-Live-X** (new benchmark). 822 hosts, 141 CVEs, 4 ecosystems: Ubuntu, PyPI apps, Maven jars, vendor software whose version exists only in text or banners. 41 config-gated cases; 43% temporal hold-out in test; sealed labels. |
| "Model synthesizes, controller decides": what does the LLM add? | **Unstructured-evidence settings.** Vendor software requires LLM extraction (H10); verified extraction is measured directly (H11). |
| Validated synthesis (repair, fallback) is a core paper claim but was never run | **Implemented** in DC v2.1 and measured for the first time. Note quality judged with cross-family LLM judges validated by error-injection recall (E11, H15). |
| Home-made baselines; models ≤ 31B | **Third-party baseline:** Inspect AI's ReAct agent (S3I). **Panel extension:** Granite-4.1-30B, Nemotron-Super-49B, Mistral-Medium-3.5-128B. |
| Freshness is agenda only; v2 had a restart-blindness failure | **DC v2.1:** service-aware, instance-aware evidence. Confirmed on D2 (H7/H8) and tested independently on fresh D7 drift episodes (H13). |
| VOI untested where acquisition matters | **X3 on D7**, withheld and blind arms (H14). |
| Statistics: GLMM missing | **R/lme4 GLMM** for v2 E2 (post hoc; agrees with H1). |
| RQ-2 security | Not extended: the adaptive-attack workstream was stopped. v2 E5 stands with its documented attack-strength limitation. |

## 2. Pre-registered results

### prereg-v2 (D1 test; panel addendum and DC v2.1 drift study, 9 models)

| Hypothesis | Estimate | p (Holm) | Verdict |
|---|---|---|---|
| H7 upgrade-without-restart: DCv21 − DC loss | −9.253 [−9.762, −8.432] | 0.0001 | supported, confirmatory only: these test episodes motivated v2.1 (disclosed) |
| H8 other drift kinds: DCv21 non-inferior to DC (margin 0.05) | 0.000, upper bound 0 | — | supported |

On those episodes DC v2.1 reaches accuracy 0.933, loss 0.420, DER 0.041. DC: 0.000 / 9.673 / 0.967. S3: 0.574 / 3.979 / 0.396.

### prereg-v3 (D7 test, 414 cases / 70 CVEs; 8 LLMs + LLM-free systems; Holm over H9–H14)

| Hypothesis | Estimate [95% CI] | p (Holm) | Verdict |
|---|---|---|---|
| H9 withheld arm: DC − S3 loss | −0.883 [−1.030, −0.740] | 0.0005 | supported |
| H10 vendor/tracker: DC − S1′ loss (value of verified LLM extraction) | −0.205 [−0.265, −0.142] | ≤ 0.0016 | supported |
| H11 accepted-fact error: DC − DC_noverify | −0.027 [−0.039, −0.016] | 0.0005 | supported |
| H12 LTT, blind arm, α = 0.05 | criterion met: ≥ 0.93 of 200 splits within α for every model; mean coverage gain +0.421 | — | supported |
| H13 independent drift test (D7), upgrade without restart: DCv21 − DC loss | −4.593 [−6.305, −3.021] | 0.0005 | supported |
| H14 withheld, max budget: DC (EC²) − checklist cost-to-decision | −0.35 [−0.51, −0.21]; loss difference 0 | 0.0016 | supported |
| H15 (secondary) DCv21 note faithfulness non-inferior to DC (margin −0.02) | −0.018 [−0.047, +0.010] | p = 0.23 | **not supported** |

**D7 headline table** (pooled over 8 models):

| Arm | System | Loss | DER | Coverage |
|---|---|---|---|---|
| Tracker | DC | 0.030 | 0 | 0.944 |
| Tracker | S1′ (no LLM) | 0.071 | 0 | 0.858 |
| Tracker | S1 lookup | 0.147 | 0 | 0.792 |
| Tracker | S3 ReAct | 0.852 | 0.204 | 0.969 |
| Tracker | S2 direct | 1.362 | 0.343 | 0.986 |
| Tracker | Trivy | 1.137 | 0.291 | 1.000 |
| Withheld | DC | 0.344 | 0 | 0.312 |
| Withheld | S3 | 1.227 | 0.295 | 0.935 |
| Withheld | S2 | 2.076 | 0.539 | 0.981 |
| Withheld | Trivy | 1.137 | 0.291 | 1.000 |

**Learn-then-Test (H12)** at α = 0.05 in the blind arm: realised risk 1.4–1.9%, coverage rises from 0.311 to 0.50–0.91 depending on the model (Qwen3-4B 0.50, Mistral-Medium 0.91).

**D7 drift (X5).** On upgrade without restart, DC v2.1 reaches loss 0.445, DER 0.041 (DC 5.038 / 0.497; S3 2.034 / 0.197). On rollback, DC 0.031 and DC v2.1 0.025 against S3 4.078.

## 3. What a careful reader must also know

1. **Where DC's advantage comes from.** Outside the vendor ecosystem, DC's decisions equal the LLM-free S1′. In both feed-less arms DC equals S1′ and abstains on two thirds of cases (coverage 0.31) at zero dangerous errors.
   - H9 is effectively "evidence-state controller vs ReAct".
   - The LLM decisively matters in two places: vendor software (H10) and risk-controlled release of hint-based decisions (H12).
2. **Conservative trust costs coverage.** No scanner met the dev trust rule on D7, so DC ignores scanners. In the withheld arm, plain scanners would have done better than DC's abstention on deb, pypi and maven (V3 audit).
3. **The verifier trades coverage for precision on benign data.**
   - Vendor/tracker loss: DC 0.152 vs DC_noverify 0.086 as run.
   - With the post-hoc verifier fixes (D21): DC 0.115, DC_noverify still 0.086.
   - Its benefit is the 2.7-pp lower accepted-fact error (H11) and robustness to injected text, which v3 does not test.
4. **H14 holds, but EC² is not the best acquisition rule.** Entropy-greedy is cheaper still (4.20 vs EC² 5.34 tool-cost units) at identical loss.
5. **DC v2.1 has a cost.** On upgrade-with-restart episodes it abstains more than DC (accuracy 0.74 vs 0.95). It adds about 8% tool cost and 35–143% more prompt tokens.
6. **H15 failed because of a prompt defect.** The DC v2.1 synthesis prompt said "The decision is FIXED"; 40.5% of non-fixed notes then contained "FIXED". Post hoc (D23), a neutral prompt (DCv21b) reaches:
   - faithfulness +0.036 [+0.011, +0.062] over DC;
   - note/decision consistency 0.978 (DC 0.960; DC v2.1 0.752);
   - validated synthesis: 90.9% pass first time, 3.4% repaired, 5.8% fall back.

   This needs confirmation in a new pre-registered run.
7. **Larger ReAct agents close part of the gap.**
   - D1, S3 − DC loss: Mistral-Medium-128B +0.409 (tracker) / +0.788 (withheld); Granite 8B → 30B roughly halves S3 loss.
   - D7, Mistral-Medium-128B S3 − DC: +0.181 (tracker, p = 0.005), +0.302 (withheld, p = 0.022), +0.192 (blind, p = 0.12, not significant).
   - Nemotron-49B's ReAct runs are unreliable: 25% made no tool call, using a generic Llama-3.1 tool template.
8. **The third-party baseline confirms ours.** S3I (Inspect AI) agrees with S3 on 80.6% of D7 decisions, with similar losses: tracker 0.92 / 1.14, withheld 1.50 / 1.51.
9. **Audit corrections, all logged.**
   - Non-deb drift physics (X5 fully re-run, D20).
   - Verifier header names and series numbers (post-hoc X2V, D21).
   - Environment–labeler alignment before the tag (D17, D18).
   - The pre-registered numbers above are from the corrected or as-registered runs as stated in DEVIATIONS.

## 4. Recommended changes to the paper

- **Evaluation:**
  - Replace the v0 evaluation (100 synthetic cases, lexical composite) with D1 (v2) and D7 (v3), the decision-theoretic loss, and the pre-registered H-families.
  - Keep v0 only as an appendix (E0 shows why it misled).
- **Contribution claims:** state them as supported by the data —
  - an evidence-state controller that dominates LLM agents on missed vulnerabilities across ecosystems and nine models;
  - verified LLM extraction where evidence is unstructured;
  - freshness and instance-aware verification against drift;
  - Learn-then-Test for risk-controlled coverage;
  - evidence-conditioned gating (v2 E5).
- **Related work:** add TMA-NM and Pandey et al. for C2.
- **Still missing:**
  - an attack study where attacks actually move baselines;
  - a pre-registered confirmation of the corrected synthesis (DCv21b);
  - a trust-estimation rule that does not discard useful scanners;
  - human label audit and a practitioner study;
  - container-based execution.
