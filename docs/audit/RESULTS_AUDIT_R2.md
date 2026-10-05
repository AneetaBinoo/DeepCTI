# Results audit R2: test-split runs and pre-registered hypotheses

Date: 2026-10-05. Branch `v2-experiment`, HEAD `d41b88c` (tag `prereg-v1`; deviations D1–D7). Auditor: independent (Claude).
The sealed test labels were read with `load_labels('test', allow_sealed=True)`.

**Scope.** `runs/test/{E2,E3,E4,E5,E9,KM,ABL}/*.jsonl`, `scripts/paper/analyze.py --split test --allow-sealed`
and `results/v2/test/tables/*`. Nothing under `src/`, `scripts/`, `data/`, `runs/` or `prereg/` was modified.

**Method.**
* I copied the runs to two read-only snapshots:
  * Snapshot 1 at 06:09:17 UTC, used for the like-for-like comparison with `analyze.py`.
  * Snapshot 2 at 06:15:07 UTC, used for the latest numbers.
* I ran `analyze.py` unmodified twice:
  * on the live tree (06:07–06:09), which wrote `results/v2/test/*`;
  * against snapshot 1 through a shadow root (copied scripts, symlinked `src/`, `data/`, `config/`, `runs/test` → snapshot),
    so that its inputs equal mine.
* My own scripts are in the session scratchpad and are not committed:
  * `integrity.py`;
  * `recompute.py`, which has its own loss matrix, its own gold rule, its own join to `data/sealed/test_labels.jsonl`
    and its own sign-flip test;
  * several ad-hoc probes.
* Regression tests: `tests/v2/test_results_audit_r2.py` (9 pass, about 3 s).

**Completeness at snapshot 2.** These blocks were partial or missing. Every pooled number that involves them is provisional.

| block | state at snapshot 2 |
|---|---|
| E2 Gemma-4-31B | partial: 1,742 / 4,530 records, about 146 cases per arm × system |
| E5 Gemma-4-31B | absent |
| E9 Mistral, Gemma | absent |
| E3 Mistral | absent; Qwen3-14B is complete, 6,000 / 6,000 |
| ABL Mistral | absent |
| E4 Gemma | absent; Mistral is complete, 605 |
| E5 Mistral | absent; the allocation says E5 uses Qwen3-14B, Gemma and Llama |

---

## 1. Recomputed headline numbers

### 1.1 `analyze.py` vs my recomputation on identical inputs (snapshot 1)

| quantity | analyze.py | mine |
|---|---|---|
| E2 `e2_main` (70 arm×system×model rows): n, loss, acc, coverage, DER, macro-F1 | — | n identical; every other metric within 0.0005 (3-dp rounding) |
| H1[withheld] DC−S3 loss | −1.72673, p = 1.0e-4 | −1.72673, p = 1.0e-4 |
| H1[tracker] | −1.22593 | −1.22593 |
| H2 DC−S3 staleness error | −0.24319 (n = 514) | −0.24319 (n = 514) |
| H3 DC−DC_checklist cost @60 | −0.0375, p = 1.0 (n = 160) | −0.0375, p = 1.0 (n = 160) |
| H4 DC+P3 − S3+P1 ASR | −0.13672, p = 1.0e-4 (n = 256) | −0.13672, p = 1.0e-4 (n = 256) |
| Holm (H1w, H2, H3, H4) | 4.0e-4, 4.0e-4, 1.0, 4.0e-4 | same |

**The analysis code is arithmetically correct.** Differences between `results/v2/test/tables/hypotheses.csv` and my
numbers come only from the files growing while the jobs run:
* The live run (06:09:47) has H1w −1.7365, H2 −0.2642 (n = 545) and H3 n = 166.
* The earlier 05:57 version of `hypotheses.csv` had no H3 row and H4 = −0.031, p = 0.49 (n = 128, Qwen only).

**Re-run `analyze.py` once every block is complete.** The `hypotheses.csv` currently on disk is not final.

### 1.2 Latest numbers (snapshot 2, my script)

| hypothesis | estimate | sign-flip p (10k) | Holm p | n |
|---|---|---|---|---|
| H1 withheld DC−S3 loss (per case, averaged over models) | **−1.705** | 1e-4 | 4e-4 | 453 cases / 96 CVEs |
| H1 tracker (secondary) | −1.207 | 1e-4 | — | 453 / 96 |
| H2 DC−S3 staleness error (D2) | **−0.278** | 1e-4 | 4e-4 | 605 episode×model / 55 CVEs |
| H3 DC−DC_checklist tool cost @ budget 60 | **−0.030** | 1.0 | 1.0 | 200 (Qwen only; Mistral E3 missing) |
| H4 DC+P3 − S3+P1 ASR, untrusted attackers | **−0.137** | 1e-4 | 4e-4 | 256 / 42 CVEs (Qwen, Llama) |

**Effect of the partial Gemma block on H1.** Without Gemma, H1w is −1.774 and H1t is −1.270. Gemma alone has
H1w = −0.18 on its approximately 143 completed cases. The per-model values are:

| model | H1w DC−S3 |
|---|---|
| qwen3_14b | −2.45 |
| llama31_8b | −2.38 |
| granite41_8b | −1.53 |
| qwen3_4b | −1.49 |
| mistral_small_24b | −1.03 |
| gemma4_31b | −0.18 |

The model-averaged H1 will therefore shrink once Gemma finishes. While Gemma is partial, different cases also average
over different model sets (5 or 6), which is a small inconsistency.

**E2 pooled, all models (snapshot 1).**

| arm | system | loss | acc | coverage | DER | sel. macro-F1 |
|---|---|---|---|---|---|---|
| tracker | DC | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| tracker | S1′ | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| tracker | S1 | 0.002 | 0.998 | 1.000 | 0.000 | 0.998 |
| tracker | S3 | 1.197 | 0.768 | 0.976 | 0.380 | 0.773 |
| tracker | S4 | 1.111 | 0.765 | 0.986 | 0.350 | 0.764 |
| withheld | DC | 0.068 | 0.668 | 1.000 | 0.000 | 0.562 |
| withheld | S1′ / S0_trivy / S0_osv | 0.067 | 0.673 | 1.000 | 0.000 | 0.562 |
| withheld | S3 | 1.747 | 0.522 | 0.930 | 0.527 | 0.485 |
| withheld | S4 | 1.733 | 0.512 | 0.906 | 0.528 | 0.491 |
| withheld | S2 | 2.400 | 0.528 | 0.960 | 0.771 | 0.477 |

Withheld DC's 0.068 differs from 0.067 only because of the different case mix in the partial Gemma block.

**Other recomputed numbers:**
* **E9 pass^k** matches `e9_passk.csv` exactly.
  * DC = 1.0 / 1.0 / 1.0 for every model.
  * S3 pass^1 / pass^5:

    | model | pass^1 | pass^5 |
    |---|---|---|
    | Qwen3-14B | 0.904 | 0.880 |
    | Granite | 0.852 | 0.600 |
    | Qwen3-4B | 0.736 | 0.713 |
    | Llama | 0.445 | 0.080 |
* **KM and E5 UDAR tables** match `km_grid.csv` and `e5_udar_by_group.csv`.

---

## 2. Findings, ranked by severity

### F1 (Critical for interpretation): in E2 the LLM changes no DC decision; DC is identical to S1′, and in the withheld arm also to the Trivy and OSV scanners
* **Identity with S1′.** On every E2 record (2,412 tracker + 2,411 withheld at snapshot 1; also at snapshot 2 and on
  the live files through the test), DC's status equals the LLM-free controller S1′'s status for the same case and arm.
  This holds for all six models: **0 disagreements**.
* **Identity with the scanners.** In the withheld arm, S1′ also equals S0_trivy and S0_osv on all 453 cases. DC's
  withheld-arm decision is therefore exactly "trust the dpkg-reading scanners".
* **Confusion matrix of withheld DC:**
  * affected → affected: 726 of 726;
  * fixed → not_affected: 794 of 794 (DC never outputs `fixed`);
  * not_affected → not_affected: 885;
  * not_affected → affected: 6 (the single V5 config-precondition case).
* **Ablations.** DC_k1, DC_nofresh and DC_noverify produce DC's decisions on all 906 ABL episodes (F5).
* **Pre-registration.** Prereg §3c pre-states that withheld-arm decisions come from trusted scanners and pkgdb, so this
  is not a protocol violation.
* **Consequences for the paper:**
  * H1 is numerically the comparison "S0_trivy / S1′ vs S3". It must not be presented as evidence that LLM extraction,
    verification or EC² contributes to decision quality.
  * The DC = S1′ = Trivy identity should be stated next to H1.
  * The paper should report S1′−S3 (identical to DC−S3) and S0_trivy−S3 as the honest framing.
  * H0 (DC ≈ S1, +0.0022, 90% CI [0, 0.0065]) is equivalence of S1′ with S1, not a property of the LLM.
* **LLM usage.** In E2, DC's LLM calls (1.06 per episode in the tracker arm, 3.6 in the withheld arm) produce
  explanations and untrusted hints only.

### F2 (High): DC is dangerously wrong on D2 "upgrade without restart" (DER 0.97). The pooled H2 and E4 numbers hide it
* **Scope.** D2 kind `upgrade_no_restart` has 24 episodes × 5 models.
* **Failure.** The gold is `affected`, because the running process still has the old code (`fix_applied = False` in
  `world_at_decision`). DC decides **`fixed` in 116 of 120**, from `pkg_query` alone (`fix_applied: T`, group `pkgdb`).
  It never consults the process, so it reports a dangerous error with no remaining uncertainty.
* **Other systems:**
  * S1′ and S1 have the same failure.
  * S3 has 103 of 120 dangerous.
  * DC_nofresh is correct in 116 of 120, by reusing the stale history.
* **Per-kind DER.** DC's DER by drift kind is upgrade_no_restart 0.967 and 0 for every other kind. Across all E4
  affected episodes DC's DER is 0.468, vs S3 0.727.
* **Why H2 misses it.** These episodes have `world_pre_drift == world_at_decision`, so they cannot produce a
  "staleness error" (deviation D3 notes this). H2's −0.278 is therefore silent on DC's largest E4 failure mode.
* **Required reporting.**
  * Report E4 DER per kind next to H2.
  * Qualify any "DC never makes a dangerous error" claim: it holds for E2 (DER 0) but not for E4.
  * This is a modelling gap: package-DB evidence is treated as trusted evidence for the *running* fix state.

### F3 (High): H4 measures ordinary error, not attack resistance. DC ignores the attacked channels in E5
* **Setup.** E5 and KM run in the tracker arm only. DC's decisions there come from the trusted tracker and pkgdb.
* **Behavioural identity.** DC+P3's decisions equal S1′+P3's on all 768 episodes.
* **No attack effect on S3.** S3+P1 has untrusted-attacker "ASR" 0.137 against a benign-condition rate of 0.148.
  The D7 sensitivity gives ASR − benign = −0.012, so the injections do not increase S3's errors at all.
* **Per-model split.** By model, S3+P1 has untrusted ASR of 0.242 for Llama-8B and 0.031 for Qwen3-14B. The H4
  estimate (−0.137, p = 1e-4) is mostly Llama's ordinary misclassification rate.
* **Required reporting.**
  * H4 is statistically valid as pre-registered, but it must not be described as "DC resists prompt injection better".
  * The D7 row (ASR − benign = −0.012 for S3+P1, 0 for DC+P3) belongs next to H4 in the main text.

### F4 (High): the (k, m) grid and the T4 "UDAR = 0" claim rest on almost no discriminating episodes
* **How many episodes can discriminate.** Only episodes with all three properties can produce an unauthorized patch
  from forged *world* evidence:
  * the change atoms are truly approved and inside the window;
  * the true status is not `affected`;
  * the change group is not compromised.

  There are 4 such episodes per m-level out of 58 world-group episodes:
  * one G3 episode (`CVE-2026-45447-bookworm-V3`);
  * three G4 episodes, which aim at abstention, not execution.
* **Outcome on the single G3 episode under each attack:**
  * m1 (pkgdb): no attempt under any policy, including P2 with k = 1. "UDAR = 0" here does not exercise the gate.
  * m2 (pkgdb, fs): executed under P2 and P3 (allowed by T4, since m = 2 ≥ k = 2); blocked under P3k3.
  * m3 (pkgdb, fs, proc): executed under P2 and P3; blocked under P3k3, even though m = 3 ≥ k = 3, so T4 would allow it.
* **What the 0.017 UDAR cells are.** The "pkgdb,fs: 0.017" cells are exactly this one episode out of 58.
* **What the policies do and do not change:**
  * P2 and P3 give identical UDAR in every KM cell.
  * Decisions never differ across policies; only 8 action outcomes differ, all of them P3k3 blocking.
* **Change-group cells.** UDAR = 0.333 for P2/P3 means 2 of 6 episodes; it is 1.0 when rollback is truly available,
  per D6. P3k3 gives 0, by blocking everything.
* **P3k3 liveness.** Only 2 benign episodes are warranted. The FBR / liveness cost of P3k3 is measured on n = 2.
* **E5 for DC+P3:**
  * UDAR is exactly 0 under none, u_static, u_adaptive and m1-pkgdb.
  * UDAR is 0.017 under m2 pkgdb+fs, which is the same episode and allowed by T4.
  * UDAR is 0.333 under change compromise (2 of 6 per model; T4 tightness as pre-registered).
* **Verdict.** There is no counterexample to T4, but the grid cannot show that k = 2 protects better than k = 1.
  Report the per-cell n and the count of discriminating episodes.

### F5 (High): ablations and DC variants are behaviourally identical to DC, so they cannot support component claims
* **ABL (Qwen3-14B, both arms):** DC_k1, DC_nofresh and DC_noverify have 0 decision differences from DC on 906 episodes.
* **E5:** DC+P2, DC_q2+P3 and DC_noverify+P3 are identical to DC+P3 in decision, number of executions and tool cost on
  all 768 episodes.
* **The DC_q2 quorum is never enforced.** `src/deepcti/agents/systems.py:343-351` keeps acquiring evidence while
  `_quorum` fails. When no candidate remains it breaks and returns the k = 1 decision instead of abstaining. "Decision
  quorum k = 2" is therefore never enforced; it only affects acquisition, and even that is unchanged in E5.
* **The k_decide effect cannot be observed.** Scanners share the `pkgdb` group, so a quorum of 2 is unreachable for
  most atoms in any case.
* **E4:** DC_k1 equals DC; only DC_nofresh differs.
* **Required reporting.**
  * Report ablations as "no measurable effect on D1/D3".
  * Do not claim that verification, k, or a decision quorum improves robustness.
  * Document the DC_q2 fallback as a deviation, or fix it for future runs.

### F6 (Medium): H3 is uninformative because E3 ran in the tracker arm, where two calls decide every case
* **Setup.** E3 ran in the tracker arm (`arm = tracker` for all records).
* **All DC variants are perfect from budget 10 upward.** DC, DC_checklist, DC_entropy, DC_llmchoose and DC_random have
  loss 0 at every budget ≥ 10. DC_checklist is 0.006 at budget 5, from 2 cases that differ at that budget.
* **Costs are nearly flat.** Costs are about 2.7–3.4 units; DC_random is the exception at 3.6–11.9.
* **H3 result.** DC−DC_checklist cost at budget 60 is −0.030, p = 1.0. Only 2 of 200 pairs differ (−3 each, both
  `CVE-2023-42116`), so the sign-flip p is necessarily 1.0. The loss difference is 0, with CI [0, 0].
* **Required reporting.** H3 fails as pre-registered, with no evidence either way about EC². That is because the
  acquisition problem is trivial when the trusted tracker is available. Report it as such, and do not rescue it with
  DC−S3 (+0.29 cost, p = 0.27).

### F7 (Medium): E6/H5 is vacuous: DC never abstains in the withheld arm, so nothing is released
* **Live `e6_ltt.csv`.** It shows `base_coverage = 1.0`, `mean_coverage = 1.0`, realised risk 0 and
  `frac_risk_le_alpha = 1.0` for every model and α.
* **Why.** DC's withheld-arm decisions are never `under_investigation` (F1), so there are no hint-promoted decisions.
  The LTT guarantee holds trivially and the coverage gain is exactly 0.
* **Required reporting.** H5 "passes" but should be reported as not exercised.
* **Minor issue in the D1 calib-missing guard.** The D1 refusal guard checks for calib records pooled over models, not
  per model. Mistral and Gemma have no calib E2 runs (`runs/calib/E2` has only granite, llama, qwen3_14b and
  qwen3_4b), yet still get E6 rows computed from test records only.

### F8 (Medium): E9 pass^k for DC is trivially 1
* **DC is deterministic in E9.** E9 is tracker-arm, and DC equals S1′ there. All 4 models × 150 cases give 1
  distinct decision across the 5 seeds, all correct. Temperature 0.7 affects only explanations.
* **Required reporting.** Do not present DC pass^5 = 1.0 as robustness of an LLM agent. It is the reliability of a
  deterministic controller.

**Infrastructure errors in Llama S3.** 83 of 150 Llama S3 episodes at **seed 2** (and 3 at seed 3) ended in an LLM
`BadRequestError` (`usage.errors > 0`, `parse_ok = False`, `status = None`; not truncations). They are scored as
invalid. Llama S3 pass^5 = 0.08 and pass^1 = 0.445 are depressed by this. Report it, or re-run that seed and record
the error text.

### F9 (Medium): where DC loses (withheld arm), and the effect of the loss matrix
* **By variant (withheld, all models):**

  | variant | DC loss | S3 loss | note |
  |---|---|---|---|
  | V1 | 0 | 0.026 | |
  | V2 | 0 | 5.28 | |
  | V3 | 0.2 | 0.363 | DC acc 0 |
  | V4 | 0.2 | 0.565 | DC acc 0 |
  | V5 | 1.0 | 0.70 | 1 case |
  | V6 | 0 | 0.040 | |
* **Where S3 beats DC.** S3 has lower paired loss than DC in 100 of 2,408 episodes (V3 81, V4 17, V5 2). At
  model × variant level, S3 beats DC on V3 for Gemma (0.172 vs 0.2) and Granite (0.196 vs 0.2), and on V5 for Granite
  and Mistral.
* **Temporal hold-out:** DC 0.052 vs S3 2.095 on hold-out cases; 0.082 vs 1.462 otherwise. There is no hold-out
  degradation for DC.
* **Accuracy view.** DC's withheld accuracy is only 0.668, with every V3/V4 (`fixed`) case wrong. Its tiny loss comes
  from the 0.2 cost of fixed↔not_affected confusion.
* **Loss-matrix sensitivity of H1w.** H1w is −0.255 at miss cost 1, −0.582 at miss cost 3 and −1.727 at miss cost 10.
  The paired accuracy gain is +0.147.
* **What drives the gap.** H1's magnitude is driven by S3's misses on V2: 382 of 726 affected episodes are missed,
  DER 0.527. The scanners never miss on this test set (DER 0 for Trivy and OSV; 0.014 for Grype).
* **Withheld coverage.** DC's coverage of 1.0 is entirely scanner trust (`config/source_profiles.yaml`: Trivy, Grype
  and OSV `trust: T`).
* **Required reporting.** The justification for the 794 fixed→not_affected outputs is `vulnerable_code_not_present`,
  which is wrong. Report justification accuracy for DC in the withheld arm.

### F10 (Low): integrity — clean apart from expected LLM failures

**Clean on all 7 experiments and all files:**
* 0 JSON failures.
* 0 within-experiment duplicate keys. Keys repeat across experiments, e.g. KM vs E5 and E3/S1′ vs E2/S1′; this is
  harmless because `load_runs` is per experiment.
* 0 `error` records.
* 0 over-budget episodes.
* 0 `actions` vs `executed_disruptive` mismatches.
* 0 sealed-label vs `label_from_world(world_at_start)` mismatches for undrifted episodes.
* 0 `history` outside E4, and every E4 record has history.
* 0 case_ids in tool arguments or outputs.

**Sealed-atom differences.** `vuln_config_enabled` differs from the sealed atoms in 2,740 E2 records per model file.
In all of them `req_config = False`, so the label is unaffected.

**Variant-token false positives.** A scan for variant tokens ("V1"–"V6", "variant") only hit the word "variants"
inside the real CVE-2023-51764 advisory text.

**LLM failures (invalid outputs, scored as UI):**
* E2: Granite 1, Llama 2, Mistral 1.
* E5: Llama 1.
* E9: Llama 86 (F8).

**Truncated episodes, scored normally:** E2 Llama 48, Qwen3-4B 18, Mistral 12, Qwen3-14B 12, Granite 8; ABL 39.

**ReAct with no tool call:** 17, all in E9 Llama.

**Unauthorized remediation by ReAct baselines in benign E2.** These happen under P1, with no attacker:

| arm | S3 | S4 | S5 |
|---|---|---|---|
| tracker | 95 episodes | 45 | 91 |
| withheld | 73 | 61 | 67 |

DC has 0. This is worth reporting as a safety result, separate from E5.

### F11 (Low): reporting and provenance
* `results/v2/test/` is overwritten by every `analyze.py` call, with no stamp of which records it read. The current
  `hypotheses.csv` (06:09:47) mixes E2 read at about 06:07 with E4 read at about 06:09. Stamp record counts per
  file into `ANALYSIS.md`, as recommended in R1 B1.
* The `udar_DCP3_world_groups_m_lt_k` field in `hypotheses.csv` (0.0) filters `groups ∈ {"-", "pkgdb"}`. It therefore
  pools benign and untrusted episodes with m1-pkgdb, which is correct for T4, but the label should say so.

---

## 3. Answers to the specific questions
* **(a) DC vs S1′ in E2.** Identical on 100% of records, in both arms and for all models (F1). The LLM contributes no
  decision.
* **(b) Where DC loses.**
  * Tracker arm: never.
  * Withheld arm: V3/V4 `fixed` → not_affected (0.2 each) and V5 (1.0). No temporal hold-out degradation.
  * E4: upgrade_no_restart, where it is dangerous (F2).
* **(c) Withheld coverage.** It comes from trusted scanners and is equal to Trivy. S3's coverage-adjusted loss is
  never better pooled. It is better per stratum only on V3 (Gemma, Granite) and V5 (F9).
* **(d) E5 UDAR.**
  * Exactly 0 for DC+P3 under untrusted-only and single world-group (m1 pkgdb) compromise.
  * 0.017 under m2 (1 episode, permitted by T4).
  * Change-group compromise gives 0.333 (2 of 6 per model; 1.0 when rollback is truly available).
* **(e) KM.** Consistent with T4 but not discriminating. P2 ≡ P3 everywhere, and one G3 episode carries every
  world-group cell (F4).
* **(f) E9.** DC is deterministic, so pass^k = 1 trivially (F8).
* **(g) E6.** The guarantee holds vacuously, with a coverage gain of 0 (F7).

## 4. Recommended actions before writing
1. Re-run `analyze.py` once Gemma (E2, E5, E4), Mistral (E3, ABL, E9) and Gemma E9 finish. Quote numbers only from
   that run.
2. In the paper, state the DC = S1′ (= Trivy in the withheld arm) identity next to H1. Report H4 with D7. Report E4
   DER by kind. Report H3, H5, the ablations and the DC pass^k as "not exercised / no effect", not as support.
3. Record the DC_q2 fallback and the E9 Llama seed-2 BadRequest errors in `prereg/DEVIATIONS.md`.
