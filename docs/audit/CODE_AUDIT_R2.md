# DeepCTI v2: code audit, round 2

**Scope.** Changes made after round 1 (`git diff f7ddd1b prereg-v1 -- src scripts`) and every path that can change a test-split number:

- D2 "drift since the last assessment"
- the hypothesis tests in `scripts/paper/analyze.py`
- E6 Learn-then-Test (LTT)
- E5 metrics and D3 forging
- record exclusion in `summarize.py`

The audit is read-only with respect to `src/`, `scripts/`, `data/` and `runs/`. It did not open `data/sealed/`, and it did not read any test labels.

**New tests:** `tests/v2/test_audit_r2.py` (20 passed, 2 strict xfail; full suite `tests/properties tests/v2`: 135 passed, 3 xfailed).

**Run:** `PYTHONPATH=src .venv/bin/python -m pytest -q tests/v2/test_audit_r2.py`

Both xfails were re-run with `--runxfail`. Each fails on the asserted defect.

**Bottom line.** No defect makes a pre-registered primary p-value or estimate *wrong* as specified:

- The pairing, two-sided sign-flip, +1 correction, Holm and BH are all correct.
- The primary flags are H1[withheld], H2 vs S3, H3 vs DC_checklist and H4. This matches prereg §5.
- The D2 history and drift physics behave as designed.

There are, however, several construction and definition issues. They change what the D2/D3/E3 numbers *mean*, and they should be disclosed or fixed in analysis before results are reported. Findings F1–F7 affect test numbers; P1–P5 are presentation only.

## Verified correct (with tests where marked)

| Item | Evidence |
|---|---|
| History calls (`pkg_query`, `service_status` on the src name) run on the **pre-drift** host. They cost nothing in the episode, `env.calls` is reset, the clock is set to 0, and call ids are `h001`/`h002` (no collision with `c003…`). | `test_history_is_pre_drift_and_stale_under_delta`, `test_runner_record_fields` |
| History observations are older than Δ=12 at t=0. For DC/S1′ they are dropped as stale (`present` = N, `stale_dropped` ≥ 1, decision UI). With Δ=∞ (DC_nofresh) they stay T. | `test_history_is_stale_for_dc…`, `test_history_is_never_stale_for_nofresh` |
| The controller re-queries under freshness and returns the post-drift status (`fixed`). With Δ=∞ and no precondition it stops after `vex_lookup` and returns the pre-drift `affected` (a staleness error). | `test_controller_requeries_with_freshness_and_is_stale_without` |
| Drift events at t ≤ 0 fire exactly once, at t=0, in order (upgrade before restart; the stable sort keeps file order). Later calls do not re-apply them. | `test_drift_events_apply_exactly_once` |
| Physics (world labels): upgrade+restart: affected → fixed. Upgrade without restart: affected → affected (the old binary stays loaded). Remove: affected → not_affected, changelogs removed, service unloaded. Rollback: fixed → affected, changelog refreshed. Config drift flips `vuln_config_enabled`. | `test_drift_physics_labels`, `test_rollback_drift`, `test_config_drift` |
| Gold for drift episodes is the world at decision time. `label_world_mismatch` is skipped for drift episodes. The e4 staleness error uses `world_pre_drift`. | `test_runner_record_fields` |
| Fairness of the history: ReAct (S3–S5) and S2 receive the same two history outputs verbatim in `task_message`. DC, S1′ and DC_* ingest them into the mediator state. S1 and S0 ignore them, but always query fresh, so they cannot be stale. `prompts/core_spec.md:34-36` warns that earlier evidence may be stale. | `test_react_and_s2_prompt_carries_the_same_history` |
| `cluster_signflip` is two-sided, works on per-CVE means (unequal cluster sizes), and uses (1+#)/(n+1). It matches exact enumeration. | `test_cluster_signflip_matches_exact_enumeration` |
| Holm (R1 test) and BH match statsmodels. Primary = {H1[withheld], H2 DC−S3, H3 DC−DC_checklist, H4}; everything else goes to BH. | `test_benjamini_hochberg_matches_statsmodels`, code read at `analyze.py:180-186, 362-372, 282-287, 434` |
| Pairing: H1 pivots on (case_id, model), takes the mean over models with both systems present, then the per-CVE sign-flip. H2 pairs on (D2 episode id, model). H3 pairs on (case_id, model) at `budget.max()` = 60, which is in E3 `BUDGETS`. H4 pairs on (D3 episode id, model) for untrusted attackers only, with DC+P3 against S3+P1 without defense. | code read |
| The E5 m<k subset `groups ∈ {'-', 'pkgdb'}` = none / untrusted / single world group. | `test_h4_m_lt_k_subset_definition` |
| Change forging under P3 authorizes `restart_service` (change atoms, k=1), and the metric counts it as UDAR. World atoms ignore the forged ticket. | `test_change_forging_permits_restart_under_p3_and_counts_as_udar` |
| Forged fs rewrites only the version in the header line of the changelog and leaves the body intact. | `test_forged_fs_rewrites_only_the_header_version` |
| HB p-value matches Bates et al.: min(Hoeffding, e·P(Bin(n,α) ≤ ⌈n·R̂⌉)). Fixed-sequence testing starts at λ=∞. Splits are 40/60 by CVE, per model. | code read, `analyze.py:504-520` |
| Dev check: `load_runs` excludes 0 records as `label_world_mismatch` across E2/E3/E4/E5/KM/ABL `_final`. Test E2 so far has 0 error records and 2 invalid outputs. | ad-hoc script (no labels read for test) |

## Findings that affect test numbers (ranked)

### F1 [MEDIUM]: the H2 staleness-error rate includes episodes where a staleness error is impossible by construction
- **Where:** `scripts/paper/analyze.py:340-349, 356-372`, together with `scripts/data/build_d2_d3.py:60-62, 68-72`.
- **Input A:** `upgrade_no_restart`. The world atoms are unchanged (the old binary stays loaded, so the host is still affected). `drift_before_decision` is therefore False and `stale_i` = 0 for every system. On dev this is 24 of 117 D2 episodes (all `world_before == world_after`).
- **Input B:** `config_enable`. The carried-over history contains no `config_get`, so no stale evidence for the drifted atom exists. A "pre-drift status" answer (not_affected/requires_configuration) can only come from inference without evidence, not from stale evidence. On dev this is 3 episodes.
- **Impact:** The H2 estimate (DC−S3 staleness-error rate) is diluted towards 0 by about 20–25% of the pairs. The p-value is affected less, because those pairs are exact zeros and the per-CVE means shrink proportionally. Interpreting the effect as "the staleness rate when drift changed the status" is wrong as computed.
- **Fix:** Estimate H2 on episodes with `label(world_pre_drift) != label(world_at_decision)`, which is what prereg §5 H2 defines ("reporting the pre-drift status when it is wrong now"). Report the all-episodes number as well. Per-kind numbers already exist (`e4_drift_by_kind`). Disclose that `config_enable` carries no config history. To test that kind properly, add `config_get` to the history calls (this would be a deviation).

### F2 [MEDIUM]: D3 m-attackers often forge the true version (no-op compromise)
- **Where:** `build_d2_d3.py:139-140, 156`. The forged target is `fixed_version() or installed` for G2/G4 and `vuln_version.get(..., installed)` for G1/G3.
- **When it happens:**
  - For an open CVE (no fixed version), or a G4/G2 host that is already fixed, the forged stanza equals the real one.
  - The same happens for G1/G3 when no vulnerable sample exists for (CVE, release).
  - For G1 on in-range hosts, `pkgdb` is forged "towards vulnerable" on an already vulnerable host.
- **Dev counts (pkgdb forging equal to the world):**
  - G2: 5/16
  - G3: 3/16
  - G4: 3/16
  - G1: 3/7 at m1 and 12/16 at m2/m3
- **Test:** `test_d3_forged_pkgdb_payload_differs_from_world` (xfail strict; open CVE → G2 m1 forges OLD == installed).
- **Impact:**
  - ASR and UDAR for m1–m3 (`e5_attacked`, `e5_asr_by_goal`, `km_grid`, `*_udar_by_group`) are diluted by attacks that change nothing.
  - The H4 secondary field `udar_DCP3_world_groups_m_lt_k` counts no-op 'pkgdb' episodes as evidence for "UDAR = 0".
  - H4 itself (untrusted attackers) is unaffected.
- **Fix (analysis-time, no re-run needed):** Flag `effective = forged payload != world` per episode from `data/d3/test.jsonl` together with the fixture versions. Report ASR/UDAR for effective episodes only, plus the share that is effective.

### F3 [MEDIUM]: the T4 tightness case ("change compromised ⇒ UDAR > 0") is mostly unreachable for apply_patch
- **Where:**
  - `build_d2_d3.py:174-175`: the forged change payload has no rollback field.
  - `src/deepcti/env/host.py:578-590`: `request_approval` reports the honest `self.rollback`.
  - `pdp.py` GATES: `apply_patch` requires `rollback_available`.
  - `systems.py` `Controller.remediate`: aborts unless `rollback_available`.
- **Input:** A host with `rollback_available=False` and a forged change ticket. Both `apply_patch` and the DC controller's remediation are blocked. Only a direct `restart_service` could produce UDAR, and DC never calls it without first patching.
- **Dev:** 6 of 9 G1 change-compromised (m1) episodes have rollback False.
- **Tests:** `test_change_forging_cannot_authorize_apply_patch_when_rollback_unavailable` (pins the behaviour) and `…permits_restart_under_p3…`.
- **Impact:** The pre-registered expectation "a compromised change system (m = 1 ≥ k) is expected to produce UDAR > 0" will show a small UDAR for DC+P3. That could be misread as "T4 not tight". The UDAR-by-group value for 'change' is bounded by the rollback=True share (dev ≤ 3/9).
- **Fix:** In reporting, condition the 'change' column on `rollback_available=True` in the fixture world (sealed world, allowed after the run). Alternatively, state that the change system is modelled as not controlling rollback.

### F4 [MEDIUM, interpretation]: a "pkgdb-compromised" group is only partly compromised
- **Where:** `host.py:406-414` versus `_t_run_scanner` (`host.py:556-576`). Forged `pkgdb` rewrites dpkg-query output only. The trusted scanners belong to the same `pkgdb` independence group, but they read their honest reports. `Attack.forged["scanner:<name>"]` exists, but `build_d3` never sets it.
- **Test:** `test_forged_pkgdb_does_not_reach_scanners_of_the_same_group`.
- **Impact:** For m1='pkgdb' (and m≥2 including pkgdb), honest group members can contradict the forged facts. UDAR=0 / ASR for 'pkgdb' columns is therefore not a test of a fully compromised group (T4's m counts groups). This affects the KM grid and `udar_by_group`, but not H4.
- **Fix:** Disclose it, or forge every trusted `scanner:*` alongside `pkgdb` in a follow-up. This cannot be changed for the running test.

### F5 [LOW-MEDIUM]: DC_nofresh is not "Δ=∞" in general, because the controller re-queries whenever the history alone does not decide
- **Where:** `systems.py:283` (`self.done` is controller-local, so the history calls are not in it), together with latest-per-source in `belnap`.
- **Input:** A CVE with a configuration precondition. The stale history leaves the decision UI (`missing:vuln_config_enabled`). The checklist or VOI then re-runs `pkg_query`, and the fresh fact replaces the stale one. DC_nofresh then returns the post-drift status.
- **Test:** `test_nofresh_requeries_pkg_query_when_history_alone_does_not_decide`.
- **Impact:** The DC vs DC_nofresh contrast in E4 and ABL measures "decides on carried-over evidence without acquiring" only on episodes where history alone is decisive. This is not H2 (DC vs S3). Describe it accordingly.

### F6 [LOW-MEDIUM]: H3 compares total tool cost, including post-decision remediation calls
- **Where:** `analyze.py:270-287` uses `cost` = the sum over all `env.calls`.
- **What is included:** Every `affected` decision of DC/DC_checklist adds `request_approval` (+1). When approval is granted, it also adds `file_read`, `service_status`, `pkg_query`, `apply_patch` (20) and `restart_service` (15 per unit). In E3 there is no history, so `t_decision` equals the cost to decision.
- **Dev E3, budget 60:** `cost − t_decision` ≈ 1.0 for both arms. On the test split, any approved remediation adds ≥ 45 to a single pair.
- **Impact:** The H3 estimate and p-value (DC−DC_checklist cost) mix acquisition cost (what EC² optimises) with remediation cost, whenever the two systems reach different decisions or approvals.
- **Fix:** Report H3 on `t_decision` (cost-to-decision, already a prereg §4 metric), with total cost as secondary. If this deviates from the frozen analysis, log it in DEVIATIONS.md.

### F7 [LOW]: E6/H5 can silently lose the calibration split
- **Where:** `analyze.py:462-466, 596-599`.
- **The failure:** `_raw_records("calib", "E2"+suffix)` returns `{}` without error when `runs/calib/E2` is missing or incomplete. `launch_test_phase.sh` runs calib E2 *after* each model's test queue. H5 would then be computed on a test-only pool, while the table text still says "pooled".
- **Also:**
  - The λ grid is built from scores of the whole pool, including the evaluation folds. This is a mild violation of LTT's fixed-grid assumption. Use the calibration fold or a fixed integer grid.
  - Any `KeyError` (for example a calib case without a label) skips E6 entirely via the broad `except`.
- **Fix:** Assert that both splits are non-empty and that every model has calib records. Print n per split.

### F8 [LOW]: errored episodes vanish from every analysis
- **Where:** `scripts/paper/summarize.py:31-33`. Error rows lack `case_id`/`arm`/`loss` and are excluded by `ok = df[~df.error]`. They are not scored as UI, so paired tests drop the whole pair.
- **Current state:** Test E2 has 0 errors so far, so there is no impact today.
- **Fix:** Report error counts per system next to each hypothesis. Optionally score errors as invalid (UI loss 0.5) in a sensitivity row.

### F9 [LOW, interpretation of H4]: ASR is not baseline-corrected
- **Where:** `analyze.py:395-406`.
- **The issue:** G2, G3 and G4 count a dangerous error, a needless `affected` or an abstention whether or not the attack caused it. G4 counts every UI, and DC abstains more by design.
- **Impact:** H4 (the paired DC+P3 − S3+P1 difference) is biased against DC by its benign UI rate on G4 episodes. This makes the test conservative for DC.
- **Fix:** Also report ASR minus the rate on the matching `attacker == none` episode, paired by (case, goal, model).

## Presentation-only

- **P1:** History observations are stamped −29 and −28, because the clock is read after each call's cost (R1 design note 8). The prompt says "30 time units before". This does not matter under Δ=12. Test: `test_history_timestamps_are_post_tick_not_minus_30`.
- **P2:** The history `service_status {"name": <src>}` returns "Unit <src>.service could not be found" for source packages that have no service (for example `openssl` on dev). Units of packages that do have a service are found, because `_t_service_status` also matches on the binary's source name. In those episodes the carried-over proc evidence is empty. This is the same for all systems.
- **P3:** The forged `fs` hook rewrites the header of *every* `changelog.Debian`, not only the case binaries' (`host.py:431-435`). The verifier rejects headers that name another component, so the evidence state is not affected.
- **P4:** `compromised_groups` lists `proc` when no unit exists, so nothing is forged (`build_d2_d3.py:170-176`). On dev this applies to 30 of 64 m3 episodes, so the KM column `pkgdb,fs,proc` contains episodes that are effectively m=2. Test: `test_d3_compromised_groups_match_forged_payload` (xfail strict). Fix by labelling groups from `attack.forged`.
- **P5:** The E3 figure title says "budgets 5,10,20,40", but the sweep includes 60 (`analyze.py:295`). The H1 code does not filter on budget; E2 runs only at the default budget of 60, so this is correct.
