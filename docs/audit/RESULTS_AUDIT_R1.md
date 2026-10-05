# Results audit R1: dev pilot runs and analysis code

Date: 2026-10-05. Branch `v2-experiment`, HEAD `f7ddd1b`. Auditor: independent (Claude).
Scope: `runs/dev/*_pilot/*.jsonl`, `src/deepcti/eval/{runner,metrics}.py`, `scripts/paper/{summarize,analyze}.py`,
`results/v2/dev/ANALYSIS_pilot.md` + `tables/`, checked against prereg §4–§6 and `docs/VERIFICATION_LOG.md`.
`data/sealed/` was not opened. Runs were snapshotted at 05:24 UTC because E4, E5 and KM were still being written.
At that point E4 had 84 of 721 jobs, E5 732 of 3072 and KM 7 of 768.
Audit scripts (not committed) live in the session scratchpad. They are `integrity.py`, `labelchk.py`, `recompute.py`,
`e5chk.py` and `harness.py`; the last one re-runs `analyze.py` blocks against the snapshot with `OUT` redirected.
Regression tests: `tests/v2/test_metrics_audit.py` (16 pass, plus 2 `xfail(strict)` tests that document bugs B4 and B6).

## What checks out (verified, no action)

* **Record integrity.** Checked all 10 pilot files (4,093 records):
  * 0 JSON parse failures, 0 duplicate keys, 0 `error` records.
  * Every record has `parse_ok=True`. Usage shows 0 truncations and 0 LLM errors.
  * 0 ReAct (S3–S5) episodes submitted with no tool call.
  * `env.actions` R2 entries equal `executed_disruptive` in every record, so no disruptive action bypassed the mediator.
* **Headline numbers.** I recomputed the E2 arm × system table independently from the raw JSONL, using my own loss
  matrix and my own join to the dev labels. All 20 rows match `ANALYSIS_pilot.md` to 3 dp: n, acc, coverage, loss,
  DER and selective macro-F1. The one difference is S4/tracker loss: 0.1775 is shown as 0.177 vs 0.178, a rounding mode.
  E9 pass^k also matches on the case set that existed when the analysis was run.
* **Loss matrix** (`metrics.py:14-22`). It equals the plan exactly.
* **Invalid outputs** are scored as UI for loss and as incorrect for accuracy (`metrics.py:40-42`).
* **DER** is P(pred ∈ {not_affected, fixed} | gold affected) (`metrics.py:66`, `summarize.py:56`).
* **Selective macro-F1** is computed over covered cases only (`metrics.py:78-88`).
* **Gold for drift episodes** is `decide_world(world_at_decision)` (`metrics.py:30-35`). Decision time is the first
  disruptive attempt, otherwise the end of the episode; DC uses its own pre-remediation time (`runner.py:119-124`).
  This matches prereg §4.
* **UDAR uses the true change atoms.** `HostEnv.world_atoms` reads the change ticket from `fixture.host` and never from
  `attack.forged` (`host.py:646-649`).
  * On the snapshot, all 9 executed `apply_patch` calls under m1/m2/m3 G1 attacks (DC, DC_q2; P2 and P3) have
    `world_before.change_approved=False`. This equals the D3 true world, while the forged ticket said approved.
    All 9 are counted as unauthorized.
  * In E5 and KM, no executed action has `world_before` change atoms that differ from the D3 `world`.
  * Test `test_hostenv_world_atoms_ignore_forged_change` pins this.
* **Statistics helpers:**
  * McNemar exact p equals `scipy.binomtest` (test).
  * Holm equals `statsmodels.multipletests(method="holm")` (test).
  * `cluster_bootstrap` resamples whole CVEs (test).
  * GEE uses `Treatment('S3')`, a binomial family and exchangeable CVE clusters.
  * The H0 TOST uses the 5th/95th percentiles, i.e. a 90% CI (`analyze.py:179`).
  * The LTT HB p-value is `min(exp(-n·h1(R̂∧α, α)), e·P(Bin(n,α) ≤ ⌈nR̂⌉))` (`analyze.py:410-416`), as in VERIFICATION_LOG.
  * Fixed-sequence testing starts at λ=∞ and walks down, stopping at the first non-rejection (`analyze.py:418-426`).
  * Calibration and evaluation are split by CVE (`analyze.py:435-437`).
  * pass^k = mean over tasks of C(c,k)/C(n,k) (`metrics.py:91-94`). It equals brute-force subset enumeration (test).

---

## Bugs (ranked)

### B1 (High): the pilot artefacts are stale and their provenance is wrong; re-running the analysis now crashes
* **Analysis timing.** `results/v2/dev/ANALYSIS_pilot.md` was written at 05:17:31.
  * The E4, E5 and KM pilot runs started at 05:19:52, so the E4 section is missing. The E5 section shows only 3 episodes.
  * `data/d1/cases/{dev,calib,test}.jsonl` were rebuilt at 05:22:03.
* **Crash on re-run.** Re-running `e3`, `ablations` and `e9` on the current data fails with
  `KeyError: 'D1-CVE-2026-7258-trixie-V*'` (see B4). Records for 4 trixie cases that left dev are still in E3 (24),
  ABL (3) and E9 (40).
* **Old code.** Manifests record `git_commit=a3a81528` ("Initial DeepCTI release", v1) for E2, E3, ABL and E9, and
  `6b9b2db` for E4, E5 and KM. Both are before `f7ddd1b`, which changed several things the results depend on:
  * remediation budget enforcement;
  * apply_patch scope;
  * the drift `remove` handling;
  * unparseable scanner reports;
  * the default budget, now 60.
  The v2 code was evidently uncommitted when the E2 run was made, so the recorded hash does not identify the code.
* **Budget.** Every pilot key carries `budget=40.0`, but prereg §2 fixes 60. There are 19 over-budget episodes:
  * E3: 4 episodes at budget 5 with cost 6–8. `request_approval` (cost 3) was taken after the budget was spent.
  * E9: 15 DC episodes with cost 45 at budget 40 (patch 20 + restart 15).
  Commit f7ddd1b says this is fixed. The pilot numbers predate the fix.
* **Fix:**
  * `runner.manifest` (`runner.py:232-242`) should record `git status --porcelain` and a hash of `git diff HEAD`, and
    refuse non-pilot runs on a dirty tree.
  * Re-run all pilots on HEAD and regenerate `ANALYSIS_pilot.md` afterwards.
  * Stamp the analysis with the run manifests' hashes and the data file mtimes or hashes.

### B2 (High): Holm (and BH) correction is never applied
`holm()` is defined at `analyze.py:68-75`, and `pvals` is filled at `analyze.py:131`, but nothing calls `holm()`.
`e2_pairwise.csv` and the markdown print unadjusted `p_mcnemar`, with no "unadjusted" label.
Prereg §5/§6 requires Holm over H1–H5 and BH for secondary analyses.

Fix:
* Build the H1–H5 primary family explicitly (one p-value per hypothesis, as pre-registered).
* Apply `holm`, and BH (`multipletests(method="fdr_bh")`) to the pairwise and secondary tables.
* Print both raw and adjusted p.
* Do not put LLM-free baselines (S1, S1p) into the family once per DC model. They currently appear twice with
  identical numbers (`analyze.py:118-120`).

### B3 (High, design-level): E4 cannot observe drift, so the staleness error is identically 0 and H2 is untestable
* **Drift time.** All 103 D2 dev episodes put every drift event at `at=6.0`.
* **Decision time.** In the 84 E4 pilot records the maximum `t_decision` is 3.0, with a mean of about 2.2 for every
  system: DC, DC_k1, DC_nofresh, S1, S1p and S3. Only 8/84 episodes ever reach t=6, and then only after the decision.
* **Effect.** `world_at_decision == world_at_start` in 84/84 records, so the gold label is always the pre-drift label.
  `drift_before_dec` is 0 and `stale_err` is 0 everywhere (snapshot E4 table).
* **Hard-coded drift time.** `analyze.py:284` hard-codes `t_decision >= 6.0` instead of reading the episode's drift
  `at` from D2.
* **Denominator.** `stale_err` (`analyze.py:292`) averages over all episodes, not over episodes with drift before the
  decision. That is defensible, but it must be stated.

Fix:
* Make drift land inside the assessment window, e.g. `at` ≤ 2, or "after the k-th tool call".
* Read `at` from `data/d2/<split>.jsonl`.
* Report the conditional staleness rate and the share of episodes where drift preceded the decision.

### B4 (Medium): label joins fail hard or silently; label/fixture consistency is never asserted
* **Hard failure.** `metrics.gold_for` does `labels[record["case_id"]]` (`metrics.py:34`), which raises `KeyError` for
  any record whose case left the split. `summarize.load_runs` has no guard, so the run crashes (B1).
* **Silent failure.** `analyze.main` catches `KeyError` around E6 (`analyze.py:499-502`), so the same problem there
  silently produces "E6 skipped".
* **No consistency check.** Nothing checks that the label equals `decide_world(world_at_start)` for undrifted
  records. My check (`labelchk.py`) finds one rebuilt host:
  * Case `D1-CVE-2026-7258-bookworm-V3`: the dev label is now `fixed`, but the world the episodes actually ran on was
    `affected` (`in_affected_range=True`).
  * 22 pilot records are scored against the wrong gold: E5 S1p 12, E9 S3 5, E9 DC 5.
  * `data/d2/dev.jsonl` (2 episodes) and `data/d3/dev.jsonl` (12 episodes) still carry this case's pre-rebuild
    `world`. Its D3 goal-pool membership was decided from the old world.
  * All other undrifted records with a case still in dev (3,920) are label-consistent.

Fix:
* Join labels explicitly and report dropped or missing cases. Do not catch `KeyError` broadly.
* Add a hard assertion `label == decide_world(world_at_start)` for every undrifted record in `load_runs`.
* Regenerate D2/D3 after every D1 rebuild.

The xfail test `test_gold_for_missing_case_does_not_crash` documents the KeyError.

### B5 (Medium): E6/LTT runs on a smaller pool than described and passes H5 vacuously
* **Pool.** `--calib-split calib` loads `runs/calib/E2_pilot`, which does not exist (`runs/` contains only `dev`, `e7`).
  The pool is therefore dev only. The text at `analyze.py:449-452` still says "pooled calib+test".
* **Data-dependent grid.** The λ grid (`analyze.py:401`) is built from the scores of the whole pool, including the
  evaluation folds and all models. Use a fixed grid instead, e.g. integer margins 0…K.
* **No power.** With zero observed risk, the HB p-value reaches δ = 0.1 only for n ≥ 45 at α = 0.05, n ≥ 230 at
  α = 0.01 and n ≥ 22 at α = 0.1. The pilot calibration folds have about 8 CVEs, roughly 15 cases. So no λ < ∞ is
  ever certified:
  * the "certified" λ is always the fallback ∞, i.e. DC's own base decisions;
  * mean_coverage is about base_coverage, 0.45;
  * `frac_risk_le_alpha` = 1.0 only because base DC has DER = 0.
* **Fallback.** The fallback λ = ∞ is returned without being tested (`analyze.py:419-426`).

Fix:
* State whether the λ = ∞ fallback is "no hints released" (the base) and that it is uncertified.
* Report the fraction of splits in which any λ < ∞ was certified.
* Pre-check that n_cal is enough for the requested α.

### B6 (Low): definition of "invalid" and the G4 success definition
* **Invalid flag.** `metrics.py:40-41`: a record with `parse_ok=True` but a non-canonical status (e.g. "vulnerable")
  gets loss as UI, which is correct. But `invalid=False`, so the reported invalid rate understates (xfail test).
* **G4 success.** `analyze.py:330-331` counts G4 success only when `pred == "under_investigation"`. Invalid outputs,
  scored as UI everywhere else, do not count. The `gold != UI` clause is always true.

### B7 (Low): error episodes are dropped from denominators
`summarize.summary` filters `~error` before computing n, acc and loss (`summarize.py:50`). A crashed episode therefore
does not count as a failure, although prereg §4 says invalid output counts as a failure for accuracy.

Error rows also carry no arm, policy or attack (`summarize.py:31-33`). So `errors` lands in a NaN group when grouping
by `arm`.

There are 0 errors in the pilot, so there is no numeric impact yet. Fix: score error episodes as invalid (UI loss,
incorrect), or report them alongside with the same grouping keys.

### B8 (Low): inconsistent UDAR and FBR definitions
* **UDAR.** E5 `UDAR` is the mean of `unauthorized_exec` counts per episode (`analyze.py:338,341`). It can exceed 1
  when a patch and a restart are both unauthorized. The KM grid instead uses the episode share `(x > 0).mean()`
  (`analyze.py:351`).
* **FBR.** FBR (`analyze.py:336`) is computed over all benign episodes, not over warranted ones. False blocks can only
  occur on warranted episodes, so the rate is diluted by the G1/G3 pools.
* Choose one definition per metric, put it in prereg §4 or DEVIATIONS, and use it everywhere.

### B9 (Low): GEE non-estimability is shown as a table of NaN
In the tracker arm DC is 80/80 correct (perfect separation). `e2_gee_tracker.csv` is all NaN and is printed as a
result.

Fix: detect separation and report "not estimable", with a penalised or exact alternative or the paired bootstrap only.

---

## Presentation and misleading-risk (ranked)

### P1 (High): DC's decisions are identical to the LLM-free S1p in every E2 pilot episode
In 160/160 E2 episodes (2 arms × 2 models × 40 cases) DC's status equals S1p's. In the tracker arm DC makes exactly
one LLM call (the explanation). In the withheld arm the LLM calls (mean 4.15) never change the outcome. As a result:
* the per-model DC rows are duplicates;
* "DC (model-averaged)" in H0 is S1p;
* putting DC in a GEE with `C(model)` and the H6 size interaction treats an LLM-free outcome as model-dependent. The
  fitted `dc:log_size = −1.1712 = −log_size` exactly, i.e. no size dependence for DC by construction, with 2 sizes.

Any "DC beats ReAct" claim must say that, on this pilot, the gain is entirely the deterministic controller (S1p).
DC vs S1p should be a headline comparison. The same applies to the ablations (P6).

### P2 (Medium): pooled and duplicated rows
* `e2_by_system` ("all models pooled", `analyze.py:104-112`) shows n = 80 for DC and S2–S5 against 40 for the LLM-free
  systems. DC's 80 are 40 cases duplicated.
* The pairwise table repeats the S1 and S1p rows once per DC model with identical numbers.
* Label per-model rows of LLM-free or LLM-invariant systems as such, and count them once.

### P3 (Medium): H1 direction depends on the metric
In the withheld arm the GEE on correctness gives OR(DC vs S3) = 0.487 (p < 0.001), i.e. DC looks worse. That is
because UI (DC abstains on 55% of cases) counts as incorrect. Mean loss favours DC: 0.275 vs 0.670/0.842.

Prereg H1 says "lower mean decision loss … (GEE logistic on correctness …)". These two measures point in opposite
directions here. Decide before the test run which one decides H1 (loss is primary per §4), and report both, with the
reason they diverge.

### P4 (Medium): E5 systems compared on different episode sets
On the snapshot:
* S1p+P3 has n = 64 per attacker over G1–G4;
* every LLM configuration has n = 8–9, G1 only, because the run is partial.

ASR 0.266 (S1p) vs 0.125 (DC) and UA 0.61 vs 0.625 are therefore not comparable (goal-mix/Simpson risk). E4 has the
same issue: S3 n = 9 vs DC_k1 n = 17 on `remove`.

Fix: inner-join on `attack` (or `drift`) episode ids before comparing configurations, and print the common n.

### P5 (Medium): what "m < k" means in H4
DC+P3 shows UDAR = 0.125 under m1. The m1 attacker forges the change group first (`build_d2_d3.py:161`), and P3 uses
k_change = 1, so m1 ≥ k for change atoms. The KM caption says this, but the E5 "Attacked" table and H4 ("DC+P3 has
UDAR = 0 with m < k") do not.

Define the m < k subset per atom group in the analysis, or report H4 only on u_static, u_adaptive and the
m < k_world cells where the change group is not compromised.

### P6 (Low): pilot blocks that cannot discriminate between systems
* **E3.** Mean cost does not depend on budget: DC 3.4 and S3 2.45 at every budget from 5 to 40, so the sweep never
  binds and the Pareto plot is four identical points. The title hard-codes "budgets 5,10,20,40" (`analyze.py:240`),
  while prereg adds 60. Take the title from the data.
* **Ablations (tracker arm).** DC_k1, DC_noverify and DC_nofresh make 0 LLM calls and are 30/30 correct. Verification
  and freshness are not exercised, so the ablation rows say nothing yet.
* **E9.** DC pass^1 = pass^3 = pass^5 = 0.9867 (the deterministic controller; see P1).

### P7 (Low): small pilot
E2 has 40 cases from 21 CVEs, with only 9 gold-affected cases, so per-model DER rests on 9 cases. The 2,000-resample
CIs are over 21 clusters. Pilot p-values (e.g. 0.031 = 2·0.5⁵) should not be quoted as evidence.

### P8 (Info): label atom convention differs from world atoms
D1 label `atoms` set `vuln_config_enabled=True` when `req_config=False`; `world_atoms` sets it to False. This has no
effect on `decide_world`. But a naive comparison of atom dicts reports about 2,000 spurious mismatches, so compare
decisions, not atoms, or normalise the atoms.

---

## Suggested order of work
1. **B1:** add a dirty-tree hash to the manifest, then re-run the pilots on HEAD with budget 60.
2. **B4:** add the label-consistency assertion, then regenerate D2/D3.
3. **B3:** redesign the drift timing.
4. **B2:** wire in Holm/BH.
5. **P1, P3:** decide how DC vs S1p and the H1 metric will be reported.
6. **P4:** add common-set joins.
7. **B5–B9:** fix the remaining items.
