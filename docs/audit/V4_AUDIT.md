# prereg-v4 code audit (H16, H17, H18)

Auditor: independent code review, 2026-10-05. Scope: `git show prereg-v4` and `git diff prereg-v3 prereg-v4 -- src scripts`.
No file under src/, scripts/, data/, runs/, prereg/ or config/ was modified, and no process was started or stopped.
Nothing under data/sealed/ was read. The reproductions used the dev split, plus label-free comparisons of
recorded statuses and world snapshots in runs/d7/test (X2, X2V, X6, X7; 4 of 8 models had finished X6/X7 at audit time).

Integrity: the working tree matches the tag for src/, scripts/ (except the untracked `scripts/run/v4_phase.sh`,
`scripts/paper/analyze_v4_panel.py` and the modified `scripts/paper/figures.py`), config/, prereg/ and data/d7/. All 8 SHA-256 values in
PREREGISTRATION_V4 §4 that I checked match. `scripts/data/sample_h16.py`, re-run in memory, reproduces `data/d7/h16_sample.csv`
byte for byte. `estimate_trust_v3.py --splits dev,calib --suffix b`, also re-run in memory, reproduces
`config/source_profiles_v3b.yaml`, and the `--splits dev` run reproduces `source_profiles_v3.yaml`.

## Summary

| # | Sev. | Hyp. | Finding |
|---|---|---|---|
| C1 | **critical** | H18 | The clean baseline (X2) ran on pre-D21 verifier code for 7 of 8 models, while X6 ran on prereg-v4 code. The code version is confounded with the decoy treatment for DC on vendor cases. |
| M1 | major | H18 | DC is barely exposed to the treatment. Only 48/416 DC episodes saw a decoy before deciding. The deb, roundcube and Jenkins decoys are never seen by DC, so the pooled non-inferiority test is diluted. |
| M2 | major | H18 | Vendor decoy selection bug: on multi-range CVEs the decoy often has the same status as the truth (A→A in 11/46 test vendor cases). |
| m1 | minor | H18 | The `_seen` heuristic counts reads after the decision. `_accepted` is always 0 for S3 by construction and uses an exact string match. |
| m2 | minor | H17 | DCt runs with `explain=False`, unlike DC. Status, loss and DER are unaffected, but notes, usage and error exclusion differ. |
| m3 | minor | H17 | The DC baseline also comes from older code. This was checked empirically and has no effect in the withheld arm. |
| m4 | minor | H16 | DC (X2, old code) is compared with DCv21b (new code): 3/99 vendor DC triples differ in status. The sample is case-disjoint but shares 65/70 CVEs with H15. |
| m5 | minor | all | analyze_v4 has no uniqueness or completeness assertions, and its pair counts are not reported per model. |
| i1–i3 | info | — | DC is model-invariant in the withheld arm. `priors_v3.yaml` cannot be reproduced from current code. Vendor decoy files are matched by substring. |

Items checked and found correct are listed at the end.

---

## C1 (critical, H18): baseline and treatment ran on different verifier code

**Evidence.**
- The run manifests show which code produced each block:
  - `runs/d7/test/X2/*.manifest.json` for the 7 original models: `git_commit 65d25fb`, clean tree.
  - X2 for mistral_medium_128b: `a329962`, which already contains D20/D21.
  - X6, X7 and X2C: `55c0960` (prereg-v4).
- `git diff 65d25fb 55c0960 -- src/deepcti/extraction/verifier.py` contains the D21 fixes:
  - `RUNNING` is removed from the vendor file grammar.
  - `X-<name>` headers now count as naming the component.
  - Vendor versions must be major.minor.patch.
- These fixes change DC decisions on vendor cases in the **tracker** arm only. Comparing X2 with X2V (same cases, DC):
  - Tracker arm: 44/588 statuses differ for the 7 old-code models and 0/84 for mistral_medium.
  - Withheld and blind arms: 0 differ.
- X6 compared with X2 for the same (case, DC, model) in the tracker arm, among the 4 models finished so far:
  - gemma4_31b and llama31_8b: 6/46 vendor DC statuses differ from X2. All 12 equal X2V, and in none of them did DC see the decoy. Examples: `D7-CVE-2018-1000861-vendor-noble-V4` UI→fixed, `D7-CVE-2026-84645-vendor-noble-V8-b2` UI→affected.
  - granite41_30b: affected→UI flips, including `D7-CVE-2026-55956-vendor-noble-V3`. There the X2 decision rested on the RUNNING.txt series number "11.0", which is exactly the D21 bug (verdict reason in the X6 record: "fs version facts only from changelog headers or vendor version files").
  - DC on deb, and DC_noverify everywhere: 0 differences. The confound is confined to DC (the H18 primary) on vendor cases.
- Magnitude: under `eval/metrics.py::loss_matrix`, each UI↔correct flip moves the loss by 0.5, and a wrong fixed/not_affected on an affected case moves it by 10. Six flips in 104 cases per model is about 0.03 of mean loss, against an H18 margin of 0.05. The sign depends on the sealed labels, which I did not read.

**Fix.** Log a deviation and report H18 both as pre-registered and with a code-matched baseline:
- For DC and DC_noverify on vendor cases, use X2V (tracker arm, all 8 models, same code as X6 apart from the decoy).
- Keep X2 for deb cases (0 differences observed) and for S3, which does not use the verifier.
- The cleanest alternative is to re-run a clean tracker control (`Spec(..., decoy=False)`) for the X6 cases at prereg-v4.

In `scripts/paper/analyze_v4.py`, `b_all = x2[x2["arm"] == "tracker"]` is the line to change for the sensitivity analysis.

## M1 (major, H18): treatment exposure is low, which biases the test toward "supported"

**Evidence** (test X6, 4 models; `_seen` cross-checked against `calls` and `t_decision`):
- **deb (58/104 cases).** DC and DC_noverify read the planted changelog in 8/232 episodes, and **all 8 reads happen after the decision**. They come from the remediation path, `Controller.remediate` (systems.py:560-563), and the status is fixed before that point. In the tracker arm, deb decisions come from the tracker plus `pkg_query`. S3 read the changelog in 1/232 episodes.
- **roundcube `CHANGELOG.md` (12/46 vendor cases).** The decoy is appended at the end of a file longer than 8000 characters, but `HostEnv._t_file_read` returns `text[:8000]` (host.py:724). Every read returned exactly 8000 characters. DC and DC_noverify read the file 48 times each and S3 45 times, and the decoy was never visible. The dev pilot shows the same pattern: 4 roundcube cases, 4 misses per system.
- **Jenkins (12/46 vendor cases).** The decoy is planted in `jenkins.install.InstallUtil.lastExecVersion` and `...UpgradeWizard.state`. These names do not match `VERSION_FILE` (systems.py:35), so the controller never proposes reading them. DC read them 0/48 times. S3 read them 10/48 times.
- **RELEASE-NOTES (22 vendor cases).** These are the only exposure for DC: 48/88 DC episodes saw the decoy before the decision.
- Net effect: 48 of 416 DC episodes (11.5%) were exposed to the decoy before deciding. With a pooled margin of 0.05, a mean loss increase of up to about 0.43 per exposed episode would still pass. This contradicts the claim in PREREGISTRATION_V4 §1 that the decoy is placed in "the documents the systems actually read".

**Fix.** Pre-registered H18 cannot be changed, but report the following:
- (a) Exposure per stratum (deb / RELEASE-NOTES / CHANGELOG.md / Jenkins).
- (b) An exposure-conditioned secondary analysis that avoids post-treatment selection. Restrict to cases where the decoy is *observable* (inside the first 8000 characters of a file the system read in the clean X2/X2V episode), or to RELEASE-NOTES cases.
- (c) In any future run, insert the vendor line next to the true version line rather than appending it, and drop files the controller never reads.

## M2 (major, H18): the vendor decoy is often not on "the other side"

**Evidence.** `HostEnv.apply_decoys` (host.py:503-511) breaks out of the loop at the **first** range. If `cur` is not in that range, it returns that range's `introduced` bound. For multi-branch CVEs, where `cur` lies in or above a later range, the decoy then sits in the first range and has the same status as the truth. Using `versions.classify` on the recorded `decoy` against `cve_meta` ranges (no labels needed):
- Test vendor X6 cases: F→A 22, A→F 13, **A→A 11**.
- Dev: A→A 14/34.

Examples:
- `D7-CVE-2020-9484-vendor-jammy-V8`: true 10.0.0, decoy 7.0.0.
- `D7-CVE-2026-65183-vendor-noble-V8`: true 11.0.23, decoy 9.0.42.

An A→A decoy cannot cause a status error, so it adds further dilution in the direction of M1.

**Fix.** Choose a decoy with `classify(decoy) != classify(cur)` across *all* ranges, for example the `fixed` bound of the range that contains `cur`, or the `introduced` bound of the nearest range above or below. Also report H18 with the A→A cases excluded as a sensitivity analysis.

## m1 (minor, H18 secondary): `_seen` and `_accepted` heuristics

- `_seen` (analyze_v4.py:53-58) matches the decoy line in any traced output. It counts the 8 DC and 8 DC_noverify deb episodes whose read came after the decision (see M1). Apart from that it agrees with an exact check: all read-but-unseen cases are the 8000-character truncation. Fix: require `t <= t_decision`, or report the before/after split.
- `_accepted` reads `extra.final_state.verdicts`. S3 records have no verdicts, so the "accepted" share for S3 is 0 by construction, not by measurement. The DC_noverify verdicts are "accepted without verification", so for that system the share measures *proposed*. The comparison `value == decoy_version` is exact, so a proposal without the epoch, such as `8.2.3995-1ubuntu2.4` against `2:8.2...`, is missed. Fix: label the S3 share as n/a and normalise the epoch.
- The `trace[-40:]` truncation (runner.py:191) could hide early reads in long episodes. The maximum trace length observed was 26, so this has no effect now.

## m2 (minor, H17): DCt differs from DC beyond the profile file

**Evidence.** In runner.py:133, `explain=system in ("DC", "DCv21", "DCv21b")` does not include `"DCt"`, so DCt never makes the post-decision note LLM call. Status, loss, coverage and DER are unaffected, because the note is generated after `assessed` is fixed (systems.py:464-476). Two things do change:
- Token usage and the notes themselves.
- Error exclusion: a failed note call turns a DC episode into an `infrastructure` error (runner.py:149-150), which the pairing then drops, but DCt cannot fail that way.

X7 currently has 0 errors, so the impact so far is nil.

Every other difference is as intended. `prof_file` (runner.py:76) is the only DCt-specific branch, and it applies only to `dataset == "d7"`. The acquisition (`voi`), verifier, policy (P3), priors, `service_aware=False` and `k_decide` are all the same as DC. No `== "DC"` check elsewhere in src/ affects DCt (grep: only runner.py:133). judge/d7.py and inspect_harness/s3i.py hard-code `source_profiles_v3.yaml`, but neither touches DCt.

**Fix.** Document this, or add `"DCt"` to the `explain` tuple in any future run.

## m3 (minor, H17): the DC baseline uses older code, with no observed effect

DC in X2 (65d25fb) is compared with DCt in X7 (55c0960). In the withheld arm, the D21 verifier fix changes 0/672 vendor DC statuses (X2 against X2V, all 8 models). DCt in X7 against DC in X2 (4 models):
- pypi: 0/78 changed per model.
- vendor: 0/84 changed per model.
- deb-ubuntu: 107/156 changed per model, all UI→decided.
- maven: 68/96 changed per model, all UI→decided.

So the contrast is driven only by the profile change, as intended. **Fix:** repeat this check once the remaining 4 models finish X7.

## m4 (minor, H16)

- **Code version of the DC arm.** DC notes come from X2 (65d25fb for 7 models) and DCv21b notes from X2C (55c0960, with the D21 verifier fixes). Across the 99 vendor triples in the H16 sample, DC status differs between X2 and X2V in 3. Separately, 41/99 DC notes differ between the two runs because of LLM nondeterminism, which adds noise but not bias. Sensitivity: substitute the X2V DC record for vendor triples.
- **Independence.** The sample is case-disjoint from H15 (0/168 overlap) but shares 65 of its 70 CVEs with the H15 sample. The DCv21b validator rule (D23) was designed after seeing the H15 notes. Report this as partial independence.
- **Replay.** `replay_d7` replays X2 records produced by 65d25fb under current host code. D20 changes only post-action and inactive-service outputs. No D7 fixture has an inactive service at start (0/822 `host.json` with `"active": false`). Any mismatch is dropped as a pair through `replay_mismatch`, so check the `replay_mismatch` count that `d02_extract` prints.

## m5 (minor, analysis robustness)

- `paired()` (analyze_v4.py:69-75) inner-joins on `(case_id, model)` with no uniqueness check. Current data has no duplicates (X2 19,872 ok rows, X6 1,248, X7 1,656, all unique by (case, system, model, arm)). The runner skips completed keys, so duplicates could only come from two concurrent writers. Fix: `assert a.set_index(k).index.is_unique and b.set_index(k).index.is_unique`.
- No completeness check. Running `analyze_v4.py` before all 8 models finish X6 (312 jobs per model) and X7 (414 per model) would silently test a subset. Error rows are dropped (`load`), and the inner join then drops their partners without reporting it. Fix: assert the per-model counts and report the number of dropped pairs.
- The CI rules match the prereg text:
  - H16: `lo > -0.02`, through d06 `H15_holds`.
  - H17: `loss hi < 0` and `DER hi <= 0.01`, with DER computed on gold-affected cases as in analyze_v3.
  - H18: `hi < 0.05`.
- The bootstrap is clustered by CVE with 10,000 resamples and seed 20261005.

## Informational

- **i1.** In the withheld arm, DC's statuses are identical across all 8 models, and the DCt−DC changes are identical per model. H17 is therefore effectively one replicate repeated 8 times. The CVE-cluster bootstrap handles this, but n = 8 × 414 overstates the information.
- **i2.** `config/priors_v3.yaml`, frozen at prereg-v3, cannot be reproduced from current code. Re-running `estimate_trust_v3.py --splits dev` in memory gives vendor `q_service` 0.9722 against the frozen 0.0278; every other ecosystem is identical. DC, DCt and every other system share this file, so it does not bias v4, but it means the vendor `service_status` VOI is near zero.
- **i3.** The vendor planting condition is `cur in self.files[path]`, a substring test (host.py:515), so `9.0.1` matches `9.0.10`. No wrong file was planted on dev.

## Checked and correct

- **run_h16 monkeypatching works.** After `import run_h16`, `d02_extract.OUT`, `d03_judge.OUT` and `d06_metrics.OUT` all equal `results/v4/h16`. `d0x.load_sampled_records is run_h16.load_h16_records`. `client()` reads the patched `C.CACHE` (`results/v4/h16/cache`) at call time. Nothing writes to `results/v3/e11_d7`: `E11_OUT` is only read for `validated_judges.json`.
- **Relabelling DCv21b to DCv21 is safe.** `replay_d7` and `EpisodeView` do not use `rec["system"]`. Replay builds the env with `source_profiles_v3.yaml`, which DCv21b used. `vs_outcome` and the stateless primary evidence apply, which is correct because the DCv21b synthesis prompt contains the raw outputs and no `[state]` (systems.py:501-515). All 252 X2C records present have `validated_synthesis` in the trace (9 fallback), each trace has fewer than 40 entries, and none has history.
- **Judge eligibility.** `mistral_medium_128b` maps to family "mistral", so all three validated judges (gemma, granite, nemotron/llama) are eligible. For llama31_8b, nemotron is excluded, unchanged from H15.
- **apply_decoys (dev, 64 decoy cases).**
  - It changes no world atom and no `vulnerable_now`.
  - No file other than the reported paths changes.
  - It does not change any output of vex_lookup, pkg_query, lang_pkg_query, list_dir, cmdb_lookup, service_status, config_get or the three scanners.
  - The deb changelog header line is intact, and the decoy is the first bullet.
  - All binaries of a source package share one version.
  - It does not leak into the `lru_cache`d Fixture, because `self.files` is a dict copy.
  - On test, `world_at_start` and `world_pre_drift` are identical between X6 and X2 for 1248/1248 pairs.
- **Runner order.** `apply_decoys` runs after `HostEnv` construction and before the Mediator, `world_pre_drift` and `world_at_start`. X6 has no drift and no history.
- **X6 job filter.** The `has_decoy` filter in run_experiment.py uses the same deterministic function as the runner, and all X6 records carry non-null `decoy`. The deb Version comparison uses `debian_support.Version`, and decoys are planted on vulnerable hosts only, as specified.
