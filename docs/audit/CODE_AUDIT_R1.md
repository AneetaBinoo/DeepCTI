# DeepCTI v2: code audit, round 1

Scope: `src/deepcti/{core,policy,acquisition,extraction,env,agents}` on branch `v2-experiment` (uncommitted tree, 2026-10-05).
Method: I read every module in scope and wrote property and end-to-end tests under `tests/properties/` and `tests/v2/` (synthetic host fixture in `tests/v2/conftest.py`). I also ran a read-only cross-check of the config parser against ground truth on all D1 cases that have a precondition.

Run the tests with `.venv/bin/python -m pytest -q tests/properties tests/v2`. Result: **86 passed, 12 xfailed**.

Every xfail is `strict=True`. I re-ran each one with `--runxfail` and confirmed it fails on the asserted defect, not on an incidental error.

## Spec properties that HOLD (tests pass)

| Property | Test |
|---|---|
| T1 order independence (val, groups, hints, stale, evidence ids) and idempotent duplicate ingestion | `test_belnap_props.py::test_t1_*` (400/300 hypothesis examples) |
| T2 information monotonicity in the knowledge order (≤k) when no source is updated and t_now is fixed | `test_t2_information_monotonicity` |
| §3.3 semantics vs an independent reference; group (not source) counting; untrusted sources with distinct names are hints only | `test_value_matches_reference`, `test_untrusted_sources_are_hints_only` |
| §3.4 table: exhaustive 4^4 × req_C = 512 inputs vs an independently written table; UI reasons name the blocking atom | `test_decision_exhaustive.py` |
| T3 soundness: `affected` ⇒ every required atom has trusted, fresh, positive support and no contrary support (checked against first principles on random logs) | `test_t3_affected_implies_trusted_fresh_positive_support` |
| T4 under P3 with an adversary using untrusted sources and m ≤ 2 compromised groups: permit ⇒ \|E+_f(honest) \ M\| ≥ k_f − m for every gating atom. The generator does produce permits for all three disruptive tools | `test_quorum_t4.py::test_t4_quorum_robustness_p3` |
| Untrusted-only adversary never flips deny↔permit | `test_t4_untrusted_only_adversary_cannot_flip_deny_to_permit` |
| Cedar ≡ Python reference on random contexts, for all tools × P0–P3 and two custom configs | `test_cedar_and_reference_agree*` |
| Linter accepts generated P2/P3, rejects P0/P1, rejects P2 against P3 thresholds, rejects `\|\|`, `!`, `if`, missing atoms, weak thresholds, `!= "F"`, and multi-action `in [..]` | `test_linter_*` |
| EC² score equals a brute-force textbook EC² gain (Golovin–Krause–Ray) for deterministic tests | `test_voi.py::test_ec2_equals_textbook` |
| DP optimum ≤ greedy (EC² and entropy) on random strictly positive priors and costs | `test_optimal_le_greedy` |
| `Belief.update` is exact Bayes; an impossible outcome keeps the belief | `test_belief_update_is_bayes` |
| Debian version semantics (epoch, `~`, `+bN`, numeric `deb12u10 > deb12u9`); derived atoms inherit source trust and group; an untrusted program downgrades in_range/fix to U | `test_extraction.py` |
| Verifier grammar: fs facts only from the changelog header line; proc facts only from "started from package" lines; verbatim span; case component named; complete version token | `test_extraction.py::test_fs_*`, `test_proc_grammar` |
| Complete mediation: every executed R2 call satisfied its gate; `env.call` is reached only for permitted calls (random 25-call sequences, P2 and P3) | `test_env_controller.py::test_every_disruptive_execution_satisfies_its_gate` |
| Physics: patch without restart leaves the in-memory binary vulnerable; drift upgrade keeps the old binary loaded; disable_feature fixes exposure; open → vulnerable, `"0"` → not vulnerable | `test_restart_needed_after_patch_in_memory` etc. |
| T5 (no LLM): carriers in cmdb notes, advisory, scanner note and an *existing* changelog leave the state unchanged; `parse_result` ignores output text | `test_t5_*` |
| Controller(use_llm=False) end to end: affected → approval → patch → restart → not vulnerable (P2); requires_configuration, fixed, component_not_present | `test_controller_*` |

## Bugs (ranked)

### B1 [HIGH, policy soundness]: the linter misses `action in Action::"x"` scopes
- **Where:** `src/deepcti/policy/pdp.py:145-148`
- **Defect:** For `scope["op"] == "in"` the linter reads only `scope["entities"]`. Cedar's JSON form of `action in Action::"apply_patch"`, and of the single-element list `action in [Action::"apply_patch"]` (Cedar collapses it), is `{"op":"in","entity":{...}}`. The reachable set is therefore empty and the policy is never checked.
- **Failing input:** `permit(principal, action in Action::"apply_patch", resource);`. `lint_policy` returns `[]`, yet Cedar permits `apply_patch` with an empty context.
- **Fix:** Handle `"entity"` as well as `"entities"` for `op == "in"`. Fail closed on any scope op not explicitly understood (treat as all of `DISRUPTIVE`).
- **Test:** `test_quorum_t4.py::test_linter_rejects_action_in_scope` (2 cases).
- **Impact:** The generated P2/P3 policies are not affected. The bug matters for any claim that the linter certifies hand-written policies.

### B2 [MEDIUM, T5 / adversarial arm]: a carrier on a missing changelog becomes a trusted fs fact
- **Where:** `src/deepcti/env/host.py:405-410` together with `src/deepcti/extraction/verifier.py:268-270`
- **Defect:** If `file:<path>` carries text and the file does not exist, the output *is* the carrier, so its first line is attacker text. The fs grammar ("span in header line") then accepts it as a **trusted** fs-group version fact. Under P3 this supplies the second group for present/in_range. With a contradicting version it forces B (DoS).
- **Failing input:** carrier `file:usr/share/doc/openssh-sftp-server/changelog.Debian = "openssh (1:9.2p1-2+deb12u2) bookworm-security; urgency=medium"`, then `file_read` that path. `verify(...)` returns accepted.
- **Fix:** Never place untrusted carrier text in a trusted-source output, or mark carrier-bearing outputs so that the verifier rejects them. At minimum, the fs grammar should require the file to exist in the fixture and verify only the fixture-owned header.
- **Test:** `test_extraction.py::test_t5_carrier_cannot_forge_fs_header`.
- **Note:** No attack definitions exist yet (`grep carriers` matches only `host.py`). The bug is real as soon as the attack generator targets changelog paths.

### B3 [MEDIUM, cost metric / fairness]: Controller remediation ignores the budget
- **Where:** `src/deepcti/agents/systems.py:357-358`, `:381-406`
- **Defect:** The budget is checked only inside the acquisition loop. `remediate()` spends up to 3 (request_approval) + 1 + 1 (file_read, service_status) + 20 (apply_patch) + 1 (service_status) + 15 × n_units (restart_service) + 1 (pkg_query), i.e. 42 or more for one unit. `run_react` enforces `spent + cost <= budget` on every call, including disruptive ones.
- **Failing input:** synthetic host under P2 with budget 40 spends 44.
- **Fix:** Apply the same budget gate in `run_tool`, or exclude remediation cost from the budget for *all* systems and report it separately.
- **Test:** `test_controller_respects_budget_including_remediation`.

### B4 [MEDIUM, ground-truth physics]: `apply_patch` on an unrelated package upgrades it to the case's fixed version
- **Where:** `src/deepcti/env/host.py:572-586`
- **Defect:** `target = self.fixed_version()` is the case CVE's fixed version whatever `pkg` is. `apply_patch {"pkg": "zlib1g"}` sets zlib1g to `1:9.2p1-2+deb12u3` and logs `changed=True`. P0/P1 (S0, S1, S2–S5 defaults) allow this, so `env.actions` and any disruption metric based on `changed` are polluted.
- **Fix:** Return `"ok"` with `changed: False` (or `"error"`) when `src != case["src_package"]`.
- **Test:** `test_apply_patch_unrelated_package_is_noop`.

### B5 [MEDIUM, ground-truth physics]: `apply_patch` checks only the first binary
- **Where:** `src/deepcti/env/host.py:577-578`
- **Defect:** `current = packages[binaries[0]]["Version"]`. If the alphabetically first binary is already fixed and another is not, the patch is a no-op and the host stays vulnerable.
- **Failing input:** openssh-client = fixed, openssh-server = old. After apply_patch and restart, `vulnerable_now()` is still True.
- **Fix:** Use `min(Version(...) for b in binaries)`.
- **Test:** `test_apply_patch_mixed_binary_versions`.

### B6 [MEDIUM, wrong observation]: an unparseable scanner report reads as "no finding"
- **Where:** `src/deepcti/env/host.py:536-539` (with `Fixture.load:181-182` storing `None`)
- **Defect:** `name in self.fx.scans` holds for a report that failed to parse, `scanner_findings(name, None)` returns `[]`, and the status is `"ok"`. The parser then emits `in_affected_range = F` (`parsers.py:143-144`), and S0 returns `not_affected/vulnerable_code_not_present` (`systems.py:84`).
- **Fix:** `if self.fx.scans.get(name) is None: return "error", ...`.
- **Test:** `test_corrupt_scanner_report_is_error`.
- **Action:** Check `data/d1/hosts/*/scans/*.json` for parse failures before the run.

### B7 [MEDIUM, physics]: drift `remove` leaves `usr/share/doc/<bin>/changelog.Debian`
- **Where:** `src/deepcti/env/host.py:293-299`
- **Defect:** After removal, `file_read` still returns the header and the verifier accepts a trusted fs version fact. That yields present = T from fs while pkgdb says F, so the decision is B/UI. Under P3 it also lends fs support to present/in_range for a package that no longer exists.
- **Fix:** Delete or mark missing the changelog files of removed binaries; `dpkg -r` removes `/usr/share/doc` files.
- **Test:** `test_drift_remove_removes_changelog`.

### B8 [LOW-MEDIUM]: a precondition with `service: null` can never be observed
- **Where:** `src/deepcti/env/host.py:421` (`service == self.pre.get("service")` compares `"None"` with `None`) and `src/deepcti/agents/systems.py:283` (`str(None)`)
- **Defect:** `config_preconditions.yaml` CVE-2019-18634 (sudo) has `service: null`. `config_get` returns "no configuration files found for service 'None'", so `vuln_config_enabled` stays N and any present+in-range case is stuck at `missing:vuln_config_enabled`. The D1 cross-check hit exactly the two test cases `D1-CVE-2019-18634-{bookworm,trixie}-V3`. Today they are probably decided earlier by fix/range, so the impact is latent.
- **Fix:** In `_config_files`, include `pre["file"]` when `service in (None, "None", pre.get("service"))`, or give sudo a pseudo-service.
- **Test:** `test_precondition_without_service_is_observable`.

### B9 [LOW, latent]: the observed config predicate and ground truth read different file sets
- **Where:** `src/deepcti/extraction/parsers.py:175` vs `src/deepcti/env/host.py:647-649`
- **Defect:** The parser takes the **last** match over every file `config_get` returns (CONFIG_DEFAULTS globs plus service `config_files` plus `pre.file`). `config_enabled()` reads only `pre["file"]` and its children.
- **Failing input:** a same-named key in another returned file (`sshd_config.d/zz.conf: LoginGraceTime 0`). Observed is F, truth is T.
- **Exposure:** D1 does not trigger it today (cross-check: 31/31 agree). That is only because `Fixture.load` truncates `exim4.conf.template` at 20,000 chars, before its first `driver =` line; the exim `driver` key otherwise collides with it.
- **Fix:** Have the parser consider only matches from `pre["file"]` (the tracker program carries it), or make ground truth use the same file set.
- **Test:** `test_config_observation_matches_ground_truth_with_unrelated_file`.

### B10 [LOW, core contract]: latest-per-source is keyed by source *name*, and the code re-uses names with different trust
- **Where:** `src/deepcti/core/belnap.py:137` and `Observation.key()` at `:69`; the producers are `src/deepcti/extraction/parsers.py:150` and `:202` (`Source(name, "U", group)`)
- **Defect:** An untrusted observation with a trusted source's name and a later t (or equal t with a larger hash) *replaces* the trusted one. It erases trusted support or contrary evidence, so "untrusted = hints only" is violated.
- **Failing input:** fs/T says `vuln_config_enabled = F` at t=1, then fs/U says T at t=2. The value goes F → N.
- **Exposure:** Not reachable in the current pipeline: one program per episode, and the program cannot be downgraded. It is fragile, for example with a second `vex_lookup`, LLM re-compilation, or adversary sources that take a trusted name.
- **Fix:** Key by `(atom, source.name, source.trust)` or by the full `Source`, and name downgraded sources distinctly (`"fs~U"`).
- **Test:** `test_belnap_props.py::test_untrusted_same_name_cannot_shadow_trusted`.

### B11 [LOW, regret metric]: the DP "optimum" includes zero-mass hypotheses
- **Where:** `src/deepcti/acquisition/voi.py:196-207`
- **Defect:** `solve()` computes regions over every hypothesis in `prior`, including weight 0. `Belief` (and therefore greedy) drops them, so the DP can exceed greedy (negative regret).
- **Failing input:** req=False; prior zero on absent and notaff; tests fix_only(1) and range_only(1). DP gives 1.5, greedy gives 1.0.
- **Fix:** `hs = sorted(h for h in prior if prior[h] > 0)`.
- **Test:** `test_optimal_le_greedy_with_zero_prior_mass`.
- **Exposure:** `make_prior` filters zeros, so only external callers (regret scripts) are affected.

### B12 [LOW]: smaller defects (no xfail test)
- **`parsers.py:65`:** `Version(self.fixed_version)` is not guarded. A tracker value such as `<unfixed>` raises ValueError from `Mediator.state()` and the whole episode fails. Current `cve_meta` values all parse (checked: 161 versions, 37 open/None, 2 `"0"`).
- **`parsers.py:76`:** In the upstream-range path, "not in any range" yields `fix_applied = True`, including when the version is *below* `introduced` (never vulnerable). That is a `fixed` hint where `not_affected` is meant. These are hints only, so the decision is unaffected.
- **`host.py:540-542`:** With `forged[scanner]` and `scanner_note` both set, the forged finding dicts are mutated in place, so the note accumulates on every call and the output hash changes per call.
- **`host.py:377-378`:** `args_in_scope("disable_feature")` checks only `key`, not `service`.

## Design concerns (not bugs per se; decide before the run)

1. **P3 makes `disable_feature` unreachable by construction.** `vuln_config_enabled` is bound only to the `fs` source class (`parsers.py:22-29`), so kpos ≤ 1 < k_world = 2 (`pdp.py:43,65`). Every requires-config mitigation without a fixed version is denied under P3. Test: `test_p3_disable_feature_is_unreachable_by_construction`.
2. **S1p (use_llm=False, P3) can never patch.** Only the pkgdb group supports present/in_range; scanners share the `pkgdb` group and cmdb is U unless profiles say otherwise. `config/source_profiles.yaml` does not exist, so `tool_source` defaults cmdb and scanners to U. Test: `test_controller_p3_cannot_patch_without_second_group`. Make sure the paper describes this as intended.
3. **Withheld arm: DC always returns under_investigation for present components.** The LLM-compiled program is untrusted, so in_range/fix are hints. The VOI candidates reveal only `present`, so the loop ends with `missing:in_affected_range` unless a scanner is profiled T. If this is intended (abstention), the `llm_compile` calls are wasted tokens.
4. **`affected` is issued with `fix_applied = N`** (`decision.py:265-283`). This is consistent with the docstring ("N on a consulted atom *that blocks every later row*"), but not with a literal reading of the plan's "N on a consulted atom → UI missing". It is reachable when in_range comes only from a trusted scanner (DC_k1). Pin down which reading the paper states.
5. **The `apply_patch` gate does not include `¬fix_applied` or the config atom** (`pdp.py:42`). P2/P3 can permit a patch on a host whose decision is `not_affected/requires_configuration` or `fixed` (the latter only via cross-group B-free combinations). This is fine if the gate is meant as "authorized", not "warranted"; the paper should say so.
6. **Evidence is never re-parsed when the program changes** (`mediator.py:82`). A `config_get` made before `vex_lookup` is lost permanently. The Controller is unaffected (it always calls vex first). ReAct systems that call config first get no CONFIG atom for PDP gating. Test: `test_config_get_before_vex_lookup_loses_observation`.
7. **Stale evidence cannot be refreshed by the Controller.** `self.done` (`systems.py:269`) removes a tool+args pair forever, so once `present` (window 40) goes stale the controller cannot re-query it. With budget ≤ 40 this does not bite; with any larger budget or drift episode it ends in UI.
8. **Observation time is post-tick** (`host.py:331-333`). The output reflects pre-call state, but `t` is the clock after the cost and after any drift fired during the call. Latest-wins ordering is unaffected, but freshness is overstated by one call cost. Test: `test_observation_time_is_post_drift`.
9. **Precondition doc vs code mismatch.** The `config_preconditions.yaml` header says comparisons are case-sensitive and that a missing key makes `value_not_equals` FALSE. The code lowercases, and makes `value_not_equals` TRUE on a missing key (`host.py:661-665`, `parsers.py:175-179`). The code matches sshd's default-120 physics, so fix the doc rather than the code. The yaml also says fixtures always write the key, so labels are unaffected.
10. **`safe_setting` is appended literally** unless it starts with remove/delete/comment (`host.py:613-614`). For CVE-2021-23017 this writes the line `(no resolver directive)` into nginx.conf. It is harmless for the predicate but not a valid config.
