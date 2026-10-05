# DeepCTI v3 — independent code + results audit (D7, X4, panel addendum)

Auditor: independent (read-only on src/, scripts/, data/, runs/, prereg/). Date 2026-10-05, HEAD `a8ceb83`
(branch v2-experiment), tag `prereg-v3` present. All numbers below were recomputed from raw logs by the auditor's
own scripts:

* `tests/v3/audit_v3_integrity.py` — label/world consistency for every D7 test case (HostEnv built as the runner
  builds it, per arm), duplicates / errors / budget overruns / invalid outputs / excluded mismatches per run file,
  leakage token scan.
* `tests/v3/audit_v3_drift_physics.py` — for every D7 TEST drift episode (X5), applies the drift exactly as the
  runner does and checks that the evidence an agent can read agrees with the ground-truth world.
* `tests/v3/recompute_hypotheses_v3.py` — independent H9, H10, H11, H13, H14 (own loss, pairing, CVE-clustered
  sign-flip 20 000 draws, bootstrap 5 000) and H12 (own LTT loop, different seed), plus sensitivities.

Run: `PYTHONPATH=src .venv/bin/python tests/v3/<script>.py` (sealed D7 test labels; tag exists).

---------------------------------------------------------------------------------------------------------------

## 0. Verdict in one paragraph

All six pre-registered D7 results (H9–H14) **reproduce** from raw logs to the reported precision, the
implementations match the prereg-v3 text, and D7 test results are clean (0 duplicates, 0 errors, 0 budget
overruns, 0 label/world status mismatches, no leakage of case ids/variants/labels into prompts). Two
environment/verifier defects do, however, change reported D7 numbers: **(F1) non-deb drift physics is inconsistent
(worst: vendor restart/rollback/remove)** (vendor banner never updated on restart, inactive units still print a banner;
maven Implementation-Version and pypi METADATA not updated), which manufactures most of the X5 "DCv21 fixes rollback" gap and all X5 vendor losses for
`remove`/`upgrade_restart`; H13 itself is *not* affected (no restart in upgrade_no_restart). **(F2) the verifier's
component-name boundary rejects `X-Jenkins: <ver>` banners**, which makes DC abstain on 105/126 Jenkins tracker
records and is the *entire* reason DC loses to DC_noverify on vendor/tracker (0.152 vs 0.086); H10 is therefore
conservative, not inflated (so is C1: DC abstains on 32% of absent vendor/tracker records because
the zero-VOI fallback exists only for DCv21). The largest presentation risk is (P1): **on D7, DC's decisions are identical to the
LLM-free S1′ in every arm and ecosystem except vendor/tracker** (and withheld ≡ blind for DC), so H9 is an S1′-vs-S3
result and DC loses to off-the-shelf scanners in the withheld arm on deb-ubuntu, pypi and maven. Also
`results/v3/test/ADDENDUM.md` is stale (pre-dates the completed Granite-30B / Nemotron runs).

---------------------------------------------------------------------------------------------------------------

## 1. Recomputed headline numbers (D7 test)

| test | reported (hypotheses_v3.csv) | auditor recompute | prereg conformance |
|---|---|---|---|
| H9 withheld DC−S3 loss, per case avg over 7 models | −0.966 [−1.118, −0.818], p=1e-4, n=414, 70 CVEs | −0.9659 [−1.122, −0.816], p₂=5e-5, p₁=5e-5 | matches |
| H10 vendor/tracker DC−S1′ loss | −0.199 [−0.260, −0.133], p=8e-4, n=84, 14 CVEs | −0.1990 [−0.262, −0.132], p₂=9e-4, p₁=4.5e-4 | matches |
| H11 accepted-fact error DC−DC_noverify | −0.0280 [−0.041, −0.016], p=1e-4, n=151 | −0.0280 [−0.042, −0.016], p₂=5e-5; model-averaged sensitivity −0.0134 [−0.021, −0.006], p₂=3.5e-4 | matches (unit unspecified in prereg; see P5) |
| H13 X5 upgrade_no_restart DCv21−DC loss | −4.534 [−6.244, −2.981], p=1e-4, n=280, 26 CVEs | −4.5336 [−6.271, −2.910], p₂=5e-5 (deb −7.07, n=175; vendor −0.31, n=105) | matches |
| H14 withheld@60 DC−DC_checklist cost-to-decision | −0.35 [−0.507, −0.208], p=1.5e-3; loss diff 0, UB 0 | −0.350 [−0.509, −0.206], p₂=1.25e-3; loss diff 0.000 (0/400 pairs differ), UB 0.000 | matches |
| H12 LTT blind α=0.05 criterion | min frac 0.97, mean gain 0.395, met | min frac 0.94 (qwen3_4b; seed-dependent), mean gain 0.3954, every model gain>0 → **met** | matches |

Holm (m=6, H12 criterion encoded p=0): all five p-value hypotheses remain < 0.003 after adjustment. The
sign-flip test in `analyze.py` is two-sided while H9–H14 are directional; one-sided p-values are smaller, so this is
conservative (no change to conclusions).

X4 (prereg-v2 H7/H8) recomputed on the **current** runs (7 models incl. Granite-30B):
H7 DCv21−DC = **−9.133** [−9.70, −8.27], p₂=5e-5, n=210 (ADDENDUM.md reports −9.046, n=180 — stale, see P2);
H8 = 0.000, UB 0.000, n=637, 0/637 pairs differ → non-inferior.

---------------------------------------------------------------------------------------------------------------

## 2. Findings that AFFECT REPORTED NUMBERS (ranked)

### F1 (high; X5 table, any X5 per-kind claim; not H13) — non-deb drift physics: vendor banner not updated on restart, inactive units print a banner, stale maven manifest / pypi METADATA
`src/deepcti/env/host.py:478-484` (drift `restart`) and `:926-930` (`restart_service` tool):

```python
svc["loaded_version"] = insts[0]["version"]
if svc.get("banner") and svc.get("version"):
    svc["banner"] = svc["banner"].replace(str(svc["version"]), insts[0]["version"])
```
D7 vendor services carry `banner` and `loaded_version` but **no `version` key**
(e.g. tomcat: `{'banner': 'Apache Tomcat/10.0.2', 'loaded_version': '10.0.2', ...}`), so the banner is never
rewritten: after a restart the ground truth (`loaded_version`, used by `world_atoms`) changes but `service_status`
keeps printing the old version. Separately, `_t_service_status` (`host.py:722`) prints `Main PID` and the
`server banner` whenever `loaded_version` is set, without checking `active`, and the non-deb `remove` drift sets
`active=False` but leaves `loaded_version`; a removed product therefore shows "inactive (dead)" **plus** a live
version banner.

`tests/v3/audit_v3_drift_physics.py` on all 160 D7 test drift episodes:

| kind × ecosystem | episodes with evidence ≠ world |
|---|---|
| rollback / vendor | **12/12** (e.g. tomcat banner 10.0.2, loaded 10.0.0) |
| upgrade_restart / vendor | **13/13** (e.g. jenkins banner 2.151, loaded 2.154) |
| remove / vendor | **7/7** (inactive unit still prints `server banner: Apache/2.4.46`) |
| upgrade_no_restart / vendor | 2/15 (httpd `ap_release.h` keeps PATCHLEVEL 46 — version split across `#define`s, string replace cannot match; gold unaffected because the running 2.4.46 keeps the case `affected`) |
| rollback / maven, upgrade_restart / maven | 6/6, 8/8 — `lang_pkg_query` prints `version=2.14.1 (Implementation-Version: 2.16.0)`: `set_instance_version` does not update `manifest_version`; nested (`!/BOOT-INF`) jar paths keep the old version in the name |
| rollback / pypi, upgrade_restart / pypi | 3/4, 10/10 — dist-info directory renamed but `METADATA` still says the old `Version:` |
| all deb-ubuntu kinds; maven/pypi `remove` | 0 |

The maven/pypi defects leave the authoritative field (`version=` / `Version:` in `lang_pkg_query`) correct, so DC,
DCv21 and S1′ score 0 loss there; but every non-deb version-change episode presents a self-contradictory host to
the free-form agents (S2/S3), which inflates their X5 maven/pypi losses (S3 rollback 4.08/4.66, upgrade_restart
0.59/0.29) by an unknown amount. (No static D7 test host has `manifest_version ≠ version`, so this contradiction exists only
because of the drift code; static X2 hosts are consistent: 0 inactive units with a loaded version, 0 vendor banner/loaded
mismatches.)

Effect on reported X5 numbers (loss, pooled over 7 models; auditor breakdown):

| kind × eco | DC | DCv21 | S1′ |
|---|---|---|---|
| rollback / vendor | **5.35** | 0.21 | 0.50 |
| rollback / deb, maven, pypi | 0.00 | 0.00 | 0.00 |
| remove / vendor | **0.90** | **0.90** | 0.50 |
| upgrade_restart / vendor | **0.77** | **0.81** | 0.50 |

The whole X5 `rollback` gap (DC 1.605 vs DCv21 0.064) comes from vendor episodes where DC accepts the stale
"fixed" banner; DCv21 is right only because its instance-aware rule lets the (correctly rewritten) on-disk
RELEASE-NOTES win ("any instance in range"). With consistent physics both would see the vulnerable version. The
`remove`/`upgrade_restart` vendor losses (both DC variants worse than abstaining S1′) are likewise artefacts.
**H13 is unaffected** (upgrade_no_restart involves no restart; the banner correctly stays at the running version).
The same defect affects any X2 vendor episode in which an agent calls `restart_service` (BU/remediation outcomes,
`vulnerable_after`), not the status metrics. Recommendation: fix (`replace(old loaded_version, new)`; gate the
banner on `active`; drop product files on remove), re-run X5 vendor episodes, log as a deviation; or exclude
vendor restart/rollback/remove from X5 claims and say why.

### F2 (high; X2 vendor/tracker DC, DCv21; H10 conservative) — verifier rejects `X-Jenkins:` banners
`src/deepcti/extraction/verifier.py:82`:
```python
named = [n for n in names if n and re.search(rf"(?<![\w.+-]){re.escape(n)}(?![\w.+-])", span, re.I)]
```
The look-behind excludes `-`, so `server banner: X-Jenkins: 2.154` does not "name" `jenkins`. In X2 vendor/tracker
the verifier rejected 70 Jenkins banner facts for this reason (+12 by the proximity rule), and **DC abstained on
105/126 Jenkins records**, while DC_noverify decided on 102/126 (loss 0.110). Loss by component (tracker arm, 7 models):

| component | DC | DC_noverify |
|---|---|---|
| jenkins | **0.417** | 0.110 |
| httpd / tomcat / roundcube | 0.107 / 0.112 / 0.000 | identical |

So the reported "DC 0.152 vs DC_noverify 0.086 on vendor/tracker" (verification apparently *costing* accuracy) is
entirely this boundary rule. H10 (DC−S1′ = −0.199) would be more negative with the rule fixed; the direction of H11
is unaffected (it measures accepted facts). Roundcube has 44 analogous rejections (no loss consequence here).

### F3 (medium; H11 interpretation, 6 X2 tracker errors) — verifier accepts Tomcat series numbers as installed versions
All 207 wrong *accepted* DC vendor fs facts are `opt/tomcat/RUNNING.txt` lines such as
`Running The Apache Tomcat 10.1 Servlet/JSP Container` → value `10.1` (true 10.1.57). Consequence: the reported
"DC accepted-fact error, fs = 9.7%" is 0% on deb-ubuntu and 35.7% on vendor, all from this one file type; it
caused 6 tracker-arm `fixed → affected` errors (loss 1 each) and many blind/withheld abstentions. `RUNNING.txt`
should not be in the vendor version-file grammar (`verifier.py:63-65`), or the value must be a complete
`x.y.z` token. H11's DC<DC_noverify effect comes from the proc rules (DC_noverify proc errors 5.8% deb, 3.3%
vendor vs 0%), not from fs.

### F4 (low-medium; X5 non-deb episodes) — drift "previous assessment" uses `pkg_query` for non-deb components
`src/deepcti/eval/runner.py:95-97` always seeds history with `pkg_query{name: src_package}` +
`service_status`. For vendor/maven/pypi this returns `dpkg-query: package 'jenkins' is not installed` — a
trusted-source (pkgdb) statement that the component is absent, injected into every non-deb drift episode (passed
to `Mediator.ingest_history` for DC; S2/S3 see it in the task message). It is truthful for dpkg but is not the evidence a
prior assessment of a vendor/language component would contain. Numbers for maven/pypi kinds are 0 loss for DC so
the practical effect is small; it may contribute to S2/S3 vendor/maven/pypi losses in X5.

---------------------------------------------------------------------------------------------------------------

## 3. Results integrity (D7 test)

* **World/label consistency:** HostEnv world atoms recomputed for all 414 test cases × 3 arms: **0 status and 0
  justification mismatches** with `data/sealed/d7_test_labels.jsonl`. Atom-level differences exist only for
  `vuln_config_enabled` where it is decision-irrelevant (198 cases with `req_config=False`, labeller writes True,
  env False; 14 with `req_config=True` but `present=False`). Every X2/X3/X2I record also has
  `label_world_mismatch=False`, so analyze_v3's exclusion filter removes nothing (no stderr warnings).
* **Run files:** X2 8 files × 6210 = 414 cases × 3 arms × 5 systems (S0×3/S1/S1′ under `none`); X2I 2 × 828;
  X3 2 × 12 000 + 2 000; X5 7 × 640 + 320. **0 duplicate keys, 0 error records, 0 infra errors, 0 `cost>budget`,
  0 `t_decision>budget`, 0 unknown case ids.**
* **Invalid outputs** (counted as UI, loss 0.5): X2 S2 3–11 per model; S3 llama 8, mistral-small 31; X2I S3I
  mistral 10; X3 S3 mistral 61/2000; X5 S2 ≤3, S3 mistral 4. DC/DCv21/DC_noverify: 0.
* **Leakage:** case ids appear only in S3I `extra.inspect_sample_id` (record metadata; the Inspect `Sample.input`
  is `task_message(env)`, which contains hostname, release, CVE and component only). A scan of all 2 070 S3/S3I
  tool outputs (qwen3_14b) for case ids, host ids, variant tags, label words found only benign advisory text
  (`v2.43.7`, "per-label conversions"). Hostnames encode the ecosystem (`srv-ven-…`), which the task message
  states anyway.
* **Scope vs prereg §4:** X2 has the 7 pre-registered models (big-model phase not yet in D7 runs); X3 qwen3_14b +
  mistral_small_24b, 200 cases; X5 all 7; S3I only in X2I (tracker + withheld) as pre-registered.

---------------------------------------------------------------------------------------------------------------

## 4. Code review of changes since prereg-v1 (D7-relevant)

Diff `prereg-v1..HEAD -- src scripts` reviewed (host.py, versions.py, parsers.py, verifier.py, systems.py,
mediator.py, decision.py, runner.py, data.py, catalog.py) with probe scripts on dev/calib/test case rows and
fixtures. Findings not already listed in §2:

* **C1 (affects X2 vendor DC; makes H10 conservative). VOI stops early on absent vendor products that have a
  config precondition; the zero-VOI fallback exists only for DCv21.** If `config_get` is picked first on an
  absent product it returns "no configuration files"; the noiseless config model treats that as "not present"
  with posterior mass 1.0, `select_test` returns None, but the mediator holds no PRESENT fact → UI. The D18
  fallback (`systems.py:436-439`) is gated on `med.instance_aware` (DCv21 only). Auditor confirmation on the
  raw X2 tracker runs, vendor cases with `present=False`: **DC UI 63/196 (32%)**, DCv21 21/196, LLM-free S1′ 3/28.
  The UIs are loss 0.5 each, so DC beats S1′ on vendor/tracker *despite* this defect.
* **C2 (affects X2 vendor V6). `list_dir` presence uses bidirectional substring matching** (`parsers.py:150-152`,
  `n in d or d in n`; same in `systems.py` discover): `gitlab` matches `gitlab-runner/` and `jenkins` matches
  `jenkins-agent/`. The result is a trusted PRESENT=T on decoy hosts where the product is absent (3 Jenkins V6 test cases;
  6/14 V6 vendor cases on dev+calib), so the decision ends as UI instead of not_affected.
* **C3 (latent / H11 risk). Verifier accepts decoy product versions.** It accepts `GitLab Runner 17.11.0` as gitlab,
  `RCMCardDAV plugin for Roundcube 5.1.0` as roundcube, and `Apache Tomcat/11.0.25` as httpd (alias "Apache"). DC's own calls do not reach these units, so
  this is latent for DC. Jenkins additionally has no verifiable fs path (InstallUtil.lastExecVersion and
  config.xml are outside the vendor basename grammar) and fails the proximity rule on the full
  `jenkins[800]: …` line (the PID is the first version token). This extends §F2.
* **C4 (X5 baselines). pypi/maven services are keyed by app name, so `running_versions()` is always [] for them.**
  As a result, restart drift never updates their banners (`Werkzeug/3.0.3` after a rollback to 3.0.1), and these ecosystems are
  excluded from upgrade_no_restart (consistent with P7). DCv21's instance-aware path is never exercised on pypi/maven.
* **C5 (X5). Non-deb `remove` leaves files, jars and dist-info directories in place**: `list_dir` still lists them. DC is protected for
  pypi/maven by `lang_pkg_query`, but not for vendor (§F1), and LLM baselines see contradictions.
* **C6 (latent unless BU reported on D7).** DC never remediates non-deb cases because `program.fixed_version` is None
  for non-deb programs. `restart_service` is never in scope for non-deb, and `apply_patch` rejects `group:artifact`
  names.
* **C7 (minor).** `llm_compile` (`systems.py:222`) sets no `ecosystem`, so withheld/blind compiled programs for
  non-deb use Debian comparison; the program is untrusted, so only hints are affected. The lang_pkg_query parser lacks
  PEP 503 normalisation. `Mediator.decision` `applies_to_versions` uses stale/history facts (only log4j
  CVE-2021-44228). `versions.parse` strips only a trailing `-ee`. `runner.manifest` records the v2
  profiles/priors rather than the v3 per-ecosystem ones (cosmetic).

**Checked and correct:**
* World physics matches labels on dev+calib (408/408) and, per the auditor, on test (414/414 × 3 arms,
  status + justification).
* `versions.classify`: `last_affected` inclusive, multi-branch OSV ranges, Maven qualifiers, PEP 440, Jenkins
  two-part weekly versions.
* `combine_instances` matches D16: any instance in range → affected; fixed only if the disk instance is fixed and
  the running instance is fixed or unobserved.
* Deb proc rule (package start line only).
* gitlab `-ee` normalisation.
* Runner keys include `|d7|v3`, so there are no resume collisions across datasets/specs.
* Per-env deep copies of fixtures.
* Per-ecosystem v3 profiles/priors are selected in `run_episode` (`runner.py:72-76`).

---------------------------------------------------------------------------------------------------------------

## 5. PRESENTATION findings (numbers correct; claims at risk)

**P1 — On D7 the LLM changes DC's decision only in vendor/tracker.** DC decision == S1′ decision in 100% of
records for blind, withheld and tracker × {deb-ubuntu, pypi, maven}; 43.9% for vendor/tracker. DC withheld ≡ DC
blind (100% identical decisions; X3 also identical loss/cost per budget), i.e. scanners never influence DC in D7
(trust profiles mark them untrusted). Hence H9 is "LLM-free S1′ (abstain-when-unsure) vs S3", and H10 is the only
primary test of the LLM's decision value. The paper must say this explicitly (as the v2 audit already required for E2).

**P2 — DC loses to plain scanners in the withheld arm on three of four ecosystems.** Withheld loss: deb-ubuntu DC
0.343 vs S0 (all) 0.133; pypi DC 0.327 vs S0_osv/grype 0.190; maven DC 0.354 vs S0_osv/trivy 0.104. DC wins pooled
only because of vendor (S0 3.39) and Grype-maven (4.42). Any "DC dominates scanners" phrasing must be per-ecosystem.
Also tracker/vendor: DC 0.152 > DC_noverify 0.086 (F2) and DCv21 0.165 > DC.

**P3 — `results/v3/test/ADDENDUM.md` is stale.** Written 15:24, before Granite-30B E2 (15:39) and X4 (15:52)
finished: it shows Granite-30B E2 n=94 and Nemotron n≤17 although runs/test/E2 now hold 4 530 records each, and
X4 with 6 models (n=180/kind) instead of 7 (n=210). Re-run `analyze_addendum.py` before quoting H7/H8 or the panel.
Mistral-Medium-128B E2 is partial (598 records).

**P4 — Panel scaling (matched cases, E2, D1 test).** Granite 8B→30B (all 453 cases): S3 tracker 0.956→0.440,
withheld 1.599→0.645; S4 withheld 1.716→0.417; DC unchanged (0.000 / 0.067). Mistral 24B→128B (partial, ~57–63
cases/cell): withheld S3 **0.088→0.067 vs DC 0.094** and tracker S3 0.237→0.015 — on this partial subset the 128B
ReAct agent *matches or beats* DC in the withheld arm. Do not claim "DC beats agents at every scale" until the
128B run completes; report matched-case comparisons only (the ADDENDUM panel compares different case subsets).

**P5 — H11 unit.** Implemented as fact-weighted error per case pooled over 7 models × 3 arms (−0.028); the
model-averaged per-case version is −0.013 (still p<0.001). State the unit. The headline "DC accepted-fact error
0% (proc) / 9.7% (fs)" should be split by ecosystem (F3).

**P6 — H14 and acquisition.** At max budget DC and DC_checklist make identical decisions in 400/400 pairs (loss UB
0), so H14 is purely a cost result (−0.35 units). DC_entropy is cheaper than DC (4.195 vs 5.335) at the same loss;
"EC² is the cheapest acquisition" is not supported — only "cheaper than the checklist". X3 withheld ≡ blind for
every DC variant.

**P7 — X5 scope.** No pypi/maven `upgrade_no_restart` episodes exist (builder requires a running component
version; `build_drift_v3.py:39-42`), so H13 is deb-ubuntu (25 episodes, −7.07) + vendor (15, −0.31). DCv21's
H13 gain is overwhelmingly a deb result. DC = S1′ on deb upgrade_no_restart (both 7.65).

**P8 — S3I vs S3 (X2I; not tabulated by analyze_v3.py).** Same two models, tracker + withheld: exact decision
agreement 79.8% (tracker 83.5%, withheld 76.1%); accuracy within 3 points (tracker S3 0.700/0.722 vs S3I
0.676/0.705; withheld 0.534/0.519 vs 0.568/0.570). Loss: tracker S3I−S3 = +0.05, withheld −0.38 (S3I less
over-confident). The qualitative conclusion "DC ≪ third-party agent loss" holds (DC 0.025 / 0.344 vs S3I
0.92–1.14 / 1.50–1.51). Add the X2I table to the analysis script or the report.

**P9 — DCv21 cost overhead (X2, pooled).** Tool cost +0.45 (blind/withheld, +8.6%) / +0.30 (tracker, +8.2%);
LLM calls 3.32→4.04 / 1.31→1.83; prompt tokens +35% / +143%; model seconds +37% / +72%. No accuracy gain on X2
(tracker loss 0.0335 vs DC 0.0309).

**P10 — Minor.** H12's p is encoded as 0/1 inside the Holm table (`p_holm` 0 for H12) — label it as a criterion,
not a p-value, in the paper table. `hypotheses_v3.csv` reports two-sided p for one-sided hypotheses (conservative).
H12 min-frac is seed-sensitive (0.97 reported vs 0.94 auditor seed, both ≥ 0.9; qwen3_4b is the binding model).
