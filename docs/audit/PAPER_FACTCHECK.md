# Fact-check of `paper/main.tex` (DeepCTI IEEE draft)

Date: 2026-10-05. Auditor: independent, read-only. Nothing outside this file was modified. `data/sealed/` was not read.
`\VF{...}` placeholders (H16–H18, episode count, panel completion) were skipped.

Sources of truth (abbreviations used below):
- **R2** `results/v2/REPORT.md`, **A2** `results/v2/test/ANALYSIS.md`, **T2/x.csv** `results/v2/test/tables/x.csv`
- **R3** `results/v3/REPORT_V3.md`, **A3** `results/v3/test/ANALYSIS_V3.md`, **ADD** `results/v3/test/ADDENDUM.md`,
  **PH** `results/v3/test/POSTHOC.md`, **T3/x.csv** `results/v3/test/tables/x.csv`
- **E11** `results/v3/e11_d7/E11_D7_REPORT.md`, **E11b** `results/v3/e11_d7b/E11_D7B_REPORT.md`
- **PR1–PR4** `prereg/PREREGISTRATION{,_V2,_V3,_V4}.md`, **DEV** `prereg/DEVIATIONS.md`
- **BR1/BR7** `data/d1/BUILD_REPORT.md`, `data/d7/BUILD_REPORT.md`; **DC1** `docs/DATA_CONTRACT.md`
- **V3A** `docs/audit/V3_AUDIT.md`; **VLOG** `docs/VERIFICATION_LOG.md`; **RWC** `docs/RELATED_WORK_CHECK.md`
- code: `src/deepcti/...`, `scripts/paper/...`

Line numbers (`Lnnn`) refer to `paper/main.tex`.

Verdicts: **OK**, **WRONG** (contradicted by a source), **IMPRECISE** (true in substance but misleading,
mis-scoped or mis-rounded), **UNSUPPORTED** (no generated source in the repo).

---

## 1. Non-OK items (summary, ordered by severity)

| # | Where | Claim | Verdict | Source | Suggested fix |
|---|---|---|---|---|---|
| 1 | L436 | "The result holds across models (Fig. scale)" | **WRONG** for D7 | T3/x2_by_model.csv rows withheld S3 gemma4_31b (loss 0.2908, DER 0.047) vs DC (0.3442); PH:146 vs PH:138; blind Gemma S3 0.365 vs DC 0.344 (PH:115/107) | "On D1 the gap holds for every model. On D7 the strongest ReAct agent (Gemma-31B) reaches a lower loss than DC without a feed (0.29 vs 0.34), although with DER 0.05 vs 0." The D7 panel of Fig. 2 already shows this dot below the DC line. |
| 2 | L512 | "with a tracker every strategy decides in about two calls" | **WRONG** | A2 "D4/F6" table: DC_random cost-to-decision 10.555; R2:70 lists only EC², entropy, checklist and LLM-chosen | "every strategy except random order (EC², entropy, checklist, LLM-chosen: 2.01–2.04 units; random: 10.6)" |
| 3 | L505–506 (Fig. drift caption) | v2.1 "removes the failure without cost on other drift kinds" | **WRONG** for the right (D7) panel | A3 X5 table L174–175: upgrade_restart DC loss 0.025 / acc 0.95 vs DCv21 0.128 / 0.744; also contradicts the text at L497–499 | "...without cost on the other D2 drift kinds (H8). On fresh D7 episodes it abstains more after restarts." |
| 4 | L441–442 | Inspect AI's ReAct agent "is no stronger" (tracker numbers only) | **WRONG** as worded (selective) | PH:38–45: withheld S3I 1.499/1.514 vs S3 1.630/2.142 (Mistral-24B/Qwen3-14B); R3:92 says "withheld, S3I is somewhat better" | "...With a tracker S3I's loss is similar (0.92/1.14 vs 0.84/1.13); without one it is somewhat lower (1.50/1.51 vs 1.63/2.14), so our S3 is not a stronger baseline than a standard harness." |
| 5 | L344–349 vs L46, L110, L629 | 10 models listed (6 + Granite-30B, Nemotron-49B, Mistral-Medium, GLM-4.5-Air) but "nine open models" elsewhere | **WRONG** (internal inconsistency) | config/models.yaml; DEV D19, D22, D24; no GLM runs exist under runs/test/E2 or runs/d7/test/X2 | Remove GLM from the list until its v4 runs exist, or write "nine open models (plus GLM-4.5-Air, descriptive only)" consistently in abstract, contributions and conclusion. |
| 6 | L48 (abstract) | DC lowers loss vs ReAct "by 1.59 (D1)" | **WRONG** (rounding) | T2/hypotheses.csv H1[withheld] = −1.58495 (rounds to 1.58; 1.59 is double rounding of −1.585) | "by 1.58 (D1)" |
| 7 | L412 (Table II, H10) | CI "[−0.27, −0.14]" | **WRONG** (rounding) | A3:8 / T3/hypotheses_v3.csv: [−0.26466, −0.14205] | "[−0.26, −0.14]" |
| 8 | L415 (Table II, H13) | CI "[−6.31, −3.02]" | **WRONG** (rounding) | A3:11: [−6.30489, −3.02142] | "[−6.30, −3.02]" |
| 9 | L403 (Table II, H2) | "−0.265" | **IMPRECISE** (rounding) | T2/hypotheses.csv H2 = −0.264463 | "−0.264" (or "−0.26") |
| 10 | L374 | "Every change after a tag is logged (24 entries)" | **WRONG** (count) | DEV has D1–D24 plus D8a = 25 entries (also 25 at tag prereg-v4) | "(25 entries, D1–D24 and D8a)" |
| 11 | L410 (Table II header) "prereg-v3: D7, 8 models" | covers H14 and H15 | **IMPRECISE** | H14 = X3 on Qwen3-14B and Mistral-24B only (PR3 §4; A3:10 n=400); H15 pools 7 generators (R3:39; E11:7) | Add a footnote: "H14: 2 models; H15: 7 generators (Mistral-Medium runs finished after the note sample was drawn)." |
| 12 | L48–49 (abstract), L459, L412 | "Verified LLM extraction lowers loss by 0.21 relative to an LLM-free controller on vendor software" | **IMPRECISE** (scope) | H10 is the vendor ecosystem in the **tracker arm** only (PR3 H10; A3:8, n=84). In withheld/blind DC = S1′ on vendor (0.351 both, A3:56/64) | "...on vendor software when a tracker supplies the affected ranges" |
| 13 | L461–463 | "This precision costs coverage on benign data: ... unverified extraction has lower loss (0.084 vs 0.146)" | **IMPRECISE** (cause misattributed) | V3A §0: the gap was largely a verifier defect (`X-Jenkins:` banners rejected; DC abstained on 105/126 Jenkins tracker records), fixed post hoc in DEV D21; with the fix DC 0.115 vs DC_noverify 0.086 (PH:17/19, 7 models) | Add: "Part of this gap was a verifier defect fixed post hoc (D21); with the fix the gap shrinks to 0.115 vs 0.086." |
| 14 | L493 | DC's 9.67 is "worse than ReAct's 3.98" | **IMPRECISE** | 3.98 is X4 (ADD:30), where all systems ran with spec v3, whose core prompt "adds rule 3 on running services for ALL systems" (PR2 §B). Under the original v1 prompt ReAct's loss on the same episodes was 7.56 (A2 E4, T2/e4_drift_by_kind.csv) | "...worse than ReAct (7.56 under the original prompt; 3.98 when the prompt tells every system to check running services)" |
| 15 | L498–499 | DCv21 "uses about 8% more tool cost" (in the drift paragraph) | **IMPRECISE** (scope) | 8% is the D7 main study X2 (A3:28–30 tracker 3.707→4.009; A3:38–40 withheld 5.203→5.652; R3:81). On the X5 drift episodes DCv21 costs +34% (upgrade+restart 2.806→3.766) and +79% (no restart 3.691→6.594) (A3:168–175) | "...and on the main D7 study it uses about 8% more tool cost (more on drift episodes)." |
| 16 | L384–386 (Fig. 1 caption) | "Without one, it keeps loss low by abstaining instead of guessing" | **IMPRECISE** | On D1 without a tracker DC never abstains (coverage 1.000) and equals Trivy alone (A2 E2 table rows withheld DC / S0_trivy; R2:56). Abstention explains only D7 | "Without one, it decides from trusted scanners (D1) or abstains instead of guessing (D7)..." |
| 17 | L437–438 | pass^5 "ranges from 0.98 to 0.08" | **IMPRECISE** (scope) | T2/e9_passk.csv covers the six v1-panel models only. E9 runs exist for Granite-30B and Nemotron-49B (runs/test/E9) but no pass^k table was generated; Nemotron's E9 accuracy is 0.228 (T2/panel_e9.csv), so its pass^5 is probably below 0.08 | "...(six-model panel)" or generate pass^k for the two added models |
| 18 | L267–268 | R is "the rate of released not affected/fixed decisions on affected hosts" | **IMPRECISE** | scripts/paper/analyze_v3.py `risk()` and analyze.py:509–511: R = P(gold affected ∧ released not_affected/fixed) **over all cases**, not conditional on affected hosts | "R is the share of all cases that are affected but released as not affected or fixed" |
| 19 | L274 | "P1 checks only arguments: scope and allow-listed paths" | **IMPRECISE** | pdp.py `render_cedar`: P1 checks `context.args_ok` only; `args_in_scope` (target is the case component) is added only for P2/P3. host.py:644–669 `args_ok` = well-formed arguments + allow-listed paths | "P1 checks only that arguments are well formed and paths allow-listed. P2/P3 also check that a disruptive call targets the case component and require..." |
| 20 | L281–283 | "Therefore no unwarranted disruptive action is permitted. ... at m ≥ k_f the attacker succeeds." | **IMPRECISE** (overclaim) | T4 guarantees only that no gating atom is falsely supported. `restart_service` is gated only on change atoms (pdp.py GATES), so a restart on an unaffected host with a genuine approval is permitted. At m = k the grid shows UDAR 0.017, not success (A2 (k,m) grid) | "...no disruptive action is permitted on the basis of a falsely supported gating atom. The bound is tight: at m ≥ k_f the guarantee no longer holds (observed UDAR 0.017 at m = k = 2, 0.33 for the change system)." |
| 21 | L290 | Validator rule "the stated status must equal the decision" | **IMPRECISE** | systems.py:604–634 `validate_note`: (i) at least one call id cited, (ii) cited ids exist, (iii) the decided status word occurs, and an `affected` note must not say "not affected", (iv) version tokens occur in the cited outputs. A check that the note asserts no other status exists only with `strict=True` (DCv21b, DEV D23). E11:13 says this gap let "FIXED" notes pass | "the note must state the decided status (and, in DCv21b, no other status) and cite at least one call" |
| 22 | L339 | "DCv21b DCv21 with a neutral synthesis prompt" | **IMPRECISE** | DEV D23: neutral prompt **plus** a validator check that rejects notes asserting another status | "...with a neutral synthesis prompt and a stricter status check" |
| 23 | L359–361, L568–569 | Notes judged "by three LLM judges from other model families" | **IMPRECISE** | E11 PROTOCOL rule (results/v3/e11/PROTOCOL.md:73) and E11:74: soft label over the *eligible* validated judges (Gemma-4-31B, Granite-4.1-30B, Nemotron-49B), excluding the generator's family. Gemma and Granite generators are judged by two judges | "by up to three validated LLM judges, never one from the generator's family" |
| 24 | L568–569 | "share of notes stating the controller's decision" | **IMPRECISE** | Consistency = share of eligible judges whose status read from the note alone equals the decision (E11:74), not a string check | "share of judge readings in which the note's asserted status equals the decision" |
| 25 | L372–374, L391 | "Primary tests are two-sided CVE-clustered sign-flip permutation tests ... with Holm correction within each family"; Table II caption "p Holm-adjusted within family" | **IMPRECISE** | H0 is a TOST; H8 and the H14 loss side use bootstrap bounds; H12 is a criterion; H15 is a CI non-inferiority rule; H16–H18 are CI rules "with no multiplicity adjustment" (PR4 §1, §3). Table II reports no p-values except H3 | "Superiority hypotheses use ... sign-flip tests with Holm within each family; equivalence and non-inferiority hypotheses use CI rules (prereg-v4: no multiplicity adjustment)." |
| 26 | L374–375 | "Separate audit passes re-derived every reported number from raw logs" | **UNSUPPORTED** (overclaim) | The audits re-derived the pre-registered hypotheses and the v2/v3 report numbers (RESULTS_AUDIT_R2, V3A §0, R2:7–8), not every number in this paper (e.g. the v4 results, the 34–140% token figures) | "Independent audits re-derived the pre-registered estimates and the v2/v3 report tables from raw logs." |
| 27 | L106–108, L302–304 | "real root file systems, package databases, jars, version files" / "All hosts are real root file systems with real ... jars" | **IMPRECISE** (overclaim) | DC1:8–16: D1 dpkg status files come from official images but are "extended with target-package stanzas"; the process table is simulated. BR7: D7 jars are "valid zip: MANIFEST + pom.properties + pom.xml, **no classes**", and dist-info METADATA is built from the PyPI API | "rootfs fixtures built from official base images, with real version metadata (dpkg stanzas, dist-info, metadata-only jars, vendor text files), simulated process tables, and real scanner reports" |
| 28 | L318 | "Maven jars (incl. shaded copies)" | **IMPRECISE** | BR7 variants: nested jars stored in Spring Boot fat jars (`BOOT-INF/lib`) and pip-vendored copies (V7). Nothing is shaded (relocated) | "(incl. jars nested in fat jars and pip-vendored copies)" |
| 29 | L176 | "The agent sees only the host name, release and CVE" | **IMPRECISE** | systems.py:82–95 `task_message` also names the vulnerable source package or component and its kind. D2 episodes add prior-assessment notes (PR1 §7 also lists the source package) | "...host name, release, CVE and the component named in the advisory" |
| 30 | L186–192 | independence groups: pkgdb (+scanners), fs, proc, change, feeds | **IMPRECISE** (incomplete) | host.py:74–105: also `langdb` (PyPI dist-info), `artifact` (Maven jars), `cmdb` and one group per advisory source. Scanners are put in `pkgdb` on D7 too, where they read dist-info/jars rather than the dpkg DB. **Validity note for H17:** with Maven scanners trusted (source_profiles_v3b.yaml), a scanner (`pkgdb`) and `lang_pkg_query` on the jar (`artifact`) count as two independent groups although both read the same jar metadata | List all groups; state the D7 grouping of scanners; discuss scanner/artifact independence if H17 is reported |
| 31 | L228–229 | "an N [on a consulted atom] yields under investigation (missing)" | **IMPRECISE** | decision.py:66–74: N on `fix_applied` does not block; the table falls through to `in_affected_range` | "an N on present, in_affected_range or a required config atom yields..." |
| 32 | L236–237 | "For service packages, acquisition must consult the process view before deciding fixed" | **IMPRECISE** | systems.py:484–488: v2.1 checks the process view once before **any** `fixed` decision **or** `not_affected/vulnerable_code_not_present` decision, for every component | Reword accordingly |
| 33 | L253–256 | verifier grammar: "changelog header line, a vendor version document, or a process line started from the package (an upstream banner cannot establish a distribution revision)"; "parses as a version of the ecosystem, compared with univers semantics" | **IMPRECISE** | verifier.py: for non-Debian ecosystems a `server banner:` line **is** accepted (the banner restriction applies to deb only). Parsing uses the Debian `Version` parser for all ecosystems, plus major.minor.patch for vendor. versions.py compares deb with python-debian (dpkg) and PyPI/Maven/vendor with `univers` | "...or a process start line (for distribution packages) or start/banner line (other ecosystems)...; it parses as a version (vendor: major.minor.patch); comparison uses dpkg semantics for Debian/Ubuntu and univers for PyPI, Maven and vendor" |
| 34 | L333 | "S1′: the DC controller without any LLM" | **IMPRECISE** | PR1 §2: S1′ = deterministic controller with **checklist** acquisition and P3; it has no extraction for changelogs or banners (PR1 §3c) | "S1′: DC's state and decision table with checklist acquisition and no LLM extraction" |
| 35 | L343 | "All models are served ... at temperature 0" | **IMPRECISE** | E9 (pass^k) uses T = 0.7 (PR1 §3b), as the paper itself says at L437 | "temperature 0 for main runs" |
| 36 | L611 | "there were no containers, and nothing was executed" | **IMPRECISE** | Trivy, Grype and OSV-Scanner were really run against every fixture (BR1:20, BR7). No *agent action* was executed | "...and no agent action was executed (scanners were run once per host, offline)" |
| 37 | L629–633 (conclusion) | "it avoids the missed vulnerabilities..."; "Each was diagnosed ... repaired, and each repair was tested on held-out, pre-registered data"; "an invalidated note validator" | **IMPRECISE / UNSUPPORTED (pending)** | DC DER is 0 in the main studies, but the restart-blind DC has DER 0.483 on D2 (ADD panel E4) and 0.497 on X5 upgrade-without-restart; DCv21 still has 0.041 (A3:168–169). The trust and note repairs are tested only by H16/H17, still `\VF`. The H15 defect was the synthesis **prompt**, not the validator (E11:13, DEV D23) | Scope "avoids missed vulnerabilities" to the main decision studies. Make the "each repair was tested" sentence conditional on H16/H17. Write "a defective synthesis prompt" |
| 38 | L243, L155–156 | EC² selects tests "with near-optimal cost" | **IMPRECISE** | VLOG:9–13 erratum: the original EC² constant rests on a flawed proof. The log recommends "O(log(1/p_min))-competitive" with the corrected constant from ACN22 | "with a logarithmic approximation guarantee" (cite the corrected bound) |
| 39 | L156–157 | LTT "turns any decision rule into one with finite-sample risk control" | **IMPRECISE** | LTT calibrates a parameter (threshold) of a family of rules and controls risk with probability ≥ 1−δ (VLOG §(d)) | "calibrates the threshold of a family of decision rules so that risk ≤ α holds with probability ≥ 1−δ" |
| 40 | L580–581 | decoy is "a 'see also' line in vendor release notes" | **IMPRECISE** (minor) | PR4 H18: the line is added to **every product document that states the true version** (not only release notes). The deb decoy goes into a changelog body line of vulnerable hosts | "...or a 'See also' line in each vendor document that states the version" |
| 41 | L458–459 | vendor versions exist "only in release notes, README files and banners" | **IMPRECISE** (minor) | BR7 table: also `ap_release.h` defines, Jenkins `config.xml`/`lastExecVersion`, Roundcube `iniset.php`/`CHANGELOG.md` | "only in text files (release notes, headers, config files) and banners" |
| 42 | L326 | tracker arm "exposes a distribution tracker/VEX feed" | **IMPRECISE** (minor) | PR3 §2: on D7 the tracker arm exposes structured tracker/VEX ranges (Ubuntu tracker, OSV ranges, vendor ranges) | "a tracker/VEX feed with structured affected ranges" |
| 43 | L214–215 | "only tool executions write to it" | **IMPRECISE** (minor) | belnap.py EvidenceLog docstring: "Only tool executions and mirror reads write here". D2 also injects carried-over history at t = −30 | "only tool executions (including the carried-over history of earlier ones) write to it" |

---

## 2. Bibliography (`paper/deepcti_references.bib`)

- All 47 `\cite` keys exist in the .bib. 14 entries are unused (cisa_kev, deepcti_repository, edge2024graphrag,
  hao2023rap, jayaram2026pat, jeong2024adaptiverag, karpukhin2020dense, khanmohammadi2023halfday, robertson2009bm25,
  sarmah2024hybridrag, trivedi2023ircot, wei2022cot, yao2023tot, yu2025cor). This is harmless with `\bibliography` (only cited entries print).
- **Checked against RWC/VLOG, OK in substance:** louck2026tmanm (RWC:23, 47–49; k independent trusted principals),
  pandey2026certified (RWC:24, 64), debenedetti2025camel, shi2025progent (venue unverified, RWC:89), wang2026agentspec
  (ICSE 2026 confirmed, RWC:99), golovin2010ec2, golovin2011adaptive, angelopoulos2021ltt (VLOG §(a),(b),(d)).
- **Metadata to fix or verify:**
  - `li2025drift`: RWC:106 gives venue NeurIPS 2025 and says the full author list is unverified. The bib has only the arXiv preprint and lists six authors. Verify the authors and add the venue.
  - `cutler2024cedar`: author field is "Cutler, Joseph W. and others", with no article number or pages. Give the full author list (PACMPL 8, OOPSLA1, 2024).
  - `inspectai2024`: author "UK AI Security Institute", year 2024. In 2024 the organization was the UK AI *Safety* Institute. Minor; acceptable if the current name is used on purpose.
  - `golovin2010ec2`: the claim it supports (L155, L243) needs the VLOG erratum wording (see item 38).
- **Not covered by RWC/VLOG (unverified in this repo; check title, authors and IDs before submission):**
  malamas2026trustops (SSRN 7346308; claim at L124–125), siu2026agentsecurity (arXiv 2603.19469; claim at L145),
  nie2026evotrustrag (2608.07933), ozer2025temporalconflict (2506.07270), alam2025athenabench (2511.01144),
  cheng2025cticonnect (2510.11974; "accepted to KDD 2026"), wu2025excytin (2507.14201; "accepted to ICML 2026"),
  bhagwatkar2025injectionbenchmarks (2510.05244; claim at L153 that it argues for reporting the benign error rate next to ASR).
  The older, well-known entries (ReAct, Toolformer, RAG, Self-RAG, CRAG, FreshLLMs, MemGPT, AgentDojo, InjecAgent,
  ToolEmu, R-Judge, CTIBench, NIST SPs, Saltzer–Schroeder, Holm, Belnap, CSAF 2.0, patch-management studies) look correct.
- **Citation use:** each citation supports a claim its work plausibly makes. Minor: Toolformer (L74) does not
  "interleave reasoning with tool calls". It is a tool-use paper, so "use tools" is the safer wording.
- **Omissions flagged by RWC:**
  - VEX-Bench (arXiv 2609.08040, RWC:364–380, verified). It is the closest benchmark (per-project VEX/exploitability), and the repo ran a transfer study on it (E7, R2:79–80: the evidence-state wrapper did **not** beat the plain harness; it abstained on 54–73%). The paper neither cites it nor reports E7. L123 "None asks whether a specific host is affected" is literally true for the four benchmarks cited, but it is incomplete without VEX-Bench.
  - Wu & Rus, "Safe to Stop?" (2609.09678, RWC:25: "C5 STRONG at method level"). Consider citing it in the LTT paragraph.

---

## 3. Claim-by-claim log of OK items (with sources)

### Abstract (L35–55)
- D1 906 hosts: OK (BR1:13, one host per case). D7 822 hosts spanning Ubuntu/PyPI/Maven/vendor: OK (BR7).
- Nine models from 4B to 128B: OK for the runs that exist (config/models.yaml sizes 4–128). See item 5 for the inconsistency.
- 0.88 (D7): OK (A3:7 −0.8829). "no dangerous errors": OK for DC in the main feed-less arms (A2 E2 DER 0; A3:18, 38 DER 0).
- LTT realised risk below 2%, coverage 0.31 → 0.50–0.91: OK (A3 LTT blind α=0.05: mean_risk 0.0137–0.0187; coverage 0.4995 Qwen3-4B to 0.9084 Mistral-Medium; base 0.3109).
- ReAct unauthorized disruptive actions 5–6%: OK (T2/e5_benign.csv and e5_attacked.csv: S3+P0 benign 5.2%/injected 5.5%,
  S3+P1 6.3%/6.0%, S3+P1+defence 5.7%/5.5%; S3+P3 0%).
- Restart-blind loss 9.67 → 0.42: OK (ADD:25–26).

### Introduction (L64–115)
- ReAct misses 34–49% of affected Debian hosts: OK (A2 E2 S3 DER 0.337 tracker, 0.485 withheld).
- Loss varies fifteenfold: OK (S3 tracker 0.177 Gemma to 2.636 Qwen3-4B = 14.9×; also holds for the 9-model panel, PH:62–70).
- 19 hypotheses (H0–H18), four tagged rounds: OK (`git tag`: prereg-v1…v4; PR1–PR4).
- Unauthorized actions without an attacker: OK (S3+P1 benign UDAR 6.3%, R2:64).

### Design (L161–295)
- Tool costs: read 1, scanner 5, patch 20, restart 15, budget 60: OK (host.py:31–46; PR1 §2). Not mentioned: approval 3, disable_feature 10.
- Tool tiers (read / medium-risk / disruptive): OK (pdp.py TOOL_TIERS).
- Trust rule Wilson-95 UB of FP and FN ≤ 0.10, n ≥ 20: OK (config/source_profiles*.yaml `rule`; PR1 §2).
- Freshness Δ = 12 world / 30 change: OK (mediator.py:20–28).
- Belnap value from κ±, untrusted observations are hints only: OK (belnap.py `compute_state`).
- Atoms (world, change, v2.1 running atoms) and the decision-table order: OK (decision.py `decide_values`, `combine_instances`), except item 31.
- Instance-aware rule ("in range if any instance; fixed only if all observed"): OK (decision.py:96–121).
- Verifier: verbatim span, names the component, first version token within 40 chars, changelog header line: OK (verifier.py), except item 33.
- LTT score = minimum support margin over the required atoms; fixed-sequence testing from strict to loose; Hoeffding–Bentkus; α = 0.05, δ = 0.1: OK (analyze_v3.py `ltt`, analyze.py `e6_ltt`).
- Gating atoms for a patch; P2 k=1; P3 k_world=2, k_change=1; linter requires pure conjunctions with val=T and kpos ≥ k: OK (pdp.py GATES, POLICIES, `lint_policy`).
- Validated synthesis: one repair, deterministic fallback; the note never changes the decision: OK (E11:95; systems.py `_fallback_note`).

### Evaluation design (L298–375)
- D1: Debian 11–13, 906/192/32, test 453 cases / 96 CVEs, 48% hold-out (46/96, published **on or after** 2026-05-01), six variants, Debian tracker labels: OK (BR1:8–13; DC1 Variants).
- D2: carried-over history at t = −30, five drift kinds, 121 episodes per model: OK (PR1 H2; T2/panel_e4.csv n=121).
- D3: injected text and forged groups m = 1..3, 64 episodes per model: OK (A2 E5 n=64).
- D7: Ubuntu 22.04/24.04, Tomcat/httpd/Jenkins/Roundcube/GitLab, 822 cases, 141 CVEs, test 414 / 70 CVEs, 43% hold-out, 21 config-gated (V5 test): OK (BR7). See items 27–28.
- X5 fresh drift episodes with consistent rewriting: OK (DEV D20).
- Arms (tracker / withheld / blind): OK (PR3 §2).
- Systems S0–S5, S3I, DC/DCv21/DCv21b, ablations: OK (PR1 §2; PR3 §2; DEV D15, D23). See items 22 and 34.
- Model names: OK (config/models.yaml).
- Loss matrix (miss 10, needless change 1, fixed↔not affected 0.2, abstain 0.5; invalid = abstain): OK (A2:3; PR1 §4).
- DER = misses among affected cases: OK (scripts/paper/summarize.py:69; metrics.py:73).
- Judge admission thresholds (recall ≥ 0.85, false alarm ≤ 0.10): OK (results/v3/e11/validated_judges.json; PROTOCOL.md:68).
- Pre-registration contents by round: OK (PR1 §5 H0–H6; PR2 H7–H8; PR3 H9–H15; PR4 H16–H18).

### Table II (L390–426)
- H0 +0.002 (TOST, equivalent): OK (A2:150). H1 −1.585 [−1.76, −1.42]: OK. H3 −0.03, p = 1: OK. H4 −0.099: OK.
- H5 vacuous: OK (R2:31). H6 exploratory: OK.
- H7 −9.25 [−9.76, −8.43]: OK (ADD:42). H8 0.000: OK (ADD:43).
- H9 −0.883 [−1.03, −0.74]: OK. H11 −0.027 [−0.04, −0.02]: OK. H12 ≥ 93% of splits: OK (min 0.93, Qwen3-4B).
- H14 −0.35 [−0.51, −0.21]: OK. H15 −0.018 [−0.05, +0.01], not held: OK (E11:7).
- See items 7–9 and 11 for H10, H13, H2 and the header.

### Results (L428–584)
- Tracker: DC zero loss on D1; DC 0.030 vs S1′ 0.071 vs S1 0.147 on D7: OK (A3:28, 34, 35).
- ReAct withheld loss 1.65 (D1) / 1.23 (D7); DER 0.49 / 0.30: OK (A2 E2; A3:47).
- DC DER 0 in every arm; D7 coverage 0.31: OK (A3:18, 28, 38).
- DC's D1 decisions are identical for every model: OK (T2/panel_e2.csv: identical DC rows for all 9 models). This holds on D1 only; on the D7 tracker arm DC's loss varies by model, 0.021–0.044 (T3/x2_by_model.csv).
- Mistral-Medium gaps 0.41 / 0.79 / 0.18 / 0.30: OK (PH:90–91, 151–152).
- S3I agreement 80.6% (n = 1,635); tracker losses 0.92/1.14 vs 0.84/1.13: OK (PH:38–47). See item 4.
- On D1 and on the structured D7 ecosystems DC = S1′: OK (R2:54; A3:57–63; R3:72).
- H10 0.205; H11 2.7 pp; verification rejects 9% of file proposals and 17% of process proposals; banner wrong facts 4.1% → 0%: OK (A3:70–73: accepted 0.9117 / 0.8254; noverify proc error 0.0409).
- Fig. 4 caption (all arms, 8 models): OK (T3/x2_extraction.csv: 8 models, no arm filter).
- LTT: 200 re-splits (40/60), coverage 0.50–0.91, mean risk 1.4–1.9%, ≥ 93% of splits within α: OK (A3 LTT blind). "Hints point to a decision for most abstentions": supported only indirectly, since α = 0.10 coverage is 0.82–0.97 (A3:187–208). No D7 table of naive hint coverage was generated.
- Drift: H2; 9.67 / acc 0; 0.42 / acc 0.93; H8; D7 DCv21 0.45 vs DC 5.04 vs ReAct 2.03; rollbacks ReAct 4.08 (D7) / 6.87 (D2), DC near zero; DCv21 accuracy after restart 0.74 vs 0.95: OK (ADD:19–30; A3:162–175). See items 3, 14 and 15.
- Fig. 3 caption, 9 models on D2 and 8 on D7: OK (ADD n=270 = 30 × 9; A3 X5 n=320 = 40 × 8).
- Acquisition H14 −0.35 at identical loss; entropy 4.20 vs EC² 5.34; ReAct at 3–5× the loss: OK (A3:81–150: DC 0.322 vs S3 1.10–1.71). Fig. 5 models (Qwen3-14B, Mistral-24B): OK (runs/d7/test/X3).
- Authorization: S3+P3 false-block rate 0.33 over 6 warranted episodes; m=1 world → 0; m=2 → 0.017; change system 0.33 (6 episodes); P3k3 0; ASR − benign −0.005: OK (T2/e5_benign.csv; A2 (k,m) grid; A2 D7/F9). Fig. 6 (3 models): OK (figures.py V1_PANEL filter). See item 20.
- Notes: H15 −0.018 [−0.047, +0.010]; the "FIXED" prompt; 40.5%; DCv21b +0.036 [+0.011, +0.062]; consistency 0.978 / 0.960 / 0.752; 90.9 / 3.4 / 5.8%: OK (E11:7, 13; E11b:9, 13, 15).
- H16 sample: 504 triples, disjoint from the H15 sample, all 8 generators: OK (PR4 H16).
- Trust: 42 dev CVEs, no D7 scanner trusted; dev+calib 71 CVEs trusts Ubuntu and Maven scanners, not PyPI (FN 10.5%) or vendor (FN 1.0): OK (BR7 split dev 42 / calib 29; config/source_profiles_v3.yaml and _v3b.yaml). "Abstained where scanners were right": OK (A3:61–63 withheld S0 < DC on deb/maven/pypi; R3:75).
- Decoy pilot (unread documents are never observed): OK (PR4:41–42).

### Discussion and conclusion (L587–633)
- Coverage 0.31 before LTT: OK. Token overhead +34% to +140%: OK as reported (R3:81, "recomputed from raw logs"; no generated table).
- Nemotron: 25.5% of D1 ReAct episodes made no tool call; generic tool template: OK (R3:91; config/models.yaml:69).
- Labels without human audit; variants never shown to systems; no practitioner study: OK (PR1 §7).

---

## 4. Notes for the authors (not errors in the text)
- E7 (VEX-Bench transfer, negative) and the D1 blind-arm E10 are not mentioned. A paper that claims to report failures should at least mention E7 in a sentence or a footnote.
- On D1 without a tracker, DC equals Trivy alone (loss 0.067 both). The paper's framing ("keeps loss low by abstaining") should credit the trusted scanners there (item 16).
- If H17 is reported, address the scanner/artifact independence issue (item 30) when describing k = 2 corroboration on Maven.

## 5. Resolution (added 2026-10-06)

Every item in §1 was fixed in `paper/main.tex` (items 22 and 41–43 in a second pass after
`docs/audit/DOCS_FACTCHECK.md`), along with the bibliography gaps flagged in §2:
- Gemma exception stated; H10 scope, drift-cost scope and S3I scope corrected.
- Model count is now ten, and the deviation count was updated.
- Rounding fixed.
- Method descriptions aligned with the code: LTT risk definition, P1 vs P2/P3 scope check, the blocking-N
  rule, the process-view rule, verifier semantics, S1′ acquisition, component name, groups.
- Authorization property worded as the guarantee's boundary.
- Fixture description corrected.
- Judge eligibility and the statistics paragraph corrected.
- Conclusion scoped.
- Bibliography: VEX-Bench (with the negative E7 transfer result) and Wu & Rus are now cited.

Still open:
- Metadata for `li2025drift` and `cutler2024cedar` is unchanged; Cedar is cited as "Cutler et al.".
- The eight references not covered by the repo's verification docs still need checking before submission.

The v4 results (H16–H18, GLM, Mistral-Medium) were added afterwards, with numbers taken from `results/v4/`.
They were not re-checked by this independent pass.
