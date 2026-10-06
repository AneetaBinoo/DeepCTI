# INQ Phase 1 — E0 retrospective question audit (branch `inq-phase-1-e0-audit`, 2026-10-06)

## Acceptance criteria (plan §11, Phase 1)
1. Implement `audit_e0.py` and its metrics, with tests on ≥ 30 hand-labelled episodes including drift cases.
   **Done.**
   - Code: `src/deepcti/inquiry/audit.py` (metrics), `scripts/inquiry/audit_e0.py` (driver) and
     `scripts/inquiry/analyze_e0.py`.
   - Tests: `tests/inquiry/test_e0_audit.py` holds 7 unit tests of the inference rules and 30 hand-labelled
     episodes.
   - The episodes span D1, D2 drift, D7 drift, D7 decoys, vendor, Maven, PyPI, the S3I baseline and the
     blind arm.
   - Labels: Claude labelled them by reading the replayed traces in a separate pass. They are **not a human
     annotation**; this is stated in the fixture.
   - Full suite: 225 passed, 3 xfailed.
2. E0 figures and tables regenerate from the logs. **Done.**
   - Commands: `audit_e0.py` (about 3 min on 32 workers), then `analyze_e0.py`, then `e0_glmm.R`.
   - Outputs: `results/inquiry/e0/`, and `paper2/figs/fig_e0_questions.{pdf,png}`.
3. The critical-omission detector flags the process-view omission in D2 upgrade-without-restart DC episodes,
   at about 100%. **Done:** DC 100% (540/540), and the closing question is always `service_status`.
   DCv21 is at 2.6%.

## What E0 found (test split, about 200k episodes after de-duplication, no new LLM calls)

1. **Omissions roughly double the miss rate.** For LLM agents on affected hosts:
   - DER with an omission is 44.7% [40.6, 48.7]; without one it is 28.6% [26.5, 30.7].
   - In the mixed model (model, dataset and wasted-question share as covariates; CVE random effect), the
     omission odds ratio is **2.55 [2.35, 2.78]**.
   - The **share of wasted questions does not predict misses**: OR 0.91 [0.80, 1.04].
2. **Questions are not the only bottleneck.** What preceded each of the 6,360 LLM-agent misses:
   - 39% followed a critical omission;
   - **54% happened although every decision-relevant fact was already established** at face value, so the
     agent asked the right questions and still decided wrong;
   - 7% concerned facts that no affordable catalog question could reveal.

   The split depends on the benchmark: on D7, which is more open, omissions are the largest cause (49%); on
   D1 they account for 35%.
3. **Most questions are spent badly.** Only 25–40% of LLM-agent questions add a decision-useful evidence
   component, against 38–83% for the controllers. Redundant repeats are 7–12% of ReAct questions.
4. **Model size reduces omissions but not waste.** For ReAct across models (descriptive Spearman ρ):
   - log size vs omission rate: −0.47 on D7 and −0.22 on D1;
   - log size vs wasted share: 0.08 on D7 and 0.04 on D1.

   Larger models ask the critical question more often, but not more efficiently.
5. **Drift is where omissions concentrate.** In upgrade-without-restart episodes:
   - ReAct omits a critical question in 54% (D1) and 49% (D7) of episodes; on clean D1 with a tracker the
     rate is 6%.
   - DC v2.0 omits the process view in 100% of D2 cases; DCv21 omits it in 0.6–2.6%.

**Implication for the plan (§14: "E0 should decide how strongly the introduction frames question choice as
the bottleneck").** The data support "question choice is *a* major and separable cause of agent misses" and
"it dominates where inquiry is open (D7, drift)". They do **not** support "*the* bottleneck": more than half
of all misses follow correct inquiry. Paper 2 should:
- frame inquiry as one of two failure channels, and keep commitment risk-controlled (LTT);
- report E0's three-way decomposition as a primary diagnostic.

## What was reused / what is new
- **Reused:**
  - Paper 1 run logs (read only);
  - `HostEnv` and the drift, decoy and history mechanics;
  - `parse_result`, `program_from_vex` and `CaseProgram.derive`;
  - `decision.decide_values` (gold paths);
  - `eval.metrics.episode_metrics`, labels and the `data` loaders;
  - the figure style from `scripts/paper/figures.py`;
  - the GLMM pattern from `scripts/stats/glmm.R`;
  - the R env `.renv`.
- **New:** `src/deepcti/inquiry/audit.py`, `scripts/inquiry/{audit_e0,analyze_e0}.py`,
  `scripts/inquiry/e0_glmm.R`, `tests/inquiry/` and `results/inquiry/e0/`.

## Deviations from the plan
1. **Measure (1), the model-based EC² value of each question, is not implemented.** The plan makes it
   secondary because of circularity, and the label-derived measures (2)–(4) answer RQ1 without it. It is
   deferred to Phase 2, where `inquiry/value.py` will provide it.
2. **Operational definitions** are specified in the module docstring. They involve choices the plan left open:
   - face-value inference, with a running instance assumed equal to disk unless observed;
   - range knowledge is required before versions decide anything;
   - stale history is not counted;
   - critical omissions use 1- and 2-question lookahead over a fixed per-case catalog;
   - attack blocks are excluded.
3. **Oracle rules corrected during hand labelling** (before any result was written up):
   - a scanner finding implies "not fixed";
   - a running version implies presence;
   - dpkg "not installed" is not evidence of absence for vendor or language components;
   - vendor presence is read exactly from the `/opt` listing, not with DeepCTI's substring heuristic;
   - a wrong-polarity observation is classed as *misleading*.
4. **De-duplication.** Blocks that re-run an identical episode spec (X2V, X6C, the budget-60 cells of X3/E3)
   are de-duplicated by key, keeping the original block: 250,241 → 238,192 episodes.
5. **Range knowledge.** The oracle accepts range knowledge from advisory text. A system that may not trust
   advisories, as DC does by design in the withheld arm, can therefore be "omitting" a question it could not
   act on. DC's withheld-arm omission rates (D7 22.5%) should be read that way.
6. **"Right for the wrong reason."** DC_nofresh is 97% accurate on D2 upgrade-without-restart while
   "omitting" the process view: it reads the stale pre-drift history, which E0 deliberately does not credit.

## Incident (logged)
The first full run used 110 workers, and each worker cached up to 4,096 host fixtures. Memory was exhausted
(503 GB), and the kernel OOM-killer took down the user session, including every tmux session and the user's
Gemma-4-31B server. Gemma was restarted on GPU 2:
- port 8103, `google/gemma-4-31B-it`, served as `gemma_4_31b`;
- the `gemma4` tool parser, with `VLLM_USE_FLASHINFER_SAMPLER=0`;
- the same 262,144-token context and memory footprint as before;
- tool calling verified.

The driver now runs 32 workers by default, recycles each worker after every task, keeps at most 16 cached
fixtures per worker, and has a watchdog that kills the pool below 64 GB of available memory. The full run then
peaked at about 10 GB.

## Next (Phase 2)
DIVE core on top of `acquisition/voi.py`:
- the ⊥ region and the expansion term;
- extract the LTT/Hoeffding–Bentkus code into `inquiry/stopping.py`;
- property tests T-A, T-C and T-D.

BrowseComp-Plus and its encoder need the download approval listed in `INQ_PHASE_0_REPORT.md`.
