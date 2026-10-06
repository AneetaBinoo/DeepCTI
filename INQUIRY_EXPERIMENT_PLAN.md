<!-- Saved verbatim from the plan supplied on 2026-10-06. Corrections found in Phase 0 are listed in the
     errata block below; the plan text after it is unchanged. -->

> **Errata (Phase 0, 2026-10-06; details in INQ_PHASE_0_REPORT.md):**
> 1. `scripts/fig_*.py` / `softstyle.py` do not exist in this repo; figure style comes from `scripts/paper/figures.py`.
> 2. `results/v3/test/tables/x4_by_kind.csv` does not exist; the D2 per-kind numbers are in
>    `results/v3/test/ADDENDUM.md` (X4 table), and the D7 drift numbers are in `results/v3/test/tables/x5_drift.csv`.
> 3. Paper 1 has no numbered propositions ("Prop. 2/3/4"). The authorization property is stated informally
>    (paper §III-G); the EC² constant is in `docs/VERIFICATION_LOG.md`; the LTT guarantee is cited from Angelopoulos et al.
> 4. Hardware: the node has **five** H200 NVL GPUs. "Server B" (Gemma-4-31B) runs on GPU 2 of this node. "Server A"
>    (Llama-3.1-8B) is a remote endpoint with a 16k context whose hardware is not visible to us (`docs/inquiry/HARDWARE.md`).
> 5. The VEX-Bench checkout is at `data/external/vex-bench` (untracked); `results/v2/e7/` holds the E7 results only.
> 6. The LTT/Hoeffding–Bentkus code lives as nested functions inside `scripts/paper/analyze_v3.py::ltt` and
>    `scripts/paper/analyze.py`. It must be extracted into a library before reuse (Phase 2).
> 7. `runs/` holds ~213k non-attack test episodes and ~37k calibration episodes (`docs/inquiry/RUNS_INVENTORY.md`).
>    The E0 audit excludes the attack blocks (E5, KM).

# Paper 2 — Experiment Plan: Decision-Aware Inquiry for Deep-Research Agents

> **Audience:** Claude Code (VS Code) working in the `DeepCTI` repository (branch `v2-experiment`, commit `314ad48` or later), plus the human authors.
> **Goal:** a NeurIPS / ICLR / ACL-main paper on *how an agent should decide which question to ask next* during iterative, open-world research, built so that **most of the existing DeepCTI code, data and results are reused** rather than re-run.
> **Relationship to Paper 1:** Paper 1 (`paper/main.tex`, "Evidence-State Control for LLM Agents in Threat Mitigation") is about *decision integrity and authorization*. Paper 2 is about *inquiry*: choosing questions while the hypothesis space is still growing. Different claims, shared infrastructure.

---

## 0. How to use this plan with Claude Code

Suggested opening prompt:

```
Read INQUIRY_EXPERIMENT_PLAN.md fully. Work phase by phase (Section 11). For each phase:
(1) restate its acceptance criteria, (2) work on a branch named inq-phase-N-<slug>,
(3) REUSE existing modules and run logs listed in Section 2 before writing anything new,
(4) add tests and run them, (5) write INQ_PHASE_N_REPORT.md listing what was reused,
what was new, and every deviation from this plan. Never compute metrics on a sealed
split before prereg-q1 is tagged. Ask before downloading > 5 GB or pulling a model.
```

### Guardrails (non-negotiable)

1. **Reuse first.** Before implementing anything, check Section 2. If an existing module, dataset, run log or table covers the need, import or extend it. Record reuse in the phase report.
2. **Never re-run what exists.** Paper 1 run logs under `runs/` (local, not committed) and tables under `results/v2..v4/` are inputs. Re-scoring them with new metrics is allowed and encouraged; regenerating them is not.
3. **No dual-submission overlap.** Paper 1 results may appear in Paper 2 only (a) as cited background ("as reported in [Paper 1]", cited anonymously in the third person), or (b) as inputs to a *new* analysis (the retrospective audit, E0) whose outputs are new. No Paper 1 table or figure is reproduced as a Paper 2 contribution.
4. **Fresh sealed test data.** D1 and D7 test labels were unsealed for Paper 1, so they become *development* data for Paper 2. Paper 2's confirmatory CTI results use a newly built, sealed split (D8, Section 4.2).
5. **No fabricated numbers.** Every number in the paper comes from a script in `scripts/inquiry/paper/` that reads run logs.
6. **Verify volatile facts.** Before use, check benchmark versions, licences, model IDs and theorem constants against their sources. Log the checks in `docs/VERIFICATION_LOG.md` (append a "Paper 2" section).

---

## 1. Thesis, research questions, contributions

### 1.1 The problem: open-world inquiry

An agent receives a task whose answer or decision depends on facts it must discover. At each step it chooses a **question**: a search query, tool call, file read, or clarification to a user. The process stops when it commits to an answer or abstains. Paper 2's claim is that question choice should be a **decision-aware value-of-information problem solved over an expanding hypothesis frontier, with fallible sources and calibrated stopping**.

The four conditions that separate this from prior work:

| Condition | Prior Bayesian question-asking (BED-LLM, Active Task Disambiguation, CA-BED, ASIG) | Deep-research agents (ReAct, Search-R1, HypoSearch, Re²Search) | Paper 2 |
|---|---|---|---|
| G1 Hypothesis space | given, closed | implicit in the transcript | explicit frontier that grows from evidence |
| G2 Answer source | truthful oracle | web or corpus, reliability ignored | sources with estimated reliability; conflicts kept |
| G3 Question value | expected information gain about hypotheses | heuristic, or an RL reward needing gold answers | value relative to the *decision*, computed at inference time |
| G4 Stopping | fixed budget or heuristic | model decides, or budget | Learn-then-Test risk bound on the final answer |

**Planning-based reasoning (Tree of Thoughts; Reasoning via Planning, RAP)** is the closest family on the method side, and DIVE must be positioned against it explicitly. RAP repurposes the LLM as both a world model and a reasoning agent, and uses Monte Carlo Tree Search (MCTS) to find high-reward reasoning paths. DIVE also uses the LLM to simulate outcomes. The difference is *what is optimized and what is kept*:
- RAP maximizes a self-evaluated reward along simulated paths; DIVE scores the *real* next question by its expected reduction in decision-region uncertainty.
- RAP keeps no explicit belief over candidate answers and no source reliability; DIVE does.
- RAP has no calibrated stopping rule; DIVE uses LTT.

E2 and E4 test whether these differences matter, comparing at matched numbers of questions and at matched total compute.

### 1.2 Research questions

- **RQ1 (Diagnosis).** How much of LLM-agent failure is explained by asking the wrong questions: decision-irrelevant queries, and decision-critical queries never asked?
- **RQ2 (Method).** Does decision-aware question selection over an expanding frontier reach correct answers with fewer questions than ReAct-family agents and closed-world BED methods?
- **RQ3 (Which assumption matters).** When the closed-world assumptions (G1–G4) are restored one at a time, which relaxation accounts for the gains?
- **RQ4 (Stopping).** Can an agent stop with a finite-sample bound on the probability of a wrong answer, and what coverage does that cost?

### 1.3 Contributions (target)

1. **Formulation.** Open-world inquiry as sequential, cost-sensitive decision-region identification over an expanding hypothesis frontier with fallible sources.
2. **Method: DIVE** (Decision-aware Inquiry with Verified Evidence, working name). It has four parts:
   - the LLM proposes hypotheses and candidate questions;
   - questions are chosen by decision-aware value of information per unit cost, including the value of expanding the frontier;
   - evidence enters a provenance-tracked four-valued state through a verifier (reused from DeepCTI);
   - stopping is risk-controlled (LTT, reused).
3. **Theory.** A cost bound relative to an agent that knows the true hypothesis set, with an additive term for expansion (target statement in Section 3.5). Paper 1's no-action soundness carries over to answers.
4. **Retrospective audit.** A question-level analysis of more than 190k existing agent episodes, showing which question failures predict which answer failures. This uses no new LLM calls (E0).
5. **Evaluation:**
   - BrowseComp-Plus (fixed 100K-document corpus, per-query evidence labels);
   - a fresh CTI inquiry benchmark (D8) built with the existing DeepCTI builders;
   - a closed-world sanity check (20 Questions);
   - transfer to VEX-Bench (reusing the Paper 1 E7 harness).

**Working title:** *Asking the Right Question: Decision-Aware Inquiry over an Expanding Hypothesis Frontier.*

---

## 2. Reuse map (read before writing any code)

### 2.1 Code reused directly

| Existing module | Role in Paper 2 | Change needed |
|---|---|---|
| `src/deepcti/core/belnap.py` (Observation, EvidenceLog, `compute_state`) | Evidence state over *claims* instead of VEX atoms | Generalize atom keys to claim IDs; no logic change |
| `src/deepcti/core/decision.py` | VEX decision rule for the CTI track | None for CTI; QA track uses an answer-equivalence rule (new, small) |
| `src/deepcti/acquisition/voi.py` (`Belief`, `ec2_score`, `entropy_score`, `optimal_expected_cost`, `policy_expected_cost`) | Core of question scoring, DP optimum for regret | Hypotheses become frontier objects; add a residual-mass term (Section 3.3) |
| `src/deepcti/extraction/verifier.py`, `parsers.py` | Span verification of facts extracted from tool outputs and retrieved documents | Add a generic "claim in document" verifier for the QA track |
| `src/deepcti/agents/systems.py` (`Controller`, `run_react`, `run_direct`, `_llm_choose`) | Baselines S2 and S3 and the LLM-chooses ablation; Controller loop becomes DIVE's skeleton | Refactor the Controller loop into `inquiry/loop.py`, keeping the old entry points intact |
| `src/deepcti/agents/mediator.py`, `src/deepcti/env/host.py` | CTI environment and fixtures | Add an open, read-only query interface (Section 4.2) |
| `src/deepcti/inspect_harness/` (S3I) | Third-party ReAct baseline | Point it at the new tool sets |
| `src/deepcti/vexbench/` (E7 tools, verifier, harness) | VEX-Bench transfer experiment | Swap the fixed decision rule for DIVE |
| `src/deepcti/judge/` (E11 validated judges) | LLM-judged answer equivalence where exact match fails | Reuse the validated judges and the error-injection protocol |
| `src/deepcti/llm/client.py`, `config/models.yaml`, `config/chat_templates/`, `scripts/serve/` | vLLM serving and model panel | Reuse unchanged |
| `scripts/paper/analyze_v3.py::ltt` and the Hoeffding–Bentkus code | Risk-controlled stopping | Generalize the score to answer margins |
| `scripts/stats/` (`glmm.R`, `export_long.py`), clustered bootstrap and sign-flip code in `scripts/paper/analyze*.py` | Statistics | Cluster by query or CVE |
| `scripts/data/*` (D1/D7 builders, labellers, `estimate_trust_v3.py`) | Build the fresh D8 split and source-reliability profiles | Run with new CVE selection; no code change expected |
| `scripts/paper/figures.py` (style, palettes) and `scripts/fig_*.py` (soft design system) | Paper 2 figures | Reuse styles |

### 2.2 Data reused

| Existing data | Role |
|---|---|
| `data/d1`, `data/d7` (fixtures, mirrors, labels incl. test) | **Development** set for the CTI track (labels already unsealed) |
| `data/d2` (drift), X5 drift episodes | Development for "unknown unknowns": restart blindness is a hypothesis-space failure (Section 5, E3) |
| `data/d6` (3,000 advisory→status tuples) | Fit the outcome-likelihood model for advisory text; calibration data for LTT on the advisory channel |
| `config/source_profiles*.yaml` (Wilson-bounded FP/FN per source and ecosystem) | Source-reliability priors (G2) |
| `config/priors*.yaml` | Hypothesis priors for the CTI track (note deviation D27) |
| `data/mirrors/*` (NVD, OSV, Debian/Ubuntu trackers, vendor files) | Corpus for open advisory search in the CTI track |
| VEX-Bench checkout (`results/v2/e7/`, commit `80cddea`) | Transfer experiment |

### 2.3 Results reused (as cited background or as inputs to new analyses)

| Paper 1 result | How Paper 2 uses it |
|---|---|
| ReAct misses 34–49% of affected Debian hosts; loss varies ~15× across models (`results/v2/test/tables/e2_by_system.csv`, `panel_*`) | Motivation (cited). E0 re-scores the same logs at question level. |
| Restart blindness: DC loss 9.67 → DCv21 0.42 once the process view is consulted (`x4_by_kind.csv`, `x5_drift.csv`) | Central motivating example: a missing hypothesis means a missing question. E3 tests whether frontier expansion *discovers* the running-instance hypothesis without the v2.1 hand fix. |
| Acquisition on D7 withheld (`results/v3/test/tables/x3_acquisition.csv`): EC² 5.34, checklist 5.69, entropy 4.20, LLM-chosen 5.69, random 6.22 cost units at equal loss; ReAct 3.3–4.1× the loss | Cited baseline. It shows closed-world VOI is cheap but undifferentiated when the hypothesis space is tiny (≤7). This motivates the larger, open spaces in Paper 2. |
| D1 greedy EC² equals the DP optimum (`results/v2/test/tables/e3_regret_model.csv`, ratio 1.00) | Sanity anchor for the regret code; reused as a unit test. |
| H3 failed (with a feed, every strategy decides in about 2 calls) | Scope argument: inquiry matters only when the task is under-determined. Paper 2 benchmarks are chosen accordingly. |
| LTT release: coverage 0.31 → 0.50–0.91 at risk < 2% (`results/v3/test/tables/ltt_blind.csv`) | Cited. E5 extends LTT from VEX releases to answer stopping. |
| VEX-Bench transfer: wrapper did not beat the plain harness and abstained on 54–73% (`results/v2/e7/`) | Motivation for G1: a fixed atom set and decision rule are too rigid for open tasks. E6 re-runs with DIVE. |
| E11 judge validation (recall ≥ 0.85, false alarms ≤ 0.10; `results/v3/e11/validated_judges.json`) | Reuse the validated judges; no re-validation unless a judge is used on a new task type. |

### 2.4 Run logs reused without re-execution

`runs/test/E2`, `runs/test/E9`, `runs/d7/test/X2`, `X3`, `X5`, `X2V`, `X6`, `X6C`, `X7`, plus the corresponding `dev` and `calib` runs (all local). Each record contains the tool-call trace (`env.calls`, `trace[-40:]`), the controller state where applicable, and labels. These feed the retrospective audit E0. **Check first that `runs/` is present and complete** (counts per block in `results/*/` manifests). If a block is missing, report it and do not regenerate it.

---

## 3. Formal model and method (DIVE)

All new code lives in `src/deepcti/inquiry/`. It imports `core.belnap`, `acquisition.voi` and `extraction.verifier` rather than copying them.

### 3.1 Task, answers, decisions

- A task $x$ has an unknown answer $y^\star$ in a possibly unbounded space $\mathcal{Y}$.
- A decision map $D:\mathcal{Y}\to\mathcal{D}$ groups answers that lead to the same decision:
  - **QA track:** answer-equivalence classes, using exact match or the validated judge.
  - **CTI track:** the VEX status, using `core/decision.py`.
- The loss is $L(d,d^\star)$:
  - **CTI:** reuse Paper 1's matrix (miss 10, needless change 1, fixed↔not affected 0.2, abstain 0.5).
  - **QA:** 0/1 loss with an abstention cost $c_a$, swept in {0.25, 0.5}.

### 3.2 Inquiry state

At step $t$ the agent holds $(\sigma_t, F_t, b_t)$:

- **Evidence state $\sigma_t$.** Paper 1's Belnap state, keyed by *claims* (atomic, checkable propositions) rather than VEX atoms. Claims enter only through tool outputs, or through LLM extractions admitted by the verifier. Untrusted text is kept as hints.
- **Frontier $F_t=\{h_1,\dots,h_n\}\cup\{\bot\}$.** Each $h$ is a candidate answer together with the claims $C(h)$ it requires. $\bot$ ("none of these") carries the residual mass $\varepsilon_t=b_t(\bot)$.
- **Belief $b_t$.** A posterior over $F_t$. Likelihoods come from source reliability: a source $s$ reports a true claim as true with probability $1-\mathrm{fn}_s$ and a false claim as true with probability $\mathrm{fp}_s$, taken from `config/source_profiles*.yaml` for CTI and estimated on the dev split for QA. Hypotheses contradicted by a trusted value $\mathsf{F}$ on a required claim are removed exactly, which is the noiseless EC² case.

### 3.3 Question value

The candidate pool $Q_t$ holds $k$ (default 8) LLM-proposed questions plus catalog tools (CTI). Each question has a cost $c(q)$ (CTI: Paper 1 costs; QA: 1 per search, 0.5 per document read). Outcome models come from LLM simulation, as in BED-LLM: "if $h$ were true, what would $q$ most likely return, and which claims would that support or refute?". Simulations are cached per (task, $h$, $q$).

Score:

$$
V(q)=\frac{\mathbb{E}_{o\sim p(\cdot\mid b_t,q)}\bigl[W(b_t)-W(b_t\mid o)\bigr]+\beta\,P_{\text{exp}}(q)\,\varepsilon_t}{c(q)},
\qquad
W(b)=\sum_{d<d'} b(\mathcal{R}_d)\,b(\mathcal{R}_{d'}),
$$

- $W$ is the EC² edge weight between decision regions. $\bot$ is its own region, so questions that could settle "the answer is outside the frontier" earn value.
- $P_{\text{exp}}(q)$ is the LLM-estimated probability that $q$'s result names an answer outside $F_t$.
- $\beta$ is tuned on dev only.
- **Reuse:** `voi._edge_weight` and `voi.ec2_score` already compute $W$ and its expected reduction. The only additions are the $\bot$ region and the expansion term.

**Frontier expansion.** After each observation, if $\varepsilon_t>\bar\varepsilon$ or every $h\in F_t$ has a required claim valued $\mathsf{F}$/$\mathsf{B}$, the LLM proposes up to $m$ new hypotheses conditioned on $\sigma_t$. They receive prior mass from $\varepsilon_t$. Every expansion is logged so its precision can be measured (did it contain $y^\star$?).

### 3.4 Stopping

The score is the posterior margin of the top decision region. Like Paper 1, it uses only trusted support when committing a no-action status on the CTI track. The threshold $\lambda$ is chosen with Learn-then-Test over $R(\lambda)=\Pr[\text{stop}\wedge D(\hat y)\neq D(y^\star)]$, reusing `analyze_v3.py::ltt` (fixed-sequence testing, Hoeffding–Bentkus). If the budget runs out first, the agent abstains.

### 3.5 Theory targets

| ID | Statement (target) | Status / reuse |
|---|---|---|
| T-A (closed-world reduction) | With a frozen frontier and noiseless sources, DIVE equals greedy EC² and inherits the bound $4(1+2\ln(1/p_{\min}))\cdot\mathrm{OPT}$ (Al-Thani, Cui, Nagarajan) | Restates Paper 1 Prop. 3. Add a property test: on toy problems DIVE with $\beta=0$ matches `voi.select_test` exactly |
| T-B (expansion) | If each expansion call includes the true hypothesis with probability $\ge\rho$, then $\mathbb{E}[\text{cost}]\le\kappa\cdot\mathrm{OPT}_{\text{closed}}+c_{\exp}/\rho$ | **New. Must be proved before submission.** If the proof fails, state it as a conjecture and report the measured $\rho$ and empirical regret |
| T-C (answer soundness) | If a committed answer requires trusted support for every claim in $C(h)$, a wrong committed answer implies a false trusted claim | Same proof as Paper 1 Prop. 2. Property test over random claim sets |
| T-D (stopping) | $\Pr[R(\hat\lambda)\le\alpha]\ge 1-\delta$ under exchangeability | Paper 1 Prop. 4 with a new score. Reuse the simulation test from Paper 1 Phase 6 |

Claude Code writes the property tests for T-A, T-C and T-D in Phase 2. The authors own the T-B proof. Claude Code can assist with a draft in `docs/inquiry/THEORY.md`, flagged for human review.

---

## 4. Benchmarks

### 4.1 BrowseComp-Plus (main open-world QA track)

- **Contents:** 830 BrowseComp queries over a fixed, human-verified corpus of 100,195 documents, with pre-built BM25 and Qwen3-Embedding indexes (texttron/BrowseComp-Plus, ACL 2026). Each query has evidence documents (about 6.1 on average) and gold documents (about 2.9).
- **Why it fits:** the evidence labels allow *question-level* scoring (did this query retrieve needed evidence?), not just answer accuracy.
- **Tools:** `search(query, k=5)` over the provided index, and `read(docid, span)`.
- **Retriever:** Qwen3-Embedding-8B for the main runs. A BM25 sensitivity run on the dev subset only.
- **Split:** dev = 200 queries (stratified by number of evidence documents), test = the remaining 630. The test query-ID list is hashed into `prereg/PREREG_Q1.md` before any test run. Labels are public, so "sealed" here means *pre-registered and untouched by tuning*. Say so in the paper.
- **Contamination:** report a closed-book CoT baseline (no tools) as the memorization floor, per model.

### 4.2 D8: fresh CTI inquiry benchmark (sealed)

- **Build:** with the existing D7 builders (`scripts/data/`) on new CVEs published after 2026-08-01, so they postdate both Paper 1 data and the model panel's cut-offs. Target 70–90 CVEs and about 400 test cases across the deb-ubuntu, PyPI, Maven and vendor ecosystems.
- **Hard variants, chosen because the right question is not in a default checklist:**
  - upgrade without restart (running instance differs);
  - pip-vendored copies (V7);
  - jars nested in fat jars;
  - config-gated cases (V5);
  - backports (V4);
  - decoy version mentions in documents that are actually read (the H18 limitation fixed: the decoy sits next to the true version line).
- **Open query interface** (new, read-only, mediated by the existing PDP): `grep(pattern, glob)`, `list_dir(path)`, `read_file(path, lines)`, `pkg_query(name)`, `process_list()`, `run_scanner(name)`, `search_advisories(text)` over `data/mirrors`, and `ask_owner(question)`.
  - `ask_owner` is a simulated clarification channel answering from the case's change record. It is fallible, with a configured error rate, so it is a G2 source rather than an oracle.
- **Arms:** withheld (no structured feed) as primary; blind (no scanners) as secondary. The tracker arm is not used: Paper 1 showed inquiry is trivial there.
- **Labels:** the builders already compute every atom. Map atoms to claims so each question's realized information is exact.
- **Seal:** labels go to `data/sealed/d8_test_labels.jsonl`, with the hash in the pre-registration.

D1, D7, D2 and X5 serve as the CTI development sets (already unsealed).

### 4.3 Closed-world sanity: 20 Questions

- Recreate the BED-LLM setting: entity sets plus a simulated answerer LLM that is truthful and knows the target.
- Check whether BED-LLM's data and code are public. If not, rebuild from a public entity list and record the deviation.
- **Purpose:** show that when G1–G4 are removed, DIVE reduces to BED-style EIG and matches it. A loss here would undermine every other claim.

### 4.4 VEX-Bench transfer (reuse the E7 harness)

Same 62 tasks, same models (Gemma-4-31B, Qwen3-14B), same budgets as Paper 1 E7. Replace the fixed rule R1–R7 with DIVE's frontier over justification categories. The question is whether the 54–73% abstention falls without losing status F1.

### 4.5 Optional: SeekerGym

If its code and data are public, use it to compare DIVE's residual-mass $\varepsilon_t$ with SeekerGym's completeness estimates, as a calibration check. SeekerGym already uses conformal calibration for stopping, so DIVE's stopping contribution is framed as *decision-risk* control (Section 3.4), not completeness.

---

## 5. Systems and baselines

All systems share the model, retriever or tool set, maximum questions $Q_{\max}$, context limit and answer format. Prompt cores live in `prompts/inquiry/` and are frozen at pre-registration.

| ID | System | Source |
|---|---|---|
| B0 | CoT, closed-book (no tools) | new, trivial |
| B1 | Direct prompting with top-k retrieval of the task text (RAG-once) | reuse `run_direct` pattern |
| B2 | ReAct | **reuse `run_react`** |
| B3 | Inspect AI ReAct (third-party harness) | **reuse `inspect_harness`** |
| B4 | Self-Ask | new prompt module |
| B5 | IRCoT (retrieve per reasoning step) | new |
| B6 | **RAP-agent** (Reasoning via Planning, adapted to tool use; Section 5.1) | **LLM Reasoners library** (`maitrix-org/llm-reasoners`): implement `WorldModel`, `SearchConfig`; reuse its MCTS |
| B6b | Plan-and-Solve / decompose-then-search (optional, dev only unless it beats B2) | new prompt module |
| B7 | Re²Search-style: draft answer, query the first unverified claim | new prompt module |
| B8 | HypoSearch-style: hypothesis branches searched in parallel, then aggregated | new, matched total budget |
| B9 | BED-LLM-style: frontier fixed at t=0, EIG over hypotheses, oracle likelihood | new; this is DIVE with A1+A2+A3 (Section 6, E4) |
| B10 | Search-R1 public checkpoint (reference only, if licence permits) | external |
| DIVE | full method | new, on reused cores |

Paper 1's DC controller appears in the CTI track as **B11**: the closed atom set with EC² over the fixed catalog. That is reused code and reused configuration, run on the new D8.

### 5.1 RAP adaptation (B6)

RAP was designed for closed reasoning problems (Blocksworld, GSM8K, logical inference), where the world model is the only environment. For tool-using research it is adapted as a planner wrapped around real actions:

- **State $s_t$:** the task, the transcript of executed questions and their real results, and the current draft answer.
- **Actions:** the same LLM-proposed candidate questions DIVE uses ($k=8$, shared generator and prompt). This isolates *selection* from *proposal*.
- **World model:** the LLM predicts the result of a question and the next draft answer: $P(s_{t+1}\mid s_t,a_t)$. Same model as the agent.
- **Reward:** RAP's self-evaluation ("is this step useful / correct?") plus the model's confidence in the draft answer, as in the original paper.
- **Search:** MCTS with $n=8$ iterations and depth $d=3$ simulated steps per real step (tune $n\in\{4,8\}$ on dev). Execute the first action of the best path for real, observe, and re-plan.
- **Termination:** RAP commits when the draft answer's self-evaluated confidence exceeds a dev-tuned threshold, or the budget is spent.
- **RAP-Aggregation:** included as an option, since the original paper uses it for final answers.

**Fairness:**
- RAP is reported at **matched executed questions** ($Q_{\max}$), as for every system.
- It is also reported at **matched total LLM tokens**, because MCTS spends many simulated tokens. For the compute-matched view, ReAct and DIVE receive extra question budget until their mean total tokens equal RAP's.
- DIVE's own simulation tokens are counted in the same way.


---

## 6. Experiments

Each experiment lists what it reuses. Run everything on dev first; run test once, after `prereg-q1`.

### E0 — Retrospective question audit (RQ1; **no new LLM calls**)

- **Inputs:** every Paper 1 episode in `runs/`, covering S2, S3, S4, S5, S3I, DC, DCv21 and the ablations across D1, D7, D2 and X5 (more than 190k test episodes plus dev and calib).
- **Per-question measures**, for each tool call $q_t$ in each episode:
  1. *Model-based value:* the EC² value of $q_t$ under the case's fitted hypothesis model, recomputed with `voi.Belief` and the frozen priors (Paper 1 code).
  2. *Realized information (model-free):* whether the call's output changed the label-aware status of any decision-relevant atom, using ground-truth atoms from the builders. This guards against circularity in (1).
  3. *Redundancy:* the same tool and arguments as an earlier call, or an output identical to one already logged (content hash).
  4. *Critical omission:* a question was feasible within the remaining budget, had positive realized information for the ground truth, and was **never asked** before the final decision. The canonical case: the process view in upgrade-without-restart episodes.
- **Analyses:**
  - Share of questions with zero value, per system and model.
  - Mixed model: $\text{dangerous error}\sim\text{critical omission}+\text{wasted-question share}+\text{model}+(1\mid\text{CVE})$, reusing `scripts/stats/glmm.R`.
  - Fraction of ReAct misses preceded by a critical omission.
  - Whether model size reduces omissions or only wasted questions.
- **Outputs:**
  - Figure "where agents' questions go" (stacked: decision-relevant, redundant, irrelevant, plus omission markers).
  - Table of omission vs error rates.
- **Why it matters:** it turns Paper 1's logs into new evidence for the diagnosis claim of Paper 2 at near-zero compute cost.
- **Circularity note:** report (2) and (4) as primary, since they are label-derived. Report (1) as secondary, since it depends on DeepCTI's own model.

### E1 — Closed-world sanity (20 Questions)

- **Systems:** DIVE with $\beta=0$, a frozen frontier and truthful likelihood, vs B9 (BED-LLM-style) and B2 (ReAct-as-questioner).
- **Panel:** Qwen3-14B, Gemma-4-31B, Mistral-Medium-3.5-128B.
- **Metrics:** success rate within $N$ questions; questions to success.
- **Expectation:** DIVE ≈ B9. Pre-register this as an *equivalence* hypothesis (±5 pp).

### E2 — BrowseComp-Plus main study (RQ2)

- **Systems:** B0–B9 and DIVE.
- **Models (fixed by the available hardware, Section 9):** Llama-3.1-8B (existing server A), Qwen3-14B (H200), Gemma-4-31B (existing server B) and Mistral-Medium-3.5-128B (2×H200). These four span 8B–128B and are all in Paper 1's panel, so chat templates and tool parsers are reused from `config/models.yaml`.
- **Budgets:** every system at $Q_{\max}=20$. Only ReAct, RAP-agent, B9 and DIVE also run at $Q_{\max}\in\{10,40\}$ for the Pareto curves.
- **Metrics:** accuracy; accuracy vs questions asked (Pareto); evidence recall@questions; index of the first question that retrieves evidence; question precision (share of searches returning ≥1 evidence document); tokens; wall-clock.
- **Primary hypothesis:** DIVE has higher accuracy than B2 (ReAct) at matched $Q_{\max}=20$, pooled over models.

### E3 — D8 CTI inquiry (RQ2, sealed)

- **Systems:** DIVE, B2, B3, B7, B8, B9, and B11 (Paper 1 DC, reused).
- **Metrics:** decision loss, DER, coverage, questions to decision, critical omissions (E0 measure).
- **Unknown-unknowns sub-study, the key link to Paper 1:**
  - Run DIVE with the **v2.0 hypothesis space**, which has no running-instance hypotheses, on X5 drift episodes (dev) and D8 drift cases (test).
  - Measure how often frontier expansion proposes a "running build differs from disk" hypothesis, and the resulting loss.
  - Paper 1's hand-built fix (DCv21: 0.42 on D2, 0.45 on X5) is the cited reference, not a re-run.
  - **Pre-registered hypothesis:** DIVE without hand-coded instance atoms has non-inferior loss to that reference (margin +0.25) on D8 drift cases.

### E4 — Assumption ablations (RQ3; the novelty test against BED-LLM / CA-BED)

Run with Qwen3-14B and Gemma-4-31B on the BrowseComp-Plus dev-300 subset (100 dev queries plus 200 test-disjoint queries drawn before prereg, logged) and on D8 test. Each ablation restores one closed-world assumption:

| Ablation | Restored assumption |
|---|---|
| A1 frozen frontier (no expansion) | G1 |
| A2 truthful-oracle likelihood (ignore source reliability) | G2 |
| A3 entropy over hypotheses instead of decision-region weight | G3 (reuse `voi.entropy_score`) |
| A4 transcript-only belief (no evidence state; the LLM judges hypotheses from context) | evidence discipline |
| A5 LLM self-stop instead of LTT | G4 |
| A6 no verifier (accept LLM-extracted claims directly) | reuse Paper 1 DC_noverify |
| A1+A2+A3 | = B9 (BED-LLM-style) |

**Design note from Paper 1 (cited):** on D7, entropy-greedy was cheaper than EC² when the hypothesis space had at most 7 states. A3 must therefore be tested where decision-irrelevant uncertainty exists, meaning many hypotheses share one answer or status. Construct a *distractor-rich* stratum: BrowseComp-Plus queries whose frontier contains several aliases or near-duplicate entities, and D8 cases where many versions map to the same status. Pre-register the stratum before test.

### E5 — Risk-controlled stopping (RQ4)

- **Data:** BrowseComp-Plus and D8.
- **Stopping rules compared:** LTT on answer margin (reuse); LLM self-stop; fixed budget; completeness-conformal stopping in the style of SeekerGym (reimplemented; note in the paper that its target is completeness, not decision risk).
- **Procedure:** 200 query- or CVE-level re-splits (40% calibrate / 60% evaluate), as in Paper 1.
- **Metrics:** realized risk vs $\alpha\in\{0.05, 0.10\}$; coverage; questions saved by stopping early.

### E6 — VEX-Bench transfer (reuse E7)

- **Setup:** same tasks, seeds 0–2, temperature 0.7, budgets, and VEX-Bench's metric code.
- **Comparisons:** DIVE vs the open harness (A) and vs Paper 1's evidence-state wrapper (B). For A and B, reuse the logged runs in `results/v2/e7/` as references where seeds and budgets match exactly; do not re-run them.
- **Hypothesis (secondary):** DIVE lowers abstention below B's 54–73% while keeping status F1 non-inferior to A (margin −0.05).

### E7 — Scaling, reliability, cost

- pass$^k$ at $T{=}0.7$ on a 150-query BrowseComp-Plus subset for B2, B6 and DIVE, all four models (reuse the Paper 1 E9 code path).
- Token, LLM-simulation and wall-clock costs. DIVE's simulation calls are counted, so overhead is reported honestly.

---

## 7. Metrics (formal)

- **Accuracy / decision loss:** as in Section 3.1. Abstentions count with cost $c_a$.
- **DER (CTI):** $\Pr[\hat d\in\{\textit{not affected},\textit{fixed}\}\mid d^\star=\textit{affected}]$ (reused definition).
- **Questions to decision $Q_{\text{dec}}$:** number of questions before commitment. Report the Pareto front of loss vs $Q$.
- **Question precision:**
  - BrowseComp-Plus: share of `search` calls returning at least one labelled evidence document.
  - CTI: share of questions with positive realized information (E0 measure 2).
- **Critical omission rate:** E0 measure 4, per episode.
- **Frontier recall:** share of episodes where $y^\star\in F_t$ at stopping. Also the step at which $y^\star$ first entered $F_t$.
- **Residual calibration:** Brier score of $\varepsilon_t$ against the indicator $\mathbb{1}[y^\star\notin F_t]$.
- **Expansion precision $\hat\rho$:** share of expansion calls that add $y^\star$. This is an empirical input to T-B.
- **Risk and coverage under stopping:** realized $R$, coverage, AURC.
- **Cost:** tokens (prompt, completion, simulation), questions, wall-clock. Report the mean and the median *conditional on at least one call*, per Paper 1's audit fix.

---

## 8. Statistical analysis plan

- **Units and clustering:** BrowseComp-Plus is clustered by query; CTI by CVE. Reuse the clustered bootstrap (10,000 resamples) and paired sign-flip code from `scripts/paper/analyze*.py`, and `scripts/stats/glmm.R` for mixed models.
- **Pre-registration:** commit `prereg/PREREG_Q1.md` and tag `prereg-q1` before any test run. It contains:
  - hypotheses H-Q1 to H-Q8;
  - primary metrics, budgets and $\beta$;
  - prompt hashes;
  - model revisions;
  - the BrowseComp-Plus test ID hash and the D8 label hash.
- **Primary family (Holm-corrected):**
  - H-Q1 (E2): DIVE accuracy > ReAct at $Q_{\max}=20$.
  - H-Q2 (E3): DIVE loss < ReAct on D8 withheld.
  - H-Q3 (E4): DIVE accuracy > A1 (frozen frontier), the core novelty claim.
  - H-Q4 (E5): LTT realized risk ≤ α in ≥ 90% of re-splits.
- **Secondary:**
  - H-Q5: E1 equivalence with BED-style.
  - H-Q6: E3 drift non-inferiority vs DCv21 reference.
  - H-Q7: E4 A2 and A3 effects on their pre-registered strata.
  - H-Q8: E6 VEX-Bench abstention and F1.
  - H-Q9: E2 DIVE accuracy ≥ RAP-agent at matched executed questions *and* at matched total tokens (two separate tests).
- **Power for H-Q1:** paired accuracy, discordance ≈ 0.20, target difference 0.05, α = 0.05 two-sided, power 0.8:
  $n\approx\bigl(1.96\sqrt{0.20}+0.84\sqrt{0.20-0.05^2}\bigr)^2/0.05^2\approx 626$.
  The 630-query test split is therefore just adequate *per model*. Pooling over four models adds precision but must be analysed with query-clustered resampling. Re-estimate discordance on dev and update in the pre-registration.
- **Deviations:** log to `prereg/DEVIATIONS_Q.md` in Paper 1's format.

---

## 9. Compute plan (hardware-specific; re-measure in Phase 5)

### 9.1 Available hardware and allocation

| Device | Model(s) served | Role | Notes |
|---|---|---|---|
| Server A (existing) | Llama-3.1-8B-Instruct | agent model | Paper 1 deviation D8a: at $T{=}0.7$ Llama emitted parallel tool calls that the server rejected. Force one tool call per turn (`parallel_tool_calls=false` plus a template check) before any run |
| Server B (existing) | Gemma-4-31B-it | agent model; also a validated judge (Paper 1 E11) | Never judges Gemma-generated episodes (cross-family rule). Run judging *after* agent runs, so the two jobs don't compete |
| H200 #0 + #1 (TP=2) | Mistral-Medium-3.5-128B, BF16 | agent model (largest) | ~256 GB weights across 282 GB leaves room for KV cache at 64k context with prefix caching. Reuse the Paper 1 TP=2 launcher (`scripts/serve/`, deviation D19) |
| H200 #2 | Qwen3-14B (BF16, `gpu-memory-utilization≈0.55`) + Qwen3-Embedding-8B query encoder (≈0.15) | agent model + BrowseComp-Plus dense retrieval | The corpus index is pre-built (HF), so only queries are encoded online. BM25 runs on CPU |
| H200 #3 | Granite-4.1-30B (validated judge, Paper 1 E11) + a second Qwen3-14B replica when no judging is scheduled | answer-equivalence judging; throughput burst for Qwen3-14B runs | Granite judges Gemma-generated episodes; Gemma judges Granite-free episodes; Llama and Mistral episodes can use either |

Rules:
- **Same model for agent and simulation.** DIVE's simulations, RAP's world model and every system's question proposals use the agent's own model, never a stronger helper. That keeps comparisons fair and costs comparable.
- **Record server specs in Phase 0.** GPU type, vLLM version, max context and tool parser for servers A and B go into `docs/inquiry/HARDWARE.md`; throughput estimates depend on them.
- **One model per job queue.** Reuse Paper 1's scheduler pattern (`scripts/run/` phase launchers) so each served model has its own queue, and run all systems for that model before moving on (maximizes prefix-cache hits).

### 9.2 Episode counts

| Block | Episodes (approx.) | Notes |
|---|---|---|
| E0 audit | 0 LLM calls | CPU only |
| E1 20Q | 3 models × 3 systems × 100 games × 3 seeds ≈ 2,700 | short |
| E2 BrowseComp-Plus | 4 models × 12 systems × 630 at $Q_{\max}=20$ ≈ 30,000, plus 4 models × 4 systems × 630 × 2 extra budgets ≈ 20,000 | dominant cost; RAP is the most expensive system per episode |
| E3 D8 | 4 models × 8 systems × ~400 × 2 arms ≈ 26,000 | short CTI episodes (5–15 calls) |
| E4 ablations | 2 models × 6 ablations × (300 + 400) ≈ 8,400 | Qwen3-14B, Gemma-4-31B |
| E5 stopping | 0 extra | reuses logged scores |
| E6 VEX-Bench | 2 models × 62 × 3 seeds ≈ 370 | Paper 1 references reused |
| E7 pass$^k$ | 4 models × 3 systems × 150 × 5 ≈ 9,000 | |

### 9.3 Cost model and schedule

Per BrowseComp-Plus episode at $Q_{\max}=20$ (to be re-measured on 50 dev episodes per model in Phase 5):

| System | Output tokens / episode (est.) | Main driver |
|---|---|---|
| ReAct, Self-Ask, IRCoT, Re²Search | 4k–8k | reasoning + queries |
| HypoSearch-style | 10k–15k | parallel branches |
| DIVE | 15k–25k | per step: $k=8$ batched simulation calls (one call per question predicting outcomes for all frontier hypotheses, $|F_t|\le 12$) |
| RAP-agent | 40k–80k | MCTS: $n=8$ iterations × depth 3 per real step |

With prefix caching, decode throughput dominates. Rough wall-clock for the E2 main grid (630 test queries, all systems, $Q_{\max}=20$):
- Qwen3-14B on one H200 (two when H200 #3 is free): about 1 day.
- Mistral-Medium-128B on two H200s: about 3–4 days.
- Gemma-4-31B and Llama-3.1-8B on servers A and B: depends on their GPUs; measure in Phase 5.

The four models run **in parallel**, one per device group, so the E2 main grid takes roughly the slowest model's time (expected: Mistral-Medium, 3–4 days). The full test phase (E1–E4, E6, E7) is estimated at **10–14 days** of wall-clock.

**If Phase 5 measurements exceed this, cut in this order:**
1. RAP-agent at $Q_{\max}=40$ (keep 10 and 20);
2. E7 for Llama-3.1-8B;
3. B4/B5 (Self-Ask, IRCoT) on Mistral-Medium only;
4. RAP-agent on Llama-3.1-8B (report 3 models);
5. the BM25 sensitivity run.

Never cut DIVE, ReAct, B9 or the E4 ablations; they carry the primary hypotheses.

## 10. Repository additions

```
src/deepcti/inquiry/
  frontier.py      hypotheses, residual mass, expansion trigger and logging
  questions.py     LLM candidate generation (k proposals), dedup, cost tagging
  likelihood.py    LLM-simulated outcome models + source-reliability correction (cached)
  value.py         decision-aware VOI (wraps acquisition/voi.py; adds ⊥ region, expansion term)
  stopping.py      LTT margin scorer (wraps analyze_v3.ltt logic as a library)
  loop.py          DIVE controller (refactored from agents/systems.Controller.run)
src/deepcti/env/
  qa_corpus.py     BrowseComp-Plus search/read tools over the provided indexes
  open_cti.py      open read-only query interface over D1/D7/D8 fixtures (PDP-mediated)
  owner_sim.py     fallible clarification channel for CTI
src/deepcti/baselines/
  selfask.py ircot.py plan_solve.py re2search.py hyposearch.py bedllm.py
scripts/inquiry/
  audit_e0.py run_e1.py run_e2.py run_e3.py run_e4.py run_e6.py run_e7.py
  analyze_q.py  paper/figures_q.py  paper/tables_q.py
prompts/inquiry/  core_spec.md and per-system prompts (frozen at prereg-q1)
prereg/PREREG_Q1.md  prereg/DEVIATIONS_Q.md
tests/inquiry/    property tests T-A, T-C, T-D; frontier/value unit tests; E0 metric tests
```

---

## 11. Phases and acceptance criteria

**Phase 0 — Inventory and reuse audit (week 1)**
- Record hardware for servers A and B and the H200 node in `docs/inquiry/HARDWARE.md` (GPU, vLLM version, context, tool parser).
- Install and pin LLM Reasoners (`maitrix-org/llm-reasoners`); check its licence and that its MCTS runs with an OpenAI-compatible vLLM endpoint.
- Confirm that `runs/` is complete against the manifests.
- List the reusable modules and their tests; run the existing test suite (green).
- Verify the external benchmarks (BrowseComp-Plus licence and indexes, BED-LLM code, SeekerGym availability, Search-R1 checkpoint licence).
- *Accept when:* `docs/inquiry/REUSE_INVENTORY.md` maps every Section 2 item to a path and a status.

**Phase 1 — E0 retrospective audit (weeks 1–2; no GPU)**
- Implement `audit_e0.py` and its metrics, with tests on hand-labelled episodes (at least 30, including drift cases).
- *Accept when:* E0 figures and tables regenerate from logs, and the critical-omission detector flags the process-view omission in D2 upgrade-without-restart DC episodes (sanity: should be ~100%).

**Phase 2 — DIVE core (weeks 2–4)**
- Implement `inquiry/` on top of the reused cores, plus property tests for T-A, T-C and T-D.
- *Accept when:* with $\beta=0$, a frozen frontier and noiseless likelihoods, DIVE's choices equal `voi.select_test` on the D1 dev hypothesis spaces (T-A test), and the D1 regret test still gives ratio 1.00.

**Phase 3 — Environments (weeks 3–5)**
- BrowseComp-Plus tools; open CTI interface; owner simulator.
- Build D8 with the existing builders and seal it.
- *Accept when:* tools pass integration tests; D8's build report matches D7's format; seal hashes are recorded.

**Phase 4 — Baselines (weeks 4–5)**
- B0–B10 with a shared prompt core and matched budgets; reuse `run_react` and S3I.
- RAP-agent (B6) through LLM Reasoners `WorldModel`/`SearchConfig` classes, sharing DIVE's question generator (Section 5.1).
- Fix Llama-3.1-8B single-tool-call behaviour (Paper 1 D8a) and verify on 20 episodes.
- *Accept when:* every system completes 20 dev queries per track on two models.

**Phase 5 — Dev pilots and tuning (weeks 5–6)**
- Tune $\beta$, $k$, $\bar\varepsilon$ and $m$ on dev only.
- Measure throughput and $\hat\rho$; estimate discordance for the power calculation.
- *Accept when:* tuning logs are committed and parameters are frozen.

**Phase 6 — Pre-registration (week 6)**
- *Accept when:* `prereg-q1` is tagged with every item in Section 8.

**Phase 7 — Test runs (weeks 7–9)**
- E1–E7 on test; E5 from logged scores.
- *Accept when:* every pre-registered cell is complete or its failure documented; nightly integrity checks pass (counts, parse failures, duplicates).

**Phase 8 — Analysis, audit, paper artifacts (weeks 9–10)**
- Independent audit pass, as in Paper 1 (a separate Claude Code session re-derives pre-registered estimates from raw logs).
- Generate figures and tables; write the anonymized artifact README.
- *Accept when:* a clean checkout reproduces E0 fully and one main table on a subset.

---

## 12. Paper mapping

| Section | Content | Source |
|---|---|---|
| 1 Introduction | Question choice is the bottleneck. Cite deep-research failure analyses and Paper 1's ReAct misses; E0 headline number | E0 + citations |
| 2 Related work | Reasoning and planning (CoT, ToT, RAP, LLM Reasoners); BED for LLMs (BED-LLM, Active Task Disambiguation, CA-BED, ASIG, UoT, CaRT); deep-research agents (ReAct, Search-R1, HypoSearch, Re²Search, Question's Gambit); RL information-gain rewards (InForage, IG-Search, TIPS); completeness (SeekerGym); Paper 1 | lit check in Phase 0 |
| 3 Problem | Open-world inquiry; conditions G1–G4 | Section 1.1 |
| 4 Method | DIVE; theory T-A to T-D | Section 3 |
| 5 Diagnosis | E0 retrospective audit | new analysis of existing logs |
| 6 Experiments | E1–E4, E6, E7 | new runs |
| 7 Stopping | E5 | new + reused LTT |
| 8 Discussion | When inquiry does not matter (Paper 1 H3, cited); limits of LLM-simulated likelihoods | |

**New figures:** question-budget breakdown (E0); accuracy vs questions Pareto (E2); frontier growth trace on one drift case (E3); assumption-ablation bars (E4); risk–coverage (E5). Use the soft design system in `scripts/fig_*.py` / `softstyle.py`, with orthogonal connectors for any diagram.

---

## 13. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Open models score low on BrowseComp-Plus (Search-R1 reaches 3.86% with BM25), compressing differences | Use the Qwen3-Embedding-8B retriever and the largest open models; report evidence recall and question precision, which separate systems even at low accuracy; add a dev "easier" stratum (queries with ≤ 4 evidence documents) as secondary |
| Novelty vs BED-LLM / CA-BED | E4 is designed to show which relaxation matters; E1 shows equivalence when assumptions hold; state the differences explicitly |
| LLM-simulated likelihoods are costly or miscalibrated | Cache; cap $k$ and $|F_t|$; report simulation cost; A2 isolates the reliability correction |
| E0 circularity (DeepCTI model scoring other systems' questions) | Primary E0 measures are label-derived (realized information, omissions) |
| Dual-submission or self-plagiarism concerns | Guardrail 3; Paper 2 cites Paper 1 and reports no Paper 1 table as its own result |
| T-B proof fails | Present it as a conjecture with measured $\hat\rho$ and empirical regret; the paper still stands on E0, E2–E4 |
| D8 build yields too few hard cases | Oversample the V4/V5/V7 and drift variants; stratify the analysis by variant |
| RAP-agent's MCTS cost dominates the budget | Cap $n$ and depth; report compute-matched results; cut per Section 9.3 if needed |
| Llama-3.1-8B's tool-call template breaks at $T{=}0.7$ (Paper 1 D8a) | Force single tool calls; verify in Phase 4; report any residual failures as invalid output (abstention) |
| Gemma server shared between agent runs and judging | Schedule judging after agent runs; use Granite on H200 #3 for overflow |
| Public BrowseComp-Plus labels allow accidental tuning on test | Hash the test IDs at prereg; tuning code reads only the dev ID list (enforced by an assert) |

---

## 14. Timeline (indicative, one author + Claude Code)

| Weeks | Work |
|---|---|
| 1 | Phase 0 inventory; start Phase 1 (E0) |
| 2 | Finish E0; start the DIVE core |
| 3–4 | DIVE core + environments; build D8 |
| 5 | Baselines; dev pilots |
| 6 | Tuning frozen; `prereg-q1` |
| 7–9 | Test runs |
| 9–10 | Audit, figures, writing |

E0 can be written up as soon as Phase 1 finishes. Its result should decide how strongly the introduction frames "question choice as the bottleneck" before any new GPU spend.