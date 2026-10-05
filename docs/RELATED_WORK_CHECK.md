# Related-work check: DeepCTI v2 contributions (C1–C5)

Date: 2026-10-05. The search was a focused WebSearch/WebFetch pass over 2025–2026 work.

How the items were checked:
- Every arXiv ID below was resolved through the arXiv API or the abs page, so it exists with the title and authors shown.
- Summaries come from the abstract and/or HTML full text. Where only an abstract or search snippet was seen, the entry says so.
- Venue claims not confirmed on a proceedings page are marked *unverified*.
- C4 was not part of this check's brief, so verdicts cover C1, C2, C3 and C5 only.

Contributions checked:
- **C1:** a four-valued (Belnap–Dunn) or provenance-tracked evidence state used to control an LLM agent.
- **C2:** tool-call authorization conditioned on evidence, provenance or belief, with k-of-n / quorum independent-source guarantees against evidence poisoning and prompt injection.
- **C3:** value-of-information / EC² / decision-region-determination tool selection for LLM or security agents.
- **C5:** conformal risk control / Learn-then-Test for abstention in LLM agents or vulnerability triage.

---

## ⚠ STRONG overlaps (read first)

| Paper | Contribution | Why it matters |
|---|---|---|
| **TMA-NM.** Louck, arXiv **2606.24322** (23 Jun 2026) | **C2 STRONG** | A consequential tool action on untrusted-origin data runs only if **≥k independent trusted principals** corroborate it, with Sybil and echo resistance. This is model-checked in TLA+ against memory poisoning. |
| **Certified Multi-Source Integrity for Structured Agent Actions.** Pandey, Jain, Chen, Maple, Panchev, arXiv **2609.34245** (28 Sep 2026) | **C2 STRONG**; C1 partial | Field-level admission of agent actions under a corruption budget of k control domains. Independence is counted by **minimum hitting set**, so laundered or republished copies do not count. The certifier executes or abstains/escalates. The evaluation includes **npm supply-chain provenance**, which is close to our domain. |
| **Safe to Stop?** Wu & Rus, arXiv **2609.09678** (9 Sep 2026) | **C5 STRONG at method level**; different domain | Uses LTT-style exact tests of selective error, with a pre-registered candidate family, to decide when a **sequential evidence-gathering LLM diagnosis agent** may stop or answer. Its results are clinical, not security, and labelled exploratory. |

Two more are near-strong and must be cited with explicit positioning:
- **HESP**, arXiv 2609.33446 (C3). A security alert-triage LLM agent that ranks probes by EIG/cost and uses a controller stop. It does not use EC² or decision regions.
- **Li**, arXiv 2608.12444 (C5). CRC with abstention/deferral for LLM security triage, with a non-degeneracy certificate. It is a single-shot classifier, not an agent.

**Novel as far as this search found:**
- **No paper uses a Belnap–Dunn four-valued state (T/F/Both/Neither) to gate an agent's tool calls or actions.** The closest is Allen et al., NeSy 2025, which builds four-valued truth values with an LLM for reasoning, not for authorization.
- **No paper applies EC², HEC, DRD or DiRECt to LLM agents.**
- **No conformal or LTT work targets vulnerability/VEX triage** specifically.

**Suggested re-positioning of C2.** "Quorum or provenance-conditioned tool authorization" is **not novel by itself** in 2026. Claim instead:
1. a *four-valued* evidence state, in which conflict (Both) and absence (Neither) are separate states with separate action policies, used as the authorization signal;
2. its compilation to Cedar;
3. the composition of that state with DRD tool selection and LTT abstention, instantiated for VEX triage.

Compare directly against 2609.34245 and 2606.24322.

---

## C1 / C2: Evidence state and evidence-conditioned authorization

### TMA-NM: origin-bound authority with k-independent corroboration ⚠ STRONG (C2)
- **Citation:** Y. Louck (Ariel University). "Securing LLM-Agent Long-Term Memory Against Poisoning: Non-Malleable, Origin-Bound Authority with Machine-Checked Guarantees." arXiv:2606.24322, 2026. Preprint.
- **URL:** https://arxiv.org/abs/2606.24322
- **Summary:**
  - Memory items get their authority to act from their origin, bound when the item is written, and never from their content or lineage.
  - The paper shows that content- and lineage-based signals can be laundered through three channels: agent summarization, trusted-tool echo, and manufactured corroboration.
  - A consequential action whose security-relevant value comes from an untrusted item is allowed only if ≥2 (generally ≥k) *independent trusted principals* corroborate it, or a fresh user authorization covers it. "Independent" means distinct identities and trust domains with no shared upstream.
  - TLA+/TLC machine-checked results: a separation theorem (any content-dependent gate can be manipulated) and non-malleability of the k-principal gate.
  - Evaluated on 12 business domains, 8 LLMs, and Mem0/Qdrant.
- **Overlap:** C1 none–partial (binary trusted/untrusted origin). **C2 STRONG.**
- **Differentiation:**
  - It corroborates only from trusted principals, with binary labels and no conflict state.
  - DeepCTI's gate runs over a four-valued evidence lattice: contradiction (Both) is first-class and routed differently from absence (Neither).
  - DeepCTI's sources are heterogeneous security evidence (advisories, vendor VEX, reachability analysis), not memory items.
  - DeepCTI should adopt their echo/laundering threat model as a test case.

### Certified Multi-Source Integrity for Structured Agent Actions ⚠ STRONG (C2)
- **Citation:** A. Pandey, A. Jain, L. Chen, C. Maple, C. Panchev. arXiv:2609.34245, 2026. Preprint.
- **URL:** https://arxiv.org/abs/2609.34245
- **Summary:**
  - Agents build privileged structured actions (for example, paying an invoice) from fields an adversary can corrupt.
  - The adversary corrupts at most k control domains. Evidence classes are counted by minimum hitting set over the dependencies of attestations, so copies inherit their origin and laundering cannot manufacture independence.
  - A field is admitted only if at most k domains dissent and its value is the unique survivor. Otherwise the certifier abstains or escalates (⊥).
  - Characterizes when an action can be safely certified and gives the "maximally live safe certifier".
  - Evaluated on OpenSanctions, 450 npm packages (apparent three-witness provenance collapses to two domains), and a live prompt-injection study with 5 LLMs.
- **Overlap:** C1 partial (abstaining on conflict or insufficiency behaves like treating Both and Neither as non-executable, but there is no four-valued semantics). **C2 STRONG.**
- **Differentiation:**
  - Separate Both from Neither, mapping them to escalate and gather-more respectively, which is where C3 comes in.
  - VEX status semantics and an integrated planning loop.
  - **Check that our independence counting is no weaker than their hitting-set rule.** If it is weaker, adopt theirs.

### CaMeL
- **Citation:** E. Debenedetti, I. Shumailov, T. Fan, J. Hayes, N. Carlini, D. Fabian, C. Kern, C. Shi, A. Terzis, F. Tramèr. "Defeating Prompt Injections by Design." arXiv:2503.18813 (2025). Venue unverified.
- **URL:** https://arxiv.org/abs/2503.18813 · code: https://github.com/google-research/camel-prompt-injection
- **Summary:**
  - A privileged LLM writes a program from the trusted query, while a quarantined LLM handles untrusted data and has no tools.
  - Values carry "capabilities" (provenance and allowed readers), and policies check these at each tool call.
  - Solves 77% of AgentDojo tasks with provable security, against 84% undefended.
- **Overlap:** C1 partial (provenance-tagged values gate tools, but taint is binary). C2 partial (provenance-conditioned authorization, no quorum).
- **Differentiation:** In CaMeL, untrusted provenance only ever taints a value. In DeepCTI, independent agreeing sources can *raise* support, and conflict is represented explicitly.

### Progent
- **Citation:** T. Shi, J. He, Z. Wang, H. Li, L. Wu, W. Guo, D. Song. "Progent: Securing AI Agents with Privilege Control" (earlier title "Programmable Privilege Control for LLM Agents"). arXiv:2504.11703 (2025). Venue unverified.
- **URL:** https://arxiv.org/abs/2504.11703
- **Summary:**
  - Deterministic symbolic policies over tool names and arguments.
  - An LLM generates and updates the policies; an SMT check accepts only updates that narrow the policy.
  - AgentDojo attack success 39.9% → 1.0%; ASB 70.3% → 3.9%.
- **Overlap:** C1 none. C2 partial (weak).
- **Differentiation:** Progent asks whether a tool and its arguments are allowed. DeepCTI asks whether the belief that justifies the action is sufficiently supported. The two are complementary layers.

### AgentSpec
- **Citation:** H. Wang, C. M. Poskitt, J. Sun. "AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents." ICSE 2026 (confirmed on the ICSE 2026 site). arXiv:2503.18666.
- **URL:** https://arxiv.org/abs/2503.18666
- **Summary:** A DSL of rules (trigger, predicate, enforcement) applied at runtime to code, embodied and autonomous-driving agents. It prevents more than 90% of unsafe code-agent executions.
- **Overlap:** C1 none. C2 partial (weak).
- **Differentiation:** AgentSpec is a general rule language that could host DeepCTI's predicates. It has no evidence semantics and no poisoning guarantee.

### DRIFT
- **Citation:** H. Li, X. Liu, et al. (full author list unverified). "DRIFT: Dynamic Rule-Based Defense with Injection Isolation for Securing LLM Agents." NeurIPS 2025. arXiv:2506.12104.
- **URL:** https://arxiv.org/abs/2506.12104 · https://github.com/SaFo-Lab/DRIFT
- **Summary:** A secure planner produces a minimal call plan and parameter checklist. A dynamic validator checks deviations against privilege and intent, and an injection isolator masks conflicting memory. Evaluated on AgentDojo and ASB.
- **Overlap:** C1 none. C2 partial (weak).
- **Differentiation:** DRIFT authorizes by deviation from the plan, not by evidence state. The two are orthogonal.

### Information-flow control for agents
- **FIDES.**
  - **Citation:** M. Costa, B. Köpf, A. Kolluri, A. Paverd, M. Russinovich, A. Salem, S. Tople, L. Wutschitz, S. Zanella-Béguelin. "Securing AI Agents with Information-Flow Control." arXiv:2505.23643 (2025).
  - **URL:** https://arxiv.org/abs/2505.23643 · https://github.com/microsoft/fides
  - **Summary:** The planner tracks confidentiality and integrity labels, enforces policies deterministically, and uses selective hiding. With suitable policies it stops all AgentDojo injections.
  - **Overlap:** C1 partial (integrity labels on a classical lattice, no Both or Neither). C2 partial.
- **RTBAS.** arXiv:2502.08966 (2025), https://arxiv.org/abs/2502.08966.
  - IFC for tool agents, with an LM judge and attention-saliency dependency screeners. Calls that break integrity or confidentiality go to the user for confirmation.
  - **Overlap:** C1 none–partial. C2 partial.
- **f-secure.** arXiv:2409.19091 (2024), https://arxiv.org/abs/2409.19091.
  - A planner that sees only trusted input and a rule-based executor.
  - **Overlap:** C2 partial (weak).
- **AirGapAgent.** arXiv:2405.05175 (2024), https://arxiv.org/abs/2405.05175.
  - Contextual-integrity data minimization.
  - **Overlap:** none.
- **Differentiation (all IFC):** IFC integrity takes the meet: mixing in untrusted data always lowers integrity. Corroboration cannot raise it, and contradiction or absence is not represented.

### Amazon Bedrock AgentCore Policy (Cedar)
- **Citation:** AWS announcements: preview at re:Invent, Dec 2025; GA, Mar 2026.
- **URLs:**
  - https://aws.amazon.com/about-aws/whats-new/2025/12/amazon-bedrock-agentcore-policy-evaluations-preview
  - https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/
  - https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-authorization-flow.html
- **Summary:**
  - Cedar policies are evaluated at the AgentCore Gateway for each MCP `tools/call`.
  - Per the developer guide:
    - **principal** = `AgentCore::OAuthUser`, from the JWT `sub`, with claims as tags;
    - **action** = the tool;
    - **resource** = the Gateway ARN;
    - **context** = `context.input.<arg>`, the tool arguments, plus session action history when a session ID is present, which enables temporal rules.
  - Natural-language policy authoring compiles to Cedar.
  - The official docs I read describe **no built-in provenance, evidence, or source-count attributes**. Such data could reach a policy only through tool arguments or a Lambda interceptor that the deployer writes.
- **Overlap:** C1 none. C2 partial.
- **Differentiation:** AgentCore Policy is an *enforcement point*. DeepCTI supplies the evidence semantics (four-valued state, independent-source count, risk bound) and can compile them into Cedar `context` attributes.
  - In `docs/VERIFICATION_LOG.md` → Libraries, we checked that Cedar can express `>=` thresholds on Long counts and 4-decimal `decimal()` comparisons. Floats are rejected.
  - Frame it as "DeepCTI policies are deployable on AgentCore/Cedar", not as a competitor.

### MCP authorization and gateways
- **MCP spec, Authorization (2025-06-18):** https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization.
  - OAuth 2.1 at the transport level, with resource indicators (RFC 8707). It controls access to a server or scope, not individual calls by evidence.
  - **Overlap:** none.
- **Docker MCP Gateway interceptors:** https://github.com/docker/mcp-gateway.
  - Pre- and post-call hooks that can block or rewrite calls.
  - **Overlap:** none (an enforcement point only).
- **MCP-Guard:** arXiv:2508.10991, https://arxiv.org/abs/2508.10991.
  - Three-stage detection proxy, about 89.6% accuracy.
  - **Overlap:** none (detection, not evidence-conditioned authorization).
- **MCPSecBench:** arXiv:2508.13220 (authors unverified), https://arxiv.org/abs/2508.13220.
  - 17 attack types across 4 surfaces.
  - **Overlap:** none. Possible evaluation resource.

### 2026 cluster: provenance-conditioned tool-call authorization (C2 partial)
All are arXiv preprints and their venues are unverified. All condition authorization on argument provenance. None uses a quorum or a multi-valued evidence state.

| Name | arXiv | What it does |
|---|---|---|
| **AuthGraph** (Wang, Li, Tian) | 2605.26497 | Provenance graph checked against an intent authorization graph. AgentDojo ASR 40% → 1%. |
| **ToolFence** (Li, He, Dai, Xiao) | 2609.37196 | Typed authorization blueprint plus controller-computed argument provenance. |
| **ARGUS** (Weng et al.) | 2605.03378 | Checks that "a decision is justified by trustworthy evidence before execution". |
| **Agent-Sentry** | 2603.22868 | — |
| **AGATE** | 2609.30830 | Allow / deny / approval-required. |
| **CXI** | 2607.06000 | — |
| **ProvenanceGuard** | 2607.01236 | — |
| **CAGE** | 2607.29190 | Authorization certified over plausible tool-return perturbations. |

- **Overlap:** C1 none (CAGE partial on uncertainty). C2 partial.
- **Differentiation:** Provenance-conditioned authorization is crowded. Do not claim it as novel by itself. If DeepCTI makes injection-robustness claims, compare against AuthGraph, ToolFence and ARGUS on AgentDojo.

### KITA: threshold signing
- **Citation:** Y. Zheng, Q. Zhang. "From Review to Authorization: Key-Isolated Threshold Signing for LLM Agents." arXiv:2609.05901 (2026). The page says NeurIPS 2026 Workshop; unverified.
- **URL:** https://arxiv.org/abs/2609.05901
- **Summary:** t-of-n *reviewer* signatures over the exact action bytes, including a hash of the evidence manifest.
- **Overlap:** C1 none. C2 partial (the quorum is over reviewers, not evidence sources).
- **Differentiation:** Their quorum is over who approves; DeepCTI's is over independent evidence. The two could be composed.

### SoK: Trust-Authorization Mismatch in LLM Agent Interactions
- **Citation:** G. Shi, H. Du, Z. Wang, X. Liang, W. Liu, S. Bian, et al. arXiv:2512.06914 (Dec 2025).
- **URL:** https://arxiv.org/abs/2512.06914
- **Summary:** Proposes the Belief–Intention–Permission framework. It argues that static permissions are decoupled from runtime trust, i.e. authorization is "belief-blind". Survey of more than 200 papers.
- **Overlap:** C1 none–partial (conceptual). C2 partial (it states the problem).
- **Differentiation:** Cite it as motivation. DeepCTI is a concrete mechanism for belief-conditioned permission.

### Allen et al.: Belnap computer with an LLM judge (closest C1 hit)
- **Citation:** B. P. Allen, P. Chhikara, T. M. Ferguson, F. Ilievski, P. Groth. "Sound and Complete Neurosymbolic Reasoning with LLM-Grounded Interpretations." NeSy 2025 (per the authors; unverified on a proceedings page). arXiv:2507.09751.
- **URL:** https://arxiv.org/abs/2507.09751
- **Summary:**
  - Puts an LLM in the interpretation function of a paraconsistent logic. Truth values are bilateral (verified, refuted), giving T, F, glut (Both) and gap (Neither).
  - Bilateral factuality evaluation adds about 6 macro-F1 points on GPQA and SimpleQA. A tableau reasoner applied to a medication knowledge base found contradictions.
  - It abstains on gluts and gaps.
- **Overlap:** **C1 partial.** It has a Belnap-style state built with an LLM, but uses it for reasoning and factuality, not to control or authorize an agent. C2 none.
- **Differentiation:** In DeepCTI the Belnap state is aggregated from *multiple external, possibly adversarial sources* and drives *actions and tool authorization*. Cite Allen et al. as the closest four-valued LLM precedent.

### Other four-valued and paraconsistent work
- **Majkic.** "Intensional FOL over Belnap's Bilattice for Strong-AI Robotics." arXiv:2508.02774.
  - Pure logic; no LLM gating.
  - **Overlap:** C1 none–weak.
- **Background:** "Four imprints of Belnap's useful four-valued logic in computer science." arXiv:2503.20679. Useful for the background section.

### RAG poisoning and conflicting evidence (aggregation over sources)
- **RobustRAG.** C. Xiang, T. Wu, et al. "Certifiably Robust RAG against Retrieval Corruption." arXiv:2405.15556.
  - Isolate-then-aggregate with certified robustness when up to k passages are corrupted.
  - **Overlap:** C2 partial, but certifies *answers*, not actions.
  - Its certification style could be borrowed for DeepCTI's guarantee.
- **TrustRAG.** arXiv:2501.00879.
  - **Overlap:** C1 weak.
- **Astute RAG.** arXiv:2410.07176.
  - **Overlap:** C1 weak (conflict consolidation without formal semantics).
- **MADAM-RAG / RAMDocs.** arXiv:2504.13079, COLM 2025.
  - **Overlap:** C1 weak.
- **ActProbe.** arXiv:2609.14723.
  - Localizes poisoned segments when k < n/2.
  - **Overlap:** C2 weak.
- **Seen only in search results:** ReliabilityRAG (OpenReview D9JeNTs5Bu) and RAGSentinel (arXiv:2608.23965). Details unverified.
- **Differentiation (whole group):** These works make answers robust. DeepCTI uses the aggregated state, including Both and Neither, to *authorize actions*.

---

## C3: VOI / EC² / DRD tool selection

### HESP (near-strong; must cite)
- **Citation:** Zhuowen Liu, Zhixuan Wang. "HESP: Separating What to Probe from When to Stop in Local LLM Alert-Triage Agents." arXiv:2609.33446 (cs.CR, 27 Sep 2026).
- **URL:** https://arxiv.org/abs/2609.33446 · code: https://github.com/lzwhehe/HESP
- **Summary:**
  - SOC alert-triage agent for local LLMs (7B–72B).
  - Keeps a posterior over 8 cause hypotheses plus "other".
  - Ranks 10 read-only probes by **EIG(a)/c(a)**, i.e. hypothesis-entropy reduction per unit cost.
  - A controller-side stop fires at posterior ≥ 0.8 (untuned) when supporting evidence is present.
  - Evaluated on 7,272 audited episodes in a synthetic environment. The controller stop lifts Llama-3.1-8B from 0 to 0.917. It cites Golovin et al. 2010 only as background.
- **Overlap:** C3 strong conceptually but partial algorithmically. C5 none: the stop is a fixed threshold with no guarantee.
- **Differentiation:**
  - DeepCTI's objective is decision-region-aware (EC²/DRD) over VEX status/justification regions. Golovin et al. 2010 (App. B) show that hypothesis-entropy or myopic VOI can be Ω(n/log n) times worse.
  - DeepCTI uses real CVEs and codebases, and its stopping is risk-controlled.
  - **Include an EIG/cost (HESP-style) baseline.**

### Active Inference as Context Acquisition
- **Citation:** S. Dutta, S. N. Ramachandran, S. Sra. arXiv:2608.19202 (2026).
- **URL:** https://arxiv.org/abs/2608.19202
- **Summary:** Chooses between context, task and stop actions by expected free energy minus cost. In deterministic settings this reduces to EIG per token cost. Domains: clarification and preference tasks.
- **Overlap:** C3 partial.
- **Differentiation:** Uses hypothesis entropy and free energy, is general-purpose, and has no near-optimality guarantee for decisions.

### BED-LLM
- **Citation:** Choudhury, Williamson, Goliński, Miao, Bickford Smith, Kirchhof, Zhang, Rainforth. ICLR 2026 (unverified on a proceedings page). arXiv:2508.21184.
- **URL:** https://arxiv.org/abs/2508.21184
- **Summary:** Sequential Bayesian experimental design with EIG over LLM-derived beliefs, for 20 Questions and preference elicitation.
- **Overlap:** C3 partial.
- **Differentiation:** Uses EIG over the full hypothesis space. DeepCTI uses a decision-focused objective over tool actions.

### Uncertainty of Thoughts (UoT)
- **Citation:** Z. Hu et al. NeurIPS 2024. arXiv:2402.03271.
- **URL:** https://arxiv.org/abs/2402.03271
- **Summary:** Simulated question trees with information-gain rewards, for medical diagnosis, troubleshooting and 20Q.
- **Overlap:** C3 partial.
- **Differentiation:** As for BED-LLM.

### Uncertainty-Aware Clarification in LLM Agents with Information Gain
- **Citation:** M. Deng et al. ICML 2026 (unverified). arXiv:2606.03135.
- **URL:** https://arxiv.org/abs/2606.03135
- **Summary:** A clarifier trained with an information-gain reward, deciding whether to ask or act before tool calls. On τ-bench it gains +3.7% success.
- **Overlap:** C3 partial.
- **Differentiation:** A trained reward on user intent, versus inference-time DRD over evidence tools.

### Conformal Information Pursuit (C-IP)
- **Citation:** K. H. R. Chan, Y. Ge, E. Dobriban, H. Hassani, R. Vidal. arXiv:2507.03279 (2025).
- **URL:** https://arxiv.org/abs/2507.03279
- **Summary:** Greedy information pursuit for LLM query selection. It replaces entropy with the average size of conformal prediction sets. Evaluated on 20Q and MediQ.
- **Overlap:** C3 partial. C5 partial (conformal sets are used as an uncertainty proxy, not for risk-controlled abstention).
- **Differentiation:** This is the closest bridge between C3 and C5. DeepCTI uses DRD objectives plus an LTT guarantee on the final verdict.

### ACTMED
- **Citation:** Ruhrberg Estévez, Astorga, van der Schaar. NeurIPS 2025. arXiv:2510.18988.
- **URL:** https://arxiv.org/abs/2510.18988
- **Summary:** Chooses clinical tests by expected KL divergence (information gain) against cost.
- **Overlap:** C3 partial.
- **Differentiation:** Different domain, and an IG objective rather than decision regions.

### CGDP
- **Citation:** Kausik, Swaminathan, Kallus. arXiv:2605.07042 (2026).
- **URL:** https://arxiv.org/abs/2605.07042
- **Summary:** Frames agentic search as a POMDP, with the LLM as approximate Thompson sampling.
- **Overlap:** C3 partial (framing only).

### Scores Are Not Decisions (CAM-DF)
- **Citation:** Y. Feng, Y. Zhang, Y. Cheng, W. Qi. arXiv:2607.27083 (2026).
- **URL:** https://arxiv.org/abs/2607.27083
- **Summary:** Decision-focused, cost-aware stopping over ranked tool prefixes.
- **Overlap:** C3 partial in spirit.
- **Differentiation:** It decides how many tools to expose, not which evidence to gather.

**No 2025–2026 paper was found that applies EC², HEC, DRD or DiRECt to LLM agents.**

Note for the theory section: the published EC², HEC and DiRECt constants of the form `ln(1/p_min)` rest on a Golovin–Krause theorem whose proof was later found to be flawed. See `docs/VERIFICATION_LOG.md` → Theorem constants (ERRATUM) for the currently valid 4(1+ln(Q/η)) bound (Al-Thani, Cui, Nagarajan, arXiv 2208.08351).

---

## C5: CRC / LTT abstention

### Safe to Stop? ⚠ STRONG at method level (C5)
- **Citation:** Yuexin Wu, Vasile Rus. "Safe to Stop? Risk-Constrained Stopping for Sequential Clinical Diagnosis Agents." arXiv:2609.09678 (9 Sep 2026).
- **URL:** https://arxiv.org/abs/2609.09678
- **Summary:**
  - Uses LTT-style exact tests of selective diagnostic error over a pre-registered candidate family to decide when a sequential diagnosis agent stops and answers.
  - On MIMIC (1,834 episodes): 16.9% selective error at 78.8% coverage, versus 30.8% unconstrained.
  - Results are labelled exploratory. The test-selection mechanism was not visible in the abstract (unverified).
- **Overlap:** **C5 STRONG in method.** C3 partial at most.
- **Differentiation:** Clinical domain, and it does not combine LTT with EC²/DRD selection or with an evidence-state authorization gate. DeepCTI's novelty must rest on that combination plus VEX-specific asymmetric loss (a false `not_affected` is the costly error).

### Non-Degenerate Risk Certification for Automated Security Decisions (near-strong)
- **Citation:** Zhenpeng Li. arXiv:2608.12444 (cs.CR, 12 Aug 2026).
- **URL:** https://arxiv.org/abs/2608.12444
- **Summary:**
  - An (α,ρ)-actionability certificate: risk ≤ α *and* action rate ≥ ρ. This rules out the trivial "always abstain" solution.
  - CRC threshold with deferral to humans.
  - Applied to zero-shot LLM intrusion-detection triage with 6 LLMs on 3 datasets.
- **Overlap:** C5 partial–strong. C3 none.
- **Differentiation:** It is a single-shot classifier, not a tool-using agent. It does not use LTT over multi-parameter agent policies or VEX labels. **Adopt or contrast the non-degeneracy argument**, because DeepCTI's abstention claim needs a coverage floor.

### Post-Hoc Trajectory-Risk Certification for Modular LLM-Based Security Agents
- **Citation:** Zhenpeng Li. arXiv:2608.05199 (2026).
- **URL:** https://arxiv.org/abs/2608.05199
- **Summary:** Split-conformal trajectory coverage for a fixed multi-stage security pipeline: 92.7% coverage at α = 0.1. Under cross-dataset shift, miscoverage reaches 100%.
- **Overlap:** C5 partial.
- **Differentiation:** Fixed stages versus an adaptive agent. **Cite its shift failure as a threat to validity for the temporal hold-out.**

### CORA
- **Citation:** Y. Feng et al. "CORA: Conformal Risk-Controlled Agents for Safeguarded Mobile GUI Automation." arXiv:2604.09155 (2026).
- **URL:** https://arxiv.org/abs/2604.09155
- **Summary:** CRC-calibrated execute/abstain thresholds for actions proposed by a GUI agent. Introduces the Phone-Harm benchmark.
- **Overlap:** C5 partial (abstention on actions, not on the verdict).

### Role-Stratified Conformal Risk Control for LLM Tool Calls
- **Citation:** M. A. Rahman et al. "Beyond Aggregate Risk: Role-Stratified Conformal Risk Control for LLM Tool Calls." arXiv:2607.24343 (2026).
- **URL:** https://arxiv.org/abs/2607.24343
- **Summary:** Per-argument-role CRC, evaluated on AgentDojo and InjecAgent.
- **Overlap:** C5 partial. It also touches C2's evaluation space.

### Other C5 items
- **Doomed from the Start.** K. Ruan et al., arXiv:2607.06503. Recall-controlled early abort of agent episodes.
  - **Overlap:** C5 partial.
- **Conformal Arbitrage.** arXiv:2506.00911, NeurIPS 2025 poster (authors unverified). CRC deferral between models.
  - **Overlap:** C5 partial.

### Foundational (cite)
- **Conformal Abstention.** Yadkori et al., arXiv:2405.01563.
- **Conformal Factuality.** Mohri & Hashimoto, ICML 2024, https://proceedings.mlr.press/v235/mohri24a.html.
- **When Can Conformal Risk Control Certify LLM Outputs?** arXiv:2606.29054. Seen in search results only; it reportedly proves abstention is forced when base risk exceeds α.

**No conformal or LTT work specific to vulnerability or VEX triage was found.**

---

## Benchmarks and domain papers (verification)

### VEX-Bench (confirmed)
- **Citation:** Jiahao Shi, Edward Tsien, Yifeng Di, Hongjiao Zhang, Yuan Tang, Ronit Dey, Ilona Shishov, Gal Netanel, Zvi Grinberg, Vladimir Belousov, Bat-Zion Rotman, Ilan Pinto, Tianyi Zhang. "VEX-Bench: Benchmarking LLM Agents for Assessing Exploitability of Software Supply Chain Vulnerabilities." arXiv:**2609.08040** (7 Sep 2026). The arXiv page says EMNLP 2026; not confirmed on the proceedings.
- **URL:** https://arxiv.org/abs/2609.08040 · **repo:** https://github.com/steven1518/vex-bench
- **Size:** **75 cases**, confirmed by `benchmark/tasks/vex_bench.jsonl`, which has 75 lines.
  - Go: 30 cases, 24 CVEs, 15 projects.
  - Java: 25 cases, 23 CVEs, 10 projects.
  - Python: 20 cases, 20 CVEs, 10 projects.
  - 22 (29.3%) exploitable / 53 (70.7%) not affected.
- **Label space:** **not the CSAF/OpenVEX status set.** The paper calls it "adapted from the VEX standard".
  - Ground truth is **binary** `exploitable` / `not_exploitable` plus a `ground_truth_category`.
  - The prompt taxonomy has 12 categories: false_positive, code_not_present, code_not_reachable, requires_configuration, requires_dependency, requires_environment, compiler_protected, runtime_protected, perimeter_protected, mitigating_control_protected, uncertain, vulnerable.
  - Only 4 not-affected categories occur in the data: code_not_present, code_not_reachable (38 cases), requires_configuration, requires_environment.
  - There is no `fixed` and no `under_investigation`.
  - Record fields: task_id, repo_url, commit_sha, cve_id, ground_truth, ground_truth_category, metadata.language, metadata.pr_url.
- **License:** **MIT**, "Copyright (c) 2026 Jiahao Shi", confirmed from the raw LICENSE file. No separate dataset license was found. The referenced third-party repositories keep their own licenses (our inference).
- **Results:** 9 frontier models across 3 harnesses (Claude Code, Codex, OpenCode).
  - Best is GPT-5.5: 89.3% status accuracy, 81.6% binary F1, 73.5% justification macro-F1.
  - GPT-5.5 is the only model above 70% macro-F1.
- **Overlap:** none with C1–C5. **Direct evaluation target and baseline.**
  - With 75 cases, LTT/CRC calibration needs its own split or a larger in-house set. VEX-Bench alone is too small to calibrate and test.
  - Its cases are probably not after 2026-04-29, so check them against the temporal hold-out.

### SSVC + LLM prioritization (confirmed)
- **Citation:** Osama Al Haddad, Muhammad Ikram, Ejaz Ahmed, Young Lee. "Prompting the Priorities: A First Look at Evaluating LLMs for Vulnerability Triage and Prioritization." arXiv:**2510.18508** (21 Oct 2025).
- **URL:** https://arxiv.org/abs/2510.18508
- **Summary:**
  - Tests 4 LLMs (ChatGPT, Claude, Gemini, DeepSeek) with 12 prompting strategies on 384 vulnerabilities, over 165k queries.
  - Predicts 4 SSVC decision points: Exploitation, Automatable, Technical Impact, Mission & Wellbeing.
  - Gemini is best on 3 of 4 points. Only DeepSeek reaches "fair" weighted-κ agreement.
  - All models over-predict risk. The authors conclude LLMs do not replace experts.
- **Overlap:** same domain. C3 none, C5 none. A motivating baseline for "an uncalibrated LLM over-predicts risk".

### AgentDojo
- **Citation:** Debenedetti, Zhang, Balunović, Beurer-Kellner, Fischer, Tramèr. NeurIPS 2024 Datasets & Benchmarks Track. arXiv:2406.13352.
- **URL:** https://arxiv.org/abs/2406.13352
- **Summary:** 97 user tasks, 27 injection tasks, 629 security test cases and 74 tools, across 4 suites:

| Suite | Tools | User tasks | Injection tasks |
|---|---|---|---|
| Workspace | 24 | 40 | 6 |
| Slack | 11 | 21 | 5 |
| Travel | 28 | 20 | 7 |
| Banking | 11 | 16 | 9 |

- **Metrics (§3.4):** benign utility, utility under attack, and targeted ASR.
- **Overlap:** an evaluation venue for C2. CaMeL, Progent, FIDES, AuthGraph and others report on it.

### InjecAgent
- **Citation:** Qiusi Zhan, Zhixiang Liang, Zifan Ying, Daniel Kang. ACL 2024 Findings. arXiv:2403.02691.
- **URL:** https://arxiv.org/abs/2403.02691
- **Summary:**
  - 1,054 test cases from 17 user tools and 62 attacker tools; 2,108 with the base and enhanced settings combined.
  - Attack types: direct harm (30) and data stealing (32).
  - Metrics: ASR-valid, ASR-all and valid rate.
  - ReAct GPT-4 is attacked successfully 24% of the time, roughly doubling in the enhanced setting.
- **Overlap:** an evaluation venue for C2.

### τ-bench pass^k
- **Citation:** Shunyu Yao, Noah Shinn, Pedram Razavi, Karthik Narasimhan. "τ-bench: A Benchmark for Tool-Agent-User Interaction in Real-World Domains." arXiv:2406.12045 (2024).
- **URL:** https://arxiv.org/abs/2406.12045
- **Definition:** In the §3 paragraph "Pass^k metric", verified in the PDF: "the chance that all k i.i.d. task trials are successful, averaged across tasks".
- **Formula:** "if a task is run for n trials and c of those trials end up successful (r = 1), **unbiased estimates** for pass^k and pass@k would be":
  - `pass^k = E_task[ C(c,k) / C(n,k) ]`
  - `pass@k = 1 − E_task[ C(n−c,k) / C(n,k) ]`
- See `docs/VERIFICATION_LOG.md` → Theorem constants (e).

### Other LLM-for-VEX and exploitability work
- **Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering.** Xiong & Zhang, ISSTA 2026 (unverified). arXiv:2601.22952.
  - Agents filter false positives from static-analysis (SAST) tools, not dependency VEX.
- **Automated Vulnerability Validation and Verification: A Large Language Model Approach.** arXiv:2509.24037. Summary seen in search results only.
- **Seen in search results only, not examined:**
  - VEXGen (Computers & Security 2026, https://www.sciencedirect.com/science/article/pii/S0167404826003408).
  - arXiv 2511.20313 (SBOM reality check).
  - arXiv 2512.17710.
  - arXiv 2508.18439.

---

## Searches that returned nothing relevant
- "Belnap" / "bilattice" / "first-degree entailment" / "paraconsistent" combined with LLM agent, tool or authorization: only logic background and Allen et al.
- "four-valued" with RAG, conflicting evidence or agent: conflict-handling RAG papers only, none four-valued.
- "provenance semiring" / "why-provenance" with agent tool policy: nothing.
- "evidence-gated" agent actions as an exact phrase: no hits. The related work is in the provenance cluster above.
- EC² / equivalence-class determination / hyperedge cutting / DiRECt with LLM agents: only the original 2010–2015 papers.
- Conformal or selective classification with CVE / exploitability / VEX: nothing beyond Li's intrusion-detection papers.
