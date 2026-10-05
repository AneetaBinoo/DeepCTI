# DeepCTI v3 — experiment improvement plan (2026-10-05)

Inputs: `paper/main.tex` (the v0 manuscript), `results/v2/REPORT.md` (v2 results), the four audit reports.

## 1. Gap analysis: paper claims vs. evidence a Tier-1 reviewer needs

| # | Paper element (v0) | Status after v2 | Remaining gap | v3 action |
|---|---|---|---|---|
| G1 | 100 template cases, synthetic profiles | Replaced by D1 (906 real Debian fixtures) | single distro family; tracker makes the task easy; config-gated cases thin (7) | **D7 DeepCTI-Live-X**: Ubuntu hosts, language-ecosystem apps (PyPI, Maven jars), vendor software in /opt with version only in unstructured files, ≥ 30 config-gated cases |
| G2 | Validated synthesis (repair, fallback, lexical claim support) is a core component | Not evaluated in v2 | the paper's LLM role (analyst response) has no quality evidence | **E11 response quality**: claim-level faithfulness with cross-family LLM judges, judges validated by injected-error recall and inter-judge κ; repair/fallback rates on real data |
| G3 | "Model synthesizes, controller decides" | DC decision-identical to LLM-free S1′ | reviewers ask what the LLM adds | D7 settings where version evidence is unstructured (vendor software, free-text tickets) and no structured feed exists → verified LLM extraction is required; measure its accuracy/acceptance and decision impact |
| G4 | Baselines: one-shot, RAG, iterative | v2: S2–S5 with shared spec | home-made ReAct only; panel ≤ 31B | **third-party harness** (Inspect AI `react()` agent) as S3-I; **panel expansion** with cached models: Granite-4.1-30B (scaling pair with 8B), Nemotron-Super-49B, GLM-4.5-Air (106B MoE), Mistral-Medium-3.5 (128B; pair with Small-24B), SecGPT (security-tuned, no tool calling → S2/DC only) |
| G5 | RQ-2 authorization = agenda | v2 E5: gating works, attacks weak (ASR ≈ benign error) | no attack that actually moves baselines | **D3b adaptive attacks**: per-model attack search on dev (tool-output spoofing, fake VEX records, ticket forgery, "important instructions"); keep attacks with dev ASR above benign rate; evaluate on test |
| G6 | Freshness = agenda | v2 E4: staleness solved; restart-blindness failure (DER 0.97) | design flaw | **DC v2.1 service-aware verification**: running-binary evidence is required for packages with active services; pre-registered |
| G7 | Information needs / acquisition | v2 E3 trivial (2 calls decide) | VOI untested where it matters | E3 on D7 where scanners are noisy and costs differ; DP regret on real cases |
| G8 | Bootstrap + sign-flip | v2 GEE (R unavailable) | plan requires GLMM | R + lme4 in a conda env; `scripts/stats/glmm.R` |
| G9 | — | E6/LTT only post-hoc (blind arm) | needs pre-registration | pre-registered LTT on D7 withheld/blind arms |

## 2. Protocol
New pre-registration `prereg-v2` (tag) before any D7/D3b test run; v2 benchmark results remain frozen under `prereg-v1`.
Panel extension runs on the frozen v2 test split are an addendum declared in `prereg-v2`.
Dev-only development; sealed D7 test labels; audits (code + results + report fact-check) as in v2.
