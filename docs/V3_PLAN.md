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

## 3. Outcome (updated 2026-10-06)

Details: `results/v3/REPORT_V3.md` and `results/v4/REPORT_V4.md`.

| # | Outcome |
|---|---|
| G1 | **Done.** D7 has 822 cases, 141 CVEs and 4 ecosystems; 41 cases are config-gated (21 in test). |
| G2 | **Done.** E11 note-quality pipeline. On D1, judges were validated by error injection. On D7: H15 failed because of a prompt defect; the corrected DCv21b was post hoc in v3 and confirmed in v4 (H16, +0.044). |
| G3 | **Done.** The LLM's extraction changes decisions only for vendor software: H10 −0.205 (vendor, tracker arm). Verification lowers accepted-fact error by 2.7 pp (H11, pooled over deb and vendor proposals). In feed-less arms DC equals the LLM-free S1′. |
| G4 | **Done, with two changes.** S3I (Inspect AI react) agrees with S3 on 80.6% of decisions. Panel: Granite-30B, Nemotron-49B, Mistral-Medium-128B and GLM-4.5-Air (added in v4, descriptive). SecGPT was not run. |
| G5 | **Not done.** The adaptive-attack workstream (D3b) was stopped. The v2 E5 results stand, with their attack-strength limitation. v4 added a decoy-robustness test (H18), which is not an attack study. |
| G6 | **Done.** DC v2.1 is instance-aware: H7 −9.25 on D2; independent D7 test H13 −4.59. Costs: more abstention after restarts on D7, and +34–79% tool cost on drift episodes. |
| G7 | **Done.** On D7, EC² is cheaper than the checklist (H14 −0.35), but entropy-greedy is cheaper still. |
| G8 | **Done.** R/lme4 GLMM on v2 E2 (`results/v3/glmm_e2.md`); it agrees with H1. |
| G9 | **Done.** Pre-registered LTT on the D7 blind arm (H12). Coverage rises from 0.31 to 0.50–0.91 at realised risk 1.4–1.9%. |
| new | Trust estimation was too conservative on dev alone. Re-estimating on dev+calib was pre-registered in v4 (H17: withheld loss 0.344 → 0.207, coverage 0.31 → 0.73). |
