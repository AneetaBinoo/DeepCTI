# DeepCTI — Pre-registration v3 (tag `prereg-v3`): D7 DeepCTI-Live-X

Committed and tagged before any run on the D7 test split, after D7 was frozen and a dev-only pilot.
Design: docs/V3_PLAN.md, docs/DATA_CONTRACT_V3.md. Analysis: scripts/paper/analyze_v3.py (hash below).

## 1. Data
D7 (data/d7, frozen; build report data/d7/BUILD_REPORT.md): ecosystems deb-ubuntu, pypi, maven, vendor
(version only in unstructured text and banners); variants V1–V8; splits by CVE (dev/calib/test); sealed test
labels `data/sealed/d7_test_labels.jsonl`. Trust classes and VOI priors estimated per ecosystem on D7 dev
(config/source_profiles_v3.yaml, config/priors_v3.yaml; rule as v2). Drift episodes for X5 are generated from D7
TEST hosts after this tag by scripts/data/build_drift_v3.py (seed 20261005; world physics sealed).

## 2. Systems and arms
Arms: tracker (structured tracker/VEX ranges available), withheld (no tracker/VEX; scanners available),
blind (no tracker/VEX, no scanners). Systems: S0 (Trivy, Grype, OSV), S1, S1′ (LLM-free); S2, S3, DC, DCv21,
DC_noverify (LLM); S3I (Inspect AI react; subset, see §4). DCv21 = service-aware + instance-aware atoms +
validated synthesis (prereg/DEVIATIONS.md D16). Spec v3 (prompts/core_spec_v3.md), catalog v3, budget 60,
policies as v2.

## 3. Hypotheses (primary family H9–H14, Holm; H15 secondary)
* **H9** Withheld arm: DC loss < S3 loss (per case averaged over models; CVE-clustered sign-flip).
* **H10** (LLM role) Vendor ecosystem, tracker arm: DC (verified LLM extraction) loss < S1′ (no extraction).
* **H11** (verification) Accepted-fact error rate (extracted version ≠ any true on-disk/running version):
  DC < DC_noverify.
* **H12** (risk control, criterion) Blind arm, LTT at α = 0.05, δ = 0.1, calib+test pooled, 200 CVE re-splits:
  every model has ≥ 90% of splits with realised risk ≤ α AND mean coverage gain over DC's base coverage > 0.
* **H13** (independent v2.1 test) D7 drift episodes, upgrade-without-restart: DCv21 loss < DC loss.
* **H14** (acquisition) Withheld arm, max budget: DC (EC²) cost-to-decision < DC_checklist, with loss
  difference one-sided 95% upper bound < 0.05 (reported; the primary test is on cost).
* **H15** (secondary, E11 protocol unchanged) Analyst-note faithfulness of DCv21 (validated) ≥ DC (unvalidated)
  on D7 test, judged by the validated judges of results/v3/e11/PROTOCOL.md.

## 4. Allocation
X2 (all arms, all systems): Qwen3-4B, Llama-3.1-8B, Granite-4.1-8B, Qwen3-14B, Mistral-Small-24B, Gemma-4-31B,
Granite-4.1-30B (+ Nemotron-49B, GLM-4.5-Air, Mistral-Medium-128B if served in the big-model phase).
X3 (acquisition; 200-case stratified subset; budgets 5–60; withheld + blind): Qwen3-14B, Mistral-Small-24B.
X5 (drift): all models of X2. S3I: Qwen3-14B and Mistral-Small-24B on X2 tracker + withheld arms.
LTT (H12) uses X2 DC records on calib and test (calib X2 runs for every X2 model).

## 5. Hashes (filled at tag time)

Code commit at freeze: `5f0483bc6e55dcdf1f348194d07a6b3a5042fb13`

| file | SHA-256 |
|---|---|
| `data/sealed/d7_test_labels.jsonl` | `21857ab4dde6fe9a9afde19f23570f96935bc282ed4d0e10b429030685336c21` |
| `data/d7/cases/test.jsonl` | `86c4ca9ce6e9df92298bbae31adfb52009a64e5ac461945c57c0d53ba58766ba` |
| `data/d7/cases/dev.jsonl` | `c8a78a2c57932c27f29e73474f3248ae9bff55aebcfbc722010593ddbcf501a6` |
| `data/d7/cases/calib.jsonl` | `20a589ea07f256448e833d2cfedc5f415b1b0d07227e7b67fabdd38d3532a354` |
| `data/d7/cve_meta.jsonl` | `7a62eee676e6ec18043aa220e9a5d5817d8d8cbf2e645bf072e05b6ca5d14a21` |
| `config/source_profiles_v3.yaml` | `b0119e990f6e69a2f505b1291f06c7abe0b662bdbb61e435a9ffc471d4655e37` |
| `config/priors_v3.yaml` | `39d8b6f8e08f92f02f58afa6c7467d1fed4af76be9e63863b6c00e2fee8cf993` |
| `config/config_preconditions_v3.yaml` | `43291f45d03620bf60aba86563c8fbe4152b317936924858461245fab5d238d4` |
| `config/models.yaml` | `9c0f0f023b484a1e3a2a9694c216bc364edec9f17652828f542a40434267845b` |
| `prompts/core_spec_v3.md` | `0fb37664bce4f09ede77c73ff59efe2a12ab8b3d850c98fd7544b1d80e357b3a` |
| `scripts/paper/analyze_v3.py` | `a69d9a273570ad81c6d2ab265c4e141396c5c9266863c45f37ba7b41eb7264ec` |
| `scripts/data/build_drift_v3.py` | `0a2fe2b8387808d1866cf8082f3785b9fdea80c2e4563405647d5a7f39e8287e` |
| `src/deepcti/core/versions.py` | `db695e81231e47d1386512246dfe30c3706a27e061c59308773701dfbf630d6c` |
| `src/deepcti/extraction/verifier.py` | `b3627f9bfaed80b29a69426d2040d9cb5ceb05d4d697baa61e561d1bc52fe24e` |
| `data/d7/hosts (tree)` | `95781a5d7d627c9bd948f69270e79c86e9b4c8e30ab89c8290c9c6d313153603` (518578 files) |
