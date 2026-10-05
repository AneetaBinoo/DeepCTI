# DeepCTI — Pre-registration v2 (tag `prereg-v2`): panel addendum and DC v2.1 drift study

Committed and tagged before any run below on the D1 test split. The v2 results under `prereg-v1` are frozen
and unaffected. Plan and rationale: `docs/V3_PLAN.md` (gaps G4, G6).

## A. Panel addendum on the frozen v2 protocol (D1 test, spec v2, policies/budgets as prereg-v1)
Models added (served with vLLM 0.23.0, temperature 0; revisions in config/models.yaml / HF cache):
Granite-4.1-30B (`4fae6278…`), Llama-3.3-Nemotron-Super-49B-v1 (`387156d8…`, with vLLM's
examples/tool_chat_template_llama3.1_json.jinja sha256 `8aedd05f…` and system prefix "detailed thinking off"
per its model card), and — in a later GPU phase — GLM-4.5-Air (`a24ceef6…`) and Mistral-Medium-3.5-128B.
Blocks: E2, E4, E5 (configs as prereg-v1), E9 — identical code paths and spec as v2 (spec v2).
Analysis: identical scripts; results reported as a panel extension (no new primary hypotheses).
Exploratory question (H6′): does S3's loss approach DC's as model size grows (Granite 8B → 30B pair;
Mistral 24B → 128B pair)? Reported descriptively with per-model estimates and CVE-clustered CIs.

## B. DC v2.1 drift study X4 (D2 test episodes, spec v3)
**Disclosure.** The v2.1 design (service-aware verification; instance-aware atoms: running-process evidence
feeds `running_in_affected_range`/`running_fix_applied`; the component is in range if any instance is and fixed
only if all observed instances are) was motivated by the v2 TEST result on D2 upgrade-without-restart episodes.
X4 on the same D2 test episodes is therefore a confirmation, not an independent test; an independent test on
fresh drift episodes generated from D7 test hosts is pre-registered in prereg-v3.
Systems: DC (v2 controller), DCv21, S3, S2 (LLM, spec v3: prompts/core_spec_v3.md, which adds rule 3 on
running services for ALL systems), S1′, S1 (LLM-free). Models: the full panel available at run time.
Hypotheses (Holm over H7–H8, CVE-clustered sign-flip, 10,000 permutations):
* **H7** On upgrade-without-restart episodes, DCv21 has lower loss than DC.
* **H8** (non-inferiority) On the other D2 kinds, DCv21's loss exceeds DC's by less than 0.05 (one-sided 95%
  CVE-clustered bootstrap upper bound < 0.05).
Reported regardless: DCv21 vs S3 per kind; cost increase of DCv21.

## C. Deviation handling
As for prereg-v1: any later change is logged in prereg/DEVIATIONS.md.
