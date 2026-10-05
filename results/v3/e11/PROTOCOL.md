# E11 analyst-response quality — analysis protocol (written before any system-level result)

Status: fixed on 2026-10-05 before claim judging was run at scale. Inputs: the frozen v2 test episodes
`runs/test/E2/<model>.jsonl` (prereg-v1 runs, commit 9e2bc08). Gap G2 in `docs/V3_PLAN.md`.
Before this file was written, only a 4-episode pilot (one generator, qwen3_4b; 3 claims each) was run to
check that the endpoints accept JSON-schema outputs; pilot outputs live in a scratch cache that is not used by
the pipeline. Any later change to this protocol is listed under "Deviations" at the end, with its reason.

## 1. Episodes
- Generators: the six v2 panel models (gemma4_31b, granite41_8b, llama31_8b, mistral_small_24b, qwen3_14b,
  qwen3_4b). Systems DC, S2, S3, S4, S5; arms tracker, withheld.
- Sample (`scripts/e11/01_sample.py`, seed 20261005): 180 distinct test cases drawn stratified by variant
  (proportional allocation, largest remainder), shuffled and split into six blocks of 30; block *k* is assigned
  to generator *k*. For each (generator, case) all 5 systems x 2 arms are taken, giving 1,800 episodes and 180
  episodes per system x arm (paired across systems within a generator).
- Episodes with `error != null` are excluded (reported). Episodes whose explanation yields zero claims are
  reported as "no-claim" and excluded from claim ratios.

## 2. Evidence the judges see
- The tool outputs of the episode, reconstructed by replaying the recorded calls on a fresh `HostEnv`
  (deterministic; each replayed output must equal the recorded 400-character prefix, call id and status —
  replay mismatches are reported, mismatched episodes excluded). Each output is truncated to what the
  generating system's LLM was shown (S2: 2,500 chars; S3/S4/S5: 3,000; DC: 3,000 cap).
- Episode context: host asset, Debian release, CVE, source package, whether the tracker was available.
- DC only (primary): additionally the controller evidence state exactly as passed to DC's response prompt
  (atom values, supporting groups, evidence ids) as an item labelled `[state]`. Sensitivity: DC judged
  against the tool outputs only.

## 3. Claim extraction
- One extraction call per episode; JSON schema `{claims:[{claim, citations}]}`, temperature 0, ≤ 12 claims.
- Extractor: gemma_4_31b, except for gemma4_31b-generated episodes, which use granite_41_30b (an extractor is
  never of the generator's family). Prompt: `src/deepcti/judge/prompts.py::EXTRACT_SYSTEM`.
- Extraction fidelity check (deterministic): fraction of claims whose version strings and call ids all occur
  in the source explanation.

## 4. Judges
- Candidates (five families): gemma_4_31b (gemma), mistral_small_24b (mistral), qwen3_14b (qwen; thinking
  disabled), granite_41_30b (granite), nemotron_super_49b (llama lineage). Every candidate judges every claim
  (per-claim calls, evidence first, claim last), JSON schema `{reasoning, label}`, label in
  {supported, contradicted, not_in_evidence}, temperature 0, seed 0.
- A judge is never applied to episodes of its own family: nemotron_super_49b is ineligible for llama31_8b
  episodes, granite_41_30b for granite41_8b, gemma_4_31b for gemma4_31b, mistral_small_24b for
  mistral_small_24b, qwen3_14b for qwen3_14b and qwen3_4b. Labels from ineligible judges are still used for
  inter-judge agreement and for perturbation-pool construction (no system-level quantity).

## 5. Judge validation (no humans)
(a) Inter-judge agreement over all judged claims (≥ 300 required): Fleiss κ (5 judges) and pairwise Cohen κ,
3-class and binary (supported vs not).

(b) Perturbation test (`src/deepcti/judge/perturb.py`, seed 20261005):
- Pool: claims labelled supported by ≥ 3 of the 5 judges.
- Four deterministic minimal edits, 75 claims each (300 injected errors), disjoint base claims, sampled
  round-robin over systems:
  - `wrong_version`: the first version string (contains a digit and a '.') has its first numeric component
    incremented by 1 (after any epoch); the new string must not occur anywhere in the evidence.
  - `flipped_polarity` (claims without a status word): remove the first negation (`not`, `n't`, `no`), or, if
    none, insert `not` after the first auxiliary (is/are/was/were/has/have/had/does/do/did/can).
  - `wrong_status` (claims with a status word): not affected → affected; affected → not affected; fixed →
    affected; vulnerable ↔ not vulnerable; under investigation → fixed (`fixed version` is never edited).
  - `invented_id`: replace the first cited call id with `c{max+5:03d}` (absent from the episode); a claim with no
    call-id citation gets ` [c{max+5:03d}]` appended.
- Controls: 150 further pool claims, untouched (disjoint from the bases).
- Scoring per judge J, restricted to items whose base claim is supported by ≥ 3 of the other 4 judges
  (leave-one-out reference, so J's own label does not define its controls): recall = injected items labelled
  contradicted or not_in_evidence; false-alarm = controls labelled contradicted or not_in_evidence. Recall is
  pooled over the four edit types (per-type recall reported).

**Rule (fixed here): a judge is used for the main metrics only if injected-error recall ≥ 0.85 and control
false-alarm ≤ 0.10.** If fewer than two judges pass, metrics are still reported per judge but flagged as not
validated.

## 6. Metrics (per system x generator x arm, and per system x arm pooled over generators)
For each claim, the eligible validated judges (pass rule and not of the generator's family) each give a label;
the claim's score for a label is the fraction of eligible validated judges giving it (soft label).
- Faithfulness = Σ soft(supported) / #claims. Hallucination rate = Σ soft(contradicted + not_in_evidence) /
  #claims, reported also split into contradicted and not_in_evidence.
- Explanation–decision consistency: each eligible validated judge reads the explanation only (no evidence)
  and returns the asserted status (affected/not_affected/fixed/under_investigation/none); consistency = fraction
  of judges whose asserted status equals the submitted status; averaged over episodes. Inter-judge κ reported.
- Citation validity (DC primary; reported for any system whose claims cite call ids): for every claim citing
  ≥ 1 call id, valid = all cited ids exist in the episode AND the claim is judged supported against the cited
  outputs only (separate judge pass with only those outputs). Also deterministic, on all DC records: share of
  explanations with ≥ 1 call-id citation, share of cited ids that exist.
- Length: characters, words, claims per explanation.
- 95% CIs: CVE-clustered percentile bootstrap (2,000 resamples, seed 0) of the ratio estimators.
- Secondary: faithfulness split by decision correctness (submitted status vs sealed test label, read with
  `load_labels('test', allow_sealed=True)`), DC sensitivity without `[state]`, per-judge metrics.

## 7. DC validation / repair / fallback
Report from raw DC records whatever is recorded about response validation, repair and fallback; if nothing is
recorded, state so explicitly.

## Deviations and post-hoc additions (appended after the runs; the primary metrics and the judge rule above
## were not changed)
1. `wrong_version` perturbations: no DC claim in the pool contains a version string, so the 75 items come from
   S2–S5 only (the round-robin selection is otherwise as specified).
2. 5 of 46,000 claim-judge calls returned unparseable JSON; those labels are missing (no infrastructure errors).
3. Post hoc, added after system-level results were seen (reported as secondary and labelled post hoc):
   coarse explanation–decision consistency (fixed and not_affected treated as one "not affected" class);
   citation-contradicted rate (cited outputs contradict the claim) beside citation validity; faithfulness split
   into status/conclusion claims vs factual-detail claims (status claims = claims matched by the
   `wrong_status` pattern in `perturb.py`); faithfulness by arm x decision correctness; Fleiss κ over the
   validated judges only; count of perturbations that every judge still labels supported.
4. Cache duplicates: in the first pass, a few identical prompts (episodes with identical explanation, context and
   evidence) were sent concurrently and answered twice; vLLM batching makes temperature-0 outputs not always
   bit-identical. The cache keeps the last response per prompt, and every reported output comes from a rerun of
   `run_all.sh` that reads only the cache (two consecutive reruns give byte-identical outputs). Effect versus the
   first pass: ≤ 0.1 pp on any system x arm faithfulness, one control per judge in the perturbation scoring.
