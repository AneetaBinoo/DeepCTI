# DeepCTI — pre-registration v4 (tag `prereg-v4`, 2026-10-05)

Builds on prereg-v1/v2/v3 (unchanged). Three new confirmatory hypotheses address the open items of
results/v3/REPORT_V3.md §4: (i) a confirmation of the corrected synthesis prompt (DCv21b, post-hoc in v3, D23);
(ii) a trust-estimation rule that does not discard useful scanners; (iii) robustness of verified extraction to
misleading version mentions in documents the systems actually read. Data: D7 test (sealed labels; v3 hashes
unchanged). All systems, prompts, catalogs and the environment are as at prereg-v3 plus the DEVIATIONS D12–D23 fixes.

## 1. Hypotheses (each decided by its own 95% CI rule; CVE-clustered bootstrap, 10,000 resamples)

**H16 (DCv21b note faithfulness).** On a fresh sample disjoint from the H15 sample, claim-level faithfulness of
DCv21b notes is non-inferior to DC's: lower 95% bound of (DCv21b − DC) > −0.02.
- Sample: `data/d7/h16_sample.csv` (scripts/data/sample_h16.py, seed 20261006): 168 D7 test cases not in
  results/v3/e11_d7/sample.csv, stratified by ecosystem × variant, 21 per generator for all 8 D7 generators
  (adds Mistral-Medium-128B), all three arms: 504 (case, generator, arm) triples per system.
- DCv21b episodes: block X2C (new runs). DC episodes: the existing X2 records of the same triples.
- Pipeline: E11-D7 unchanged (scripts/e11/h16/run_h16.py wraps d02_extract/d03_judge/d06_metrics: same extractor
  rule, validated judges Gemma-4-31B / Granite-4.1-30B / Nemotron-49B, cross-family eligibility; Mistral-Medium
  is family "mistral"; soft labels, margin, bootstrap).

**H17 (scanner trust estimated on more data).** DCt = DC whose per-ecosystem source trust classes are estimated
with the unchanged v2/v3 rule (Wilson-95 upper bounds of FP and FN ≤ 0.10, n ≥ 20) on D7 dev + calib instead of dev
only (`config/source_profiles_v3b.yaml`: scanners trusted for deb-ubuntu and maven; untrusted for pypi and
vendor). D7 test, withheld arm, 8 models, paired with DC (X2) on (case, model):
- supported iff the upper 95% bound of loss(DCt) − loss(DC) < 0, AND the upper 95% bound of
  DER(DCt) − DER(DC) on affected cases ≤ 0.01.
- Reported: coverage, per-model table.

**H18 (decoy version mentions).** Block X6: on every D7 test case where a decoy can be planted, one realistic,
non-instructive wrong-version line is added to the documents the systems read:
- deb (vulnerable hosts): a changelog.Debian body line naming the fixed version;
- vendor: a "See also: <product> <version> release announcement." line in every product document that states the
  true version (decoy = the range bound on the other side of the installed version).

pypi and maven are excluded because the dev pilot showed no system ever opens a document there. Tracker arm; DC,
DC_noverify, S3; 8 models. Compared with the same (case, model) in X2 (clean):
- supported iff the upper 95% bound of DC loss(decoy) − loss(clean) < 0.05 (non-inferiority).
- Secondary, descriptive: the same contrast for DC_noverify and S3; per-system share of episodes that saw the decoy
  line and that accepted the decoy version as a fact.

Pilot (dev, Gemma, logged before the tag): with decoys placed only in non-read documents (CMDB notes, docs/
folder), no system ever observed them; the design above was fixed after that pilot and before any test run.

## 2. Descriptive panel completion (no hypotheses)
- Mistral-Medium-128B: D1 E5 and E9 (spec v2), D7 X2V (verifier fixes).
- GLM-4.5-Air (106B MoE, TP2): D1 E2; D7 X2 and X5. Reported next to the panel; not part of H9–H18.

## 3. Analysis
`scripts/paper/analyze_v4.py` (hash below) → results/v4/ANALYSIS_V4.md. H16 verdict from results/v4/h16/h16.json.
No multiplicity adjustment across H16–H18 (three separate questions, each with a CI rule).

## 4. Hashes (filled at tag time)

| file | SHA-256 |
|---|---|
| `data/d7/h16_sample.csv` | `509518a18d8a1b0936df727edb1cb38bb50ac4ea0a4693eb088913e67fa15aa6` |
| `config/source_profiles_v3b.yaml` | `3a747e06aef37ed4023fcba147cbc33641b9cee4536c41f622d961282f53521d` |
| `scripts/paper/analyze_v4.py` | `d41f993c6f152a37666bb048dc83a41495be496de7be216abfb6fc24867e09c4` |
| `scripts/e11/h16/run_h16.py` | `51e8ae56025267ee4db906ea70a169f8f38ac61f60fc5a8a601e6f2a72a1447e` |
| `scripts/data/sample_h16.py` | `01020853ef766ca4973a23da3ba7798217822620ab40775d3d6efbe6909ac9ef` |
| `src/deepcti/env/host.py` | `a85046eeff2f8d09119ea6045da728d73d6555fcb3b6e0dc02983f68c5c3655c` |
| `src/deepcti/eval/runner.py` | `65a5e5e32501cdaacb0c9c68f8ba1a95ca70d509f6b07ae06e5becfaef47bfd4` |
| `scripts/run/run_experiment.py` | `f3aba0b533794dfbfe59f8d0bbac01fb91ae21bbbf7f92a7706c34d9a14e76a7` |
| `data/sealed/d7_test_labels.jsonl` | `21857ab4dde6fe9a9afde19f23570f96935bc282ed4d0e10b429030685336c21` |
| `results/v3/e11/validated_judges.json` | `13a6a81cdf1381632cf55a4f42c7de347cc3f4d612bc1e751809e019ecd7eef9` |
