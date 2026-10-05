"""prereg-v4 H16: confirmatory DCv21b vs DC analyst-note faithfulness on a FRESH sample (data/d7/h16_sample.csv,
disjoint from the H15 sample; all 8 D7 generators).

The E11-D7 pipeline (scripts/e11/d7/d02_extract, d03_judge, d06_metrics) runs unchanged: same prompts, extractor
rule, validated judges, family-eligibility rule, soft labels, bootstrap, sign-flip test and margin (-0.02). Only
the inputs and the output directory differ. Inside the pipeline the DCv21b records carry system="DCv21" (so
DCv21-specific code paths, e.g. validated-synthesis outcome and "no [state]" primary evidence, apply as for H15);
their record keys keep "DCv21b". Outputs: results/v4/h16/ (h16.json = the pre-registered H16 verdict).

  python scripts/e11/h16/run_h16.py [--steps extract,judge,metrics]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "d7"))

import common_d7 as C  # noqa: E402

ROOT = C.ROOT
OUT = ROOT / "results" / "v4" / "h16"
GENERATORS = ["gemma4_31b", "granite41_30b", "granite41_8b", "llama31_8b", "mistral_medium_128b",
              "mistral_small_24b", "qwen3_14b", "qwen3_4b"]


def load_h16_records() -> dict[str, dict]:
    triples = {(r["case_id"], r["model"], r["arm"]) for r in csv.DictReader((ROOT / "data" / "d7" / "h16_sample.csv").open())}
    out = {}
    for m in GENERATORS:
        for exp, system in (("X2", "DC"), ("X2C", "DCv21b")):
            for r in C.read_jsonl(ROOT / "runs" / "d7" / "test" / exp / f"{m}.jsonl"):
                if r["system"] == system and (r["case_id"], r["model"], r["arm"]) in triples:
                    if system == "DCv21b":
                        r = {**r, "system": "DCv21"}
                    out[r["key"]] = r
    per = {}
    for r in out.values():
        per[r["system"]] = per.get(r["system"], 0) + 1
    assert per == {"DC": len(triples), "DCv21": len(triples)}, (per, len(triples))
    return out


C.OUT, C.CACHE, C.GENERATORS = OUT, OUT / "cache", GENERATORS
C.load_sampled_records = load_h16_records


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--steps", default="extract,judge,metrics")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    steps = args.steps.split(",")
    if "extract" in steps:
        import d02_extract
        d02_extract.main()
    if "judge" in steps:
        import d03_judge
        sys.argv = [sys.argv[0], "--stages", "primary,sensitivity"]
        d03_judge.main()
    if "metrics" in steps:
        import d06_metrics
        d06_metrics.main()
        h = json.loads((OUT / "h15.json").read_text())
        res = {"hypothesis": "H16 (prereg-v4): DCv21b - DC claim-level faithfulness > margin (non-inferiority)",
               "note": "pipeline labels: DCv21 = DCv21b", "margin": h["margin"], "diff": h["diff"], "lo": h["lo"],
               "hi": h["hi"], "p_signflip": h["p_signflip"], "faithfulness_DCv21b": h["faithfulness_DCv21"],
               "faithfulness_DC": h["faithfulness_DC"], "n_claims_DCv21b": h["n_claims_DCv21"],
               "n_claims_DC": h["n_claims_DC"], "n_cves": h["n_cves"], "n_pairs": h["n_pairs"],
               "n_pairs_per_arm": h["n_pairs_per_arm"], "H16_holds": h["H15_holds"],
               "share_fallback_DCv21b": h["share_fallback_DCv21"]}
        (OUT / "h16.json").write_text(json.dumps(res, indent=1))
        print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
