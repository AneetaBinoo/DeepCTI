"""prereg-v4 H16: fresh (case, generator, arm) sample for the DCv21b note-faithfulness confirmation.

Same design as scripts/e11/d7/d01_sample.py (stratified by ecosystem x variant, proportional allocation with
largest remainder, shuffled, one block of PER_MODEL cases per generator, all three arms), but drawn only from D7 test
cases NOT in the H15 sample (results/v3/e11_d7/sample.csv), for all 8 D7 generators, with a new seed.
Output: data/d7/h16_sample.csv (case_id, model, arm, cve, ecosystem, variant).
"""

from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from deepcti.eval import data  # noqa: E402

GENERATORS = ["gemma4_31b", "granite41_30b", "granite41_8b", "llama31_8b", "mistral_medium_128b",
              "mistral_small_24b", "qwen3_14b", "qwen3_4b"]
ARMS = ["tracker", "withheld", "blind"]
PER_MODEL = 21
SEED = 20261006


def main() -> None:
    data.set_dataset("d7")
    h15 = {r["case_id"] for r in csv.DictReader((ROOT / "results" / "v3" / "e11_d7" / "sample.csv").open())}
    cases = [c for c in data.load_cases("test") if c["case_id"] not in h15]
    n_cases = PER_MODEL * len(GENERATORS)
    by_s: dict[tuple, list[dict]] = {}
    for c in sorted(cases, key=lambda c: c["case_id"]):
        by_s.setdefault((c["ecosystem"], c["variant"]), []).append(c)
    quota = {s: n_cases * len(cs) / len(cases) for s, cs in by_s.items()}
    alloc = {s: int(q) for s, q in quota.items()}
    for s in sorted(quota, key=lambda s: (-(quota[s] - alloc[s]), s))[:n_cases - sum(alloc.values())]:
        alloc[s] += 1
    rng = random.Random(SEED)
    picked = []
    for s in sorted(by_s):
        picked += rng.sample(by_s[s], alloc[s])
    rng.shuffle(picked)
    out = ROOT / "data" / "d7" / "h16_sample.csv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "model", "arm", "cve", "ecosystem", "variant"])
        for i, c in enumerate(picked):
            for arm in ARMS:
                w.writerow([c["case_id"], GENERATORS[i // PER_MODEL], arm, c["cve"], c["ecosystem"], c["variant"]])
    print(f"{len(cases)} eligible cases (H15 excluded: {len(h15)}); picked {len(picked)}; "
          f"{len(picked) * len(ARMS)} triples; CVEs {len({c['cve'] for c in picked})}")
    print({f"{a}/{b}": n for (a, b), n in sorted(alloc.items()) if n})


if __name__ == "__main__":
    main()
