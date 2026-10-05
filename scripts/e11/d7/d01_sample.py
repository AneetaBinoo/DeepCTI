"""E11-D7 step 1: stratified, paired episode sample -> results/v3/e11_d7/sample.csv.

As E11 §1: N distinct D7 test cases drawn stratified (here by ecosystem x variant; proportional allocation,
largest remainder), shuffled, split into one block per generator. For each (generator, case) both systems
(DC, DCv21) x all three arms are taken, so DC and DCv21 are paired on (case_id, model, arm).
"""

from __future__ import annotations

import json
import random
from collections import Counter

import pandas as pd
from common_d7 import ARMS, GENERATORS, OUT, RUNS, SEED, SYSTEMS

from deepcti.eval import data

PER_MODEL = 24
N_CASES = PER_MODEL * len(GENERATORS)  # 168 per system x arm


def main() -> None:
    cases = data.load_cases("test")
    by_s: dict[tuple, list[dict]] = {}
    for c in sorted(cases, key=lambda c: c["case_id"]):
        by_s.setdefault((c["ecosystem"], c["variant"]), []).append(c)
    total = len(cases)
    quota = {s: N_CASES * len(cs) / total for s, cs in by_s.items()}
    alloc = {s: int(q) for s, q in quota.items()}
    for s in sorted(quota, key=lambda s: (-(quota[s] - alloc[s]), s))[:N_CASES - sum(alloc.values())]:
        alloc[s] += 1
    rng = random.Random(SEED)
    picked = []
    for s in sorted(by_s):
        picked += rng.sample(by_s[s], alloc[s])
    rng.shuffle(picked)
    assign = {c["case_id"]: GENERATORS[i // PER_MODEL] for i, c in enumerate(picked)}
    rows = []
    for m in GENERATORS:
        for line in (RUNS / f"{m}.jsonl").read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if assign.get(r["case_id"]) == m and r["system"] in SYSTEMS and r["arm"] in ARMS:
                rows.append({"key": r["key"], "model": m, "system": r["system"], "arm": r["arm"],
                             "case_id": r["case_id"], "cve": r["cve"], "variant": r["variant"],
                             "error": r["error"] is not None})
    eco = {c["case_id"]: c["ecosystem"] for c in cases}
    df = pd.DataFrame(rows)
    df["ecosystem"] = df.case_id.map(eco)
    df = df.sort_values(["model", "case_id", "system", "arm"])
    assert len(df) == N_CASES * len(SYSTEMS) * len(ARMS), len(df)
    df.to_csv(OUT / "sample.csv", index=False)
    print("allocation", {f"{a}/{b}": n for (a, b), n in sorted(alloc.items())})
    print("episodes", len(df), "distinct cases", df.case_id.nunique(), "distinct CVEs", df.cve.nunique(),
          "errors", int(df.error.sum()))
    print(Counter(zip(df.system, df.arm)))


if __name__ == "__main__":
    main()
