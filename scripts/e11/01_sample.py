"""E11 step 1: stratified episode sample (PROTOCOL.md §1) -> results/v3/e11/sample.csv."""

from __future__ import annotations

import json
import random
from collections import Counter

import pandas as pd
from common import ARMS, GENERATORS, OUT, RUNS, SEED, SYSTEMS, read_jsonl  # noqa: F401

from deepcti.eval import data

N_CASES, PER_MODEL = 180, 30


def main() -> None:
    cases = data.load_cases("test")
    by_var: dict[str, list[dict]] = {}
    for c in sorted(cases, key=lambda c: c["case_id"]):
        by_var.setdefault(c["variant"], []).append(c)
    total = len(cases)
    quota = {v: N_CASES * len(cs) / total for v, cs in by_var.items()}
    alloc = {v: int(q) for v, q in quota.items()}
    for v in sorted(quota, key=lambda v: (-(quota[v] - alloc[v]), v))[:N_CASES - sum(alloc.values())]:
        alloc[v] += 1
    rng = random.Random(SEED)
    picked = []
    for v in sorted(by_var):
        picked += rng.sample(by_var[v], alloc[v])
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
    df = pd.DataFrame(rows).sort_values(["model", "case_id", "system", "arm"])
    assert len(df) == N_CASES * len(SYSTEMS) * len(ARMS), len(df)
    df.to_csv(OUT / "sample.csv", index=False)
    print("allocation", alloc, "episodes", len(df), "distinct CVEs", df.cve.nunique())
    print(Counter(zip(df.system, df.arm)))


if __name__ == "__main__":
    main()
