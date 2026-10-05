"""E11 step 4: perturbation set (PROTOCOL.md §5b) and its judging by every candidate judge.

Outputs: perturbations.jsonl (items: injected errors + untouched controls), perturb_judgments.jsonl.
"""

from __future__ import annotations

import argparse
import hashlib
from collections import defaultdict

from common import (
    JUDGE_NAMES,
    OUT,
    SEED,
    SYSTEMS,
    EpisodeView,
    client,
    load_sampled_records,
    read_jsonl,
    run_parallel,
    write_jsonl,
)

from deepcti.judge import prompts as P
from deepcti.judge.perturb import TYPES, perturb

PER_TYPE, N_CONTROLS = 75, 150


def order_key(cid: str) -> str:
    return hashlib.sha256(f"{SEED}:{cid}".encode()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-judge", type=int, default=None)
    args = ap.parse_args()
    claims = {c["cid"]: c for c in read_jsonl(OUT / "claims.jsonl")}
    labels: dict[str, dict[str, str]] = defaultdict(dict)
    for j in read_jsonl(OUT / "judgments.jsonl"):
        if j["mode"] == "main" and j["label"]:
            labels[j["cid"]][j["judge"]] = j["label"]
    pool = [cid for cid, d in labels.items()
            if len(d) == len(JUDGE_NAMES) and sum(v == "supported" for v in d.values()) >= 3]
    pool.sort(key=order_key)
    recs = load_sampled_records()
    views: dict[str, EpisodeView] = {}

    def view(key):
        if key not in views:
            views[key] = EpisodeView(recs[key])
        return views[key]

    by_sys = {s: [cid for cid in pool if claims[cid]["system"] == s] for s in SYSTEMS}
    used: set[str] = set()
    items = []
    for kind in TYPES:
        ptr = {s: 0 for s in SYSTEMS}
        n = 0
        while n < PER_TYPE and any(ptr[s] < len(by_sys[s]) for s in SYSTEMS):
            for s in SYSTEMS:
                if n >= PER_TYPE:
                    break
                while ptr[s] < len(by_sys[s]):
                    cid = by_sys[s][ptr[s]]
                    ptr[s] += 1
                    if cid in used:
                        continue
                    c = claims[cid]
                    v = view(c["key"])
                    new = perturb(kind, c["claim"], evidence_text=v.evidence_text_all(), existing_ids=v.ids)
                    if new is None or new == c["claim"]:
                        continue
                    used.add(cid)
                    items.append({"pid": f"{kind}:{cid}", "kind": kind, "base_cid": cid, "key": c["key"],
                                  "system": s, "model": c["model"], "original": c["claim"], "claim": new})
                    n += 1
                    break
        print(kind, n)
    ptr = {s: 0 for s in SYSTEMS}
    n = 0
    while n < N_CONTROLS:
        progressed = False
        for s in SYSTEMS:
            while n < N_CONTROLS and ptr[s] < len(by_sys[s]):
                cid = by_sys[s][ptr[s]]
                ptr[s] += 1
                if cid in used:
                    continue
                used.add(cid)
                c = claims[cid]
                items.append({"pid": f"control:{cid}", "kind": "control", "base_cid": cid, "key": c["key"],
                              "system": s, "model": c["model"], "original": c["claim"], "claim": c["claim"]})
                n += 1
                progressed = True
                break
        if not progressed:
            break
    print("controls", n, "pool", len(pool))
    write_jsonl(OUT / "perturbations.jsonl", items)

    tasks, meta = [], []
    for it in items:
        v = view(it["key"])
        user = P.judge_user(v.context, v.evidence(with_state=True), it["claim"])
        for j in JUDGE_NAMES:
            llm = client(j, "judge")
            tasks.append((j, lambda llm=llm, user=user: llm.ask(P.JUDGE_SYSTEM, user, P.JUDGE_SCHEMA)))
            meta.append({"pid": it["pid"], "judge": j})
    res = run_parallel(tasks, per_judge=args.per_judge, log_every=500, label="perturb")
    rows = [{**m, "label": (r.get("parsed") or {}).get("label"), "error": r.get("error")} for m, r in zip(meta, res)]
    write_jsonl(OUT / "perturb_judgments.jsonl", rows)
    print("perturb judgments", len(rows), "errors", sum(1 for r in rows if r["error"]))


if __name__ == "__main__":
    main()
