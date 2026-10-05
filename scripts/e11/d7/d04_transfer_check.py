"""E11-D7 step 4 (secondary): does the E11 judge validation transfer to D7? Reduced perturbation test
(PROTOCOL.md §5b edits, same code) on D7 DC/DCv21 claims; the judge set is NOT changed by this check (the
E11-validated judges are used as pre-registered); it is reported as a transfer check only.

Pool: claims labelled supported by all three validated judges (main mode). 40 items per edit type, 80
controls, round-robin over DC/DCv21. Scoring per judge: items whose base claim the other two judges label
supported (leave-one-out reference). Outputs: transfer_perturbations.jsonl, transfer_judgments.jsonl,
transfer_validation.csv, transfer_validation_by_type.csv.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

import pandas as pd
from common_d7 import (
    OUT,
    SEED,
    SYSTEMS,
    VALIDATED,
    EpisodeView,
    client,
    load_sampled_records,
    read_jsonl,
    run_parallel,
    write_jsonl,
)

from deepcti.judge import prompts as P
from deepcti.judge.perturb import TYPES, perturb

PER_TYPE, N_CONTROLS = 40, 80
RECALL_MIN, FA_MAX = 0.85, 0.10


def order_key(cid: str) -> str:
    return hashlib.sha256(f"{SEED}:{cid}".encode()).hexdigest()


def main() -> None:
    claims = {c["cid"]: c for c in read_jsonl(OUT / "claims.jsonl")}
    labels: dict[str, dict[str, str]] = defaultdict(dict)
    for j in read_jsonl(OUT / "judgments.jsonl"):
        if j["mode"] == "main" and j["label"]:
            labels[j["cid"]][j["judge"]] = j["label"]
    pool = sorted([cid for cid, d in labels.items()
                   if len(d) == len(VALIDATED) and all(v == "supported" for v in d.values())], key=order_key)
    recs = load_sampled_records()
    views: dict[str, EpisodeView] = {}

    def view(key):
        if key not in views:
            views[key] = EpisodeView(recs[key])
        return views[key]

    by_sys = {s: [cid for cid in pool if claims[cid]["system"] == s] for s in SYSTEMS}
    used: set[str] = set()
    items = []
    for kind in list(TYPES) + ["control"]:
        target = N_CONTROLS if kind == "control" else PER_TYPE
        ptr = {s: 0 for s in SYSTEMS}
        n = 0
        while n < target and any(ptr[s] < len(by_sys[s]) for s in SYSTEMS):
            for s in SYSTEMS:
                if n >= target:
                    break
                while ptr[s] < len(by_sys[s]):
                    cid = by_sys[s][ptr[s]]
                    ptr[s] += 1
                    if cid in used:
                        continue
                    c = claims[cid]
                    v = view(c["key"])
                    new = c["claim"] if kind == "control" else perturb(
                        kind, c["claim"], evidence_text=v.evidence_text_all(), existing_ids=v.ids)
                    if new is None or (kind != "control" and new == c["claim"]):
                        continue
                    used.add(cid)
                    items.append({"pid": f"{kind}:{cid}", "kind": kind, "base_cid": cid, "key": c["key"],
                                  "system": s, "model": c["model"], "original": c["claim"], "claim": new})
                    n += 1
                    break
        print(kind, n, flush=True)
    print("pool", len(pool))
    write_jsonl(OUT / "transfer_perturbations.jsonl", items)
    tasks, meta = [], []
    for it in items:
        v = view(it["key"])
        user = P.judge_user(v.context, v.evidence(with_state=it["system"] == "DC"), it["claim"])
        for j in VALIDATED:
            llm = client(j, "judge")
            tasks.append((j, lambda llm=llm, user=user: llm.ask(P.JUDGE_SYSTEM, user, P.JUDGE_SCHEMA)))
            meta.append({"pid": it["pid"], "judge": j})
    res = run_parallel(tasks, log_every=200, label="transfer")
    rows = [{**m, "label": (r.get("parsed") or {}).get("label"), "error": r.get("error")} for m, r in zip(meta, res)]
    write_jsonl(OUT / "transfer_judgments.jsonl", rows)
    plab: dict[str, dict[str, str]] = defaultdict(dict)
    for r in rows:
        if r["label"]:
            plab[r["pid"]][r["judge"]] = r["label"]
    vrows, trows = [], []
    for j in VALIDATED:
        others = [x for x in VALIDATED if x != j]
        hit = defaultdict(lambda: [0, 0])
        for it in items:
            base = labels.get(it["base_cid"], {})
            if not all(base.get(o) == "supported" for o in others):
                continue
            lab = plab.get(it["pid"], {}).get(j)
            if lab is None:
                continue
            hit[it["kind"]][1] += 1
            hit[it["kind"]][0] += lab != "supported"
        ik = sum(v[0] for k, v in hit.items() if k != "control")
        inn = sum(v[1] for k, v in hit.items() if k != "control")
        fk, fn = hit["control"]
        rec, fa = ik / max(1, inn), fk / max(1, fn)
        vrows.append({"judge": j, "n_injected": inn, "recall": rec, "n_controls": fn, "false_alarm": fa,
                      "would_pass_e11_rule": bool(rec >= RECALL_MIN and fa <= FA_MAX)})
        for kind, (k, n) in sorted(hit.items()):
            trows.append({"judge": j, "kind": kind, "n": n, "flagged": k, "rate": k / n if n else float("nan")})
    pd.DataFrame(vrows).to_csv(OUT / "transfer_validation.csv", index=False)
    pd.DataFrame(trows).to_csv(OUT / "transfer_validation_by_type.csv", index=False)
    print(pd.DataFrame(vrows).to_string(index=False))


if __name__ == "__main__":
    main()
