"""E11 step 3: every candidate judge labels every claim (PROTOCOL.md §4, §6).

Modes: main (DC evidence includes [state]); dc_nostate (DC sensitivity); cited (claims with call-id citations,
judged against the cited outputs only). Plus asserted-status judging per episode.
Outputs: judgments.jsonl, status_judgments.jsonl.
"""

from __future__ import annotations

import argparse

from common import JUDGE_NAMES, OUT, EpisodeView, client, load_sampled_records, read_jsonl, run_parallel, write_jsonl

from deepcti.judge import prompts as P


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-judge", type=int, default=None)
    args = ap.parse_args()
    recs = load_sampled_records()
    episodes = {e["key"]: e for e in read_jsonl(OUT / "episodes.jsonl")}
    claims = read_jsonl(OUT / "claims.jsonl")
    views = {k: EpisodeView(recs[k]) for k in {c["key"] for c in claims}}
    tasks, meta = [], []

    def add(judge, mode, cid, system, user):
        llm = client(judge, "judge")
        tasks.append((judge, lambda: llm.ask(P.JUDGE_SYSTEM, user, P.JUDGE_SCHEMA)))
        meta.append({"cid": cid, "judge": judge, "mode": mode})

    for c in claims:
        v = views[c["key"]]
        ev_main = v.evidence(with_state=True)
        ev_plain = v.evidence(with_state=False) if c["system"] == "DC" else None
        cited = set(c["call_ids"])
        exists = [x for x in c["call_ids"] if x in v.ids]
        ev_cited = v.evidence(only=set(exists)) if cited and len(exists) == len(cited) else None
        for j in JUDGE_NAMES:
            add(j, "main", c["cid"], c["system"], P.judge_user(v.context, ev_main, c["claim"]))
            if ev_plain is not None:
                add(j, "dc_nostate", c["cid"], c["system"], P.judge_user(v.context, ev_plain, c["claim"]))
            if ev_cited is not None:
                add(j, "cited", c["cid"], c["system"], P.judge_user(v.context, ev_cited, c["claim"]))
    res = run_parallel(tasks, per_judge=args.per_judge, log_every=2000, label="judge")
    rows = []
    for m, r in zip(meta, res):
        rows.append({**m, "label": (r.get("parsed") or {}).get("label"), "error": r.get("error")})
    write_jsonl(OUT / "judgments.jsonl", rows)
    print("judgments", len(rows), "errors", sum(1 for r in rows if r["error"]))

    stasks, smeta = [], []
    for k, e in sorted(episodes.items()):
        if e["error"] or not e["explanation"].strip():
            continue
        ctx = views[k].context if k in views else EpisodeView(recs[k]).context
        for j in JUDGE_NAMES:
            llm = client(j, "status", 60)
            stasks.append((j, lambda llm=llm, ctx=ctx, e=e: llm.ask(
                P.STATUS_SYSTEM, P.status_user(ctx, e["explanation"]), P.STATUS_SCHEMA, 60)))
            smeta.append({"key": k, "judge": j})
    sres = run_parallel(stasks, per_judge=args.per_judge, log_every=2000, label="status")
    srows = [{**m, "asserted_status": (r.get("parsed") or {}).get("asserted_status"), "error": r.get("error")}
             for m, r in zip(smeta, sres)]
    write_jsonl(OUT / "status_judgments.jsonl", srows)
    print("status judgments", len(srows), "errors", sum(1 for r in srows if r["error"]))


if __name__ == "__main__":
    main()
