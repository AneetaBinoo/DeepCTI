"""E11-D7 step 3: claim judging with the E11-validated judges (PROTOCOL.md §4, §6).

Stage "primary": mode main for every claim x every validated judge (ineligible same-family labels are kept for
agreement only), mode cited (claims citing call ids that all exist; eligible judges), asserted-status judging per
episode (eligible judges). Evidence: replayed tool outputs (3,000-char cap) + DC's controller [state] for DC
(as E11 primary); DCv21's synthesis prompt never received the state, so its primary evidence is the tool outputs.
Stage "sensitivity": dc_nostate (DC without [state]) and v21_state (DCv21 with [state]); eligible judges.
Outputs: judgments.jsonl, status_judgments.jsonl (all stages merged; rerun reads the caches).
"""

from __future__ import annotations

import argparse

from common_d7 import (
    OUT,
    VALIDATED,
    EpisodeView,
    client,
    load_sampled_records,
    read_jsonl,
    run_parallel,
    write_jsonl,
)

from deepcti.judge import prompts as P
from deepcti.judge.d7 import eligible_d7


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stages", default="primary,sensitivity")
    args = ap.parse_args()
    stages = set(args.stages.split(","))
    recs = load_sampled_records()
    episodes = {e["key"]: e for e in read_jsonl(OUT / "episodes.jsonl")}
    claims = read_jsonl(OUT / "claims.jsonl")
    views = {k: EpisodeView(recs[k]) for k in episodes}
    tasks, meta = [], []

    def add(judge, mode, cid, user):
        llm = client(judge, "judge")
        tasks.append((judge, lambda: llm.ask(P.JUDGE_SYSTEM, user, P.JUDGE_SCHEMA)))
        meta.append({"cid": cid, "judge": judge, "mode": mode})

    # order: all main calls first (evidence-first prompts -> prefix-cache reuse), then the rest
    if "primary" in stages:
        for c in claims:
            v = views[c["key"]]
            ev = v.evidence(with_state=c["system"] == "DC")
            for j in VALIDATED:
                add(j, "main", c["cid"], P.judge_user(v.context, ev, c["claim"]))
        for c in claims:
            v = views[c["key"]]
            cited = set(c["call_ids"])
            exists = [x for x in c["call_ids"] if x in v.ids]
            if cited and len(exists) == len(cited):
                ev = v.evidence(with_state=False, only=set(exists))
                for j in VALIDATED:
                    if eligible_d7(j, c["model"]):
                        add(j, "cited", c["cid"], P.judge_user(v.context, ev, c["claim"]))
    if "sensitivity" in stages:
        for c in claims:
            v = views[c["key"]]
            mode = "dc_nostate" if c["system"] == "DC" else "v21_state"
            if v.state is None:
                continue
            ev = v.evidence(with_state=c["system"] != "DC")
            for j in VALIDATED:
                if eligible_d7(j, c["model"]):
                    add(j, mode, c["cid"], P.judge_user(v.context, ev, c["claim"]))
    res = run_parallel(tasks, log_every=1000, label="judge")
    new = [{**m, "label": (r.get("parsed") or {}).get("label"), "error": r.get("error")} for m, r in zip(meta, res)]
    done_modes = {m["mode"] for m in meta}
    old = [r for r in read_jsonl(OUT / "judgments.jsonl") if r["mode"] not in done_modes]
    write_jsonl(OUT / "judgments.jsonl", old + new)
    print("judgments", len(new), "errors", sum(1 for r in new if r["error"]), "modes", sorted(done_modes))

    if "primary" in stages:
        stasks, smeta = [], []
        for k, e in sorted(episodes.items()):
            if e["error"] or not e["explanation"].strip():
                continue
            for j in VALIDATED:
                if not eligible_d7(j, e["model"]):
                    continue
                llm = client(j, "status", 60)
                stasks.append((j, lambda llm=llm, ctx=views[k].context, e=e: llm.ask(
                    P.STATUS_SYSTEM, P.status_user(ctx, e["explanation"]), P.STATUS_SCHEMA, 60)))
                smeta.append({"key": k, "judge": j})
        sres = run_parallel(stasks, log_every=1000, label="status")
        srows = [{**m, "asserted_status": (r.get("parsed") or {}).get("asserted_status"), "error": r.get("error")}
                 for m, r in zip(smeta, sres)]
        write_jsonl(OUT / "status_judgments.jsonl", srows)
        print("status judgments", len(srows), "errors", sum(1 for r in srows if r["error"]))


if __name__ == "__main__":
    main()
