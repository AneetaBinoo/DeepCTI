"""E11-D7b step 3 (POST HOC, D23): claim and asserted-status judging of the DCv21b notes.

Identical to d03_judge.py with DCv21b in the role of DCv21 (its synthesis prompt likewise received only the raw
cited tool outputs, never the controller [state]): stage "primary" = mode main (every validated judge), cited
(eligible judges, all cited ids exist), asserted status per episode (eligible judges); stage "sensitivity" =
v21_state (DCv21b judged with the [state]; eligible judges). DC/DCv21 are NOT re-judged (results/v3/e11_d7 reused).
Outputs (results/v3/e11_d7b): judgments.jsonl, status_judgments.jsonl.
"""

from __future__ import annotations

import argparse

from common_d7 import VALIDATED, EpisodeView, read_jsonl, run_parallel, write_jsonl
from common_d7b import OUT_B, client, load_b_records

from deepcti.judge import prompts as P
from deepcti.judge.d7 import eligible_d7


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stages", default="primary,sensitivity")
    args = ap.parse_args()
    stages = set(args.stages.split(","))
    recs = load_b_records()
    episodes = {e["key"]: e for e in read_jsonl(OUT_B / "episodes.jsonl")}
    claims = read_jsonl(OUT_B / "claims.jsonl")
    views = {k: EpisodeView(recs[k]) for k in episodes}
    tasks, meta = [], []

    def add(judge, mode, cid, user):
        llm = client(judge, "judge")
        tasks.append((judge, lambda: llm.ask(P.JUDGE_SYSTEM, user, P.JUDGE_SCHEMA)))
        meta.append({"cid": cid, "judge": judge, "mode": mode})

    if "primary" in stages:
        for c in claims:
            v = views[c["key"]]
            ev = v.evidence(with_state=c["system"] == "DC")  # False for DCv21b (as DCv21)
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
    res = run_parallel(tasks, log_every=500, label="judge")
    new = [{**m, "label": (r.get("parsed") or {}).get("label"), "error": r.get("error")} for m, r in zip(meta, res)]
    done_modes = {m["mode"] for m in meta}
    old = [r for r in read_jsonl(OUT_B / "judgments.jsonl") if r["mode"] not in done_modes]
    write_jsonl(OUT_B / "judgments.jsonl", old + new)
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
        sres = run_parallel(stasks, log_every=500, label="status")
        srows = [{**m, "asserted_status": (r.get("parsed") or {}).get("asserted_status"), "error": r.get("error")}
                 for m, r in zip(smeta, sres)]
        write_jsonl(OUT_B / "status_judgments.jsonl", srows)
        print("status judgments", len(srows), "errors", sum(1 for r in srows if r["error"]))


if __name__ == "__main__":
    main()
