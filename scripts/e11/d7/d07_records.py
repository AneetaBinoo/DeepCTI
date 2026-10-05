"""E11-D7 step 7: validated-synthesis outcomes and deterministic note checks over ALL D7 test DC/DCv21 records
(7 models x 3 arms x 414 cases), plus a full replay check of every DC/DCv21 episode in the D7 environment.

Outputs: v21_synthesis_rates.csv (per model x arm, + pooled rows), v21_attempt1_error_types.csv,
note_checks_all_records.csv (deterministic citation / status checks, DC vs DCv21), replay_check_all.json.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter

import pandas as pd
from common_d7 import ARMS, GENERATORS, OUT, RUNS

from deepcti.agents.systems import validate_note
from deepcti.judge.d7 import replay_d7, validated_synthesis
from deepcti.judge.prompts import call_ids_in


def err_type(msg: str) -> str:
    if msg.startswith("no evidence ids"):
        return "no_citation"
    if msg.startswith("cited ids do not exist"):
        return "cited_id_missing"
    if msg.startswith("the note must state"):
        return "status_not_stated"
    if msg.startswith("the note asserts 'not affected'"):
        return "status_contradicts_decision"
    if msg.startswith("version-like token"):
        return "version_not_in_cited_evidence"
    return "other"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-replay", action="store_true")
    args = ap.parse_args()
    rows, nrows, etypes = [], [], Counter()
    replay = {"episodes": 0, "prefix_mismatch_episodes": 0, "full_trace_mismatch_episodes": 0, "examples": []}
    for m in GENERATORS:
        recs = [json.loads(x) for x in (RUNS / f"{m}.jsonl").read_text(encoding="utf-8").splitlines()]
        recs = [r for r in recs if r["system"] in ("DC", "DCv21")]
        for r in recs:
            text = (r["explanation"] or "").strip()
            calls = {c["id"]: c for c in r["calls"]}
            full = {t["call_id"]: t["output"] for t in r["trace"] if "call_id" in t}
            ids = call_ids_in(text)
            # deterministic re-check with the DCv21 validator on the full outputs (both systems)
            errs = validate_note(text, r["status"], full) if text else ["empty"]
            vs = validated_synthesis(r) or {}
            nrows.append({"model": m, "system": r["system"], "arm": r["arm"], "error": r["error"] is not None,
                          "empty": not text, "has_citation": bool(ids), "n_ids": len(ids),
                          "n_ids_exist": sum(i in calls for i in ids), "validator_pass": not errs,
                          "chars": len(text),
                          # the DCv21 synthesis prompt says "The decision is FIXED (do not change it)"; notes that copy
                          # the word FIXED although the decision is not 'fixed' (found in E11-D7 judging)
                          "fixed_word_nonfixed": bool(re.search(r"\bFIXED\b", text)) and r["status"] != "fixed",
                          "nonfixed": r["status"] != "fixed",
                          "outcome": ("fallback" if vs.get("fallback") else "repaired" if vs.get("repaired")
                                      else "first_pass") if r["system"] == "DCv21" else "n/a"})
            if r["system"] == "DCv21":
                for e in vs.get("attempt1_errors") or []:
                    etypes[(m, "attempt1", err_type(e))] += 1
                for e in vs.get("attempt2_errors") or []:
                    etypes[(m, "attempt2", err_type(e))] += 1
            if not args.no_replay and r["error"] is None:
                _, chk = replay_d7(r)
                replay["episodes"] += 1
                replay["prefix_mismatch_episodes"] += bool(chk["mismatches"])
                replay["full_trace_mismatch_episodes"] += bool(chk["full_trace_mismatches"])
                if (chk["mismatches"] or chk["full_trace_mismatches"]) and len(replay["examples"]) < 20:
                    replay["examples"].append({"key": r["key"], "prefix": chk["mismatches"],
                                               "full": chk["full_trace_mismatches"]})
        print(m, "done", flush=True)
    nd = pd.DataFrame(nrows)
    v = nd[nd.system == "DCv21"]
    for keys in (["model", "arm"], ["model"], ["arm"], []):
        groups = v.groupby(keys) if keys else [((), v)]
        for k, g in groups:
            k = k if isinstance(k, tuple) else (k,)
            n = len(g)
            rows.append({**{c: x for c, x in zip(keys, k)}, **{c: "ALL" for c in ("model", "arm") if c not in keys},
                         "n": n, "first_pass": (g.outcome == "first_pass").mean(),
                         "repaired": (g.outcome == "repaired").mean(), "fallback": (g.outcome == "fallback").mean(),
                         "attempt1_fail": (g.outcome != "first_pass").mean(),
                         "repair_success_given_fail": ((g.outcome == "repaired").sum()
                                                       / max(1, (g.outcome != "first_pass").sum()))})
    pd.DataFrame(rows).to_csv(OUT / "v21_synthesis_rates.csv", index=False)
    pd.DataFrame([{"model": a, "attempt": b, "error_type": c, "n": n} for (a, b, c), n in sorted(etypes.items())]) \
        .to_csv(OUT / "v21_attempt1_error_types.csv", index=False)
    agg = nd.groupby(["system", "arm"]).agg(n=("empty", "size"), empty=("empty", "mean"),
                                             has_citation=("has_citation", "mean"), n_ids=("n_ids", "sum"),
                                             n_ids_exist=("n_ids_exist", "sum"),
                                             validator_pass=("validator_pass", "mean"), chars=("chars", "mean"),
                                             n_nonfixed=("nonfixed", "sum"), n_FIXED_word_nonfixed=("fixed_word_nonfixed", "sum"))
    agg["FIXED_word_share_of_nonfixed"] = agg.n_FIXED_word_nonfixed / agg.n_nonfixed
    agg["cited_id_exist_share"] = agg.n_ids_exist / agg.n_ids
    agg.reset_index().to_csv(OUT / "note_checks_all_records.csv", index=False)
    if not args.no_replay:
        (OUT / "replay_check_all.json").write_text(json.dumps(replay, indent=1))
    print(pd.DataFrame(rows).query("model=='ALL' or arm=='ALL'").to_string(index=False))
    print(agg.to_string())
    print(json.dumps({k: v for k, v in replay.items() if k != "examples"}))
    _ = ARMS


if __name__ == "__main__":
    main()
