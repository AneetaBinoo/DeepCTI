"""E11-D7b step 7 (POST HOC, D23): validated-synthesis outcomes, deterministic note checks and a full replay check
over ALL X2B (DCv21b) records, with DC and DCv21 on the same (case_id, model, arm) triples for comparison.

As d07_records.py (same outcome definitions, same validator re-check, same "FIXED" count); additionally the strict
(DCv21b) validator is re-applied to all three systems' notes. Outputs (results/v3/e11_d7b): v21b_synthesis_rates.csv,
v21b_attempt_error_types.csv, note_checks_same_triples.csv, replay_check_x2b.json.
"""

from __future__ import annotations

import json
import re
from collections import Counter

import pandas as pd
from common_d7 import GENERATORS, RUNS
from common_d7b import OUT_B, RUNS_B, SYSTEM_B
from d07_records import err_type

from deepcti.agents.systems import validate_note
from deepcti.judge.d7 import replay_d7, validated_synthesis
from deepcti.judge.prompts import call_ids_in


def err_type_b(msg: str) -> str:
    return "status_conflict_other_status" if msg.startswith("the note asserts status") else err_type(msg)


def outcome(r: dict) -> str:
    vs = validated_synthesis(r) or {}
    if r["system"] not in ("DCv21", SYSTEM_B):
        return "n/a"
    if not vs:
        return "missing"
    return "fallback" if vs.get("fallback") else "repaired" if vs.get("repaired") else "first_pass"


def main() -> None:
    b = {}
    for m in GENERATORS:
        for x in (RUNS_B / f"{m}.jsonl").read_text(encoding="utf-8").splitlines():
            r = json.loads(x)
            b[(r["case_id"], r["model"], r["arm"])] = r
    recs = list(b.values())
    for m in GENERATORS:  # DC / DCv21 on the same triples (X2)
        for x in (RUNS / f"{m}.jsonl").read_text(encoding="utf-8").splitlines():
            r = json.loads(x)
            if r["system"] in ("DC", "DCv21") and (r["case_id"], r["model"], r["arm"]) in b:
                recs.append(r)
    nrows, etypes = [], Counter()
    replay = {"episodes": 0, "prefix_mismatch_episodes": 0, "full_trace_mismatch_episodes": 0, "examples": []}
    for r in recs:
        text = (r["explanation"] or "").strip()
        calls = {c["id"]: c for c in r["calls"]}
        full = {t["call_id"]: t["output"] for t in r["trace"] if "call_id" in t}
        ids = call_ids_in(text)
        errs = validate_note(text, r["status"], full) if text else ["empty"]
        errs_s = validate_note(text, r["status"], full, strict=True) if text else ["empty"]
        nonfixed = r["status"] != "fixed"
        nrows.append({"model": r["model"], "system": r["system"], "arm": r["arm"], "status": r["status"],
                      "error": r["error"] is not None, "empty": not text, "has_citation": bool(ids),
                      "n_ids": len(ids), "n_ids_exist": sum(i in calls for i in ids), "validator_pass": not errs,
                      "strict_validator_pass": not errs_s,
                      "other_status_asserted": any(e.startswith("the note asserts status") for e in errs_s),
                      "chars": len(text), "nonfixed": nonfixed,
                      "fixed_word_nonfixed": bool(re.search(r"\bFIXED\b", text)) and nonfixed,
                      "fixed_anycase_nonfixed": bool(re.search(r"\bfixed\b", text, re.I)) and nonfixed,
                      "outcome": outcome(r)})
        if r["system"] in ("DCv21", SYSTEM_B):
            vs = validated_synthesis(r) or {}
            for e in vs.get("attempt1_errors") or []:
                etypes[(r["system"], "attempt1", err_type_b(e))] += 1
            for e in vs.get("attempt2_errors") or []:
                etypes[(r["system"], "attempt2", err_type_b(e))] += 1
        if r["system"] == SYSTEM_B and r["error"] is None:
            _, chk = replay_d7(r)
            replay["episodes"] += 1
            replay["prefix_mismatch_episodes"] += bool(chk["mismatches"])
            replay["full_trace_mismatch_episodes"] += bool(chk["full_trace_mismatches"])
            if (chk["mismatches"] or chk["full_trace_mismatches"]) and len(replay["examples"]) < 20:
                replay["examples"].append({"key": r["key"], "prefix": chk["mismatches"],
                                           "full": chk["full_trace_mismatches"]})
    replay["records_with_error"] = sum(1 for r in recs if r["system"] == SYSTEM_B and r["error"] is not None)
    nd = pd.DataFrame(nrows)
    rows = []
    for sysname in ("DCv21", SYSTEM_B):
        v = nd[nd.system == sysname]
        for keys in (["model", "arm"], ["model"], ["arm"], []):
            groups = v.groupby(keys) if keys else [((), v)]
            for k, g in groups:
                k = k if isinstance(k, tuple) else (k,)
                rows.append({"system": sysname, **{c: x for c, x in zip(keys, k)},
                             **{c: "ALL" for c in ("model", "arm") if c not in keys}, "n": len(g),
                             "missing": (g.outcome == "missing").mean(),
                             "first_pass": (g.outcome == "first_pass").mean(),
                             "repaired": (g.outcome == "repaired").mean(),
                             "fallback": (g.outcome == "fallback").mean(),
                             "attempt1_fail": (g.outcome != "first_pass").mean(),
                             "repair_success_given_fail": ((g.outcome == "repaired").sum()
                                                           / max(1, (g.outcome != "first_pass").sum()))})
    rates = pd.DataFrame(rows)
    rates.to_csv(OUT_B / "v21b_synthesis_rates.csv", index=False)
    pd.DataFrame([{"system": a, "attempt": b_, "error_type": c, "n": n} for (a, b_, c), n in sorted(etypes.items())]) \
        .to_csv(OUT_B / "v21b_attempt_error_types.csv", index=False)
    agg_spec = dict(n=("empty", "size"), empty=("empty", "mean"), has_citation=("has_citation", "mean"),
                    n_ids=("n_ids", "sum"), n_ids_exist=("n_ids_exist", "sum"),
                    validator_pass=("validator_pass", "mean"), strict_validator_pass=("strict_validator_pass", "mean"),
                    other_status_asserted=("other_status_asserted", "mean"), chars=("chars", "mean"),
                    n_nonfixed=("nonfixed", "sum"), n_FIXED_word_nonfixed=("fixed_word_nonfixed", "sum"),
                    n_fixed_anycase_nonfixed=("fixed_anycase_nonfixed", "sum"))
    parts = []
    for keys in (["system", "arm"], ["system"]):
        a = nd.groupby(keys).agg(**agg_spec).reset_index()
        if "arm" not in keys:
            a["arm"] = "ALL"
        parts.append(a)
    agg = pd.concat(parts, ignore_index=True)
    agg["FIXED_word_share_of_nonfixed"] = agg.n_FIXED_word_nonfixed / agg.n_nonfixed
    agg["fixed_anycase_share_of_nonfixed"] = agg.n_fixed_anycase_nonfixed / agg.n_nonfixed
    agg["cited_id_exist_share"] = agg.n_ids_exist / agg.n_ids
    agg.to_csv(OUT_B / "note_checks_same_triples.csv", index=False)
    (OUT_B / "replay_check_x2b.json").write_text(json.dumps(replay, indent=1))
    print(rates.query("model=='ALL' or arm=='ALL'").to_string(index=False))
    print(agg.to_string())
    print(json.dumps({k: v for k, v in replay.items() if k != "examples"}))


if __name__ == "__main__":
    main()
