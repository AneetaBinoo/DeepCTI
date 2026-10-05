"""E11-D7b step 2 (POST HOC, D23): replay evidence for the DCv21b episodes and extract atomic claims.

Identical to d02_extract.py (same EpisodeView replay, extractor assignment, prompt, schema, 12-claim cap, fidelity
check); input = runs/d7/test/X2B (DCv21b, exactly the H15 sample triples). Outputs (results/v3/e11_d7b):
episodes.jsonl, claims.jsonl (DCv21b only; DC/DCv21 rows are read from results/v3/e11_d7 at the metrics step).
"""

from __future__ import annotations

from common_d7 import EpisodeView, run_parallel, write_jsonl
from common_d7b import OUT_B, SYSTEM_B, client, h15_triples, load_b_records
from d02_extract import extractor_for

from deepcti.judge import prompts as P
from deepcti.judge.d7 import validated_synthesis
from deepcti.judge.perturb import versions_in


def vs_outcome(rec: dict) -> str:
    vs = validated_synthesis(rec)
    if rec["system"] != SYSTEM_B:
        return "n/a"
    if vs is None:
        return "missing"
    if vs.get("fallback"):
        return "fallback"
    if vs.get("repaired"):
        return "repaired"
    return "first_pass"


def main() -> None:
    recs = load_b_records()
    trip = {(r["case_id"], r["model"], r["arm"]) for r in recs.values()}
    assert trip == h15_triples() and len(recs) == len(trip), "X2B triples differ from the H15 DCv21 sample"
    views, episodes = {}, []
    for k, r in sorted(recs.items()):
        v = EpisodeView(r)
        views[k] = v
        vs = validated_synthesis(r) or {}
        episodes.append({"key": k, "model": r["model"], "system": r["system"], "arm": r["arm"],
                         "case_id": r["case_id"], "cve": r["cve"], "variant": r["variant"], "status": r["status"],
                         "justification": r["justification"], "parse_ok": r["parse_ok"],
                         "error": r["error"] is not None, "explanation": r["explanation"] or "",
                         "n_chars": len(r["explanation"] or ""), "n_words": len((r["explanation"] or "").split()),
                         "n_tool_calls": len(v.items), "replay_mismatch": v.check["mismatches"],
                         "replay_full_mismatch": v.check["full_trace_mismatches"],
                         "call_ids": v.ids, "extractor": extractor_for(r["model"]), "vs_outcome": vs_outcome(r),
                         "vs_attempt1_errors": vs.get("attempt1_errors"),
                         "vs_attempt2_errors": vs.get("attempt2_errors")})
    tasks = []
    for e in episodes:
        if e["error"] or not e["explanation"].strip() or e["replay_mismatch"]:
            tasks.append((e["extractor"], lambda: {"parsed": {"claims": []}, "error": "skipped"}))
            continue
        v = views[e["key"]]
        llm = client(e["extractor"], "extract", 1500)
        tasks.append((e["extractor"], lambda llm=llm, v=v, e=e: llm.ask(
            P.EXTRACT_SYSTEM, P.extract_user(v.context, e["explanation"]), P.EXTRACT_SCHEMA)))
    res = run_parallel(tasks, label="extract", log_every=100)
    claims = []
    for e, out in zip(episodes, res):
        e["extract_error"] = out.get("error") if out.get("error") != "skipped" else None
        cl = ((out.get("parsed") or {}).get("claims") or [])[:12]
        e["n_claims"] = 0
        expl = e["explanation"]
        for i, c in enumerate(cl):
            text = str(c.get("claim", "")).strip()
            if not text:
                continue
            vs = versions_in(text)
            ids = P.call_ids_in(text)
            fidelity = all(x in expl for x in vs) and all(x in expl for x in ids)
            claims.append({"cid": f"{e['key']}#{i}", "key": e["key"], "model": e["model"], "system": e["system"],
                           "arm": e["arm"], "cve": e["cve"], "claim": text,
                           "citations": [str(x) for x in c.get("citations", [])], "call_ids": ids,
                           "fidelity_ok": fidelity})
            e["n_claims"] += 1
    write_jsonl(OUT_B / "episodes.jsonl", episodes)
    write_jsonl(OUT_B / "claims.jsonl", claims)
    n_err = sum(1 for e in episodes if e["extract_error"])
    print(f"episodes {len(episodes)} claims {len(claims)} extract_errors {n_err} "
          f"replay_mismatch {sum(1 for e in episodes if e['replay_mismatch'])} "
          f"full_trace_mismatch {sum(1 for e in episodes if e['replay_full_mismatch'])}")
    print("fidelity_ok", sum(c["fidelity_ok"] for c in claims) / max(1, len(claims)))


if __name__ == "__main__":
    main()
