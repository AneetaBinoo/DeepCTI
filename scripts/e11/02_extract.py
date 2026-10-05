"""E11 step 2: replay evidence and extract atomic claims (PROTOCOL.md §2-3).

Outputs: episodes.jsonl (one row per sampled episode), claims.jsonl (one row per claim).
"""

from __future__ import annotations

from common import OUT, EpisodeView, client, load_sampled_records, run_parallel, write_jsonl

from deepcti.judge import prompts as P
from deepcti.judge.perturb import versions_in


def extractor_for(generator: str) -> str:
    return "granite_41_30b" if generator == "gemma4_31b" else "gemma_4_31b"


def main() -> None:
    recs = load_sampled_records()
    views, episodes = {}, []
    for k, r in sorted(recs.items()):
        v = EpisodeView(r)
        views[k] = v
        episodes.append({"key": k, "model": r["model"], "system": r["system"], "arm": r["arm"],
                         "case_id": r["case_id"], "cve": r["cve"], "variant": r["variant"], "status": r["status"],
                         "justification": r["justification"], "parse_ok": r["parse_ok"],
                         "error": r["error"] is not None, "explanation": r["explanation"] or "",
                         "n_chars": len(r["explanation"] or ""), "n_words": len((r["explanation"] or "").split()),
                         "n_tool_calls": len(v.items), "replay_mismatch": v.check["mismatches"],
                         "call_ids": v.ids, "extractor": extractor_for(r["model"])})
    tasks = []
    for e in episodes:
        if e["error"] or not e["explanation"].strip() or e["replay_mismatch"]:
            tasks.append((e["extractor"], lambda: {"parsed": {"claims": []}, "error": "skipped"}))
            continue
        v = views[e["key"]]
        llm = client(e["extractor"], "extract", 1500)
        tasks.append((e["extractor"], lambda llm=llm, v=v, e=e: llm.ask(
            P.EXTRACT_SYSTEM, P.extract_user(v.context, e["explanation"]), P.EXTRACT_SCHEMA)))
    res = run_parallel(tasks, per_judge=16, label="extract")
    claims = []
    for e, out in zip(episodes, res):
        e["extract_error"] = out.get("error") if out.get("error") != "skipped" else None
        cl = ((out.get("parsed") or {}).get("claims") or [])[:12]
        e["n_claims"] = len(cl)
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
    write_jsonl(OUT / "episodes.jsonl", episodes)
    write_jsonl(OUT / "claims.jsonl", claims)
    n_err = sum(1 for e in episodes if e["extract_error"])
    print(f"episodes {len(episodes)} claims {len(claims)} extract_errors {n_err} "
          f"replay_mismatch {sum(1 for e in episodes if e['replay_mismatch'])}")
    print("fidelity_ok", sum(c["fidelity_ok"] for c in claims) / max(1, len(claims)))


if __name__ == "__main__":
    main()
