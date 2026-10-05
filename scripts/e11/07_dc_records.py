"""E11 step 7: what the raw DC records say about response validation / repair / fallback (PROTOCOL.md §7),
plus deterministic citation checks over ALL DC test episodes (E2, 6 models x 2 arms x 453 cases).

Outputs: dc_records.csv (per model x arm), dc_records_fields.json.
"""

from __future__ import annotations

import json
import re
from collections import Counter

import pandas as pd
from common import GENERATORS, OUT, RUNS

from deepcti.judge.prompts import CITE_RE, call_ids_in

PATTERN = re.compile(r"repair|fallback|valid|retry|regenerat", re.IGNORECASE)
STATUS_WORDS = {"affected": r"\baffected\b", "not_affected": r"\bnot[ _]affected\b", "fixed": r"\bfixed\b",
                "under_investigation": r"\bunder[ _]investigation\b"}


def keys_matching(obj, prefix="") -> set[str]:
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if PATTERN.search(k):
                out.add(path)
            out |= keys_matching(v, path)
    elif isinstance(obj, list):
        for v in obj[:50]:
            out |= keys_matching(v, prefix + "[]")
    return out


def main() -> None:
    rows, fields = [], Counter()
    verdicts = Counter()
    for m in GENERATORS:
        recs = [json.loads(x) for x in (RUNS / f"{m}.jsonl").read_text(encoding="utf-8").splitlines()]
        for arm in ("tracker", "withheld"):
            dc = [r for r in recs if r["system"] == "DC" and r["arm"] == arm]
            n_cite = n_ids = n_exist = n_group = n_group_ok = n_cut = n_empty = n_single = n_trunc_single = 0
            for r in dc:
                fields.update(keys_matching({k: v for k, v in r.items() if k not in ("trace", "calls")}))
                for v in r["extra"].get("assessed_state", {}).get("verdicts", []):
                    verdicts[(v.get("kind"), v.get("accepted"), v.get("reason"))] += 1
                text = (r["explanation"] or "").strip()
                n_empty += not text
                ids = call_ids_in(text)
                have = {c["id"] for c in r["calls"]}
                sources = {c["source"] for c in r["calls"]}
                groups_known = set(sources)
                for v in r["extra"].get("assessed_state", {}).get("state", {}).values():
                    groups_known |= set(v.get("pos_groups", [])) | set(v.get("neg_groups", []))
                n_cite += bool(ids)
                n_ids += len(ids)
                n_exist += sum(i in have for i in ids)
                groups = [g.strip() for grp in CITE_RE.findall(text) for g in grp.split(",")
                          if g.strip() and not re.fullmatch(r"[ch]\d{3}", g.strip())]
                n_group += len(groups)
                n_group_ok += sum(g in groups_known for g in groups)
                n_cut += bool(text) and not re.search(r"[.!?\])\"'`*_]\s*$", text)
                n_single += r["usage"]["calls"] == 1
                n_trunc_single += r["usage"]["calls"] == 1 and r["usage"]["truncations"] > 0
            rows.append({"model": m, "arm": arm, "n_dc_episodes": len(dc), "empty_explanation": n_empty,
                         "with_call_id_citation": n_cite, "share_with_citation": n_cite / len(dc),
                         "cited_call_ids": n_ids, "cited_ids_existing": n_exist,
                         "share_cited_ids_existing": n_exist / n_ids if n_ids else float("nan"),
                         "other_bracket_tokens": n_group, "other_bracket_tokens_naming_a_source_or_group": n_group_ok,
                         "explanation_unterminated": n_cut, "single_llm_call_episodes": n_single,
                         "explain_call_hit_max_tokens": n_trunc_single})
    df = pd.DataFrame(rows)
    tot = df.drop(columns=["model", "arm"]).sum(numeric_only=True)
    tot["share_with_citation"] = tot.with_call_id_citation / tot.n_dc_episodes
    tot["share_cited_ids_existing"] = tot.cited_ids_existing / tot.cited_call_ids
    df = pd.concat([df, pd.DataFrame([{"model": "ALL", "arm": "ALL", **tot.to_dict()}])], ignore_index=True)
    df.to_csv(OUT / "dc_records.csv", index=False)
    (OUT / "dc_records_fields.json").write_text(json.dumps({
        "record_keys_matching_repair_fallback_valid_retry": sorted(fields),
        "note": "keys searched in every DC record (excluding calls/trace) with regex " + PATTERN.pattern,
        "extraction_verifier_verdicts": {f"{k[0]}|accepted={k[1]}|{k[2]}": v for k, v in sorted(
            verdicts.items(), key=lambda kv: -kv[1])},
    }, indent=1))
    print(df.to_string(index=False))
    print("matching keys:", sorted(fields))
    print("verdicts:", verdicts.most_common(10))


if __name__ == "__main__":
    main()
