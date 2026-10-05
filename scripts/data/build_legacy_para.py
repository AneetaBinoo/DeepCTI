"""Build `legacy-para` (data/d4/legacy_para.jsonl): LLM paraphrases of every distinct v0 evidence sentence.

* Generators: qwen3_14b and mistral_small_24b, 5 paraphrases each per sentence (one call returning a
  JSON list of 5), temperature 0.7, fixed seed.
* Filter: gemma_4_31b judges (temperature 0) whether the decision-relevant meaning is preserved
  (product presence/absence, version status, rollback availability, approval polarity, hedging).
  DEVIATION FROM PLAN: no human filtering; the dataset is labelled `filter_status=auto_llm_judge`.
* Gold atoms for every row are the v0 regex atoms of the ORIGINAL sentence (correct on originals by
  construction of the v0 generator).
* Distance: 1 - token Jaccard(original, paraphrase) on lower-cased alphanumeric tokens.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter
from pathlib import Path

from deepcti.legacy_eval.client import ENDPOINTS, CachedChat
from deepcti.legacy_eval.sentences import ROOT, distinct_sentences, jaccard_distance, load_cases

GENERATORS = ("qwen3_14b", "mistral_small_24b")
JUDGE = "gemma_4_31b"
N_PARA = 5
SEED = 20261005
OUT = ROOT / "data" / "d4" / "legacy_para.jsonl"
META = ROOT / "data" / "d4" / "legacy_para_meta.json"
CACHE = ROOT / "data" / "d4" / "cache" / "legacy_para_llm_cache.jsonl"

PARA_SCHEMA = {
    "type": "object",
    "properties": {
        "paraphrases": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": N_PARA,
            "maxItems": N_PARA,
        }
    },
    "required": ["paraphrases"],
    "additionalProperties": False,
}
JUDGE_SCHEMA = {
    "type": "object",
    "properties": {"reason": {"type": "string"}, "meaning_preserved": {"type": "boolean"}},
    "required": ["reason", "meaning_preserved"],
    "additionalProperties": False,
}

PARA_PROMPT = """You rewrite short IT-operations evidence statements for a robustness test.
Write {n} different paraphrases of the statement below. Each paraphrase must:
- keep exactly the same facts: whether the product is installed / not installed / possibly present / of \
unknown presence, whether its version is affected / unaffected / unknown, whether a tested rollback is \
available or not, and whether change approval is granted or withheld; keep hedges (e.g. "may", \
"potentially") and negations;
- keep product names and CVE identifiers verbatim;
- not add or remove any information;
- use different wording and sentence structure from the original and from each other (use synonyms, \
reorder clauses, change voice), as a different analyst would write it.

Statement: "{text}"

Return JSON with the key "paraphrases" (a list of {n} strings)."""

JUDGE_PROMPT = """You check whether a paraphrase preserves the decision-relevant meaning of an IT-operations \
evidence statement. Compare ORIGINAL and PARAPHRASE on each of:
1. product presence: installed / not installed (absent) / possibly present / unknown (missing data);
2. version status: affected / unaffected / unknown or not verified;
3. rollback plan: tested rollback available / unavailable / not mentioned;
4. change approval: approved / withheld / not mentioned;
5. hedging and negation (e.g. "may be present", "potentially affected", "cannot yet reconcile").
The paraphrase preserves meaning only if ALL of these are identical (including "not mentioned") and it \
adds no new facts. Wording differences are fine.

ORIGINAL: "{original}"
PARAPHRASE: "{paraphrase}"

Return JSON with "reason" (one short sentence) and "meaning_preserved" (true/false)."""


async def build(limit: int | None) -> None:
    sentences = distinct_sentences(load_cases())
    if limit:
        sentences = sentences[:limit]
    chat = CachedChat(CACHE, max_tokens=1200)

    async def paraphrase(sent: dict, gen: str) -> list[str]:
        msg = [{"role": "user", "content": PARA_PROMPT.format(n=N_PARA, text=sent["text"])}]
        row = await chat.json_chat(ENDPOINTS[gen], msg, PARA_SCHEMA, temperature=0.7, seed=SEED)
        items = (row.get("parsed") or {}).get("paraphrases") or []
        return [" ".join(str(x).split()) for x in items][:N_PARA]

    async def judge(original: str, para: str) -> tuple[bool | None, str]:
        msg = [{"role": "user", "content": JUDGE_PROMPT.format(original=original, paraphrase=para)}]
        row = await chat.json_chat(ENDPOINTS[JUDGE], msg, JUDGE_SCHEMA, temperature=0.0, seed=SEED)
        parsed = row.get("parsed") or {}
        value = parsed.get("meaning_preserved")
        return (value if isinstance(value, bool) else None), str(parsed.get("reason", row.get("error", "")))

    jobs = [(s, g) for s in sentences for g in GENERATORS]
    para_lists = await asyncio.gather(*(paraphrase(s, g) for s, g in jobs))
    candidates = []
    for (sent, gen), paras in zip(jobs, para_lists, strict=True):
        for index, text in enumerate(paras):
            candidates.append((sent, gen, index, text))
    verdicts = await asyncio.gather(*(judge(s["text"], t) for s, _, _, t in candidates))
    chat.close()

    rows = []
    for sent in sentences:
        base = {k: sent[k] for k in ("sent_id", "template_id", "profile", "field", "source_type")}
        base |= {"reliability": sent["reliability"], "step": sent["step"], "gold_atoms": sent["gold_atoms"]}
        base |= {"original": sent["text"], "n_cases": len(sent["case_ids"]), "case_ids": sent["case_ids"]}
        rows.append(
            base
            | {
                "item_id": f"{sent['sent_id']}-orig",
                "kind": "original",
                "generator": None,
                "text": sent["text"],
                "distance": 0.0,
                "judge_preserved": True,
                "judge_reason": "original",
                "kept": True,
                "filter_status": "original",
            }
        )
    by_sent = {r["sent_id"]: r for r in rows}
    seen_text: set[tuple[str, str]] = set()
    for (sent, gen, index, text), (preserved, reason) in zip(candidates, verdicts, strict=True):
        duplicate = (sent["sent_id"], text.lower()) in seen_text or text == sent["text"]
        seen_text.add((sent["sent_id"], text.lower()))
        base = {k: v for k, v in by_sent[sent["sent_id"]].items() if k not in {"item_id", "text"}}
        rows.append(
            base
            | {
                "item_id": f"{sent['sent_id']}-{gen}-{index}",
                "kind": "paraphrase",
                "generator": gen,
                "text": text,
                "distance": round(jaccard_distance(sent["text"], text), 4),
                "judge_preserved": preserved,
                "judge_reason": reason,
                "kept": bool(preserved) and bool(text) and not duplicate,
                "duplicate": duplicate,
                "filter_status": "auto_llm_judge",
            }
        )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    paras = [r for r in rows if r["kind"] == "paraphrase"]
    meta = {
        "dataset": "legacy-para",
        "filter_status": "AUTOMATICALLY FILTERED by LLM judge (gemma_4_31b); NOT human-verified "
        "(deviation from plan: human filtering not possible in this run)",
        "source": str(LEGACY_DATASET_REL),
        "generators": list(GENERATORS),
        "judge": JUDGE,
        "paraphrases_per_generator": N_PARA,
        "generator_temperature": 0.7,
        "seed": SEED,
        "distinct_sentences": len(sentences),
        "distinct_templates": len({s["template_id"] for s in sentences}),
        "paraphrases_generated": len(paras),
        "paraphrases_kept": sum(r["kept"] for r in paras),
        "kept_by_generator": dict(Counter(r["generator"] for r in paras if r["kept"])),
        "judge_rejected": sum(r["judge_preserved"] is False for r in paras),
        "judge_unparsed": sum(r["judge_preserved"] is None for r in paras),
        "duplicates": sum(bool(r.get("duplicate")) for r in paras),
        "gold_atoms": "v0 regex extract_observations() on the ORIGINAL sentence (with original field)",
        "distance": "1 - Jaccard(lower-cased alphanumeric token sets)",
        "llm_calls": chat.calls,
        "llm_errors": chat.errors,
    }
    META.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))


LEGACY_DATASET_REL = Path("data/derived/deepcti_kev_contextual_synthetic_100_v1.jsonl")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, help="only the first N distinct sentences (smoke test)")
    asyncio.run(build(parser.parse_args().limit))


if __name__ == "__main__":
    main()
