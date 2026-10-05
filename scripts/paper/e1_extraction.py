"""E1: extraction robustness of the v0 regex extractor vs LLM extraction (with / without span verifier).

Data: data/d4/legacy_para.jsonl (originals + automatically filtered paraphrases; see build_legacy_para.py).
Gold atoms: v0 regex atoms of the ORIGINAL sentence.

Extractors
  regex        v0 `extract_observations` applied to the (paraphrased) text with the original record field.
  llm          LLM returns atoms {field, value} (JSON schema, temperature 0).
  llm_verified LLM returns atoms {field, value, span}. An atom is ACCEPTED iff
                 (a) span occurs verbatim in the sentence (case-insensitive, whitespace-normalised substring),
                 (b) span has >= 3 whitespace tokens, and
                 (c) a second call to the SAME LLM, shown only the span and asked for the value of that
                     field (allowed values + "not_stated"), returns the same value.
               Only accepted atoms are scored.

Metrics: micro atom P/R/F1 vs gold on originals and paraphrases, by paraphrase-distance bin; verifier
acceptance and accepted-atom error rates; downstream applicability from the v0 controller
(EvidenceBackedMemory slot logic) fed with each extractor's atoms vs the v0 reference applicability.
CIs: bootstrap over ORIGINAL sentences (cluster = sentence and all of its paraphrases).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
from collections import defaultdict
from typing import Any

import matplotlib
import numpy as np
import pandas as pd

from deepcti.legacy_eval.client import ENDPOINTS, CachedChat
from deepcti.legacy_eval.sentences import ROOT, load_cases, local_evidence, sentence_key
from deepcti.memory import EvidenceBackedMemory, FactObservation, FactSlot, extract_observations
from deepcti.schemas import EvidenceRecord

matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA = ROOT / "data" / "d4" / "legacy_para.jsonl"
OUT = ROOT / "results" / "v2" / "e1"
CACHE = ROOT / "data" / "d4" / "cache" / "e1_extraction_llm_cache.jsonl"
MODELS = ("qwen3_4b", "granite_41_8b", "llama31_8b", "qwen3_14b", "mistral_small_24b", "gemma_4_31b")
FIELD_VALUES = {
    "product_presence": ["installed", "not_installed", "potential", "unknown"],
    "version_status": ["affected", "unaffected", "unknown"],
    "rollback_plan": ["available", "unavailable"],
    "change_approval": ["approved", "withheld"],
}
DECISION_FIELDS = {"product_presence", "version_status"}
ALL_VALUES = sorted({v for vals in FIELD_VALUES.values() for v in vals})
BINS = [(0.0, 0.0, "0 (original)"), (0.0, 0.4, "[0,0.4)"), (0.4, 0.55, "[0.4,0.55)"),
        (0.55, 0.7, "[0.55,0.7)"), (0.7, 1.01, "[0.7,1]")]
SEED = 20261005
N_BOOT = 1000
VARIANTS_PER_CASE = 10

FIELD_GUIDE = """Fields and allowed values:
- product_presence: installed (the product is stated to be installed/present), not_installed (stated to be \
not installed/absent), potential (possibly present, e.g. only suggested by indirect observation), unknown \
(the statement says installation data is missing or unknown).
- version_status: affected (the installed version is stated to be affected/vulnerable), unaffected (stated \
not affected), unknown (the statement says the version is missing, unverified or not established).
- rollback_plan: available (a tested rollback/backup procedure is available), unavailable (no tested \
rollback is available).
- change_approval: approved (the change/remediation is approved), withheld (approval is withheld/not given).
Report only fields the statement explicitly addresses; at most one atom per field; an empty list if none."""

EXTRACT_PROMPT = """Extract structured facts ("atoms") from an IT-operations evidence statement about a \
software product on an asset.
{guide}

Evidence record type: {field}
Statement: "{text}"

Return JSON {{"atoms": [{{"field": ..., "value": ...}}]}}."""

EXTRACT_SPAN_PROMPT = """Extract structured facts ("atoms") from an IT-operations evidence statement about a \
software product on an asset.
{guide}
For every atom also give "span": an exact, verbatim substring of the statement (at least 3 words) that \
by itself supports the atom.

Evidence record type: {field}
Statement: "{text}"

Return JSON {{"atoms": [{{"field": ..., "value": ..., "span": ...}}]}}."""

RECLASSIFY_PROMPT = """Read this text fragment from an IT-operations evidence statement.
{guide}

Fragment: "{span}"

Using ONLY the fragment, what is the value of the field "{field}"? Answer "not_stated" if the fragment \
alone does not state it. Return JSON {{"value": ...}}."""


def atoms_schema(with_span: bool) -> dict[str, Any]:
    props: dict[str, Any] = {
        "field": {"type": "string", "enum": list(FIELD_VALUES)},
        "value": {"type": "string", "enum": ALL_VALUES},
    }
    if with_span:
        props["span"] = {"type": "string"}
    item = {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}
    return {
        "type": "object",
        "properties": {"atoms": {"type": "array", "items": item, "maxItems": 6}},
        "required": ["atoms"],
        "additionalProperties": False,
    }


def reclass_schema(field: str) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"value": {"type": "string", "enum": [*FIELD_VALUES[field], "not_stated"]}},
        "required": ["value"],
        "additionalProperties": False,
    }


def norm(text: str) -> str:
    return " ".join(text.lower().split())


def clean_atoms(raw: Any) -> tuple[list[dict[str, str]], int]:
    """Keep legal (field, value) pairs, first atom per field. Returns (atoms, n_illegal)."""
    atoms, seen, illegal = [], set(), 0
    for atom in raw if isinstance(raw, list) else []:
        if not isinstance(atom, dict):
            illegal += 1
            continue
        field, value = atom.get("field"), atom.get("value")
        if field not in FIELD_VALUES or value not in FIELD_VALUES[field]:
            illegal += 1
            continue
        if field in seen:
            continue
        seen.add(field)
        atoms.append({k: str(v) for k, v in atom.items()})
    return atoms, illegal


async def run_llm(items: list[dict], models: list[str]) -> list[dict]:
    chat = CachedChat(CACHE, max_tokens=512)
    schema_plain, schema_span = atoms_schema(False), atoms_schema(True)

    async def one(model: str, item: dict) -> list[dict]:
        ep = ENDPOINTS[model]
        common = {"guide": FIELD_GUIDE, "field": item["field"], "text": item["text"]}
        plain_msg = [{"role": "user", "content": EXTRACT_PROMPT.format(**common)}]
        span_msg = [{"role": "user", "content": EXTRACT_SPAN_PROMPT.format(**common)}]
        plain, spanned = await asyncio.gather(
            chat.json_chat(ep, plain_msg, schema_plain), chat.json_chat(ep, span_msg, schema_span)
        )
        out = []
        atoms, illegal = clean_atoms((plain.get("parsed") or {}).get("atoms"))
        out.append(
            {
                "item_id": item["item_id"], "model": model, "extractor": "llm",
                "atoms": [[a["field"], a["value"]] for a in atoms], "proposed": len(atoms),
                "illegal": illegal, "error": plain.get("error"), "calls": 1, "tokens": plain.get("tokens", 0),
            }
        )
        atoms, illegal = clean_atoms((spanned.get("parsed") or {}).get("atoms"))
        checks = []
        for atom in atoms:
            span = atom.get("span", "")
            verbatim = bool(norm(span)) and norm(span) in norm(item["text"])
            long_enough = len(span.split()) >= 3
            checks.append({"atom": atom, "verbatim": verbatim, "long_enough": long_enough})
        reclass_rows = await asyncio.gather(
            *(
                chat.json_chat(
                    ep,
                    [{"role": "user", "content": RECLASSIFY_PROMPT.format(
                        guide=FIELD_GUIDE, span=c["atom"]["span"], field=c["atom"]["field"])}],
                    reclass_schema(c["atom"]["field"]),
                )
                for c in checks
                if c["verbatim"] and c["long_enough"]
            )
        )
        reclass_iter = iter(reclass_rows)
        accepted, detail = [], []
        tokens = spanned.get("tokens", 0)
        for c in checks:
            reclass_value = None
            if c["verbatim"] and c["long_enough"]:
                row = next(reclass_iter)
                tokens += row.get("tokens", 0)
                reclass_value = (row.get("parsed") or {}).get("value")
            consistent = reclass_value == c["atom"]["value"]
            ok = c["verbatim"] and c["long_enough"] and consistent
            detail.append(
                {"field": c["atom"]["field"], "value": c["atom"]["value"], "span": c["atom"].get("span", ""),
                 "verbatim": c["verbatim"], "long_enough": c["long_enough"], "reclass": reclass_value,
                 "accepted": ok}
            )
            if ok:
                accepted.append([c["atom"]["field"], c["atom"]["value"]])
        out.append(
            {
                "item_id": item["item_id"], "model": model, "extractor": "llm_verified", "atoms": accepted,
                "proposed": len(atoms), "proposed_atoms": [[a["field"], a["value"]] for a in atoms],
                "illegal": illegal, "error": spanned.get("error"), "verifier": detail,
                "calls": 1 + len(reclass_rows), "tokens": tokens,
            }
        )
        return out

    results = await asyncio.gather(*(one(m, it) for m in models for it in items))
    chat.close()
    print(f"llm calls made (uncached): {chat.calls}, transport errors: {chat.errors}", flush=True)
    return [row for rows in results for row in rows]


def regex_predictions(items: list[dict]) -> list[dict]:
    rows = []
    for item in items:
        probe = EvidenceRecord(
            evidence_id=item["item_id"], text=item["text"], source_type=item["source_type"], source_uri="",
            case_id="", step=item["step"], field=item["field"], retrieved_at="", content_sha256="",
            reliability=item["reliability"],
        )
        atoms = sorted({(o.field, o.value) for o in extract_observations(probe)})
        rows.append({"item_id": item["item_id"], "model": "regex_v0", "extractor": "regex",
                     "atoms": [list(a) for a in atoms], "proposed": len(atoms), "illegal": 0, "error": None,
                     "calls": 0, "tokens": 0})
    return rows


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def bin_label(kind: str, distance: float) -> str:
    if kind == "original":
        return BINS[0][2]
    for low, high, label in BINS[1:]:
        if low <= distance < high:
            return label
    return BINS[-1][2]


def counts(pred: list[list[str]], gold: list[list[str]], fields: set[str] | None = None) -> tuple[int, int, int]:
    p = {tuple(a) for a in pred if fields is None or a[0] in fields}
    g = {tuple(a) for a in gold if fields is None or a[0] in fields}
    return len(p & g), len(p - g), len(g - p)


def boot_f1(df: pd.DataFrame, cols: tuple[str, str, str], rng: np.random.Generator) -> tuple[float, float]:
    per_sent = df.groupby("sent_id")[list(cols)].sum()
    arr = per_sent.to_numpy()
    if len(arr) == 0:
        return (float("nan"), float("nan"))
    idx = rng.integers(0, len(arr), size=(N_BOOT, len(arr)))
    sums = arr[idx].sum(axis=1)
    tp, fp, fn = sums[:, 0], sums[:, 1], sums[:, 2]
    f1 = np.where(2 * tp + fp + fn > 0, 2 * tp / np.maximum(2 * tp + fp + fn, 1), 1.0)
    lo, hi = np.quantile(f1, [0.025, 0.975])
    return float(lo), float(hi)


def controller_applicability(evidence: list[tuple[dict, list[list[str]]]]) -> str:
    """v0 controller slot logic (FactSlot.update + EvidenceBackedMemory.applicability) on given atoms."""
    memory = EvidenceBackedMemory("probe")
    for meta, atoms in evidence:
        for field, value in atoms:
            obs = FactObservation(field=field, value=value, evidence_id=meta["evidence_id"],
                                  source_type=meta["source_type"], reliability=meta["reliability"],
                                  step=meta["step"])
            slot = memory.slots.setdefault(field, FactSlot(field))
            slot.observations.append(obs)
            slot.update()
    return memory.applicability()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="*", default=list(MODELS))
    parser.add_argument("--limit", type=int, help="smoke test: sentences of the first N cases only")
    parser.add_argument("--skip-llm", action="store_true", help="analyse cached predictions only")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    rows = [json.loads(line) for line in DATA.read_text(encoding="utf-8").splitlines() if line.strip()]
    meta = json.loads((DATA.parent / "legacy_para_meta.json").read_text(encoding="utf-8"))
    items = [r for r in rows if r["kept"]]
    if args.limit:
        first_cases = {c.case_id for c in load_cases()[: args.limit]}
        items = [r for r in items if first_cases & set(r["case_ids"])]
    by_id = {r["item_id"]: r for r in items}
    pred_path = OUT / "predictions.jsonl"
    if args.skip_llm:
        preds = [json.loads(x) for x in pred_path.read_text(encoding="utf-8").splitlines()]
    else:
        preds = regex_predictions(items) + asyncio.run(run_llm(items, args.models))
        pred_path.write_text("".join(json.dumps(p) + "\n" for p in preds), encoding="utf-8")

    # ---------------- atom-level metrics ----------------
    recs = []
    for p in preds:
        item = by_id[p["item_id"]]
        tp, fp, fn = counts(p["atoms"], item["gold_atoms"])
        dtp, dfp, dfn = counts(p["atoms"], item["gold_atoms"], DECISION_FIELDS)
        recs.append({
            "item_id": p["item_id"], "sent_id": item["sent_id"], "template_id": item["template_id"],
            "kind": item["kind"], "generator": item["generator"], "distance": item["distance"],
            "bin": bin_label(item["kind"], item["distance"]), "model": p["model"], "extractor": p["extractor"],
            "tp": tp, "fp": fp, "fn": fn, "dtp": dtp, "dfp": dfp, "dfn": dfn,
            "exact": int(fp == 0 and fn == 0), "error": int(bool(p.get("error"))),
            "calls": p["calls"], "tokens": p["tokens"],
        })
    df = pd.DataFrame(recs)
    df.to_csv(OUT / "item_scores.csv", index=False)
    rng = np.random.default_rng(SEED)

    def summarise(group_cols: list[str]) -> pd.DataFrame:
        out = []
        for key, g in df.groupby(group_cols, sort=False):
            key = key if isinstance(key, tuple) else (key,)
            tp, fp, fn = int(g.tp.sum()), int(g.fp.sum()), int(g.fn.sum())
            p, r, f = prf(tp, fp, fn)
            lo, hi = boot_f1(g, ("tp", "fp", "fn"), rng)
            _, _, df1 = prf(int(g.dtp.sum()), int(g.dfp.sum()), int(g.dfn.sum()))
            dlo, dhi = boot_f1(g, ("dtp", "dfp", "dfn"), rng)
            out.append(dict(zip(group_cols, key, strict=True)) | {
                "items": len(g), "sentences": g.sent_id.nunique(), "templates": g.template_id.nunique(),
                "tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f,
                "f1_ci_low": lo, "f1_ci_high": hi, "decision_f1": df1, "decision_f1_ci_low": dlo,
                "decision_f1_ci_high": dhi, "exact_match_rate": g.exact.mean(), "error_rate": g.error.mean(),
                "mean_calls": g.calls.mean(), "mean_tokens": g.tokens.mean(),
            })
        return pd.DataFrame(out)

    order = {"none": -1, "regex": 0, "llm": 1, "llm_verified": 2}
    model_order = {m: i for i, m in enumerate(["no_atoms", "regex_v0", *MODELS])}

    def sort(frame: pd.DataFrame) -> pd.DataFrame:
        frame = frame.assign(_e=frame.extractor.map(order), _m=frame.model.map(model_order))
        return frame.sort_values(["_e", "_m", *[c for c in ("kind", "bin") if c in frame]]).drop(
            columns=["_e", "_m"])

    by_kind = sort(summarise(["extractor", "model", "kind"]))
    by_kind.to_csv(OUT / "atom_prf_by_kind.csv", index=False)
    by_bin = sort(summarise(["extractor", "model", "bin"]))
    by_bin.to_csv(OUT / "atom_prf_by_distance.csv", index=False)
    by_gen = sort(summarise(["extractor", "model", "generator"]).dropna(subset=["generator"]))
    by_gen.to_csv(OUT / "atom_prf_by_generator.csv", index=False)
    by_tmpl = sort(summarise(["extractor", "model", "template_id", "kind"]))
    by_tmpl.to_csv(OUT / "atom_prf_by_template.csv", index=False)

    # ---------------- error patterns (pooled over LLMs) ----------------
    err_rows = []
    for p in preds:
        item = by_id[p["item_id"]]
        pred_set, gold_set = {tuple(a) for a in p["atoms"]}, {tuple(a) for a in item["gold_atoms"]}
        for kind_err, atoms in (("FP", pred_set - gold_set), ("FN", gold_set - pred_set)):
            for field, value in atoms:
                err_rows.append({"extractor": p["extractor"], "template_id": item["template_id"],
                                 "error": kind_err, "atom": f"{field}={value}"})
    errs = pd.DataFrame(err_rows)
    errs = errs.groupby(["extractor", "error", "template_id", "atom"]).size().rename("count").reset_index()
    errs = errs.sort_values(["extractor", "count"], ascending=[True, False])
    errs.to_csv(OUT / "error_patterns.csv", index=False)

    # ---------------- verifier ----------------
    ver_rows = []
    for p in preds:
        if p["extractor"] != "llm_verified":
            continue
        item = by_id[p["item_id"]]
        gold = {tuple(a) for a in item["gold_atoms"]}
        for d in p["verifier"]:
            ver_rows.append({"model": p["model"], "kind": item["kind"], "correct": (d["field"], d["value"]) in gold,
                             "verbatim": d["verbatim"], "long_enough": d["long_enough"],
                             "consistent": d["reclass"] == d["value"], "accepted": d["accepted"]})
    ver = pd.DataFrame(ver_rows)
    vsum = []
    for (model, kind), g in ver.groupby(["model", "kind"]):
        acc = g[g.accepted]
        rej = g[~g.accepted]
        vsum.append({
            "model": model, "kind": kind, "proposed_atoms": len(g), "acceptance_rate": g.accepted.mean(),
            "pass_verbatim": g.verbatim.mean(), "pass_len3": (g.verbatim & g.long_enough).mean(),
            "pass_consistency": g.accepted.mean(),
            "proposed_error_rate": 1 - g.correct.mean(),
            "accepted_error_rate": 1 - acc.correct.mean() if len(acc) else float("nan"),
            "rejected_error_rate": 1 - rej.correct.mean() if len(rej) else float("nan"),
            "correct_atoms_rejected_share": (rej.correct.sum() / g.correct.sum()) if g.correct.sum() else 0.0,
        })
    vdf = pd.DataFrame(vsum)
    vdf = vdf.assign(_m=vdf.model.map(model_order)).sort_values(["_m", "kind"]).drop(columns="_m")
    vdf.to_csv(OUT / "verifier.csv", index=False)

    # ---------------- downstream applicability ----------------
    cases = load_cases()
    if args.limit:
        keep_texts = {(r["field"], r["original"]) for r in items}
        cases = [c for c in cases if all(sentence_key(e) in keep_texts for e in local_evidence(c))]
    sent_of = {(r["field"], r["original"]): r["sent_id"] for r in items}
    items_by_sent: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for r in items:
        items_by_sent[r["sent_id"]][r["kind"]].append(r["item_id"])
    pred_atoms = {(p["extractor"], p["model"], p["item_id"]): p["atoms"] for p in preds}
    systems = sorted({(p["extractor"], p["model"]) for p in preds}, key=lambda k: (order[k[0]], model_order[k[1]]))
    systems.insert(0, ("none", "no_atoms"))  # floor: empty extraction -> controller default "uncertain"
    rnd = random.Random(SEED)
    case_variants = []
    for case in cases:
        ev = local_evidence(case)
        sids = [sent_of[sentence_key(e)] for e in ev]
        case_variants.append((case, ev, "original", [f"{s}-orig" for s in sids]))
        pools = []
        for s in sids:
            pool = list(items_by_sent[s]["paraphrase"])
            rnd.shuffle(pool)
            pools.append(pool)
        for v in range(VARIANTS_PER_CASE):
            if all(pools):
                case_variants.append((case, ev, "paraphrase", [pool[v % len(pool)] for pool in pools]))
    app_rows = []
    for case, ev, kind, item_ids in case_variants:
        reference = case.reference["expected_applicability"]
        for extractor, model in systems:
            evidence = [
                ({"evidence_id": e.evidence_id, "source_type": e.source_type, "reliability": e.reliability,
                  "step": e.step}, pred_atoms.get((extractor, model, iid), []))
                for e, iid in zip(ev, item_ids, strict=True)
            ]
            got = controller_applicability(evidence)
            app_rows.append({"case_id": case.case_id, "profile": case.asset_context["profile_kind"],
                             "kind": kind, "extractor": extractor, "model": model, "predicted": got,
                             "reference": reference, "correct": int(got == reference)})
    app = pd.DataFrame(app_rows)
    app.to_csv(OUT / "applicability_case_variants.csv", index=False)
    asum = []
    for (extractor, model, kind), g in app.groupby(["extractor", "model", "kind"], sort=False):
        per_case = g.groupby("case_id").correct.mean()
        arr = per_case.to_numpy()
        idx = rng.integers(0, len(arr), size=(N_BOOT, len(arr)))
        lo, hi = np.quantile(arr[idx].mean(axis=1), [0.025, 0.975])
        row = {"extractor": extractor, "model": model, "kind": kind, "case_variants": len(g),
               "cases": len(arr), "applicability_accuracy": g.correct.mean(), "ci_low": lo, "ci_high": hi}
        for prof, gp in g.groupby("profile"):
            row[f"acc_{prof}"] = gp.correct.mean()
        asum.append(row)
    adf = sort(pd.DataFrame(asum))
    adf.to_csv(OUT / "applicability.csv", index=False)

    # ---------------- template counts & figure ----------------
    tmpl = pd.DataFrame(items).groupby(["template_id", "kind"]).agg(
        items=("item_id", "count"), sentences=("sent_id", "nunique")).reset_index()
    all_para = [r for r in rows if r["kind"] == "paraphrase"]
    kept_rate = pd.DataFrame(all_para).groupby("template_id").kept.mean().rename("para_kept_rate")
    tmpl = tmpl.merge(kept_rate, on="template_id", how="left")
    tmpl.to_csv(OUT / "template_counts.csv", index=False)
    dist = pd.DataFrame(all_para)
    dist_summary = dist[dist.kept].groupby("generator").distance.describe()
    dist_summary.to_csv(OUT / "paraphrase_distance.csv")
    make_figure(by_bin)
    write_report(meta, items, rows, by_kind, by_bin, by_gen, vdf, adf, tmpl, dist_summary, df, errs)


def make_figure(by_bin: pd.DataFrame) -> None:
    labels = [b[2] for b in BINS]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), sharey=True)
    # fixed categorical order (reference palette, light mode); markers give a non-colour second encoding
    style = dict(zip(MODELS, zip(["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"],
                                 ["o", "^", "v", "D", "P", "X"], strict=True), strict=True))
    for ax, extractor, title in zip(axes, ("llm", "llm_verified"), ("LLM extraction", "LLM + span verifier"),
                                    strict=True):
        regex = by_bin[by_bin.extractor == "regex"].set_index("bin").reindex(labels)
        ax.plot(range(len(labels)), regex.f1, color="#3d3d3a", lw=2, ls="--", marker="s", ms=6,
                label="v0 regex")
        sub = by_bin[by_bin.extractor == extractor]
        for model, g in sub.groupby("model", sort=False):
            g = g.set_index("bin").reindex(labels)
            color, marker = style[model]
            ax.plot(range(len(labels)), g.f1, color=color, lw=2, marker=marker, ms=6, label=model)
        ax.set_xticks(range(len(labels)), labels, rotation=20)
        ax.set_title(title)
        ax.set_xlabel("paraphrase distance (1 - token Jaccard)")
        ax.grid(alpha=0.25, lw=0.6)
        ax.spines[["top", "right"]].set_visible(False)
        ax.set_ylim(0, 1.02)
    axes[0].set_ylabel("atom F1 vs gold (micro)")
    axes[1].legend(fontsize=8, loc="lower left")
    fig.suptitle("legacy-para (auto-filtered): atom F1 by paraphrase distance", fontsize=11)
    fig.tight_layout()
    fig.savefig(OUT / "atom_f1_vs_distance.png", dpi=150)


def fmt(x: Any) -> str:
    if isinstance(x, float):
        return "nan" if np.isnan(x) else f"{x:.3f}"
    return str(x)


def md_table(frame: pd.DataFrame, cols: list[str]) -> str:
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for _, r in frame.iterrows():
        lines.append("| " + " | ".join(fmt(r[c]) for c in cols) + " |")
    return "\n".join(lines)


def write_report(meta, items, rows, by_kind, by_bin, by_gen, vdf, adf, tmpl, dist_summary, df, errs) -> None:
    by_kind = by_kind.assign(f1_ci=[f"[{a:.3f}, {b:.3f}]" for a, b in zip(by_kind.f1_ci_low, by_kind.f1_ci_high,
                                                                          strict=True)])
    pivot = by_bin.pivot_table(index=["extractor", "model"], columns="bin", values="f1", sort=False)
    pivot = pivot[[b[2] for b in BINS if b[2] in pivot.columns]].reset_index()
    n_by_bin = df[(df.extractor == "regex")].groupby("bin").size()
    adf = adf.assign(ci=[f"[{a:.3f}, {b:.3f}]" for a, b in zip(adf.ci_low, adf.ci_high, strict=True)])
    paras = [r for r in rows if r["kind"] == "paraphrase"]
    regex_orig = by_kind[(by_kind.extractor == "regex") & (by_kind.kind == "original")].iloc[0]
    regex_para = by_kind[(by_kind.extractor == "regex") & (by_kind.kind == "paraphrase")].iloc[0]
    text = f"""# E1 — Extraction robustness on `legacy-para` (auto-filtered)

All numbers produced by `scripts/paper/e1_extraction.py` (data: `scripts/data/build_legacy_para.py`).

## Data
- Distinct v0 evidence sentences: {meta['distinct_sentences']} from {meta['distinct_templates']} sentence \
templates (4 profiles x 3 steps); KEV public records excluded (v0 regex yields no atoms on them).
- Paraphrases: {meta['paraphrases_generated']} generated ({', '.join(meta['generators'])}; 5 each, T=0.7, \
seed {meta['seed']}); kept {meta['paraphrases_kept']} ({meta['paraphrases_kept'] / max(len(paras), 1):.1%}); \
judge-rejected {meta['judge_rejected']}, unparsed {meta['judge_unparsed']}, duplicates {meta['duplicates']}.
- **Filtering: {meta['filter_status']}.**
- Gold atoms = v0 regex on the ORIGINAL sentence. Caveat: this gold inherits regex conventions (e.g. \
"approved maintenance window" yields no change_approval atom; a scanner sentence on "the installed version" \
yields no product_presence atom), so LLM atoms that are semantically defensible can count as FP. \
`decision_f1` restricts scoring to product_presence/version_status, the fields applicability depends on.
- Items scored: {len(items)} (originals + kept paraphrases). Items per distance bin: \
{', '.join(f'{k}: {v}' for k, v in n_by_bin.items())}.

Kept-paraphrase distance by generator:

{md_table(dist_summary.reset_index(), ['generator', 'count', 'mean', '25%', '50%', '75%', 'max'])}

Per-template counts (cluster structure; paraphrases of one sentence are not independent, CIs bootstrap \
original sentences, {N_BOOT} resamples):

{md_table(tmpl, ['template_id', 'kind', 'sentences', 'items', 'para_kept_rate'])}

## Atom-level P/R/F1 vs gold

{md_table(by_kind, ['extractor', 'model', 'kind', 'items', 'precision', 'recall', 'f1', 'f1_ci',
                    'decision_f1', 'exact_match_rate', 'error_rate'])}

v0 regex: F1 {regex_orig.f1:.3f} on originals vs {regex_para.f1:.3f} on paraphrases \
(recall {regex_orig.recall:.3f} -> {regex_para.recall:.3f}).

### F1 by paraphrase distance (figure: `atom_f1_vs_distance.png`)

{md_table(pivot, list(pivot.columns))}

### F1 on paraphrases by paraphrase generator

{md_table(by_gen, ['extractor', 'model', 'generator', 'items', 'f1', 'decision_f1'])}

## Span verifier
Acceptance = verbatim span (case-insensitive, whitespace-normalised) AND >= 3 tokens AND same-LLM \
re-classification of the span alone returns the same value. Error = atom not in gold.

{md_table(vdf, ['model', 'kind', 'proposed_atoms', 'pass_verbatim', 'pass_len3', 'acceptance_rate',
                'proposed_error_rate', 'accepted_error_rate', 'rejected_error_rate',
                'correct_atoms_rejected_share'])}

## Downstream applicability (v0 controller slot logic on each extractor's atoms)
Original: the 100 v0 cases. Paraphrase: {VARIANTS_PER_CASE} variants per case, each sentence replaced by \
a kept paraphrase (seeded; cases with a sentence that has no kept paraphrase are skipped). `none/no_atoms` \
is the floor of an extractor that returns nothing (the controller then defaults to "uncertain"). Accuracy vs v0 reference `expected_applicability`; CI = bootstrap over cases.

{md_table(adf, ['extractor', 'model', 'kind', 'case_variants', 'applicability_accuracy', 'ci',
                'acc_affected', 'acc_not_applicable', 'acc_uncertain', 'acc_contradictory'])}

## Most frequent error patterns (pooled over the 6 LLMs; full list in `error_patterns.csv`)

{md_table(errs.groupby("extractor").head(6), ["extractor", "error", "template_id", "atom", "count"])}

## Deviations
- Paraphrase filtering was automatic (gemma_4_31b judge), not human; dataset labelled `auto_llm_judge`.
- Qwen3 models (4B and 14B) run with `enable_thinking=false`.
- LLM extractors receive the evidence record type (field name) as context, as the v0 regex does.
- Gold is regex-derived (see caveat above); applicability accuracy is the semantics-level check.
"""
    (OUT / "E1_REPORT.md").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
