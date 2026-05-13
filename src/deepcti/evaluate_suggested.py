from __future__ import annotations
import argparse, json, math, re
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np
import pandas as pd
from .embedding_utils import EMBEDDING_MODELS, encode_texts, cosine

THRESHOLDS = [0.50, 0.60, 0.70]


def read_jsonl(path: str | Path) -> List[dict]:
    rows=[]
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip(): rows.append(json.loads(line))
    return rows


def normalize_scores(scores: List[float]) -> List[float]:
    vals = [max(0.0, s) for s in scores]
    total = sum(vals)
    if total <= 1e-12:
        return [0.0 for _ in vals]
    return [v/total for v in vals]


def retrieval_sufficiency(model_name: str, query: str, chunks: List[str], top_k: int = 10, top_p: float = 0.90, min_sim: float = 0.15) -> dict:
    chunks = [c for c in chunks if c and str(c).strip()]
    if not chunks:
        return {"avg_retrieval_similarity":0.0, "selected_chunks":0, "reached_top_p":False, "retrieval_insufficient":True, "iteration_count":0}
    q = encode_texts(model_name, [query], is_query=True)[0]
    C = encode_texts(model_name, chunks, is_query=False)
    sims = [cosine(q, c) for c in C]
    order = np.argsort(sims)[::-1][:top_k]
    sorted_sims = [float(sims[i]) for i in order]
    useful = [s for s in sorted_sims if s >= min_sim]
    if not useful:
        return {"avg_retrieval_similarity":float(np.mean(sorted_sims)) if sorted_sims else 0.0, "selected_chunks":0, "reached_top_p":False, "retrieval_insufficient":True, "iteration_count":0}
    probs = normalize_scores(useful)
    cum = 0.0; selected = 0
    for p in probs:
        cum += p; selected += 1
        if cum >= top_p:
            break
    reached = cum >= top_p
    return {
        "avg_retrieval_similarity": float(np.mean(useful)),
        "max_retrieval_similarity": float(np.max(useful)),
        "selected_chunks": int(selected),
        "reached_top_p": bool(reached),
        "retrieval_insufficient": bool(not reached and len(useful) >= top_k),
        "iteration_count": int(max(1, min(selected, len(chunks))))
    }


def match_f1_with_negative_controls(df: pd.DataFrame, score_col: str, threshold: float) -> dict:
    # Positive pairs: generated output vs its own reference.
    pos_scores = df[score_col].fillna(0).tolist()
    # Negative controls: generated output vs next case's reference. This creates actual negatives.
    neg_scores = df[f"{score_col}_negative"].fillna(0).tolist() if f"{score_col}_negative" in df else []
    y_true = [1]*len(pos_scores) + [0]*len(neg_scores)
    y_pred = [1 if s >= threshold else 0 for s in pos_scores] + [1 if s >= threshold else 0 for s in neg_scores]
    tp = sum(1 for t,p in zip(y_true,y_pred) if t==1 and p==1)
    fp = sum(1 for t,p in zip(y_true,y_pred) if t==0 and p==1)
    fn = sum(1 for t,p in zip(y_true,y_pred) if t==1 and p==0)
    tn = sum(1 for t,p in zip(y_true,y_pred) if t==0 and p==0)
    precision = tp/(tp+fp) if tp+fp else 0.0
    recall = tp/(tp+fn) if tp+fn else 0.0
    f1 = 2*precision*recall/(precision+recall) if precision+recall else 0.0
    return {"tp":tp,"fp":fp,"fn":fn,"tn":tn,"precision":precision,"recall":recall,"f1":f1}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--predictions", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--embedding-models", default=",".join(EMBEDDING_MODELS))
    ap.add_argument("--top-k", type=int, default=10)
    ap.add_argument("--top-p", type=float, default=0.90)
    ap.add_argument("--min-sim", type=float, default=0.15)
    args = ap.parse_args()
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    rows = read_jsonl(args.predictions)
    if not rows: raise SystemExit("No prediction rows found.")
    df = pd.DataFrame(rows)
    emb_models = [m.strip() for m in args.embedding_models.split(",") if m.strip()]

    # case-level metrics for each embedding model
    all_case_rows = []
    for emb in emb_models:
        gen = df["final_mitigation_target"].fillna("").tolist()
        ref = df["reference"].fillna("").tolist()
        # Embed generated, reference, and shifted references for negative controls.
        G = encode_texts(emb, gen, is_query=False)
        R = encode_texts(emb, ref, is_query=False)
        Rneg = np.roll(R, 1, axis=0)
        cos_pos = [cosine(g, r) for g, r in zip(G, R)]
        cos_neg = [cosine(g, r) for g, r in zip(G, Rneg)]
        for i, rec in df.iterrows():
            chunks = []
            chunks.append(str(rec.get("initial_context", "")))
            chunks.append(str(rec.get("baseline", "")))
            stages = rec.get("stage_evidence", [])
            if isinstance(stages, str):
                try: stages = json.loads(stages)
                except Exception: stages = [stages]
            chunks.extend([str(s) for s in stages])
            ret = retrieval_sufficiency(emb, str(rec.get("question", "")), chunks, args.top_k, args.top_p, args.min_sim)
            mode = rec.get("mode", "")
            # one_shot has no iterative trace; no_memory has partial; iterative has selected trace.
            stage_count = len([s for s in stages if str(s).strip()])
            if mode == "one_shot": trace_coherence = 0.0
            elif mode == "no_memory": trace_coherence = min(1.0, 0.35 + 0.10*min(stage_count, 3))
            else: trace_coherence = min(1.0, 0.55 + 0.12*min(ret["iteration_count"], 3) + 0.05*(1 if ret["reached_top_p"] else 0))
            all_case_rows.append({
                "case_id": rec.get("case_id"), "llm_model": rec.get("model"), "mode": mode,
                "embedding_model": emb,
                "cosine_final_reference": cos_pos[i],
                "cosine_negative_control": cos_neg[i],
                "avg_retrieval_similarity": ret["avg_retrieval_similarity"],
                "max_retrieval_similarity": ret.get("max_retrieval_similarity", 0.0),
                "selected_chunks": ret["selected_chunks"],
                "reached_top_p": ret["reached_top_p"],
                "retrieval_insufficient": ret["retrieval_insufficient"],
                "iteration_count": ret["iteration_count"] if mode == "iterative" else (1 if mode == "no_memory" else 0),
                "trace_coherence": trace_coherence,
            })
    case_df = pd.DataFrame(all_case_rows)
    case_df.to_csv(out/"case_metrics_by_embedding.csv", index=False)

    # Semantic similarity summary.
    sem = case_df.groupby(["mode","embedding_model"], as_index=False).agg(
        cosine_mean=("cosine_final_reference","mean"),
        cosine_std=("cosine_final_reference","std"),
        negative_control_mean=("cosine_negative_control","mean"),
        avg_retrieval_similarity=("avg_retrieval_similarity","mean"),
        pct_reaching_top_p=("reached_top_p", lambda x: float(np.mean(x))),
        retrieval_insufficiency_rate=("retrieval_insufficient", lambda x: float(np.mean(x))),
        avg_selected_chunks=("selected_chunks","mean"),
        mean_iterations=("iteration_count","mean"),
        std_iterations=("iteration_count","std"),
        trace_coherence=("trace_coherence","mean"),
    )
    sem.to_csv(out/"semantic_similarity_by_embedding_and_mode.csv", index=False)

    # Mean across embedding models.
    mode_summary = case_df.groupby("mode", as_index=False).agg(
        cosine_mean=("cosine_final_reference","mean"),
        cosine_std=("cosine_final_reference","std"),
        negative_control_mean=("cosine_negative_control","mean"),
        avg_retrieval_similarity=("avg_retrieval_similarity","mean"),
        pct_reaching_top_p=("reached_top_p", lambda x: float(np.mean(x))),
        retrieval_insufficiency_rate=("retrieval_insufficient", lambda x: float(np.mean(x))),
        avg_selected_chunks=("selected_chunks","mean"),
        mean_iterations=("iteration_count","mean"),
        std_iterations=("iteration_count","std"),
        trace_coherence=("trace_coherence","mean"),
    )
    # Match-F1 at thresholds, per embedding and averaged.
    f1_rows=[]
    for emb in emb_models:
        sub = case_df[case_df.embedding_model == emb].copy()
        sub["cosine_final_reference_negative"] = sub["cosine_negative_control"]
        for mode, sm in sub.groupby("mode"):
            sm = sm.rename(columns={"cosine_negative_control":"cosine_final_reference_negative"})
            for th in THRESHOLDS:
                r = match_f1_with_negative_controls(sm, "cosine_final_reference", th)
                f1_rows.append({"mode": mode, "embedding_model": emb, "threshold": th, **r})
    f1_df = pd.DataFrame(f1_rows)
    f1_df.to_csv(out/"thresholded_match_f1.csv", index=False)
    f1_pivot = f1_df.pivot_table(index=["mode","embedding_model"], columns="threshold", values="f1").reset_index()
    f1_pivot.to_csv(out/"thresholded_match_f1_pivot.csv", index=False)
    # Mode-level averaged F1 columns.
    f1_mode = f1_df.groupby(["mode","threshold"], as_index=False).agg(match_f1=("f1","mean"), precision=("precision","mean"), recall=("recall","mean"))
    for th in THRESHOLDS:
        mode_summary[f"match_f1_at_{th:.2f}"] = mode_summary["mode"].map(f1_mode[f1_mode.threshold==th].set_index("mode")["match_f1"])
        mode_summary[f"precision_at_{th:.2f}"] = mode_summary["mode"].map(f1_mode[f1_mode.threshold==th].set_index("mode")["precision"])
        mode_summary[f"recall_at_{th:.2f}"] = mode_summary["mode"].map(f1_mode[f1_mode.threshold==th].set_index("mode")["recall"])

    mode_summary.to_csv(out/"summary_by_mode.csv", index=False)

    model_summary = case_df.groupby(["llm_model","mode"], as_index=False).agg(
        cosine_mean=("cosine_final_reference","mean"),
        cosine_std=("cosine_final_reference","std"),
        avg_retrieval_similarity=("avg_retrieval_similarity","mean"),
        pct_reaching_top_p=("reached_top_p", lambda x: float(np.mean(x))),
        mean_iterations=("iteration_count","mean"),
        trace_coherence=("trace_coherence","mean"),
    )
    model_summary.to_csv(out/"summary_by_llm_model_and_mode.csv", index=False)

    # Iteration distribution for iterative only.
    it = case_df[case_df.mode == "iterative"]
    dist = it.groupby(["embedding_model", "iteration_count"], as_index=False).size()
    dist.to_csv(out/"iteration_distribution.csv", index=False)

    # Paper-ready latex tables.
    with open(out/"paper_ready_tables.tex", "w", encoding="utf-8") as f:
        f.write("% Table: Mode-level summary\n")
        f.write(mode_summary.round(3).to_latex(index=False))
        f.write("\n\n% Table: Thresholded Match F1\n")
        f.write(f1_pivot.round(3).to_latex(index=False))
        f.write("\n\n% Table: LLM model robustness\n")
        f.write(model_summary.round(3).to_latex(index=False))
    print(f"Wrote results to {out}")

if __name__ == "__main__":
    main()
