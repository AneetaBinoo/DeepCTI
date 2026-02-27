from __future__ import annotations

from typing import Any, Dict, List
import json
from pathlib import Path
import re


def save_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def make_evidence_block(evidence_items: List[Dict[str, Any]]) -> str:
    lines = []
    for ev in evidence_items:
        text = str(ev.get("text", "")).replace("\n", " ").strip()
        if len(text) > 600:
            text = text[:600] + "..."
        meta = ev.get("metadata") or {}
        meta_txt = f"case_id={meta.get('case_id')},step={meta.get('step')},field={meta.get('field')}"
        lines.append(f"- {ev['evidence_id']}: {text} (source={ev.get('source','unknown')}; {meta_txt})")
    return "\n".join(lines)


def _simple_text_overlap_score(a: str, b: str) -> float:
    toks = lambda s: {t.lower() for t in re.findall(r"[A-Za-z0-9_\-]{3,}", s or "")}
    A, B = toks(a), toks(b)
    if not A or not B:
        return 0.0
    return round(len(A & B) / max(1, len(B)), 4)


def build_step_report(
    case_id: str,
    step: int,
    working_context: Dict[str, Any],
    llm_out: Dict[str, Any],
    verification: Dict[str, Any],
    *,
    retrieval_query: str,
    retrieved_evidence: List[Dict[str, Any]],
    expected_update: str = "",
    eval_summary: Dict[str, Any] | None = None,
    retrieval_trace: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    return {
        "case_id": case_id,
        "step": step,
        "working_context": working_context,
        "llm_output": llm_out,
        "verification": verification,
        "retrieval": {
            "query": retrieval_query,
            "retrieved_evidence": retrieved_evidence,
            "retrieval_trace": retrieval_trace or [],
            "available_evidence_count": len(retrieved_evidence),
        },
        "expected_update": expected_update,
        "evaluation": eval_summary or {},
    }


def build_final_report(case_id: str, step_reports: List[Dict[str, Any]], ground_truth: str = "") -> Dict[str, Any]:
    final_answer = step_reports[-1]["llm_output"].get("updated_answer", "") if step_reports else ""
    final_decision = step_reports[-1]["llm_output"].get("decision_support", "uncertain") if step_reports else "uncertain"

    evolution = []
    step_matches = []
    for r in step_reports:
        ev = r.get("evaluation", {}) or {}
        if r["step"] > 0 and "expected_update_overlap" in ev:
            step_matches.append(ev["expected_update_overlap"])
        evolution.append(
            {
                "step": r["step"],
                "update": r["working_context"].get("latest_update", ""),
                "expected_update": r.get("expected_update", ""),
                "updated_answer": r["llm_output"].get("updated_answer", ""),
                "decision_support": r["llm_output"].get("decision_support", "uncertain"),
                "verified_percent": r["verification"]["verification_summary"].get("verified_percent", 0.0),
                "expected_update_overlap": ev.get("expected_update_overlap"),
            }
        )

    gt_overlap = _simple_text_overlap_score(final_answer, ground_truth) if ground_truth else None
    avg_step_overlap = round(sum(step_matches) / len(step_matches), 4) if step_matches else None

    return {
        "case_id": case_id,
        "final_answer": final_answer,
        "final_decision_support": final_decision,
        "ground_truth": ground_truth,
        "ground_truth_overlap": gt_overlap,
        "avg_step_expected_update_overlap": avg_step_overlap,
        "answer_evolution": evolution,
        "notes": (
            "Work-in-progress stepwise CTI deep-research prototype using controlled evidence retrieval and "
            "citation-consistency + lexical-grounding checks."
        ),
    }


def summarize_case_metrics(final_report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "case_id": final_report.get("case_id"),
        "final_decision_support": final_report.get("final_decision_support"),
        "ground_truth_overlap": final_report.get("ground_truth_overlap"),
        "avg_step_expected_update_overlap": final_report.get("avg_step_expected_update_overlap"),
    }