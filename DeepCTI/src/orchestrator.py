from __future__ import annotations

from typing import Any, Dict, List, Optional
import re

from .memory import EvidenceStore
from .tools import add_baseline_as_evidence, add_scenario_update_as_evidence, retrieve_relevant
from .llm import run_llm
from .verifier import verify_claims
from .report import save_json, make_evidence_block, build_step_report, build_final_report


def _text_overlap(a: str, b: str) -> float:
    toks = lambda s: {t.lower() for t in re.findall(r"[A-Za-z0-9_\-]{3,}", s or "")}
    A, B = toks(a), toks(b)
    if not A or not B:
        return 0.0
    return round(len(A & B) / max(1, len(B)), 4)


def init_working_context(case_id: str, baseline: Dict[str, Any], question: str = "") -> Dict[str, Any]:
    return {
        "case_id": case_id,
        "question": question,
        "baseline": baseline,
        "step": 0,
        "latest_update": "",
        "task": "Generate mitigation decision support using evidence-backed stepwise context updates.",
        "current_answer": "",
        "open_questions": [],
        "decision_support": "uncertain",
    }


def _make_query_from_baseline(baseline: Dict[str, Any], question: str = "") -> str:
    parts = []
    if question:
        parts.append(f"question: {question[:250]}")
    for key in ["CVE", "Dependency", "Version", "Keywords", "Questions", "Global_Knowledge", "Local_knowledge"]:
        if key in baseline:
            s = str(baseline.get(key) or "").strip()
            if s and s.lower() not in {"nan", "none"}:
                parts.append(f"{key}: {s[:250]}")
    if not parts:
        for k, v in baseline.items():
            s = str(v).strip() if v is not None else ""
            if not s or s.lower() in ("nan", "none") or len(s) < 10:
                continue
            parts.append(f"{k}: {s[:200]}")
            if len(parts) >= 5:
                break
    return "\n".join(parts) if parts else "cybersecurity mitigation context"


def _evaluate_step(llm_out: Dict[str, Any], expected_update: str) -> Dict[str, Any]:
    updated_answer = llm_out.get("updated_answer", "")
    rec_action = llm_out.get("recommended_action", "")
    combined = (updated_answer + "\n" + rec_action).strip()
    return {
        "expected_update_overlap": _text_overlap(combined, expected_update) if expected_update else None,
        "decision_support": llm_out.get("decision_support", "uncertain"),
        "num_claims": len(llm_out.get("claims", []) or []),
    }


def _run_inner_loop(
    settings,
    store: EvidenceStore,
    working: Dict[str, Any],
    base_query: str,
    *,
    case_id: str,
    current_step: int,
    k: int,
    expected_update: str = "",
) -> tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]], str, List[Dict[str, Any]]]:
    query = base_query
    llm_out: Dict[str, Any] = {}
    verification: Dict[str, Any] = {}
    retrieval_trace: List[Dict[str, Any]] = []
    evidence_items_dicts: List[Dict[str, Any]] = []

    max_iters = max(1, int(getattr(settings, "inner_loop_max_iters", 1)))
    for iter_idx in range(1, max_iters + 1):
        print(f"[STEP] case={case_id} step={current_step} iter={iter_idx} | retrieving...")
        relevant = retrieve_relevant(
            store,
            query,
            case_id=case_id,
            k=k,
            current_step=current_step,
            scope="causal_case_only",
        )
        print(f"[STEP] case={case_id} step={current_step} iter={iter_idx} | retrieved={len(relevant)}")

        evidence_items_dicts = [e.__dict__ for e in relevant]
        evidence_block = make_evidence_block(evidence_items_dicts)

        print(f"[STEP] case={case_id} step={current_step} iter={iter_idx} | running LLM...")
        llm_out = run_llm(settings, working, evidence_block)
        print(f"[STEP] case={case_id} step={current_step} iter={iter_idx} | LLM done (decision={llm_out.get('decision_support')})")

        print(f"[STEP] case={case_id} step={current_step} iter={iter_idx} | verifying claims...")
        verification = verify_claims(store, llm_out)
        print(f"[STEP] case={case_id} step={current_step} iter={iter_idx} | verify done")

        retrieval_trace.append(
            {
                "iter": iter_idx,
                "query": query,
                "retrieved_ids": [e["evidence_id"] for e in evidence_items_dicts],
                "retrieved_count": len(evidence_items_dicts),
                "decision_support": llm_out.get("decision_support", "uncertain"),
                "verification_verified_percent": verification.get("verification_summary", {}).get("verified_percent", 0.0),
            }
        )

        followup = (llm_out.get("followup_query") or "").strip()
        if not followup or iter_idx >= max_iters or followup == query:
            break

        query = f"{query}\nFOLLOWUP: {followup}"

    return llm_out, verification, evidence_items_dicts, query, retrieval_trace


def run_case(
    settings,
    case_id: str,
    baseline: Dict[str, Any],
    scenario_updates: List[str],
    *,
    expected_updates: Optional[List[str]] = None,
    ground_truth: str = "",
    question: str = "",
    mode: str = "iterative",
) -> None:
    print(f"[CASE] Start {case_id} | mode={mode}")

    case_dir = settings.outputs_dir / mode / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    store = EvidenceStore(str(settings.chroma_dir / mode), f"{settings.chroma_collection}_{mode}")
    working = init_working_context(case_id, baseline, question=question)
    step_reports: List[Dict[str, Any]] = []
    expected_updates = expected_updates or []

    print(f"[CASE] {case_id} | ingesting baseline evidence...")
    add_baseline_as_evidence(store, case_id, baseline, step=0)
    print(f"[CASE] {case_id} | baseline evidence ingested")

    baseline_query = _make_query_from_baseline(baseline, question=question)

    if mode == "one_shot":
        combined_update = "\n".join([u for u in scenario_updates if u]).strip()
        if combined_update:
            add_scenario_update_as_evidence(store, case_id, combined_update, step=99)
        working["step"] = len(scenario_updates)
        working["latest_update"] = combined_update
        base_query = f"{baseline_query}\nALL_UPDATES: {combined_update}" if combined_update else baseline_query

        llm_out, verification, evidence_items, final_query, retrieval_trace = _run_inner_loop(
            settings, store, working, base_query, case_id=case_id, current_step=99, k=settings.retrieval_k_step
        )

        expected_concat = " ".join([e for e in expected_updates if e])
        rep = build_step_report(
            case_id,
            step=1,
            working_context=working,
            llm_out=llm_out,
            verification=verification,
            retrieval_query=final_query,
            retrieved_evidence=evidence_items,
            expected_update=expected_concat,
            eval_summary=_evaluate_step(llm_out, expected_concat),
            retrieval_trace=retrieval_trace,
        )
        save_json(case_dir / "step_1.json", rep)
        step_reports.append(rep)
        final = build_final_report(case_id, step_reports, ground_truth=ground_truth)
        save_json(case_dir / "final_report.json", final)
        print(f"[CASE] Done {case_id}")
        return

    print(f"[CASE] {case_id} | baseline reasoning (step 0)...")
    llm_out, verification, evidence_items, final_query, retrieval_trace = _run_inner_loop(
        settings,
        store,
        working,
        baseline_query,
        case_id=case_id,
        current_step=0,
        k=settings.retrieval_k_baseline,
    )
    report0 = build_step_report(
        case_id,
        0,
        working,
        llm_out,
        verification,
        retrieval_query=final_query,
        retrieved_evidence=evidence_items,
        expected_update="",
        eval_summary={},
        retrieval_trace=retrieval_trace,
    )
    save_json(case_dir / "step_0.json", report0)
    step_reports.append(report0)

    for i, update in enumerate(scenario_updates, start=1):
        print(f"[CASE] {case_id} | scenario step {i}/{len(scenario_updates)}")
        prev = step_reports[-1]["llm_output"] if step_reports else {}
        working = {**working}
        working["step"] = i
        working["latest_update"] = update

        if mode == "no_memory":
            working["current_answer"] = ""
            working["open_questions"] = []
            working["decision_support"] = "uncertain"
        else:
            working["current_answer"] = prev.get("updated_answer", "")
            working["open_questions"] = prev.get("missing_info", [])
            working["decision_support"] = prev.get("decision_support", "uncertain")

        add_scenario_update_as_evidence(store, case_id, update, step=i)

        query = f"{baseline_query}\nNEW_INFO: {update}"
        if mode != "no_memory" and working["current_answer"]:
            query += f"\nPREV_ANSWER: {working['current_answer'][:400]}"
        if working.get("open_questions"):
            query += "\nOPEN_QUESTIONS: " + " | ".join([str(x)[:120] for x in working["open_questions"][:5]])

        llm_out, verification, evidence_items, final_query, retrieval_trace = _run_inner_loop(
            settings,
            store,
            working,
            query,
            case_id=case_id,
            current_step=i,
            k=settings.retrieval_k_step,
            expected_update=(expected_updates[i - 1] if i - 1 < len(expected_updates) else ""),
        )

        exp = expected_updates[i - 1] if i - 1 < len(expected_updates) else ""
        rep = build_step_report(
            case_id,
            i,
            working,
            llm_out,
            verification,
            retrieval_query=final_query,
            retrieved_evidence=evidence_items,
            expected_update=exp,
            eval_summary=_evaluate_step(llm_out, exp),
            retrieval_trace=retrieval_trace,
        )
        save_json(case_dir / f"step_{i}.json", rep)
        step_reports.append(rep)

    final = build_final_report(case_id, step_reports, ground_truth=ground_truth)
    save_json(case_dir / "final_report.json", final)
    print(f"[CASE] Done {case_id}")