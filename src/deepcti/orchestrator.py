from __future__ import annotations

from dataclasses import asdict
from typing import Any, Protocol

from .evidence import EvidenceStore
from .memory import EvidenceBackedMemory
from .metrics import claim_metrics, extract_athenabench_rms_answer, lexical_prf, mitigation_id_prf
from .prompts import REQUIRED_FIELDS, analysis_prompt, validated_memory_prompt, validation_repair_prompt
from .schemas import CaseRecord, Claim, KnowledgeState, UsageRecord
from .verifier import CitationVerifier, mitigation_grounding


class Generator(Protocol):
    def generate(self, *, model: str, prompt: str, temperature: float = 0.0): ...

    def generate_text(self, *, model: str, prompt: str, temperature: float = 0.0): ...


VALID_MODES = {
    "initial_one_shot",
    "evidence_equal_one_shot",
    "rag_once",
    "iterative_no_memory",
    "iterative_memory",
    "adaptive_memory",
}


def run_athenabench_model_only_case(
    *, case: CaseRecord, model: str, client: Generator, temperature: float
) -> dict[str, Any]:
    if not case.benchmark_prompt:
        raise ValueError(f"Case {case.case_id} has no original benchmark prompt.")
    generation = client.generate_text(
        model=model,
        prompt=case.benchmark_prompt,
        temperature=temperature,
    )
    prediction = extract_athenabench_rms_answer(generation.raw_text)
    reference = str(case.reference.get("final_answer", ""))
    return {
        "case_id": case.case_id,
        "source_dataset": case.source_dataset,
        "split": case.split,
        "condition": "athenabench_model_only",
        "mode": "benchmark_direct",
        "model": model,
        "raw_response": generation.raw_text,
        "final_answer": prediction,
        "alignment": mitigation_id_prf(prediction, reference),
        "mitigation_grounding": None,
        "final_claim_metrics": None,
        "usage": asdict(generation.usage),
        "steps_executed": 1,
        "completed": bool(prediction),
        "traces": [],
    }


def _claims(payload: dict[str, Any]) -> list[Claim]:
    claims = []
    for index, raw in enumerate(payload.get("claims", []) or [], start=1):
        if not isinstance(raw, dict):
            continue
        confidence = str(raw.get("confidence", "low")).lower()
        if confidence not in {"high", "medium", "low"}:
            confidence = "low"
        claims.append(
            Claim(
                claim_id=str(raw.get("claim_id") or f"claim_{index}"),
                text=str(raw.get("text", "")).strip(),
                evidence_ids=[str(item) for item in raw.get("evidence_ids", []) if str(item)],
                confidence=confidence,  # type: ignore[arg-type]
                claim_type=str(raw.get("claim_type", "fact")),
            )
        )
    return claims


def _merge_state(previous: KnowledgeState, payload: dict[str, Any], step: int) -> KnowledgeState:
    facts = dict(previous.facts)
    contradictions = list(previous.contradictions)
    for key, value in dict(payload.get("facts", {}) or {}).items():
        old = facts.get(key)
        if old not in (None, "", [], {}) and value not in (None, "", [], {}) and old != value:
            contradictions.append({"field": key, "previous": old, "new": value, "step": step})
        facts[key] = value
    applicability = str(payload.get("applicability", "uncertain")).lower()
    if applicability not in {"applicable", "potentially_applicable", "not_applicable", "uncertain"}:
        applicability = "uncertain"
    return KnowledgeState(
        case_id=previous.case_id,
        step=step,
        applicability=applicability,  # type: ignore[arg-type]
        facts=facts,
        evidence_ids=list(previous.evidence_ids),
        open_information_needs=[str(item) for item in payload.get("information_needs", []) or []],
        candidate_actions=[str(item) for item in payload.get("candidate_actions", []) or []],
        selected_action=str(payload.get("selected_action", "")),
        contradictions=contradictions,
        claims=_claims(payload),
    )


def _is_sufficient(state: KnowledgeState, unsafe_claims: int) -> bool:
    present = all(state.facts.get(field) not in (None, "", [], {}) for field in REQUIRED_FIELDS)
    return present and not state.open_information_needs and not state.contradictions and unsafe_claims == 0


def _usage_add(total: UsageRecord, current: UsageRecord) -> None:
    total.prompt_tokens += current.prompt_tokens
    total.completion_tokens += current.completion_tokens
    total.total_duration_ms += current.total_duration_ms
    total.load_duration_ms += current.load_duration_ms
    total.model_digest = current.model_digest or total.model_digest


def run_case(
    *,
    case: CaseRecord,
    mode: str,
    model: str,
    client: Generator,
    retrieval_k: int,
    max_steps: int,
    temperature: float,
) -> dict[str, Any]:
    if mode not in VALID_MODES:
        raise ValueError(f"Unknown mode: {mode}")
    if mode == "adaptive_memory":
        return run_adaptive_memory_case(
            case=case,
            model=model,
            client=client,
            temperature=temperature,
        )
    all_evidence = case.initial_evidence + case.staged_evidence
    store = EvidenceStore(all_evidence)
    verifier = CitationVerifier()
    state = KnowledgeState(
        case_id=case.case_id, evidence_ids=[item.evidence_id for item in case.initial_evidence]
    )
    traces = []
    usage = UsageRecord()
    generation_error: str | None = None

    if mode == "initial_one_shot":
        schedule = [(0, case.initial_evidence)]
    elif mode == "evidence_equal_one_shot":
        schedule = [(max([item.step for item in all_evidence], default=0), all_evidence)]
    elif mode == "rag_once":
        query = f"{case.question} {case.cve_id} " + " ".join(map(str, case.asset_context.values()))
        schedule = [
            (
                max([item.step for item in all_evidence], default=0),
                store.search(query, case_id=case.case_id, max_step=99, k=retrieval_k),
            )
        ]
    else:
        maximum = min(max_steps, max([item.step for item in all_evidence], default=0))
        schedule = []
        for step in range(maximum + 1):
            available = [item for item in all_evidence if item.step <= step]
            schedule.append((step, available))

    for step, available in schedule:
        if mode == "iterative_no_memory" and step > 0:
            prompt_state = KnowledgeState(case_id=case.case_id, step=step - 1)
        else:
            prompt_state = state
        if mode.startswith("iterative"):
            query = " ".join([case.question, case.cve_id, *prompt_state.open_information_needs])
            evidence = store.search(query, case_id=case.case_id, max_step=step, k=retrieval_k)
        else:
            evidence = available
        generation = client.generate(
            model=model,
            prompt=analysis_prompt(
                question=case.question,
                state=prompt_state,
                evidence=evidence,
                mode=mode,
                task_profile="mitigation_benchmark"
                if case.source_dataset.startswith("athenabench_rms")
                else "operational_decision",
            ),
            temperature=temperature,
        )
        _usage_add(usage, generation.usage)
        generation_error = getattr(generation, "parse_error", None)
        next_state = _merge_state(prompt_state, generation.content, step)
        next_state.evidence_ids = list(
            dict.fromkeys(prompt_state.evidence_ids + [item.evidence_id for item in evidence])
        )
        assessments = verifier.assess_all(next_state.claims, store)
        support = claim_metrics(assessments)
        traces.append(
            {
                "step": step,
                "evidence": [asdict(item) for item in evidence],
                "state_before": prompt_state.to_dict(),
                "model_output": generation.content,
                "raw_response": generation.raw_text,
                "generation_error": generation_error,
                "state_after": next_state.to_dict(),
                "claim_assessments": [asdict(item) for item in assessments],
                "claim_metrics": support,
                "usage": asdict(generation.usage),
            }
        )
        state = next_state
        if generation_error:
            break
        if mode == "iterative_memory" and _is_sufficient(
            state, support["unsupported"] + support["contradicted"]
        ):
            break

    final_output = traces[-1]["model_output"] if traces else {}
    final_answer = str(final_output.get("final_answer", ""))
    reference = str(case.reference.get("final_answer", ""))
    grounding = mitigation_grounding(final_answer, state.claims, store)
    alignment = (
        mitigation_id_prf(final_answer, reference)
        if case.source_dataset.startswith("athenabench_rms")
        else lexical_prf(final_answer, reference)
        if reference
        else None
    )
    return {
        "case_id": case.case_id,
        "source_dataset": case.source_dataset,
        "split": case.split,
        "mode": mode,
        "model": model,
        "final_answer": final_answer,
        "final_state": state.to_dict(),
        "alignment": alignment,
        "mitigation_grounding": grounding,
        "final_claim_metrics": traces[-1]["claim_metrics"] if traces else {},
        "usage": asdict(usage),
        "steps_executed": len(traces),
        "completed": bool(final_answer) and generation_error is None,
        "generation_error": generation_error,
        "traces": traces,
    }


def _adaptive_state(memory: EvidenceBackedMemory, payload: dict[str, Any]) -> KnowledgeState:
    information_needs = list(
        dict.fromkeys(
            [
                *memory.information_needs(),
                *[str(item) for item in payload.get("information_needs", []) or []],
            ]
        )
    )
    return KnowledgeState(
        case_id=memory.case_id,
        step=memory.step,
        applicability=memory.applicability(),  # type: ignore[arg-type]
        facts={name: slot.to_dict() for name, slot in memory.slots.items()},
        evidence_ids=list(memory.evidence_ids),
        open_information_needs=information_needs,
        candidate_actions=[str(item) for item in payload.get("candidate_actions", []) or []],
        selected_action=str(payload.get("selected_action", "")),
        contradictions=memory.contradictions(),
        claims=_claims(payload),
    )


def _adaptive_validation_errors(
    *,
    case: CaseRecord,
    memory: EvidenceBackedMemory,
    payload: dict[str, Any],
    parse_error: str | None,
    state: KnowledgeState,
    store: EvidenceStore,
) -> tuple[list[str], dict[str, Any]]:
    errors = []
    if parse_error:
        errors.append(parse_error)
    final_answer = str(payload.get("final_answer", "")).strip()
    if not final_answer:
        errors.append("final_answer is empty")
    if str(payload.get("applicability", "")) != memory.applicability():
        errors.append(f"applicability must be {memory.applicability()}")
    lowered = f"{state.selected_action} {final_answer}".lower()
    for phrase in case.reference.get("forbidden_keywords", []) or []:
        if str(phrase).lower() in lowered:
            errors.append(f"unsafe or forbidden action present: {phrase}")
    assessments = CitationVerifier().assess_all(state.claims, store)
    support = claim_metrics(assessments)
    if support["unsupported"] or support["contradicted"]:
        errors.append("one or more claims failed evidence verification")
    return errors, {
        "assessments": [asdict(item) for item in assessments],
        "metrics": support,
    }


def _safe_fallback_payload(memory: EvidenceBackedMemory) -> dict[str, Any]:
    needs = memory.information_needs()
    final_text = f"Applicability is {memory.applicability()}. {memory.policy_action()}" + (
        f" Information needs: {'; '.join(needs)}" if needs else ""
    )
    return {
        "applicability": memory.applicability(),
        "facts": {},
        "information_needs": needs,
        "candidate_actions": [],
        "selected_action": ""
        if memory.applicability() in {"uncertain", "potentially_applicable"}
        else memory.policy_action(),
        "claims": [],
        "final_answer": final_text,
    }


def run_adaptive_memory_case(
    *,
    case: CaseRecord,
    model: str,
    client: Generator,
    temperature: float,
) -> dict[str, Any]:
    all_evidence = sorted(
        [*case.initial_evidence, *case.staged_evidence],
        key=lambda item: (item.step, item.evidence_id),
    )
    store = EvidenceStore(all_evidence)
    memory = EvidenceBackedMemory(case.case_id)
    controller_traces = []

    initial = memory.ingest(case.initial_evidence)
    controller_traces.append(
        {
            "step": 0,
            "event": "evidence_ingest",
            "novel_evidence_ids": [item.evidence_id for item in initial],
            "memory_after": memory.to_dict(),
            "sufficient": memory.sufficient(),
        }
    )
    for step in sorted({item.step for item in case.staged_evidence}):
        if memory.sufficient():
            break
        available = [item for item in case.staged_evidence if item.step == step]
        novel = memory.ingest(available)
        controller_traces.append(
            {
                "step": step,
                "event": "evidence_ingest",
                "novel_evidence_ids": [item.evidence_id for item in novel],
                "memory_after": memory.to_dict(),
                "sufficient": memory.sufficient(),
            }
        )
        if not novel:
            break

    used_evidence = [item for item in all_evidence if item.evidence_id in memory.evidence_ids]
    if memory.applicability() in {"uncertain", "potentially_applicable"}:
        payload = _safe_fallback_payload(memory)
        state = _adaptive_state(memory, payload)
        errors, verification = _adaptive_validation_errors(
            case=case,
            memory=memory,
            payload=payload,
            parse_error=None,
            state=state,
            store=store,
        )
        final_answer = str(payload["final_answer"])
        reference = str(case.reference.get("final_answer", case.reference.get("required_action", "")))
        return {
            "case_id": case.case_id,
            "source_dataset": case.source_dataset,
            "split": case.split,
            "mode": "adaptive_memory",
            "model": model,
            "final_answer": final_answer,
            "final_state": state.to_dict(),
            "validated_memory": memory.to_dict(),
            "alignment": lexical_prf(final_answer, reference) if reference else None,
            "mitigation_grounding": None,
            "final_claim_metrics": verification["metrics"],
            "usage": asdict(UsageRecord()),
            "steps_executed": len(controller_traces),
            "model_calls": 0,
            "repair_attempted": False,
            "fallback_used": True,
            "validation_passed": not errors,
            "validation_errors": errors,
            "completed": bool(final_answer) and not errors,
            "traces": controller_traces,
            "generation_attempts": [],
        }
    prompt = validated_memory_prompt(
        question=case.question,
        memory=memory.to_dict(),
        evidence=used_evidence,
    )
    usage = UsageRecord()
    attempts = []
    generation = client.generate(
        model=model,
        prompt=prompt,
        temperature=temperature,
    )
    _usage_add(usage, generation.usage)
    payload = generation.content
    state = _adaptive_state(memory, payload)
    errors, verification = _adaptive_validation_errors(
        case=case,
        memory=memory,
        payload=payload,
        parse_error=getattr(generation, "parse_error", None),
        state=state,
        store=store,
    )
    attempts.append(
        {
            "attempt": 1,
            "raw_response": generation.raw_text,
            "model_output": payload,
            "validation_errors": errors,
            "verification": verification,
            "usage": asdict(generation.usage),
        }
    )

    repair_attempted = bool(errors) and memory.applicability() in {
        "applicable",
        "not_applicable",
    }
    fallback_used = False
    if repair_attempted:
        repaired = client.generate(
            model=model,
            prompt=validation_repair_prompt(
                original_prompt=prompt,
                raw_response=generation.raw_text,
                errors=errors,
            ),
            temperature=temperature,
        )
        _usage_add(usage, repaired.usage)
        if repaired.content and not getattr(repaired, "parse_error", None):
            generation = repaired
            payload = repaired.content
        state = _adaptive_state(memory, payload)
        errors, verification = _adaptive_validation_errors(
            case=case,
            memory=memory,
            payload=payload,
            parse_error=getattr(generation, "parse_error", None),
            state=state,
            store=store,
        )
        attempts.append(
            {
                "attempt": 2,
                "raw_response": repaired.raw_text,
                "model_output": repaired.content,
                "validation_errors": errors,
                "verification": verification,
                "usage": asdict(repaired.usage),
            }
        )

    if errors:
        fallback_used = True
        payload = _safe_fallback_payload(memory)
        state = _adaptive_state(memory, payload)
        errors, verification = _adaptive_validation_errors(
            case=case,
            memory=memory,
            payload=payload,
            parse_error=None,
            state=state,
            store=store,
        )

    final_answer = str(payload.get("final_answer", ""))
    reference = str(case.reference.get("final_answer", case.reference.get("required_action", "")))
    return {
        "case_id": case.case_id,
        "source_dataset": case.source_dataset,
        "split": case.split,
        "mode": "adaptive_memory",
        "model": model,
        "final_answer": final_answer,
        "final_state": state.to_dict(),
        "validated_memory": memory.to_dict(),
        "alignment": lexical_prf(final_answer, reference) if reference else None,
        "mitigation_grounding": None,
        "final_claim_metrics": verification["metrics"],
        "usage": asdict(usage),
        "steps_executed": len(controller_traces),
        "model_calls": len(attempts),
        "repair_attempted": repair_attempted,
        "fallback_used": fallback_used,
        "validation_passed": not errors,
        "validation_errors": errors,
        "completed": bool(final_answer) and not errors,
        "traces": controller_traces,
        "generation_attempts": attempts,
    }
