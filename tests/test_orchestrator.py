from deepcti.ollama import MockClient
from deepcti.orchestrator import run_case
from deepcti.schemas import CaseRecord, EvidenceRecord


def record(step: int, text: str) -> EvidenceRecord:
    return EvidenceRecord.create(
        text=text,
        source_type="test",
        source_uri="test://case",
        case_id="CASE-1",
        step=step,
        field=f"E{step}",
    )


def case() -> CaseRecord:
    return CaseRecord(
        case_id="CASE-1",
        question="What should the analyst do?",
        cve_id="CVE-2026-0001",
        asset_context={},
        initial_evidence=[record(0, "A vulnerability affects product A.")],
        staged_evidence=[record(1, "The local version is affected."), record(2, "A fixed version is available.")],
        reference={"final_answer": "Upgrade to the fixed version."},
        source_dataset="test",
    )


def test_information_equal_one_shot_receives_all_evidence() -> None:
    result = run_case(
        case=case(), mode="evidence_equal_one_shot", model="mock", client=MockClient(),
        retrieval_k=8, max_steps=4, temperature=0.0,
    )
    assert len(result["traces"]) == 1
    assert len(result["traces"][0]["evidence"]) == 3


def test_iterative_memory_has_multiple_steps() -> None:
    result = run_case(
        case=case(), mode="iterative_memory", model="mock", client=MockClient(),
        retrieval_k=8, max_steps=4, temperature=0.0,
    )
    assert result["steps_executed"] == 3
