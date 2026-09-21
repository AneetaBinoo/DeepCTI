from deepcti.memory import EvidenceBackedMemory
from deepcti.ollama import Generation
from deepcti.orchestrator import run_case
from deepcti.schemas import CaseRecord, EvidenceRecord, UsageRecord


def evidence(*, text: str, field: str, step: int, reliability: str = "primary") -> EvidenceRecord:
    return EvidenceRecord.create(
        text=text,
        source_type="test",
        source_uri=f"test://{field}/{step}",
        case_id="MEM-1",
        step=step,
        field=field,
        reliability=reliability,  # type: ignore[arg-type]
    )


def test_unknown_to_known_is_refinement_not_contradiction() -> None:
    memory = EvidenceBackedMemory("MEM-1")
    memory.ingest(
        [
            evidence(
                text="Product is installed but version status is not yet verified.",
                field="asset_inventory",
                step=0,
            )
        ]
    )
    memory.ingest(
        [
            evidence(
                text="Authenticated scanner confirms the installed version is affected.",
                field="version_validation",
                step=1,
            )
        ]
    )
    assert memory.applicability() == "applicable"
    assert memory.contradictions() == []


def test_mutually_exclusive_evidence_creates_conflict() -> None:
    memory = EvidenceBackedMemory("MEM-1")
    memory.ingest(
        [
            evidence(text="The CMDB states that Product is not installed.", field="product_presence", step=0),
            evidence(
                text="An authenticated scanner reports that Product is installed.",
                field="product_presence",
                step=1,
                reliability="secondary",
            ),
        ]
    )
    assert memory.applicability() == "uncertain"
    assert memory.contradictions()[0]["field"] == "product_presence"


def test_non_applicability_requires_independent_confirmation() -> None:
    memory = EvidenceBackedMemory("MEM-1")
    memory.ingest(
        [evidence(text="The CMDB states that Product is not installed.", field="product_presence", step=0)]
    )
    assert memory.applicability() == "not_applicable"
    assert memory.sufficient() is False
    memory.ingest(
        [
            evidence(
                text="A signed inventory confirms Product is absent.",
                field="inventory_validation",
                step=1,
            )
        ]
    )
    assert memory.sufficient() is True


class RepairingClient:
    def __init__(self, evidence_id: str) -> None:
        self.evidence_id = evidence_id
        self.calls = 0

    def generate(self, *, model: str, prompt: str, temperature: float = 0.0) -> Generation:
        self.calls += 1
        applicability = "potentially_applicable" if self.calls == 1 else "applicable"
        content = {
            "applicability": applicability,
            "facts": {},
            "information_needs": [],
            "candidate_actions": ["Use the tested rollback procedure."],
            "selected_action": "Use the tested rollback procedure.",
            "claims": [
                {
                    "claim_id": "c1",
                    "text": "A tested backup and rollback procedure are available.",
                    "evidence_ids": [self.evidence_id],
                    "confidence": "high",
                    "claim_type": "fact",
                }
            ],
            "final_answer": "Apply the vendor mitigation using the tested rollback procedure.",
        }
        return Generation(content, str(content), UsageRecord(prompt_tokens=10, completion_tokens=10))


def test_adaptive_memory_repairs_policy_mismatch_and_uses_full_evidence() -> None:
    inventory = evidence(
        text="Product is installed; version status is not yet verified.", field="asset_inventory", step=0
    )
    affected = evidence(
        text="Authenticated scanner confirms the installed version is affected.",
        field="version_validation",
        step=1,
    )
    rollback = evidence(
        text="A tested backup and rollback procedure are available.",
        field="change_safety",
        step=2,
    )
    case = CaseRecord(
        case_id="MEM-1",
        question="What should the analyst do?",
        cve_id="CVE-2026-0001",
        asset_context={},
        initial_evidence=[inventory],
        staged_evidence=[affected, rollback],
        reference={"required_action": "Apply the vendor mitigation.", "forbidden_keywords": []},
        source_dataset="test",
    )
    client = RepairingClient(rollback.evidence_id)

    result = run_case(
        case=case,
        mode="adaptive_memory",
        model="test",
        client=client,
        retrieval_k=8,
        max_steps=3,
        temperature=0.0,
    )

    assert result["final_state"]["applicability"] == "applicable"
    assert result["validated_memory"]["contradictions"] == []
    assert result["steps_executed"] == 3
    assert result["repair_attempted"] is True
    assert result["model_calls"] == 2
    assert result["validation_passed"] is True


class UnsupportedClaimClient:
    def generate(self, *, model: str, prompt: str, temperature: float = 0.0) -> Generation:
        content = {
            "applicability": "uncertain",
            "facts": {},
            "information_needs": ["Confirm the installed version."],
            "candidate_actions": [],
            "selected_action": "",
            "claims": [
                {
                    "claim_id": "bad",
                    "text": "An unsupported claim.",
                    "evidence_ids": [],
                    "confidence": "low",
                    "claim_type": "fact",
                }
            ],
            "final_answer": "More evidence is required.",
        }
        return Generation(content, str(content), UsageRecord())


def test_adaptive_memory_uses_safe_fallback_when_repair_still_fails() -> None:
    inventory = evidence(
        text="Installation and version data for Product are missing.",
        field="asset_inventory",
        step=0,
    )
    case = CaseRecord(
        case_id="MEM-1",
        question="What should the analyst do?",
        cve_id="CVE-2026-0002",
        asset_context={},
        initial_evidence=[inventory],
        staged_evidence=[],
        reference={"required_action": "Verify installed version.", "forbidden_keywords": []},
        source_dataset="test",
    )

    result = run_case(
        case=case,
        mode="adaptive_memory",
        model="test",
        client=UnsupportedClaimClient(),
        retrieval_k=8,
        max_steps=3,
        temperature=0.0,
    )

    assert result["repair_attempted"] is False
    assert result["fallback_used"] is True
    assert result["validation_passed"] is True
    assert result["completed"] is True
    assert result["final_state"]["claims"] == []
