from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Literal

Applicability = Literal["applicable", "potentially_applicable", "not_applicable", "uncertain"]
SupportLabel = Literal["supported", "partially_supported", "unsupported", "contradicted"]


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    text: str
    source_type: str
    source_uri: str
    case_id: str
    step: int
    field: str
    retrieved_at: str
    content_sha256: str
    published_at: str | None = None
    reliability: Literal["primary", "authoritative", "secondary", "unknown"] = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        text: str,
        source_type: str,
        source_uri: str,
        case_id: str,
        step: int,
        field: str,
        published_at: str | None = None,
        reliability: Literal["primary", "authoritative", "secondary", "unknown"] = "unknown",
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        clean = " ".join(str(text).split())
        digest = sha256(clean.encode("utf-8")).hexdigest()
        identity = sha256(f"{case_id}|{source_uri}|{field}|{step}|{digest}".encode()).hexdigest()[:16]
        return cls(
            evidence_id=f"ev_{identity}",
            text=clean,
            source_type=source_type,
            source_uri=source_uri,
            case_id=case_id,
            step=step,
            field=field,
            retrieved_at=utc_now(),
            published_at=published_at,
            reliability=reliability,
            content_sha256=digest,
            metadata=metadata or {},
        )


@dataclass
class Claim:
    claim_id: str
    text: str
    evidence_ids: list[str]
    confidence: Literal["high", "medium", "low"] = "low"
    claim_type: str = "fact"


@dataclass
class ClaimAssessment:
    claim_id: str
    label: SupportLabel
    evidence_ids: list[str]
    missing_evidence_ids: list[str]
    score: float
    rationale: str


@dataclass
class CaseRecord:
    case_id: str
    question: str
    cve_id: str
    asset_context: dict[str, Any]
    initial_evidence: list[EvidenceRecord]
    staged_evidence: list[EvidenceRecord]
    reference: dict[str, Any]
    source_dataset: str
    split: str = "test"
    benchmark_prompt: str = ""


@dataclass
class KnowledgeState:
    case_id: str
    step: int = 0
    applicability: Applicability = "uncertain"
    facts: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)
    open_information_needs: list[str] = field(default_factory=list)
    candidate_actions: list[str] = field(default_factory=list)
    selected_action: str = ""
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolCallRecord:
    tool_name: str
    arguments: dict[str, Any]
    started_at: str
    duration_ms: float
    status: Literal["ok", "timeout", "denied", "invalid", "error"]
    evidence_ids: list[str]
    error: str = ""


@dataclass
class UsageRecord:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_duration_ms: float = 0.0
    load_duration_ms: float = 0.0
    model_digest: str = ""
