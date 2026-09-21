from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .schemas import EvidenceRecord

RELIABILITY_RANK = {"unknown": 0, "secondary": 1, "authoritative": 2, "primary": 3}
EXCLUSIVE_VALUES = (
    {"installed", "not_installed"},
    {"affected", "unaffected"},
    {"available", "unavailable"},
    {"approved", "withheld"},
)


@dataclass(frozen=True)
class FactObservation:
    field: str
    value: str
    evidence_id: str
    source_type: str
    reliability: str
    step: int
    status: str = "observed"


@dataclass
class FactSlot:
    field: str
    observations: list[FactObservation] = field(default_factory=list)
    status: str = "unknown"
    resolved_value: str | None = None

    def update(self) -> None:
        known = [item for item in self.observations if item.value not in {"unknown", "potential"}]
        values = {item.value for item in known}
        if any(pair <= values for pair in EXCLUSIVE_VALUES):
            self.status = "conflicting"
            self.resolved_value = None
            return
        if not known:
            self.status = "unknown"
            self.resolved_value = None
            return
        strongest = max(
            known,
            key=lambda item: (RELIABILITY_RANK.get(item.reliability, 0), item.step),
        )
        self.status = "resolved"
        self.resolved_value = strongest.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "status": self.status,
            "resolved_value": self.resolved_value,
            "observations": [asdict(item) for item in self.observations],
        }


def extract_observations(item: EvidenceRecord) -> list[FactObservation]:
    text = item.text.lower()
    field_name = item.field.lower()
    candidates: list[tuple[str, str]] = []

    if any(token in field_name for token in ("asset_inventory", "product_presence", "inventory_validation")):
        if "not installed" in text or " is absent" in text:
            candidates.append(("product_presence", "not_installed"))
        elif (
            "is installed" in text
            or "confirms" in text
            and "installed" in text
            or "reports" in text
            and "installed" in text
        ):
            candidates.append(("product_presence", "installed"))
        elif "missing" in text:
            candidates.append(("product_presence", "unknown"))

    if "network_observation" in field_name and any(token in text for token in ("may be present", "suggests")):
        candidates.append(("product_presence", "potential"))

    if "version" in field_name or "version" in text:
        if "version is affected" in text or "affected version" in text:
            candidates.append(("version_status", "affected"))
        elif "version is unaffected" in text or "not affected" in text:
            candidates.append(("version_status", "unaffected"))
        elif any(
            token in text for token in ("version data", "version status", "does not establish its version")
        ) and any(
            token in text for token in ("missing", "unknown", "not yet verified", "does not establish")
        ):
            candidates.append(("version_status", "unknown"))

    if any(token in field_name for token in ("change_safety", "rollback")) or "rollback" in text:
        if "no tested rollback" in text or "rollback procedure is unavailable" in text:
            candidates.append(("rollback_plan", "unavailable"))
        elif "tested backup" in text and "rollback" in text:
            candidates.append(("rollback_plan", "available"))

    if "approval" in text:
        if any(token in text for token in ("withheld", "not approved", "approval is withheld")):
            candidates.append(("change_approval", "withheld"))
        elif "approved" in text:
            candidates.append(("change_approval", "approved"))

    return [
        FactObservation(
            field=field,
            value=value,
            evidence_id=item.evidence_id,
            source_type=item.source_type,
            reliability=item.reliability,
            step=item.step,
        )
        for field, value in candidates
    ]


@dataclass
class EvidenceBackedMemory:
    case_id: str
    slots: dict[str, FactSlot] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)
    content_hashes: set[str] = field(default_factory=set)
    step: int = 0

    def ingest(self, evidence: list[EvidenceRecord]) -> list[EvidenceRecord]:
        novel = []
        for item in evidence:
            if item.content_sha256 in self.content_hashes:
                continue
            self.content_hashes.add(item.content_sha256)
            self.evidence_ids.append(item.evidence_id)
            self.step = max(self.step, item.step)
            novel.append(item)
            for observation in extract_observations(item):
                slot = self.slots.setdefault(observation.field, FactSlot(observation.field))
                slot.observations.append(observation)
                slot.update()
        return novel

    def value(self, field_name: str) -> str | None:
        slot = self.slots.get(field_name)
        return slot.resolved_value if slot and slot.status == "resolved" else None

    def applicability(self) -> str:
        product = self.slots.get("product_presence")
        version = self.slots.get("version_status")
        if product and product.status == "conflicting":
            return "uncertain"
        if version and version.status == "conflicting":
            return "uncertain"
        if self.value("product_presence") == "not_installed":
            return "not_applicable"
        if self.value("product_presence") == "installed" and self.value("version_status") == "affected":
            return "applicable"
        if self.value("product_presence") == "installed":
            return "potentially_applicable"
        return "uncertain"

    def information_needs(self) -> list[str]:
        needs = []
        product = self.slots.get("product_presence")
        version = self.slots.get("version_status")
        if product and product.status == "conflicting":
            needs.append("Reconcile conflicting CMDB/inventory and authenticated-scanner evidence.")
        elif not product or self.value("product_presence") is None:
            needs.append("Confirm whether the affected product is installed.")
        if self.value("product_presence") != "not_installed":
            if version and version.status == "conflicting":
                needs.append("Reconcile conflicting affected-version evidence.")
            elif not version or self.value("version_status") is None:
                needs.append("Confirm the installed version and whether it is affected.")
        if self.value("product_presence") != "not_installed" and self.value("rollback_plan") != "available":
            needs.append("Establish rollback capability before a state-changing mitigation.")
        return needs

    def policy_action(self) -> str:
        applicability = self.applicability()
        if applicability == "not_applicable":
            return "Document the evidence-backed non-applicability decision and monitor inventory drift."
        if applicability == "applicable":
            return "Apply the authoritative mitigation only with change approval and a tested rollback plan."
        return "Do not change the asset; resolve the listed information gaps or conflicting evidence first."

    def sufficient(self) -> bool:
        applicability = self.applicability()
        if applicability == "not_applicable":
            product = self.slots.get("product_presence")
            confirmations = (
                {item.evidence_id for item in product.observations if item.value == "not_installed"}
                if product
                else set()
            )
            return len(confirmations) >= 2
        if applicability == "applicable":
            return self.value("rollback_plan") in {"available", "unavailable"}
        return False

    def contradictions(self) -> list[dict[str, Any]]:
        return [
            {
                "field": slot.field,
                "status": "conflicting",
                "observations": [asdict(item) for item in slot.observations],
            }
            for slot in self.slots.values()
            if slot.status == "conflicting"
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "step": self.step,
            "applicability": self.applicability(),
            "facts": {name: slot.to_dict() for name, slot in self.slots.items()},
            "evidence_ids": list(self.evidence_ids),
            "open_information_needs": self.information_needs(),
            "policy_action": self.policy_action(),
            "contradictions": self.contradictions(),
        }
