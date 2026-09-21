from __future__ import annotations

from typing import Any

from .evidence import EvidenceStore, tokenize
from .metrics import MITIGATION_ID
from .schemas import Claim, ClaimAssessment

NEGATION_CUES = {"not", "no", "never", "without"}
NEGATIVE_TERMS = {"unaffected", "disabled", "absent"}


def _overlap(claim: str, evidence: str) -> float:
    claim_tokens = set(tokenize(claim))
    evidence_tokens = set(tokenize(evidence))
    if not claim_tokens:
        return 0.0
    return len(claim_tokens & evidence_tokens) / len(claim_tokens)


def _negation_conflict(claim: str, evidence: str) -> bool:
    claim_tokens = tokenize(claim)
    evidence_tokens = tokenize(evidence)
    shared = set(claim_tokens) & set(evidence_tokens)

    def negated_shared_terms(tokens: list[str]) -> set[str]:
        scoped: set[str] = set()
        for index, token in enumerate(tokens):
            if token in NEGATION_CUES and index + 1 < len(tokens):
                target = tokens[index + 1]
                if target in shared:
                    scoped.add(target)
            elif token in NEGATIVE_TERMS and token in shared:
                scoped.add(token)
        return scoped

    claim_negated = negated_shared_terms(claim_tokens)
    evidence_negated = negated_shared_terms(evidence_tokens)
    return bool(claim_negated ^ evidence_negated) and _overlap(claim, evidence) >= 0.35


class CitationVerifier:
    """Check model claims against cited evidence."""

    def assess(self, claim: Claim, store: EvidenceStore) -> ClaimAssessment:
        found = [store.get(evidence_id) for evidence_id in claim.evidence_ids]
        missing = [evidence_id for evidence_id, item in zip(claim.evidence_ids, found) if item is None]
        evidence = [item for item in found if item is not None]
        if not claim.evidence_ids:
            return ClaimAssessment(claim.claim_id, "unsupported", [], [], 0.0, "No evidence identifiers cited.")
        if missing:
            return ClaimAssessment(
                claim.claim_id,
                "unsupported",
                [item.evidence_id for item in evidence],
                missing,
                0.0,
                "At least one cited evidence identifier does not resolve.",
            )
        scores = [_overlap(claim.text, item.text) for item in evidence]
        best = max(scores, default=0.0)
        if any(_negation_conflict(claim.text, item.text) for item in evidence):
            label, rationale = "contradicted", "Cited evidence has high lexical overlap but opposite negation polarity."
        elif best >= 0.55:
            label, rationale = "supported", "Citation resolves and has strong lexical coverage; semantic review remains required."
        elif best >= 0.25:
            label, rationale = "partially_supported", "Citation resolves but lexical coverage is incomplete."
        else:
            label, rationale = "unsupported", "Citation resolves but provides little textual support for the claim."
        return ClaimAssessment(
            claim.claim_id,
            label,
            [item.evidence_id for item in evidence],
            [],
            round(best, 4),
            rationale,
        )

    def assess_all(self, claims: list[Claim], store: EvidenceStore) -> list[ClaimAssessment]:
        return [self.assess(claim, store) for claim in claims]


def mitigation_grounding(candidate: str, claims: list[Claim], store: EvidenceStore) -> dict[str, Any]:
    predicted = sorted({item.upper() for item in MITIGATION_ID.findall(candidate)})
    grounded: list[str] = []
    for mitigation_id in predicted:
        recommendation_claims = [
            claim
            for claim in claims
            if claim.claim_type == "mitigation_recommendation"
        ]
        supported = False
        for claim in recommendation_claims:
            for evidence_id in claim.evidence_ids:
                item = store.get(evidence_id)
                if not item or not item.source_type.startswith("mitre_attack_enterprise_v"):
                    continue
                if str(item.metadata.get("mitigation_id", "")).upper() == mitigation_id:
                    supported = True
                    break
            if supported:
                break
        if supported:
            grounded.append(mitigation_id)
    ungrounded = sorted(set(predicted) - set(grounded))
    return {
        "predicted_ids": predicted,
        "grounded_ids": grounded,
        "ungrounded_ids": ungrounded,
        "grounded_fraction": len(grounded) / len(predicted) if predicted else 0.0,
        "all_grounded": bool(predicted) and not ungrounded,
    }
