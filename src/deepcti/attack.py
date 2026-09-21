from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evidence import tokenize
from .schemas import EvidenceRecord

ATTACK_VERSION = "19.1"
ATTACK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-19.1.json"
)


@dataclass(frozen=True)
class AttackMitigationLink:
    mitigation_id: str
    mitigation_name: str
    mitigation_description: str
    technique_id: str
    technique_name: str
    technique_description: str
    relationship_description: str
    mitigation_stix_id: str
    technique_stix_id: str
    relationship_stix_id: str
    source_uri: str

    @property
    def search_text(self) -> str:
        return (
            f"{self.mitigation_name} {self.mitigation_description} {self.technique_name} "
            f"{self.technique_description} {self.relationship_description}"
        )

    def evidence_text(self) -> str:
        return (
            f"MITRE ATT&CK Enterprise v{ATTACK_VERSION}: mitigation {self.mitigation_id} "
            f"({self.mitigation_name}) mitigates technique {self.technique_id} "
            f"({self.technique_name}). Relationship guidance: {self.relationship_description or 'None provided.'} "
            f"Mitigation description: {self.mitigation_description}"
        )


def _external_id(item: dict[str, Any], prefix: str) -> str:
    for reference in item.get("external_references", []) or []:
        value = str(reference.get("external_id", ""))
        if value.upper().startswith(prefix):
            return value.upper()
    return ""


def _source_uri(item: dict[str, Any], mitigation_id: str) -> str:
    for reference in item.get("external_references", []) or []:
        if str(reference.get("external_id", "")).upper() == mitigation_id:
            url = str(reference.get("url", "")).strip()
            if url:
                return url
    return f"https://attack.mitre.org/mitigations/{mitigation_id}/"


def _active(item: dict[str, Any]) -> bool:
    return not item.get("revoked", False) and not item.get("x_mitre_deprecated", False)


def load_attack_mitigation_links(path: str | Path) -> list[AttackMitigationLink]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = {
        str(item["id"]): item
        for item in payload.get("objects", [])
        if isinstance(item, dict) and item.get("id") and _active(item)
    }
    links: list[AttackMitigationLink] = []
    for relationship in objects.values():
        if relationship.get("type") != "relationship" or relationship.get("relationship_type") != "mitigates":
            continue
        mitigation = objects.get(str(relationship.get("source_ref", "")))
        technique = objects.get(str(relationship.get("target_ref", "")))
        if not mitigation or not technique:
            continue
        if mitigation.get("type") != "course-of-action" or technique.get("type") != "attack-pattern":
            continue
        mitigation_id = _external_id(mitigation, "M10")
        technique_id = _external_id(technique, "T")
        if not mitigation_id or not technique_id:
            continue
        links.append(
            AttackMitigationLink(
                mitigation_id=mitigation_id,
                mitigation_name=str(mitigation.get("name", "")),
                mitigation_description=str(mitigation.get("description", "")),
                technique_id=technique_id,
                technique_name=str(technique.get("name", "")),
                technique_description=str(technique.get("description", "")),
                relationship_description=str(relationship.get("description", "")),
                mitigation_stix_id=str(mitigation["id"]),
                technique_stix_id=str(technique["id"]),
                relationship_stix_id=str(relationship["id"]),
                source_uri=_source_uri(mitigation, mitigation_id),
            )
        )
    return sorted(links, key=lambda item: (item.mitigation_id, item.technique_id, item.relationship_stix_id))


def retrieve_attack_mitigations(
    links: list[AttackMitigationLink], *, query: str, case_id: str, k: int
) -> list[EvidenceRecord]:
    if not links or k <= 0:
        return []
    query_terms = set(tokenize(query))
    documents = [tokenize(item.search_text) for item in links]
    document_frequency = Counter(term for terms in documents for term in set(terms))
    average_length = sum(map(len, documents)) / len(documents)
    scored: list[tuple[float, str, str, AttackMitigationLink]] = []
    for link, terms in zip(links, documents):
        frequencies = Counter(terms)
        score = 0.0
        for term in query_terms:
            frequency = frequencies.get(term, 0)
            if not frequency:
                continue
            inverse = math.log(
                1 + (len(links) - document_frequency[term] + 0.5) / (document_frequency[term] + 0.5)
            )
            denominator = frequency + 1.5 * (0.25 + 0.75 * len(terms) / max(average_length, 1))
            score += inverse * frequency * 2.5 / max(denominator, 1e-9)
        scored.append((score, link.mitigation_id, link.technique_id, link))
    selected = [item[-1] for item in sorted(scored, key=lambda row: (-row[0], row[1], row[2]))[:k]]
    return [
        EvidenceRecord.create(
            text=link.evidence_text(),
            source_type=f"mitre_attack_enterprise_v{ATTACK_VERSION}",
            source_uri=link.source_uri,
            case_id=case_id,
            step=0,
            field="attack_mitigation_relationship",
            reliability="authoritative",
            metadata={
                "attack_version": ATTACK_VERSION,
                "mitigation_id": link.mitigation_id,
                "technique_id": link.technique_id,
                "mitigation_stix_id": link.mitigation_stix_id,
                "technique_stix_id": link.technique_stix_id,
                "relationship_stix_id": link.relationship_stix_id,
            },
        )
        for link in selected
    ]
