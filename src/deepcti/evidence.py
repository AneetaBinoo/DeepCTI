from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime

from .schemas import EvidenceRecord

TOKEN = re.compile(r"[A-Za-z0-9_.:-]{2,}")
INJECTION_PATTERNS = (
    re.compile(r"ignore (?:all |the )?(?:previous|prior|system) instructions", re.IGNORECASE),
    re.compile(r"(?:system|assistant)\s*:", re.IGNORECASE),
    re.compile(r"reveal (?:the )?(?:prompt|secret|credentials)", re.IGNORECASE),
    re.compile(r"execute (?:this )?(?:command|code|tool)", re.IGNORECASE),
)


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN.findall(text or "")]


def prompt_injection_risk(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in INJECTION_PATTERNS)


def published_on_or_before(item: EvidenceRecord, cutoff: str) -> bool:
    if not item.published_at:
        return True
    try:
        published = datetime.fromisoformat(item.published_at)
        boundary = datetime.fromisoformat(cutoff)
    except ValueError:
        return False
    return published <= boundary


class EvidenceStore:
    def __init__(self, evidence: list[EvidenceRecord] | None = None) -> None:
        self._items: dict[str, EvidenceRecord] = {}
        for item in evidence or []:
            self.add(item)

    def add(self, item: EvidenceRecord) -> None:
        existing = self._items.get(item.evidence_id)
        if existing and existing.content_sha256 != item.content_sha256:
            raise ValueError(f"Evidence identity collision: {item.evidence_id}")
        self._items[item.evidence_id] = item

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        return self._items.get(evidence_id)

    def values(self, *, case_id: str | None = None, max_step: int | None = None) -> list[EvidenceRecord]:
        items = list(self._items.values())
        if case_id is not None:
            items = [item for item in items if item.case_id == case_id]
        if max_step is not None:
            items = [item for item in items if item.step <= max_step]
        return items

    def search(self, query: str, *, case_id: str, max_step: int, k: int) -> list[EvidenceRecord]:
        candidates = self.values(case_id=case_id, max_step=max_step)
        if not candidates:
            return []
        query_terms = set(tokenize(query))
        documents = {item.evidence_id: tokenize(item.text) for item in candidates}
        document_frequency = Counter(term for terms in documents.values() for term in set(terms))
        average_length = sum(map(len, documents.values())) / len(documents)
        scored: list[tuple[float, EvidenceRecord]] = []
        for item in candidates:
            terms = documents[item.evidence_id]
            term_frequency = Counter(terms)
            score = 0.0
            for term in query_terms:
                if term not in term_frequency:
                    continue
                frequency = term_frequency[term]
                inverse = math.log(
                    1 + (len(candidates) - document_frequency[term] + 0.5) / (document_frequency[term] + 0.5)
                )
                denominator = frequency + 1.5 * (0.25 + 0.75 * len(terms) / max(average_length, 1))
                score += inverse * frequency * 2.5 / max(denominator, 1e-9)
            provenance_bonus = {"primary": 0.25, "authoritative": 0.2, "secondary": 0.05}.get(
                item.reliability, 0.0
            )
            scored.append((score + provenance_bonus, item))
        return [item for _, item in sorted(scored, key=lambda pair: pair[0], reverse=True)[:k]]


def evidence_as_prompt(items: list[EvidenceRecord], *, max_chars: int = 1200) -> str:
    blocks = []
    for item in items:
        text = item.text[:max_chars]
        risk = prompt_injection_risk(text)
        blocks.append(
            f"[{item.evidence_id}] source={item.source_type} uri={item.source_uri} "
            f"reliability={item.reliability} published={item.published_at or 'unknown'} "
            f"instruction_like_content={'yes' if risk else 'no'}\n"
            f"BEGIN_UNTRUSTED_EVIDENCE\n{text}\nEND_UNTRUSTED_EVIDENCE"
        )
    return "\n\n".join(blocks)
