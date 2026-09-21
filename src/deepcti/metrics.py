from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .evidence import tokenize
from .schemas import ClaimAssessment

MITIGATION_ID = re.compile(r"M10\d{2}", re.IGNORECASE)
ATHENABENCH_MITIGATION_ID = re.compile(r"M\d{4}", re.IGNORECASE)
ANSWER_PREFIX = re.compile(
    r"^\s*(?:final\s+answer|answer|prediction|output|result)\s*[:\-–—]?\s*",
    re.IGNORECASE,
)


def lexical_prf(candidate: str, reference: str) -> dict[str, float]:
    predicted = Counter(tokenize(candidate))
    expected = Counter(tokenize(reference))
    overlap = sum((predicted & expected).values())
    precision = overlap / sum(predicted.values()) if predicted else 0.0
    recall = overlap / sum(expected.values()) if expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def mitigation_id_prf(candidate: str, reference: str) -> dict[str, float]:
    predicted = {match.upper() for match in MITIGATION_ID.findall(candidate)}
    expected = {match.upper() for match in MITIGATION_ID.findall(reference)}
    overlap = len(predicted & expected)
    precision = overlap / len(predicted) if predicted else 0.0
    recall = overlap / len(expected) if expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def extract_athenabench_rms_answer(text: str) -> str:
    """Read the final non-empty response line."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    if not lines:
        return ""
    final_line = ANSWER_PREFIX.sub("", lines[-1]).strip().upper()
    return ", ".join(ATHENABENCH_MITIGATION_ID.findall(final_line))


def claim_metrics(assessments: list[ClaimAssessment]) -> dict[str, Any]:
    counts = Counter(item.label for item in assessments)
    total = len(assessments)
    supported_equivalent = counts["supported"] + 0.5 * counts["partially_supported"]
    return {
        "claim_count": total,
        "supported": counts["supported"],
        "partially_supported": counts["partially_supported"],
        "unsupported": counts["unsupported"],
        "contradicted": counts["contradicted"],
        "supported_fraction": supported_equivalent / total if total else 0.0,
        "unsafe_claim_fraction": (counts["unsupported"] + counts["contradicted"]) / total if total else 0.0,
    }
