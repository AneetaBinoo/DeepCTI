from __future__ import annotations

from typing import Dict, List, Optional
from .memory import EvidenceStore, EvidenceItem


def add_baseline_as_evidence(store: EvidenceStore, case_id: str, baseline: Dict, step: int = 0) -> List[EvidenceItem]:
    """Tool Gateway (prototype): ingest baseline dataset fields as evidence rows."""
    evidence_items: List[EvidenceItem] = []
    for k, v in baseline.items():
        text = str(v).strip() if v is not None else ""
        if not text or text.lower() in ("nan", "none"):
            continue
        if len(text) < 8:
            continue
        ev = store.add(
            text=text,
            source="localintel_dataset",
            metadata={"case_id": case_id, "step": int(step), "field": str(k), "evidence_type": "baseline"},
            extra=f"{case_id}|{step}|{k}",
        )
        evidence_items.append(ev)
    return evidence_items


def add_scenario_update_as_evidence(store: EvidenceStore, case_id: str, update_text: str, step: int) -> EvidenceItem:
    return store.add(
        text=update_text,
        source="scenario_update",
        metadata={"case_id": case_id, "step": int(step), "field": f"scenario_update_{step}", "evidence_type": "scenario_update"},
        extra=f"{case_id}|scenario|{step}",
    )


def retrieve_relevant(
    store: EvidenceStore,
    query: str,
    *,
    case_id: str,
    k: int = 8,
    current_step: Optional[int] = None,
    scope: str = "case_only",
) -> List[EvidenceItem]:
    """
    Retrieval with leakage-safe filtering.

    scope:
      - case_only: all evidence from same case
      - causal_case_only: same case and evidence with step <= current_step
      - global: no filter
    """
    where = None
    if scope == "case_only":
        where = {"case_id": case_id}
    elif scope == "causal_case_only":
        if current_step is None:
            raise ValueError("current_step is required for scope='causal_case_only'")
        where = {"$and": [{"case_id": case_id}, {"step": {"$lte": int(current_step)}}]}
    elif scope == "global":
        where = None
    else:
        raise ValueError(f"Unknown retrieval scope: {scope}")

    return store.query(query_text=query, k=k, where=where)