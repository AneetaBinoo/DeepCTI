from __future__ import annotations

from typing import Any, Dict, List


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if not isinstance(x, str):
            continue
        x = x.strip()
        if not x:
            continue
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def verify_claims(store, llm_out: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verifies whether cited evidence IDs exist in the evidence store.
    This is an existence check (not semantic fact verification).
    """
    claims = llm_out.get("claims", []) or []
    verified_claims: List[Dict[str, Any]] = []
    verified_count = 0

    for c in claims:
        if not isinstance(c, dict):
            continue

        claim_text = str(c.get("claim", "")).strip()
        raw_ev_ids = c.get("evidence_ids", []) or []

        # ✅ Deduplicate IDs to avoid Chroma DuplicateIDError
        ev_ids = _dedupe_preserve_order(raw_ev_ids)

        # Look up cited evidence (safe even if empty)
        cited = store.get_items(ev_ids) if ev_ids else []
        found_ids = [e.evidence_id for e in cited]

        missing_ids = [eid for eid in ev_ids if eid not in found_ids]
        is_verified = len(ev_ids) > 0 and len(missing_ids) == 0

        if is_verified:
            verified_count += 1

        verified_claims.append(
            {
                "claim": claim_text,
                "evidence_ids": ev_ids,  # deduped list
                "found_evidence_ids": found_ids,
                "missing_evidence_ids": missing_ids,
                "is_verified": is_verified,
                "confidence": c.get("confidence", "low"),
            }
        )

    total = len(verified_claims)
    verified_percent = round((verified_count / total), 4) if total > 0 else 0.0

    return {
        "verified_claims": verified_claims,
        "verification_summary": {
            "num_claims": total,
            "num_verified_claims": verified_count,
            "verified_percent": verified_percent,
        },
    }