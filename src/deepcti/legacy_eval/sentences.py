"""Distinct synthetic evidence sentences of the v0 dataset, their templates and v0-regex atoms."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from deepcti.datasets import load_contextual_jsonl
from deepcti.memory import extract_observations
from deepcti.schemas import CaseRecord, EvidenceRecord

ROOT = Path(__file__).resolve().parents[3]
LEGACY_DATASET = ROOT / "data" / "derived" / "deepcti_kev_contextual_synthetic_100_v1.jsonl"
PROFILES = ("affected", "not_applicable", "uncertain", "contradictory")
WORD = re.compile(r"[a-z0-9]+(?:[-.][a-z0-9]+)*")


def load_cases(path: Path = LEGACY_DATASET) -> list[CaseRecord]:
    return load_contextual_jsonl(path)


def local_evidence(case: CaseRecord) -> list[EvidenceRecord]:
    """Synthetic local-context evidence (the KEV public record yields no regex atoms and is excluded)."""
    return [e for e in case.initial_evidence + case.staged_evidence if e.field != "cisa_kev_record"]


def sentence_key(item: EvidenceRecord) -> tuple[str, str]:
    return (item.field, item.text)


def template_id(case: CaseRecord, item: EvidenceRecord) -> str:
    return f"{case.asset_context['profile_kind']}:s{item.step}"


def regex_atoms(item: EvidenceRecord, text: str | None = None) -> list[tuple[str, str]]:
    probe = item if text is None else replace(item, text=text)
    return sorted({(o.field, o.value) for o in extract_observations(probe)})


def distinct_sentences(cases: list[CaseRecord]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for case in cases:
        for item in local_evidence(case):
            key = sentence_key(item)
            if key not in seen:
                seen[key] = {
                    "sent_id": f"S{len(seen):03d}",
                    "template_id": template_id(case, item),
                    "profile": case.asset_context["profile_kind"],
                    "field": item.field,
                    "source_type": item.source_type,
                    "reliability": item.reliability,
                    "step": item.step,
                    "text": item.text,
                    "gold_atoms": [list(a) for a in regex_atoms(item)],
                    "case_ids": [],
                }
            seen[key]["case_ids"].append(case.case_id)
    return list(seen.values())


def tokens(text: str) -> set[str]:
    return set(WORD.findall(text.lower()))


def jaccard_distance(a: str, b: str) -> float:
    ta, tb = tokens(a), tokens(b)
    if not ta and not tb:
        return 0.0
    return 1.0 - len(ta & tb) / len(ta | tb)
