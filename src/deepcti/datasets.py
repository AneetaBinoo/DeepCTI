from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pandas as pd
import requests

from .attack import ATTACK_BUNDLE_URL, load_attack_mitigation_links, retrieve_attack_mitigations
from .schemas import CaseRecord, EvidenceRecord

CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATHENABENCH_RMS_MINI = (
    "https://raw.githubusercontent.com/Athena-Software-Group/athenabench/"
    "main/benchmark-mini/athena-cti-rms.jsonl"
)


def _clean(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return " ".join(str(value).split())


def download(url: str, destination: str | Path, *, timeout: int = 90) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    response = requests.get(url, timeout=timeout, headers={"User-Agent": "DeepCTI-research/0.3"})
    response.raise_for_status()
    destination.write_bytes(response.content)
    return destination


def fetch_public_benchmarks(data_root: str | Path) -> dict[str, Path]:
    root = Path(data_root)
    return {
        "cisa_kev": download(CISA_KEV_JSON, root / "public" / "cisa_kev.json"),
        "athenabench_rms_mini": download(
            ATHENABENCH_RMS_MINI, root / "public" / "athenabench_rms_mini.jsonl"
        ),
        "mitre_attack_enterprise_v19_1": download(
            ATTACK_BUNDLE_URL, root / "public" / "enterprise-attack-19.1.json"
        ),
    }


def load_athenabench_rms(path: str | Path) -> list[dict[str, Any]]:
    rows = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def load_athenabench_cases(
    path: str | Path,
    *,
    attack_corpus_path: str | Path | None = None,
    attack_retrieval_k: int = 8,
) -> list[CaseRecord]:
    cases = []
    attack_links = load_attack_mitigation_links(attack_corpus_path) if attack_corpus_path else []
    for row in load_athenabench_rms(path):
        digest = str(row.get("prompt_hash", ""))
        case_id = f"ATHENA-RMS-{digest[:12]}"
        evidence = EvidenceRecord.create(
            text=f"Observed behavior: {row.get('description', '')} Scenario: {row.get('scenario', '')}",
            source_type="athenabench_rms",
            source_uri="https://github.com/Athena-Software-Group/athenabench",
            case_id=case_id,
            step=0,
            field="attack_scenario",
            reliability="secondary",
            metadata={"prompt_hash": digest},
        )
        attack_evidence = retrieve_attack_mitigations(
            attack_links,
            query=f"{row.get('description', '')} {row.get('scenario', '')}",
            case_id=case_id,
            k=attack_retrieval_k,
        )
        cases.append(
            CaseRecord(
                case_id=case_id,
                question=(
                    "Recommend exactly two MITRE ATT&CK Enterprise mitigation IDs for the observed scenario. "
                    "Use only mitigation IDs supported by the supplied authoritative ATT&CK evidence."
                ),
                cve_id="",
                asset_context={"platform": "Windows"},
                initial_evidence=[evidence, *attack_evidence],
                staged_evidence=[],
                reference={
                    "final_answer": str(row.get("answer", "")),
                    "mitigation_ids": str(row.get("answer", "")),
                    "benchmark_technique_id": str(row.get("technique_id", "")),
                },
                source_dataset="athenabench_rms_mini",
                split="external_test",
                benchmark_prompt=str(row.get("prompt", "")),
            )
        )
    return cases


def load_cisa_kev(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return list(payload.get("vulnerabilities", []))


def load_contextual_jsonl(path: str | Path) -> list[CaseRecord]:
    cases = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            cases.append(
                CaseRecord(
                    case_id=str(row["case_id"]),
                    question=str(row["question"]),
                    cve_id=str(row.get("cve_id", "")),
                    asset_context=dict(row.get("asset_context", {})),
                    initial_evidence=[EvidenceRecord(**item) for item in row.get("initial_evidence", [])],
                    staged_evidence=[EvidenceRecord(**item) for item in row.get("staged_evidence", [])],
                    reference=dict(row.get("reference", {})),
                    source_dataset=str(row.get("source_dataset", "contextual_jsonl")),
                    split=str(row.get("split", "test")),
                    benchmark_prompt=str(row.get("benchmark_prompt", "")),
                )
            )
    return cases


def _source_for_field(field: str) -> tuple[str, str]:
    lower = field.lower()
    if "global" in lower or "cve" in lower:
        return "public_cti", "legacy://public-cti"
    if "local" in lower or "dependency" in lower or "version" in lower:
        return "local_context", "legacy://local-context"
    return "case_input", "legacy://case-input"


def load_legacy_xlsx(path: str | Path) -> list[CaseRecord]:
    frame = pd.read_excel(path, sheet_name="DeepCTI_Run_Input")
    frame.columns = [str(column).strip() for column in frame.columns]
    scenario_columns = [f"Scenario Step {i}: New Info Arrives" for i in range(1, 4)]
    expected_columns = [f"Scenario Step {i}: Expected Update" for i in range(1, 4)]
    blocked = set(scenario_columns + expected_columns + ["Ground_truth"])
    cases: list[CaseRecord] = []

    for row_index, row in frame.iterrows():
        raw_id = _clean(row.get("id")) or f"LI-{row_index + 1:03d}"
        case_id = raw_id if raw_id.startswith("LI-") else f"LI-{row_index + 1:03d}"
        initial: list[EvidenceRecord] = []
        asset_context: dict[str, Any] = {}
        for column in frame.columns:
            if column in blocked:
                continue
            text = _clean(row.get(column))
            if not text:
                continue
            source_type, source_uri = _source_for_field(column)
            record = EvidenceRecord.create(
                text=text,
                source_type=source_type,
                source_uri=source_uri,
                case_id=case_id,
                step=0,
                field=column,
                reliability="unknown" if source_type == "case_input" else "secondary",
                metadata={"row_index": int(row_index)},
            )
            initial.append(record)
            if source_type == "local_context":
                asset_context[column] = text

        staged = []
        for step, column in enumerate(scenario_columns, start=1):
            text = _clean(row.get(column))
            if text:
                staged.append(
                    EvidenceRecord.create(
                        text=text,
                        source_type="staged_evidence",
                        source_uri="legacy://staged-evidence",
                        case_id=case_id,
                        step=step,
                        field=f"E{step}",
                        reliability="unknown",
                    )
                )

        cases.append(
            CaseRecord(
                case_id=case_id,
                question=_clean(row.get("Questions")),
                cve_id=_clean(row.get("CVE")),
                asset_context=asset_context,
                initial_evidence=initial,
                staged_evidence=staged,
                reference={
                    "final_answer": _clean(row.get("Ground_truth")),
                    "expected_updates": [_clean(row.get(c)) for c in expected_columns],
                },
                source_dataset="legacy_deepcti_61",
            )
        )
    return cases


def build_kev_seed_cases(rows: Iterable[dict[str, Any]], *, limit: int | None = None) -> list[CaseRecord]:
    """Create seed cases from public evidence."""
    cases: list[CaseRecord] = []
    for index, row in enumerate(rows):
        if limit is not None and index >= limit:
            break
        cve = str(row.get("cveID", "")).strip()
        case_id = f"KEV-{cve}" if cve else f"KEV-{index + 1:04d}"
        text = " ".join(
            filter(
                None,
                [
                    row.get("vendorProject", ""),
                    row.get("product", ""),
                    row.get("vulnerabilityName", ""),
                    row.get("shortDescription", ""),
                    f"Required action: {row.get('requiredAction', '')}",
                ],
            )
        )
        evidence = EvidenceRecord.create(
            text=text,
            source_type="cisa_kev",
            source_uri=CISA_KEV_JSON,
            case_id=case_id,
            step=0,
            field="cisa_kev_record",
            published_at=row.get("dateAdded"),
            reliability="authoritative",
            metadata={"known_ransomware_campaign_use": row.get("knownRansomwareCampaignUse")},
        )
        cases.append(
            CaseRecord(
                case_id=case_id,
                question=f"What mitigation evidence is required before acting on {cve}?",
                cve_id=cve,
                asset_context={},
                initial_evidence=[evidence],
                staged_evidence=[],
                reference={"required_action": row.get("requiredAction", "")},
                source_dataset="cisa_kev",
                split="unannotated",
            )
        )
    return cases
