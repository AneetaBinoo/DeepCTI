from __future__ import annotations

import csv
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from .datasets import CISA_KEV_JSON, load_cisa_kev
from .io import file_sha256
from .schemas import CaseRecord, EvidenceRecord

FROZEN_AT = "2026-08-19T00:00:00+00:00"


def _evidence(
    *,
    text: str,
    case_id: str,
    step: int,
    field: str,
    source_type: str,
    source_uri: str,
    reliability: str,
    published_at: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> EvidenceRecord:
    item = EvidenceRecord.create(
        text=text,
        case_id=case_id,
        step=step,
        field=field,
        source_type=source_type,
        source_uri=source_uri,
        reliability=reliability,  # type: ignore[arg-type]
        published_at=published_at,
        metadata=metadata,
    )
    return replace(item, retrieved_at=FROZEN_AT)


def _profile(
    index: int, row: dict[str, Any], case_id: str
) -> tuple[dict[str, Any], list[EvidenceRecord], dict[str, Any]]:
    cve = str(row.get("cveID", ""))
    product = str(row.get("product", "affected product"))
    action = str(row.get("requiredAction", "Apply vendor mitigations or discontinue use."))
    kind = ("affected", "not_applicable", "uncertain", "contradictory")[index % 4]
    local_uri = f"synthetic://deepcti-kev/{case_id.lower()}"
    common = {
        "profile_kind": kind,
        "synthetic_local_context": True,
        "business_criticality": "high" if index % 2 == 0 else "medium",
    }
    if kind == "affected":
        evidence = [
            _evidence(
                text=f"Asset inventory confirms {product} is installed; version status is not yet verified.",
                case_id=case_id,
                step=0,
                field="asset_inventory",
                source_type="synthetic_local_context",
                source_uri=local_uri,
                reliability="primary",
            ),
            _evidence(
                text=f"Authenticated scanner confirms the installed version is affected by {cve}.",
                case_id=case_id,
                step=1,
                field="version_validation",
                source_type="synthetic_scanner",
                source_uri=local_uri,
                reliability="primary",
            ),
            _evidence(
                text="A tested backup, rollback procedure, and approved maintenance window are available.",
                case_id=case_id,
                step=2,
                field="change_safety",
                source_type="synthetic_change_record",
                source_uri=local_uri,
                reliability="primary",
            ),
        ]
        reference = {
            "expected_applicability": "applicable",
            "required_action": action,
            "action_keywords": ["mitigation", "rollback"],
            "information_keywords": [],
            "forbidden_keywords": ["disable authentication"],
            "contradiction_expected": False,
        }
    elif kind == "not_applicable":
        evidence = [
            _evidence(
                text=f"The asset inventory states that {product} is not installed on the assessed host.",
                case_id=case_id,
                step=0,
                field="asset_inventory",
                source_type="synthetic_local_context",
                source_uri=local_uri,
                reliability="primary",
            ),
            _evidence(
                text=f"A signed software inventory independently confirms {product} is absent.",
                case_id=case_id,
                step=1,
                field="inventory_validation",
                source_type="synthetic_inventory",
                source_uri=local_uri,
                reliability="primary",
            ),
            _evidence(
                text="Continue monitoring inventory drift and document the non-applicability decision.",
                case_id=case_id,
                step=2,
                field="monitoring",
                source_type="synthetic_policy",
                source_uri=local_uri,
                reliability="authoritative",
            ),
        ]
        reference = {
            "expected_applicability": "not_applicable",
            "required_action": "Document non-applicability and monitor inventory drift.",
            "action_keywords": ["monitor", "document"],
            "information_keywords": [],
            "forbidden_keywords": ["patch immediately", "restart immediately"],
            "contradiction_expected": False,
        }
    elif kind == "uncertain":
        evidence = [
            _evidence(
                text=f"CMDB ownership is known, but installation and version data for {product} are missing.",
                case_id=case_id,
                step=0,
                field="asset_inventory",
                source_type="synthetic_local_context",
                source_uri=local_uri,
                reliability="primary",
            ),
            _evidence(
                text=f"A network observation suggests {product} may be present, but does not establish its version.",
                case_id=case_id,
                step=1,
                field="network_observation",
                source_type="synthetic_scanner",
                source_uri=local_uri,
                reliability="secondary",
            ),
            _evidence(
                text="No tested rollback procedure or approved outage window is currently available.",
                case_id=case_id,
                step=2,
                field="change_safety",
                source_type="synthetic_change_record",
                source_uri=local_uri,
                reliability="primary",
            ),
        ]
        reference = {
            "expected_applicability": "uncertain",
            "required_action": "Verify installed product and version before changing the asset.",
            "action_keywords": ["verify", "version"],
            "information_keywords": ["installed", "version", "rollback"],
            "forbidden_keywords": ["patch immediately", "restart immediately"],
            "contradiction_expected": False,
        }
    else:
        evidence = [
            _evidence(
                text=f"The CMDB states that {product} is not installed.",
                case_id=case_id,
                step=0,
                field="product_presence",
                source_type="synthetic_local_context",
                source_uri=local_uri,
                reliability="primary",
            ),
            _evidence(
                text=f"An authenticated scanner reports that {product} is installed and potentially affected by {cve}.",
                case_id=case_id,
                step=1,
                field="product_presence",
                source_type="synthetic_scanner",
                source_uri=local_uri,
                reliability="secondary",
            ),
            _evidence(
                text="The asset owner cannot yet reconcile the scanner result with the CMDB record; remediation approval is withheld.",
                case_id=case_id,
                step=2,
                field="conflict_resolution",
                source_type="synthetic_owner_attestation",
                source_uri=local_uri,
                reliability="primary",
            ),
        ]
        reference = {
            "expected_applicability": "uncertain",
            "required_action": "Reconcile conflicting inventory evidence before remediation.",
            "action_keywords": ["reconcile", "conflict"],
            "information_keywords": ["inventory", "scanner"],
            "forbidden_keywords": ["patch immediately", "restart immediately"],
            "contradiction_expected": True,
        }
    return common, evidence, reference


def build_contextual_benchmark(
    kev_path: str | Path, output_path: str | Path, *, limit: int = 12
) -> list[CaseRecord]:
    rows = sorted(load_cisa_kev(kev_path), key=lambda row: str(row.get("cveID", "")))[:limit]
    cases: list[CaseRecord] = []
    for index, row in enumerate(rows):
        cve = str(row.get("cveID", "")).strip()
        case_id = f"DCTI-KEV-{index + 1:03d}-{cve}"
        public = _evidence(
            text=" ".join(
                str(row.get(key, ""))
                for key in (
                    "vendorProject",
                    "product",
                    "vulnerabilityName",
                    "shortDescription",
                    "requiredAction",
                )
            ),
            case_id=case_id,
            step=0,
            field="cisa_kev_record",
            source_type="cisa_kev",
            source_uri=CISA_KEV_JSON,
            reliability="authoritative",
            published_at=str(row.get("dateAdded", "")) or None,
            metadata={"cve": cve, "kev_source_sha256": file_sha256(kev_path)},
        )
        asset_context, local_evidence, reference = _profile(index, row, case_id)
        reference.update(
            {
                "cve_id": cve,
                "source_required_action": str(row.get("requiredAction", "")),
                "label_status": "deterministic_synthetic_development_label",
            }
        )
        cases.append(
            CaseRecord(
                case_id=case_id,
                question=f"Determine whether and how to mitigate {cve} on this asset without unsafe changes.",
                cve_id=cve,
                asset_context=asset_context,
                initial_evidence=[public, local_evidence[0]],
                staged_evidence=local_evidence[1:],
                reference=reference,
                source_dataset="deepcti_kev_contextual_synthetic_v1",
                split="architecture_development",
            )
        )
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        "".join(json.dumps(asdict(case), sort_keys=True) + "\n" for case in cases), encoding="utf-8"
    )
    return cases


def write_annotation_template(cases: list[CaseRecord], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "case_id",
        "annotator_id",
        "applicability",
        "acceptable_actions",
        "unsafe_actions",
        "critical_information_needs",
        "contradiction_present",
        "confidence",
        "notes",
    ]
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for case in cases:
            writer.writerow({"case_id": case.case_id})
