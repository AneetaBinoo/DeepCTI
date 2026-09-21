from __future__ import annotations

import re
import time
from dataclasses import asdict
from typing import Any, ClassVar, Protocol

import requests

from .schemas import EvidenceRecord, ToolCallRecord, utc_now


class ReadOnlyTool(Protocol):
    name: str

    def execute(self, *, case_id: str, arguments: dict[str, Any]) -> list[EvidenceRecord]: ...


class NVDLookup:
    name = "nvd_lookup"

    def __init__(self, *, timeout: int = 30) -> None:
        self.timeout = timeout

    def execute(self, *, case_id: str, arguments: dict[str, Any]) -> list[EvidenceRecord]:
        cve_id = str(arguments.get("cve_id", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ValueError("nvd_lookup requires a CVE identifier")
        uri = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(uri, timeout=self.timeout, headers={"User-Agent": "DeepCTI-research/0.3"})
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
        if not vulnerabilities:
            return []
        cve = vulnerabilities[0].get("cve", {})
        descriptions = [
            item.get("value", "") for item in cve.get("descriptions", []) if item.get("lang") == "en"
        ]
        references = [item.get("url", "") for item in cve.get("references", [])]
        text = " ".join(descriptions + ["References: " + "; ".join(references[:20])])
        return [
            EvidenceRecord.create(
                text=text,
                source_type="nvd_api",
                source_uri=uri,
                case_id=case_id,
                step=0,
                field="nvd_cve",
                published_at=cve.get("published"),
                reliability="authoritative",
                metadata={"last_modified": cve.get("lastModified")},
            )
        ]


class ToolGateway:
    """Run approved read-only tools."""

    def __init__(self, tools: list[ReadOnlyTool]) -> None:
        self.tools = {tool.name: tool for tool in tools}

    def call(
        self, tool_name: str, *, case_id: str, arguments: dict[str, Any]
    ) -> tuple[list[EvidenceRecord], ToolCallRecord]:
        started_at = utc_now()
        started = time.perf_counter()
        evidence: list[EvidenceRecord] = []
        status = "ok"
        error = ""
        try:
            if tool_name not in self.tools:
                raise PermissionError(f"Tool is not allowlisted: {tool_name}")
            evidence = self.tools[tool_name].execute(case_id=case_id, arguments=arguments)
        except requests.Timeout as exc:
            status, error = "timeout", str(exc)
        except PermissionError as exc:
            status, error = "denied", str(exc)
        except ValueError as exc:
            status, error = "invalid", str(exc)
        except requests.RequestException as exc:
            status, error = "error", f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # noqa: BLE001 - isolate arbitrary tool implementation failures
            status, error = "error", f"{type(exc).__name__}: {exc}"
        record = ToolCallRecord(
            tool_name=tool_name,
            arguments=arguments,
            started_at=started_at,
            duration_ms=(time.perf_counter() - started) * 1000,
            status=status,  # type: ignore[arg-type]
            evidence_ids=[item.evidence_id for item in evidence],
            error=error,
        )
        return evidence, record

    @staticmethod
    def serialize(record: ToolCallRecord) -> dict[str, Any]:
        return asdict(record)


class ReadOnlyToolPolicy:
    """Select approved tools and reject changes."""

    MUTATING_CUES: ClassVar[set[str]] = {
        "delete",
        "disable",
        "install",
        "patch",
        "restart",
        "execute",
        "quarantine",
    }

    def select(self, *, cve_id: str, information_needs: list[str]) -> list[dict[str, Any]]:
        joined = " ".join(information_needs).lower()
        if set(re.findall(r"[a-z]+", joined)) & self.MUTATING_CUES:
            return []
        if cve_id.upper().startswith("CVE-") and any(
            cue in joined for cue in ("version", "advisory", "severity", "description", "reference")
        ):
            return [{"tool_name": "nvd_lookup", "arguments": {"cve_id": cve_id.upper()}}]
        return []
