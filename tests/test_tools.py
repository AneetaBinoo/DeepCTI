from typing import Any

from deepcti.schemas import EvidenceRecord
from deepcti.tools import ReadOnlyToolPolicy, ToolGateway


class BrokenTool:
    name = "broken"

    def execute(self, *, case_id: str, arguments: dict[str, Any]) -> list[EvidenceRecord]:
        raise RuntimeError("boom")


def test_gateway_records_unexpected_tool_failure() -> None:
    evidence, record = ToolGateway([BrokenTool()]).call("broken", case_id="CASE-1", arguments={})
    assert evidence == []
    assert record.status == "error"
    assert record.error == "RuntimeError: boom"


def test_read_only_policy_selects_lookup_and_denies_mutation() -> None:
    policy = ReadOnlyToolPolicy()
    assert policy.select(cve_id="CVE-2025-0001", information_needs=["Verify installed version"])
    assert not policy.select(cve_id="CVE-2025-0001", information_needs=["Restart and patch host"])
