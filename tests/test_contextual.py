import json

from deepcti.contextual import build_contextual_benchmark
from deepcti.datasets import load_contextual_jsonl


def test_contextual_builder_is_deterministic_and_staged(tmp_path) -> None:
    source = tmp_path / "kev.json"
    rows = []
    for index in range(4):
        rows.append(
            {
                "cveID": f"CVE-2025-000{index}",
                "vendorProject": "Vendor",
                "product": "Product",
                "vulnerabilityName": "Issue",
                "shortDescription": "Description",
                "requiredAction": "Apply the vendor mitigation.",
                "dateAdded": "2025-01-01",
            }
        )
    source.write_text(json.dumps({"vulnerabilities": rows}), encoding="utf-8")
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"

    cases = build_contextual_benchmark(source, first, limit=4)
    build_contextual_benchmark(source, second, limit=4)

    assert first.read_bytes() == second.read_bytes()
    assert len(cases) == 4
    assert {case.asset_context["profile_kind"] for case in cases} == {
        "affected",
        "not_applicable",
        "uncertain",
        "contradictory",
    }
    assert all(len(case.initial_evidence) == 2 for case in cases)
    assert all(len(case.staged_evidence) == 2 for case in cases)
    assert len(load_contextual_jsonl(first)) == 4
