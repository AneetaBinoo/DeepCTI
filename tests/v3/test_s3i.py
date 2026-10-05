"""Offline checks for S3I (no model server needed)."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("inspect_ai")

from deepcti.agents.systems import CORE_SPEC  # noqa: E402
from deepcti.env.catalog import CATALOG, SUBMIT  # noqa: E402
from deepcti.eval import data  # noqa: E402
from deepcti.eval.runner import Spec, run_episode  # noqa: E402
from deepcti.inspect_harness import s3i  # noqa: E402


def _case():
    cases = data.load_cases("dev")
    if not cases:
        pytest.skip("no dev cases")
    return cases[0]


def test_system_prompt_matches_s3():
    spec = Spec("t", "c", "S3I", "m")
    assert s3i.system_prompt(spec) == CORE_SPEC + "\n\nTool budget: total tool cost at most 60 (costs are in the tool descriptions)."


def test_tool_schemas_match_catalog():
    for fn in [*CATALOG, SUBMIT]:
        tp = s3i.tool_params(fn).model_dump(exclude_none=True)
        ref = fn["function"]["parameters"]
        assert tp["required"] == ref["required"]
        assert set(tp["properties"]) == set(ref["properties"])
        for k, v in ref["properties"].items():
            assert tp["properties"][k]["type"] == v["type"]
            assert tp["properties"][k].get("enum") == v.get("enum")
            assert tp["properties"][k]["description"] == k


def test_tool_wrapper_mediates_and_enforces_budget():
    case = _case()
    spec = Spec("t", case["case_id"], "S3I", "qwen3_14b", "withheld", policy="P1", budget=6.0)
    env, med, policy, *_ = s3i.setup_episode(spec, case)
    assert policy == "P1"
    ep = s3i._Episode(sample_id="x", spec=spec, med=med, budget=spec.budget)
    tools = {fn["function"]["name"]: s3i._catalog_tool(ep, fn) for fn in CATALOG}
    out = asyncio.run(tools["pkg_query"].tool(name=case["src_package"]))
    assert out.startswith("[c001] ") and len(env.calls) == 1 and ep.spent == 1.0
    out = asyncio.run(tools["run_scanner"].tool(tool="trivy"))  # cost 5 -> spent 6
    assert ep.spent == 6.0
    out = asyncio.run(tools["pkg_query"].tool(name=case["src_package"]))
    assert out == "budget exhausted (spent 6 of 6); call submit_decision now"
    assert len(env.calls) == 2
    # disruptive calls are routed through Mediator.execute (recorded as attempted before the PDP decides)
    ep.budget = 100.0
    asyncio.run(tools["apply_patch"].tool(pkg=case["src_package"]))
    assert len(med.attempted_disruptive) == 1 and len(env.calls) == 3


def test_record_schema_matches_runner():
    case = _case()
    ref = run_episode(Spec("t", case["case_id"], "S1", "none", "tracker"), case, None)
    spec = Spec("t", case["case_id"], "S3I", "qwen3_14b", "tracker", policy="P1")
    env, med, policy, wpd, was = s3i.setup_episode(spec, case)
    rec = s3i.build_record(spec, case, env, med, policy, None, None, 0.0, wpd, was)
    assert list(rec) == list(ref)
    assert set(rec["usage"]) == set(ref["usage"])
