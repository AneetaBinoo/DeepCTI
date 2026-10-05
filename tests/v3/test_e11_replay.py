"""Replay of recorded E2 episodes reproduces every recorded tool-output prefix (E11 evidence reconstruction)."""

import json
from pathlib import Path

import pytest

from deepcti.judge.evidence import dc_state_item, evidence_block, replay

RUN = Path(__file__).resolve().parents[2] / "runs" / "test" / "E2" / "qwen3_4b.jsonl"


@pytest.mark.skipif(not RUN.exists(), reason="E2 runs not present")
def test_replay_matches_recorded_prefixes():
    with RUN.open(encoding="utf-8") as fh:
        recs = [json.loads(next(fh)) for _ in range(40)]
    for r in recs:
        items, check = replay(r)
        assert check["mismatches"] == []
        assert [i["id"] for i in items] == [c["id"] for c in r["calls"]]
        assert all(i["output"].startswith(c["out"]) for i, c in zip(items, r["calls"]))
        block = evidence_block(items, r["system"])
        assert all(f"[{c['id']}]" in block for c in r["calls"])
        if r["system"] == "DC":
            assert dc_state_item(r)["id"] == "state"
