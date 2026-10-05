"""POST HOC E11-D7b (D23): X2B covers exactly the H15 DCv21 triples, replays cleanly, and the strict validator
rejects notes asserting another status."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from deepcti.agents.systems import validate_note
from deepcti.judge.d7 import replay_d7, validated_synthesis

ROOT = Path(__file__).resolve().parents[2]
X2B = ROOT / "runs" / "d7" / "test" / "X2B"
SAMPLE = ROOT / "results" / "v3" / "e11_d7" / "sample.csv"


@pytest.mark.skipif(not (X2B.exists() and SAMPLE.exists()), reason="X2B runs / H15 sample not present")
def test_x2b_triples_equal_h15_sample_and_replay():
    s = pd.read_csv(SAMPLE)
    want = set(zip(*(s[s.system == "DCv21"][c] for c in ("case_id", "model", "arm"))))
    got = set()
    for f in sorted(X2B.glob("*.jsonl")):
        for i, line in enumerate(f.read_text().splitlines()):
            r = json.loads(line)
            assert r["system"] == "DCv21b" and r["error"] is None
            got.add((r["case_id"], r["model"], r["arm"]))
            assert validated_synthesis(r) is not None
            if i < 10:
                _, chk = replay_d7(r)
                assert chk["mismatches"] == [] and chk["full_trace_mismatches"] == []
    assert got == want and len(got) == 504


def test_strict_validator_rejects_other_status():
    calls = {"c001": "package foo 1.2.3 installed"}
    note = "foo 1.2.3 is installed [c001]. The issue is marked as FIXED. Status: under investigation."
    assert not validate_note(note, "under_investigation", calls)
    errs = validate_note(note, "under_investigation", calls, strict=True)
    assert any(e.startswith("the note asserts status 'fixed'") for e in errs)
    ok = "foo 1.2.3 is installed [c001]; status: under investigation pending the fixed-version record."
    assert not validate_note(ok, "under_investigation", calls, strict=True)
