"""E11 on D7 (H15): D7 replay reproduces recorded outputs; paired sign-flip test sanity; family eligibility."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from deepcti.judge.d7 import GENERATOR_FAMILY_D7, eligible_d7, replay_d7, validated_synthesis
from deepcti.judge.paired import signflip_ratio_diff

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / "runs" / "d7" / "test" / "X2" / "qwen3_4b.jsonl"


@pytest.mark.skipif(not RUN.exists(), reason="D7 X2 runs not present")
def test_replay_d7_matches_recorded_outputs():
    n = 0
    with RUN.open() as fh:
        for line in fh:
            r = json.loads(line)
            if r["system"] not in ("DC", "DCv21") or r["error"]:
                continue
            items, chk = replay_d7(r)
            assert chk["mismatches"] == [] and chk["full_trace_mismatches"] == []
            assert [it["id"] for it in items] == [c["id"] for c in r["calls"]]
            if r["system"] == "DCv21":
                assert validated_synthesis(r) is not None
            n += 1
            if n >= 60:
                break
    assert n == 60


def test_eligibility_never_same_family():
    assert not eligible_d7("granite_41_30b", "granite41_30b")
    assert not eligible_d7("gemma_4_31b", "gemma4_31b")
    assert not eligible_d7("nemotron_super_49b", "llama31_8b")
    assert eligible_d7("gemma_4_31b", "granite41_30b")
    assert set(GENERATOR_FAMILY_D7) >= {"granite41_30b", "qwen3_4b"}


def test_signflip_null_and_effect():
    rng = np.random.default_rng(1)
    rows = []
    for c in range(40):
        for s in ("a", "b"):
            for _ in range(10):
                rows.append({"cve": c, "sys": s, "x": float(rng.random() < 0.8), "one": 1.0})
    df = pd.DataFrame(rows)
    _, p = signflip_ratio_diff(df[df.sys == "a"], df[df.sys == "b"], "cve", "x", "one", n=2000)
    assert p > 0.01
    df.loc[df.sys == "a", "x"] = 1.0
    t, p = signflip_ratio_diff(df[df.sys == "a"], df[df.sys == "b"], "cve", "x", "one", n=2000)
    assert t > 0.1 and p < 0.01
