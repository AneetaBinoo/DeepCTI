"""E0 audit tests (Paper 2 Phase 1): unit tests of the face-value inference rules and a regression check against
30 hand-labelled Paper 1 episodes (tests/inquiry/fixtures/e0_hand_labels.json; skipped when runs/ is absent)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from deepcti.core.decision import CONFIG, FIX, IN_RANGE, PRESENT
from deepcti.extraction.parsers import CaseProgram
from deepcti.inquiry import audit as A

ROOT = Path(__file__).resolve().parents[2]


def _orc(disk=("1.0-1",), running=("1.0-1",), fixed="1.0-2"):
    prog = CaseProgram(cve="CVE-X", src_package="pkg", binaries=["pkg"], release="bookworm", status="resolved",
                       fixed_version=fixed, trusted=True)
    return A.Oracle(prog, set(disk), set(running), {}, {fixed})


def test_running_assumed_equal_to_disk_when_unobserved():
    o = _orc(disk=("1.0-2",), running=("1.0-2",))
    k = A.Knowledge(present={True}, disk={"1.0-2"}, ranges=True)
    assert A.infer(k, o)[FIX] is True and A.infer(k, o)[IN_RANGE] is False


def test_running_old_build_overrides_fixed_disk():
    o = _orc(disk=("1.0-2",), running=("1.0-1",))
    k = A.Knowledge(present={True}, disk={"1.0-2"}, running={"1.0-1"}, ranges=True)
    inf = A.infer(k, o)
    assert inf[IN_RANGE] is True and inf[FIX] is False


def test_versions_without_range_knowledge_decide_nothing():
    k = A.Knowledge(present={True}, disk={"1.0-1"}, ranges=False)
    assert A.infer(k, _orc())[IN_RANGE] is None


def test_scanner_finding_implies_not_fixed():
    k = A.Knowledge(present={True}, scanner={True})
    inf = A.infer(k, _orc())
    assert inf[IN_RANGE] is True and inf[FIX] is False


def test_conflicting_presence_is_unknown():
    assert A.infer(A.Knowledge(present={True, False}), _orc())[PRESENT] is None


def test_established_and_contradictions():
    req = [(PRESENT, True), (FIX, False), (IN_RANGE, True), (CONFIG, False)]
    k = A.Knowledge(present={True}, disk={"1.0-1"}, ranges=True, config={True})
    est = A.established(k, _orc(), req)
    assert est == {PRESENT: True, FIX: True, IN_RANGE: True, CONFIG: False}
    assert A.contradictions(k, req) == {"config"}


def test_gold_required_paths():
    g, req = A.gold_required({PRESENT: False})
    assert g == "not_affected" and req == [(PRESENT, False)]
    g, req = A.gold_required({PRESENT: True, IN_RANGE: True, FIX: False, CONFIG: False, "req_config": True})
    assert g == "not_affected" and [a for a, _ in req] == [PRESENT, FIX, IN_RANGE, CONFIG]
    g, req = A.gold_required({PRESENT: True, IN_RANGE: False, FIX: True, "req_config": False})
    assert g == "fixed" and req == [(PRESENT, True), (FIX, True)]


HAND = json.loads((ROOT / "tests" / "inquiry" / "fixtures" / "e0_hand_labels.json").read_text())["episodes"]


def _record(key: str, source_file: str) -> dict | None:
    path = ROOT / source_file
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            if r["key"] == key:
                return r
    return None


@pytest.mark.parametrize("lab", HAND, ids=[f"{i}:{h['note'][:30]}" for i, h in enumerate(HAND)])
def test_hand_labelled_episode(lab):
    r = _record(lab["key"], lab["source_file"])
    if r is None:
        pytest.skip("local run logs (runs/) not available")
    ep, rows = A.audit_record(r)
    missing = {x for x in str(ep["missing_at_decision"]).split(",") if x}
    assert missing == set(lab["missing"]), lab["note"]
    assert bool(ep["omission_2step"]) == lab["omission"], lab["note"]
    if lab["fixer"]:
        assert lab["fixer"] in ep["omission_fixers"], lab["note"]
    cats = {row["call_id"]: row["category"] for row in rows}
    for cid, want in lab["categories"].items():
        assert cats[cid] == want, f"{lab['note']}: {cid}"
    assert ep["replay_mismatches"] == 0
