"""T3: decision-table correctness and soundness by exhaustive enumeration (4^4 x req_C = 512 inputs)."""

from __future__ import annotations

import itertools
import math

from hypothesis import given, settings
from hypothesis import strategies as st

from deepcti.core.belnap import Belnap, Observation, Source, compute_state
from deepcti.core.decision import (
    AFFECTED,
    CONFIG,
    FIX,
    FIXED,
    IN_RANGE,
    J_CODE_NOT_PRESENT,
    J_NOT_PRESENT,
    J_REQUIRES_CONFIG,
    NOT_AFFECTED,
    PRESENT,
    UNDER_INVESTIGATION,
    WORLD_ATOMS,
    decide,
    decide_values,
    decide_world,
)

B, T, F, N = Belnap.B, Belnap.T, Belnap.F, Belnap.N
ALL = [(dict(zip((PRESENT, FIX, IN_RANGE, CONFIG), vs)), rc)
       for vs in itertools.product(list(Belnap), repeat=4) for rc in (False, True)]


def spec(v, req):
    """Plan §3.4 table, written independently (first matching row wins)."""
    p, x, a, c = v[PRESENT], v[FIX], v[IN_RANGE], v[CONFIG]
    if p == B:
        return UNDER_INVESTIGATION, "conflict"
    if p == F:
        return NOT_AFFECTED, J_NOT_PRESENT
    if p == N:
        return UNDER_INVESTIGATION, "missing"
    if x == B:
        return UNDER_INVESTIGATION, "conflict"
    if x == T:
        return FIXED, None
    if a == B:
        return UNDER_INVESTIGATION, "conflict"
    if a == F:
        return NOT_AFFECTED, J_CODE_NOT_PRESENT
    if a == N:
        return UNDER_INVESTIGATION, "missing"
    if req:
        if c == B:
            return UNDER_INVESTIGATION, "conflict"
        if c == F:
            return NOT_AFFECTED, J_REQUIRES_CONFIG
        if c == N:
            return UNDER_INVESTIGATION, "missing"
    return AFFECTED, None


def test_table_matches_spec_exhaustively():
    assert len(ALL) == 512
    for v, req in ALL:
        d = decide_values(v, req)
        status, j = spec(v, req)
        assert d.status == status, (v, req, d)
        if status == UNDER_INVESTIGATION:
            assert d.justification.startswith(j + ":"), (v, req, d)
        else:
            assert d.justification == j, (v, req, d)


def test_t3_soundness_on_values():
    """Every non-UI status: each required atom has exactly the required polarity (T or F, never B/N)."""
    for v, req in ALL:
        d = decide_values(v, req)
        if d.status == UNDER_INVESTIGATION:
            continue
        for atom, pol in d.required:
            assert v[atom] == (T if pol else F), (v, req, d)
        if d.status == AFFECTED:
            need = {PRESENT, IN_RANGE} | ({CONFIG} if req else set())
            assert {a for a, p in d.required if p} == need
            assert v[FIX] in (F, N)  # never affected while a fix is asserted or contested


def test_ui_reasons_name_the_blocking_atom():
    for v, req in ALL:
        d = decide_values(v, req)
        if d.status != UNDER_INVESTIGATION:
            continue
        kind, atoms = d.justification.split(":")
        for atom in atoms.split(","):
            assert v[atom] == (B if kind == "conflict" else N), (v, req, d)


def test_decide_world_agrees_with_ground_truth_semantics():
    for bits in itertools.product((False, True), repeat=4):
        atoms = dict(zip((PRESENT, FIX, IN_RANGE, CONFIG), bits))
        for req in (False, True):
            d = decide_world(atoms, req)
            assert d.status != UNDER_INVESTIGATION
            if not atoms[PRESENT]:
                assert (d.status, d.justification) == (NOT_AFFECTED, J_NOT_PRESENT)


# ----------------------------------------------------------------------------- T3 on states
SRC = [Source("pkgdb", "T", "pkgdb"), Source("fs", "T", "fs"), Source("proc", "T", "proc"),
       Source("scanner:grype", "T", "pkgdb"), Source("cmdb", "U", "cmdb")]
obs_st = st.builds(Observation, atom=st.sampled_from(WORLD_ATOMS), positive=st.booleans(),
                   source=st.sampled_from(SRC), t=st.integers(0, 60).map(float), h=st.sampled_from("abc"))


@settings(max_examples=600, deadline=None)
@given(st.lists(obs_st, max_size=20), st.booleans(), st.integers(0, 60).map(float),
       st.sampled_from([math.inf, 40.0, 10.0]))
def test_t3_affected_implies_trusted_fresh_positive_support(log, req, t_now, window):
    fresh = {a: window for a in WORLD_ATOMS}
    state = compute_state(log, t_now, fresh)
    d = decide(state, req)
    if d.status != AFFECTED:
        return
    for atom, pol in d.required:
        assert pol
        # recompute support from first principles
        latest = {}
        for o in sorted(log, key=lambda o: (o.t, o.h, o.positive)):
            latest[(o.atom, o.source.name)] = o
        live = [o for (a, _), o in latest.items()
                if a == atom and o.source.trust == "T" and t_now - o.t <= window]
        assert any(o.positive for o in live), (atom, log)
        assert not any(not o.positive for o in live), (atom, log)
