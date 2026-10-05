"""Property tests for the Belnap evidence state (plan §3.1-§3.3; theorems T1, T2).

Sources are drawn from a fixed registry (one Source object per name), which is the model the
theorems are stated in. A separate xfail documents what happens when that registry assumption is
violated inside the code base itself (parsers.py downgrades trust by re-using the source name).
"""

from __future__ import annotations

import math
import random

from hypothesis import given, settings
from hypothesis import strategies as st

from deepcti.core.belnap import (
    Belnap,
    EvidenceLog,
    Observation,
    Source,
    compute_state,
    leq_k,
)

ATOMS = ("present", "in_affected_range", "fix_applied", "vuln_config_enabled")
REGISTRY = (
    Source("pkgdb", "T", "pkgdb"),
    Source("scanner:trivy", "T", "pkgdb"),  # shares the pkgdb group
    Source("fs", "T", "fs"),
    Source("proc", "T", "proc"),
    Source("cmdb", "U", "cmdb"),
    Source("advisory:nvd", "U", "advisory:nvd"),
)

obs_st = st.builds(
    Observation,
    atom=st.sampled_from(ATOMS),
    positive=st.booleans(),
    source=st.sampled_from(REGISTRY),
    t=st.integers(0, 30).map(float),
    h=st.sampled_from(["h0", "h1", "h2"]),
    evidence_id=st.sampled_from(["", "c001", "c002"]),
)
logs = st.lists(obs_st, max_size=25)
fresh_st = st.dictionaries(st.sampled_from(ATOMS), st.sampled_from([5.0, 10.0, 40.0, math.inf]))


def vals(state):
    return {a: s.val for a, s in state.items()}


def project(state):
    """Everything in AtomState except evidence ids (see test_evidence_ids_order_independent)."""
    return {a: (s.val, s.pos_groups, s.neg_groups, s.hints_pos, s.hints_neg, s.stale_dropped)
            for a, s in state.items()}


# ----------------------------------------------------------------------------- T1
@settings(max_examples=400, deadline=None)
@given(logs, st.randoms(use_true_random=False), st.integers(0, 40).map(float), fresh_st)
def test_t1_order_independence(log, rnd, t_now, fresh):
    # evidence_id is not part of key(): strip it so the generator never creates two observations
    # with the same key and different evidence ids (unreachable in the pipeline: call ids are unique
    # per (t, h)). See test_evidence_ids_tie for that corner.
    log = [Observation(o.atom, o.positive, o.source, o.t, o.h, f"{o.source.name}:{o.t}:{o.h}") for o in log]
    shuffled = list(log)
    rnd.shuffle(shuffled)
    a = compute_state(log, t_now, fresh)
    b = compute_state(shuffled, t_now, fresh)
    assert project(a) == project(b)
    assert {k: v.evidence_ids for k, v in a.items()} == {k: v.evidence_ids for k, v in b.items()}


@settings(max_examples=300, deadline=None)
@given(logs, st.integers(0, 40).map(float), fresh_st)
def test_t1_idempotent_duplicate_ingestion(log, t_now, fresh):
    once = EvidenceLog()
    once.extend(log)
    twice = EvidenceLog()
    twice.extend(log)
    added_again = twice.extend(log)
    assert added_again == 0
    assert len(once) == len(twice)
    assert project(compute_state(once, t_now, fresh)) == project(compute_state(twice, t_now, fresh))
    # compute_state itself is idempotent on raw duplicated input too
    assert project(compute_state(log + log, t_now, fresh)) == project(compute_state(log, t_now, fresh))


# ----------------------------------------------------------------------------- T2
@settings(max_examples=400, deadline=None)
@given(logs, logs, st.integers(0, 40).map(float), fresh_st)
def test_t2_information_monotonicity(base, extra, t_now, fresh):
    """Adding observations from (atom, source) pairs not yet in the log moves every atom up in <=k."""
    seen = {(o.atom, o.source.name) for o in base}
    extra = [o for o in extra if (o.atom, o.source.name) not in seen]
    before = compute_state(base, t_now, fresh)
    after = compute_state(base + extra, t_now, fresh)
    for atom in set(before) | set(after):
        vb = before[atom].val if atom in before else Belnap.N
        va = after[atom].val if atom in after else Belnap.N
        assert leq_k(vb, va), (atom, vb, va)
        if atom in before:
            assert before[atom].pos_groups <= after[atom].pos_groups
            assert before[atom].neg_groups <= after[atom].neg_groups


def test_leq_k_is_the_bilattice_knowledge_order():
    order = {(Belnap.N, x) for x in Belnap} | {(x, Belnap.B) for x in Belnap} | {(x, x) for x in Belnap}
    for a in Belnap:
        for b in Belnap:
            assert leq_k(a, b) == ((a, b) in order)


# ----------------------------------------------------------------------------- semantics
@settings(max_examples=300, deadline=None)
@given(logs, st.integers(0, 40).map(float), fresh_st)
def test_value_matches_reference(log, t_now, fresh):
    """Independent re-implementation of §3.3: latest per (atom, source) by (t, h), trusted+fresh, groups."""
    state = compute_state(log, t_now, fresh)
    latest = {}
    for o in sorted(log, key=lambda o: (o.t, o.h, o.positive)):
        latest[(o.atom, o.source.name)] = o
    for atom in {o.atom for o in log}:
        pos, neg = set(), set()
        for (a, _), o in latest.items():
            if a != atom or o.source.trust != "T" or t_now - o.t > fresh.get(atom, math.inf):
                continue
            (pos if o.positive else neg).add(o.source.group)
        assert state[atom].pos_groups == pos
        assert state[atom].neg_groups == neg
        assert state[atom].val == Belnap.from_support(len(pos), len(neg))


@settings(max_examples=300, deadline=None)
@given(logs, logs, st.integers(0, 40).map(float), fresh_st)
def test_untrusted_sources_are_hints_only(log, noise, t_now, fresh):
    noise = [o for o in noise if o.source.trust == "U"]
    a = compute_state(log, t_now, fresh)
    b = compute_state(log + noise, t_now, fresh)
    for atom, s in b.items():
        ref = a.get(atom)
        assert s.val == (ref.val if ref else Belnap.N)
        assert s.pos_groups == (ref.pos_groups if ref else frozenset())


def test_support_counted_in_groups_not_sources():
    t = [Observation("present", True, REGISTRY[0], 1.0, "a"), Observation("present", True, REGISTRY[1], 1.0, "b")]
    s = compute_state(t, 1.0)["present"]
    assert s.val == Belnap.T and s.kappa_pos == 1  # pkgdb and scanner:trivy share a group


def test_stale_latest_observation_removes_source():
    src = REGISTRY[0]
    log = [Observation("present", True, src, 0.0, "a"), Observation("present", False, src, 5.0, "b")]
    st_ = compute_state(log, 50.0, {"present": 40.0})["present"]
    assert st_.val == Belnap.N and st_.stale_dropped == 1


def test_source_update_is_latest_wins():
    src = REGISTRY[2]
    log = [Observation("present", False, src, 3.0, "x"), Observation("present", True, src, 2.0, "y")]
    assert compute_state(log, 3.0)["present"].val == Belnap.F


# ----------------------------------------------------------------------------- defects
def test_evidence_ids_tie_order_dependent_but_unreachable():
    """Two observations with the same key() and different evidence ids: the first one wins.

    Order dependence of evidence_ids only (never of val/groups). Unreachable in the pipeline
    because call ids are unique per (t, h). Documented, not marked as a bug.
    """
    s = REGISTRY[0]
    o1 = Observation("present", True, s, 1.0, "h", "c001")
    o2 = Observation("present", True, s, 1.0, "h", "c002")
    a = compute_state([o1, o2], 1.0)["present"]
    b = compute_state([o2, o1], 1.0)["present"]
    assert a.val == b.val and a.pos_groups == b.pos_groups
    assert a.evidence_ids != b.evidence_ids


import pytest  # noqa: E402


@pytest.mark.xfail(strict=True, reason="BUG: belnap.py:137 keys latest-per-source by source NAME only; an untrusted "
                   "observation that re-uses a trusted source's name (parsers.py:150/202 do exactly this when "
                   "downgrading) shadows the trusted observation and changes val -> untrusted is not hints-only")
def test_untrusted_same_name_cannot_shadow_trusted():
    trusted_fs = Source("fs", "T", "fs")
    downgraded_fs = Source("fs", "U", "fs")  # what parsers.py builds for an untrusted program
    honest_neg = Observation("vuln_config_enabled", False, trusted_fs, 1.0, "aaa")
    hint_pos = Observation("vuln_config_enabled", True, downgraded_fs, 2.0, "bbb")
    before = compute_state([honest_neg], 2.0)["vuln_config_enabled"].val
    after = compute_state([honest_neg, hint_pos], 2.0)["vuln_config_enabled"].val
    assert before == Belnap.F
    assert after == Belnap.F  # actual: N (the trusted negative is erased by an untrusted hint)


def test_random_smoke_large_logs():
    rnd = random.Random(7)
    log = [Observation(rnd.choice(ATOMS), rnd.random() < 0.5, rnd.choice(REGISTRY), float(rnd.randint(0, 50)),
                       rnd.choice("abcdef")) for _ in range(2000)]
    a = compute_state(log, 50.0, {"present": 20.0})
    rnd.shuffle(log)
    assert project(a) == project(compute_state(log, 50.0, {"present": 20.0}))
