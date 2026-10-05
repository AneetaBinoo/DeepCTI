"""VOI: EC2 score vs a brute-force textbook EC2 gain, DP optimum <= greedy, Bayes update."""

from __future__ import annotations

import itertools
import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from deepcti.acquisition import voi
from deepcti.core.decision import CONFIG, FIX, IN_RANGE, PRESENT


def make_catalog(req: bool):
    out = [
        voi.Test("pkg", 1.0, voi.deterministic_reveal([PRESENT, IN_RANGE, FIX])),
        voi.Test("present_only", 0.5, voi.deterministic_reveal([PRESENT])),
        voi.Test("range_only", 2.0, voi.deterministic_reveal([IN_RANGE])),
        voi.Test("fix_only", 1.5, voi.deterministic_reveal([FIX])),
    ]
    if req:
        out.append(voi.Test("cfg", 1.0, voi.config_reveal()))
    return out


def prior_st(req: bool, allow_zero: bool = False):
    hs = voi.hypothesis_space(req)
    lo = 0.0 if allow_zero else 0.01
    return st.lists(st.floats(lo, 1.0), min_size=len(hs), max_size=len(hs)).map(lambda ws: dict(zip(hs, ws)))


def brute_force_ec2(p: dict, test: voi.Test, req: bool) -> float:
    """Golovin-Krause-Ray EC2: expected prior weight of edges {h,h'} (different regions) cut by the test."""
    hs = list(p)
    outcome = {h: next(iter(test.model(h))) for h in hs}
    total = 0.0
    py = {}
    for h in hs:
        py[outcome[h]] = py.get(outcome[h], 0.0) + p[h]
    for y, pr in py.items():
        cut = 0.0
        for h1, h2 in itertools.combinations(hs, 2):
            if h1.region(req) == h2.region(req):
                continue
            if outcome[h1] != y or outcome[h2] != y:  # edge cut when an endpoint is ruled out
                cut += p[h1] * p[h2]
        total += pr * cut
    return total / test.cost


@settings(max_examples=200, deadline=None)
@given(st.booleans().flatmap(lambda req: st.tuples(st.just(req), prior_st(req))))
def test_ec2_equals_textbook(arg):
    req, prior = arg
    belief = voi.Belief(prior, req)
    for t in make_catalog(req):
        assert math.isclose(voi.ec2_score(belief, t), brute_force_ec2(belief.p, t, req), rel_tol=1e-9,
                            abs_tol=1e-12)


@settings(max_examples=150, deadline=None)
@given(st.booleans().flatmap(lambda req: st.tuples(st.just(req), prior_st(req))),
       st.lists(st.floats(0.1, 5.0), min_size=5, max_size=5))
def test_optimal_le_greedy(arg, costs):
    req, prior = arg
    tests = [voi.Test(t.name, c, t.model) for t, c in zip(make_catalog(req), costs)]
    opt, _ = voi.optimal_expected_cost(prior, tests, req)
    for scorer in ("ec2", "entropy"):
        greedy = voi.policy_expected_cost(prior, tests, req, scorer)
        assert opt <= greedy + 1e-9, (scorer, opt, greedy)


@pytest.mark.xfail(strict=True, reason="BUG: voi.py:196-207 optimal_expected_cost keeps zero-weight hypotheses "
                   "(regions computed over them) while Belief drops them, so the 'optimal' DP can cost MORE than "
                   "the greedy policy (regret < 0)")
def test_optimal_le_greedy_with_zero_prior_mass():
    req = False
    hs = voi.hypothesis_space(req)
    absent = next(h for h in hs if not h.present)
    prior = {h: (0.0 if h is absent else 1.0) for h in hs}
    prior[next(h for h in hs if h.present and h.status == "notaff")] = 0.0
    tests = [voi.Test("fix_only", 1.0, voi.deterministic_reveal([FIX])),
             voi.Test("range_only", 1.0, voi.deterministic_reveal([IN_RANGE]))]
    # live hypotheses: present/vuln (affected) and present/fixed (fixed): one test separates them,
    # greedy pays 1.0; the DP also insists on separating the zero-mass absent/notaff hypotheses (1.5).
    opt, _ = voi.optimal_expected_cost(prior, tests, req)
    greedy = voi.policy_expected_cost(prior, tests, req, "ec2")
    assert opt <= greedy + 1e-9, (opt, greedy)


@settings(max_examples=200, deadline=None)
@given(st.booleans().flatmap(lambda req: st.tuples(st.just(req), prior_st(req))),
       st.floats(0.0, 0.5), st.floats(0.0, 0.5))
def test_belief_update_is_bayes(arg, fp, fn):
    req, prior = arg
    test = voi.Test("scan", 5.0, voi.noisy_finding(fp, fn), deterministic=False)
    for y in {y for h in prior for y in test.model(h)}:
        b = voi.Belief(prior, req)
        z = sum(prior.values())
        joint = {h: prior[h] / z * test.model(h).get(y, 0.0) for h in prior}
        py = sum(joint.values())
        ok = b.update(test, y)
        if py <= 0:
            assert not ok
            continue
        assert ok
        assert math.isclose(sum(b.p.values()), 1.0, rel_tol=1e-9)
        for h in prior:
            assert math.isclose(b.p.get(h, 0.0), joint[h] / py, rel_tol=1e-9, abs_tol=1e-15)


def test_impossible_outcome_keeps_belief():
    prior = {h: 1.0 for h in voi.hypothesis_space(False)}
    b = voi.Belief(prior, False)
    before = dict(b.p)
    assert not b.update(make_catalog(False)[0], frozenset({("nonsense", True)}))
    assert b.p == before


def test_regions_match_decision_table():
    regions = {(h.present, h.status, h.config): h.region(True) for h in voi.hypothesis_space(True)}
    assert regions[(False, "-", False)] == "not_affected"
    assert regions[(True, "fixed", True)] == "fixed"
    assert regions[(True, "notaff", True)] == "not_affected"
    assert regions[(True, "vuln", True)] == "affected"
    assert regions[(True, "vuln", False)] == "not_affected"


@settings(max_examples=100, deadline=None)
@given(st.booleans().flatmap(lambda req: st.tuples(st.just(req), prior_st(req))))
def test_entropy_score_nonnegative_and_ec2_nonnegative(arg):
    req, prior = arg
    b = voi.Belief(prior, req)
    for t in make_catalog(req) + [voi.Test("scan", 5.0, voi.noisy_finding(0.1, 0.1), False),
                                   voi.Test("svc", 1.0, voi.reveal_with_availability([PRESENT, IN_RANGE, FIX], 0.4),
                                            False)]:
        assert voi.ec2_score(b, t) >= -1e-12
        assert voi.entropy_score(b, t) >= -1e-12


def test_select_test_none_when_resolved():
    hs = voi.hypothesis_space(False)
    vuln = next(h for h in hs if h.present and h.status == "vuln")
    assert voi.select_test(voi.Belief({vuln: 1.0}, False), make_catalog(False)) is None


def test_ec2_bound_finite():
    prior = {h: 1.0 for h in voi.hypothesis_space(True)}
    b = voi.ec2_bound(prior)
    assert b["published"] > 1 and b["citable"] > b["published"]
