"""T4: quorum robustness of the PDP, linter fragment checks, Cedar vs reference agreement."""

from __future__ import annotations

import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from deepcti.core.belnap import Observation, Source, compute_state
from deepcti.policy.pdp import (
    DISRUPTIVE,
    GATE_CONTEXT_ATOMS,
    GATES,
    POLICIES,
    TOOL_TIERS,
    PolicyConfig,
    PolicyDecisionPoint,
    lint_policy,
    reference_allowed,
    render_cedar,
)

GROUPS = ("pkgdb", "fs", "proc", "change", "cmdb")
# one trusted source per group (+ a second pkgdb-group source), plus untrusted sources
TRUSTED = {g: [Source(g, "T", g)] for g in GROUPS}
TRUSTED["pkgdb"].append(Source("scanner:trivy", "T", "pkgdb"))
UNTRUSTED = [Source("advisory:nvd", "U", "advisory:nvd"), Source("scanner:osv", "U", "pkgdb"),
             Source("llm", "U", "llm")]
P3 = POLICIES["P3"]
FRESH = {a: 40.0 for a in GATE_CONTEXT_ATOMS}


def honest_support(honest_log, atom, t_now, M):
    """E+_f(honest) \\ M: groups whose latest fresh honest observation of `atom` is positive."""
    latest = {}
    for o in sorted(honest_log, key=lambda o: (o.t, o.h, o.positive)):
        latest[(o.atom, o.source.name)] = o
    return {o.source.group for (a, _), o in latest.items()
            if a == atom and o.positive and t_now - o.t <= FRESH.get(atom, math.inf)} - set(M)


@st.composite
def scenario(draw):
    m = draw(st.integers(0, 2))
    M = draw(st.lists(st.sampled_from(GROUPS), min_size=m, max_size=m, unique=True))
    honest_sources = [s for g in GROUPS if g not in M for s in TRUSTED[g]]
    adv_sources = UNTRUSTED + [s for g in M for s in TRUSTED[g]]
    atoms = st.sampled_from(GATE_CONTEXT_ATOMS)
    times = st.integers(0, 50).map(float)
    honest = draw(st.lists(st.builds(Observation, atom=atoms, positive=st.booleans(),
                                     source=st.sampled_from(honest_sources), t=times,
                                     h=st.sampled_from("abc")), max_size=25))
    adv = draw(st.lists(st.builds(Observation, atom=atoms, positive=st.booleans(),
                                  source=st.sampled_from(adv_sources), t=times,
                                  h=st.sampled_from("xyz")), max_size=25))
    # bias toward permits: honest positive observations on all gating atoms from a few groups
    if draw(st.booleans()):
        for atom in GATE_CONTEXT_ATOMS:
            for s in draw(st.lists(st.sampled_from(honest_sources), max_size=3, unique=True)) if honest_sources else []:
                honest.append(Observation(atom, True, s, 50.0, "p"))
    if draw(st.booleans()):
        for atom in GATE_CONTEXT_ATOMS:
            for s in adv_sources:
                if s.trust == "T":
                    adv.append(Observation(atom, True, s, 50.0, "q"))
    t_now = draw(st.sampled_from([50.0, 60.0, 95.0]))
    return M, honest, adv, t_now


@settings(max_examples=500, deadline=None)
@given(scenario(), st.sampled_from(DISRUPTIVE))
def test_t4_quorum_robustness_p3(sc, tool):
    M, honest, adv, t_now = sc
    m = len(M)
    state = compute_state(honest + adv, t_now, FRESH)
    pdp = PolicyDecisionPoint("P3")
    d = pdp.authorize(tool, state, args_ok=True, args_in_scope=True)  # raises on Cedar/ref disagreement
    if not d.allowed:
        return
    for atom in GATES[tool]:
        k = P3.k(atom)
        assert len(honest_support(honest, atom, t_now, M)) >= k - m, (tool, atom, M)


@settings(max_examples=300, deadline=None)
@given(scenario(), st.sampled_from(DISRUPTIVE))
def test_t4_untrusted_only_adversary_cannot_flip_deny_to_permit(sc, tool):
    M, honest, adv, t_now = sc
    adv = [o for o in adv if o.source.trust == "U"]  # m = 0
    base = PolicyDecisionPoint("P3").authorize(tool, compute_state(honest, t_now, FRESH),
                                               args_ok=True, args_in_scope=True)
    attacked = PolicyDecisionPoint("P3").authorize(tool, compute_state(honest + adv, t_now, FRESH),
                                                   args_ok=True, args_in_scope=True)
    assert attacked.allowed == base.allowed


# ----------------------------------------------------------------------------- Cedar vs reference
ctx_atom = st.fixed_dictionaries({"val": st.sampled_from("NTFB"), "kpos": st.integers(0, 3),
                                  "kneg": st.integers(0, 3)})
ctx_st = st.fixed_dictionaries({"args_ok": st.booleans(), "args_in_scope": st.booleans(),
                                "atoms": st.fixed_dictionaries({a: ctx_atom for a in GATE_CONTEXT_ATOMS})})


@settings(max_examples=400, deadline=None)
@given(ctx_st, st.sampled_from(sorted(TOOL_TIERS)), st.sampled_from(sorted(POLICIES)))
def test_cedar_and_reference_agree(ctx, tool, pname):
    import cedarpy

    cfg = POLICIES[pname]
    req = {"principal": 'Agent::"deepcti"', "action": f'Action::"{tool}"', "resource": 'Host::"target"',
           "context": ctx}
    assert bool(cedarpy.is_authorized(req, render_cedar(cfg), []).allowed) == reference_allowed(cfg, tool, ctx)


@pytest.mark.parametrize("cfg", [PolicyConfig("X", k_world=3, k_change=2),
                                 PolicyConfig("Y", evidence_gated=True, argument_gated=False)])
def test_cedar_and_reference_agree_on_custom_configs(cfg):
    import itertools

    import cedarpy

    for tool in sorted(TOOL_TIERS):
        for args_ok, scope, val, kpos in itertools.product((False, True), (False, True), "NTFB", range(4)):
            ctx = {"args_ok": args_ok, "args_in_scope": scope,
                   "atoms": {a: {"val": val, "kpos": kpos, "kneg": 0} for a in GATE_CONTEXT_ATOMS}}
            req = {"principal": 'Agent::"d"', "action": f'Action::"{tool}"', "resource": 'Host::"t"',
                   "context": ctx}
            assert bool(cedarpy.is_authorized(req, render_cedar(cfg), []).allowed) == reference_allowed(cfg, tool, ctx)


def test_unknown_tool_denied():
    d = PolicyDecisionPoint("P0").authorize("rm_rf", {}, args_ok=True, args_in_scope=True)
    assert not d.allowed


# ----------------------------------------------------------------------------- linter
def k_of(cfg):
    return {a: cfg.k(a) for a in GATE_CONTEXT_ATOMS}


@pytest.mark.parametrize("name", ["P2", "P3"])
def test_linter_accepts_generated_p2_p3(name):
    assert lint_policy(render_cedar(POLICIES[name]), k_of(POLICIES[name])) == []


def test_linter_p2_fails_p3_thresholds():
    assert lint_policy(render_cedar(POLICIES["P2"]), k_of(P3))


@pytest.mark.parametrize("name", ["P0", "P1"])
def test_linter_rejects_p0_p1(name):
    assert lint_policy(render_cedar(POLICIES[name]), k_of(POLICIES[name]))


FULL_APPLY = " && ".join(
    f'context.atoms.{a}.val == "T" && context.atoms.{a}.kpos >= {P3.k(a)}' for a in GATES["apply_patch"])


@pytest.mark.parametrize("text", [
    f'permit(principal, action == Action::"apply_patch", resource) when {{ {FULL_APPLY} || context.args_ok }};',
    f'permit(principal, action == Action::"apply_patch", resource) when {{ !(!({FULL_APPLY})) }};',
    f'permit(principal, action == Action::"apply_patch", resource) when {{ if context.args_ok then true else ({FULL_APPLY}) }};',
    'permit(principal, action == Action::"apply_patch", resource) when { context.atoms.present.val == "T" };',
    'permit(principal, action, resource);',
    'permit(principal, action in [Action::"apply_patch", Action::"restart_service"], resource);',
    f'permit(principal, action == Action::"apply_patch", resource) when {{ {FULL_APPLY.replace(">= 2", ">= 1")} }};',
    'permit(principal, action == Action::"apply_patch", resource) when { ' + FULL_APPLY.replace('== "T"', '!= "F"') + ' };',
])
def test_linter_rejects_handwritten_non_fragment(text):
    assert lint_policy(text, k_of(P3)), text


def test_linter_accepts_handwritten_conjunctive_fragment():
    text = f'permit(principal, action == Action::"apply_patch", resource) when {{ context.args_ok && {FULL_APPLY} }};'
    assert lint_policy(text, k_of(P3)) == []


@pytest.mark.parametrize("text", [
    'permit(principal, action in Action::"apply_patch", resource);',
    'permit(principal, action in [Action::"apply_patch"], resource);',
])
def test_linter_rejects_action_in_scope(text):
    import cedarpy

    req = {"principal": 'Agent::"d"', "action": 'Action::"apply_patch"', "resource": 'Host::"t"', "context": {}}
    assert cedarpy.is_authorized(req, text, []).allowed  # Cedar really permits it
    assert lint_policy(text, k_of(P3))  # ... but the linter reports nothing
