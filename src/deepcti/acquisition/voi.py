"""Value-of-information tool selection (plan §3.6).

Hypotheses are joint assignments of the latent world atoms of a case:
``present`` × status-of-installed-version ∈ {vuln, fixed, notaff} × ``vuln_config_enabled``.
Decision regions are the VEX statuses induced by the §3.4 table on the true world.

* ``ec2_score`` — EC² (equivalence-class edge cutting) expected weight of cut edges per unit
  cost. With deterministic tests this is exactly EC² (Golovin, Krause, Ray 2010); with noisy
  tests we use the likelihood-weighted ("soft") extension, for which the logarithmic
  approximation guarantee is NOT claimed.
* ``entropy_score`` — expected reduction of Shannon entropy over hypotheses per unit cost
  (known to be suboptimal for decision regions; used as a contrast).
* ``optimal_expected_cost`` — exact DP over consistent hypothesis sets for deterministic tests
  (the reference policy for regret).
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache

from ..core.decision import CONFIG, FIX, IN_RANGE, PRESENT, decide_world

Outcome = frozenset  # frozenset[tuple[str, bool]]


@dataclass(frozen=True)
class Hypothesis:
    present: bool
    status: str  # vuln | fixed | notaff | "-" when absent
    config: bool

    def atoms(self) -> dict[str, bool]:
        return {
            PRESENT: self.present,
            IN_RANGE: self.present and self.status == "vuln",
            FIX: self.present and self.status == "fixed",
            CONFIG: self.present and self.config,
        }

    def region(self, req_config: bool) -> str:
        return decide_world(self.atoms(), req_config).status


def hypothesis_space(req_config: bool) -> list[Hypothesis]:
    hs = [Hypothesis(False, "-", False)]
    configs = (True, False) if req_config else (True,)
    for status, cfg in itertools.product(("vuln", "fixed", "notaff"), configs):
        hs.append(Hypothesis(True, status, cfg))
    return hs


@dataclass(frozen=True)
class Test:
    """A tool call with a cost and an outcome model P(y | h)."""

    name: str
    cost: float
    model: Callable[[Hypothesis], dict[Outcome, float]]
    deterministic: bool = True


def deterministic_reveal(atoms: Sequence[str]) -> Callable[[Hypothesis], dict[Outcome, float]]:
    def model(h: Hypothesis) -> dict[Outcome, float]:
        values = h.atoms()
        if not h.present:
            return {frozenset({(PRESENT, False)}): 1.0}
        return {frozenset((a, values[a]) for a in atoms): 1.0}

    return model


def reveal_with_availability(atoms: Sequence[str], q: float) -> Callable[[Hypothesis], dict[Outcome, float]]:
    """Reveals ``atoms`` with probability q (e.g. a service banner exists), else nothing."""
    base = deterministic_reveal(atoms)

    def model(h: Hypothesis) -> dict[Outcome, float]:
        if not h.present:
            return {frozenset(): 1.0}  # no service for an absent package: uninformative
        out: dict[Outcome, float] = {}
        for y, p in base(h).items():
            out[y] = out.get(y, 0.0) + p * q
        out[frozenset()] = out.get(frozenset(), 0.0) + (1 - q)
        return out

    return model


def config_reveal() -> Callable[[Hypothesis], dict[Outcome, float]]:
    def model(h: Hypothesis) -> dict[Outcome, float]:
        return {frozenset({(CONFIG, h.config)}): 1.0}

    return model


def noisy_finding(fp: float, fn: float) -> Callable[[Hypothesis], dict[Outcome, float]]:
    """Scanner: a finding asserts present+ and in_range+; no finding asserts in_range−."""
    hit = frozenset({(PRESENT, True), (IN_RANGE, True)})
    miss = frozenset({(IN_RANGE, False)})

    def model(h: Hypothesis) -> dict[Outcome, float]:
        p_hit = (1 - fn) if (h.present and h.status == "vuln") else fp
        return {hit: p_hit, miss: 1 - p_hit}

    return model


# ----------------------------------------------------------------------------- belief
class Belief:
    def __init__(self, prior: Mapping[Hypothesis, float], req_config: bool):
        total = sum(prior.values())
        self.p = {h: v / total for h, v in prior.items() if v > 0}
        self.req_config = req_config

    def region_mass(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for h, v in self.p.items():
            r = h.region(self.req_config)
            out[r] = out.get(r, 0.0) + v
        return out

    def max_region(self) -> tuple[str, float]:
        mass = self.region_mass()
        region = max(sorted(mass), key=lambda r: mass[r])
        return region, mass[region]

    def update(self, test: Test, y: Outcome) -> bool:
        post = {h: v * test.model(h).get(y, 0.0) for h, v in self.p.items()}
        total = sum(post.values())
        if total <= 0:  # outcome impossible under the model: keep the belief, report it
            return False
        self.p = {h: v / total for h, v in post.items() if v > 0}
        return True


def _edge_weight(weights: Mapping[Hypothesis, float], req_config: bool) -> float:
    by_region: dict[str, float] = {}
    for h, w in weights.items():
        r = h.region(req_config)
        by_region[r] = by_region.get(r, 0.0) + w
    total = sum(by_region.values())
    return (total * total - sum(v * v for v in by_region.values())) / 2.0


def ec2_score(belief: Belief, test: Test) -> float:
    """Expected EC² edge weight removed by ``test`` divided by its cost."""
    now = _edge_weight(belief.p, belief.req_config)
    outcomes: dict[Outcome, dict[Hypothesis, float]] = {}
    for h, v in belief.p.items():
        for y, lik in test.model(h).items():
            if lik > 0:
                outcomes.setdefault(y, {})[h] = v * lik
    # E_y[W(consistent_y)] with P(y) = Σ_h p(h) P(y|h); belief.p is normalised. For deterministic
    # tests the likelihood-weighted mass equals the prior mass of the consistent set (exact EC²).
    expected_remaining = 0.0
    for weights in outcomes.values():
        p_y = sum(weights.values())
        expected_remaining += p_y * _edge_weight(weights, belief.req_config)
    return (now - expected_remaining) / test.cost


def entropy_score(belief: Belief, test: Test) -> float:
    def entropy(ps: Mapping[Hypothesis, float]) -> float:
        total = sum(ps.values())
        return -sum((v / total) * math.log(v / total) for v in ps.values() if v > 0)

    now = entropy(belief.p)
    outcomes: dict[Outcome, dict[Hypothesis, float]] = {}
    for h, v in belief.p.items():
        for y, lik in test.model(h).items():
            if lik > 0:
                outcomes.setdefault(y, {})[h] = v * lik
    expected = sum(sum(w.values()) * entropy(w) for w in outcomes.values())
    return (now - expected) / test.cost


def select_test(belief: Belief, tests: Sequence[Test], scorer: str = "ec2", eps: float = 1e-12) -> Test | None:
    fn = ec2_score if scorer == "ec2" else entropy_score
    best, best_score = None, eps
    for test in tests:  # deterministic tie-break: catalog order
        s = fn(belief, test)
        if s > best_score:
            best, best_score = test, s
    return best


# ----------------------------------------------------------------------------- optimal (noiseless)
def optimal_expected_cost(
    prior: Mapping[Hypothesis, float], tests: Sequence[Test], req_config: bool
) -> tuple[float, dict]:
    """Minimum expected cost to identify the decision region with deterministic tests (exact DP)."""
    det = [t for t in tests if t.deterministic]
    hs = sorted(prior, key=lambda h: (h.present, h.status, h.config))
    weights = {h: prior[h] for h in hs}

    def outcome(t: Test, h: Hypothesis) -> Outcome:
        (y,) = t.model(h).keys()
        return y

    @cache
    def solve(consistent: frozenset, used: frozenset) -> tuple[float, str | None]:
        mass = sum(weights[h] for h in consistent)
        regions = {h.region(req_config) for h in consistent}
        if len(regions) <= 1 or mass == 0:
            return 0.0, None
        best, best_name = math.inf, None
        for t in det:
            if t.name in used:
                continue
            parts: dict[Outcome, list[Hypothesis]] = {}
            for h in consistent:
                parts.setdefault(outcome(t, h), []).append(h)
            if len(parts) == 1:
                continue
            cost = t.cost
            for part in parts.values():
                pm = sum(weights[h] for h in part)
                sub, _ = solve(frozenset(part), used | {t.name})
                cost += (pm / mass) * sub
            if cost < best:
                best, best_name = cost, t.name
        if best_name is None:  # cannot separate further: unresolvable with these tests
            return 0.0, None
        return best, best_name

    total, first = solve(frozenset(hs), frozenset())
    return total, {"first_test": first}


def policy_expected_cost(
    prior: Mapping[Hypothesis, float], tests: Sequence[Test], req_config: bool, scorer: str
) -> float:
    """Expected cost of the greedy policy under the (noiseless) model, by enumerating worlds."""
    det = [t for t in tests if t.deterministic]
    total = 0.0
    z = sum(prior.values())
    for h_true, w in prior.items():
        belief = Belief(prior, req_config)
        remaining = list(det)
        cost = 0.0
        while len({h.region(req_config) for h in belief.p}) > 1 and remaining:
            t = select_test(belief, remaining, scorer)
            if t is None:
                break
            (y,) = t.model(h_true).keys()
            belief.update(t, y)
            remaining.remove(t)
            cost += t.cost
        total += (w / z) * cost
    return total


def ec2_bound(prior: Mapping[Hypothesis, float]) -> dict[str, float]:
    """Approximation factors for greedy EC² (see docs/VERIFICATION_LOG.md, "Theorem constants").

    ``published``: 2 ln(1/p_min) + 1 (Golovin, Krause, Ray 2010) — rests on a Golovin–Krause
    theorem whose proof was later found flawed. ``citable``: 4(1 + 2 ln(1/p_min)), our application of
    Al-Thani et al. (arXiv 2208.08351) to EC² (own derivation; labelled as such in the paper).
    """
    p_min = min(v for v in prior.values() if v > 0) / sum(prior.values())
    return {"published": 2 * math.log(1 / p_min) + 1, "citable": 4 * (1 + 2 * math.log(1 / p_min))}
