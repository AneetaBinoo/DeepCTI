"""VEX-aligned decision function over the Belnap state (plan §3.4).

Rows are evaluated top to bottom. An atom is *required* only if a row that is reached
consults it. A B value on a consulted atom yields under_investigation/conflict:<atom>;
an N value on a consulted atom that blocks every later row yields missing:<atoms>.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .belnap import AtomState, Belnap, val

PRESENT = "present"
IN_RANGE = "in_affected_range"
FIX = "fix_applied"
CONFIG = "vuln_config_enabled"
WORLD_ATOMS = (PRESENT, IN_RANGE, FIX, CONFIG)

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
FIXED = "fixed"
UNDER_INVESTIGATION = "under_investigation"
STATUSES = (AFFECTED, NOT_AFFECTED, FIXED, UNDER_INVESTIGATION)

J_NOT_PRESENT = "component_not_present"
J_CODE_NOT_PRESENT = "vulnerable_code_not_present"
J_REQUIRES_CONFIG = "requires_configuration"


@dataclass(frozen=True)
class Decision:
    status: str
    justification: str | None
    # (atom, polarity) pairs the firing row depends on; polarity True means "must be T"
    required: tuple[tuple[str, bool], ...]

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "justification": self.justification,
            "required": [[a, p] for a, p in self.required],
        }


def decide_values(values: Mapping[str, Belnap], req_config: bool) -> Decision:
    """Decision from per-atom Belnap values (pure function, used for exhaustive tests)."""
    g = lambda a: values.get(a, Belnap.N)
    p, x, a, c = g(PRESENT), g(FIX), g(IN_RANGE), g(CONFIG)
    if p == Belnap.B:
        return Decision(UNDER_INVESTIGATION, f"conflict:{PRESENT}", ((PRESENT, True),))
    if p == Belnap.F:
        return Decision(NOT_AFFECTED, J_NOT_PRESENT, ((PRESENT, False),))
    if p == Belnap.N:
        return Decision(UNDER_INVESTIGATION, f"missing:{PRESENT}", ((PRESENT, True),))
    # p == T
    if x == Belnap.B:
        return Decision(UNDER_INVESTIGATION, f"conflict:{FIX}", ((PRESENT, True), (FIX, True)))
    if x == Belnap.T:
        return Decision(FIXED, None, ((PRESENT, True), (FIX, True)))
    if a == Belnap.B:
        return Decision(UNDER_INVESTIGATION, f"conflict:{IN_RANGE}", ((PRESENT, True), (IN_RANGE, True)))
    if a == Belnap.F:
        return Decision(NOT_AFFECTED, J_CODE_NOT_PRESENT, ((PRESENT, True), (IN_RANGE, False)))
    if a == Belnap.N:
        missing = [IN_RANGE] + ([FIX] if x == Belnap.N else [])
        return Decision(UNDER_INVESTIGATION, "missing:" + ",".join(missing), ((PRESENT, True), (IN_RANGE, True)))
    # a == T
    if req_config:
        if c == Belnap.B:
            return Decision(
                UNDER_INVESTIGATION, f"conflict:{CONFIG}", ((PRESENT, True), (IN_RANGE, True), (CONFIG, True))
            )
        if c == Belnap.F:
            return Decision(
                NOT_AFFECTED, J_REQUIRES_CONFIG, ((PRESENT, True), (IN_RANGE, True), (CONFIG, False))
            )
        if c == Belnap.N:
            return Decision(
                UNDER_INVESTIGATION, f"missing:{CONFIG}", ((PRESENT, True), (IN_RANGE, True), (CONFIG, True))
            )
        return Decision(AFFECTED, None, ((PRESENT, True), (IN_RANGE, True), (CONFIG, True)))
    return Decision(AFFECTED, None, ((PRESENT, True), (IN_RANGE, True)))


def decide(state: Mapping[str, AtomState], req_config: bool) -> Decision:
    return decide_values({atom: val(state, atom) for atom in WORLD_ATOMS}, req_config)


def decide_world(atoms: Mapping[str, bool], req_config: bool) -> Decision:
    """Ground-truth decision for a fully known world (all atoms two-valued)."""
    values = {k: (Belnap.T if v else Belnap.F) for k, v in atoms.items() if k in WORLD_ATOMS}
    if not atoms.get(PRESENT, False):
        values = {PRESENT: Belnap.F}
    return decide_values(values, req_config)
