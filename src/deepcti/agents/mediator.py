"""Complete mediation (A3): every tool call of every system passes through the PDP.

The mediator also maintains the provenance-tracked evidence state from tool outputs using the
deterministic parsers (and, for DeepCTI, LLM proposals accepted by the verifier). The LLM never
writes to the log directly (A1).
"""

from __future__ import annotations

import math
from typing import Any

from ..core.belnap import EvidenceLog, compute_state
from ..core.decision import decide, decide_instance_aware
from ..env.host import HostEnv, ToolResult
from ..extraction.parsers import CaseProgram, VersionFact, derive_from_facts, parse_result, program_from_vex
from ..policy.pdp import TOOL_TIERS, PolicyDecisionPoint

# Freshness windows Δ_f in tool-cost units of the simulated clock (fixed on dev before the test run).
FRESHNESS_DEFAULT = {
    "present": 12.0,
    "in_affected_range": 12.0,
    "fix_applied": 12.0,
    "vuln_config_enabled": 12.0,
    "change_approved": 30.0,
    "rollback_available": 30.0,
    "in_maintenance_window": 30.0,
}


class Mediator:
    def __init__(self, env: HostEnv, pdp: PolicyDecisionPoint, *, freshness: dict | None = None,
                 use_freshness: bool = True, instance_aware: bool = False):
        self.instance_aware = instance_aware
        self.env = env
        self.pdp = pdp
        self.case = env.case
        self.log = EvidenceLog()
        self.facts: list[VersionFact] = []
        self.program: CaseProgram | None = None
        self.freshness = (freshness or FRESHNESS_DEFAULT) if use_freshness else {}
        self.verdicts: list[dict] = []
        self.attempted_disruptive: list[dict] = []
        self.denials: list[dict] = []
        self.executed_disruptive: list[dict] = []

    # ----------------------------------------------------------------- state
    def state(self):
        derived = derive_from_facts(self.facts, self.program, split_running=self.instance_aware)
        return compute_state(list(self.log) + derived, self.env.clock, self.freshness, math.inf)

    def decision(self):
        req = bool(self.program and self.program.precondition and self.program.trusted)
        if self.instance_aware:
            return decide_instance_aware(self.state(), req)
        return decide(self.state(), req)

    def set_program(self, program: CaseProgram | None) -> None:
        if program is not None and (self.program is None or not self.program.trusted or program.trusted):
            self.program = program

    def add_facts(self, facts: list[VersionFact]) -> None:
        self.facts.extend(facts)

    # ----------------------------------------------------------------- execution
    def execute(self, tool: str, args: dict[str, Any] | None) -> ToolResult:
        args = dict(args or {})
        tier = TOOL_TIERS.get(tool)
        if tier == "R2":
            self.attempted_disruptive.append({"tool": tool, "args": args, "t": self.env.clock,
                                              "world": self.env.world_atoms()})
        decision = self.pdp.authorize(
            tool,
            self.state(),
            args_ok=self.env.args_ok(tool, args),
            args_in_scope=self.env.args_in_scope(tool, args),
        )
        if not decision.allowed:
            self.denials.append({"tool": tool, "args": args, "t": self.env.clock, "context": decision.context})
            return self.env.denied(tool, args, f"{self.pdp.cfg.name} denies {tool}")
        result = self.env.call(tool, args)
        if tier == "R2" and result.status == "ok":
            self.executed_disruptive.append({"tool": tool, "args": args, "t": result.t,
                                             "gate_context": decision.context,
                                             "world_before": self.attempted_disruptive[-1]["world"]})
        if tool == "vex_lookup":
            self.set_program(program_from_vex(result, self.case))
        observations, facts = parse_result(result, self.case, self.program)
        self.log.extend(observations)
        self.add_facts(facts)
        return result

    def ingest_history(self, results: list[ToolResult]) -> None:
        for r in results:
            observations, facts = parse_result(r, self.case, self.program)
            self.log.extend(observations)
            self.add_facts(facts)

    def summary(self) -> dict:
        state = self.state()
        return {
            "state": {k: v.to_dict() for k, v in sorted(state.items())},
            "decision": self.decision().to_dict(),
            "program": None if self.program is None else {
                "fixed_version": self.program.fixed_version, "status": self.program.status,
                "trusted": self.program.trusted, "precondition": self.program.precondition,
                "upstream_ranges": self.program.upstream_ranges, "provenance": self.program.provenance},
            "verdicts": self.verdicts,
            "attempted_disruptive": self.attempted_disruptive,
            "executed_disruptive": self.executed_disruptive,
            "denials": [{k: v for k, v in d.items() if k != "context"} for d in self.denials],
            "log_size": len(self.log),
        }
