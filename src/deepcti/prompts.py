from __future__ import annotations
from .dataset import Case

SYSTEM = """You are DeepCTI, a cybersecurity mitigation-analysis assistant.
Only use the provided CTI evidence and local context. Do not invent vendors, versions, assets, or impact.
Every answer must begin with a short section named FINAL MITIGATION TARGET.
"""

FORMAT = """Required output format:
FINAL MITIGATION TARGET:
- 4 to 6 concise sentences.
- Include the affected product/dependency, the concrete mitigation action, any local operational constraint, validation step, monitoring/follow-up, and residual risk if supported.
- This section should be compact enough to compare with a reference mitigation target.

EVIDENCE USED:
- Bullet the evidence items actually used.

WHY THIS MITIGATION:
- Explain why the final action follows from the evidence.

VERIFICATION / STOPPING DECISION:
- State whether enough evidence was available and what uncertainty remains.
"""


def make_prompt(case: Case, mode: str) -> str:
    if mode == "one_shot":
        context = f"Initial CTI and local context:\n{case.initial_context}\n\nBaseline mitigation:\n{case.baseline}"
        mode_desc = "ONE-SHOT: Use only the initial CTI/local context. Do not assume staged evidence."
    elif mode == "no_memory":
        last_stage = case.stage_evidence[-1] if case.stage_evidence else "No staged evidence available."
        context = f"Initial CTI and local context:\n{case.initial_context}\n\nBaseline mitigation:\n{case.baseline}\n\nCurrent staged evidence only, without memory of earlier stages:\n{last_stage}"
        mode_desc = "NO-MEMORY: Use the current staged evidence, but do not reconstruct a full accumulated trace."
    elif mode == "iterative":
        stages = "\n".join([f"Stage {i+1} evidence: {s}" for i, s in enumerate(case.stage_evidence)]) or "No staged evidence available."
        context = f"Initial CTI and local context:\n{case.initial_context}\n\nBaseline mitigation:\n{case.baseline}\n\nAccumulated staged evidence trace:\n{stages}"
        mode_desc = "ITERATIVE DEEPCTI: Preserve the full evidence trace, update the mitigation state after each stage, verify support, and produce the final recommendation."
    else:
        raise ValueError(f"Unknown mode: {mode}")
    return f"{SYSTEM}\nMode: {mode_desc}\n\nAnalyst question:\n{case.question}\n\n{context}\n\n{FORMAT}\n"


def dry_answer(case: Case, mode: str) -> str:
    # This is only for pipeline testing. It deliberately does not copy the reference.
    base = case.baseline or "apply the vendor-recommended mitigation"
    first_stage = case.stage_evidence[0] if case.stage_evidence else "initial CTI evidence"
    stages = "; ".join(case.stage_evidence[:3]) if case.stage_evidence else "no additional staged evidence"
    if mode == "one_shot":
        final = f"Use the baseline mitigation for the reported vulnerability. Prioritize patching or configuration hardening where feasible and validate the change before production rollout."
        evidence = f"Initial context only; baseline: {base[:250]}"
    elif mode == "no_memory":
        final = f"Apply the baseline mitigation while incorporating the latest staged evidence. Use the current evidence to choose patching, compensating controls, or exposure reduction, then validate the affected service before closing the case."
        evidence = f"Latest evidence only: {(case.stage_evidence[-1] if case.stage_evidence else first_stage)[:400]}"
    else:
        final = f"Apply the mitigation that is supported by the accumulated CTI and local evidence: prioritize the required patch or upgrade, add compensating controls if immediate remediation is constrained, reduce exposure for affected assets, validate the deployment, and monitor residual risk until remediation is complete."
        evidence = f"Accumulated staged evidence: {stages[:700]}"
    return f"FINAL MITIGATION TARGET:\n{final}\n\nEVIDENCE USED:\n- {evidence}\n\nWHY THIS MITIGATION:\nThe recommendation is selected because it follows the available evidence and avoids unsupported operational assumptions.\n\nVERIFICATION / STOPPING DECISION:\nEvidence is considered sufficient for a recommendation if retrieved evidence passes the Top-P threshold or no additional high-similarity chunks remain."
