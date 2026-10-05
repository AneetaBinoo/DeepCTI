"""Exact evidence reconstruction for a recorded episode.

Episode records keep only the first 400 characters of each tool output. HostEnv is deterministic, so
re-issuing the recorded calls in order on a fresh environment (same case, fixture and arm) reproduces
every output; each replayed output is checked against the recorded prefix and id.
"""

from __future__ import annotations

import json
from functools import lru_cache

from ..env.host import HostEnv
from ..eval import data

# characters of each tool output the generating system's LLM was shown (agents/systems.py)
SEEN_CHARS = {"S2": 2500, "S3": 3000, "S4": 3000, "S5": 3000}
DEFAULT_SEEN = 3000  # DC: the controller parses full outputs; capped for the judge prompt


@lru_cache(maxsize=1)
def cases_by_id() -> dict[str, dict]:
    out = {}
    for split in ("dev", "test"):
        for c in data.load_cases(split):
            out[c["case_id"]] = c
    return out


def replay(record: dict) -> tuple[list[dict], dict]:
    """Return (evidence items, check) for an episode record without attack/drift."""
    if record.get("attack") or record.get("drift") or record.get("history"):
        raise ValueError("replay supports clean episodes only")
    case = cases_by_id()[record["case_id"]]
    arm = record.get("arm", "tracker")
    env = HostEnv(case, data.fixture(case["host_id"]), data.cve_meta().get(case["cve"], {}),
                  data.preconditions(), data.advisories(case["cve"]),
                  tracker_available=arm not in ("withheld", "blind"), scanners_available=arm != "blind")
    items, mismatches = [], []
    for c in record.get("calls", []):
        if c["status"] == "denied":
            reason = c["out"].removeprefix("DENIED by policy: ")
            r = env.denied(c["tool"], c["args"], reason)
        else:
            r = env.call(c["tool"], c["args"])
        if r.call_id != c["id"] or r.output[:400] != c["out"] or r.status != c["status"]:
            mismatches.append(c["id"])
        items.append({"id": r.call_id, "tool": r.tool, "args": r.args, "status": r.status,
                      "source": c.get("source", r.source.name), "output": r.output})
    return items, {"n_calls": len(items), "mismatches": mismatches, "asset": env.asset(),
                   "release": case["release"], "src_package": case["src_package"]}


def context_block(record: dict, check: dict) -> str:
    tracker = "available" if record.get("arm", "tracker") not in ("withheld", "blind") else "NOT available"
    return (f"Host asset: {check['asset']} (Debian {check['release']}). CVE: {record['cve']}. Vulnerable source "
            f"package named in the advisory: {check['src_package']}. Debian security tracker in this episode: "
            f"{tracker}.")


def evidence_block(items: list[dict], system: str, only: set[str] | None = None) -> str:
    cap = SEEN_CHARS.get(system, DEFAULT_SEEN)
    parts = []
    for it in items:
        if only is not None and it["id"] not in only:
            continue
        out = it["output"]
        if len(out) > cap:
            out = out[:cap] + " …[truncated]"
        parts.append(f"[{it['id']}] {it['tool']} {json.dumps(it['args'], sort_keys=True)} "
                     f"(source: {it['source']}, status: {it['status']})\n{out}")
    return "\n\n".join(parts) if parts else "(no evidence)"


def dc_state_item(record: dict) -> dict | None:
    """The controller evidence state exactly as DC's response prompt received it (agents/systems.py::_explain)."""
    summary = (record.get("extra") or {}).get("assessed_state")
    if not summary:
        return None
    facts = {k: {"val": v["val"], "groups+": v["pos_groups"], "groups-": v["neg_groups"],
                 "evidence": v["evidence_ids"]} for k, v in summary["state"].items()}
    return {"id": "state", "tool": "controller_evidence_state", "args": {}, "status": "ok",
            "source": "deepcti_controller (derived from the tool outputs; atom values T=true F=false B=both N=none)",
            "output": json.dumps(facts)}
