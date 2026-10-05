"""E11 on D7 (H15): evidence replay in the D7 environment, D7 episode context, generator families.

Mirrors judge/evidence.py, but builds HostEnv exactly as eval/runner.py::run_episode does for spec.dataset='d7'
(per-ecosystem v3 trust profiles, env.spec_version='v3'), so replayed outputs match the recorded ones.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import yaml

from ..env.host import HostEnv, source_profiles
from ..eval import data
from .llm import JUDGES

ROOT = Path(__file__).resolve().parents[3]

# generator -> family (D7 panel adds granite41_30b); a judge is never applied to its own family's episodes
GENERATOR_FAMILY_D7 = {"gemma4_31b": "gemma", "granite41_30b": "granite", "granite41_8b": "granite",
                       "llama31_8b": "llama", "mistral_small_24b": "mistral", "qwen3_14b": "qwen",
                       "qwen3_4b": "qwen", "mistral_medium_128b": "mistral"}


def eligible_d7(judge: str, generator: str) -> bool:
    return JUDGES[judge]["family"] != GENERATOR_FAMILY_D7[generator]


@lru_cache(maxsize=1)
def cases_by_id_d7() -> dict[str, dict]:
    data.set_dataset("d7")
    out = {}
    for split in ("dev", "test"):
        for c in data.load_cases(split):
            out[c["case_id"]] = c
    return out


@lru_cache(maxsize=1)
def _v3_profiles() -> dict:
    return (yaml.safe_load((ROOT / "config" / "source_profiles_v3.yaml").read_text()) or {}).get("by_ecosystem", {})


def make_env(case: dict, arm: str) -> HostEnv:
    """HostEnv as in runner.run_episode for spec.dataset='d7' (no attack, no drift)."""
    data.set_dataset("d7")
    profiles = _v3_profiles().get(case.get("ecosystem", ""), source_profiles())
    env = HostEnv(case, data.fixture(case["host_id"]), data.cve_meta().get(case["cve"], {}),
                  data.preconditions(), data.advisories(case["cve"]),
                  tracker_available=arm not in ("withheld", "blind"), scanners_available=arm != "blind",
                  attack=None, drift=None, profiles=profiles)
    env.spec_version = "v3"
    return env


def replay_d7(record: dict) -> tuple[list[dict], dict]:
    """(evidence items, check) for a clean D7 episode; check['mismatches'] lists call ids whose replayed output
    prefix / id / status differ from the record."""
    if record.get("attack") or record.get("drift") or record.get("history"):
        raise ValueError("replay supports clean episodes only")
    case = cases_by_id_d7()[record["case_id"]]
    arm = record.get("arm", "tracker")
    env = make_env(case, arm)
    full = {t["call_id"]: t.get("output") for t in record.get("trace", []) if "call_id" in t}
    items, mismatches, full_mismatches = [], [], []
    for c in record.get("calls", []):
        if c["status"] == "denied":
            r = env.denied(c["tool"], c["args"], c["out"].removeprefix("DENIED by policy: "))
        else:
            r = env.call(c["tool"], c["args"])
        if r.call_id != c["id"] or r.output[:400] != c["out"] or r.status != c["status"]:
            mismatches.append(c["id"])
        if c["id"] in full and full[c["id"]] is not None and full[c["id"]] != r.output:
            full_mismatches.append(c["id"])
        items.append({"id": r.call_id, "tool": r.tool, "args": r.args, "status": r.status,
                      "source": c.get("source", r.source.name), "output": r.output})
    return items, {"n_calls": len(items), "mismatches": mismatches, "full_trace_mismatches": full_mismatches,
                   "asset": env.asset(), "release": case["release"], "distro": case.get("distro", ""),
                   "ecosystem": case.get("ecosystem", ""), "component": case.get("component") or case["src_package"],
                   "src_package": case["src_package"]}


def context_block_d7(record: dict, check: dict) -> str:
    """E11 context block with D7's facts (distro/ecosystem/component instead of the D1 'Debian release' wording)."""
    tracker = "available" if record.get("arm", "tracker") not in ("withheld", "blind") else "NOT available"
    scanners = "" if record.get("arm") != "blind" else " Vulnerability scanners in this episode: NOT available."
    return (f"Host asset: {check['asset']} ({check['distro'].capitalize()} {check['release']}; ecosystem "
            f"{check['ecosystem']}). CVE: {record['cve']}. Vulnerable component named in the advisory: "
            f"{check['component']}. Security tracker / VEX record in this episode: {tracker}.{scanners}")


def state_item(record: dict) -> dict | None:
    """Controller evidence state as DC's (unvalidated) response prompt received it (agents/systems.py::_explain)."""
    summary = (record.get("extra") or {}).get("assessed_state")
    if not summary:
        return None
    facts = {k: {"val": v["val"], "groups+": v["pos_groups"], "groups-": v["neg_groups"],
                 "evidence": v["evidence_ids"]} for k, v in summary["state"].items()}
    return {"id": "state", "tool": "controller_evidence_state", "args": {}, "status": "ok",
            "source": "deepcti_controller (derived from the tool outputs; atom values T=true F=false B=both N=none)",
            "output": json.dumps(facts)}


def validated_synthesis(record: dict) -> dict | None:
    for t in record.get("trace", []):
        if isinstance(t, dict) and "validated_synthesis" in t:
            return t["validated_synthesis"]
    return None
