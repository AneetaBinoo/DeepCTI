"""Episode runner: one (case, system, model, arm, policy, budget, attack, drift, seed) → one JSONL record.

Never reads labels: evaluation joins labels afterwards (scripts/paper/*). Resumable by record key.
"""

from __future__ import annotations

import json
import platform
import subprocess
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..agents.mediator import Mediator
from ..agents.systems import (Controller, ControllerConfig, ReactConfig, run_direct, run_react, run_scanner_only,
                              run_structured_lookup)
from ..env.host import Attack, HostEnv, source_profiles
from ..llm.client import LLM, Usage, load_models
from ..policy.pdp import PolicyDecisionPoint
from . import data

ROOT = Path(__file__).resolve().parents[3]

LLM_SYSTEMS = {"S2", "S3", "S4", "S5", "DC", "DC_checklist", "DC_llmchoose", "DC_noverify", "DC_k1",
               "DC_nofresh", "DC_entropy", "DC_random", "DC_q2"}
DEFAULT_POLICY = {"S0_trivy": "P0", "S0_grype": "P0", "S0_osv": "P0", "S1": "P1", "S1p": "P3", "S2": "P1",
                  "S3": "P1", "S4": "P1", "S5": "P1"}


@dataclass(frozen=True)
class Spec:
    experiment: str
    case_id: str
    system: str
    model: str  # "none" for LLM-free systems
    arm: str = "tracker"  # tracker | withheld
    policy: str = ""
    budget: float = 60.0
    temperature: float = 0.0
    seed: int = 0
    attack: str = ""
    drift: str = ""
    prompt_defense: bool = False

    def key(self) -> str:
        return "|".join(str(x) for x in (self.case_id, self.system, self.model, self.arm, self.policy or
                                         DEFAULT_POLICY.get(self.system, "P3"), self.budget, self.temperature,
                                         self.seed, self.attack, self.drift, int(self.prompt_defense)))


def _yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}


def run_episode(spec: Spec, case: dict, llm: LLM | None, *, attack: dict | None = None,
                drift: list[dict] | None = None, priors: dict | None = None) -> dict:
    system = spec.system
    policy = spec.policy or DEFAULT_POLICY.get(system, "P3")
    profiles = source_profiles()
    if system == "DC_k1":
        profiles = {k: dict(v, trust="T") for k, v in profiles.items()}
        for name in ("cmdb", "scanner:trivy", "scanner:grype", "scanner:osv"):
            profiles.setdefault(name, {"trust": "T", "fp": 0.05, "fn": 0.05})
        policy = spec.policy or "P2"
    try:
        env = HostEnv(case, data.fixture(case["host_id"]), data.cve_meta().get(case["cve"], {}),
                      data.preconditions(), data.advisories(case["cve"]), tracker_available=spec.arm != "withheld",
                      attack=Attack(**attack) if attack else None, drift=drift, profiles=profiles)
    except Exception:
        return {"key": spec.key(), **asdict(spec), "case_id": case["case_id"], "error": traceback.format_exc(limit=4)}
    med = Mediator(env, PolicyDecisionPoint(policy), use_freshness=system != "DC_nofresh")
    world_at_start = env.world_atoms()
    t0 = time.monotonic()
    error = None
    outcome = None
    try:
        if system.startswith("S0_"):
            outcome = run_scanner_only(med, system.split("_", 1)[1])
        elif system == "S1":
            outcome = run_structured_lookup(med)
        elif system == "S1p":
            outcome = Controller(med, None, ControllerConfig(use_llm=False, acquisition="checklist",
                                                             budget=spec.budget, trust_profiles=profiles,
                                                             explain=False), priors).run()
        elif system == "S2":
            outcome = run_direct(med, llm)
        elif system in ("S3", "S4", "S5"):
            variant = {"S3": "react", "S4": "scratchpad", "S5": "reflect"}[system]
            outcome = run_react(med, llm, ReactConfig(variant=variant, budget=spec.budget,
                                                      prompt_defense=spec.prompt_defense))
        elif system.startswith("DC"):
            acq = {"DC_checklist": "checklist", "DC_llmchoose": "llm", "DC_entropy": "entropy",
                   "DC_random": "random"}.get(system, "voi")
            cfg = ControllerConfig(use_llm=True, acquisition=acq, verified=system != "DC_noverify",
                                   budget=spec.budget, seed=spec.seed, trust_profiles=profiles,
                                   q_service=float((priors or {}).get("q_service", 0.4)),
                                   explain=system == "DC", k_decide=2 if system == "DC_q2" else 1)
            outcome = Controller(med, llm, cfg, priors).run()
        else:
            raise ValueError(f"unknown system {system}")
    except Exception:  # recorded, never swallowed silently: counted as a failed episode
        error = traceback.format_exc(limit=8)
    wall = time.monotonic() - t0
    calls = env.calls
    seen, redundant = set(), 0
    for c in calls:
        k = c.tool + json.dumps(c.args, sort_keys=True)
        redundant += k in seen
        seen.add(k)
    usage = outcome.usage if outcome else Usage()
    extra = outcome.extra if outcome else {}
    if "world_at_decision" in extra:
        world_at_decision, t_decision = extra.pop("world_at_decision"), extra.pop("t_decision")
    elif med.attempted_disruptive:  # decision time = first disruptive attempt
        world_at_decision, t_decision = med.attempted_disruptive[0]["world"], med.attempted_disruptive[0]["t"]
    else:
        world_at_decision, t_decision = env.world_atoms(), env.clock
    record: dict[str, Any] = {
        "key": spec.key(),
        **asdict(spec),
        "policy": policy,
        "cve": case["cve"],
        "variant": case.get("variant"),
        "family": case.get("family"),
        "split": case.get("split"),
        "host_id": case["host_id"],
        "status": outcome.status if outcome else None,
        "justification": outcome.justification if outcome else None,
        "parse_ok": bool(outcome and outcome.parse_ok),
        "explanation": (outcome.explanation if outcome else "")[:1500],
        "cost": sum(c.cost for c in calls),
        "n_calls": len(calls),
        "n_redundant": redundant,
        "calls": [{"id": c.call_id, "tool": c.tool, "args": c.args, "status": c.status, "cost": c.cost,
                   "source": c.source.name, "t": c.t, "out": c.output[:400]} for c in calls],
        "attempted_disruptive": med.attempted_disruptive,
        "executed_disruptive": med.executed_disruptive,
        "denials": [{k: v for k, v in d.items() if k != "context"} for d in med.denials],
        "actions": env.actions,
        "vulnerable_after": env.vulnerable_now() if error is None else None,
        "usage": usage.to_dict(),
        "wall_s": wall,
        "error": error,
        "world_at_decision": world_at_decision,
        "t_decision": t_decision,
        "world_at_start": world_at_start,
        "extra": extra,
        "trace": (outcome.trace if outcome else [])[-40:],
    }
    return record


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


@dataclass
class Job:
    spec: Spec
    case: dict
    attack: dict | None = None
    drift: list[dict] | None = None


@dataclass
class RunConfig:
    out: Path
    jobs: list[Job] = field(default_factory=list)


def run_jobs(jobs: list[Job], out_path: Path, *, model_name: str, concurrency: int = 16,
             temperature: float = 0.0, progress_every: int = 25) -> dict:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
                if rec.get("error") is None:
                    done.add(rec["key"])
            except json.JSONDecodeError:
                continue
    todo = [j for j in jobs if j.spec.key() not in done]
    models = load_models()
    priors = _yaml(ROOT / "config" / "priors.yaml")
    lock = threading.Lock()
    llms: dict[tuple, LLM] = {}

    def get_llm(spec: Spec) -> LLM | None:
        if spec.model == "none":
            return None
        k = (spec.model, spec.temperature, spec.seed)
        with lock:
            if k not in llms:
                llms[k] = LLM(spec.model, models[spec.model], temperature=spec.temperature,
                              seed=spec.seed if spec.temperature > 0 else None)
            return llms[k]

    progress_path = out_path.with_suffix(".progress.json")
    stats = {"total": len(jobs), "skipped_done": len(jobs) - len(todo), "ok": 0, "error": 0,
             "started": time.time(), "model": model_name}

    def work(job: Job) -> dict:
        return run_episode(job.spec, job.case, get_llm(job.spec), attack=job.attack, drift=job.drift,
                           priors=priors)

    with ThreadPoolExecutor(max_workers=concurrency) as pool, out_path.open("a", encoding="utf-8") as fh:
        futures = [pool.submit(work, j) for j in todo]
        for i, fut in enumerate(as_completed(futures), 1):
            rec = fut.result()
            with lock:
                fh.write(json.dumps(rec, default=str) + "\n")
                fh.flush()
                stats["error" if rec["error"] else "ok"] += 1
            if i % progress_every == 0 or i == len(futures):
                stats["elapsed_s"] = time.time() - stats["started"]
                stats["remaining"] = len(futures) - i
                progress_path.write_text(json.dumps(stats, indent=1), encoding="utf-8")
    return stats


def manifest(path: Path, extra: dict) -> None:
    models = load_models()
    path.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git_commit(),
        "python": platform.python_version(),
        "models": models,
        "source_profiles": source_profiles(),
        "priors": _yaml(ROOT / "config" / "priors.yaml"),
        **extra,
    }, indent=1, default=str), encoding="utf-8")
