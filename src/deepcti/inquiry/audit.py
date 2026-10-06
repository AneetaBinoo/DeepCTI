"""E0 retrospective question audit (Paper 2, INQUIRY_EXPERIMENT_PLAN.md §6 E0).

Label-derived, model-free measures for every tool call ("question") of an existing episode record:

* **Replay.** Each record is replayed on a freshly built environment, configured exactly as the runner built it:
  dataset, arm, drift episode and carried-over history, decoys and spec version. Replay yields the structured
  tool outputs. It is checked against the logged outputs, and records that do not replay are flagged.
* **Face-value inference** ``infer(K)``. This is what the evidence gathered so far implies about the decision
  atoms when read at face value:
  - presence comes from presence observations;
  - instance versions: disk versions from disk tools, running versions from the process view. A running
    instance not observed is assumed equal to disk;
  - the in-range and fixed status of each observed version is judged by the *oracle* program (the
    authoritative tracker/OSV/vendor ranges), but only once the agent has itself seen range knowledge
    (``R``: a tracker answer, or advisory text naming the true range bounds);
  - configuration comes from configuration observations;
  - scanner findings decide ``in_affected_range`` when no version-based inference exists.

  Evidence collected before the episode (drift history at t < 0) is stale and never counted.
* **Established.** A decision-relevant atom (one consulted on the gold decision's path, see
  ``decision.Decision.required``) is *established* when ``infer(K)`` equals its true value at decision time.
* **Per question:**
  - *realized information*: the call changed the established status of at least one required atom;
    gains and losses are counted separately;
  - *redundant*: the same tool and arguments as an earlier call, or byte-identical output;
  - otherwise *irrelevant*;
  - calls after the decision are counted as *post-decision*.
* **Critical omission.** At decision time a required atom is not established, yet some set of at most two
  catalog questions (canonical calls for this case, including the process view), affordable with the
  remaining budget, would have established it. Both the 1-step and the 2-step versions are recorded, along
  with the tools that would have closed the gap.

Version strings are matched in free text only when they are *true* versions of the host, token-bounded. The
oracle is therefore a best-case reader: it never invents a version, and decoy or stale strings are ignored.
CMDB output is not used: it is untrusted, and its versions may be stale.
"""

from __future__ import annotations

import copy
import itertools
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ..core.belnap import Belnap
from ..core.decision import CONFIG, FIX, IN_RANGE, PRESENT, decide_values
from ..env.host import ADVISORY_SOURCES, SCANNERS, HostEnv, ToolResult
from ..eval import data
from ..extraction.parsers import CaseProgram, parse_result, program_from_vex

ROOT = Path(__file__).resolve().parents[3]
DECISION_ATOMS = (PRESENT, IN_RANGE, FIX, CONFIG)
DISK_TOOLS = ("pkg_query", "lang_pkg_query", "file_read", "list_dir")
DISRUPTIVE = ("apply_patch", "restart_service", "disable_feature")


# ----------------------------------------------------------------------------- environment reconstruction
@lru_cache(maxsize=4)
def _drift_defs(dataset: str, split: str) -> dict[str, dict]:
    path = ROOT / "data" / ("d2" if dataset == "d1" else "drift_d7") / f"{split}.jsonl"
    if not path.exists():
        return {}
    return {e["episode_id"]: e for e in map(json.loads, path.read_text().splitlines()) if e}


@lru_cache(maxsize=8)
def _cases(dataset: str) -> dict[str, dict]:
    data.set_dataset(dataset)
    out = {}
    for split in ("dev", "calib", "test"):
        for c in data.load_cases(split):
            out[c["case_id"]] = c
    return out


@lru_cache(maxsize=1)
def _v3_profiles() -> dict:
    import yaml
    return (yaml.safe_load((ROOT / "config" / "source_profiles_v3.yaml").read_text()) or {}).get("by_ecosystem", {})


def record_dataset(r: dict) -> str:
    return r.get("dataset") or "d1"


def env_config_key(r: dict) -> tuple:
    return (record_dataset(r), r["case_id"], r.get("arm", "tracker"), r.get("drift") or "",
            bool(r.get("decoy")), r.get("spec") or "v2")


def build_env(r: dict, *, arm: str | None = None) -> tuple[HostEnv, dict]:
    """Environment as runner.run_episode built it (no attack support: attack blocks are excluded)."""
    if r.get("attack"):
        raise ValueError("attack episodes are not audited")
    ds = record_dataset(r)
    data.set_dataset(ds)
    case = _cases(ds)[r["case_id"]]
    arm = arm or r.get("arm", "tracker")
    drift = None
    if r.get("drift"):
        d = _drift_defs(ds, r.get("split", "test")).get(r["drift"])
        if d is None:
            raise ValueError(f"unknown drift episode {r['drift']}")
        drift = copy.deepcopy(d["drift"])
    profiles = None
    if ds == "d7":
        profiles = _v3_profiles().get(case.get("ecosystem", ""), None)
    kw = {"profiles": profiles} if profiles is not None else {}
    env = HostEnv(case, data.fixture(case["host_id"]), data.cve_meta().get(case["cve"], {}), data.preconditions(),
                  data.advisories(case["cve"]), tracker_available=arm not in ("withheld", "blind"),
                  scanners_available=arm != "blind", attack=None, drift=drift, **kw)
    env.spec_version = r.get("spec") or "v2"
    if r.get("decoy"):
        env.apply_decoys()
    env.history = []
    if drift and any(float(e["at"]) <= 0 for e in drift):
        src = case["src_package"]
        env.history = env.run_history([("pkg_query", {"name": src}), ("service_status", {"name": src})])
    return env, case


def replay(r: dict, at_decision=None) -> tuple[HostEnv, dict, list[ToolResult], list[str]]:
    """Replay every logged call. ``at_decision(env, case)`` is invoked once, on the environment as it was at
    decision time: before the first disruptive call or the first call after ``t_decision`` (remediation changes
    the world, and the ground truth is the world the decision was about)."""
    env, case = build_env(r)
    results, mismatches = [], []
    td = decision_time(r)
    fired = False
    for c in r.get("calls", []):
        if at_decision and not fired and (c["tool"] in DISRUPTIVE or (td is not None and float(c["t"]) > td + 1e-9)):
            at_decision(env, case)
            fired = True
        if c["status"] == "denied":
            res = env.denied(c["tool"], c["args"], c["out"].removeprefix("DENIED by policy: "))
        else:
            res = env.call(c["tool"], c["args"])
        if res.call_id != c["id"] or res.output[:400] != c["out"] or res.status != c["status"]:
            mismatches.append(c["id"])
        results.append(res)
    if at_decision and not fired:
        at_decision(env, case)
    return env, case, results, mismatches


# ----------------------------------------------------------------------------- oracle
@dataclass
class Oracle:
    program: CaseProgram | None
    disk: set[str]
    running: set[str]
    world: dict
    bounds: set[str]  # strings that, seen in advisory text, reveal the affected range
    install_dirs: set[str] = field(default_factory=set)  # non-deb: top-level product directories (opt/<x>, srv/<x>)


def oracle_program(case: dict, r: dict) -> CaseProgram | None:
    env, _ = build_env({**r, "drift": None, "decoy": None}, arm="tracker")
    res = env.call("vex_lookup", {"cve": case["cve"]})
    prog = program_from_vex(res, case)
    if prog is not None:
        prog.trusted = True
    return prog


def make_oracle(env: HostEnv, case: dict, r: dict) -> Oracle:
    prog = oracle_program(case, r)
    if env.is_deb():
        bins = [b for b in env.src_binaries(case["src_package"]) if b in env.packages]
        disk = {str(env.packages[b]["Version"]) for b in bins}
        running = {str(s["loaded_version"]) for s in env.services.values()
                   if s.get("package") in bins and s.get("loaded_version") and s.get("active", True)}
    else:
        disk = {str(i["version"]) for i in env.instances()}
        running = {str(v) for v in env.running_versions()}
    bounds: set[str] = set()
    if prog is not None:
        if prog.fixed_version not in (None, "", "0"):
            bounds.add(str(prog.fixed_version))
        for rg in prog.ranges or []:
            for k in ("introduced", "fixed", "last_affected"):
                v = rg.get(k)
                if v not in (None, "", "0"):
                    bounds.add(str(v))
    dirs = set()
    if not env.is_deb():
        for inst in env.instances():
            parts = str(inst.get("path", "")).split("!/")[0].split("/")
            if len(parts) >= 2 and parts[0] in ("opt", "srv"):
                dirs.add(parts[1].lower())
    return Oracle(prog, disk, running, env.world_atoms(), bounds, dirs)


def gold_required(world: dict) -> tuple[str, list[tuple[str, bool]]]:
    """Gold decision and the atoms (with their true values) consulted on its path."""
    vals = {a: (Belnap.T if world.get(a) else Belnap.F) for a in DECISION_ATOMS}
    if not world.get(PRESENT):
        vals = {PRESENT: Belnap.F}
    d = decide_values(vals, bool(world.get("req_config")))
    req = [(a, bool(world.get(a))) for a, _ in d.required]
    if (FIX, True) not in req and (FIX, False) not in req and world.get(PRESENT):
        # the path passed fix_applied (value F) before reaching in_affected_range: it is consulted too
        if d.status != "fixed":
            req.insert(1, (FIX, False))
    return d.status, req


# ----------------------------------------------------------------------------- knowledge and inference
def _tok(v: str) -> re.Pattern:
    return re.compile(rf"(?<![\w.+~:-]){re.escape(v)}(?![\w.+~-])")


@dataclass
class Knowledge:
    present: set[bool] = field(default_factory=set)
    disk: set[str] = field(default_factory=set)
    running: set[str] = field(default_factory=set)
    ranges: bool = False
    scanner: set[bool] = field(default_factory=set)
    config: set[bool] = field(default_factory=set)

    def copy(self) -> Knowledge:
        return Knowledge(set(self.present), set(self.disk), set(self.running), self.ranges, set(self.scanner),
                         set(self.config))


def absorb(k: Knowledge, res: ToolResult, case: dict, orc: Oracle) -> Knowledge:
    """Knowledge after one tool result (pure: returns a new object)."""
    k = k.copy()
    if res.status != "ok":
        return k
    if res.tool == "cmdb_lookup":
        return k
    obs, facts = parse_result(res, case, orc.program)
    deb = case.get("ecosystem", "deb-debian").startswith("deb")
    for o in obs:
        if o.atom == PRESENT and res.tool != "run_scanner":
            if res.tool == "pkg_query" and not o.positive and not deb:
                continue  # dpkg not knowing a vendor/language component is not evidence of its absence
            if res.tool == "list_dir" and not deb:
                continue  # vendor presence is read exactly from the listing below (no substring heuristics)
            k.present.add(o.positive)
        elif o.atom == IN_RANGE and res.tool == "run_scanner":
            k.scanner.add(o.positive)
        elif o.atom == CONFIG:
            k.config.add(o.positive)
    for f in facts:
        if f.version in orc.disk:
            k.disk.add(f.version)
            k.present.add(True)
    out = res.output or ""
    if res.tool == "list_dir" and not deb and isinstance(res.structured, dict) \
            and str(res.structured.get("path", "")).strip("/") in ("opt", "srv"):
        entries = {str(e).rstrip("/").lower() for e in res.structured.get("entries", []) if str(e).endswith("/")}
        if orc.world.get(PRESENT):
            if entries & orc.install_dirs:
                k.present.add(True)
        elif str(res.structured.get("path", "")).strip("/") == "opt":
            k.present.add(False)  # the product directory is not under /opt (where every product is installed)
    if res.tool in ("file_read", "list_dir"):
        for v in orc.disk:
            if _tok(v).search(out):
                k.disk.add(v)
                k.present.add(True)
    if res.tool == "service_status":
        for v in orc.running:
            if _tok(v).search(out):
                k.running.add(v)
                k.present.add(True)  # a running instance of the component proves presence
    if res.tool == "vex_lookup" and isinstance(res.structured, dict) and (
            "fixed_version" in res.structured or res.structured.get("affected_ranges")):
        k.ranges = True
    if res.tool == "advisory_fetch" and out:
        if orc.bounds:
            k.ranges = k.ranges or any(_tok(b).search(out) for b in orc.bounds)
        elif res.args.get("source") in ("debian", "ubuntu", "osv", "vendor"):
            k.ranges = True
    return k


def infer(k: Knowledge, orc: Oracle) -> dict[str, bool | None]:
    out: dict[str, bool | None] = {a: None for a in DECISION_ATOMS}
    if len(k.present) == 1:
        out[PRESENT] = next(iter(k.present))
    if len(k.config) == 1:
        out[CONFIG] = next(iter(k.config))
    insts = set(k.disk) | set(k.running)
    if k.disk and not k.running:
        insts = set(k.disk)  # running assumed equal to disk
    if insts and k.ranges and orc.program is not None and orc.program.known():
        derived = [orc.program.derive(v) for v in insts]
        if all(d is not None for d in derived):
            out[IN_RANGE] = any(d[0] for d in derived)
            out[FIX] = all(d[1] for d in derived)
    if out[IN_RANGE] is None and len(k.scanner) == 1:
        out[IN_RANGE] = next(iter(k.scanner))
        if out[IN_RANGE] and out[FIX] is None:
            out[FIX] = False  # a scanner finding means the installed version is vulnerable, hence not fixed
    return out


def components(k: Knowledge, orc: Oracle, req: list[tuple[str, bool]]) -> set[str]:
    """Decision-useful evidence components held in ``k`` (the unit of per-question credit). A component counts
    only if it agrees with the truth and feeds an atom on the gold decision's path."""
    atoms = {a for a, _ in req}
    truth = dict(req)
    out: set[str] = set()
    if PRESENT in atoms and truth[PRESENT] in k.present:
        out.add(f"presence:{truth[PRESENT]}")
    if atoms & {IN_RANGE, FIX}:
        if k.ranges:
            out.add("ranges")
        out |= {f"disk:{v}" for v in k.disk} | {f"run:{v}" for v in k.running}
        t_in = truth.get(IN_RANGE)
        if t_in is not None and t_in in k.scanner:
            out.add(f"scanner:{t_in}")
    if CONFIG in atoms and truth[CONFIG] in k.config:
        out.add(f"config:{truth[CONFIG]}")
    return out


def contradictions(k: Knowledge, req: list[tuple[str, bool]]) -> set[str]:
    """Observations held in ``k`` whose polarity contradicts the truth of a required atom."""
    truth = dict(req)
    out = set()
    if PRESENT in truth and (not truth[PRESENT]) in k.present:
        out.add("presence")
    if CONFIG in truth and (not truth[CONFIG]) in k.config:
        out.add("config")
    if IN_RANGE in truth and (not truth[IN_RANGE]) in k.scanner:
        out.add("scanner")
    return out


def established(k: Knowledge, orc: Oracle, req: list[tuple[str, bool]]) -> dict[str, bool]:
    inf = infer(k, orc)
    return {a: inf[a] is not None and inf[a] == truth for a, truth in req}


# ----------------------------------------------------------------------------- catalog of canonical questions
def catalog(env: HostEnv, case: dict) -> list[tuple[str, dict]]:
    src, cve = case["src_package"], case["cve"]
    comp = case.get("component") or src
    eco = case.get("ecosystem", "deb-debian")
    q: list[tuple[str, dict]] = [("vex_lookup", {"cve": cve})]
    q += [("advisory_fetch", {"cve": cve, "source": s}) for s in ADVISORY_SOURCES]
    q += [("run_scanner", {"tool": s}) for s in SCANNERS]
    q += [("service_status", {"name": src})]
    q += [("service_status", {"name": key}) for key in sorted(env.services) if key != src]
    if eco.startswith("deb"):
        q.append(("pkg_query", {"name": src}))
        for b in env.src_binaries(src):
            q.append(("file_read", {"path": f"usr/share/doc/{b}/changelog.Debian"}))
    else:
        if eco in ("pypi", "maven"):
            q.append(("lang_pkg_query", {"ecosystem": eco, "name": comp}))
        q.append(("list_dir", {"path": "opt"}))
        for inst in env.instances():
            base = str(inst.get("path", "")).split("!/")[0]
            parts = base.split("/")
            if len(parts) >= 2:
                q.append(("list_dir", {"path": "/".join(parts[:2])}))
        cur = {str(i["version"]) for i in env.instances()}
        docs = sorted(p for p in env.files if re.match(r"(opt|srv)/", p) and any(v in env.files[p] for v in cur)
                      and not p.endswith((".jar", ".so", ".class")))
        q += [("file_read", {"path": p}) for p in docs[:6]]
    if env.pre:
        q.append(("config_get", {"service": env.pre.get("service") or src, "key": env.pre.get("key")}))
    seen, uniq = set(), []
    for t, a in q:
        key = (t, json.dumps(a, sort_keys=True))
        if key not in seen:
            seen.add(key)
            uniq.append((t, a))
    return uniq


@lru_cache(maxsize=256)
def catalog_results(cfg_key: str) -> list[tuple[str, dict, float, ToolResult]]:
    """Catalog question outputs for one environment configuration. Worlds are static after t = 0 (all drift
    events fire at t <= 0), so the outputs do not depend on when a question is asked."""
    r = json.loads(cfg_key)
    env, case = build_env(r)
    out = []
    for tool, args in catalog(env, case):
        res = env.call(tool, args)
        out.append((tool, args, float(res.cost), res))
    return out


# ----------------------------------------------------------------------------- episode audit
def decision_time(r: dict) -> float | None:
    t = r.get("t_decision")
    return float(t) if t is not None else None


def audit_record(r: dict) -> tuple[dict, list[dict]]:
    """(episode row, per-call rows) for one record."""
    snap: dict = {}
    _, case, results, mism = replay(r, at_decision=lambda e, c: snap.setdefault("orc", make_oracle(e, c, r)))
    orc = snap["orc"]
    gold, req = gold_required(orc.world)
    td = decision_time(r)
    k = Knowledge()
    seen_calls, seen_h = set(), set()
    rows = []
    cost_before = 0.0
    est_prev = established(k, orc, req)
    comp_prev: set[str] = set()
    for res in results:
        pre_decision = (td is None or res.t <= td + 1e-9) and res.tool not in DISRUPTIVE
        key = (res.tool, json.dumps(res.args, sort_keys=True))
        redundant = key in seen_calls or (res.status == "ok" and res.h in seen_h)
        seen_calls.add(key)
        if res.status == "ok":
            seen_h.add(res.h)
        if pre_decision:
            k2 = absorb(k, res, case, orc)
            est = established(k2, orc, req)
            gains = [a for a in est if est[a] and not est_prev[a]]
            losses = [a for a in est if est_prev[a] and not est[a]]
            comp = components(k2, orc, req)
            new_comp = sorted(comp - comp_prev)
            wrong = contradictions(k2, req) - contradictions(k, req)
            k, est_prev, comp_prev = k2, est, comp
            cost_before += float(res.cost)
            if losses or wrong:
                cat = "misleading"
            elif new_comp:
                cat = "relevant"
            else:
                cat = "redundant" if redundant else "irrelevant"
        else:
            gains, losses, new_comp = [], [], []
            cat = "post_decision"
        rows.append({"call_id": res.call_id, "tool": res.tool, "status": res.status, "cost": res.cost,
                     "t": res.t, "category": cat, "redundant": redundant, "gains": ",".join(gains),
                     "losses": ",".join(losses), "new_components": ";".join(new_comp)})
    missing = [a for a, ok in est_prev.items() if not ok]
    budget = float(r.get("budget") or 60.0)
    remaining = budget - cost_before
    cfg = json.dumps({**{k_: r.get(k_) for k_ in ("dataset", "case_id", "arm", "drift", "decoy", "spec", "split")}},
                     sort_keys=True)
    omit1, omit2, fixers = False, False, set()
    if missing:
        cands = [c for c in catalog_results(cfg) if c[2] <= remaining + 1e-9]
        for tool, args, cost, res in cands:
            est = established(absorb(k, res, case, orc), orc, req)
            if any(est[a] for a in missing):
                omit1 = True
                fixers.add(tool)
        omit2 = omit1
        if not omit1:
            for (t1, a1, c1, r1), (t2, a2, c2, r2) in itertools.combinations(cands, 2):
                if c1 + c2 > remaining + 1e-9:
                    continue
                est = established(absorb(absorb(k, r1, case, orc), r2, case, orc), orc, req)
                if any(est[a] for a in missing):
                    omit2 = True
                    fixers.add(f"{t1}+{t2}")
                    break
    pre = [x for x in rows if x["category"] != "post_decision"]
    ep = {"key": r["key"], "dataset": record_dataset(r), "experiment": r.get("experiment"), "split": r.get("split"),
          "system": r["system"], "model": r["model"], "arm": r.get("arm"), "case_id": r["case_id"], "cve": r["cve"],
          "variant": r.get("variant"), "drift": r.get("drift") or "", "decoy": bool(r.get("decoy")),
          "budget": budget, "status": r.get("status"), "gold": gold, "required": ",".join(a for a, _ in req),
          "missing_at_decision": ",".join(missing), "n_questions": len(pre),
          "n_relevant": sum(x["category"] == "relevant" for x in pre),
          "n_redundant": sum(x["category"] == "redundant" for x in pre),
          "n_irrelevant": sum(x["category"] == "irrelevant" for x in pre),
          "n_misleading": sum(x["category"] == "misleading" for x in pre),
          "n_post": sum(x["category"] == "post_decision" for x in rows),
          "cost_before_decision": cost_before, "remaining_budget": remaining,
          "omission_1step": omit1, "omission_2step": omit2, "omission_fixers": ";".join(sorted(fixers)),
          "replay_mismatches": len(mism)}
    return ep, rows
