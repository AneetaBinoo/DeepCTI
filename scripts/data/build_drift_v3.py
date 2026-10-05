"""Drift episodes ("drift since the last assessment") for any dataset, incl. D7 non-Debian components.

Independent test of DC v2.1 pre-registered in prereg-v2/§B (episodes generated from D7 test hosts after
prereg-v3). Targets are chosen from world physics (HostEnv.world_atoms), never from sealed labels.

  python scripts/data/build_drift_v3.py --dataset d7 --split test
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from deepcti.env.host import HostEnv  # noqa: E402
from deepcti.eval import data  # noqa: E402

SEED = 20261005


def env_for(case: dict) -> HostEnv:
    return HostEnv(case, data.fixture(case["host_id"]), data.cve_meta().get(case["cve"], {}), data.preconditions(),
                   data.advisories(case["cve"]))


def current_version(env: HostEnv) -> str | None:
    if env.is_deb():
        b = env.src_binaries(env.case["src_package"])
        return env.packages[b[0]]["Version"] if b else None
    insts = env.instances()
    return str(insts[0]["version"]) if insts else None


def has_service(env: HostEnv) -> bool:
    if env.is_deb():
        return any(s.get("package") in env.src_binaries(env.case["src_package"]) for s in env.services.values())
    return bool(env.running_versions())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="d7")
    ap.add_argument("--split", required=True)
    ap.add_argument("--per-kind", type=int, default=40)
    args = ap.parse_args()
    data.set_dataset(args.dataset)
    cases = data.load_cases(args.split)
    rng = random.Random(SEED)
    envs = {c["case_id"]: env_for(c) for c in cases}
    vuln_version: dict[tuple, str] = {}
    for c in cases:
        env = envs[c["case_id"]]
        w = env.world_atoms()
        if w["present"] and w["in_affected_range"]:
            v = current_version(env)
            if v:
                vuln_version.setdefault((c["cve"], c.get("release", ""), c.get("ecosystem")), v)
    kinds: dict[str, list[dict]] = {k: [] for k in ("upgrade_restart", "upgrade_no_restart", "rollback", "remove")}
    for c in sorted(cases, key=lambda x: x["case_id"]):
        env = envs[c["case_id"]]
        w = env.world_atoms()
        src, fixed = c["src_package"], env.fixed_version()
        key = (c["cve"], c.get("release", ""), c.get("ecosystem"))
        if w["present"] and w["in_affected_range"] and fixed:
            kinds["upgrade_restart"].append({"case": c, "drift": [
                {"at": 0.0, "kind": "upgrade", "src": src, "version": fixed}, {"at": 0.0, "kind": "restart", "src": src}]})
            if has_service(env):
                kinds["upgrade_no_restart"].append({"case": c, "drift": [
                    {"at": 0.0, "kind": "upgrade", "src": src, "version": fixed}]})
            kinds["remove"].append({"case": c, "drift": [{"at": 0.0, "kind": "remove", "src": src}]})
        if w["present"] and w["fix_applied"] and key in vuln_version:
            kinds["rollback"].append({"case": c, "drift": [
                {"at": 0.0, "kind": "downgrade", "src": src, "version": vuln_version[key]},
                {"at": 0.0, "kind": "restart", "src": src}]})
    out, sealed = [], []
    for kind, items in kinds.items():
        rng.shuffle(items)
        for it in items[: args.per_kind]:
            env = env_for(it["case"])
            env.drift = list(it["drift"])
            before = env.world_atoms()
            env.run_history([])
            after = env.world_atoms()
            eid = f"DV3-{kind}-{it['case']['case_id']}"
            row = {"episode_id": eid, "case_id": it["case"]["case_id"], "kind": kind, "drift": it["drift"],
                   "ecosystem": it["case"].get("ecosystem")}
            if args.split == "test":
                sealed.append({"episode_id": eid, "world_before": before, "world_after": after})
            else:
                row.update(world_before=before, world_after=after)
            out.append(row)
    path = ROOT / "data" / f"drift_{args.dataset}" / f"{args.split}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in sorted(out, key=lambda r: r["episode_id"])))
    if sealed:
        (ROOT / "data" / "sealed" / f"drift_{args.dataset}_test_world.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in sealed))
    from collections import Counter
    print(path, len(out), Counter((r["kind"], r["ecosystem"]) for r in out))


if __name__ == "__main__":
    main()
