"""Independent audit (V3_AUDIT.md): after each D7 TEST drift episode is applied (exactly as the runner does),
is the evidence an agent can read consistent with the ground-truth world?

  PYTHONPATH=src .venv/bin/python tests/v3/audit_v3_drift_physics.py
Checks per episode: service_status of the component's units shows a 'server banner' whose version token equals
the running (loaded) version, never a banner for an inactive unit; lang_pkg_query / pkg_query show the on-disk
instance versions; vendor evidence files contain the on-disk version.
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from deepcti.env.host import HostEnv  # noqa: E402
from deepcti.eval import data  # noqa: E402

VER = re.compile(r"\d+(?:\.\d+)+(?:[-.~+:][\w.~+-]*)?")


def main() -> None:
    data.set_dataset("d7")
    cases = {c["case_id"]: c for c in data.load_cases("test")}
    eps = [json.loads(x) for x in (ROOT / "data/drift_d7/test.jsonl").read_text().splitlines() if x.strip()]
    bad = collections.Counter()
    tot = collections.Counter()
    examples = collections.defaultdict(list)
    for e in eps:
        c = cases[e["case_id"]]
        env = HostEnv(c, data.fixture(c["host_id"]), data.cve_meta().get(c["cve"], {}), data.preconditions(),
                      data.advisories(c["cve"]), tracker_available=False, scanners_available=False,
                      drift=[dict(x) for x in e["drift"]])
        # manifest versions that agreed with the on-disk version BEFORE the drift (not a deliberate trap)
        pre_mv = {str(i.get("manifest_version")) for i in env.instances()
                  if str(i.get("manifest_version")) == str(i["version"])} if not env.is_deb() else set()
        env.history = env.run_history([("pkg_query", {"name": c["src_package"]}),
                                       ("service_status", {"name": c["src_package"]})])
        k = (e["kind"], e["ecosystem"])
        tot[k] += 1
        probs = []
        if not env.is_deb():
            names = {n.lower() for n in env.names()}
            for key, svc in env.services.items():
                owner = str(svc.get("component") or svc.get("package") or key or "").lower()
                if owner not in names:
                    continue
                out = env.call("service_status", {"name": key}).output
                m = re.search(r"server banner: (.*)", out)
                active = bool(svc.get("active", True) and svc.get("loaded_version"))
                if m and not active:
                    probs.append(f"inactive unit {key} still prints banner '{m.group(1)}'")
                if m and active and str(svc["loaded_version"]) not in m.group(1):
                    probs.append(f"banner '{m.group(1)}' != loaded_version {svc['loaded_version']}")
            insts = env.instances()
            if env.eco in ("pypi", "maven"):
                out = env.call("lang_pkg_query", {"ecosystem": env.eco, "name": c["component"]}).output
                for i in insts:
                    if str(i["version"]) not in out:
                        probs.append(f"lang_pkg_query lacks on-disk {i['version']}: {out[:120]!r}")
                    mv = i.get("manifest_version")
                    if env.eco == "maven" and mv and str(mv) != str(i["version"]) and str(mv) in pre_mv:
                        probs.append(f"maven Implementation-Version {mv} stale (version {i['version']})")
                    if env.eco == "maven" and "!/" in str(i["path"]) and not str(i["path"]).endswith(f"-{i['version']}.jar"):
                        probs.append(f"nested jar path {i['path']} not renamed to {i['version']}")
                    if env.eco == "pypi":
                        for fk in [f for f in env.files if f.startswith(str(i["path"])) and f.endswith("METADATA")]:
                            if f"Version: {i['version']}" not in env.files[fk]:
                                probs.append(f"{fk.rsplit('/', 2)[-2]}/METADATA still has old Version")
            if env.eco == "vendor":
                for i in insts:
                    ev = i.get("evidence")
                    if ev and ev in env.files and str(i["version"]) not in env.files[ev]:
                        probs.append(f"vendor evidence {ev} lacks {i['version']}")
            if e["kind"] == "remove":
                left = [p for p in env.files if any(str(p).startswith(str(x.get("path", "")).rstrip("/") + "/")
                                                    for x in (env.fx.apps if hasattr(env.fx, "apps") else []))]
                if left:
                    probs.append(f"{len(left)} product files remain after remove")
        else:
            for key, svc in env.services.items():
                if svc.get("package") in env.src_binaries(c["src_package"]) and svc.get("loaded_version"):
                    out = env.call("service_status", {"name": key}).output
                    if str(svc["loaded_version"]) not in out:
                        probs.append(f"deb unit {key} does not show loaded {svc['loaded_version']}")
        if probs:
            bad[k] += 1
            if len(examples[k]) < 2:
                examples[k].append((e["episode_id"], probs[:3]))
    for k in sorted(tot):
        print(f"{k}: {bad[k]}/{tot[k]} episodes with evidence/world inconsistencies")
        for x in examples[k]:
            print("    ", x)


if __name__ == "__main__":
    main()
