"""Run Trivy, Grype and OSV-Scanner offline against every D7 host fixture (whole host).

Same method as D1 (scripts/data/run_scanners.py, reused here): trivy rootfs, grype dir:, OSV-Scanner on a
single-layer docker-archive of the rootfs (needed for Ubuntu release detection). OSV-Scanner's offline
databases (osv-scalibr/{Ubuntu,PyPI,Maven}/all.zip) are the same 2026-10-05 exports used for D7 labels.
Outputs data/d7/hosts/<id>/scans/{trivy,grype,osv}.json and data/d7/scanner_runs.json.

Deviation (found on 2026-10-05, see data/d7/BUILD_REPORT.md): OSV-Scanner 2.6.0 in offline mode does not match
Ubuntu OS packages (it labels them ecosystem "Ubuntu:22.04" while the offline export uses "Ubuntu:22.04:LTS")
and reports nothing for them. `--osv-online` therefore re-runs OSV-Scanner on every host against the
api.osv.dev online database (same day), which matches Ubuntu, PyPI and Maven packages correctly.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import now_iso  # noqa: E402
from d7common import D7  # noqa: E402
from run_scanners import BIN, CACHE, ENV, docker_archive, run, scan_host, tool_versions  # noqa: E402


def osv_online(hdir: Path) -> dict:
    out = hdir / "scans" / "osv.json"
    out.parent.mkdir(exist_ok=True)
    arch = CACHE / "osv_archives" / f"{hdir.name}.tar"
    arch.parent.mkdir(parents=True, exist_ok=True)
    docker_archive(hdir / "rootfs", arch)
    tmp = out.with_suffix(".json.part")
    res = run([str(BIN / "osv-scanner"), "scan", "image", "--archive", str(arch), "--format", "json",
               "--verbosity", "error", "--output-file", str(tmp)], tmp)
    arch.unlink(missing_ok=True)
    if res["ok"]:
        tmp.replace(out)
    return {"host_id": hdir.name, "osv": res}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--osv-online", action="store_true", help="re-run only OSV-Scanner, online database")
    a = ap.parse_args()
    hosts = sorted(p for p in (D7 / "hosts").iterdir() if (p / "rootfs").is_dir())
    done = [0]

    def one(h):
        if a.osv_online:
            o = h / "scans" / "osv.json"
            r = osv_online(h) if (a.force or not o.exists()) else {"host_id": h.name}
        else:
            r = scan_host(h, a.force)
        done[0] += 1
        if done[0] % 25 == 0:
            print(f"{done[0]}/{len(hosts)} {now_iso()}", flush=True)
        return r

    with ThreadPoolExecutor(a.workers) as ex:
        results = list(ex.map(one, hosts))
    fails = [r for r in results if any(not v["ok"] for k, v in r.items() if isinstance(v, dict))]
    summary = {"finished_at": now_iso(), "n_hosts": len(hosts), "n_failed_hosts": len(fails),
               "tools": tool_versions(), "failures": fails}
    path = D7 / "scanner_runs.json"
    prev = json.loads(path.read_text()) if path.exists() else {}
    if a.osv_online:
        runs = prev.get("osv_online_runs", []) + [{**summary, "mode": "osv-scanner scan image --archive (online api.osv.dev)"}]
        summary = {**{k: v for k, v in prev.items() if k != "osv_online"}, "osv_online_runs": runs}
    else:
        summary["osv_note"] = "osv.json files come from the osv_online run (offline OSV cannot match Ubuntu packages)"
        summary = {**prev, **summary}
    path.write_text(json.dumps(summary, indent=1))
    print(f"scanned {len(hosts)} hosts, {len(fails)} with failures")


if __name__ == "__main__":
    main()
