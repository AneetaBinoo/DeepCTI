"""Run Trivy, Grype and OSV-Scanner offline against every D1 host fixture (whole host).

Outputs data/d1/hosts/<host_id>/scans/{trivy,grype,osv}.json and data/d1/scanner_runs.json (versions,
DB metadata, per-host exit codes). Resumable: existing non-empty outputs are skipped unless --force.

* trivy rootfs --skip-db-update --offline-scan (DB pre-downloaded into tools/cache/trivy)
* grype dir:<rootfs> with GRYPE_DB_AUTO_UPDATE=false (DB pre-downloaded into tools/cache/grype)
* osv-scanner v2 cannot detect the distro release when given a bare dpkg status file (it guessed the
  Ubuntu ecosystem and found nothing), so each rootfs is packed into a single-layer docker-archive tarball
  and scanned with `osv-scanner scan image --archive ... --offline-vulnerabilities` (local Debian DB).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, ROOT, now_iso  # noqa: E402

BIN = ROOT / "tools" / "bin"
CACHE = ROOT / "tools" / "cache"
ENV = dict(os.environ, GRYPE_DB_AUTO_UPDATE="false", GRYPE_DB_CACHE_DIR=str(CACHE / "grype"),
           GRYPE_CHECK_FOR_APP_UPDATE="false", OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(CACHE / "osv"),
           TRIVY_NO_PROGRESS="true")


def run(cmd: list[str], out: Path, timeout: int = 600) -> dict:
    p = subprocess.run(cmd, env=ENV, capture_output=True, text=True, timeout=timeout)
    ok = p.returncode in (0, 1) and out.exists() and out.stat().st_size > 0
    return {"rc": p.returncode, "ok": ok, "stderr_tail": p.stderr[-400:] if not ok else ""}


def docker_archive(rootfs: Path, dest: Path) -> None:
    with tempfile.TemporaryDirectory(dir=dest.parent) as td:
        layer = Path(td) / "layer.tar"
        with tarfile.open(layer, "w") as tf:
            tf.add(rootfs, arcname=".")
        digest = hashlib.sha256(layer.read_bytes()).hexdigest()
        (Path(td) / "config.json").write_text(json.dumps({
            "architecture": "amd64", "os": "linux", "config": {},
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{digest}"]},
            "history": [{"created_by": "DeepCTI rootfs fixture"}]}))
        (Path(td) / "manifest.json").write_text(json.dumps(
            [{"Config": "config.json", "RepoTags": ["deepcti/fixture:latest"], "Layers": ["layer.tar"]}]))
        with tarfile.open(dest, "w") as tf:
            for n in ("manifest.json", "config.json", "layer.tar"):
                tf.add(Path(td) / n, arcname=n)


def scan_host(hdir: Path, force: bool) -> dict:
    rootfs, sdir = hdir / "rootfs", hdir / "scans"
    sdir.mkdir(exist_ok=True)
    res = {}
    t = sdir / "trivy.json"
    if force or not t.exists() or t.stat().st_size == 0:
        res["trivy"] = run([str(BIN / "trivy"), "rootfs", "--quiet", "--format", "json", "--skip-db-update",
                            "--offline-scan", "--scanners", "vuln", "--cache-dir", str(CACHE / "trivy"),
                            "--output", str(t), str(rootfs)], t)
    g = sdir / "grype.json"
    if force or not g.exists() or g.stat().st_size == 0:
        res["grype"] = run([str(BIN / "grype"), f"dir:{rootfs}", "-q", "-o", "json", "--file", str(g)], g)
    o = sdir / "osv.json"
    if force or not o.exists() or o.stat().st_size == 0:
        tmp = CACHE / "osv_archives"
        tmp.mkdir(parents=True, exist_ok=True)
        arch = tmp / f"{hdir.name}.tar"
        docker_archive(rootfs, arch)
        res["osv"] = run([str(BIN / "osv-scanner"), "scan", "image", "--archive", str(arch), "--format", "json",
                          "--offline-vulnerabilities", "--verbosity", "error", "--output-file", str(o)], o)
        arch.unlink(missing_ok=True)
    return {"host_id": hdir.name, **res}


def tool_versions() -> dict:
    def out(cmd):
        return subprocess.run(cmd, env=ENV, capture_output=True, text=True).stdout.strip()

    meta = {"trivy": out([str(BIN / "trivy"), "--version", "--cache-dir", str(CACHE / "trivy")]),
            "grype": out([str(BIN / "grype"), "version"]),
            "grype_db": out([str(BIN / "grype"), "db", "status"]),
            "osv-scanner": out([str(BIN / "osv-scanner"), "--version"])}
    osv_db = {}
    for z in sorted((CACHE / "osv" / "osv-scalibr").glob("*/all.zip")):
        osv_db[z.parent.name] = {"bytes": z.stat().st_size,
                                 "mtime": __import__("datetime").datetime.fromtimestamp(z.stat().st_mtime)
                                 .isoformat()}
    meta["osv_db"] = osv_db
    return meta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=48)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    hosts = sorted(p for p in (DATA / "d1" / "hosts").iterdir() if (p / "rootfs").is_dir())
    with ThreadPoolExecutor(a.workers) as ex:
        results = list(ex.map(lambda h: scan_host(h, a.force), hosts))
    fails = [r for r in results if any(not v["ok"] for k, v in r.items() if isinstance(v, dict))]
    summary = {"finished_at": now_iso(), "n_hosts": len(hosts), "n_failed_hosts": len(fails),
               "tools": tool_versions(), "failures": fails}
    (DATA / "d1" / "scanner_runs.json").write_text(json.dumps(summary, indent=1))
    print(f"scanned {len(hosts)} hosts, {len(fails)} with failures")


if __name__ == "__main__":
    main()
