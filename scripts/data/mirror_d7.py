"""Mirror the external sources used by D7 (DeepCTI-Live-X) into data/mirrors/<source>/<SNAP_DATE>/.

Sub-commands (all resumable from cache; every file is recorded in the source's MANIFEST.json):
  base                       ubuntu:22.04 / ubuntu:24.04 (linux/amd64) via the Docker Registry v2 HTTP API
  ubuntu_archive             Packages.xz (main+universe) for jammy/noble{,-updates,-security}
  osv_zips                   OSV ecosystem exports (PyPI, Maven) -> mirror + OSV-Scanner offline cache
  ubuntu_cves --cves FILE    official Ubuntu CVE tracker JSON (ubuntu.com/security/cves/<CVE>.json)
  launchpad --spec FILE      Launchpad published-source history per (source, series)
  ubuntu_changelogs --spec   changelogs.ubuntu.com per (source, version)
  pypi --spec FILE           PyPI JSON API per (project) and per (project, version)
  maven --spec FILE          Maven Central maven-metadata.xml per groupId:artifactId
  nvd / osv --cves FILE      NVD 2.0 / OSV.dev per CVE (shared with D1 mirror; reuse mirror_sources)
  urls --spec FILE           arbitrary vendor files (release notes, default configs at release tags)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, ROOT, Manifest, fetch_cached, now_iso, sha256_file  # noqa: E402

LIC = {
    "docker_hub_ubuntu": "Ubuntu official images (Docker Official Images); Canonical, mostly DFSG-free contents",
    "ubuntu_archive": "Ubuntu archive indices (archive.ubuntu.com / security.ubuntu.com) package metadata",
    "osv_ecosystems": "OSV.dev ecosystem exports (osv-vulnerabilities bucket), CC-BY 4.0 / per-source",
    "ubuntu_cve_tracker": "Ubuntu CVE tracker JSON API (ubuntu.com/security/cves), Canonical, public data",
    "launchpad": "Launchpad API (api.launchpad.net) published source history, public metadata",
    "ubuntu_changelogs": "changelogs.ubuntu.com Debian changelogs (package metadata, per-package license)",
    "pypi": "PyPI JSON API metadata (pypi.org/pypi/<project>/json), public metadata",
    "maven_central": "Maven Central maven-metadata.xml (repo1.maven.org), public metadata",
    "vendor_files": "Vendor source files at release tags (Apache-2.0 / GPL-3.0 / MIT per project)",
    "ubuntu_debs": "Ubuntu binary packages (only default configuration files are used in fixtures)",
    "advisory_pages": "Vendor advisory pages (fetched for verbatim quotes of configuration preconditions)",
}

UBUNTU = {"jammy": "22.04", "noble": "24.04"}
REG = "https://registry-1.docker.io/v2/library/ubuntu"
KEEP_PREFIXES = ("etc/", "var/lib/dpkg/")
KEEP_FILES = ("usr/lib/os-release",)


def _read_spec(path: str):
    return json.loads(Path(path).read_text())


# ------------------------------------------------------------------------------------------- base images
def mirror_base() -> None:
    man = Manifest("docker_hub_ubuntu", LIC["docker_hub_ubuntu"])
    for codename, tag in UBUNTU.items():
        tok = requests.get(
            "https://auth.docker.io/token",
            params={"service": "registry.docker.io", "scope": "repository:library/ubuntu:pull"},
            timeout=60,
        ).json()["token"]
        h = {
            "Authorization": f"Bearer {tok}",
            "Accept": "application/vnd.oci.image.index.v1+json, "
            "application/vnd.docker.distribution.manifest.list.v2+json",
        }
        r = requests.get(f"{REG}/manifests/{tag}", headers=h, timeout=60)
        r.raise_for_status()
        index_digest = r.headers.get("Docker-Content-Digest")
        index = r.json()
        (man.dir / f"{codename}_index.json").write_text(json.dumps(index, indent=1))
        man.add(f"{REG}/manifests/{tag}", man.dir / f"{codename}_index.json", now_iso(), digest=index_digest)
        amd = [
            m
            for m in index["manifests"]
            if m.get("platform", {}).get("architecture") == "amd64" and m["platform"].get("os") == "linux"
        ]
        mdigest = amd[0]["digest"]
        h["Accept"] = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
        r = requests.get(f"{REG}/manifests/{mdigest}", headers=h, timeout=60)
        r.raise_for_status()
        manifest = r.json()
        (man.dir / f"{codename}_manifest_amd64.json").write_text(json.dumps(manifest, indent=1))
        man.add(f"{REG}/manifests/{mdigest}", man.dir / f"{codename}_manifest_amd64.json", now_iso(), digest=mdigest)
        raw = man.dir / "raw" / codename
        raw.mkdir(parents=True, exist_ok=True)
        layers = []
        for layer in manifest["layers"]:
            dg = layer["digest"]
            dest = raw / (dg.replace(":", "_") + ".tar.gz")
            if not dest.exists() or sha256_file(dest) != dg.split(":")[1]:
                with requests.get(
                    f"{REG}/blobs/{dg}", headers={"Authorization": f"Bearer {tok}"}, stream=True, timeout=300
                ) as rr:
                    rr.raise_for_status()
                    with open(dest, "wb") as f:
                        for chunk in rr.iter_content(1 << 20):
                            f.write(chunk)
                assert sha256_file(dest) == dg.split(":")[1], "layer digest mismatch"
            man.add(f"{REG}/blobs/{dg}", dest, now_iso(), digest=dg)
            layers.append(dest)
        root = DATA / "base_images" / codename / "rootfs"
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        for lp in layers:
            with tarfile.open(lp, "r:gz") as tf:
                members = [
                    m
                    for m in tf.getmembers()
                    if (m.name.lstrip("./").startswith(KEEP_PREFIXES) or m.name.lstrip("./") in KEEP_FILES)
                    and (m.isfile() or m.isdir() or m.issym())
                ]
                tf.extractall(root, members=members, filter="tar")
        info = {
            "release": codename,
            "image": f"ubuntu:{tag}",
            "index_digest": index_digest,
            "manifest_digest_amd64": mdigest,
            "reference": f"ubuntu:{tag}@{index_digest}",
            "layers": [m["digest"] for m in manifest["layers"]],
            "retrieved_at": now_iso(),
            "extracted": list(KEEP_PREFIXES) + list(KEEP_FILES),
        }
        (DATA / "base_images" / codename / "IMAGE.json").write_text(json.dumps(info, indent=1))
        print(codename, info["reference"])
    man.save()


# ------------------------------------------------------------------------------------------ ubuntu archive
def mirror_ubuntu_archive() -> None:
    man = Manifest("ubuntu_archive", LIC["ubuntu_archive"])
    jobs = []
    for cn in UBUNTU:
        for suite in (cn, f"{cn}-updates", f"{cn}-security"):
            host = "http://security.ubuntu.com/ubuntu" if suite.endswith("-security") else "http://archive.ubuntu.com/ubuntu"
            for comp in ("main", "universe"):
                jobs.append(
                    (
                        f"{host}/dists/{suite}/{comp}/binary-amd64/Packages.xz",
                        man.dir / "raw" / suite / f"{comp}_binary-amd64_Packages.xz",
                    )
                )
            jobs.append((f"{host}/dists/{suite}/InRelease", man.dir / "raw" / suite / "InRelease"))
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(lambda j: (j[0], *fetch_cached(j[0], j[1], timeout=600)), jobs))
    for url, p, new in res:
        man.add(url, p, now_iso() if new else None)
    man.save()


# ------------------------------------------------------------------------------------------------ OSV zips
def mirror_osv_zips(ecos: list[str]) -> None:
    man = Manifest("osv_ecosystems", LIC["osv_ecosystems"])
    for eco in ecos:
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
        p, new = fetch_cached(url, man.dir / "raw" / eco / "all.zip", timeout=1200)
        man.add(url, p, now_iso() if new else None)
        # OSV-Scanner offline database (same export, same day)
        dst = ROOT / "tools" / "cache" / "osv" / "osv-scalibr" / eco / "all.zip"
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists() or sha256_file(dst) != sha256_file(p):
            shutil.copy2(p, dst)
        print(eco, p.stat().st_size)
    # record the Ubuntu export that OSV-Scanner already holds (used for the cross-check)
    ub = ROOT / "tools" / "cache" / "osv" / "osv-scalibr" / "Ubuntu" / "all.zip"
    if ub.exists():
        man.data.setdefault("notes", {})["Ubuntu"] = {
            "path": str(ub.relative_to(ROOT)),
            "sha256": sha256_file(ub),
            "bytes": ub.stat().st_size,
            "url": "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip",
            "note": "downloaded by OSV-Scanner on 2026-10-05 05:08Z (D1 run); used as the OSV Ubuntu cross-check",
        }
    man.save()


# -------------------------------------------------------------------------------------- ubuntu CVE tracker
def mirror_ubuntu_cves(cves: list[str]) -> None:
    man = Manifest("ubuntu_cve_tracker", LIC["ubuntu_cve_tracker"])

    def one(cve):
        url = f"https://ubuntu.com/security/cves/{cve}.json"
        p, new = fetch_cached(url, man.dir / "cves" / f"{cve}.json", min_interval=0.3, throttle_key="ubuntu")
        return url, p, new

    with ThreadPoolExecutor(4) as ex:
        for url, p, new in ex.map(one, cves):
            man.add(url, p, now_iso() if new else None)
    man.save()


def mirror_launchpad(spec: list[list[str]]) -> None:
    """spec: [[source, series], ...] -> all publications (any pocket/status) of source in series."""
    man = Manifest("launchpad", LIC["launchpad"])

    def one(item):
        src, series = item
        url = (
            "https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources"
            f"&source_name={quote(src)}&exact_match=true&distro_series="
            f"{quote(f'https://api.launchpad.net/1.0/ubuntu/{series}', safe='')}&ws.size=300"
        )
        p, new = fetch_cached(url, man.dir / "sources" / series / f"{src}.json", min_interval=0.2, throttle_key="lp")
        return url, p, new

    with ThreadPoolExecutor(4) as ex:
        for url, p, new in ex.map(one, spec):
            man.add(url, p, now_iso() if new else None)
    man.save()


def _pool(src: str) -> str:
    return src[:4] if src.startswith("lib") else src[0]


def mirror_ubuntu_changelogs(spec: list[list[str]]) -> None:
    """spec: [[source, version, component], ...]"""
    man = Manifest("ubuntu_changelogs", LIC["ubuntu_changelogs"])

    def one(item):
        src, ver, comp = item
        nv = ver.split(":", 1)[1] if ":" in ver else ver
        url = f"https://changelogs.ubuntu.com/changelogs/pool/{comp}/{_pool(src)}/{src}/{src}_{nv}/changelog"
        p, new = fetch_cached(url, man.dir / "raw" / src / f"{nv}_changelog", min_interval=0.2, throttle_key="clog")
        return url, p, new

    with ThreadPoolExecutor(4) as ex:
        for url, p, new in ex.map(one, spec):
            man.add(url, p, now_iso() if new else None)
    man.save()


def mirror_pypi(spec: list[list[str]]) -> None:
    """spec: [[project], [project, version], ...]"""
    man = Manifest("pypi", LIC["pypi"])

    def one(item):
        if len(item) == 1:
            url = f"https://pypi.org/pypi/{item[0]}/json"
            dest = man.dir / "projects" / f"{item[0].lower()}.json"
        else:
            url = f"https://pypi.org/pypi/{item[0]}/{item[1]}/json"
            dest = man.dir / "releases" / item[0].lower() / f"{item[1]}.json"
        p, new = fetch_cached(url, dest, min_interval=0.05, throttle_key="pypi")
        return url, p, new

    with ThreadPoolExecutor(8) as ex:
        for url, p, new in ex.map(one, spec):
            man.add(url, p, now_iso() if new else None)
    man.save()


def mirror_maven(spec: list[str]) -> None:
    """spec: ["groupId:artifactId", ...]"""
    man = Manifest("maven_central", LIC["maven_central"])

    def one(ga):
        g, a = ga.split(":")
        url = f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/maven-metadata.xml"
        p, new = fetch_cached(url, man.dir / "metadata" / g / f"{a}.xml", min_interval=0.05, throttle_key="maven")
        return url, p, new

    with ThreadPoolExecutor(8) as ex:
        for url, p, new in ex.map(one, spec):
            man.add(url, p, now_iso() if new else None)
    man.save()


def mirror_urls(spec: list[list[str]], source: str) -> None:
    """spec: [[url, relative_dest], ...]"""
    man = Manifest(source, LIC[source])

    def one(item):
        url, rel = item
        p, new = fetch_cached(url, man.dir / "raw" / rel, min_interval=0.1, throttle_key=source)
        return url, p, new

    with ThreadPoolExecutor(6) as ex:
        for url, p, new in ex.map(one, spec):
            man.add(url, p, now_iso() if new else None)
    man.save()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd")
    ap.add_argument("--cves")
    ap.add_argument("--spec")
    ap.add_argument("--source", default="vendor_files")
    ap.add_argument("--eco", nargs="*", default=["PyPI", "Maven"])
    a = ap.parse_args()
    if a.cmd == "base":
        mirror_base()
    elif a.cmd == "ubuntu_archive":
        mirror_ubuntu_archive()
    elif a.cmd == "osv_zips":
        mirror_osv_zips(a.eco)
    elif a.cmd == "ubuntu_cves":
        mirror_ubuntu_cves([x for x in Path(a.cves).read_text().split() if x])
    elif a.cmd == "launchpad":
        mirror_launchpad(_read_spec(a.spec))
    elif a.cmd == "ubuntu_changelogs":
        mirror_ubuntu_changelogs(_read_spec(a.spec))
    elif a.cmd == "pypi":
        mirror_pypi(_read_spec(a.spec))
    elif a.cmd == "maven":
        mirror_maven(_read_spec(a.spec))
    elif a.cmd == "urls":
        mirror_urls(_read_spec(a.spec), a.source)
    else:
        raise SystemExit(f"unknown command {a.cmd}")


if __name__ == "__main__":
    _ = hashlib  # keep import (digest helpers)
    main()
