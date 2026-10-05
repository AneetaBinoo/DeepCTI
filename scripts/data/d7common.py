"""Shared helpers for the D7 (DeepCTI-Live-X) pipeline: paths, mirrored-source loaders."""

from __future__ import annotations

import json
import lzma
import sys
import zipfile
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, MIRRORS, ROOT, SEED, SNAP_DATE, src_of  # noqa: E402,F401

sys.path.insert(0, str(ROOT / "src"))
from deepcti.core import versions as V  # noqa: E402  (shared comparator; owned by the lead)

D7 = DATA / "d7"
HOSTS = D7 / "hosts"
CUR = D7 / "curation"
UBUNTU_RELEASES = ("jammy", "noble")
UBUNTU_NUM = {"jammy": "22.04", "noble": "24.04"}
UBUNTU_OSV_ECO = {"jammy": "Ubuntu:22.04:LTS", "noble": "Ubuntu:24.04:LTS"}
TEMPORAL_CUTOFF = "2026-05-01"
OSV_UBUNTU_ZIP = ROOT / "tools" / "cache" / "osv" / "osv-scalibr" / "Ubuntu" / "all.zip"


def load_json(p: Path):
    return json.loads(Path(p).read_text())


def mirror(source: str) -> Path:
    return MIRRORS / source / SNAP_DATE


@lru_cache(maxsize=None)
def ubuntu_packages(codename: str) -> dict[str, dict]:
    """Binary name -> Packages paragraph (highest version over release/-updates/-security, main+universe)."""
    from debian.deb822 import Packages
    from debian.debian_support import Version

    cache = DATA / "cache" / f"ubuntu_packages_{codename}_{SNAP_DATE}.json"
    if cache.exists():
        return json.loads(cache.read_text())
    out: dict[str, dict] = {}
    for suite in (codename, f"{codename}-updates", f"{codename}-security"):
        for comp in ("main", "universe"):
            p = mirror("ubuntu_archive") / "raw" / suite / f"{comp}_binary-amd64_Packages.xz"
            with lzma.open(p, "rt", encoding="utf-8") as f:
                for para in Packages.iter_paragraphs(f, use_apt_pkg=False):
                    d = dict(para)
                    d["_suite"] = suite
                    d["_component"] = comp
                    name = d["Package"]
                    if name not in out or Version(d["Version"]) > Version(out[name]["Version"]):
                        out[name] = d
    cache.write_text(json.dumps(out))
    return out


def base_status_text(release: str) -> str:
    return (DATA / "base_images" / release / "rootfs" / "var" / "lib" / "dpkg" / "status").read_text()


@lru_cache(maxsize=None)
def base_packages(release: str) -> dict[str, dict]:
    from debian.deb822 import Deb822

    return {dict(p)["Package"]: dict(p) for p in Deb822.iter_paragraphs(base_status_text(release).splitlines())}


@lru_cache(maxsize=None)
def base_sources(release: str) -> set[str]:
    return {src_of(p)[0] for p in base_packages(release).values()}


@lru_cache(maxsize=None)
def osv_zip_index(eco: str) -> dict[str, list[str]]:
    """CVE -> list of record names in the OSV export of ecosystem eco (PyPI/Maven/Ubuntu)."""
    path = OSV_UBUNTU_ZIP if eco == "Ubuntu" else mirror("osv_ecosystems") / "raw" / eco / "all.zip"
    z = zipfile.ZipFile(path)
    idx: dict[str, list[str]] = {}
    for nm in z.namelist():
        j = json.loads(z.read(nm))
        if j.get("withdrawn"):
            continue
        ids = {j["id"], *j.get("aliases", []), *j.get("upstream", [])}
        for c in ids:
            if c.startswith("CVE-"):
                idx.setdefault(c, []).append(nm)
    return idx


@lru_cache(maxsize=None)
def _zip(eco: str) -> zipfile.ZipFile:
    path = OSV_UBUNTU_ZIP if eco == "Ubuntu" else mirror("osv_ecosystems") / "raw" / eco / "all.zip"
    return zipfile.ZipFile(path)


def osv_records(eco: str, cve: str) -> list[dict]:
    return [json.loads(_zip(eco).read(nm)) for nm in osv_zip_index(eco).get(cve, [])]


def osv_ranges(rec: dict, eco_name: str, pkg: str) -> list[dict]:
    """All ECOSYSTEM ranges of package pkg in an OSV record, as [{introduced, fixed|last_affected}]."""
    out = []
    for a in rec.get("affected", []):
        if a["package"]["ecosystem"] != eco_name:
            continue
        n = a["package"]["name"]
        if (n.lower() if eco_name == "PyPI" else n) != (pkg.lower() if eco_name == "PyPI" else pkg):
            continue
        for r in a.get("ranges", []):
            if r["type"] != "ECOSYSTEM":
                continue
            cur: dict = {}
            for e in r["events"]:
                if "introduced" in e:
                    if cur:
                        out.append(cur)
                    cur = {"introduced": e["introduced"]}
                elif "fixed" in e:
                    cur["fixed"] = e["fixed"]
                    out.append(cur)
                    cur = {}
                elif "last_affected" in e:
                    cur["last_affected"] = e["last_affected"]
                    out.append(cur)
                    cur = {}
            if cur:
                out.append(cur)
    return out


def nvd_record(cve: str) -> dict | None:
    p = mirror("nvd") / "cves" / f"{cve}.json"
    if not p.exists():
        return None
    j = load_json(p)
    v = j.get("vulnerabilities") or []
    return v[0]["cve"] if v else None


def nvd_published(cve: str) -> str | None:
    n = nvd_record(cve)
    return n.get("published", "")[:10] if n else None


def kev_set() -> dict:
    j = load_json(MIRRORS / "cisa_kev" / SNAP_DATE / "known_exploited_vulnerabilities.json")
    return {v["cveID"]: v for v in j["vulnerabilities"]}


def epss_map() -> dict[str, float]:
    import csv
    import gzip

    out = {}
    with gzip.open(MIRRORS / "epss" / SNAP_DATE / "raw" / "epss_scores-current.csv.gz", "rt") as f:
        next(f)
        for row in csv.DictReader(f):
            out[row["cve"]] = float(row["epss"])
    return out
