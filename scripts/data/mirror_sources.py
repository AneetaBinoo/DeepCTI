"""Mirror external sources once into data/mirrors/<source>/<SNAP_DATE>/ with MANIFEST.json.

Sub-commands (all resumable from cache):
  global                 CISA KEV, Debian security tracker JSON, EPSS CSV, Debian archive Packages indices
  nvd  --cves FILE       NVD CVE API 2.0, one JSON per CVE (no API key: >= 6 s between requests)
  osv  --cves FILE       OSV.dev /v1/vulns/<CVE>
  snapshot --packages P  snapshot.debian.org /mr/package/<src>/ (version lists), <= 2 req/s
  debs --spec FILE       selected .deb files from deb.debian.org (default config files for fixtures)
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Manifest, fetch_cached, now_iso  # noqa: E402

LIC = {
    "cisa_kev": "CISA KEV catalog, U.S. Government work (public domain / CC0 per cisa.gov)",
    "debian_tracker": "Debian security tracker data (security-tracker.debian.org), freely redistributable",
    "epss": "FIRST EPSS scores (empiricalsecurity.com), free to use with attribution to FIRST.org EPSS SIG",
    "debian_archive": "Debian archive indices (deb.debian.org); package metadata under Debian archive terms",
    "nvd": "NVD data (U.S. Government work, public domain); 'This product uses the NVD API but is not "
    "endorsed or certified by the NVD.'",
    "osv": "OSV.dev data, CC-BY 4.0 / per-source licenses (Debian DSA/DLA records)",
    "snapshot_debian": "snapshot.debian.org machine-readable API responses (metadata only)",
    "debian_debs": "Debian binary packages (DFSG-free); only default config files go into fixtures",
}

ARCHIVE_SUITES = {
    "bullseye": ["bullseye", "bullseye-updates"],
    "bookworm": ["bookworm", "bookworm-updates"],
    "trixie": ["trixie", "trixie-updates"],
}
SECURITY_SUITES = {
    "bullseye": "bullseye-security",
    "bookworm": "bookworm-security",
    "trixie": "trixie-security",
}


def mirror_global() -> None:
    m = Manifest("cisa_kev", LIC["cisa_kev"])
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    p, new = fetch_cached(url, m.dir / "known_exploited_vulnerabilities.json")
    m.add(url, p, now_iso() if new else None)
    m.save()

    m = Manifest("debian_tracker", LIC["debian_tracker"])
    url = "https://security-tracker.debian.org/tracker/data/json"
    p, new = fetch_cached(url, m.dir / "raw" / "tracker.json", timeout=600)
    m.add(
        url,
        p,
        now_iso() if new else None,
        format="JSON {src_package: {CVE: {description, releases: "
        "{release: {status, fixed_version, urgency, repositories}}}}}",
    )
    m.save()

    m = Manifest("epss", LIC["epss"])
    url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    p, new = fetch_cached(url, m.dir / "raw" / "epss_scores-current.csv.gz")
    m.add(
        url,
        p,
        now_iso() if new else None,
        note="redirects to epss_scores-<date>.csv.gz; first line is #model_version,score_date comment",
    )
    m.save()

    m = Manifest("debian_archive", LIC["debian_archive"])
    jobs = []
    for rel, suites in ARCHIVE_SUITES.items():
        for s in suites:
            jobs.append(
                (
                    f"https://deb.debian.org/debian/dists/{s}/main/binary-amd64/Packages.xz",
                    m.dir / "raw" / s / "main_binary-amd64_Packages.xz",
                )
            )
            jobs.append(
                (f"https://deb.debian.org/debian/dists/{s}/InRelease", m.dir / "raw" / s / "InRelease")
            )
        s = SECURITY_SUITES[rel]
        jobs.append(
            (
                f"https://security.debian.org/debian-security/dists/{s}/main/binary-amd64/Packages.xz",
                m.dir / "raw" / s / "main_binary-amd64_Packages.xz",
            )
        )
        jobs.append(
            (
                f"https://security.debian.org/debian-security/dists/{s}/InRelease",
                m.dir / "raw" / s / "InRelease",
            )
        )
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(lambda j: (j[0], *fetch_cached(j[0], j[1])), jobs))
    for url, p, new in res:
        m.add(url, p, now_iso() if new else None)
    m.save()


def _read_list(path: str) -> list[str]:
    return [x.strip() for x in Path(path).read_text().split() if x.strip()]


def mirror_nvd(cves: list[str]) -> None:
    m = Manifest("nvd", LIC["nvd"])
    for i, cve in enumerate(cves):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
        p, new = fetch_cached(url, m.dir / "cves" / f"{cve}.json", min_interval=6.5, throttle_key="nvd")
        m.add(url, p, now_iso() if new else None)
        if new and i % 10 == 0:
            m.save()
            print(f"nvd {i + 1}/{len(cves)} {cve}", flush=True)
    m.save()


def mirror_osv(cves: list[str]) -> None:
    m = Manifest("osv", LIC["osv"])

    def one(cve: str):
        url = f"https://api.osv.dev/v1/vulns/{cve}"
        return url, *fetch_cached(url, m.dir / "vulns" / f"{cve}.json", min_interval=0.1, throttle_key="osv")

    with ThreadPoolExecutor(4) as ex:
        for url, p, new in ex.map(one, cves):
            m.add(url, p, now_iso() if new else None)
    m.save()


def mirror_snapshot(packages: list[str]) -> None:
    m = Manifest("snapshot_debian", LIC["snapshot_debian"])
    for pkg in packages:
        url = f"https://snapshot.debian.org/mr/package/{pkg}/"
        p, new = fetch_cached(url, m.dir / "package" / f"{pkg}.json", min_interval=0.5, throttle_key="snap")
        m.add(url, p, now_iso() if new else None)
    m.save()


def mirror_debs(spec: list[dict]) -> None:
    """spec rows: {"url": ..., "name": "<file>.deb"}."""
    m = Manifest("debian_debs", LIC["debian_debs"])
    for row in spec:
        p, new = fetch_cached(row["url"], m.dir / "raw" / row["name"], min_interval=0.2, throttle_key="deb")
        m.add(row["url"], p, now_iso() if new else None)
    m.save()


def changelog_url(src: str, version: str) -> str:
    from debian.debian_support import Version

    prefix = src[:4] if src.startswith("lib") else src[0]
    v = Version(version)
    noepoch = v.upstream_version + (f"-{v.debian_revision}" if v.debian_revision else "")
    return f"https://metadata.ftp-master.debian.org/changelogs/main/{prefix}/{src}/{src}_{noepoch}_changelog"


def mirror_changelogs(spec: list[dict]) -> None:
    """spec rows: {"src": ..., "release": ..., "versions": [candidates, newest first]}.

    metadata.ftp-master only keeps changelogs of versions currently in the archive (security-only
    versions are often missing), so candidates are tried in order until one exists; that changelog
    contains the entries of all earlier versions of the release.
    """
    m = Manifest("debian_changelogs", "Debian package changelogs (metadata.ftp-master.debian.org), DFSG")

    def one(row: dict):
        got = []
        for ver in row["versions"]:
            url = changelog_url(row["src"], ver)
            p, new = fetch_cached(
                url,
                m.dir / "raw" / row["src"] / f"{ver.replace(':', '%3a')}_changelog",
                min_interval=0.25,
                throttle_key="meta",
            )
            got.append((url, p, new))
            if not p.read_bytes().startswith(b'{"_status"'):
                break
        return got

    with ThreadPoolExecutor(4) as ex:
        for got in ex.map(one, spec):
            for url, p, new in got:
                m.add(url, p, now_iso() if new else None)
    m.save()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["global", "nvd", "osv", "snapshot", "debs", "changelogs"])
    ap.add_argument("--cves")
    ap.add_argument("--packages")
    ap.add_argument("--spec")
    a = ap.parse_args()
    if a.cmd == "global":
        mirror_global()
    elif a.cmd == "nvd":
        mirror_nvd(_read_list(a.cves))
    elif a.cmd == "osv":
        mirror_osv(_read_list(a.cves))
    elif a.cmd == "snapshot":
        mirror_snapshot(_read_list(a.packages))
    elif a.cmd == "changelogs":
        mirror_changelogs(json.loads(Path(a.spec).read_text()))
    elif a.cmd == "debs":
        mirror_debs(json.loads(Path(a.spec).read_text()))


if __name__ == "__main__":
    main()
