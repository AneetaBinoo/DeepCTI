"""Select D1 CVEs (userland Debian source packages) and split them by CVE.

Selection: KEV ∩ Debian tracker for the target packages, plus curated configuration-gated CVEs, plus
non-KEV CVEs in the same packages (balanced toward recent / temporal hold-out CVEs and toward CVEs with
an in-release fix, which yields vulnerable + backport cases). Split: dev 30 / calib 20 / test 50,
stratified by (family, temporal_holdout), seed 20261005.

Output: data/d1/selected_cves.json (list of rows) and data/d1/selected_cves.txt (one CVE per line).
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, MIRRORS, ROOT, SEED, SNAP_DATE  # noqa: E402

D1_RELEASES = ("bookworm", "trixie")  # bullseye is no longer in the tracker JSON (see BUILD_REPORT)

FAMILIES = {
    "crypto_tls": {"openssl": 6, "gnutls28": 4, "nss": 3},
    "ssh": {"openssh": 6},
    "privesc": {"sudo": 5, "policykit-1": 3},
    "compression": {"xz-utils": 2, "zlib": 3, "bzip2": 1, "libarchive": 4},
    "web_server": {"apache2": 7, "nginx": 5},
    "dns": {"bind9": 7},
    "mail": {"exim4": 5, "postfix": 2},
    "file_sharing": {"samba": 6},
    "interpreter": {"python3.11": 3, "python3.13": 3, "perl": 4, "ruby3.1": 2, "ruby3.3": 2,
                    "php8.2": 2, "php8.4": 2},
    "library": {"curl": 5, "libxml2": 4, "expat": 4, "glibc": 4, "sqlite3": 3, "libssh": 4, "tiff": 3,
                "libwebp": 1, "git": 3},
}
PKG_FAMILY = {p: f for f, ps in FAMILIES.items() for p in ps}
SPLIT_FRACS = (("dev", 0.3), ("calib", 0.2), ("test", 0.5))
INREL = {"bookworm": r"[+~]deb12u\d+", "trixie": r"[+~]deb13u\d+"}


def load_tracker() -> dict:
    return json.loads((MIRRORS / "debian_tracker" / SNAP_DATE / "raw" / "tracker.json").read_text())


def load_kev() -> dict:
    j = json.loads((MIRRORS / "cisa_kev" / SNAP_DATE / "known_exploited_vulnerabilities.json").read_text())
    return {v["cveID"]: v for v in j["vulnerabilities"]}


def load_epss() -> dict[str, float]:
    out = {}
    with gzip.open(MIRRORS / "epss" / SNAP_DATE / "raw" / "epss_scores-current.csv.gz", "rt") as f:
        next(f)
        for row in csv.DictReader(f):
            out[row["cve"]] = float(row["epss"])
    return out


TEMPORAL_CUTOFF = "2026-05-01"  # lead: Granite-4.1-8B release 2026-04-29 is the binding model cutoff


def nvd_published(cve: str) -> str | None:
    p = MIRRORS / "nvd" / SNAP_DATE / "cves" / f"{cve}.json"
    if not p.exists():
        return None
    j = json.loads(p.read_text())
    v = j.get("vulnerabilities") or []
    return v[0]["cve"]["published"][:10] if v else None


def osv_published(cve: str) -> str | None:
    p = MIRRORS / "osv" / SNAP_DATE / "vulns" / f"{cve}.json"
    if not p.exists():
        return None
    return (json.loads(p.read_text()).get("published") or "")[:10] or None


def published(cve: str) -> tuple[str | None, str]:
    pub = nvd_published(cve)
    if pub:
        return pub, "nvd"
    pub = osv_published(cve)
    return (pub, "osv") if pub else (None, "unknown")


def release_profile(entry: dict) -> dict:
    """Which variants the tracker entry supports per release."""
    prof = {}
    for r in D1_RELEASES:
        x = entry["releases"].get(r)
        if not x or not x.get("repositories"):
            continue
        fv = x.get("fixed_version")
        if x["status"] == "resolved" and fv and fv != "0":
            prof[r] = "inrelease_fix" if re.search(INREL[r], fv) else "fixed_before_release"
        elif x["status"] == "open":
            prof[r] = "open"
        elif x["status"] == "resolved" and fv == "0":
            prof[r] = "not_affected"
        else:
            prof[r] = x["status"]
    return prof


def score(cve: str, entry: dict, epss: dict) -> float:
    prof = release_profile(entry)
    s = 0.0
    s += 3 * sum(v == "inrelease_fix" for v in prof.values())
    s += 1 * sum(v == "open" for v in prof.values())
    if any(entry["releases"].get(r, {}).get("urgency") == "unimportant" for r in D1_RELEASES):
        s -= 2
    return s + epss.get(cve, 0.0)


def stable_hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def select(tracker: dict, kev: dict, epss: dict, pre_cves: dict[str, str]) -> list[dict]:
    rows = []
    for fam, pkgs in FAMILIES.items():
        for pkg, cap in pkgs.items():
            entries = tracker.get(pkg, {})
            chosen: list[tuple[str, str]] = []
            for cve in sorted(entries):
                if cve in kev:
                    chosen.append((cve, "kev"))
            for cve, p in pre_cves.items():
                if p == pkg and cve in entries and cve not in dict(chosen):
                    chosen.append((cve, "config_precondition"))
            cap = max(cap, len(chosen) + 2)
            elig = []
            for cve, e in entries.items():
                if cve in dict(chosen) or not cve.startswith("CVE-"):
                    continue
                prof = release_profile(e)
                if not any(v in ("inrelease_fix", "open") for v in prof.values()):
                    continue
                if "REJECT" in (e.get("description") or ""):
                    continue
                elig.append((score(cve, e, epss), cve))
            elig.sort(key=lambda t: (-t[0], stable_hash(str(SEED), t[1])))
            is_recent = {c: (published(c)[0] or "") >= TEMPORAL_CUTOFF for _, c in elig}
            recent = [c for _, c in elig if is_recent[c]]
            older = [c for _, c in elig if not is_recent[c]]
            n_left = max(0, cap - len(chosen))
            n_recent = min(len(recent), round(0.6 * n_left + 0.01))
            picks = recent[:n_recent] + older[: n_left - n_recent]
            if len(picks) < n_left:
                picks += [c for c in recent[n_recent:]][: n_left - len(picks)]
            chosen += [(c, "balance_recent" if is_recent[c] else "balance") for c in picks]
            for cve, why in chosen:
                rows.append({"cve": cve, "src_package": pkg, "family": fam, "kev": cve in kev,
                             "epss": epss.get(cve), "reason": why,
                             "release_profile": release_profile(entries[cve])})
    return rows


def assign_splits(rows: list[dict]) -> None:
    strata: dict[tuple, list[dict]] = {}
    for r in rows:
        strata.setdefault((r["family"], r["temporal_holdout"]), []).append(r)
    # carry fractional remainders across strata so global proportions stay close to 30/20/50
    carry = {s: 0.0 for s, _ in SPLIT_FRACS}
    for key in sorted(strata, key=lambda k: (k[0], k[1])):
        items = sorted(strata[key], key=lambda r: stable_hash(str(SEED), r["cve"]))
        n = len(items)
        counts = {}
        for s, frac in SPLIT_FRACS:
            want = n * frac + carry[s]
            counts[s] = int(want)
            carry[s] = want - counts[s]
        rest = n - sum(counts.values())
        for s, _ in sorted(SPLIT_FRACS, key=lambda t: -carry[t[0]]):
            if rest <= 0:
                break
            counts[s] += 1
            carry[s] -= 1
            rest -= 1
        i = 0
        for s, _ in SPLIT_FRACS:
            for r in items[i: i + counts[s]]:
                r["split"] = s
            i += counts[s]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--preconditions", default=str(ROOT / "config" / "config_preconditions.yaml"))
    ap.add_argument("--refresh-only", action="store_true", help="keep CVE set, refresh dates and splits")
    a = ap.parse_args()
    tracker, kev, epss = load_tracker(), load_kev(), load_epss()
    pre: dict[str, str] = {}
    if Path(a.preconditions).exists():
        for p in yaml.safe_load(Path(a.preconditions).read_text())["preconditions"]:
            pre[p["cve"]] = p["src_package"]
    out = DATA / "d1" / "selected_cves.json"
    if a.refresh_only and out.exists():
        # keep the frozen CVE set; only refresh published dates, temporal flags and splits
        rows = [{k: v for k, v in r.items() if k not in ("split",)} for r in json.loads(out.read_text())]
    else:
        rows = select(tracker, kev, epss, pre)
    for r in rows:
        pub, src = published(r["cve"])
        r["published"] = pub
        r["published_source"] = src
        r["temporal_holdout"] = bool(pub and pub >= TEMPORAL_CUTOFF)
    assign_splits(rows)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=1))
    (DATA / "d1" / "selected_cves.txt").write_text("\n".join(r["cve"] for r in rows) + "\n")
    by = {}
    for r in rows:
        by.setdefault(r["split"], [0, 0])
        by[r["split"]][0] += 1
        by[r["split"]][1] += r["temporal_holdout"]
    print(f"selected {len(rows)} CVEs; kev={sum(r['kev'] for r in rows)}; split (n, temporal) = {by}")


if __name__ == "__main__":
    main()
