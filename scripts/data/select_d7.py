"""Select D7 CVEs (curated core + seeded automatic deb-ubuntu picks) and split them by CVE.

Phase `candidates`: curated entries (data/d7/curation/selection.yaml) + automatic deb-ubuntu picks from the
OSV Ubuntu export and Launchpad publication history -> data/d7/curation/candidates.json and a CVE list for
mirroring (NVD, Ubuntu CVE tracker).
Phase `finalize`: drops candidates that fail validation against the mirrored authorities, sets
published/temporal/KEV/EPSS and assigns splits (dev 30 / calib 20 / test 50 by CVE, seed 20261005,
stratified by (ecosystem, config-gated, temporal hold-out)). CVEs that are also in D1 keep their D1 split so
that D1 and D7 test sets never cross dev/calib. Output: data/d7/selected_cves.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml
from debian.debian_support import Version

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d7common import (  # noqa: E402
    CUR,
    D7,
    DATA,
    SEED,
    TEMPORAL_CUTOFF,
    UBUNTU_OSV_ECO,
    UBUNTU_RELEASES,
    epss_map,
    kev_set,
    load_json,
    mirror,
    nvd_record,
    osv_records,
)

AUTO_RECENT_PKGS = [
    "openssl", "curl", "expat", "perl", "unbound", "dnsmasq", "rsync", "libssh", "glibc", "sqlite3",
    "postgresql-16", "postgresql-14", "vim", "python3.12", "python3.10", "libxml2", "redis", "squid",
    "haproxy", "memcached", "bind9", "samba", "openssh", "apache2", "nginx", "exim4", "php8.3", "gnutls28",
]
AUTO_OLD_PKGS = ["curl", "openssl", "glibc", "sqlite3", "libxml2", "expat", "perl", "vim", "postgresql-14",
                 "redis", "dnsmasq", "unbound"]
N_AUTO_RECENT = 24
N_AUTO_OLD = 10
SPLIT_FRACS = (("dev", 0.3), ("calib", 0.2), ("test", 0.5))
ALLOWED_POCKETS = ("Security", "Updates")


def stable_hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def lp_versions(src: str, rel: str) -> list[str]:
    """Versions really shipped to users of `rel`: everything published to -security/-updates plus the final
    release-pocket version (pre-release development uploads are excluded)."""
    p = mirror("launchpad") / "sources" / rel / f"{src}.json"
    if not p.exists():
        return []
    ents = [e for e in load_json(p)["entries"] if e.get("date_published")]
    rel_pocket = [e["source_package_version"] for e in ents if e["pocket"] == "Release"]
    out = {e["source_package_version"] for e in ents if e["pocket"] in ALLOWED_POCKETS}
    if rel_pocket:
        out.add(max(rel_pocket, key=Version))
    return sorted(out, key=Version)


def ubuntu_osv_status(cve: str, src: str) -> dict:
    """{release: {"fixed": v|None, "published": date}} from the OSV Ubuntu export."""
    out = {}
    for rec in osv_records("Ubuntu", cve):
        for a in rec.get("affected", []):
            for rel, eco in UBUNTU_OSV_ECO.items():
                if a["package"]["ecosystem"] == eco and a["package"]["name"] == src:
                    fixed = [e["fixed"] for r in a.get("ranges", []) for e in r["events"] if "fixed" in e]
                    out[rel] = {"fixed": fixed[0] if fixed else None, "published": rec.get("published", "")[:10]}
    return out


def deb_plan_ok(cve: str, src: str) -> dict:
    """Per release: V2 candidate version (shipped, < fixed) and whether V3/V4 is possible."""
    st = ubuntu_osv_status(cve, src)
    out = {}
    for rel, x in st.items():
        vs = lp_versions(src, rel)
        if not vs:
            continue
        if x["fixed"]:
            lower = [v for v in vs if Version(v) < Version(x["fixed"])]
            if lower:
                out[rel] = {"v2": lower[-1], "fixed": x["fixed"], "published": x["published"]}
        else:
            out[rel] = {"v2": vs[-1], "fixed": None, "published": x["published"]}
    return out


def auto_deb(curated: set[str]) -> list[dict]:
    import zipfile

    from d7common import OSV_UBUNTU_ZIP

    z = zipfile.ZipFile(OSV_UBUNTU_ZIP)
    by_pkg: dict[str, list[tuple[str, str]]] = {}
    pkgs = set(AUTO_RECENT_PKGS) | set(AUTO_OLD_PKGS)
    for nm in z.namelist():
        if not nm.startswith("UBUNTU-CVE"):
            continue
        j = json.loads(z.read(nm))
        cve = (j.get("upstream") or [nm[7:-5]])[0]
        if cve in curated or not cve.startswith("CVE-"):
            continue
        for a in j.get("affected", []):
            if a["package"]["name"] in pkgs and a["package"]["ecosystem"] in UBUNTU_OSV_ECO.values():
                by_pkg.setdefault(a["package"]["name"], []).append((cve, j.get("published", "")[:10]))
    picks: list[dict] = []
    used = set(curated)

    def choose(pkg_list, pred, n, reason):
        got = 0
        for pkg in pkg_list:
            if got >= n:
                break
            cands = sorted({c for c, pub in by_pkg.get(pkg, []) if pred(pub)} - used,
                           key=lambda c: stable_hash(str(SEED), c))
            for c in cands:
                plan = deb_plan_ok(c, pkg)
                fixed_rels = [r for r, x in plan.items() if x["fixed"]]
                if len(fixed_rels) == 2 or (len(fixed_rels) == 1 and len(plan) >= 1 and reason == "auto-old"):
                    picks.append({"cve": c, "ecosystem": "deb-ubuntu", "src_package": pkg, "reason": reason})
                    used.add(c)
                    got += 1
                    break
        return got

    choose(AUTO_RECENT_PKGS, lambda p: p >= "2026-05-03", N_AUTO_RECENT, "auto-recent")
    choose(AUTO_OLD_PKGS, lambda p: "2023-01-01" <= p < "2026-01-01", N_AUTO_OLD, "auto-old")
    return picks


def candidates() -> None:
    sel = yaml.safe_load((CUR / "selection.yaml").read_text())
    rows = []
    for eco, items in sel.items():
        for it in items:
            r = dict(it)
            r["ecosystem"] = eco
            if eco == "deb-ubuntu":
                r["component"] = r["src_package"]
            rows.append(r)
    curated = {r["cve"] for r in rows}
    rows += [dict(r, component=r["src_package"]) for r in auto_deb(curated)]
    cves = [r["cve"] for r in rows]
    assert len(cves) == len(set(cves)), "duplicate CVE across ecosystems"
    (CUR / "candidates.json").write_text(json.dumps(rows, indent=1))
    (CUR / "candidate_cves.txt").write_text("\n".join(cves) + "\n")
    (CUR / "candidate_cves_deb.txt").write_text(
        "\n".join(r["cve"] for r in rows if r["ecosystem"] == "deb-ubuntu") + "\n"
    )
    by = {}
    for r in rows:
        by[r["ecosystem"]] = by.get(r["ecosystem"], 0) + 1
    print(f"{len(rows)} candidates {by}")


def assign_splits(rows: list[dict], forced: dict[str, str]) -> None:
    strata: dict[tuple, list[dict]] = {}
    for r in rows:
        if r["cve"] in forced:
            r["split"] = forced[r["cve"]]
            r["split_source"] = "D1 (kept)"
            continue
        strata.setdefault((r["ecosystem"], r["config_gated"], r["temporal_holdout"]), []).append(r)
    # carry-over: fill splits so that the stratum totals including forced rows approach 30/20/50
    for key in sorted(strata):
        items = sorted(strata[key], key=lambda r: stable_hash(str(SEED), r["cve"]))
        n_forced = {s: sum(1 for r in rows if r["cve"] in forced and (r["ecosystem"], r["config_gated"],
                                                                     r["temporal_holdout"]) == key
                               and r["split"] == s) for s, _ in SPLIT_FRACS}
        total = len(items) + sum(n_forced.values())
        want = {s: round(total * f) for s, f in SPLIT_FRACS}
        need = {s: max(0, want[s] - n_forced[s]) for s, _ in SPLIT_FRACS}
        order = []
        for s, _ in SPLIT_FRACS:
            order += [s] * need[s]
        while len(order) < len(items):
            order.append("test")
        # interleave deterministically by hash order
        for r, s in zip(items, order[: len(items)]):
            r["split"] = s
            r["split_source"] = "seeded"


def finalize() -> None:
    from mirror_d7 import UBUNTU  # noqa: F401

    rows = json.loads((CUR / "candidates.json").read_text())
    kev, epss = kev_set(), epss_map()
    pre = {p["cve"] for p in yaml.safe_load((Path(__file__).resolve().parents[2] / "config" /
                                             "config_preconditions_v3.yaml").read_text())["preconditions"]}
    d1 = {r["cve"]: r["split"] for r in load_json(DATA / "d1" / "selected_cves.json")}
    keep, dropped = [], []
    for r in rows:
        nvd = nvd_record(r["cve"])
        pub = (nvd or {}).get("published", "")[:10]
        src = "nvd"
        if not pub:
            if r["ecosystem"] == "deb-ubuntu":
                st = ubuntu_osv_status(r["cve"], r["src_package"])
                pub = min((x["published"] for x in st.values()), default="")
            else:
                recs = osv_records("PyPI" if r["ecosystem"] == "pypi" else "Maven", r["cve"])
                pub = min((x.get("published", "")[:10] for x in recs), default="")
            src = "osv"
        if not pub:
            dropped.append({**r, "why": "no published date"})
            continue
        r.update(
            published=pub,
            published_source=src,
            temporal_holdout=pub >= TEMPORAL_CUTOFF,
            kev=r["cve"] in kev,
            epss=epss.get(r["cve"]),
            config_gated=r["cve"] in pre,
        )
        if r["ecosystem"] == "deb-ubuntu":
            tp = mirror("ubuntu_cve_tracker") / "cves" / f"{r['cve']}.json"
            tj = load_json(tp) if tp.exists() else {}
            if tj.get("_status") == 404 or not tj:
                dropped.append({**r, "why": "not in Ubuntu CVE tracker"})
                continue
        if r["reason"] in ("recent", "auto-recent") and not r["temporal_holdout"]:
            r["note"] = f"selected as recent but NVD published {pub} < {TEMPORAL_CUTOFF}"
        keep.append(r)
    forced = {r["cve"]: d1[r["cve"]] for r in keep if r["cve"] in d1}
    assign_splits(keep, forced)
    keep.sort(key=lambda r: (r["ecosystem"], r["cve"]))
    (D7 / "selected_cves.json").write_text(json.dumps(keep, indent=1))
    (CUR / "dropped_cves.json").write_text(json.dumps(dropped, indent=1))
    by = {}
    for r in keep:
        k = r["split"]
        by.setdefault(k, [0, 0, 0])
        by[k][0] += 1
        by[k][1] += r["temporal_holdout"]
        by[k][2] += r["config_gated"]
    print(f"selected {len(keep)} (dropped {len(dropped)}); split -> [n, temporal, config] {by}; "
          f"D1-forced {len(forced)}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["candidates", "finalize"])
    a = ap.parse_args()
    candidates() if a.phase == "candidates" else finalize()


if __name__ == "__main__":
    main()
