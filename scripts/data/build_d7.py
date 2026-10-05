"""Build D7 (DeepCTI-Live-X): plan variants, then build rootfs fixtures, host.json, cases, cve_meta, seal.

  python scripts/data/build_d7.py plan    # -> data/d7/curation/plan.json + fetch specs (changelogs, PyPI
                                          #    releases, vendor files) for mirror/fetch steps
  python scripts/data/build_d7.py build   # -> data/d7/{hosts,cases,cve_meta.jsonl,hosts_meta.jsonl},
                                          #    data/sealed/d7_test_labels.jsonl + D7_SHA256

Every version written into a fixture is a real upstream version taken from a mirrored list (Launchpad
publication history, PyPI JSON, Maven Central metadata, Apache/Jenkins/Roundcube/GitLab release lists).
Labels come from label_d7.py (shared comparator src/deepcti/core/versions.py).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import random
import re
import shutil
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml
from debian.debian_support import Version
from packaging.version import InvalidVersion
from packaging.version import Version as PepVersion

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_d1 as B1  # noqa: E402  (D1 helpers: dpkg status stanzas, default configs, D1 config writers)
import d7_catalog as CAT  # noqa: E402
from common import sha256_file, src_of, write_jsonl  # noqa: E402
from d7common import (  # noqa: E402
    CUR,
    D7,
    DATA,
    HOSTS,
    SEED,
    SNAP_DATE,
    UBUNTU_NUM,
    UBUNTU_RELEASES,
    V,
    base_packages,
    base_sources,
    load_json,
    mirror,
    nvd_record,
    osv_records,
    osv_ranges,
    ubuntu_packages,
)
from label_d7 import case_ranges, label_host, load_preconditions_v3  # noqa: E402
from select_d7 import lp_versions, stable_hash  # noqa: E402

PROVENANCE = {
    "deb-ubuntu": f"ubuntu-cve-tracker@{SNAP_DATE} + dpkg version semantics (deepcti.core.versions)",
    "pypi": f"OSV PyPI export@{SNAP_DATE} (GHSA primary) + PEP 440 (deepcti.core.versions)",
    "maven": f"OSV Maven export@{SNAP_DATE} (GHSA primary) + Maven ComparableVersion (deepcti.core.versions)",
    "vendor": f"curated vendor ranges (data/d7/curation/vendor_ranges.yaml)@{SNAP_DATE} + deepcti.core.versions",
}
EXPECTED = {
    "V1": ("not_affected", "component_not_present"),
    "V2": ("affected", None),
    "V3": ("fixed", None),
    "V4": ("fixed", None),
    "V5": ("not_affected", "requires_configuration"),
    "V6": ("not_affected", "component_not_present"),
    "V7": ("affected", None),
    "V8": ("affected", None),
}
OSV_ECO = {"pypi": "PyPI", "maven": "Maven"}
VENDOR_CPE = {"tomcat": {"tomcat"}, "httpd": {"http_server"}, "jenkins": {"jenkins"}, "roundcube": {"webmail"},
              "gitlab": {"gitlab"}}
PYVER = {"jammy": ("3.10", "3.10.12"), "noble": ("3.12", "3.12.3")}

# ---------------------------------------------------------------------------------- deb-ubuntu catalog
UB_BINARIES = {
    **B1.BINARIES,
    "nginx": ["nginx", "nginx-core", "nginx-common"],
    "unbound": ["unbound", "libunbound8"],
    "dnsmasq": ["dnsmasq-base", "dnsmasq"],
    "rsync": ["rsync"],
    "squid": ["squid", "squid-common"],
    "haproxy": ["haproxy"],
    "memcached": ["memcached"],
    "vim": ["vim", "vim-common", "vim-runtime"],
    "postgresql-14": ["postgresql-14", "postgresql-client-14"],
    "postgresql-16": ["postgresql-16", "postgresql-client-16"],
    "redis": ["redis-server", "redis-tools"],
    "python3.10": ["python3.10", "python3.10-minimal", "libpython3.10-minimal", "libpython3.10-stdlib"],
    "python3.12": ["python3.12", "python3.12-minimal", "libpython3.12-minimal", "libpython3.12-stdlib"],
    "perl": ["perl", "perl-base", "perl-modules-5.34", "perl-modules-5.38", "libperl5.34", "libperl5.38"],
    "glibc": ["libc6", "libc-bin"],
}
UB_DECOYS = {
    **B1.DECOYS,
    "unbound": ["ldnsutils"],
    "dnsmasq": ["dns-root-data"],
    "rsync": ["librsync2"],
    "squid": ["squid-langpack"],
    "memcached": ["libmemcached11"],
    "vim": ["neovim"],
    "postgresql-14": ["postgresql-common"],
    "redis": ["python3-redis"],
    "python3.10": ["python3-pip"],
    "python3.12": ["python3-pip"],
    "sudo": ["doas", "opendoas"],
}
UB_CPE = {
    **B1.CPE_PRODUCTS,
    "unbound": {"unbound"},
    "dnsmasq": {"dnsmasq"},
    "rsync": {"rsync"},
    "squid": {"squid"},
    "haproxy": {"haproxy"},
    "memcached": {"memcached"},
    "vim": {"vim"},
    "postgresql-14": {"postgresql"},
    "postgresql-16": {"postgresql"},
    "redis": {"redis"},
    "python3.10": {"python", "cpython"},
    "python3.12": {"python", "cpython"},
}
UB_FAMILY = {
    "openssh": "ssh", "openssl": "crypto_tls", "gnutls28": "crypto_tls", "apache2": "web_server",
    "nginx": "web_server", "bind9": "dns", "unbound": "dns", "dnsmasq": "dns", "exim4": "mail",
    "samba": "file_sharing", "rsync": "file_sharing", "sudo": "privesc", "squid": "proxy", "haproxy": "proxy",
    "memcached": "database", "redis": "database", "postgresql-14": "database", "postgresql-16": "database",
    "python3.10": "interpreter", "python3.12": "interpreter", "perl": "interpreter", "vim": "library",
}
# services for Ubuntu binaries: (name, unit, cmd, config files, banner template using upstream/full version)
UB_SERVICES = {
    "openssh-server": ("ssh", "ssh.service", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
                       ["etc/ssh/sshd_config"], "SSH-2.0-OpenSSH_{up} Ubuntu-{rev}"),
    "apache2": ("apache2", "apache2.service", "/usr/sbin/apache2 -k start",
                ["etc/apache2/apache2.conf", "etc/apache2/ports.conf"], "Apache/{up} (Ubuntu)"),
    "nginx": ("nginx", "nginx.service", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;",
              ["etc/nginx/nginx.conf"], "nginx/{up} (Ubuntu)"),
    "nginx-core": ("nginx", "nginx.service", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;",
                   ["etc/nginx/nginx.conf"], "nginx/{up} (Ubuntu)"),
    "nginx-extras": ("nginx", "nginx.service", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;",
                     ["etc/nginx/nginx.conf"], "nginx/{up} (Ubuntu)"),
    "bind9": ("named", "named.service", "/usr/sbin/named -f -u bind",
              ["etc/bind/named.conf", "etc/bind/named.conf.options"], "{full}-Ubuntu"),
    "exim4-daemon-light": ("exim4", "exim4.service", "/usr/sbin/exim4 -bd -q30m",
                           ["etc/exim4/update-exim4.conf.conf"], "ESMTP Exim {up} Ubuntu"),
    "samba": ("smbd", "smbd.service", "/usr/sbin/smbd --foreground --no-process-group", ["etc/samba/smb.conf"], ""),
    "unbound": ("unbound", "unbound.service", "/usr/sbin/unbound -d -p", ["etc/unbound/unbound.conf"], "unbound {up}"),
    "dnsmasq": ("dnsmasq", "dnsmasq.service", "/usr/sbin/dnsmasq -x /run/dnsmasq/dnsmasq.pid -u dnsmasq",
                [], "dnsmasq-{up}"),
    "rsync": ("rsync", "rsync.service", "/usr/bin/rsync --daemon --no-detach", [], "@RSYNCD: 31.0"),
    "squid": ("squid", "squid.service", "/usr/sbin/squid --foreground -sYC", ["etc/squid/squid.conf"], "squid/{up}"),
    "haproxy": ("haproxy", "haproxy.service", "/usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg",
                ["etc/haproxy/haproxy.cfg"], ""),
    "memcached": ("memcached", "memcached.service", "/usr/bin/memcached -m 64 -p 11211 -u memcache -l 127.0.0.1",
                  [], "VERSION {up}"),
    "redis-server": ("redis", "redis-server.service", "/usr/bin/redis-server 127.0.0.1:6379", [], ""),
    "postgresql-14": ("postgresql", "postgresql@14-main.service", "/usr/lib/postgresql/14/bin/postgres -D "
                      "/var/lib/postgresql/14/main", [], ""),
    "postgresql-16": ("postgresql", "postgresql@16-main.service", "/usr/lib/postgresql/16/bin/postgres -D "
                      "/var/lib/postgresql/16/main", [], ""),
}


# ------------------------------------------------------------------------------------------- helpers
def rng_for(*parts) -> random.Random:
    return random.Random("|".join(str(p) for p in (SEED, *parts)))


def base_for(cve: str, variant: str) -> str:
    return UBUNTU_RELEASES[int(stable_hash(str(SEED), "base", cve, variant), 16) % 2]


def host_ids(case_id: str, short: str) -> tuple[str, str]:
    h = hashlib.sha1(f"{SEED}|{case_id}".encode()).hexdigest()
    return f"h7_{h[:12]}", f"srv-{short}-{h[12:18]}"


_PRE_RE = re.compile(r"(?i)(a\d|b\d|rc\d*|alpha|beta|dev|-m\d|\.m\d|snapshot|-ea|preview|cr\d|\.rc|-rc|milestone)")


def is_final(eco: str, v: str) -> bool:
    if eco == "pypi":
        try:
            pv = PepVersion(v)
        except InvalidVersion:
            return False
        return not (pv.is_prerelease or pv.is_devrelease)
    return not _PRE_RE.search(v)


def pypi_versions(name: str) -> list[str]:
    j = load_json(mirror("pypi") / "projects" / f"{name.lower()}.json")
    out = []
    for v, files in j.get("releases", {}).items():
        if files and not all(f.get("yanked") for f in files) and is_final("pypi", v):
            out.append(v)
    return sorted(out, key=lambda v: V.parse("pypi", v))


def pypi_upload_date(name: str, v: str) -> str:
    j = load_json(mirror("pypi") / "projects" / f"{name.lower()}.json")
    files = j.get("releases", {}).get(v) or []
    return min((f.get("upload_time", "")[:10] for f in files), default="")


def maven_versions(ga: str) -> list[str]:
    g, a = ga.split(":")
    txt = (mirror("maven_central") / "metadata" / g / f"{a}.xml").read_text()
    vs = re.findall(r"<version>([^<]+)</version>", txt)
    return sorted({v for v in vs if is_final("maven", v)}, key=lambda v: V.parse("maven", v))


def vendor_versions(product: str) -> list[str]:
    raw = mirror("vendor_files") / "raw" / "lists"
    vs: set[str] = set()
    if product == "tomcat":
        for m in (7, 8, 9, 10, 11):
            vs |= set(re.findall(r'href="v(\d+\.\d+\.\d+)/"', (raw / f"tomcat-{m}.html").read_text()))
    elif product == "httpd":
        vs = set(re.findall(r'href="httpd-(2\.4\.\d+)\.tar\.(?:gz|bz2)"', (raw / "httpd.html").read_text()))
    elif product == "jenkins":
        vs = set(re.findall(r"<version>(\d+\.\d+(?:\.\d+)?)</version>",
                            (raw / "jenkins-war-maven-metadata.xml").read_text()))
    elif product == "roundcube":
        for i in (1, 2, 3):
            vs |= {t["name"].lstrip("v") for t in load_json(raw / f"roundcube_tags_{i}.json")
                   if re.fullmatch(r"v?\d+\.\d+\.\d+", t["name"])}
    elif product == "gitlab":
        for f in raw.glob("gitlab_tags_v*.json"):
            vs |= {m.group(1) for t in load_json(f) if (m := re.fullmatch(r"v(\d+\.\d+\.\d+)-ee", t["name"]))}
    return sorted(vs, key=lambda v: V.parse("vendor", v))


def versions_for(eco: str, comp: str) -> list[str]:
    return {"pypi": pypi_versions, "maven": maven_versions, "vendor": vendor_versions}[eco](comp)


# ------------------------------------------------------------------------------------------ cve ranges
def lang_ranges(eco: str, cve: str, comp: str) -> tuple[list[dict], list[list[dict]], list[str]]:
    """(primary ranges, alternative record ranges, osv ids). Primary = GHSA record if any."""
    recs = osv_records(OSV_ECO[eco], cve)
    recs = sorted(recs, key=lambda r: (not r["id"].startswith("GHSA"), r["id"]))
    per = [(r["id"], osv_ranges(r, OSV_ECO[eco], comp)) for r in recs]
    per = [(i, rg) for i, rg in per if rg]
    if not per:
        return [], [], [r["id"] for r in recs]
    return per[0][1], [rg for _, rg in per[1:]], [r["id"] for r in recs]


def vendor_ranges() -> dict:
    return yaml.safe_load((CUR / "vendor_ranges.yaml").read_text())


def full_semantics(eco: str, v: str, ranges: list[dict]) -> bool:
    """Independent in-range check that also honours `last_affected` (used to guard the shared classify)."""
    for r in ranges:
        lo = r.get("introduced")
        if lo not in (None, "", "0") and V.compare(eco, v, lo) < 0:
            continue
        if r.get("fixed"):
            if V.compare(eco, v, r["fixed"]) < 0:
                return True
        elif r.get("last_affected"):
            if V.compare(eco, v, r["last_affected"]) <= 0:
                return True
        else:
            return True
    return False


def consistent(eco: str, v: str, ranges: list[dict], alts: list[list[dict]]) -> bool:
    ref = V.classify(eco, v, ranges)
    if ref[0] != full_semantics(eco, v, ranges):
        return False
    return all(V.classify(eco, v, a)[0] == ref[0] for a in alts)


# ---------------------------------------------------------------------------------------- planning
def plan_lang(sel: dict, ranges: list[dict], alts: list[list[dict]], versions: list[str], pre: dict | None
              ) -> tuple[list[dict], list[str]]:
    eco, comp, cve = sel["ecosystem"], sel["component"], sel["cve"]
    notes = []
    ok = [v for v in versions if consistent(eco, v, ranges, alts)]
    vuln = [v for v in ok if V.classify(eco, v, ranges)[0]]
    fixedv = [v for v in ok if V.classify(eco, v, ranges)[1]]
    if not vuln:
        return [], [f"{cve}: no consistent vulnerable version"]
    fixes = sorted([r["fixed"] for r in ranges if r.get("fixed")], key=lambda x: V.parse(eco, x))
    top_fix = fixes[-1] if fixes else None
    rng = rng_for(cve, "versions")
    plans = []

    # V2/V8: a vulnerable version in the top branch (just below the highest fix; for open ranges the newest)
    def branch_of(v):
        for i, r in enumerate(ranges):
            if V.classify(eco, v, [r])[0]:
                return i
        return None

    top_br = branch_of(max(vuln, key=lambda v: V.parse(eco, v)))
    top_vuln = [v for v in vuln if branch_of(v) == top_br]
    v2 = rng.choice(top_vuln[-3:])
    if pre and pre.get("applies_to_versions"):
        inapp = [v for v in vuln if any(V.classify(eco, v, [a])[0] for a in pre["applies_to_versions"])]
        if v2 not in inapp and inapp:
            v2 = inapp[-1]
    main_var = "V8" if eco == "vendor" else "V2"
    plans.append({"variant": main_var, "version": v2})
    # second vulnerable instance: newest release of another vulnerable branch when one exists, otherwise an
    # older release of the same branch (at least 3 releases below the first pick)
    other = [v for v in vuln if branch_of(v) not in (top_br, None)]
    if other:
        ob = branch_of(other[-1])
        plans.append({"variant": main_var, "version": max([v for v in other if branch_of(v) == ob],
                                                          key=lambda v: V.parse(eco, v)), "tag": "b2"})
    else:
        older = [v for v in top_vuln if V.compare(eco, v, v2) < 0]
        if len(older) >= 3:
            plans.append({"variant": main_var, "version": older[: len(older) - 2][rng.randrange(
                max(1, len(older) - 2))], "tag": "b2"})
    # V3: the top fix (or the first fixed release above it)
    if top_fix:
        above = [v for v in fixedv if V.compare(eco, v, top_fix) >= 0]
        if above:
            plans.append({"variant": "V3", "version": above[0]})
        # V4: fix on a lower maintenance branch (numerically below the highest fix)
        for f in reversed(fixes[:-1]):
            cand = [v for v in fixedv if V.compare(eco, v, f) >= 0 and V.compare(eco, v, top_fix) < 0]
            if cand:
                plans.append({"variant": "V4", "version": cand[0]})
                break
    else:
        notes.append(f"{cve}: no fix -> no V3/V4")
    if pre:
        plans.append({"variant": "V5", "version": v2})
    plans.append({"variant": "V1", "version": None})
    decoy = (CAT.PYPI.get(comp, {}).get("decoy") if eco == "pypi" else
             CAT.MAVEN.get(comp, {}).get("decoy") if eco == "maven" else CAT.VENDOR[comp]["decoy"])
    if decoy:
        affected_pkgs = {a["package"]["name"].lower() for r in osv_records(OSV_ECO.get(eco, "Maven"), cve)
                         for a in r.get("affected", [])} if eco != "vendor" else set()
        if decoy.lower() in affected_pkgs:
            notes.append(f"{cve}: decoy {decoy} is itself in the OSV record; no V6")
        else:
            plans.append({"variant": "V6", "version": None, "decoy": decoy})
    if eco == "maven":
        plans.append({"variant": "V7", "version": v2, "vendored": "fatjar"})
    if eco == "pypi" and CAT.PYPI[comp]["vendorable"]:
        pv = pip_vendoring(comp, ranges, alts)
        if pv:
            plans.append({"variant": "V7", "version": pv[1], "vendored": "pip", "pip_version": pv[0]})
        else:
            notes.append(f"{cve}: no pip release vendors an in-range {comp}")
    return plans, notes


def pip_vendor_txt(pipver: str) -> str:
    return (mirror("vendor_files") / "raw" / "pip" / pipver / "vendor.txt").read_text()


def pip_vendoring(comp: str, ranges, alts) -> tuple[str, str] | None:
    for pipver in ("24.0", "23.0.1", "22.0.2", "24.2", "25.0.1"):
        m = re.search(rf"^\s*{re.escape(comp)}==(\S+)", pip_vendor_txt(pipver), re.MULTILINE | re.IGNORECASE)
        if m and consistent("pypi", m.group(1), ranges, alts) and V.classify("pypi", m.group(1), ranges)[0]:
            return pipver, m.group(1)
    return None


def tracker_status(cve: str, src: str) -> dict:
    j = load_json(mirror("ubuntu_cve_tracker") / "cves" / f"{cve}.json")
    out = {}
    for p in j.get("packages", []):
        if p["name"] != src:
            continue
        for s in p["statuses"]:
            if s["release_codename"] in UBUNTU_RELEASES:
                st = s["status"]
                fv = s.get("description") if st == "released" else None
                out[s["release_codename"]] = {"status": st, "fixed_version": fv or None,
                                              "note": s.get("description") if st != "released" else None}
    return out


def ub_pick_binaries(src: str, rel: str, cve: str) -> list[str]:
    pk = ubuntu_packages(rel)
    if src == "nginx":
        mp4 = cve in ("CVE-2024-7347", "CVE-2022-41741")
        names = (["nginx-extras", "nginx-common"] if rel == "jammy" else ["nginx", "nginx-common"]) if mp4 else (
            ["nginx-core", "nginx-common"] if rel == "jammy" else ["nginx", "nginx-common"])
        return [b for b in names if b in pk]
    names = [b for b in UB_BINARIES.get(src, []) if b in pk and src_of(pk[b])[0] == src]
    if not names:
        names = sorted(b for b, p in pk.items() if src_of(p)[0] == src
                       and not re.search(r"-(dev|doc|dbg|dbgsym|tests?)$", b))[:2]
    return names


def ub_nvd_ranges(cve: str, src: str) -> list[dict]:
    saved = B1.CPE_PRODUCTS
    try:
        B1.CPE_PRODUCTS = UB_CPE
        return B1.nvd_ranges(nvd_record(cve), src)
    finally:
        B1.CPE_PRODUCTS = saved


def plan_deb(sel: dict, pre: dict | None) -> tuple[list[dict], list[str], dict]:
    cve, src = sel["cve"], sel["src_package"]
    st = tracker_status(cve, src)
    plans, notes = [], []
    nranges = ub_nvd_ranges(cve, src)
    v2_rels = []
    for rel in UBUNTU_RELEASES:
        x = st.get(rel)
        bins = ub_pick_binaries(src, rel, cve)
        if not x or not bins:
            notes.append(f"{cve}/{rel}: no tracker entry or binaries")
            continue
        shipped = lp_versions(src, rel)
        cur = ubuntu_packages(rel)[bins[0]]
        cur_src_ver = src_of(cur)[1]
        if x["status"] == "released" and x["fixed_version"]:
            fv = x["fixed_version"]
            lower = [v for v in shipped if Version(v) < Version(fv)]
            if lower:
                plans.append({"release": rel, "variant": "V2", "version": lower[-1], "version_source": "launchpad"})
                v2_rels.append(rel)
            else:
                notes.append(f"{cve}/{rel}: fixed before any shipped version ({fv})")
            if Version(cur_src_ver) >= Version(fv):
                inside = B1.in_nvd_range(B1.norm_upstream(cur_src_ver), nranges)
                plans.append({"release": rel, "variant": "V4" if inside else "V3", "version": cur_src_ver,
                              "version_source": "archive-current", "nvd_upstream_in_range": inside})
        elif x["status"] in ("needed", "deferred", "pending"):
            plans.append({"release": rel, "variant": "V2", "version": cur_src_ver, "version_source": "archive-current"})
            v2_rels.append(rel)
        else:
            notes.append(f"{cve}/{rel}: status {x['status']}")
    if pre:
        for rel in v2_rels:
            vv = next(p["version"] for p in plans if p["release"] == rel and p["variant"] == "V2")
            plans.append({"release": rel, "variant": "V5", "version": vv, "version_source": "same-as-V2"})
    absent = [r for r in UBUNTU_RELEASES if src not in base_sources(r) and ub_pick_binaries(src, r, cve)]
    rng = rng_for(cve, "deb")
    if absent:
        r1 = rng.choice(absent)
        plans.append({"release": r1, "variant": "V1", "version": None})
        dec = []
        for r in absent:
            pk = ubuntu_packages(r)
            d = next((d for d in UB_DECOYS.get(src, []) if d in pk and src_of(pk[d])[0] != src), None)
            if d:
                dec.append((r, d))
        if dec:
            others = [x for x in dec if x[0] != r1] or dec
            r6, d = rng.choice(others)
            plans.append({"release": r6, "variant": "V6", "version": None, "decoy": d})
    else:
        notes.append(f"{cve}: {src} in both base images -> no V1/V6")
    return plans, notes, {"tracker": st, "nvd_ranges": nranges}


def plan_all() -> None:
    sel = load_json(D7 / "selected_cves.json")
    pre = load_preconditions_v3()
    vr = vendor_ranges()
    plan, notes = [], []
    clog_spec, pypi_spec, vendor_needed = set(), set(), set()
    for s in sel:
        cve, eco = s["cve"], s["ecosystem"]
        p = pre.get(cve)
        if eco == "deb-ubuntu":
            plans, nts, extra = plan_deb(s, p)
            for x in plans:
                if x["version"]:
                    comp = ubuntu_packages(x["release"])[ub_pick_binaries(s["src_package"], x["release"], cve)[0]]
                    clog_spec.add((s["src_package"], x["version"], comp["_component"]))
            meta = {"tracker": extra["tracker"], "nvd_ranges": extra["nvd_ranges"]}
        else:
            if eco == "vendor":
                ranges, alts, ids = vr[cve]["ranges"], [], []
            else:
                ranges, alts, ids = lang_ranges(eco, cve, s["component"])
            if not ranges:
                notes.append(f"{cve}: no ranges for {s['component']}")
                continue
            plans, nts = plan_lang(s, ranges, alts, versions_for(eco, s["component"]), p)
            meta = {"ranges": ranges, "alt_ranges": alts, "osv_ids": ids}
            for x in plans:
                if eco == "pypi":
                    if x["version"] and x.get("vendored") != "pip":
                        pypi_spec.add((s["component"], x["version"]))
                if eco == "vendor" and x["version"]:
                    vendor_needed.add((s["component"], x["version"]))
            if eco == "pypi":
                for d in [CAT.PYPI[s["component"]]["decoy"]] if CAT.PYPI[s["component"]]["decoy"] else []:
                    pypi_spec.add((d, pypi_versions(d)[-1]))
        notes += nts
        plan.append({"sel": s, "plans": plans, **meta})
    for n, v in CAT.PYPI_FILLERS:
        pypi_spec.add((n, v))
    for pv in ("24.0", "23.0.1", "22.0.2", "24.2", "25.0.1"):
        pypi_spec.add(("pip", pv))
    (CUR / "plan.json").write_text(json.dumps(plan, indent=1))
    (CUR / "plan_notes.json").write_text(json.dumps(notes, indent=1))
    (CUR / "spec_changelogs.json").write_text(json.dumps(sorted(list(x) for x in clog_spec)))
    (CUR / "spec_pypi_releases.json").write_text(json.dumps(sorted(list(x) for x in pypi_spec)))
    (CUR / "spec_vendor_versions.json").write_text(json.dumps(sorted(list(x) for x in vendor_needed)))
    n = sum(len(p["plans"]) for p in plan)
    by = {}
    for p in plan:
        for x in p["plans"]:
            by[x["variant"]] = by.get(x["variant"], 0) + 1
    print(f"planned {n} cases over {len(plan)} CVEs {dict(sorted(by.items()))}; notes={len(notes)}")


# ================================================================================== fixture writers
def copy_base(rootfs: Path, rel: str) -> None:
    if rootfs.exists():
        shutil.rmtree(rootfs)
    shutil.copytree(DATA / "base_images" / rel / "rootfs", rootfs, symlinks=True)


def write_file(path: Path, text: str | bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        path.unlink()
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text)
    if mode is not None:
        path.chmod(mode)


def systemd_unit(rootfs: Path, unit: str, desc: str, execstart: str, user: str, workdir: str,
                 env: list[str] | None = None) -> None:
    env_lines = "".join(f"Environment={e}\n" for e in (env or []))
    write_file(rootfs / "etc/systemd/system" / unit,
               f"[Unit]\nDescription={desc}\nAfter=network.target\n\n[Service]\nType=simple\nUser={user}\n"
               f"WorkingDirectory=/{workdir}\n{env_lines}ExecStart={execstart}\nRestart=on-failure\n\n"
               f"[Install]\nWantedBy=multi-user.target\n")
    link = rootfs / "etc/systemd/system/multi-user.target.wants" / unit
    link.parent.mkdir(parents=True, exist_ok=True)
    if not link.is_symlink():
        link.symlink_to(f"/etc/systemd/system/{unit}")


# ---------------------------------------------------------------------------------------------- deb
def ub_changelog(src: str, version: str, rel: str, maint: str) -> tuple[str, bool]:
    nv = version.split(":", 1)[1] if ":" in version else version
    p = mirror("ubuntu_changelogs") / "raw" / src / f"{nv}_changelog"
    if p.exists() and not p.read_bytes().startswith(b'{"_status"'):
        from debian.changelog import Changelog

        try:
            blk = next(iter(Changelog(p.read_text(errors="replace"), strict=False)))
            if str(blk.version) == version:
                lines = [ln.rstrip() for ln in blk.changes() if ln.strip()]
                bullets = [b if len(b) <= 160 else b[:157] + "..." for b in lines[:8]] or ["  * Security update."]
                head = f"{src} ({version}) {blk.distributions}; urgency={blk.urgency}"
                return f"{head}\n\n" + "\n".join(bullets) + f"\n\n -- {blk.author}  {blk.date}\n", False
        except Exception:  # noqa: BLE001 - malformed changelog -> synthesized header below
            pass
    dist = f"{rel}-security" if "ubuntu0" in version or "build" in version else rel
    return (f"{src} ({version}) {dist}; urgency=medium\n\n  * Security update.\n\n -- {maint}  "
            f"Mon, 05 Jan 2026 00:00:00 +0000\n"), True


def ub_write_status(rootfs: Path, rel: str, src: str | None, version: str | None, bins: list[str],
                    decoy: str | None) -> None:
    pk = ubuntu_packages(rel)
    B1.write_status(rootfs, rel, pk, src, version, bins, decoy)


def ub_install_configs(rootfs: Path, rel: str, bins: list[str]) -> None:
    b = list(bins)
    if any(x.startswith("nginx") for x in b):
        b.append("nginx-common")
    B1.install_configs(rootfs, rel, b)


def ub_apply_precondition(rootfs: Path, cve: str, enabled: bool) -> None:
    etc = rootfs / "etc"
    if cve == "CVE-2023-38408":
        B1._sub_line(etc / "ssh/ssh_config", "Host *\n", f"Host *\n    ForwardAgent {'yes' if enabled else 'no'}\n")
    elif cve == "CVE-2025-49812":
        for ext in ("load", "conf"):
            B1.symlink(f"../mods-available/ssl.{ext}", etc / f"apache2/mods-enabled/ssl.{ext}")
        B1.symlink("../mods-available/socache_shmcb.load", etc / "apache2/mods-enabled/socache_shmcb.load")
        write_file(etc / "apache2/sites-available/010-tls-upgrade.conf",
                   "# Legacy clients negotiate TLS via RFC 2817 Upgrade on the plain-HTTP port\n"
                   "<VirtualHost *:80>\n\tServerName intranet.corp.example\n\tDocumentRoot /var/www/intranet\n"
                   f"\tSSLEngine {'optional' if enabled else 'off'}\n"
                   "\tSSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem\n"
                   "\tSSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key\n</VirtualHost>\n")
        B1.symlink("../sites-available/010-tls-upgrade.conf", etc / "apache2/sites-enabled/010-tls-upgrade.conf")
    elif cve == "CVE-2025-49630":
        for m in ("proxy.load", "proxy.conf", "proxy_http2.load", "http2.load", "http2.conf"):
            if (etc / f"apache2/mods-available/{m}").exists():
                B1.symlink(f"../mods-available/{m}", etc / f"apache2/mods-enabled/{m}")
        write_file(etc / "apache2/sites-available/020-h2-backend.conf",
                   "<VirtualHost *:80>\n\tServerName api.corp.example\n"
                   f"\tProxyPreserveHost {'On' if enabled else 'Off'}\n"
                   '\tProxyPass "/api/" "h2c://10.20.0.15:8080/"\n'
                   '\tProxyPassReverse "/api/" "h2c://10.20.0.15:8080/"\n</VirtualHost>\n')
        B1.symlink("../sites-available/020-h2-backend.conf", etc / "apache2/sites-enabled/020-h2-backend.conf")
    elif cve in ("CVE-2024-7347", "CVE-2022-41741"):
        write_file(etc / "nginx/sites-available/media",
                   "server {\n\tlisten 8081;\n\tserver_name media.corp.example;\n\troot /srv/media;\n\n"
                   "\tlocation /videos/ {\n" + ("\t\tmp4;\n\t\tmp4_buffer_size 1m;\n" if enabled else
                                                "\t\t# progressive download served as plain files\n")
                   + "\t}\n}\n")
        B1.symlink("/etc/nginx/sites-available/media", etc / "nginx/sites-enabled/media")
    elif cve == "CVE-2025-32462":
        write_file(etc / "sudoers.d/90-shared-rules",
                   "# Shared sudoers fragment distributed to all build hosts by config management\n"
                   + ("deploy  buildhost01 = (root) ALL\n" if enabled else
                      "deploy  ALL = (root) /usr/bin/systemctl restart app\n"), mode=0o440)
    else:
        B1.apply_precondition(rootfs, cve, enabled)


def deb_services(rootfs: Path, inst_bins: list[str], version: str | None, pre: dict | None, rng) -> tuple[dict, list]:
    services, procs = {}, []
    pid = 300 + rng.randrange(400)
    for b in inst_bins:
        if b in UB_SERVICES:
            name, unit, cmd, cfgs, banner_t = UB_SERVICES[b]
            if name in services:
                continue
            cfgs = list(cfgs)
            if pre and pre.get("service") == name and pre["file"] not in cfgs:
                cfgs.append(pre["file"])
            v = Version(version)
            up = v.upstream_version
            rev = v.debian_revision or ""
            services[name] = {
                "unit": unit, "active": True, "package": b,
                "config_files": [c for c in cfgs if (rootfs / c).exists() or (rootfs / c).is_symlink()],
                "banner": banner_t.format(up=up, rev=rev, full=version.split(":", 1)[-1]) if banner_t else "",
                "loaded_version": version,
            }
            pid += rng.randrange(5, 60)
            procs.append({"pid": pid, "user": "root", "cmd": cmd, "unit": unit})
    return services, procs


# --------------------------------------------------------------------------------------------- pypi
def pypi_release_info(name: str, version: str) -> dict:
    p = mirror("pypi") / "releases" / name.lower() / f"{version}.json"
    if p.exists():
        j = load_json(p)
        if not j.get("_status"):
            return j.get("info", {})
    return {}


def dist_info_name(name: str, info: dict) -> str:
    return re.sub(r"[-_.]+", "_", info.get("name") or name)


def write_dist_info(site: Path, name: str, version: str) -> Path:
    info = pypi_release_info(name, version)
    dn = dist_info_name(name, info)
    d = site / f"{dn}-{version}.dist-info"
    lines = ["Metadata-Version: 2.1", f"Name: {info.get('name') or name}", f"Version: {version}"]
    for k, key in (("Summary", "summary"), ("Home-page", "home_page"), ("Author", "author"),
                   ("Author-email", "author_email"), ("License", "license"), ("Requires-Python", "requires_python")):
        val = (info.get(key) or "").strip().splitlines()[0] if (info.get(key) or "").strip() else ""
        if val and len(val) < 200:
            lines.append(f"{k}: {val}")
    for req in (info.get("requires_dist") or [])[:12]:
        lines.append(f"Requires-Dist: {req}")
    write_file(d / "METADATA", "\n".join(lines) + "\n\n")
    write_file(d / "INSTALLER", "pip\n")
    write_file(d / "WHEEL", "Wheel-Version: 1.0\nGenerator: bdist_wheel (0.42.0)\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    mod = re.sub(r"[-.]", "_", name.lower())
    mod = {"pyyaml": "yaml", "pillow": "PIL", "python_multipart": "multipart", "pyjwt": "jwt",
           "python_dateutil": "dateutil", "jupyter_server": "jupyter_server", "django_environ": "environ",
           "ruamel.yaml": "ruamel", "pycryptodome": "Crypto", "types_urllib3": "urllib3-stubs",
           "types_requests": "requests-stubs"}.get(mod, mod)
    write_file(d / "top_level.txt", mod + "\n")
    pkg = site / mod
    if not (pkg / "__init__.py").exists():
        write_file(pkg / "__init__.py", f'"""{info.get("summary") or name}"""\n')
    write_file(d / "RECORD", f"{mod}/__init__.py,,\n{d.name}/METADATA,,\n{d.name}/INSTALLER,,\n"
                             f"{d.name}/WHEEL,,\n{d.name}/top_level.txt,,\n{d.name}/RECORD,,\n")
    return d


APP_PY = {
    "werkzeug": "from flask import Flask\n\napp = Flask(__name__)\n\n\n@app.route('/')\ndef index():\n    return 'portal'\n",
    "aiohttp": ("import os\nfrom aiohttp import web\n\nSTATIC_DIR = os.path.join(os.path.dirname(__file__), 'static')\n\n"
                "async def health(request):\n    return web.json_response({'ok': True})\n\napp = web.Application()\n"
                "app.router.add_get('/health', health)\napp.router.add_routes([\n    {STATIC}\n])\n\n"
                "if __name__ == '__main__':\n    web.run_app(app, port=8080)\n"),
}


def build_pypi_app(rootfs: Path, sel: dict, plan: dict, rel: str, app: str, pre: dict | None,
                   enabled: bool) -> tuple[list[dict], dict, list]:
    comp, var = sel["component"], plan["variant"]
    pyshort, pyfull = PYVER[rel]
    appdir = Path("opt") / app
    venv = appdir / "venv"
    site = rootfs / venv / f"lib/python{pyshort}/site-packages"
    write_file(rootfs / venv / "pyvenv.cfg", f"home = /usr/bin\ninclude-system-site-packages = false\n"
                                               f"version = {pyfull}\nexecutable = /usr/bin/python{pyshort}\n"
                                               f"command = /usr/bin/python3 -m venv --without-pip /{venv}\n")
    for exe in ("python", "python3", f"python{pyshort}"):
        lk = rootfs / venv / "bin" / exe
        lk.parent.mkdir(parents=True, exist_ok=True)
        if not lk.is_symlink():
            lk.symlink_to(f"/usr/bin/python{pyshort}")
    apps = []
    for n, v in CAT.PYPI_FILLERS:
        write_dist_info(site, n, v)
    if var in ("V2", "V3", "V4", "V5"):
        d = write_dist_info(site, comp, plan["version"])
        apps.append({"path": str(d.relative_to(rootfs)), "ecosystem": "pypi", "component": comp,
                     "version": plan["version"]})
    elif var == "V6":
        dv = pypi_versions(plan["decoy"])[-1]
        d = write_dist_info(site, plan["decoy"], dv)
        apps.append({"path": str(d.relative_to(rootfs)), "ecosystem": "pypi", "component": plan["decoy"],
                     "version": dv})
    elif var == "V7":
        pipver = plan["pip_version"]
        write_dist_info(site, "pip", pipver)
        vt = pip_vendor_txt(pipver)
        vend = site / "pip/_vendor"
        write_file(vend / "vendor.txt", vt)
        write_file(vend / "__init__.py", '"""pip._vendor is for vendoring dependencies of pip."""\n')
        mod = comp.lower().replace("-", "_")
        write_file(vend / mod / "__init__.py", f'__version__ = "{plan["version"]}"\n')
        apps.append({"path": str((vend / mod).relative_to(rootfs)), "ecosystem": "pypi", "component": comp,
                     "version": plan["version"], "vendored_in": f"pip {pipver}"})
    # application code and config
    if comp == "aiohttp" and pre:
        static = 'web.static("/static", STATIC_DIR, follow_symlinks=True),' if enabled else \
            'web.static("/static", STATIC_DIR),'
        write_file(rootfs / appdir / "app.py", APP_PY["aiohttp"].replace("{STATIC}", static))
    else:
        write_file(rootfs / appdir / "app.py", APP_PY.get(comp, f"# {app}: internal service\n"
                                                              "def application(environ, start_response):\n"
                                                              "    start_response('200 OK', [])\n"
                                                              "    return [b'ok']\n"))
    env = []
    if comp == "werkzeug" and pre:
        write_file(rootfs / appdir / "app.env", f"FLASK_APP=app.py\nFLASK_DEBUG={'1' if enabled else '0'}\n")
        env = [f"FLASK_DEBUG={'1' if enabled else '0'}"]
    if comp == "waitress" and pre:
        write_file(rootfs / appdir / "production.ini",
                   "[app:main]\nuse = egg:shop\n\n[server:main]\nuse = egg:waitress#main\nlisten = 0.0.0.0:6543\n"
                   f"threads = 8\nchannel_request_lookahead = {'5' if enabled else '0'}\n")
    unit = f"{app}.service"
    ver_running = plan["version"] if var in ("V2", "V3", "V4", "V5") else None
    banner_t = CAT.PYPI[comp]["banner"]
    banner = banner_t.format(v=ver_running) if (banner_t and ver_running and "{v}" in banner_t) else (
        banner_t if banner_t and "{v}" not in banner_t else "")
    execstart = {"waitress": f"/{venv}/bin/python -m waitress --listen=0.0.0.0:6543 app:application",
                 "werkzeug": f"/{venv}/bin/python -m flask run --host 0.0.0.0",
                 "aiohttp": f"/{venv}/bin/python /{appdir}/app.py"}.get(comp, f"/{venv}/bin/python /{appdir}/app.py")
    systemd_unit(rootfs, unit, f"{app} (Python {pyshort})", execstart, "svc-" + app[:8], str(appdir), env)
    svc = {app: {"unit": unit, "active": True, "package": None,
                 "config_files": [str(p.relative_to(rootfs)) for p in sorted((rootfs / appdir).glob("*"))
                                  if p.is_file()],
                 "banner": banner, "loaded_version": ver_running}}
    proc = [{"pid": 900 + int(stable_hash(app)[:3], 16) % 500, "user": "svc-" + app[:8], "cmd": execstart,
             "unit": unit}]
    return apps, svc, proc


# -------------------------------------------------------------------------------------------- maven
def jar_bytes(g: str, a: str, v: str, title: str, vendor: str, extra: dict | None = None,
              nested: list[tuple[str, bytes]] | None = None) -> bytes:
    mf = ["Manifest-Version: 1.0", "Created-By: Apache Maven 3.8.6", "Build-Jdk-Spec: 1.8",
          f"Implementation-Title: {title}", f"Implementation-Version: {v}", f"Implementation-Vendor: {vendor}",
          f"Implementation-Vendor-Id: {g}", f"Bundle-SymbolicName: {g}.{a}", f"Bundle-Version: {v}"]
    for k, val in (extra or {}).items():
        mf.append(f"{k}: {val}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/MANIFEST.MF", "\r\n".join(mf) + "\r\n\r\n")
        z.writestr(f"META-INF/maven/{g}/{a}/pom.properties",
                   f"#Created by Apache Maven 3.8.6\nartifactId={a}\ngroupId={g}\nversion={v}\n")
        z.writestr(f"META-INF/maven/{g}/{a}/pom.xml",
                   f'<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
                   f"  <modelVersion>4.0.0</modelVersion>\n  <groupId>{g}</groupId>\n  <artifactId>{a}</artifactId>\n"
                   f"  <version>{v}</version>\n  <name>{title}</name>\n</project>\n")
        for name, data in nested or []:
            zi = zipfile.ZipInfo(name)
            zi.compress_type = zipfile.ZIP_STORED  # Spring Boot requires stored nested jars
            z.writestr(zi, data)
    return buf.getvalue()


def maven_meta(ga: str) -> tuple[str, str]:
    m = CAT.MAVEN.get(ga)
    if m:
        return m["title"], m["vendor"]
    return ga.split(":")[1], ga.split(":")[0]


def write_jar(rootfs: Path, libdir: Path, ga: str, v: str) -> str:
    g, a = ga.split(":")
    t, vend = maven_meta(ga)
    rel = libdir / f"{a}-{v}.jar"
    write_file(rootfs / rel, jar_bytes(g, a, v, t, vend))
    return str(rel)


LOG4J2_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
  <Appenders>
    <Console name="Console" target="SYSTEM_OUT">
      <PatternLayout pattern="{PATTERN}"/>
    </Console>
    <RollingFile name="File" fileName="/var/log/{APP}/app.log" filePattern="/var/log/{APP}/app-%d{{yyyy-MM-dd}}.log.gz">
      <PatternLayout pattern="{PATTERN}"/>
      <Policies><TimeBasedTriggeringPolicy/></Policies>
    </RollingFile>{EXTRA_APPENDER}
  </Appenders>
  <Loggers>
    <Root level="info">
      <AppenderRef ref="Console"/>
      <AppenderRef ref="File"/>{EXTRA_REF}
    </Root>
  </Loggers>
</Configuration>
"""


def maven_config(rootfs: Path, appdir: Path, app: str, sel: dict, pre: dict | None, enabled: bool,
                 jdk_ver: str) -> None:
    cve, comp = sel["cve"], sel["component"]
    conf = rootfs / appdir / "conf"
    default_pat = "%d{ISO8601} %-5p [%t] %c{1.} - %m%n"
    jvm = ["-Xms256m", "-Xmx1g", "-XX:+UseG1GC", f"-Dapp.name={app}"]
    if cve == "CVE-2021-44228" and pre:
        jvm.append(f"-Dlog4j2.formatMsgNoLookups={'false' if enabled else 'true'}")
    write_file(conf / "jvm.options", "\n".join(jvm) + "\n")
    if comp == "org.apache.logging.log4j:log4j-core":
        pat, extra_app, extra_ref = default_pat, "", ""
        if cve in ("CVE-2021-45046", "CVE-2021-45105") and pre:
            pat = ("%d{ISO8601} %-5p [%t] %c{1.} [$${ctx:loginId}] - %m%n" if enabled
                   else "%d{ISO8601} %-5p [%t] %c{1.} [%X{loginId}] - %m%n")
        if cve == "CVE-2021-44832" and pre:
            jndi = "ldap://ldap.corp.example:389/cn=reportdb" if enabled else "java:comp/env/jdbc/ReportDB"
            extra_app = (f'\n    <JDBC name="Audit" tableName="APP_LOG">\n      <DataSource jndiName="{jndi}"/>\n'
                         '      <Column name="EVENT_DATE" isEventTimestamp="true"/>\n'
                         '      <Column name="LEVEL" pattern="%level"/>\n      <Column name="MESSAGE" pattern="%m"/>\n'
                         "    </JDBC>")
            extra_ref = '\n      <AppenderRef ref="Audit"/>'
        write_file(conf / "log4j2.xml", LOG4J2_XML.replace("{PATTERN}", pat).replace("{APP}", app)
                   .replace("{{", "{").replace("}}", "}").replace("{EXTRA_APPENDER}", extra_app)
                   .replace("{EXTRA_REF}", extra_ref))
    if comp == "log4j:log4j":
        lines = ["log4j.rootLogger=INFO, stdout, file", "log4j.appender.stdout=org.apache.log4j.ConsoleAppender",
                 "log4j.appender.stdout.layout=org.apache.log4j.PatternLayout",
                 "log4j.appender.stdout.layout.ConversionPattern=%d %-5p %c - %m%n",
                 "log4j.appender.file=org.apache.log4j.DailyRollingFileAppender",
                 f"log4j.appender.file.File=/var/log/{app}/batch.log",
                 "log4j.appender.file.layout=org.apache.log4j.PatternLayout"]
        if pre and enabled:
            lines[0] = "log4j.rootLogger=INFO, stdout, file, jms"
            lines += ["log4j.appender.jms=org.apache.log4j.net.JMSAppender",
                      "log4j.appender.jms.InitialContextFactoryName=org.apache.activemq.jndi.ActiveMQInitialContextFactory",
                      "log4j.appender.jms.ProviderURL=tcp://mq01.corp.example:61616",
                      "log4j.appender.jms.TopicBindingName=logEvents"]
        write_file(conf / "log4j.properties", "\n".join(lines) + "\n")
    if comp == "org.springframework:spring-beans" and pre:
        write_file(rootfs / appdir / "jre/release",
                   f'IMPLEMENTOR="Eclipse Adoptium"\nJAVA_VERSION="{jdk_ver}"\n'
                   f'JAVA_VERSION_DATE="2022-01-18"\nOS_ARCH="x86_64"\nOS_NAME="Linux"\n')
    if comp == "com.h2database:h2" and pre:
        write_file(rootfs / appdir / "config/application.properties",
                   "server.port=8090\nspring.datasource.url=jdbc:h2:file:/var/lib/admin-console/db\n"
                   "spring.h2.console.enabled=true\nspring.h2.console.path=/h2-console\n"
                   f"spring.h2.console.settings.web-allow-others={'true' if enabled else 'false'}\n")
    if comp == "org.apache.shiro:shiro-core" and pre:
        key = "securityManager.rememberMeManager.cipherKey = 0x3a7c1f9b2e6d4a8c5f0e1d2c3b4a5968"
        write_file(conf / "shiro.ini",
                   "[main]\nsessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager\n"
                   "securityManager.sessionManager = $sessionManager\n"
                   "rememberMeManager = org.apache.shiro.web.mgt.CookieRememberMeManager\n"
                   "securityManager.rememberMeManager = $rememberMeManager\n"
                   + (f"# {key}\n" if enabled else f"{key}\n")
                   + "\n[urls]\n/login = authc\n/** = user\n")
    if comp == "org.apache.struts:struts2-core" and pre:
        write_file(conf / "struts.xml",
                   '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE struts PUBLIC "-//Apache Software Foundation//'
                   'DTD Struts Configuration 2.5//EN" "http://struts.apache.org/dtds/struts-2.5.dtd">\n<struts>\n'
                   f'  <constant name="struts.mapper.alwaysSelectFullNamespace" value="{"true" if enabled else "false"}"/>\n'
                   '  <package name="claims" extends="struts-default">\n'
                   '    <action name="submit" class="com.corp.claims.SubmitAction">\n'
                   '      <result type="redirectAction">\n        <param name="actionName">status</param>\n'
                   "      </result>\n    </action>\n  </package>\n</struts>\n")
    if comp == "org.postgresql:postgresql" and pre:
        write_file(rootfs / appdir / "config/application.properties",
                   "server.port=8085\nspring.datasource.url=jdbc:postgresql://db01:5432/ledger?"
                   f"preferQueryMode={'simple' if enabled else 'extended'}\n"
                   "spring.datasource.username=ledger\nspring.datasource.password=${LEDGER_DB_PASSWORD}\n")
    if comp == "ch.qos.logback:logback-classic" and pre:
        recv = ('  <receiver class="ch.qos.logback.classic.net.server.ServerSocketReceiver">\n'
                "    <port>6000</port>\n  </receiver>\n") if enabled else ""
        write_file(conf / "logback.xml",
                   "<configuration>\n" + recv + '  <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">\n'
                   "    <encoder><pattern>%d %-5level %logger{36} - %msg%n</pattern></encoder>\n  </appender>\n"
                   '  <root level="INFO"><appender-ref ref="STDOUT"/></root>\n</configuration>\n')


def build_maven_app(rootfs: Path, sel: dict, plan: dict, app: str, pre: dict | None, enabled: bool
                    ) -> tuple[list[dict], dict, list]:
    comp, var = sel["component"], plan["variant"]
    appdir = Path("opt") / app
    lib = appdir / "lib"
    apps = []
    for ga, v in CAT.MAVEN_FILLERS:
        write_jar(rootfs, lib, ga, v)
    jdk = "17.0.2" if var != "V5" or comp != "org.springframework:spring-beans" else "1.8.0_322"
    if comp == "org.springframework:spring-beans" and var == "V5":
        jdk = "1.8.0_322"
    if var in ("V2", "V3", "V4", "V5"):
        p = write_jar(rootfs, lib, comp, plan["version"])
        apps.append({"path": p, "ecosystem": "maven", "component": comp, "version": plan["version"]})
        for sib in CAT.MAVEN.get(comp, {}).get("siblings", []):
            if plan["version"] in maven_versions(sib):
                write_jar(rootfs, lib, sib, plan["version"])
    elif var == "V6":
        dv = maven_versions(plan["decoy"])[-1]
        p = write_jar(rootfs, lib, plan["decoy"], dv)
        apps.append({"path": p, "ecosystem": "maven", "component": plan["decoy"], "version": dv})
    elif var == "V7":
        g, a = comp.split(":")
        t, vend = maven_meta(comp)
        nested = [(f"BOOT-INF/lib/{a}-{plan['version']}.jar", jar_bytes(g, a, plan["version"], t, vend))]
        for ga, v in CAT.MAVEN_FILLERS:
            gg, aa = ga.split(":")
            nested.append((f"BOOT-INF/lib/{aa}-{v}.jar", jar_bytes(gg, aa, v, *maven_meta(ga))))
        fat = CAT.MAVEN_FATJAR_POOL[int(stable_hash(sel["cve"], "fat"), 16) % len(CAT.MAVEN_FATJAR_POOL)]
        fat_rel = appdir / f"{fat}.jar"
        write_file(rootfs / fat_rel, jar_bytes("com.corp.platform", fat, "3.4.1", fat, "corp", {
            "Main-Class": "org.springframework.boot.loader.JarLauncher",
            "Start-Class": f"com.corp.platform.{fat.replace('-', '')}.Application",
            "Spring-Boot-Version": "2.7.18", "Spring-Boot-Classes": "BOOT-INF/classes/",
            "Spring-Boot-Lib": "BOOT-INF/lib/"}, nested))
        apps.append({"path": f"{fat_rel}!/BOOT-INF/lib/{a}-{plan['version']}.jar", "ecosystem": "maven",
                     "component": comp, "version": plan["version"], "vendored_in": str(fat_rel)})
    maven_config(rootfs, appdir, app, sel, pre, enabled, jdk)
    if comp != "org.springframework:spring-beans" or not pre:
        write_file(rootfs / appdir / "jre/release", f'IMPLEMENTOR="Eclipse Adoptium"\nJAVA_VERSION="{jdk}"\n'
                                                    'OS_ARCH="x86_64"\nOS_NAME="Linux"\n')
    write_file(rootfs / appdir / "bin/start.sh",
               f'#!/bin/sh\nexec /{appdir}/jre/bin/java $(cat /{appdir}/conf/jvm.options | tr "\\n" " ") '
               f'-cp "/{lib}/*" com.corp.{app.replace("-", "")}.Main\n', mode=0o755)
    unit = f"{app}.service"
    execstart = f"/{appdir}/bin/start.sh"
    systemd_unit(rootfs, unit, f"{app} (Java)", execstart, "svc-" + app[:8], str(appdir))
    loaded = plan["version"] if var in ("V2", "V3", "V4", "V5", "V7") else None
    banner = f"Jetty({loaded})" if comp == "org.eclipse.jetty:jetty-server" and loaded else ""
    svc = {app: {"unit": unit, "active": True, "package": None,
                 "config_files": sorted(str(p.relative_to(rootfs)) for p in (rootfs / appdir).rglob("*")
                                        if p.is_file() and p.suffix in (".xml", ".properties", ".ini", ".options", "")
                                        and "lib" not in p.parts and p.name != "start.sh"),
                 "banner": banner, "loaded_version": loaded}}
    proc = [{"pid": 900 + int(stable_hash(app)[:3], 16) % 500, "user": "svc-" + app[:8],
             "cmd": f"/{appdir}/jre/bin/java -Xms256m -Xmx1g -cp /{lib}/* com.corp.{app.replace('-', '')}.Main",
             "unit": unit}]
    return apps, svc, proc


# ------------------------------------------------------------------------------------------- vendor
def vx(product: str, version: str) -> Path:
    return DATA / "cache" / "vendorx" / product / version


def build_vendor_product(rootfs: Path, product: str, version: str, cve: str | None, pre: dict | None,
                         enabled: bool, rng) -> tuple[list[dict], dict, list]:
    meta = CAT.VENDOR[product]
    d = rootfs / meta["dir"]
    src = vx(product, version)
    if product == "tomcat":
        for f in ("RELEASE-NOTES", "RUNNING.txt", "NOTICE", "conf/server.xml", "conf/web.xml", "conf/context.xml",
                  "conf/tomcat-users.xml", "conf/catalina.properties", "conf/logging.properties"):
            if (src / f).exists():
                write_file(d / f, (src / f).read_bytes())
        (d / "webapps/ROOT").mkdir(parents=True, exist_ok=True)
        (d / "logs").mkdir(parents=True, exist_ok=True)
        if pre:
            srv, web, ctx = d / "conf/server.xml", d / "conf/web.xml", d / "conf/context.xml"
            if cve == "CVE-2020-1938" and not enabled:
                t = srv.read_text()
                new = re.sub(r'(?m)^(\s*)(<Connector port="8009" protocol="AJP/1\.3"[^>]*/>)',
                             r"\1<!-- disabled after CVE-2020-1938 review: \2 -->", t)
                assert new != t, f"no AJP connector in {version}"
                write_file(srv, new)
            if cve in ("CVE-2017-12617", "CVE-2025-24813") and enabled:
                t = web.read_text()
                anchor = "<param-name>listings</param-name>"
                i = t.index(anchor)
                j = t.index("</init-param>", i) + len("</init-param>")
                write_file(web, t[:j] + "\n        <init-param>\n            <param-name>readonly</param-name>\n"
                                         "            <param-value>false</param-value>\n        </init-param>" + t[j:])
            if cve == "CVE-2020-9484" and enabled:
                t = ctx.read_text()
                k = t.rindex("</Context>")
                write_file(ctx, t[:k] + '    <Manager className="org.apache.catalina.session.PersistentManager"'
                                        ' maxIdleBackup="1">\n        <Store className="org.apache.catalina.session.FileStore"'
                                        ' directory="/var/lib/tomcat/sessions"/>\n    </Manager>\n' + t[k:])
        evidence = "opt/tomcat/RELEASE-NOTES"
        execstart = "/opt/tomcat/bin/catalina.sh run"
    elif product == "httpd":
        write_file(d / "include/ap_release.h", (src / "include/ap_release.h").read_bytes())
        conf = (src / "httpd.conf").read_text()
        if pre and cve in ("CVE-2021-41773", "CVE-2021-42013") and enabled:
            conf = re.sub(r"(<Directory />\s*\n\s*AllowOverride none\s*\n\s*)Require all denied",
                          r"\1Require all granted", conf, count=1)
            assert "Require all granted" in conf.split("</Directory>")[0], "root dir rewrite failed"
        if pre and cve == "CVE-2021-40438" and enabled:
            conf = re.sub(r"(?m)^#(LoadModule proxy_module )", r"\1", conf)
            conf = re.sub(r"(?m)^#(LoadModule proxy_http_module )", r"\1", conf)
            conf += '\n# Reverse proxy to the internal application tier\nProxyPass "/app/" "http://10.20.0.30:8080/"\n' \
                    'ProxyPassReverse "/app/" "http://10.20.0.30:8080/"\n'
        write_file(d / "conf/httpd.conf", conf)
        write_file(d / "build/config.nice", "#! /bin/sh\n#\n# Created by configure\n\n\"./configure\" \\\n"
                                            "\"--prefix=/opt/httpd\" \\\n\"--enable-mods-shared=most\" \\\n"
                                            "\"--with-included-apr\" \\\n\"$@\"\n", mode=0o755)
        evidence = "opt/httpd/include/ap_release.h"
        execstart = "/opt/httpd/bin/apachectl -k start -DFOREGROUND"
    elif product == "jenkins":
        home = d / "home"
        write_file(home / "jenkins.install.InstallUtil.lastExecVersion", version + "\n")
        write_file(home / "jenkins.install.UpgradeWizard.state", version + "\n")
        write_file(home / "config.xml",
                   "<?xml version='1.1' encoding='UTF-8'?>\n<hudson>\n  <disabledAdministrativeMonitors/>\n"
                   f"  <version>{version}</version>\n  <numExecutors>2</numExecutors>\n  <mode>NORMAL</mode>\n"
                   "  <useSecurity>true</useSecurity>\n  <authorizationStrategy class=\"hudson.security."
                   "FullControlOnceLoggedInAuthorizationStrategy\">\n    <denyAnonymousReadAccess>true"
                   "</denyAnonymousReadAccess>\n  </authorizationStrategy>\n  <securityRealm class=\"hudson."
                   "security.HudsonPrivateSecurityRealm\">\n    <disableSignup>true</disableSignup>\n"
                   "  </securityRealm>\n  <slaveAgentPort>50000</slaveAgentPort>\n</hudson>\n")
        write_file(d / "README.txt", "Jenkins controller (standalone WAR deployment).\nJENKINS_HOME=/opt/jenkins/home\n"
                                     "WAR: /opt/jenkins/jenkins.war (managed by the platform team)\n")
        evidence = "opt/jenkins/home/jenkins.install.InstallUtil.lastExecVersion"
        execstart = "/usr/bin/java -Djava.awt.headless=true -jar /opt/jenkins/jenkins.war --httpPort=8080"
    elif product == "roundcube":
        for f in ("program/include/iniset.php", "CHANGELOG.md", "CHANGELOG", "README.md", "config/defaults.inc.php"):
            if (src / f).exists():
                write_file(d / f, (src / f).read_bytes())
        write_file(d / "config/config.inc.php",
                   "<?php\n\n$config = [];\n$config['db_dsnw'] = 'mysql://roundcube:secret@localhost/roundcubemail';\n"
                   "$config['imap_host'] = 'ssl://mail.corp.example:993';\n"
                   "$config['smtp_host'] = 'tls://mail.corp.example:587';\n$config['support_url'] = '';\n"
                   "$config['display_product_info'] = 2;\n$config['des_key'] = 'rcmail-!24ByteDESkey*Str';\n"
                   "$config['plugins'] = ['archive', 'zipdownload', 'managesieve'];\n")
        evidence = "opt/roundcube/program/include/iniset.php"
        execstart = "/usr/sbin/php-fpm8.1 --nodaemonize --fpm-config /etc/php/8.1/fpm/php-fpm.conf"
    elif product == "gitlab":
        write_file(d / "embedded/service/gitlab-rails/VERSION", (src / "VERSION").read_text())
        write_file(d / "version-manifest.txt",
                   f"gitlab-ee {version}\n\nComponent                 Installed Version   Version GUID\n"
                   "--------------------------------------------------------------------------------\n"
                   f"gitlab-rails              v{version}-ee         git:{stable_hash('gl', version)[:40]}\n"
                   f"omnibus-gitlab            {version}+ee.0       git:{stable_hash('omni', version)[:40]}\n")
        write_file(rootfs / "etc/gitlab/gitlab.rb", "external_url 'https://gitlab.corp.example'\n"
                                                    "gitlab_rails['gitlab_shell_ssh_port'] = 2222\n")
        evidence = "opt/gitlab/embedded/service/gitlab-rails/VERSION"
        execstart = "/opt/gitlab/embedded/bin/runsvdir-start"
    else:
        raise KeyError(product)
    systemd_unit(rootfs, meta["unit"], meta["display"], execstart, product if product != "gitlab" else "git",
                 meta["dir"])
    svc = {product: {"unit": meta["unit"], "active": True, "package": None,
                     "config_files": sorted(str(p.relative_to(rootfs)) for p in d.rglob("*")
                                            if p.is_file() and p.suffix in (".xml", ".conf", ".php", ".rb")),
                     "banner": meta["banner"].format(v=version), "loaded_version": version}}
    proc = [{"pid": 1200 + rng.randrange(800), "user": product if product != "gitlab" else "git",
             "cmd": meta["cmd"], "unit": meta["unit"]}]
    apps = [{"path": meta["dir"], "ecosystem": "vendor", "component": product, "version": version,
             "evidence": evidence}]
    return apps, svc, proc


def build_vendor_decoy(rootfs: Path, decoy: str, rng) -> tuple[list[dict], dict, list]:
    if decoy in CAT.VENDOR:  # another real vendor product (e.g. httpd for a Tomcat CVE)
        vs = [v for v in vendor_versions(decoy) if vx(decoy, v).exists()]
        v = vs[-1]
        return build_vendor_product(rootfs, decoy, v, None, None, False, rng)
    m = CAT.VENDOR_DECOYS[decoy]
    d = rootfs / m["dir"]
    if decoy == "jenkins-agent":
        write_file(d / "README.txt", f"Jenkins inbound agent\nremoting version: {m['version']}\n"
                                     "Controller URL: https://jenkins.corp.example/\n")
    elif decoy == "rcmcarddav":
        write_file(d / "CHANGELOG.md", f"# Changelog for RCMCardDAV\n\n## Version {m['version']} (to 4.4.0)\n\n"
                                       "- Support for Roundcube 1.6 elastic skin\n")
        write_file(d / "composer.json", '{\n  "name": "roundcube/carddav",\n  "description": "CardDAV adapter for '
                                        f'connecting to CardDAV-enabled addressbooks",\n  "version": "{m["version"]}"\n}}\n')
    elif decoy == "gitlab-runner":
        write_file(d / "VERSION", m["version"] + "\n")
        write_file(rootfs / "etc/gitlab-runner/config.toml",
                   'concurrent = 4\n\n[[runners]]\n  name = "build-01"\n  url = "https://gitlab.corp.example/"\n'
                   '  executor = "shell"\n')
    unit = f"{decoy}.service"
    systemd_unit(rootfs, unit, m["display"], f"/{m['dir']}/bin/{decoy}", decoy[:12], m["dir"])
    svc = {decoy: {"unit": unit, "active": True, "package": None, "config_files": [],
                   "banner": f"{m['display']} {m['version']}", "loaded_version": m["version"]}}
    proc = [{"pid": 1500 + rng.randrange(500), "user": decoy[:12], "cmd": f"/{m['dir']}/bin/{decoy} run",
             "unit": unit}]
    return [{"path": m["dir"], "ecosystem": "vendor", "component": decoy, "version": m["version"]}], svc, proc


# ------------------------------------------------------------------------------------------ host build
def app_name(sel: dict, pre: dict | None) -> str:
    if pre and pre["file"].startswith("opt/"):
        return pre["file"].split("/")[1]
    pool = CAT.PYPI_APP_POOL if sel["ecosystem"] == "pypi" else CAT.MAVEN_APP_POOL
    return pool[int(stable_hash(str(SEED), "app", sel["cve"]), 16) % len(pool)]


def aliases_for(sel: dict, bins: list[str]) -> list[str]:
    eco, comp = sel["ecosystem"], sel["component"]
    if eco == "deb-ubuntu":
        return list(dict.fromkeys([sel["src_package"], *bins]))
    if eco == "pypi":
        disp = CAT.PYPI[comp]["display"]
        return list(dict.fromkeys([comp, disp]))
    if eco == "maven":
        g, a = comp.split(":")
        return list(dict.fromkeys([a, comp, *CAT.MAVEN[comp]["aliases"]]))
    return list(CAT.VENDOR[comp]["aliases"])


def short_for(sel: dict) -> str:
    eco = sel["ecosystem"]
    if eco == "deb-ubuntu":
        return B1.FAMILY_SHORT.get(UB_FAMILY.get(sel["src_package"], "library"), "app")
    return {"pypi": "py", "maven": "jvm", "vendor": "ven"}[eco]


def build_case(job: dict) -> dict:
    sel, plan, ctx = job["sel"], job["plan"], job["ctx"]
    cve, eco, comp, var = sel["cve"], sel["ecosystem"], sel["component"], plan["variant"]
    rel = plan.get("release") or base_for(cve, var + plan.get("tag", ""))
    suffix = f"-{plan['tag']}" if plan.get("tag") else ""
    case_id = f"D7-{cve}-{eco}-{rel}-{var}{suffix}"
    host_id, hostname = host_ids(case_id, short_for(sel))
    hdir = HOSTS / host_id
    rootfs = hdir / "rootfs"
    hdir.mkdir(parents=True, exist_ok=True)
    copy_base(rootfs, rel)
    pre = ctx["pre"].get(cve)
    enabled = var != "V5"
    rng = rng_for("host", case_id)
    apps, services, procs = [], {}, [{"pid": 1, "user": "root", "cmd": "/sbin/init"}]
    bins: list[str] = []
    synth = False
    if eco == "deb-ubuntu":
        src = sel["src_package"]
        bins = ub_pick_binaries(src, rel, cve) if plan["version"] else []
        ub_write_status(rootfs, rel, src if plan["version"] else None, plan["version"], bins, plan.get("decoy"))
        if bins:
            ub_install_configs(rootfs, rel, bins)
            if pre:
                ub_apply_precondition(rootfs, cve, enabled)
        from label_live import installed_src_version, parse_status

        _, all_bins = installed_src_version(parse_status(rootfs), src)
        pk = ubuntu_packages(rel)
        if plan["version"]:
            for b in all_bins:
                maint = pk[b]["Maintainer"] if b in pk else "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"
                text, s = ub_changelog(src, plan["version"], rel, maint)
                synth |= s
                write_file(rootfs / "usr/share/doc" / b / "changelog.Debian", text)
        if plan.get("decoy"):
            d_src, d_ver = src_of(pk[plan["decoy"]])
            text, s = ub_changelog(d_src, d_ver, rel, pk[plan["decoy"]]["Maintainer"])
            write_file(rootfs / "usr/share/doc" / plan["decoy"] / "changelog.Debian", text)
        s2, p2 = deb_services(rootfs, all_bins, plan["version"], pre, rng)
        services.update(s2)
        procs += p2
    else:
        app = app_name(sel, pre)
        if eco == "pypi":
            a, s2, p2 = build_pypi_app(rootfs, sel, plan, rel, app, pre, enabled)
        elif eco == "maven":
            a, s2, p2 = build_maven_app(rootfs, sel, plan, app, pre, enabled)
        else:
            if var == "V6":
                a, s2, p2 = build_vendor_decoy(rootfs, plan["decoy"], rng)
            elif var == "V1":
                a, s2, p2 = [], {}, []
            else:
                a, s2, p2 = build_vendor_product(rootfs, comp, plan["version"], cve, pre, enabled, rng)
        apps += a
        services.update(s2)
        procs += p2
    write_file(rootfs / "etc/hostname", hostname + "\n")
    # ---------------------------------------------------------------- labels
    ranges = job["ranges"]
    insts, atoms, label = label_host(rootfs, eco, comp, ranges, pre)
    exp = EXPECTED[var]
    if (label["status"], label["justification"]) != exp:
        return {"failure": True, "case_id": case_id, "host_id": host_id,
                "why": f"label {label} != expected {exp}", "plan": plan}
    installed = None
    if insts:
        inr = [i for i in insts if V.classify(eco, i["version"], ranges)[0]]
        installed = (inr or insts)[0]["version"]
    inst_bins = insts[0].get("binaries", []) if eco == "deb-ubuntu" and insts else []
    # ---------------------------------------------------------------- CMDB
    stale = rng.random() < 0.2
    lists_apps = rng.random() < 0.7
    os_name = f"Ubuntu {UBUNTU_NUM[rel]} LTS"
    sw = []
    alt = job["alt_version"]
    if eco == "deb-ubuntu":
        if not stale:
            sw = [{"name": b, "version": installed} for b in inst_bins]
        elif alt:
            sw = [{"name": b, "version": alt} for b in (inst_bins or ub_pick_binaries(sel["src_package"], rel, cve))]
        if plan.get("decoy"):
            sw.append({"name": plan["decoy"], "version": ubuntu_packages(rel)[plan["decoy"]]["Version"]})
    elif lists_apps:
        disp = aliases_for(sel, [])[0] if eco != "vendor" else CAT.VENDOR[comp]["display"]
        if not stale:
            sw = [{"name": x["component"] if eco != "vendor" else CAT.VENDOR.get(x["component"], {}).get(
                "display", x["component"]), "version": x["version"], "source": "app-inventory"} for x in apps]
        elif alt:
            sw = [{"name": disp, "version": alt, "source": "app-inventory"}]
    base_pk = base_packages(rel)
    for b in ("base-files", "libc6", "bash"):
        if b in base_pk and b not in {s["name"] for s in sw}:
            sw.append({"name": b, "version": base_pk[b]["Version"]})
    month = rng.randrange(1, 9) if stale else 9
    last_sync = f"2026-{month:02d}-{rng.randrange(1, 28):02d}T0{rng.randrange(0, 9)}:00:00Z"
    ticket = ({"id": f"CHG-2026{rng.randrange(10000, 99999)}", "approved": rng.random() < 0.75,
               "window_open": rng.random() < 0.5} if rng.random() < 0.5 else None)
    host = {
        "host_id": host_id, "hostname": hostname, "release": rel, "services": services, "processes": procs,
        "cmdb": {"asset": hostname, "os": os_name, "software": sw, "last_sync": last_sync,
                 "notes": rng.choice(["imported from asset inventory", "owner: platform team", "prod tier 2",
                                      "managed by config management", "app inventory partially synced"])},
        "cmdb_stale": stale, "change": {"ticket": ticket}, "rollback_available": rng.random() < 0.5,
        "apps": apps,
    }
    (hdir / "host.json").write_text(json.dumps(host, indent=1))
    row = {
        "case_id": case_id, "cve": cve, "ecosystem": eco, "component": comp,
        "aliases": aliases_for(sel, inst_bins or bins),
        "install_paths": [] if eco == "deb-ubuntu" else [i["path"] for i in insts],
        "src_package": sel["src_package"] if eco == "deb-ubuntu" else comp,
        "binary_packages": (inst_bins or bins or ub_pick_binaries(sel["src_package"], rel, cve))
        if eco == "deb-ubuntu" else [],
        "distro": "ubuntu", "release": rel, "variant": var, "host_id": host_id,
        "family": UB_FAMILY.get(sel["src_package"], "library") if eco == "deb-ubuntu" else
        {"pypi": "python_app", "maven": "java_app", "vendor": comp}[eco],
        "split": sel["split"], "temporal_holdout": sel["temporal_holdout"], "kev": sel["kev"],
        "base_image": ctx["images"][rel], "installed_version": installed,
        "label": label, "atoms": atoms, "label_provenance": PROVENANCE[eco],
    }
    meta = {"host_id": host_id, "case_id": case_id, "cmdb_stale": stale, "cmdb_lists_apps": lists_apps,
            "cmdb_version": alt if stale else installed, "true_installed_version": installed,
            "version_source": plan.get("version_source"), "decoy": plan.get("decoy"),
            "changelog_synthesized": synth, "nvd_upstream_in_range": plan.get("nvd_upstream_in_range"),
            "vendored": plan.get("vendored"), "pip_version": plan.get("pip_version"), "tag": plan.get("tag")}
    return {"row": row, "meta": meta}


def alt_version_for(p: dict, plans: list[dict], rel: str | None) -> str | None:
    """Version an earlier (stale) inventory would report."""
    same = [x for x in plans if x.get("release") == rel] if rel else plans
    by = {x["variant"]: x["version"] for x in same if x["version"]}
    if p["variant"] in ("V2", "V5", "V7", "V8"):
        return by.get("V3") or by.get("V4")
    if p["variant"] in ("V3", "V4"):
        return by.get("V2") or by.get("V8")
    return by.get("V3") or by.get("V2") or by.get("V8")


def build_all(workers: int) -> None:
    plan = load_json(CUR / "plan.json")
    pre = load_preconditions_v3()
    images = {r: load_json(DATA / "base_images" / r / "IMAGE.json")["reference"] for r in UBUNTU_RELEASES}
    ctx = {"pre": pre, "images": images}
    jobs, metas = [], []
    for p in plan:
        s = p["sel"]
        for x in p["plans"]:
            if s["ecosystem"] == "deb-ubuntu":
                ranges = case_ranges({"ecosystem": "deb-ubuntu", "ubuntu": p["tracker"]}, x["release"])
            else:
                ranges = p["ranges"]
            jobs.append({"sel": s, "plan": x, "ctx": ctx, "ranges": ranges,
                         "alt_version": alt_version_for(x, p["plans"], x.get("release"))})
        metas.append(cve_meta_row(p, pre))
    if HOSTS.exists():
        shutil.rmtree(HOSTS)
    HOSTS.mkdir(parents=True)
    # warm caches before threading
    for r in UBUNTU_RELEASES:
        ubuntu_packages(r)
    with ThreadPoolExecutor(workers) as ex:
        results = list(ex.map(build_case, jobs))
    rows = [r["row"] for r in results if "row" in r]
    fails = [r for r in results if r.get("failure")]
    for f in fails:
        shutil.rmtree(HOSTS / f["host_id"], ignore_errors=True)
    built = {r["cve"] for r in rows}
    metas = [m for m in metas if m["cve"] in built]
    write_jsonl(D7 / "cve_meta.jsonl", metas)
    write_jsonl(D7 / "hosts_meta.jsonl", [r["meta"] for r in results if "meta" in r])
    write_jsonl(D7 / "build_failures.jsonl", fails + [{"note": n} for n in load_json(CUR / "plan_notes.json")])
    rows.sort(key=lambda r: r["case_id"])
    for split in ("dev", "calib"):
        write_jsonl(D7 / "cases" / f"{split}.jsonl", [r for r in rows if r["split"] == split])
    test = [r for r in rows if r["split"] == "test"]
    write_jsonl(D7 / "cases" / "test.jsonl", [{k: v for k, v in r.items() if k not in ("label", "atoms")}
                                              for r in test])
    sealed = DATA / "sealed" / "d7_test_labels.jsonl"
    write_jsonl(sealed, [{"case_id": r["case_id"], "label": r["label"], "atoms": r["atoms"]} for r in test])
    (DATA / "sealed" / "D7_SHA256").write_text(f"{sha256_file(sealed)}  data/sealed/d7_test_labels.jsonl\n")
    print(f"cases={len(rows)} cves={len(built)} failures={len(fails)}")
    for f in fails[:40]:
        print("  FAIL", f["case_id"], f["why"])


def cve_meta_row(p: dict, pre_all: dict) -> dict:
    s = p["sel"]
    cve, eco = s["cve"], s["ecosystem"]
    nvd = nvd_record(cve)
    desc = next((d["value"] for d in (nvd or {}).get("descriptions", []) if d["lang"] == "en"), "")
    pre = pre_all.get(cve)
    row = {"cve": cve, "ecosystem": eco, "component": s["component"],
           "aliases": aliases_for(s, ub_pick_binaries(s["src_package"], "noble", cve) if eco == "deb-ubuntu" else []),
           "src_package": s.get("src_package") or s["component"],
           "family": UB_FAMILY.get(s.get("src_package", ""), "library") if eco == "deb-ubuntu" else
           {"pypi": "python_app", "maven": "java_app", "vendor": s["component"]}[eco],
           "published": s["published"], "published_source": s["published_source"], "kev": s["kev"],
           "epss": s.get("epss"), "description": desc}
    if eco == "deb-ubuntu":
        row["ranges"] = [dict(r, release=rel) for rel in UBUNTU_RELEASES
                         for r in case_ranges({"ecosystem": eco, "ubuntu": p["tracker"]}, rel)]
        row["ubuntu"] = {rel: {"status": x["status"], "fixed_version": x["fixed_version"]}
                         for rel, x in p["tracker"].items()}
        row["nvd_ranges"] = p["nvd_ranges"]
        ub = osv_records("Ubuntu", cve)
        row["osv_ids"] = sorted({r["id"] for r in ub} | {x for r in ub for x in r.get("related", [])})
        row["range_source"] = f"https://ubuntu.com/security/cves/{cve}.json"
    else:
        row["ranges"] = p["ranges"]
        saved = B1.CPE_PRODUCTS
        B1.CPE_PRODUCTS = {s["component"]: VENDOR_CPE.get(s["component"], set())}
        row["nvd_ranges"] = B1.nvd_ranges(nvd, s["component"]) if eco == "vendor" else []
        B1.CPE_PRODUCTS = saved
        row["osv_ids"] = p.get("osv_ids", [])
        if eco == "vendor":
            row["range_source"] = "data/d7/curation/vendor_ranges.yaml"
            row["range_statement"] = vendor_ranges()[cve]["statement"]
        else:
            row["range_source"] = f"OSV {OSV_ECO[eco]} export {SNAP_DATE}: {(p.get('osv_ids') or ['?'])[0]}"
            row["alt_ranges"] = p.get("alt_ranges", [])
    row["config_precondition"] = None if not pre else {
        "file": pre["file"], "key": pre["key"], "vulnerable_when": pre["vulnerable_when"],
        "safe_value": pre["safe_setting"], "source": pre["advisory_url"], "service": pre.get("service"),
        "predicate": pre["predicate"], "applies_to_versions": pre.get("applies_to_versions")}
    row["split"] = s["split"]
    row["temporal_holdout"] = s["temporal_holdout"]
    return row


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["plan", "build"])
    ap.add_argument("--workers", type=int, default=24)
    a = ap.parse_args()
    if a.phase == "plan":
        plan_all()
    else:
        build_all(a.workers)
    _ = gzip


if __name__ == "__main__":
    main()
