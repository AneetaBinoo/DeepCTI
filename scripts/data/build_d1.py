"""Build D1 (DeepCTI-Live) rootfs fixtures, host.json records, cases and sealed test labels.

Inputs (all mirrored first; see mirror_sources.py / fetch_base_images.py / select_cves.py):
  data/d1/selected_cves.json, data/base_images/<release>/, data/mirrors/{debian_tracker,nvd,osv,epss,
  cisa_kev,snapshot_debian,debian_archive}/, data/cache/debx/<release>/<binary>/ (extracted default configs),
  config/config_preconditions.yaml.

Outputs: data/d1/hosts/<host_id>/{rootfs,host.json}, data/d1/cases/{dev,calib,test}.jsonl,
data/d1/cve_meta.jsonl, data/d1/tracker_entries.json, data/d1/hosts_meta.jsonl (build-side truth about
CMDB perturbations; not for the agent), data/sealed/test_labels.jsonl + SHA256, data/d1/build_failures.jsonl.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from debian.debian_support import Version

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    DATA,
    MIRRORS,
    RELEASE_NUM,
    SEED,
    SNAP_DATE,
    load_packages,
    sha256_file,
    src_of,
    write_jsonl,
)
from label_live import label_host, load_preconditions  # noqa: E402

D1 = DATA / "d1"
HOSTS = D1 / "hosts"
DEBX = DATA / "cache" / "debx"
RELEASES = ("bookworm", "trixie")
INREL = {"bookworm": r"[+~]deb12u\d+$", "trixie": r"[+~]deb13u\d+$"}
PROVENANCE = f"debian-tracker@{SNAP_DATE} + dpkg --compare-versions (python-debian)"

# preferred binary packages per source package (first ones present in the release are used)
BINARIES = {
    "openssl": ["openssl", "libssl3", "libssl3t64"],
    "gnutls28": ["libgnutls30", "libgnutls30t64", "gnutls-bin"],
    "nss": ["libnss3"],
    "openssh": ["openssh-server", "openssh-client", "openssh-sftp-server"],
    "sudo": ["sudo"],
    "policykit-1": ["polkitd", "pkexec", "libpolkit-gobject-1-0"],
    "xz-utils": ["xz-utils", "liblzma5"],
    "zlib": ["zlib1g"],
    "bzip2": ["bzip2", "libbz2-1.0"],
    "libarchive": ["libarchive13", "libarchive13t64", "libarchive-tools"],
    "apache2": ["apache2", "apache2-bin", "apache2-data", "apache2-utils"],
    "nginx": ["nginx", "nginx-common"],
    "bind9": ["bind9", "bind9-utils", "bind9-libs"],
    "exim4": ["exim4-base", "exim4-config", "exim4-daemon-light"],
    "postfix": ["postfix"],
    "samba": ["samba", "samba-common", "samba-common-bin", "samba-libs"],
    "python3.11": ["python3.11", "python3.11-minimal", "libpython3.11-minimal", "libpython3.11-stdlib"],
    "python3.13": ["python3.13", "python3.13-minimal", "libpython3.13-minimal", "libpython3.13-stdlib"],
    "perl": ["perl", "perl-base", "perl-modules-5.36", "perl-modules-5.40", "libperl5.36", "libperl5.40"],
    "ruby3.1": ["ruby3.1", "libruby3.1"],
    "ruby3.3": ["ruby3.3", "libruby3.3"],
    "php8.2": ["php8.2-cli", "php8.2-common"],
    "php8.4": ["php8.4-cli", "php8.4-common"],
    "curl": ["curl", "libcurl4", "libcurl4t64"],
    "libxml2": ["libxml2", "libxml2-16"],
    "expat": ["libexpat1"],
    "glibc": ["libc6", "libc-bin"],
    "sqlite3": ["libsqlite3-0", "sqlite3"],
    "libssh": ["libssh-4"],
    "tiff": ["libtiff6"],
    "libwebp": ["libwebp7", "libwebpdemux2", "libwebpmux3"],
    "git": ["git", "git-man"],
}
# decoys: a different source package whose name / vendor overlaps the advisory
DECOYS = {
    "openssl": ["python3-openssl"],
    "gnutls28": ["libcurl3-gnutls"],
    "nss": ["libnss-mdns"],
    "openssh": ["ssh-askpass"],
    "sudo": ["opendoas"],
    "policykit-1": ["polkit-kde-agent-1"],
    "xz-utils": ["pixz"],
    "zlib": ["pigz"],
    "bzip2": ["lbzip2"],
    "libarchive": ["libarchive-zip-perl"],
    "apache2": ["libapr1", "libapr1t64"],
    "nginx": ["python3-certbot-nginx"],
    "bind9": ["ldnsutils"],
    "exim4": ["sa-exim"],
    "postfix": ["postfix-policyd-spf-python"],
    "samba": ["cifs-utils"],
    "python3.11": ["python3-pip"],
    "python3.13": ["python3-pip"],
    "perl": ["liberror-perl"],
    "ruby3.1": ["ruby-rack"],
    "ruby3.3": ["ruby-rack"],
    "php8.2": ["php-common"],
    "php8.4": ["php-common"],
    "curl": ["python3-pycurl"],
    "libxml2": ["libxml-libxml-perl"],
    "expat": ["libxml-parser-perl"],
    "glibc": ["musl"],
    "sqlite3": ["libdbd-sqlite3-perl"],
    "libssh": ["libssh2-1", "libssh2-1t64"],
    "tiff": ["python3-tifffile"],
    "libwebp": ["webp-pixbuf-loader"],
    "git": ["git-lfs"],
}
# NVD CPE products per Debian source package (for nvd_ranges)
CPE_PRODUCTS = {
    "openssl": {"openssl"},
    "gnutls28": {"gnutls"},
    "nss": {"nss", "network_security_services"},
    "openssh": {"openssh"},
    "sudo": {"sudo"},
    "policykit-1": {"polkit"},
    "xz-utils": {"xz", "xz-utils"},
    "zlib": {"zlib"},
    "bzip2": {"bzip2"},
    "libarchive": {"libarchive"},
    "apache2": {"http_server"},
    "nginx": {"nginx"},
    "bind9": {"bind"},
    "exim4": {"exim"},
    "postfix": {"postfix"},
    "samba": {"samba"},
    "python3.11": {"python", "cpython"},
    "python3.13": {"python", "cpython"},
    "perl": {"perl"},
    "ruby3.1": {"ruby"},
    "ruby3.3": {"ruby"},
    "php8.2": {"php"},
    "php8.4": {"php"},
    "curl": {"curl", "libcurl"},
    "libxml2": {"libxml2"},
    "expat": {"libexpat", "expat"},
    "glibc": {"glibc"},
    "sqlite3": {"sqlite"},
    "libssh": {"libssh"},
    "tiff": {"libtiff"},
    "libwebp": {"libwebp"},
    "git": {"git"},
}
# daemon binaries -> service record (unit, process command line, config files) ; deb dirs for configs
SERVICES = {
    "openssh-server": (
        "ssh",
        "ssh.service",
        "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
        ["etc/ssh/sshd_config"],
    ),
    "apache2": (
        "apache2",
        "apache2.service",
        "/usr/sbin/apache2 -k start",
        ["etc/apache2/apache2.conf", "etc/apache2/ports.conf"],
    ),
    "nginx": (
        "nginx",
        "nginx.service",
        "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;",
        ["etc/nginx/nginx.conf"],
    ),
    "bind9": (
        "named",
        "named.service",
        "/usr/sbin/named -f -u bind",
        ["etc/bind/named.conf", "etc/bind/named.conf.options"],
    ),
    "exim4-daemon-light": (
        "exim4",
        "exim4.service",
        "/usr/sbin/exim4 -bd -q30m",
        ["etc/exim4/update-exim4.conf.conf"],
    ),
    "postfix": ("postfix", "postfix.service", "/usr/lib/postfix/sbin/master -w", ["etc/postfix/main.cf"]),
    "samba": (
        "smbd",
        "smbd.service",
        "/usr/sbin/smbd --foreground --no-process-group",
        ["etc/samba/smb.conf"],
    ),
    "polkitd": ("polkit", "polkit.service", "/usr/lib/polkit-1/polkitd --no-debug", []),
}
FAMILY_SHORT = {
    "crypto_tls": "tls",
    "ssh": "ssh",
    "privesc": "adm",
    "compression": "arc",
    "web_server": "web",
    "dns": "dns",
    "mail": "mx",
    "file_sharing": "fs",
    "interpreter": "app",
    "library": "app",
}
STATUS_FIELDS = [
    "Package",
    "Status",
    "Priority",
    "Section",
    "Installed-Size",
    "Maintainer",
    "Architecture",
    "Multi-Arch",
    "Source",
    "Version",
    "Replaces",
    "Provides",
    "Depends",
    "Pre-Depends",
    "Recommends",
    "Suggests",
    "Breaks",
    "Conflicts",
    "Description",
    "Homepage",
]
RELATION_FIELDS = {"Replaces", "Provides", "Depends", "Pre-Depends", "Recommends", "Suggests", "Breaks", "Conflicts"}
APACHE_DEFAULT_MODS = [
    "access_compat",
    "alias",
    "auth_basic",
    "authn_core",
    "authn_file",
    "authz_core",
    "authz_host",
    "authz_user",
    "autoindex",
    "deflate",
    "dir",
    "env",
    "filter",
    "mime",
    "mpm_event",
    "negotiation",
    "reqtimeout",
    "setenvif",
    "status",
]
APACHE_DEFAULT_CONFS = [
    "charset",
    "localized-error-pages",
    "other-vhosts-access-log",
    "security",
    "serve-cgi-bin",
]
EXPECTED = {
    "V1": ("not_affected", "component_not_present"),
    "V2": ("affected", None),
    "V3": ("fixed", None),
    "V4": ("fixed", None),
    "V5": ("not_affected", "requires_configuration"),
    "V6": ("not_affected", "component_not_present"),
}


# ----------------------------------------------------------------------------------------------- loading
def load_json(p: Path):
    return json.loads(p.read_text())


def snapshot_versions(src: str) -> list[str]:
    p = MIRRORS / "snapshot_debian" / SNAP_DATE / "package" / f"{src}.json"
    j = load_json(p) if p.exists() else {}
    return [r["version"] for r in j.get("result", [])]


def nvd_record(cve: str) -> dict | None:
    p = MIRRORS / "nvd" / SNAP_DATE / "cves" / f"{cve}.json"
    if not p.exists():
        return None
    v = load_json(p).get("vulnerabilities") or []
    return v[0]["cve"] if v else None


def osv_record(cve: str) -> dict | None:
    p = MIRRORS / "osv" / SNAP_DATE / "vulns" / f"{cve}.json"
    if not p.exists():
        return None
    j = load_json(p)
    return None if j.get("_status") == 404 else j


def nvd_ranges(nvd: dict | None, src: str) -> list[dict]:
    out = []
    if not nvd:
        return out
    prods = CPE_PRODUCTS.get(src, set())
    for conf in nvd.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m["criteria"].split(":")
                if not m.get("vulnerable") or parts[2] != "a" or parts[4] not in prods:
                    continue
                r = {"cpe": m["criteria"]}
                for k in (
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ):
                    if m.get(k):
                        r[k] = m[k]
                out.append(r)
    return out


def norm_upstream(v: str) -> str:
    up = Version(v).upstream_version
    if "really" in up:
        up = up.split("really", 1)[1].lstrip("+")
    up = re.split(r"[+~]", up)[0]
    return up


def in_nvd_range(upstream: str, ranges: list[dict]) -> bool | None:
    """Whether a naive upstream comparison says 'vulnerable'. None if NVD has no usable range."""
    if not ranges:
        return None
    u = Version(upstream)
    for r in ranges:
        ver = r["cpe"].split(":")[5]
        bounds = [k for k in r if k.startswith("version")]
        if ver not in ("*", "-") and not bounds:
            if Version(ver.replace("_", "")) == u or ver == upstream:
                return True
            continue
        ok = True
        if "versionStartIncluding" in r and u < Version(r["versionStartIncluding"]):
            ok = False
        if "versionStartExcluding" in r and u <= Version(r["versionStartExcluding"]):
            ok = False
        if "versionEndExcluding" in r and u >= Version(r["versionEndExcluding"]):
            ok = False
        if "versionEndIncluding" in r and u > Version(r["versionEndIncluding"]):
            ok = False
        if ok:
            return True
    return False


# ---------------------------------------------------------------------------------------------- planning
def base_status_text(release: str) -> str:
    return (DATA / "base_images" / release / "rootfs" / "var" / "lib" / "dpkg" / "status").read_text()


def base_sources(release: str) -> set[str]:
    from debian.deb822 import Deb822

    return {src_of(dict(p))[0] for p in Deb822.iter_paragraphs(base_status_text(release).splitlines())}


def pick_binaries(src: str, release: str, pk: dict) -> list[str]:
    names = [b for b in BINARIES.get(src, []) if b in pk and src_of(pk[b])[0] == src]
    if not names:
        names = sorted(
            b
            for b, p in pk.items()
            if src_of(p)[0] == src and not re.search(r"-(dev|doc|dbg|dbgsym|tests?)$", b)
        )[:2]
    return names


def vulnerable_version(src: str, release: str, fixed: str) -> str | None:
    base = re.sub(INREL[release], "", fixed)
    cands = [
        v
        for v in snapshot_versions(src)
        if "bpo" not in v and Version(v) < Version(fixed) and (re.search(INREL[release], v) or v == base)
    ]
    return max(cands, key=Version) if cands else None


def plan_cve(
    sel: dict,
    tr_entry: dict,
    pks: dict,
    base_src: dict,
    preconds: dict,
    rng: random.Random,
    ranges: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Return (variant plans, skipped notes). A plan: release, variant, version (src version or None)."""
    src, cve = sel["src_package"], sel["cve"]
    plans, notes = [], []
    has_pre = cve in preconds
    v2_releases = []
    for rel in RELEASES:
        x = tr_entry["releases"].get(rel)
        if not x or not x.get("repositories") or not pick_binaries(src, rel, pks[rel]):
            notes.append({"cve": cve, "release": rel, "why": "src not in release / tracker"})
            continue
        repo_max = max(x["repositories"].values(), key=Version)
        fv = x.get("fixed_version")
        if x["status"] == "open":
            plans.append(
                {"release": rel, "variant": "V2", "version": repo_max, "version_source": "tracker-repo"}
            )
            v2_releases.append(rel)
        elif x["status"] == "resolved" and fv and fv != "0":
            if re.search(INREL[rel], fv):
                vv = vulnerable_version(src, rel, fv)
                if vv:
                    plans.append(
                        {"release": rel, "variant": "V2", "version": vv, "version_source": "snapshot"}
                    )
                    v2_releases.append(rel)
                else:
                    notes.append(
                        {"cve": cve, "release": rel, "why": "no in-release vulnerable snapshot version"}
                    )
            if Version(repo_max) >= Version(fv):
                inside = in_nvd_range(norm_upstream(repo_max), ranges)
                plans.append(
                    {
                        "release": rel,
                        "variant": "V4" if inside else "V3",
                        "version": repo_max,
                        "version_source": "tracker-repo",
                        "nvd_upstream_in_range": inside,
                    }
                )
        else:
            notes.append({"cve": cve, "release": rel, "why": f"status {x['status']} fixed {fv}"})
    if has_pre and v2_releases:
        rel = v2_releases[0]
        vv = next(p["version"] for p in plans if p["release"] == rel and p["variant"] == "V2")
        plans.append({"release": rel, "variant": "V5", "version": vv, "version_source": "same-as-V2"})
    absent_rel = [r for r in RELEASES if src not in base_src[r] and pick_binaries(src, r, pks[r])]
    if absent_rel:
        r1 = rng.choice(absent_rel)
        plans.append({"release": r1, "variant": "V1", "version": None, "version_source": None})
        dec_rel = [
            r
            for r in absent_rel
            if any(d in pks[r] and src_of(pks[r][d])[0] != src for d in DECOYS.get(src, []))
        ]
        if dec_rel:
            others = [r for r in dec_rel if r != r1] or dec_rel
            r6 = rng.choice(others)
            d = next(d for d in DECOYS[src] if d in pks[r6])
            plans.append(
                {
                    "release": r6,
                    "variant": "V6",
                    "version": None,
                    "decoy": d,
                    "version_source": "archive-current",
                }
            )
    else:
        notes.append({"cve": cve, "why": "src present in both base images: no V1/V6"})
    return plans, notes


# ------------------------------------------------------------------------------------------ host building
def status_stanza(p: dict, version: str, src: str, src_version: str, keep_relations: bool = False) -> str:
    """dpkg status stanza. Relationship fields (Depends, Breaks, ...) are only kept for base-image stanzas:
    for injected packages they would reference archive-current versions / packages not in the fixture."""
    fields = STATUS_FIELDS if keep_relations else [f for f in STATUS_FIELDS if f not in RELATION_FIELDS]
    d = dict(p)
    d["Status"] = "install ok installed"
    d.setdefault("Priority", "optional")
    d["Version"] = version
    if d["Package"] != src or version != src_version:
        d["Source"] = src if version == src_version else f"{src} ({src_version})"
    else:
        d.pop("Source", None)
    lines = []
    for k in fields:
        if k in d and str(d[k]).strip():
            val = str(d[k]).rstrip("\n")
            lines.append(f"{k}: {val}" if not val.startswith("\n") else f"{k}:{val}")
    return "\n".join(lines)


def write_status(
    rootfs: Path,
    release: str,
    pk: dict,
    src: str | None,
    src_version: str | None,
    extra_bins: list[str],
    decoy: str | None,
) -> None:
    from debian.deb822 import Deb822

    stanzas = {}
    for para in Deb822.iter_paragraphs(base_status_text(release).splitlines()):
        d = dict(para)
        s_name, s_ver = src_of(d)
        if src and src_version and s_name == src:
            # same-source base package: move it to the target version, keep its own relationships but
            # rewrite exact-version pins on sibling binaries "(= old)" -> "(= new)"
            for k in RELATION_FIELDS & set(d):
                d[k] = d[k].replace(f"(= {d['Version']})", f"(= {src_version})")
            stanzas[d["Package"]] = status_stanza(d, src_version, src, src_version, keep_relations=True)
        else:
            stanzas[d["Package"]] = para.dump().rstrip("\n")
    if src and src_version:
        for b in extra_bins:
            if b in stanzas and src_of(pk[b])[0] != src:
                continue
            p = pk[b]
            arch_ver = p["Version"]
            ver = arch_ver if src_of(p)[1] == src_version and arch_ver != src_version else src_version
            stanzas[b] = status_stanza(p, ver, src, src_version)
    if decoy:
        p = pk[decoy]
        s_name, s_ver = src_of(p)
        stanzas[decoy] = status_stanza(p, p["Version"], s_name, s_ver)
    path = rootfs / "var" / "lib" / "dpkg" / "status"
    path.unlink(missing_ok=True)
    path.write_text("\n\n".join(stanzas[k] for k in sorted(stanzas)) + "\n")


def copy_tree(src: Path, dst: Path) -> None:
    if src.exists():
        shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)


def symlink(target: str, link: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target)


def install_configs(rootfs: Path, release: str, bins: list[str]) -> None:
    dx = DEBX / release
    etc = rootfs / "etc"
    if "openssh-client" in bins:
        copy_tree(dx / "openssh-client" / "etc", etc)
    if "openssh-server" in bins:
        copy_tree(dx / "openssh-server" / "etc", etc)
        shutil.copy(dx / "openssh-server" / "usr/share/openssh/sshd_config", etc / "ssh" / "sshd_config")
    if "nginx" in bins or "nginx-common" in bins:
        copy_tree(dx / "nginx-common" / "etc", etc)
        symlink("/etc/nginx/sites-available/default", etc / "nginx/sites-enabled/default")
    if "samba" in bins or "samba-common" in bins:
        copy_tree(dx / "samba-common" / "etc", etc)
        copy_tree(dx / "samba" / "etc", etc)
        shutil.copy(dx / "samba-common" / "usr/share/samba/smb.conf", etc / "samba" / "smb.conf")
    if "apache2" in bins:
        copy_tree(dx / "apache2" / "etc", etc)
        for m in APACHE_DEFAULT_MODS:
            for ext in ("load", "conf"):
                if (etc / f"apache2/mods-available/{m}.{ext}").exists():
                    symlink(f"../mods-available/{m}.{ext}", etc / f"apache2/mods-enabled/{m}.{ext}")
        for c in APACHE_DEFAULT_CONFS:
            symlink(f"../conf-available/{c}.conf", etc / f"apache2/conf-enabled/{c}.conf")
        symlink("../sites-available/000-default.conf", etc / "apache2/sites-enabled/000-default.conf")
    if any(b.startswith("exim4") for b in bins):
        copy_tree(dx / "exim4-config" / "etc", etc)
        (etc / "exim4" / "update-exim4.conf.conf").write_text(
            "# /etc/exim4/update-exim4.conf.conf\n#\n# This is a Debian specific file\n\n"
            "dc_eximconfig_configtype='internet'\ndc_other_hostnames=''\n"
            "dc_local_interfaces='127.0.0.1 ; ::1'\n"
            "dc_readhost=''\ndc_relay_domains=''\ndc_minimaldns='false'\ndc_relay_nets=''\ndc_smarthost=''\n"
            "CFILEMODE='644'\ndc_use_split_config='true'\ndc_hide_mailname=''\ndc_mailname_in_oh='true'\n"
            "dc_localdelivery='mail_spool'\n"
        )
    if "bind9" in bins:
        copy_tree(dx / "bind9" / "etc", etc)
    if "sudo" in bins:
        copy_tree(dx / "sudo" / "etc", etc)
    if "postfix" in bins:
        copy_tree(dx / "postfix" / "etc", etc)
        shutil.copy(dx / "postfix" / "usr/share/postfix/main.cf.debian", etc / "postfix" / "main.cf")
        shutil.copy(dx / "postfix" / "usr/share/postfix/master.cf.dist", etc / "postfix" / "master.cf")


def _sub_line(path: Path, old: str, new: str) -> None:
    txt = path.read_text()
    assert old in txt, f"{old!r} not in {path}"
    path.unlink()
    path.write_text(txt.replace(old, new, 1))


def _insert_before_close(path: Path, lines: str) -> None:
    txt = path.read_text()
    i = txt.rindex("};")
    path.unlink()
    path.write_text(txt[:i] + lines + txt[i:])


def apply_precondition(rootfs: Path, cve: str, enabled: bool) -> None:
    """Write the curated configuration (vulnerable feature enabled / disabled) into the fixture."""
    etc = rootfs / "etc"
    if cve == "CVE-2024-6387":
        _sub_line(
            etc / "ssh/sshd_config",
            "#LoginGraceTime 2m",
            "LoginGraceTime 120" if enabled else "LoginGraceTime 0",
        )
    elif cve == "CVE-2021-41617":
        if enabled:
            _sub_line(
                etc / "ssh/sshd_config",
                "#AuthorizedKeysCommand none",
                "AuthorizedKeysCommand /usr/local/bin/get-keys %u",
            )
            _sub_line(
                etc / "ssh/sshd_config",
                "#AuthorizedKeysCommandUser nobody",
                "AuthorizedKeysCommandUser nobody",
            )
    elif cve == "CVE-2025-26465":
        _sub_line(
            etc / "ssh/ssh_config", "Host *\n", f"Host *\n    VerifyHostKeyDNS {'yes' if enabled else 'no'}\n"
        )
    elif cve == "CVE-2023-4091":
        with open(etc / "samba/smb.conf", "a") as f:
            f.write(
                "\n[projects]\n   comment = Project data (Windows ACLs)\n   path = /srv/samba/projects\n"
                "   read only = no\n   vfs objects = acl_xattr\n"
                f"   acl_xattr:ignore system acls = {'yes' if enabled else 'no'}\n"
            )
    elif cve == "CVE-2021-23017":
        if enabled:
            _sub_line(etc / "nginx/nginx.conf", "http {\n", "http {\n\tresolver 127.0.0.53;\n")
    elif cve == "CVE-2021-44142":
        objs = "catia fruit streams_xattr" if enabled else "catia streams_xattr"
        with open(etc / "samba/smb.conf", "a") as f:
            f.write(
                f"\n[shared]\n   comment = Team share (macOS clients)\n   path = /srv/samba/shared\n"
                f"   read only = no\n   vfs objects = {objs}\n"
            )
    elif cve in ("CVE-2023-25690", "CVE-2021-44224"):
        if enabled:
            for ext in ("load", "conf"):
                symlink(f"../mods-available/proxy.{ext}", etc / f"apache2/mods-enabled/proxy.{ext}")
            symlink("../mods-available/proxy_http.load", etc / "apache2/mods-enabled/proxy_http.load")
            if cve == "CVE-2021-44224":
                _sub_line(
                    etc / "apache2/mods-available/proxy.conf", "\n#ProxyRequests On\n", "\nProxyRequests On\n"
                )
            else:
                symlink("../mods-available/rewrite.load", etc / "apache2/mods-enabled/rewrite.load")
                _sub_line(
                    etc / "apache2/sites-available/000-default.conf",
                    "</VirtualHost>",
                    '\tRewriteEngine on\n\tRewriteRule "^/app/(.*)" "http://127.0.0.1:8080/app?$1" [P]\n'
                    "</VirtualHost>",
                )
    elif cve in ("CVE-2023-42115", "CVE-2023-42116"):
        ext = cve == "CVE-2023-42115"
        name, drv, pub = ("ext_auth", "external", "EXTERNAL") if ext else ("spa_server", "spa", "NTLM")
        body = [f"{name}:", f"  driver = {drv}", f"  public_name = {pub}"]
        body += (
            ["  server_param2 = ${tls_in_peerdn}", "  server_condition = true"]
            if ext
            else ["  server_password = ${lookup{$auth1}lsearch{CONFDIR/passwd}{$value}fail}"]
        )
        if not enabled:
            body = ["# " + b for b in body]
        p = etc / f"exim4/conf.d/auth/50_local_{'external' if ext else 'spa'}"
        p.write_text("# Site-local authenticators (added by ops)\n" + "\n".join(body) + "\n")
    elif cve == "CVE-2023-42117":
        line = "hosts_proxy = 10.0.0.0/8"
        (etc / "exim4/conf.d/main/05_local_proxy").write_text(
            "# Accept PROXY protocol from the load balancer subnet\n"
            + (line if enabled else "# " + line)
            + "\n"
        )
    elif cve in ("CVE-2023-2911", "CVE-2025-40777"):
        to = "0" if enabled else "off"
        _insert_before_close(
            etc / "bind/named.conf.options",
            f"\n\tstale-answer-enable yes;\n\tstale-answer-client-timeout {to};\n",
        )
    elif cve == "CVE-2019-18634":
        (etc / "sudoers.d").mkdir(parents=True, exist_ok=True)
        (etc / "sudoers.d/pwfeedback").write_text(
            "Defaults pwfeedback\n" if enabled else "Defaults !pwfeedback\n"
        )
    else:
        raise KeyError(f"no fixture writer for precondition {cve}")


_CHANGELOG_CACHE: dict[str, list] = {}


def changelog_blocks(src: str) -> list:
    """All changelog blocks for src from the mirrored metadata.ftp-master changelogs (deduped by version)."""
    from debian.changelog import Changelog

    if src in _CHANGELOG_CACHE:
        return _CHANGELOG_CACHE[src]
    blocks, seen = [], set()
    d = MIRRORS / "debian_changelogs" / SNAP_DATE / "raw" / src
    for f in sorted(d.glob("*_changelog")) if d.exists() else []:
        raw = f.read_text(errors="replace")
        if raw.startswith('{"_status"'):
            continue
        for b in Changelog(raw, strict=False):
            try:
                v = str(b.version)
            except ValueError:  # ancient malformed versions deep in the history
                continue
            if v not in seen:
                seen.add(v)
                blocks.append(b)
    _CHANGELOG_CACHE[src] = blocks
    return blocks


def changelog_text(src: str, version: str, release: str, maintainer: str) -> tuple[str, bool]:
    """(changelog.Debian text for the installed version, synthesized?)."""
    blocks = changelog_blocks(src)
    blk = next((b for b in blocks if str(b.version) == version), None)
    if blk is not None:
        lines = [ln.rstrip() for ln in blk.changes() if ln.strip() and not ln.startswith("  [")]
        first = next((i for i, ln in enumerate(lines) if ln.startswith("  * ")), 0)
        bullets = [ln for ln in lines[first:] if ln.startswith("  ")][:3]
        bullets = [b if len(b) <= 160 else b[:157] + "..." for b in bullets] or ["  * Security update."]
        head = f"{src} ({version}) {blk.distributions}; urgency={blk.urgency}"
        return f"{head}\n\n" + "\n".join(bullets) + f"\n\n -- {blk.author}  {blk.date}\n", False
    dist = f"{release}-security" if re.search(INREL[release], version) else release
    older = [b for b in blocks if Version(str(b.version)) < Version(version)]
    date = (
        max(older, key=lambda b: Version(str(b.version))).date if older else "Mon, 05 Jan 2026 00:00:00 +0000"
    )
    text = f"{src} ({version}) {dist}; urgency=medium\n\n  * Security update.\n\n -- {maintainer}  {date}\n"
    return text, True


def write_changelogs(rootfs: Path, bins: list[str], src: str, version: str, release: str, pk: dict) -> bool:
    synth = False
    for b in bins:
        maint = pk[b]["Maintainer"] if b in pk else "Debian Maintainers <debian-devel@lists.debian.org>"
        text, s = changelog_text(src, version, release, maint)
        synth |= s
        d = rootfs / "usr" / "share" / "doc" / b
        d.mkdir(parents=True, exist_ok=True)
        (d / "changelog.Debian").write_text(text)
    return synth


def host_ids(case_id: str, family: str) -> tuple[str, str]:
    h = hashlib.sha1(f"{SEED}|{case_id}".encode()).hexdigest()
    return f"h_{h[:12]}", f"srv-{FAMILY_SHORT[family]}-{h[12:18]}"


def build_case(job: dict) -> dict:
    """Build one host fixture + host.json; return the case row (with label) or a failure record."""
    sel, plan, ctx = job["sel"], job["plan"], job["ctx"]
    cve, src, rel, var = sel["cve"], sel["src_package"], plan["release"], plan["variant"]
    case_id = f"D1-{cve}-{rel}-{var}"
    host_id, hostname = host_ids(case_id, sel["family"])
    hdir = HOSTS / host_id
    rootfs = hdir / "rootfs"
    if rootfs.exists():
        shutil.rmtree(rootfs)
    hdir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(DATA / "base_images" / rel / "rootfs", rootfs, symlinks=True)
    pk = ctx["pks"][rel]
    bins = pick_binaries(src, rel, pk) if plan["version"] else []
    write_status(rootfs, rel, pk, src if plan["version"] else None, plan["version"], bins, plan.get("decoy"))
    (rootfs / "etc" / "hostname").unlink(missing_ok=True)
    (rootfs / "etc" / "hostname").write_text(hostname + "\n")
    pre = ctx["preconds"].get(cve)
    if bins:
        install_configs(rootfs, rel, bins)
        if pre:
            apply_precondition(rootfs, cve, enabled=(var != "V5"))
    trel = ctx["tracker"][src][cve]["releases"].get(rel)
    synth = False
    if plan["version"]:
        from label_live import installed_src_version, parse_status

        _, all_bins = installed_src_version(parse_status(rootfs), src)
        synth = write_changelogs(rootfs, all_bins, src, plan["version"], rel, pk)
    if plan.get("decoy"):
        d_src, d_ver = src_of(pk[plan["decoy"]])
        synth = write_changelogs(rootfs, [plan["decoy"]], d_src, d_ver, rel, pk)
    installed, inst_bins, atoms, label = label_host(rootfs, cve, src, trel, ctx["preconds"])
    exp = EXPECTED[var]
    if (label["status"], label["justification"]) != exp:
        return {"failure": True, "case_id": case_id, "why": f"label {label} != expected {exp}", "plan": plan}
    # ---- host.json
    rng = random.Random(f"{SEED}|host|{case_id}")
    services, procs = {}, [{"pid": 1, "user": "root", "cmd": "/sbin/init"}]
    pid = 300 + rng.randrange(400)
    for b in inst_bins:
        if b in SERVICES:
            name, unit, cmd, cfgs = SERVICES[b]
            cfgs = list(cfgs)
            if pre and pre.get("service") == name and pre["file"] not in cfgs:
                cfgs.append(pre["file"])
            services[name] = {
                "unit": unit,
                "active": True,
                "package": b,
                "config_files": [c for c in cfgs if (rootfs / c).exists() or (rootfs / c).is_symlink()],
            }
            pid += rng.randrange(5, 60)
            procs.append({"pid": pid, "user": "root", "cmd": cmd, "unit": unit})
    stale = rng.random() < 0.2
    cmdb_bins = inst_bins or ctx["pk_bins"](src, rel)
    if not stale:
        cmdb_ver = installed
        sw = [{"name": b, "version": installed} for b in inst_bins]
    else:
        alt = job["alt_version"]
        cmdb_ver = alt
        sw = [{"name": b, "version": alt} for b in cmdb_bins] if alt else []
    if plan.get("decoy"):
        sw.append({"name": plan["decoy"], "version": pk[plan["decoy"]]["Version"]})
    for b in ("base-files", "libc6", "bash"):
        if b not in {s["name"] for s in sw}:
            bp = next((p for p in [ctx["base_pk"][rel].get(b)] if p), None)
            if bp:
                sw.append({"name": b, "version": bp})
    month = rng.randrange(1, 9) if stale else 9
    last_sync = f"2026-{month:02d}-{rng.randrange(1, 28):02d}T0{rng.randrange(0, 9)}:00:00Z"
    if month == 9 and last_sync[:10] > "2026-10-04":
        last_sync = "2026-10-04T03:00:00Z"
    has_ticket = rng.random() < 0.5
    ticket = (
        {
            "id": f"CHG-2026{rng.randrange(10000, 99999)}",
            "approved": rng.random() < 0.75,
            "window_open": rng.random() < 0.5,
        }
        if has_ticket
        else None
    )
    host = {
        "host_id": host_id,
        "hostname": hostname,
        "release": rel,
        "services": services,
        "processes": procs,
        "cmdb": {
            "asset": hostname,
            "os": f"Debian {RELEASE_NUM[rel]}",
            "software": sw,
            "last_sync": last_sync,
            "notes": rng.choice(
                [
                    "imported from asset inventory",
                    "owner: platform team",
                    "prod tier 2",
                    "managed by config management",
                ]
            ),
        },
        "cmdb_stale": stale,
        "change": {"ticket": ticket},
        "rollback_available": rng.random() < 0.5,
    }
    (hdir / "host.json").write_text(json.dumps(host, indent=1))
    row = {
        "case_id": case_id,
        "cve": cve,
        "src_package": src,
        "binary_packages": inst_bins or bins or pick_binaries(src, rel, pk),
        "distro": "debian",
        "release": rel,
        "variant": var,
        "host_id": host_id,
        "family": sel["family"],
        "split": sel["split"],
        "temporal_holdout": sel["temporal_holdout"],
        "kev": sel["kev"],
        "base_image": ctx["images"][rel],
        "installed_version": installed,
        "label": label,
        "atoms": atoms,
        "label_provenance": PROVENANCE,
    }
    meta = {
        "host_id": host_id,
        "case_id": case_id,
        "cmdb_stale": stale,
        "cmdb_version": cmdb_ver,
        "true_installed_version": installed,
        "version_source": plan.get("version_source"),
        "decoy": plan.get("decoy"),
        "changelog_synthesized": synth,
        "nvd_upstream_in_range": plan.get("nvd_upstream_in_range"),
    }
    return {"row": row, "meta": meta}


# -------------------------------------------------------------------------------------------------- main
def main() -> None:
    selected = load_json(D1 / "selected_cves.json")
    tracker_all = load_json(MIRRORS / "debian_tracker" / SNAP_DATE / "raw" / "tracker.json")
    tracker = {}
    for s in selected:
        tracker.setdefault(s["src_package"], {})[s["cve"]] = tracker_all[s["src_package"]][s["cve"]]
    del tracker_all
    (D1 / "tracker_entries.json").write_text(json.dumps(tracker, indent=1, sort_keys=True))
    preconds = load_preconditions()
    pks = {r: load_packages(r) for r in RELEASES}
    base_src = {r: base_sources(r) for r in RELEASES}
    from debian.deb822 import Deb822

    base_pk = {
        r: {
            dict(p)["Package"]: dict(p)["Version"]
            for p in Deb822.iter_paragraphs(base_status_text(r).splitlines())
        }
        for r in RELEASES
    }
    images = {r: load_json(DATA / "base_images" / r / "IMAGE.json")["reference"] for r in RELEASES}
    ctx = {
        "tracker": tracker,
        "preconds": preconds,
        "pks": pks,
        "images": images,
        "base_pk": base_pk,
        "pk_bins": lambda src, rel: pick_binaries(src, rel, pks[rel]),
    }

    jobs, metas, notes = [], [], []
    for s in selected:
        rng = random.Random(f"{SEED}|{s['cve']}")
        nvd = nvd_record(s["cve"])
        ranges = nvd_ranges(nvd, s["src_package"])
        plans, nts = plan_cve(s, tracker[s["src_package"]][s["cve"]], pks, base_src, preconds, rng, ranges)
        notes += nts
        by_rel = {}
        for p in plans:
            by_rel.setdefault(p["release"], {})[p["variant"]] = p["version"]
        for p in plans:
            vs = by_rel.get(p["release"], {})
            if p["variant"] in ("V2", "V5"):
                alt = vs.get("V3") or vs.get("V4")
            elif p["variant"] in ("V3", "V4"):
                alt = vs.get("V2")
            else:  # absent now; earlier state had the package at the current archive version
                trel = tracker[s["src_package"]][s["cve"]]["releases"].get(p["release"], {})
                repos = trel.get("repositories") or {}
                alt = max(repos.values(), key=Version) if repos else None
            jobs.append({"sel": s, "plan": p, "ctx": ctx, "alt_version": alt})
        osv = osv_record(s["cve"])
        osv_ids = sorted(set((osv or {}).get("aliases", []) + (osv or {}).get("related", []))) if osv else []
        desc = ""
        if nvd:
            desc = next((d["value"] for d in nvd.get("descriptions", []) if d["lang"] == "en"), "")
        desc = desc or tracker[s["src_package"]][s["cve"]].get("description", "")
        pre = preconds.get(s["cve"])
        deb = {}
        for r in RELEASES:
            x = tracker[s["src_package"]][s["cve"]]["releases"].get(r)
            if x:
                deb[r] = {
                    "status": x["status"],
                    "fixed_version": x.get("fixed_version"),
                    "urgency": x.get("urgency"),
                }
        metas.append(
            {
                "cve": s["cve"],
                "src_package": s["src_package"],
                "family": s["family"],
                "published": (nvd or {}).get("published", "")[:10] or s.get("published"),
                "kev": s["kev"],
                "epss": s.get("epss"),
                "description": desc,
                "debian": deb,
                "nvd_ranges": ranges,
                "osv_ids": osv_ids,
                "config_precondition": None
                if not pre
                else {
                    "file": pre["file"],
                    "key": pre["key"],
                    "vulnerable_when": pre["vulnerable_when"],
                    "safe_value": pre["safe_setting"],
                    "source": pre["advisory_url"],
                    "service": pre.get("service"),
                    "predicate": pre["predicate"],
                },
                "split": s["split"],
                "temporal_holdout": s["temporal_holdout"],
            }
        )

    HOSTS.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(24) as ex:
        results = list(ex.map(build_case, jobs))
    rows = [r["row"] for r in results if "row" in r]
    failures = [r for r in results if r.get("failure")] + [{"note": n} for n in notes]
    hmeta = [r["meta"] for r in results if "meta" in r]
    # drop hosts of failed cases
    for r in results:
        if r.get("failure"):
            hid, _ = host_ids(
                r["case_id"],
                next(
                    j["sel"]["family"]
                    for j in jobs
                    if f"D1-{j['sel']['cve']}-{j['plan']['release']}-{j['plan']['variant']}" == r["case_id"]
                ),
            )
            shutil.rmtree(HOSTS / hid, ignore_errors=True)
    built_cves = {r["cve"] for r in rows}
    metas = [m for m in metas if m["cve"] in built_cves]
    write_jsonl(D1 / "cve_meta.jsonl", metas)
    write_jsonl(D1 / "hosts_meta.jsonl", hmeta)
    write_jsonl(D1 / "build_failures.jsonl", failures)
    rows.sort(key=lambda r: r["case_id"])
    for split in ("dev", "calib"):
        write_jsonl(D1 / "cases" / f"{split}.jsonl", [r for r in rows if r["split"] == split])
    test = [r for r in rows if r["split"] == "test"]
    write_jsonl(
        D1 / "cases" / "test.jsonl",
        [{k: v for k, v in r.items() if k not in ("label", "atoms")} for r in test],
    )
    sealed = DATA / "sealed" / "test_labels.jsonl"
    write_jsonl(sealed, [{"case_id": r["case_id"], "label": r["label"], "atoms": r["atoms"]} for r in test])
    (DATA / "sealed" / "SHA256").write_text(f"{sha256_file(sealed)}  data/sealed/test_labels.jsonl\n")
    # remove stale host dirs from earlier builds
    keep = {r["host_id"] for r in rows}
    for d in HOSTS.iterdir():
        if d.name not in keep:
            shutil.rmtree(d)
    print(
        f"cases={len(rows)} cves={len(built_cves)} failures={sum(1 for r in results if r.get('failure'))} "
        f"notes={len(notes)}"
    )


if __name__ == "__main__":
    main()
