"""Validate D1 against docs/DATA_CONTRACT.md and print summary statistics (dev+calib only for scanners).

Exit code 1 if any hard check fails. Never reads labels of test cases except to verify the seal
(hash + case-id coverage + recomputation consistency); no metrics are computed on test.
"""

from __future__ import annotations

import collections
import hashlib
import json
import re
import sys
from pathlib import Path

from debian.deb822 import Deb822
from debian.debian_support import Version

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, read_jsonl  # noqa: E402
from label_live import label_from_atoms, label_host, load_preconditions  # noqa: E402

D1 = DATA / "d1"
CASE_FIELDS = ["case_id", "cve", "src_package", "binary_packages", "distro", "release", "variant", "host_id",
               "family", "split", "temporal_holdout", "kev", "base_image", "installed_version", "label", "atoms",
               "label_provenance"]
ATOM_FIELDS = {"present", "in_affected_range", "fix_applied", "vuln_config_enabled", "req_config"}
META_FIELDS = ["cve", "src_package", "family", "published", "kev", "epss", "description", "debian",
               "nvd_ranges", "osv_ids", "config_precondition", "split", "temporal_holdout"]
HOST_FIELDS = ["host_id", "hostname", "release", "services", "cmdb", "cmdb_stale", "change", "rollback_available"]
STATUS_REQUIRED = ["Package", "Status", "Priority", "Section", "Installed-Size", "Maintainer", "Architecture",
                   "Version", "Description"]
DAEMONS = {"openssh-server", "apache2", "nginx", "bind9", "exim4-daemon-light", "postfix", "samba", "polkitd"}
STATUSES = {"affected", "not_affected", "fixed"}
JUSTIFICATIONS = {None, "component_not_present", "vulnerable_code_not_present", "requires_configuration"}


class Checker:
    def __init__(self):
        self.errors: list[str] = []
        self.n = collections.Counter()

    def check(self, cond: bool, msg: str, key: str) -> None:
        self.n[key] += 1
        if not cond:
            self.errors.append(f"[{key}] {msg}")


_SCAN_CACHE: dict[str, dict] = {}


def scanner_cves(sdir: Path) -> dict[str, dict[str, set[str]]]:
    key = str(sdir)
    if key not in _SCAN_CACHE:
        _SCAN_CACHE[key] = _scanner_cves(sdir)
    return _SCAN_CACHE[key]


def _scanner_cves(sdir: Path) -> dict[str, dict[str, set[str]]]:
    """scanner -> {CVE -> set(package names)} from raw outputs."""
    out = {"trivy": {}, "grype": {}, "osv": {}}
    t = json.loads((sdir / "trivy.json").read_text())
    for r in t.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            out["trivy"].setdefault(v["VulnerabilityID"], set()).add(v["PkgName"])
    g = json.loads((sdir / "grype.json").read_text())
    for m in g.get("matches") or []:
        ids = {m["vulnerability"]["id"]} | {x["id"] for x in m.get("relatedVulnerabilities") or []}
        for i in ids:
            out["grype"].setdefault(i, set()).add(m["artifact"]["name"])
    o = json.loads((sdir / "osv.json").read_text())
    for r in o.get("results") or []:
        for p in r.get("packages") or []:
            name = p["package"]["name"]
            for grp in p.get("groups") or []:
                for i in grp.get("aliases", []) + grp.get("ids", []):
                    out["osv"].setdefault(re.sub(r"^DEBIAN-", "", i), set()).add(name)
    return out


def main() -> int:
    c = Checker()
    pre = load_preconditions()
    tracker = json.loads((D1 / "tracker_entries.json").read_text())
    meta = {m["cve"]: m for m in read_jsonl(D1 / "cve_meta.jsonl")}
    sealed_path = DATA / "sealed" / "test_labels.jsonl"
    sealed = {r["case_id"]: r for r in read_jsonl(sealed_path)}
    cases = {s: read_jsonl(D1 / "cases" / f"{s}.jsonl") for s in ("dev", "calib", "test")}

    # ---- cve_meta
    for m in meta.values():
        c.check(list(m.keys()) == META_FIELDS, f"cve_meta fields {m['cve']}: {list(m.keys())}", "meta.fields")
        c.check(m["split"] in ("dev", "calib", "test"), f"meta split {m['cve']}", "meta.split")
        for r, d in m["debian"].items():
            c.check(set(d) == {"status", "fixed_version", "urgency"}, f"meta debian {m['cve']} {r}", "meta.debian")
        c.check((D1 / "advisories" / f"{m['cve']}.json").exists(), f"advisory missing {m['cve']}", "advisory")
        adv = json.loads((D1 / "advisories" / f"{m['cve']}.json").read_text())
        c.check(set(adv) == {"nvd", "osv", "kev", "debian"} and all(len(v) <= 6000 for v in adv.values()),
                f"advisory format {m['cve']}", "advisory")

    # ---- splits disjoint by CVE
    split_cves = {s: {r["cve"] for r in rows} for s, rows in cases.items()}
    for a, b in (("dev", "calib"), ("dev", "test"), ("calib", "test")):
        c.check(not (split_cves[a] & split_cves[b]), f"CVE overlap {a}/{b}", "splits.disjoint")
    for s, rows in cases.items():
        for r in rows:
            c.check(meta[r["cve"]]["split"] == s == r["split"], f"split mismatch {r['case_id']}", "splits.meta")

    # ---- seal
    c.check(all("label" not in r and "atoms" not in r for r in cases["test"]), "label fields in test.jsonl",
            "seal.no_labels")
    c.check({r["case_id"] for r in cases["test"]} == set(sealed), "sealed ids != test ids", "seal.ids")
    want = (DATA / "sealed" / "SHA256").read_text().split()[0]
    c.check(hashlib.sha256(sealed_path.read_bytes()).hexdigest() == want, "sealed sha256 mismatch", "seal.hash")

    # ---- cases
    seen_ids = set()
    for s, rows in cases.items():
        for r in rows:
            cid = r["case_id"]
            exp_fields = CASE_FIELDS if s != "test" else [f for f in CASE_FIELDS if f not in ("label", "atoms")]
            c.check(list(r.keys()) == exp_fields, f"fields {cid}: {list(r.keys())}", "case.fields")
            c.check(cid not in seen_ids, f"duplicate {cid}", "case.unique")
            seen_ids.add(cid)
            c.check(cid == f"D1-{r['cve']}-{r['release']}-{r['variant']}", f"case_id format {cid}", "case.id")
            c.check(r["variant"] in {"V1", "V2", "V3", "V4", "V5", "V6"}, f"variant {cid}", "case.variant")
            c.check(r["distro"] == "debian" and r["release"] in ("bookworm", "trixie"), f"release {cid}",
                    "case.release")
            img = json.loads((DATA / "base_images" / r["release"] / "IMAGE.json").read_text())["reference"]
            c.check(r["base_image"] == img, f"base_image {cid}", "case.base_image")
            c.check(r["temporal_holdout"] == meta[r["cve"]]["temporal_holdout"] and r["kev"] == meta[r["cve"]]["kev"],
                    f"meta flags {cid}", "case.meta_flags")
            lab = r if s != "test" else sealed[cid]
            atoms, label = lab["atoms"], lab["label"]
            c.check(set(atoms) == ATOM_FIELDS and all(isinstance(v, bool) for v in atoms.values()),
                    f"atoms {cid}", "case.atoms")
            c.check(label["status"] in STATUSES and label["justification"] in JUSTIFICATIONS, f"label enum {cid}",
                    "case.label_enum")
            c.check(label_from_atoms(atoms) == label, f"label != table(atoms) {cid}", "case.label_from_atoms")
            hdir = D1 / "hosts" / r["host_id"]
            rootfs = hdir / "rootfs"
            trel = tracker[r["src_package"]][r["cve"]]["releases"].get(r["release"])
            inst, bins, atoms2, label2 = label_host(rootfs, r["cve"], r["src_package"], trel, pre)
            c.check(atoms2 == atoms and label2 == label, f"recomputed label/atoms differ {cid}", "case.recompute")
            c.check(inst == r["installed_version"], f"installed_version {cid}", "case.installed_version")
            c.check(atoms["req_config"] == (r["cve"] in pre), f"req_config {cid}", "case.req_config")
            # variant semantics
            fv = (trel or {}).get("fixed_version")
            if r["variant"] in ("V1", "V6"):
                c.check(inst is None, f"V1/V6 has src installed {cid}", "variant.absent")
            elif r["variant"] in ("V2", "V5"):
                c.check(inst is not None and (not fv or fv == "0" or Version(inst) < Version(fv)) and
                        atoms["in_affected_range"], f"V2/V5 not vulnerable {cid}", "variant.vulnerable")
            else:
                c.check(inst is not None and fv and Version(inst) >= Version(fv), f"V3/V4 not fixed {cid}",
                        "variant.fixed")
            # dpkg status syntax
            with open(rootfs / "var/lib/dpkg/status", encoding="utf-8") as f:
                paras = list(Deb822.iter_paragraphs(f, use_apt_pkg=False))
            names = [p["Package"] for p in paras]
            c.check(len(names) == len(set(names)), f"duplicate packages in status {cid}", "dpkg.unique")
            for p in paras:
                missing = [k for k in STATUS_REQUIRED if k not in p]
                c.check(not missing, f"status stanza {p.get('Package')} missing {missing} {cid}", "dpkg.fields")
                try:
                    Version(p["Version"])
                    ok = True
                except Exception:  # noqa: BLE001
                    ok = False
                c.check(ok and p["Status"] == "install ok installed", f"bad version/status {p['Package']} {cid}",
                        "dpkg.version")
            # changelogs for the installed target binaries
            for b in bins:
                cl = rootfs / "usr/share/doc" / b / "changelog.Debian"
                first = cl.read_text().splitlines()[0] if cl.exists() else ""
                c.check(first.startswith(f"{r['src_package']} ({inst}) "), f"changelog header {b} {cid}",
                        "changelog")
            # host.json
            host = json.loads((hdir / "host.json").read_text())
            c.check(all(k in host for k in HOST_FIELDS) and host["host_id"] == r["host_id"], f"host.json {cid}",
                    "host.fields")
            installed_names = set(names)
            svc_pkgs = {v["package"] for v in host["services"].values()}
            c.check(svc_pkgs <= installed_names, f"service for non-installed package {cid}", "host.services")
            c.check((installed_names & DAEMONS) <= svc_pkgs, f"daemon without service {cid}", "host.services")
            for v in host["services"].values():
                c.check(set(v) == {"unit", "active", "package", "config_files"}, f"service fields {cid}",
                        "host.services")
            for f in ("trivy", "grype", "osv"):
                p = hdir / "scans" / f"{f}.json"
                ok = p.exists() and p.stat().st_size > 0
                if ok:
                    try:
                        json.loads(p.read_text())
                    except json.JSONDecodeError:
                        ok = False
                c.check(ok, f"scan {f} missing/invalid {cid}", f"scan.{f}")
    print("== validation checks")
    for k in sorted(c.n):
        nerr = sum(1 for e in c.errors if e.startswith(f"[{k}]"))
        print(f"  {k:28s} {c.n[k]:6d} checks  {nerr:4d} errors")
    for e in c.errors[:40]:
        print("  ERROR", e)
    print(f"TOTAL errors: {len(c.errors)}")
    report_stats(cases, meta)
    return 1 if c.errors else 0


def report_stats(cases: dict, meta: dict) -> None:
    allrows = [r for rows in cases.values() for r in rows]
    print("\n== cases per split x variant")
    tab = collections.Counter((r["split"], r["variant"]) for r in allrows)
    vs = ["V1", "V2", "V3", "V4", "V5", "V6"]
    print("  split  " + " ".join(f"{v:>5s}" for v in vs) + "  total")
    for s in ("dev", "calib", "test"):
        print(f"  {s:6s} " + " ".join(f"{tab[(s, v)]:5d}" for v in vs) + f"  {sum(tab[(s, v)] for v in vs):5d}")
    print("\n== cases per split x family x release")
    fam = collections.Counter((r["split"], r["family"], r["release"]) for r in allrows)
    fams = sorted({r["family"] for r in allrows})
    print("  family          " + "  ".join(f"{s}:bw/tx" for s in ("dev", "calib", "test")))
    for f in fams:
        print(f"  {f:15s} " + "  ".join(f"{fam[(s, f, 'bookworm')]:6d}/{fam[(s, f, 'trixie')]:<3d}"
                                        for s in ("dev", "calib", "test")))
    print("\n== CVEs per split (temporal hold-out = published >= 2026-05-01, KEV)")
    for s in ("dev", "calib", "test"):
        ms = [m for m in meta.values() if m["split"] == s]
        th = sum(m["temporal_holdout"] for m in ms)
        print(f"  {s:6s} cves={len(ms):3d} temporal_holdout={th:3d} ({th / max(1, len(ms)):.0%}) "
              f"kev={sum(m['kev'] for m in ms)} config_gated={sum(bool(m['config_precondition']) for m in ms)}")
    print("\n== natural scanner-vs-tracker disagreement (dev+calib only; scanner flags CVE on host vs label)")
    for scanner in ("trivy", "grype", "osv"):
        n = dis = fp = fn = 0
        by_var = collections.Counter()
        for r in cases["dev"] + cases["calib"]:
            sdir = D1 / "hosts" / r["host_id"] / "scans"
            if not (sdir / f"{scanner}.json").exists():
                continue
            flagged = r["cve"] in scanner_cves(sdir)[scanner]
            truth = r["label"]["status"] == "affected"
            n += 1
            if flagged != truth:
                dis += 1
                fp += flagged and not truth
                fn += truth and not flagged
                by_var[r["variant"]] += 1
        print(f"  {scanner:6s} n={n} disagree={dis} ({dis / max(1, n):.1%}) flagged_not_affected={fp} "
              f"missed_affected={fn} by_variant={dict(sorted(by_var.items()))}")


if __name__ == "__main__":
    sys.exit(main())
