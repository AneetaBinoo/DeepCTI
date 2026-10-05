"""Validate D7 (DeepCTI-Live-X) against docs/DATA_CONTRACT_V3.md + docs/DATA_CONTRACT.md; print statistics.

Exit code 1 if any hard check fails. Test labels are only read to verify the seal (hash, id coverage,
recomputation consistency); no metric is computed on test. Scanner-vs-label disagreement is reported for
dev+calib only.
"""

from __future__ import annotations

import collections
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path

from debian.deb822 import Deb822

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_d7 import (  # noqa: E402
    EXPECTED,
    full_semantics,
    maven_versions,
    pypi_versions,
    ub_pick_binaries,
    vendor_versions,
)
from common import DATA, read_jsonl  # noqa: E402
from d7common import D7, TEMPORAL_CUTOFF, UBUNTU_RELEASES, V, load_json, mirror, osv_records  # noqa: E402
from label_d7 import case_ranges, label_host, load_preconditions_v3  # noqa: E402
from label_live import label_from_atoms  # noqa: E402
from select_d7 import lp_versions  # noqa: E402

ECOS = ("deb-ubuntu", "pypi", "maven", "vendor")
VARIANTS = ("V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8")
CASE_FIELDS = ["case_id", "cve", "ecosystem", "component", "aliases", "install_paths", "src_package",
               "binary_packages", "distro", "release", "variant", "host_id", "family", "split", "temporal_holdout",
               "kev", "base_image", "installed_version", "label", "atoms", "label_provenance"]
ATOM_FIELDS = {"present", "in_affected_range", "fix_applied", "vuln_config_enabled", "req_config"}
META_FIELDS = ["cve", "ecosystem", "component", "aliases", "src_package", "family", "published", "kev", "epss",
               "description", "ranges", "nvd_ranges", "osv_ids", "config_precondition", "split", "temporal_holdout"]
HOST_FIELDS = ["host_id", "hostname", "release", "services", "processes", "cmdb", "cmdb_stale", "change",
               "rollback_available", "apps"]
STATUS_JUST = {("not_affected", "component_not_present"), ("not_affected", "vulnerable_code_not_present"),
               ("not_affected", "requires_configuration"), ("affected", None), ("fixed", None)}
# version-comparator sanity pairs: (ecosystem, a, b, expected sign of compare(a, b))
KNOWN_PAIRS = [
    ("maven", "2.14.1", "2.15.0", -1), ("maven", "2.0-beta9", "2.0", -1), ("maven", "2.12.2", "2.15.0", -1),
    ("maven", "5.2.20.RELEASE", "5.3.0", -1), ("maven", "4.1.100.Final", "4.1.99.Final", 1),
    ("maven", "2.5.10.1", "2.5.10", 1), ("maven", "1.2.17", "1.2.9", 1),
    ("pypi", "1.0rc1", "1.0", -1), ("pypi", "2.2.2", "2.10.0", -1), ("pypi", "3.0.0a1", "3.0.0", -1),
    ("pypi", "2.9.0.post0", "2.9.0", 1), ("pypi", "1.26.19", "2.0.0", -1),
    ("deb-ubuntu", "1:9.2p1-2ubuntu0.1", "1:9.2p1-2", 1), ("deb-ubuntu", "1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.7", 1),
    ("deb-ubuntu", "2.35-0ubuntu3.4", "2.35-0ubuntu3.10", -1), ("deb-ubuntu", "1.2.3~rc1-1", "1.2.3-1", -1),
    ("deb-ubuntu", "1:2.34.1-1ubuntu1.12", "2:0.1", -1),
    ("vendor", "9.0.40", "9.0.41", -1), ("vendor", "9.0.100", "9.0.99", 1), ("vendor", "2.426.3", "2.441", -1),
    ("vendor", "2.555.3", "2.556", -1), ("vendor", "1.6.9", "1.6.10", -1), ("vendor", "18.10.7", "18.9.7", 1),
    ("vendor", "2.4.49", "2.4.50", -1), ("vendor", "10.1.0-M1", "10.1.0", -1),
]
# known comparator limitations (reported, not fatal): (ecosystem, a, b, correct sign)
KNOWN_LIMITS = [("vendor", "9.0.0.M1", "9.0.0", -1), ("vendor", "9.0.0.M22", "9.0.0.M3", 1)]

errors: dict[str, list[str]] = collections.defaultdict(list)
checks: collections.Counter = collections.Counter()
warnings: list[str] = []


def check(name: str, ok: bool, msg: str = "") -> None:
    checks[name] += 1
    if not ok:
        errors[name].append(msg)


def jar_ok(data: bytes, where: str) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            check("jar.zip", z.testzip() is None, f"{where}: corrupt member")
            names = z.namelist()
            check("jar.manifest", "META-INF/MANIFEST.MF" in names, f"{where}: no MANIFEST.MF")
            check("jar.pom", any(n.startswith("META-INF/maven/") and n.endswith("pom.properties") for n in names),
                  f"{where}: no pom.properties")
            for n in names:
                if n.endswith(".jar"):
                    zi = z.getinfo(n)
                    check("jar.nested_stored", zi.compress_type == zipfile.ZIP_STORED, f"{where}!/{n} compressed")
                    jar_ok(z.read(n), f"{where}!/{n}")
    except zipfile.BadZipFile:
        check("jar.zip", False, f"{where}: not a zip")


def path_exists(rootfs: Path, p: str) -> bool:
    if "!/" in p:
        outer, inner = p.split("!/", 1)
        if not (rootfs / outer).is_file():
            return False
        with zipfile.ZipFile(rootfs / outer) as z:
            return inner in z.namelist()
    return (rootfs / p).exists() or (rootfs / p).is_symlink()


def real_versions(eco: str, comp: str, rel: str | None) -> set[str]:
    if eco == "pypi":
        return set(pypi_versions(comp))
    if eco == "maven":
        return set(maven_versions(comp))
    if eco == "vendor":
        return set(vendor_versions(comp))
    from d7common import src_of, ubuntu_packages

    out = set(lp_versions(comp, rel))
    for b in ub_pick_binaries(comp, rel, ""):
        out.add(src_of(ubuntu_packages(rel)[b])[1])
    return out


def flagged(scan_dir: Path, cve: str) -> dict[str, bool]:
    res = {}
    t = load_json(scan_dir / "trivy.json")
    res["trivy"] = any(v.get("VulnerabilityID") == cve or cve in (v.get("VendorIDs") or [])
                       for r in t.get("Results", []) or [] for v in r.get("Vulnerabilities") or [])
    g = load_json(scan_dir / "grype.json")
    res["grype"] = any(m["vulnerability"]["id"] == cve or any(x.get("id") == cve for x in m.get("relatedVulnerabilities", []))
                       for m in g.get("matches", []))
    o = load_json(scan_dir / "osv.json")
    res["osv"] = any(v["id"] == cve or cve in v.get("aliases", []) or cve in v.get("upstream", [])
                     for r in o.get("results", []) or [] for p in r.get("packages", []) for v in p.get("vulnerabilities", []))
    return res


def main() -> int:
    pre = load_preconditions_v3()
    metas = {m["cve"]: m for m in read_jsonl(D7 / "cve_meta.jsonl")}
    cases = {s: read_jsonl(D7 / "cases" / f"{s}.jsonl") for s in ("dev", "calib", "test")}
    sealed_path = DATA / "sealed" / "d7_test_labels.jsonl"
    sealed = {r["case_id"]: r for r in read_jsonl(sealed_path)}
    # ---------------------------------------------------------------- comparator sanity
    for eco, a, b, sign in KNOWN_PAIRS:
        got = V.compare(eco, a, b)
        check("comparator.known_pairs", got == sign, f"{eco}: compare({a},{b})={got} expected {sign}")
    limits = []
    for eco, a, b, sign in KNOWN_LIMITS:
        got = V.compare(eco, a, b)
        if got != sign:
            limits.append(f"{eco}: compare({a},{b})={got}, correct {sign}")
    # ---------------------------------------------------------------- meta
    for cve, m in metas.items():
        check("meta.fields", list(m)[: len(META_FIELDS)] == META_FIELDS or set(META_FIELDS) <= set(m),
              f"{cve} fields {list(m)}")
        check("meta.ecosystem", m["ecosystem"] in ECOS, cve)
        check("meta.temporal", m["temporal_holdout"] == (m["published"] >= TEMPORAL_CUTOFF), cve)
        check("meta.precondition", (m["config_precondition"] is not None) == (cve in pre), cve)
        check("advisory.exists", (D7 / "advisories" / f"{cve}.json").exists(), cve)
        if (D7 / "advisories" / f"{cve}.json").exists():
            adv = load_json(D7 / "advisories" / f"{cve}.json")
            check("advisory.fields", set(adv) == {"nvd", "osv", "kev", "vendor", "ubuntu"}, cve)
            check("advisory.len", all(len(v) <= 6000 for v in adv.values()), cve)
            check("advisory.nonempty", bool(adv["nvd"] or adv["osv"]), cve)
        for r in m["ranges"]:
            check("meta.range_kinds", "last_affected" not in r or m["ecosystem"] == "maven", f"{cve} {r}")
        if m["ecosystem"] == "deb-ubuntu":
            check("meta.ubuntu", set(m["ubuntu"]) <= set(UBUNTU_RELEASES) and m["ubuntu"], cve)
            # cross-check tracker vs OSV Ubuntu export
            for rel, x in m["ubuntu"].items():
                eco = {"jammy": "Ubuntu:22.04:LTS", "noble": "Ubuntu:24.04:LTS"}[rel]
                osv_fixed = [e["fixed"] for rec in osv_records("Ubuntu", cve) for a in rec.get("affected", [])
                             if a["package"]["ecosystem"] == eco and a["package"]["name"] == m["src_package"]
                             for rr in a.get("ranges", []) for e in rr["events"] if "fixed" in e]
                if x["status"] == "released" and osv_fixed and osv_fixed[0] != x["fixed_version"]:
                    warnings.append(f"tracker/OSV mismatch {cve}/{rel}: {x['fixed_version']} vs {osv_fixed[0]}")
    # ---------------------------------------------------------------- splits
    cve_split = {}
    for s, rows in cases.items():
        for c in rows:
            cve_split.setdefault(c["cve"], set()).add(s)
    check("splits.disjoint", all(len(v) == 1 for v in cve_split.values()),
          str([c for c, v in cve_split.items() if len(v) > 1]))
    for c, v in cve_split.items():
        check("splits.meta", metas[c]["split"] in v, c)
    # ---------------------------------------------------------------- seal
    sha = hashlib.sha256(sealed_path.read_bytes()).hexdigest()
    check("seal.hash", (DATA / "sealed" / "D7_SHA256").read_text().split()[0] == sha, "hash mismatch")
    check("seal.ids", set(sealed) == {c["case_id"] for c in cases["test"]}, "id mismatch")
    check("seal.no_labels", all("label" not in c and "atoms" not in c for c in cases["test"]), "labels in test")
    # ---------------------------------------------------------------- cases + hosts
    ids = set()
    stats = collections.Counter()
    disagree = collections.defaultdict(lambda: collections.Counter())
    for split, rows in cases.items():
        for c in rows:
            cid = c["case_id"]
            check("case.unique", cid not in ids, cid)
            ids.add(cid)
            want = CASE_FIELDS if split != "test" else [f for f in CASE_FIELDS if f not in ("label", "atoms")]
            check("case.fields", list(c) == want, f"{cid}: {list(c)}")
            check("case.variant", c["variant"] in VARIANTS, cid)
            check("case.aliases", bool(c["aliases"]) and all(isinstance(a, str) and a for a in c["aliases"]), cid)
            m = metas[c["cve"]]
            check("case.meta_flags", c["temporal_holdout"] == m["temporal_holdout"] and c["kev"] == m["kev"]
                  and c["ecosystem"] == m["ecosystem"] and c["component"] == m["component"], cid)
            ref = c if split != "test" else sealed[cid]
            lab, atoms = ref["label"], ref["atoms"]
            check("case.label_enum", (lab["status"], lab["justification"]) in STATUS_JUST, cid)
            check("case.atoms", set(atoms) == ATOM_FIELDS, cid)
            check("case.label_from_atoms", label_from_atoms(atoms) == lab, cid)
            check("case.expected_by_variant", (lab["status"], lab["justification"]) == EXPECTED[c["variant"]], cid)
            hdir = D7 / "hosts" / c["host_id"]
            rootfs = hdir / "rootfs"
            ranges = case_ranges(m, c["release"])
            insts, a2, l2 = label_host(rootfs, c["ecosystem"], c["component"], ranges, pre.get(c["cve"]))
            check("case.recompute", a2 == atoms and l2 == lab, f"{cid}: {l2} vs {lab}")
            if c["ecosystem"] != "deb-ubuntu":
                check("case.install_paths", sorted(c["install_paths"]) == sorted(i["path"] for i in insts), cid)
                for p in c["install_paths"]:
                    check("files.install_paths", path_exists(rootfs, p), f"{cid}: {p}")
            # guard: shared classify vs independent semantics (incl. last_affected) on every instance
            for i in insts:
                check("range.guard", V.classify(c["ecosystem"], i["version"], ranges)[0] ==
                      full_semantics(c["ecosystem"], i["version"], ranges), f"{cid}: {i['version']}")
                check("version.real", i["version"] in real_versions(c["ecosystem"], c["component"], c["release"])
                      or i.get("kind") == "vendored", f"{cid}: {i['version']} not an upstream version")
            check("case.installed_version", (c["installed_version"] is None) == (not insts), cid)
            # variant semantics
            var = c["variant"]
            if var in ("V1", "V6"):
                check("variant.absent", not insts, cid)
            if var == "V7":
                check("variant.vendored", insts and all(i["kind"] in ("vendored", "nested-jar") for i in insts), cid)
            if var == "V8":
                check("variant.unstructured", c["ecosystem"] == "vendor", cid)
            if var == "V4" and c["ecosystem"] != "deb-ubuntu":
                fixes = [r["fixed"] for r in ranges if r.get("fixed")]
                top = max(fixes, key=lambda x: V.parse(c["ecosystem"], x))
                check("variant.v4_branch_fix", V.compare(c["ecosystem"], c["installed_version"], top) < 0, cid)
            if var == "V5":
                p = pre[c["cve"]]
                check("variant.v5_file", (rootfs / p["file"]).exists(), cid)
            # host.json
            h = load_json(hdir / "host.json")
            check("host.fields", list(h) == HOST_FIELDS, f"{cid}: {list(h)}")
            for name, s in h["services"].items():
                check("host.services", {"unit", "active", "package", "config_files", "banner", "loaded_version"}
                      <= set(s), f"{cid}: {name}")
                for f in s["config_files"]:
                    check("files.config", path_exists(rootfs, f), f"{cid}: {f}")
            for ap in h["apps"]:
                check("host.apps", {"path", "ecosystem", "component", "version"} <= set(ap), cid)
                check("files.apps", path_exists(rootfs, ap["path"]), f"{cid}: {ap['path']}")
            # dpkg status always parses
            st = (rootfs / "var/lib/dpkg/status").read_text()
            paras = list(Deb822.iter_paragraphs(st.splitlines()))
            check("dpkg.parse", len(paras) > 50 and all("Package" in p and "Version" in p for p in paras), cid)
            if c["ecosystem"] == "deb-ubuntu" and insts:
                for b in insts[0].get("binaries", []):
                    cl = rootfs / "usr/share/doc" / b / "changelog.Debian"
                    check("changelog", cl.exists() and f"({c['installed_version']})" in cl.read_text().splitlines()[0],
                          f"{cid}: {b}")
            for jar in rootfs.glob("opt/**/*.jar"):
                jar_ok(jar.read_bytes(), f"{cid}:{jar.relative_to(rootfs)}")
            for md in rootfs.glob("opt/**/*.dist-info/METADATA"):
                t = md.read_text()
                check("pypi.metadata", re.search(r"(?m)^Name: \S", t) and re.search(r"(?m)^Version: \S", t), str(md))
            if c["ecosystem"] == "vendor" and insts:
                check("vendor.no_pkg_entry", not re.search(r"(?m)^Package: (tomcat\d*|jenkins|roundcube\S*|gitlab\S*|apache2)$", st), cid)
            # scanners
            sd = hdir / "scans"
            for f in ("trivy.json", "grype.json", "osv.json"):
                ok = (sd / f).exists()
                if ok:
                    try:
                        load_json(sd / f)
                    except Exception:  # noqa: BLE001
                        ok = False
                check(f"scan.{f.split('.')[0]}", ok, cid)
            stats[(split, c["ecosystem"], var)] += 1
            if split in ("dev", "calib") and all((sd / f).exists() for f in ("trivy.json", "grype.json", "osv.json")):
                fl = flagged(sd, c["cve"])
                aff = lab["status"] == "affected"
                for sc, v in fl.items():
                    d = disagree[(sc, c["ecosystem"])]
                    d["n"] += 1
                    if v != aff:
                        d["disagree"] += 1
                        d["fp" if v else "fn"] += 1
                        d[f"var_{var}"] += 1
    # ---------------------------------------------------------------- global requirements
    v5 = collections.Counter(s for (s, e, v), n in stats.items() if v == "V5" for _ in range(n))
    check("req.v5_total", sum(v5.values()) >= 30, f"V5 total {sum(v5.values())}")
    check("req.v5_test", v5["test"] >= 10, f"V5 test {v5['test']}")
    test_cves = {c["cve"] for c in cases["test"]}
    tshare = sum(metas[c]["temporal_holdout"] for c in test_cves) / max(1, len(test_cves))
    check("req.temporal_test_share", tshare >= 0.25, f"{tshare:.2f}")
    check("req.n_cves", len(metas) >= 120, str(len(metas)))
    n_cases = sum(len(r) for r in cases.values())
    check("req.n_cases", 500 <= n_cases <= 1000, str(n_cases))
    check("req.test_cases", len(cases["test"]) >= 400, str(len(cases["test"])))
    for eco in ECOS:
        check("req.ecosystems", any(m["ecosystem"] == eco for m in metas.values()), eco)
    # decoys never in the CVE's OSV affected list
    for split, rows in cases.items():
        for c in rows:
            if c["variant"] == "V6" and c["ecosystem"] in ("pypi", "maven"):
                h = load_json(D7 / "hosts" / c["host_id"] / "host.json")
                dec = [a["component"] for a in h["apps"]]
                eco = {"pypi": "PyPI", "maven": "Maven"}[c["ecosystem"]]
                aff = {a["package"]["name"].lower() for r in osv_records(eco, c["cve"]) for a in r.get("affected", [])}
                check("variant.decoy_not_affected", not any(d.lower() in aff for d in dec), c["case_id"])
    # ---------------------------------------------------------------- report
    print("== validation checks")
    total = 0
    for k in sorted(checks):
        print(f"  {k:<30} {checks[k]:>6} checks {len(errors[k]):>5} errors")
        total += len(errors[k])
        for e in errors[k][:5]:
            print(f"      ! {e}")
    print(f"TOTAL errors: {total}")
    print("\n== known comparator limitations (not fatal; avoided by construction)")
    for x in limits:
        print("  " + x)
    print("  classify() ignores `last_affected` (only introduced/fixed); D7 ranges avoid it except "
          "log4j:log4j (last_affected = final release 1.2.17), guarded by range.guard above")
    print(f"\n== warnings ({len(warnings)})")
    for w in warnings[:20]:
        print("  " + w)
    print("\n== cases per split x ecosystem x variant")
    hdr = "  split  ecosystem   " + " ".join(f"{v:>4}" for v in VARIANTS) + "  total"
    print(hdr)
    for s in ("dev", "calib", "test"):
        for e in ECOS:
            row = [stats[(s, e, v)] for v in VARIANTS]
            print(f"  {s:<6} {e:<11} " + " ".join(f"{x:>4}" for x in row) + f"  {sum(row):>5}")
    print("  totals: " + ", ".join(f"{s}={len(r)}" for s, r in cases.items()) + f", all={n_cases}")
    print("\n== CVEs per split (temporal hold-out = NVD published >= 2026-05-01)")
    for s in ("dev", "calib", "test"):
        cv = {c["cve"] for c in cases[s]}
        by = collections.Counter(metas[c]["ecosystem"] for c in cv)
        print(f"  {s:<6} cves={len(cv):>3} temporal={sum(metas[c]['temporal_holdout'] for c in cv):>3} "
              f"({100 * sum(metas[c]['temporal_holdout'] for c in cv) / max(1, len(cv)):.0f}%) "
              f"kev={sum(metas[c]['kev'] for c in cv)} config_gated={sum(c in pre for c in cv)} by_eco={dict(by)}")
    print(f"  V5 cases: {dict(v5)} total={sum(v5.values())}")
    print("\n== natural scanner-vs-label disagreement (dev+calib only; scanner flags CVE anywhere on host vs "
          "label == affected)")
    for (sc, eco), d in sorted(disagree.items()):
        byv = {k[4:]: v for k, v in d.items() if k.startswith("var_")}
        print(f"  {sc:<6} {eco:<11} n={d['n']:>4} disagree={d['disagree']:>4} ({100 * d['disagree'] / max(1, d['n']):.1f}%) "
              f"flagged_not_affected={d['fp']} missed_affected={d['fn']} by_variant={byv}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
