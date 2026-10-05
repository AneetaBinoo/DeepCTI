"""Ground-truth atoms and labels for D7 (DeepCTI-Live-X) cases, computed from the fixture rootfs.

Version comparison uses ONLY the shared comparator src/deepcti/core/versions.py (`classify`), i.e. dpkg
semantics for deb-ubuntu, PEP 440 for PyPI, Maven ComparableVersion for Maven, a semver-like order for vendor
products — never string comparison.

Instance discovery (what is installed, at which version) reads the fixture files the way an analyst would:
  deb-ubuntu  var/lib/dpkg/status (binaries built from src_package, "install ok installed")
  pypi        **/site-packages/<dist>.dist-info/METADATA (Name/Version, PEP 503-normalised name) and
              vendored copies listed in **/_vendor/vendor.txt ("name==version")
  maven       every *.jar under opt/ (and jars nested under BOOT-INF/lib/ or WEB-INF/lib/ inside them):
              META-INF/maven/<g>/<a>/pom.properties
  vendor      product-specific text files under opt/<product>/ (RELEASE-NOTES, ap_release.h, ...)
Affected ranges come from data/d7/cve_meta.jsonl (`ranges`, all branches, ecosystem semantics).

Usable as a library (build_d7.py, validate_d7.py) or as a CLI:
    python scripts/data/label_d7.py --check    # recompute every case and compare with cases + sealed labels
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import zipfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d7common import D7, DATA, ROOT, V, load_json  # noqa: E402
from label_live import config_lines, installed_src_version, label_from_atoms, parse_status  # noqa: E402

PRECOND_V3 = ROOT / "config" / "config_preconditions_v3.yaml"


def load_preconditions_v3(path: Path = PRECOND_V3) -> dict[str, dict]:
    return {p["cve"]: p for p in yaml.safe_load(path.read_text())["preconditions"]}


# ------------------------------------------------------------------------------------------- predicates
def regex_text(path: Path) -> str:
    txt = path.read_text(errors="replace")
    txt = re.sub(r"(?s)<!--.*?-->", "", txt)
    return "\n".join(ln for ln in txt.splitlines() if not ln.lstrip().startswith(("#", ";")))


def eval_predicate(rootfs: Path, pre: dict) -> bool:
    """TRUE when the vulnerable feature is enabled (D1 semantics + regex_present)."""
    kind = pre["predicate"]["kind"]
    target = rootfs / pre["file"]
    if kind == "module_enabled":
        return (target / pre["key"]).exists() or (target / pre["key"]).is_symlink()
    if not target.is_file():
        return False
    if kind == "regex_present":
        return re.search(pre["predicate"]["pattern"], regex_text(target), re.MULTILINE) is not None
    vals = [v for k, v in config_lines(target) if k == pre["key"]]
    if kind == "directive_present":
        return bool(vals)
    if kind == "directive_absent":
        return not vals
    if not vals:
        return False
    if kind == "value_equals":
        return vals[-1] == pre["predicate"]["value"]
    if kind == "value_not_equals":
        return vals[-1] != pre["predicate"]["value"]
    raise ValueError(f"unknown predicate kind {kind}")


# ------------------------------------------------------------------------------------ instance discovery
def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _metadata_fields(text: str) -> dict:
    out = {}
    for ln in text.splitlines():
        if not ln.strip():
            break
        if ":" in ln and not ln.startswith(" "):
            k, v = ln.split(":", 1)
            out.setdefault(k.strip(), v.strip())
    return out


def pypi_instances(rootfs: Path, component: str) -> list[dict]:
    out = []
    want = pep503(component)
    for meta in sorted(rootfs.glob("opt/**/site-packages/*.dist-info/METADATA")):
        f = _metadata_fields(meta.read_text(errors="replace"))
        if pep503(f.get("Name", "")) == want:
            out.append({"path": str(meta.parent.relative_to(rootfs)), "version": f["Version"], "kind": "dist-info"})
    for vt in sorted(rootfs.glob("opt/**/_vendor/vendor.txt")):
        for ln in vt.read_text().splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)==([^\s#;]+)", ln)
            mod = m.group(1).lower().replace("-", "_") if m else ""
            # only count a vendored copy whose package directory is really there (pip lists e.g.
            # setuptools==x in vendor.txt but ships only pkg_resources)
            if m and pep503(m.group(1)) == want and (vt.parent / mod / "__init__.py").is_file():
                out.append({"path": str((vt.parent / mod).relative_to(rootfs)), "version": m.group(2),
                            "kind": "vendored"})
    return out


def _pom_props(z: zipfile.ZipFile) -> list[dict]:
    res = []
    for n in z.namelist():
        if n.startswith("META-INF/maven/") and n.endswith("/pom.properties"):
            d = {}
            for ln in z.read(n).decode("utf-8", "replace").splitlines():
                if "=" in ln and not ln.startswith("#"):
                    k, v = ln.split("=", 1)
                    d[k.strip()] = v.strip()
            if {"groupId", "artifactId", "version"} <= set(d):
                res.append(d)
    return res


def maven_instances(rootfs: Path, component: str) -> list[dict]:
    g, a = component.split(":")
    out = []
    for jar in sorted(rootfs.glob("opt/**/*.jar")):
        rel = str(jar.relative_to(rootfs))
        with zipfile.ZipFile(jar) as z:
            for d in _pom_props(z):
                if d["groupId"] == g and d["artifactId"] == a:
                    out.append({"path": rel, "version": d["version"], "kind": "jar"})
            for n in z.namelist():
                if n.endswith(".jar") and (n.startswith("BOOT-INF/lib/") or n.startswith("WEB-INF/lib/")):
                    with zipfile.ZipFile(io.BytesIO(z.read(n))) as zz:
                        for d in _pom_props(zz):
                            if d["groupId"] == g and d["artifactId"] == a:
                                out.append({"path": f"{rel}!/{n}", "version": d["version"], "kind": "nested-jar"})
    return out


def vendor_version(rootfs: Path, product: str) -> tuple[str | None, str | None]:
    """(version, evidence path) parsed from the product's own text files; (None, None) if absent."""
    if product == "tomcat":
        p = rootfs / "opt/tomcat/RELEASE-NOTES"
        if p.is_file():
            m = re.search(r"Apache Tomcat Version (\S+)", p.read_text(errors="replace"))
            if m:
                return m.group(1), str(p.relative_to(rootfs))
    elif product == "httpd":
        p = rootfs / "opt/httpd/include/ap_release.h"
        if p.is_file():
            t = p.read_text(errors="replace")
            parts = [re.search(rf"#define AP_SERVER_{k}_NUMBER\s+(\d+)", t) for k in ("MAJORVERSION", "MINORVERSION",
                                                                                       "PATCHLEVEL")]
            if all(parts):
                return ".".join(x.group(1) for x in parts), str(p.relative_to(rootfs))
    elif product == "jenkins":
        p = rootfs / "opt/jenkins/home/jenkins.install.InstallUtil.lastExecVersion"
        if p.is_file():
            return p.read_text().strip(), str(p.relative_to(rootfs))
    elif product == "roundcube":
        p = rootfs / "opt/roundcube/program/include/iniset.php"
        if p.is_file():
            m = re.search(r"define\('RCMAIL_VERSION',\s*'([^']+)'\)", p.read_text(errors="replace"))
            if m:
                return m.group(1), str(p.relative_to(rootfs))
    elif product == "gitlab":
        p = rootfs / "opt/gitlab/embedded/service/gitlab-rails/VERSION"
        if p.is_file():
            return re.sub(r"-(ee|ce)$", "", p.read_text().strip()), str(p.relative_to(rootfs))
    return None, None


def vendor_instances(rootfs: Path, product: str) -> list[dict]:
    v, path = vendor_version(rootfs, product)
    return [{"path": path, "version": v, "kind": "vendor-text"}] if v else []


def instances(rootfs: Path, ecosystem: str, component: str) -> list[dict]:
    if ecosystem == "pypi":
        return pypi_instances(rootfs, component)
    if ecosystem == "maven":
        return maven_instances(rootfs, component)
    if ecosystem == "vendor":
        return vendor_instances(rootfs, component)
    if ecosystem == "deb-ubuntu":
        ver, bins = installed_src_version(parse_status(rootfs), component)
        return [{"path": "var/lib/dpkg/status", "version": ver, "kind": "dpkg", "binaries": bins}] if ver else []
    raise ValueError(ecosystem)


# ----------------------------------------------------------------------------------------------- atoms
def ubuntu_ranges(rel_status: dict | None) -> list[dict]:
    """Ubuntu tracker per-release status -> half-open ranges (dpkg semantics)."""
    if not rel_status:
        return []
    st, fv = rel_status.get("status"), rel_status.get("fixed_version")
    if st == "released" and fv:
        return [{"introduced": "0", "fixed": fv}]
    if st in ("needed", "pending", "deferred", "needs-triage", "active"):
        return [{"introduced": "0", "fixed": None}]
    return []  # not-affected, DNE, ignored -> no affected range


def in_ranges(ecosystem: str, version: str, ranges: list[dict]) -> bool:
    return any(V.classify(ecosystem, version, [r])[0] for r in ranges or [])


def compute_atoms(ecosystem: str, insts: list[dict], ranges: list[dict], pre: dict | None,
                  rootfs: Path) -> dict:
    present = bool(insts)
    in_range = fixed = False
    for i in insts:
        r, f = V.classify(ecosystem, i["version"], ranges)
        in_range |= r
        fixed |= f
    req = pre is not None
    if req and pre.get("applies_to_versions") and insts:
        req = any(in_ranges(ecosystem, i["version"], pre["applies_to_versions"]) for i in insts)
    enabled = eval_predicate(rootfs, pre) if req else present
    return {
        "present": present,
        "in_affected_range": bool(present and in_range),
        "fix_applied": bool(present and fixed and not in_range),
        "vuln_config_enabled": bool(enabled),
        "req_config": bool(req),
    }


def label_host(rootfs: Path, ecosystem: str, component: str, ranges: list[dict],
               pre: dict | None) -> tuple[list[dict], dict, dict]:
    insts = instances(rootfs, ecosystem, component)
    atoms = compute_atoms(ecosystem, insts, ranges, pre, rootfs)
    return insts, atoms, label_from_atoms(atoms)


def case_ranges(meta: dict, release: str | None) -> list[dict]:
    if meta["ecosystem"] == "deb-ubuntu":
        return ubuntu_ranges((meta.get("ubuntu") or {}).get(release))
    return meta["ranges"]


def main() -> None:
    from common import read_jsonl

    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.parse_args()
    meta = {r["cve"]: r for r in read_jsonl(D7 / "cve_meta.jsonl")}
    pre = load_preconditions_v3()
    sealed = {r["case_id"]: r for r in read_jsonl(DATA / "sealed" / "d7_test_labels.jsonl")}
    bad = n = 0
    for split in ("dev", "calib", "test"):
        for c in read_jsonl(D7 / "cases" / f"{split}.jsonl"):
            m = meta[c["cve"]]
            _, atoms, label = label_host(D7 / "hosts" / c["host_id"] / "rootfs", c["ecosystem"], c["component"],
                                         case_ranges(m, c.get("release")), pre.get(c["cve"]))
            ref = c if split != "test" else sealed[c["case_id"]]
            n += 1
            if ref["label"] != label or ref["atoms"] != atoms:
                bad += 1
                print("MISMATCH", c["case_id"], ref["label"], label)
    print(f"relabel check: {n} cases, {bad} mismatches")
    _ = load_json


if __name__ == "__main__":
    main()
