"""Ground-truth atoms and labels for D1 cases, computed from the fixture rootfs.

Atoms are derived from (a) the fixture's var/lib/dpkg/status parsed with python-debian, (b) the Debian
security tracker snapshot entry for (src_package, CVE, release), compared with python-debian Version
objects (dpkg --compare-versions semantics; never string comparison), and (c) the curated configuration
predicate from config/config_preconditions.yaml evaluated on the fixture files.

Usable as a library (build_d1.py, validate_d1.py) or as a CLI that relabels existing cases:
    python scripts/data/label_live.py --check     # recompute and compare against cases + sealed labels
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml
from debian.deb822 import Deb822
from debian.debian_support import Version

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT  # noqa: E402

PRECOND_PATH = ROOT / "config" / "config_preconditions.yaml"


def load_preconditions(path: Path = PRECOND_PATH) -> dict[str, dict]:
    return {p["cve"]: p for p in yaml.safe_load(path.read_text())["preconditions"]}


def parse_status(rootfs: Path) -> list[dict]:
    with open(rootfs / "var" / "lib" / "dpkg" / "status", encoding="utf-8") as f:
        return [dict(p) for p in Deb822.iter_paragraphs(f, use_apt_pkg=False)]


def installed_src_version(status: list[dict], src_package: str) -> tuple[str | None, list[str]]:
    """Source version of installed binaries built from src_package (None if absent), and binary names."""
    vers, bins = set(), []
    for p in status:
        if p.get("Status", "").strip() != "install ok installed":
            continue
        src = p.get("Source", p["Package"]).strip()
        if "(" in src:
            name, sver = src.split("(", 1)
            name, sver = name.strip(), sver.rstrip(")").strip()
        else:
            name, sver = src, p["Version"].strip()
        if name == src_package:
            vers.add(sver)
            bins.append(p["Package"])
    if not vers:
        return None, []
    # all binaries of one source share one source version in our fixtures; take the lowest if not
    return min(vers, key=Version), sorted(bins)


def config_lines(path: Path) -> list[tuple[str, str]]:
    """(key, value) pairs: 'key = value' (samba/exim style, key may contain spaces) or 'Key value'."""
    out = []
    for raw in path.read_text(errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith(("#", ";")):
            continue
        first = s.split(None, 1)
        if "=" in s and (len(first) == 1 or first[1].startswith("=") or "=" in first[0]
                         or re.match(r"^[A-Za-z][\w:. -]*\s=\s", s)):
            k, v = s.split("=", 1)
            out.append((k.strip(), v.strip()))
        else:
            out.append((first[0], first[1].strip() if len(first) > 1 else ""))
    return out


def eval_predicate(rootfs: Path, pre: dict) -> bool:
    """TRUE when the vulnerable feature is enabled in the fixture."""
    kind = pre["predicate"]["kind"]
    target = rootfs / pre["file"]
    if kind == "module_enabled":
        return (target / pre["key"]).exists() or (target / pre["key"]).is_symlink()
    if not target.is_file():
        return False
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


def compute_atoms(installed: str | None, tracker_rel: dict | None, req_config: bool,
                  config_enabled: bool) -> dict:
    present = installed is not None
    status = (tracker_rel or {}).get("status")
    fixed = (tracker_rel or {}).get("fixed_version")
    in_range = False
    fix_applied = False
    if present and tracker_rel is not None:
        if fixed == "0":
            in_range = False
        elif fixed:
            in_range = Version(installed) < Version(fixed)
            fix_applied = Version(installed) >= Version(fixed)
        elif status in ("open", "undetermined"):
            in_range = True
    return {"present": present, "in_affected_range": in_range, "fix_applied": fix_applied,
            "vuln_config_enabled": bool(config_enabled), "req_config": bool(req_config)}


def label_from_atoms(a: dict) -> dict:
    if not a["present"]:
        return {"status": "not_affected", "justification": "component_not_present"}
    if a["fix_applied"]:
        return {"status": "fixed", "justification": None}
    if not a["in_affected_range"]:
        return {"status": "not_affected", "justification": "vulnerable_code_not_present"}
    if a["req_config"] and not a["vuln_config_enabled"]:
        return {"status": "not_affected", "justification": "requires_configuration"}
    return {"status": "affected", "justification": None}


def label_host(rootfs: Path, cve: str, src_package: str, tracker_rel: dict | None,
               preconds: dict[str, dict]) -> tuple[str | None, list[str], dict, dict]:
    status = parse_status(rootfs)
    installed, bins = installed_src_version(status, src_package)
    pre = preconds.get(cve)
    req = pre is not None
    # for CVEs without a curated precondition the vulnerable code path is reachable in the default
    # configuration, so vuln_config_enabled is True whenever the component is present
    enabled = eval_predicate(rootfs, pre) if req else installed is not None
    atoms = compute_atoms(installed, tracker_rel, req, enabled)
    return installed, bins, atoms, label_from_atoms(atoms)


def main() -> None:
    import json

    from common import DATA, read_jsonl

    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.parse_args()
    meta = {r["cve"]: r for r in read_jsonl(DATA / "d1" / "cve_meta.jsonl")}
    tracker_snapshot = json.loads((DATA / "d1" / "tracker_entries.json").read_text())
    pre = load_preconditions()
    sealed = {r["case_id"]: r for r in read_jsonl(DATA / "sealed" / "test_labels.jsonl")}
    bad = n = 0
    for split in ("dev", "calib", "test"):
        for c in read_jsonl(DATA / "d1" / "cases" / f"{split}.jsonl"):
            m = meta[c["cve"]]
            trel = tracker_snapshot[m["src_package"]][c["cve"]]["releases"].get(c["release"])
            _, _, atoms, label = label_host(DATA / "d1" / "hosts" / c["host_id"] / "rootfs", c["cve"],
                                            c["src_package"], trel, pre)
            ref = c if split != "test" else sealed[c["case_id"]]
            n += 1
            if ref["label"] != label or ref["atoms"] != atoms:
                bad += 1
                print("MISMATCH", c["case_id"], ref["label"], label)
    print(f"relabel check: {n} cases, {bad} mismatches")


if __name__ == "__main__":
    main()
