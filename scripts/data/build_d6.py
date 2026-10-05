"""Build D6: advisory-to-status tuples from the Debian security tracker snapshot.

Tuple: {cve, src_package, release, fixed_version, tracker_status, description, description_source, label}
label: affected_open (status open, no fix in release) | fixed_in_version (resolved with a real version) |
       not_affected (resolved with fixed_version "0").
Sampling: userland source packages (no linux kernel), releases bookworm + trixie, label-balanced targets,
seed 20261005. Split by CVE (dev 30 / calib 20 / test 50); CVEs used in D1 never enter D6 test.
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, MIRRORS, SEED, SNAP_DATE, write_jsonl  # noqa: E402

RELEASES = ("bookworm", "trixie")
TARGET = {"affected_open": 1000, "fixed_in_version": 1200, "not_affected": 800}
EXCLUDE_PREFIX = ("linux", "kernel")


def label_of(x: dict) -> str | None:
    fv = x.get("fixed_version")
    if x["status"] == "open":
        return "affected_open"
    if x["status"] == "resolved" and fv == "0":
        return "not_affected"
    if x["status"] == "resolved" and fv:
        return "fixed_in_version"
    return None


def main() -> None:
    tracker = json.loads((MIRRORS / "debian_tracker" / SNAP_DATE / "raw" / "tracker.json").read_text())
    d1_cves = {json.loads(line)["cve"] for line in open(DATA / "d1" / "cve_meta.jsonl")}
    pool: dict[str, list[dict]] = {k: [] for k in TARGET}
    for src, cves in tracker.items():
        if src.startswith(EXCLUDE_PREFIX):
            continue
        for cve, e in cves.items():
            if not cve.startswith("CVE-") or not (e.get("description") or "").strip():
                continue
            for rel in RELEASES:
                x = e["releases"].get(rel)
                if not x:
                    continue
                lab = label_of(x)
                if lab:
                    pool[lab].append(
                        {
                            "cve": cve,
                            "src_package": src,
                            "release": rel,
                            "fixed_version": x.get("fixed_version"),
                            "tracker_status": x["status"],
                            "urgency": x.get("urgency"),
                            "description": e["description"].strip(),
                            "description_source": "debian-tracker",
                            "label": lab,
                        }
                    )
    rng = random.Random(SEED)
    rows, seen = [], set()
    for lab, n in TARGET.items():
        cand = sorted(pool[lab], key=lambda r: (r["cve"], r["src_package"], r["release"]))
        rng.shuffle(cand)
        for r in cand:
            key = (r["cve"], r["src_package"], r["release"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(r)
            if sum(1 for x in rows if x["label"] == lab) >= n:
                break
    # NVD description where already mirrored (D1 CVEs)
    for r in rows:
        p = MIRRORS / "nvd" / SNAP_DATE / "cves" / f"{r['cve']}.json"
        if p.exists():
            v = json.loads(p.read_text()).get("vulnerabilities") or []
            d = next(
                (x["value"] for x in (v[0]["cve"]["descriptions"] if v else []) if x["lang"] == "en"), ""
            )
            if d:
                r["nvd_description"] = d
                r["description_source"] = "debian-tracker+nvd"
    # split by CVE, stratified by majority label of the CVE
    by_cve: dict[str, list[dict]] = {}
    for r in rows:
        by_cve.setdefault(r["cve"], []).append(r)
    strata: dict[str, list[str]] = {}
    for cve, rs in by_cve.items():
        strata.setdefault(rs[0]["label"], []).append(cve)
    split_of = {}
    for _, cves in sorted(strata.items()):
        cves.sort(key=lambda c: hashlib.sha256(f"{SEED}|{c}".encode()).hexdigest())
        n = len(cves)
        n_dev, n_cal = round(0.3 * n), round(0.2 * n)
        for i, c in enumerate(cves):
            split_of[c] = "dev" if i < n_dev else "calib" if i < n_dev + n_cal else "test"
    moved = 0
    for c in by_cve:
        if c in d1_cves and split_of[c] == "test":
            split_of[c] = "dev" if int(hashlib.sha256(c.encode()).hexdigest(), 16) % 5 < 3 else "calib"
            moved += 1
    out = DATA / "d6"
    for s in ("dev", "calib", "test"):
        part = [dict(r, split=s) for r in rows if split_of[r["cve"]] == s]
        part.sort(key=lambda r: (r["cve"], r["src_package"], r["release"]))
        write_jsonl(out / f"{s}.jsonl", part)
        lab = {k: sum(1 for r in part if r["label"] == k) for k in TARGET}
        print(f"d6 {s}: tuples={len(part)} cves={len({r['cve'] for r in part})} labels={lab}")
    print(
        f"d6 total tuples={len(rows)}; D1 CVEs moved out of test={moved}; "
        f"D1 CVEs in D6={len(d1_cves & set(by_cve))}"
    )


if __name__ == "__main__":
    main()
