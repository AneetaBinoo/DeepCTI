"""Render per-CVE advisory texts (NVD, OSV, KEV, Debian tracker) for the env's advisory_fetch tool.

Output: data/d1/advisories/<CVE>.json = {"nvd": str, "osv": str, "kev": str, "debian": str}; each field is
plain readable text <= 6000 chars, rendered only from the mirrored snapshots.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, MIRRORS, SNAP_DATE  # noqa: E402

MAX = 6000


def clip(s: str) -> str:
    s = s.strip()
    return s if len(s) <= MAX else s[: MAX - 20].rstrip() + "\n[... truncated]"


def load(p: Path) -> dict | None:
    if not p.exists():
        return None
    j = json.loads(p.read_text())
    return None if j.get("_status") == 404 else j


def nvd_text(cve: str) -> str:
    j = load(MIRRORS / "nvd" / SNAP_DATE / "cves" / f"{cve}.json")
    v = (j or {}).get("vulnerabilities") or []
    if not v:
        return ""
    c = v[0]["cve"]
    out = [f"{c['id']} (NVD, status: {c.get('vulnStatus', '?')}, published {c.get('published', '')[:10]}, "
           f"last modified {c.get('lastModified', '')[:10]})"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    out.append("Description: " + desc)
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in c.get("metrics", {}).get(key, [])[:1]:
            d = m["cvssData"]
            out.append(f"CVSS {d.get('version')}: {d.get('baseScore')} {d.get('baseSeverity', '')} "
                       f"({d.get('vectorString')}) source={m.get('source')}")
    cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])})
    if cwes:
        out.append("Weaknesses: " + ", ".join(cwes))
    lines = []
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                b = [f"{k}={m[k]}" for k in ("versionStartIncluding", "versionStartExcluding",
                                             "versionEndIncluding", "versionEndExcluding") if m.get(k)]
                prio = (0 if m["criteria"].split(":")[2] == "a" else 1) + (0 if m.get("vulnerable") else 2)
                lines.append((prio, f"  - {'vulnerable' if m.get('vulnerable') else 'not vulnerable'}: "
                              f"{m['criteria']}" + (f" ({', '.join(b)})" if b else "")))
    lines = [t for _, t in sorted(set(lines), key=lambda x: x[0])]
    if len(lines) > 25:
        lines = lines[:25] + [f"  ... ({len(lines) - 25} more CPE entries, mostly vendor appliances/OS)"]
    out.append("Affected configurations (CPE):\n" + ("\n".join(lines) if lines else "  (none published yet)"))
    refs = [r["url"] for r in c.get("references", [])][:8]
    if refs:
        out.append("References:\n" + "\n".join("  " + r for r in refs))
    return clip("\n".join(out))


def _affected_lines(rec: dict) -> list[str]:
    lines = []
    for a in rec.get("affected", []):
        pkg = a.get("package", {})
        name = f"{pkg.get('ecosystem', '?')}/{pkg.get('name', '?')}" if pkg else "(upstream)"
        for r in a.get("ranges", []):
            ev = r.get("events", [])
            if r.get("type") == "GIT":
                ev = r.get("database_specific", {}).get("extracted_events") or []
                if not ev:
                    continue
                name_r = f"{name} upstream versions (from {r.get('repo')})"
            else:
                name_r = f"{name} {r.get('type', '').lower()} range"
            evs = ", ".join(f"{k} {v}" for e in ev for k, v in e.items())
            lines.append(f"  - {name_r}: {evs}")
        vs = a.get("versions") or []
        if vs and pkg:
            shown = vs[:12]
            lines.append(f"  - {name} affected versions: {', '.join(shown)}"
                         + (f" (+{len(vs) - 12} more)" if len(vs) > 12 else ""))
    return lines


def osv_text(cve: str) -> str:
    out = []
    for rid in (cve, f"DEBIAN-{cve}"):
        rec = load(MIRRORS / "osv" / SNAP_DATE / "vulns" / f"{rid}.json")
        if not rec:
            continue
        out.append(f"{rec['id']} (OSV, published {rec.get('published', '')[:10]}, "
                   f"modified {rec.get('modified', '')[:10]})")
        if rec.get("summary"):
            out.append("Summary: " + rec["summary"])
        if rec.get("details"):
            out.append("Details: " + rec["details"][:2500])
        al = rec.get("aliases", []) + rec.get("related", []) + rec.get("upstream", [])
        if al:
            out.append("Aliases/related: " + ", ".join(sorted(set(al))[:20]))
        lines = _affected_lines(rec)
        if lines:
            out.append("Affected:\n" + "\n".join(lines[:30]))
        out.append("")
    return clip("\n".join(out))


def kev_text(cve: str, kev: dict) -> str:
    k = kev.get(cve)
    if not k:
        return ""
    keys = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
            "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes", "cwes"]
    return clip("CISA Known Exploited Vulnerabilities catalog entry\n"
                + "\n".join(f"{x}: {k.get(x)}" for x in keys if k.get(x) not in (None, "", [])))


def debian_text(cve: str, src: str, entry: dict) -> str:
    out = [f"Debian security tracker: {cve} in source package '{src}'",
           "Description: " + (entry.get("description") or "(none)")]
    if entry.get("scope"):
        out.append(f"Scope: {entry['scope']}")
    for rel in ("bookworm", "trixie", "forky", "sid"):
        x = entry["releases"].get(rel)
        if not x:
            continue
        fv = x.get("fixed_version")
        if x["status"] == "resolved" and fv == "0":
            st = "not affected"
        elif x["status"] == "resolved":
            st = f"fixed in {fv}"
        else:
            st = x["status"] + (f" (fixed_version {fv})" if fv else " (no fixed version yet)")
        extra = f"; note: {x['nodsa']}" if x.get("nodsa") else ""
        out.append(f"  {rel}: {st}; urgency: {x.get('urgency', '?')}{extra}")
    return clip("\n".join(out))


def main() -> None:
    sel = json.loads((DATA / "d1" / "selected_cves.json").read_text())
    tracker = json.loads((DATA / "d1" / "tracker_entries.json").read_text())
    kj = json.loads((MIRRORS / "cisa_kev" / SNAP_DATE / "known_exploited_vulnerabilities.json").read_text())
    kev = {v["cveID"]: v for v in kj["vulnerabilities"]}
    outdir = DATA / "d1" / "advisories"
    outdir.mkdir(parents=True, exist_ok=True)
    for s in sel:
        cve = s["cve"]
        doc = {"nvd": nvd_text(cve), "osv": osv_text(cve), "kev": kev_text(cve, kev),
               "debian": debian_text(cve, s["src_package"], tracker[s["src_package"]][cve])}
        (outdir / f"{cve}.json").write_text(json.dumps(doc, indent=1))
    print(f"advisories: {len(sel)}")


if __name__ == "__main__":
    main()
