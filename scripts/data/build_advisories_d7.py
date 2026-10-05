"""Render per-CVE advisory texts for D7: data/d7/advisories/<CVE>.json = {nvd, osv, kev, vendor, ubuntu}.

Each field is plain readable text <= 6000 chars, rendered only from mirrored snapshots:
  nvd     NVD 2.0 record (mirrors/nvd)                          (same renderer as D1)
  osv     OSV records from the ecosystem export (Ubuntu / PyPI / Maven zips of 2026-10-05)
  kev     CISA KEV entry                                         (same renderer as D1)
  vendor  vendor/maintainer statement: mirrored vendor advisory page excerpt (Tomcat, httpd, Log4j, Spring,
          sudo, nginx, OpenSSH, GHSA, ...), the curated range statement for vendor products, and the verbatim
          configuration-precondition quote when the CVE has one
  ubuntu  Ubuntu CVE tracker record (deb-ubuntu CVEs only; "" otherwise)
"""

from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_advisories import _affected_lines, clip, kev_text, nvd_text  # noqa: E402
from d7common import D7, kev_set, load_json, mirror, osv_records  # noqa: E402
from label_d7 import load_preconditions_v3  # noqa: E402

PAGES = {
    "tomcat": ["tomcat_security-11.html", "tomcat_security-10.html", "tomcat_security-9.html",
               "tomcat_security-8.html", "tomcat_security-7.html"],
    "httpd": ["httpd_vulnerabilities_24.html"],
}


def page_text(name: str) -> str:
    p = mirror("advisory_pages") / "raw" / name
    if not p.exists():
        return ""
    s = p.read_text(errors="replace")
    if name.endswith(".json"):
        j = json.loads(s)
        return (j.get("summary") or "") + "\n" + (j.get("description") or "")
    s = re.sub(r"(?is)<(script|style).*?</\1>", " ", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", html.unescape(s))


def excerpt(cve: str, names: list[str], width: int = 1800) -> str:
    for n in names:
        t = page_text(n)
        i = t.find(cve)
        if i >= 0:
            # start at the heading that precedes the CVE id (vendor pages put the title before the id)
            start = max(0, i - 160)
            return f"[{n}] ..." + t[start:start + width] + "..."
    return ""


def osv_text(eco: str, cve: str) -> str:
    oeco = {"deb-ubuntu": "Ubuntu", "pypi": "PyPI", "maven": "Maven", "vendor": "Maven"}[eco]
    recs = osv_records(oeco, cve)
    out = []
    for rec in sorted(recs, key=lambda r: (not r["id"].startswith(("GHSA", "UBUNTU")), r["id"]))[:3]:
        out.append(f"{rec['id']} (OSV {oeco} export, published {rec.get('published', '')[:10]}, "
                   f"modified {rec.get('modified', '')[:10]})")
        if rec.get("summary"):
            out.append("Summary: " + rec["summary"])
        if rec.get("details"):
            out.append("Details: " + rec["details"][:2000])
        al = rec.get("aliases", []) + rec.get("related", []) + rec.get("upstream", [])
        if al:
            out.append("Aliases/related: " + ", ".join(sorted(set(al))[:20]))
        lines = _affected_lines(rec)
        if lines:
            out.append("Affected:\n" + "\n".join(lines[:20]))
        out.append("")
    return clip("\n".join(out))


def ubuntu_text(cve: str, src: str) -> str:
    p = mirror("ubuntu_cve_tracker") / "cves" / f"{cve}.json"
    j = load_json(p) if p.exists() else {}
    if not j or j.get("_status"):
        return ""
    out = [f"Ubuntu CVE tracker: {cve} (priority: {j.get('priority', '?')}, status: {j.get('status', '?')}, "
           f"published {str(j.get('published', ''))[:10]})",
           "Description: " + (j.get("description") or "").strip()]
    if (j.get("ubuntu_description") or "").strip():
        out.append("Ubuntu description: " + j["ubuntu_description"].strip())
    for pk in j.get("packages", []):
        if pk["name"] != src:
            continue
        out.append(f"Package {src}:")
        for s in pk["statuses"]:
            if s["release_codename"] in ("focal", "jammy", "noble", "plucky", "questing", "upstream"):
                d = f" ({s['description']})" if s.get("description") else ""
                out.append(f"  {s['release_codename']}: {s['status']}{d}")
    for n in (j.get("notes") or [])[:4]:
        out.append(f"Note ({n.get('author', '')}): {n.get('note', '')}")
    if (j.get("mitigation") or "").strip():
        out.append("Mitigation: " + j["mitigation"].strip())
    if j.get("notices_ids"):
        out.append("Notices: " + ", ".join(j["notices_ids"][:8]))
    return clip("\n".join(out))


def vendor_text(meta: dict, pre: dict | None) -> str:
    out = []
    cve, eco, comp = meta["cve"], meta["ecosystem"], meta["component"]
    if eco == "vendor":
        out.append(f"Vendor statement ({meta.get('range_source')}): {meta.get('range_statement', '')}")
        ex = excerpt(cve, PAGES.get(comp, []))
        if ex:
            out.append(ex)
    if pre:
        out.append(f"Configuration precondition (source: {pre['advisory_url']}):\n\"{' '.join(pre['quote'].split())}\"")
        page = {
            "logging.apache.org": ["log4j_security.html"], "spring.io": ["spring_cve-2022-22965.html"],
            "sudo.ws": ["sudo_host_any.html"], "httpd.apache.org": ["httpd_vulnerabilities_24.html"],
        }
        for host, names in page.items():
            if host in pre["advisory_url"] and eco != "vendor":
                ex = excerpt(cve, names)
                if ex:
                    out.append(ex)
    return clip("\n\n".join(out))


def main() -> None:
    from common import read_jsonl

    kev = kev_set()
    pre = load_preconditions_v3()
    outdir = D7 / "advisories"
    outdir.mkdir(parents=True, exist_ok=True)
    metas = read_jsonl(D7 / "cve_meta.jsonl")
    for m in metas:
        cve = m["cve"]
        doc = {
            "nvd": nvd_text(cve),
            "osv": osv_text(m["ecosystem"], cve),
            "kev": kev_text(cve, kev),
            "vendor": vendor_text(m, pre.get(cve)),
            "ubuntu": ubuntu_text(cve, m["src_package"]) if m["ecosystem"] == "deb-ubuntu" else "",
        }
        (outdir / f"{cve}.json").write_text(json.dumps(doc, indent=1))
    print(f"advisories: {len(metas)}")


if __name__ == "__main__":
    main()
