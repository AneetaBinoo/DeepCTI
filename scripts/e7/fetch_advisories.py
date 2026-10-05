"""Pre-fetch public advisory data (OSV + GitHub Advisory DB) for every VEX-Bench CVE.
The agents get NO network (deviation from VEX-Bench, whose agents browse the web);
instead both systems receive the identical offline advisory digest built here.
References/URLs are deliberately dropped to avoid leaking the per-repo fix PR."""
import json, subprocess, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "data/external/vex-bench-advisories"
OUT.mkdir(parents=True, exist_ok=True)
tasks = [json.loads(l) for l in (ROOT / "data/external/vex-bench/benchmark/tasks/vex_bench.jsonl").read_text().splitlines() if l.strip()]

def osv(i):
    try:
        return json.load(urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{i}", timeout=30))
    except Exception as e:
        return {"_error": str(e)}

def ghsa(cve):
    r = subprocess.run(["gh", "api", f"/advisories?cve_id={cve}"], capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except Exception:
        return []

for cve in sorted({t["cve_id"] for t in tasks}):
    p = OUT / f"{cve}.json"
    if p.exists():
        continue
    rec = {"cve": cve, "osv_cve": osv(cve), "osv_aliases": {}, "github": ghsa(cve)}
    for a in rec["osv_cve"].get("aliases", []) or []:
        if a.startswith(("GHSA-", "GO-", "PYSEC-")):
            rec["osv_aliases"][a] = osv(a)
    for g in rec["github"]:
        gid = g.get("ghsa_id")
        if gid and gid not in rec["osv_aliases"]:
            rec["osv_aliases"][gid] = osv(gid)
    p.write_text(json.dumps(rec, indent=1))
    print(cve, "aliases:", list(rec["osv_aliases"]), "gh:", len(rec["github"]), flush=True)
