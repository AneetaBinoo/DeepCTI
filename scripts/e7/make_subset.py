"""Select the VEX-Bench subset whose pinned checkout (sum of blob sizes from the
GitHub git/trees API, recursive, none truncated) is <= 200 MB. Full benchmark
materialisation = 7.09 GB > 5 GB budget, so the full download was not done."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VB = ROOT / "data/external/vex-bench"
CAP = 200e6
sizes = json.loads((ROOT / "results/v2/e7/checkout_sizes_github_tree_api.json").read_text())
tasks = [json.loads(l) for l in (VB / "benchmark/tasks/vex_bench.jsonl").read_text().splitlines() if l.strip()]
sel, excl = [], []
for t in tasks:
    key = t["repo_url"].replace("https://github.com/", "") + "@" + t["commit_sha"]
    (sel if sizes[key]["bytes"] <= CAP else excl).append(t)
uniq = {(t["repo_url"], t["commit_sha"]) for t in sel}
tot = sum(sizes[r.replace("https://github.com/", "") + "@" + c]["bytes"] for r, c in uniq)
out = ROOT / "results/v2/e7/subset_tasks.jsonl"
out.write_text("".join(json.dumps(t) + "\n" for t in sel))
(ROOT / "results/v2/e7/excluded_tasks.jsonl").write_text("".join(json.dumps(t) + "\n" for t in excl))
print(f"full={sum(v['bytes'] for v in sizes.values())/1e9:.2f}GB selected={len(sel)} tasks, {len(uniq)} checkouts, {tot/1e9:.2f}GB; excluded={len(excl)}")
