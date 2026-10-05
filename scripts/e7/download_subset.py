"""Download pinned checkouts for the subset using VEX-Bench's own downloader
function (builder.download.download_src_with_commit: shallow fetch of the exact
commit, .git removed)."""
import json, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VB = ROOT / "data/external/vex-bench"
sys.path.insert(0, str(VB / "src"))
from builder.download import download_src_with_commit  # noqa: E402

tasks = [json.loads(l) for l in (ROOT / "results/v2/e7/subset_tasks.jsonl").read_text().splitlines() if l.strip()]
jobs = sorted({(t["repo_url"], t["commit_sha"]) for t in tasks})

def go(j):
    try:
        p = download_src_with_commit(j[0], j[1], VB / "benchmark/repos")
        print("OK", j, p, flush=True)
    except Exception as e:
        print("FAIL", j, e, flush=True)

with ThreadPoolExecutor(6) as ex:
    list(ex.map(go, jobs))
print("DONE")
