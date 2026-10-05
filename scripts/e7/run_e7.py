"""E7 runner: systems A/B x one model x seeds over the VEX-Bench subset.
Outputs runs/e7/<system>/<model>/<task_id>/run_<seed+1:03d>/{result.json,trace.json,meta.json}
(result.json = raw agent output in VEX-Bench's {"category","reasoning"} format)."""
import argparse, json, logging, sys, time, traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from deepcti.vexbench.advisory import load_advisory  # noqa: E402
from deepcti.vexbench.agent import run_system_a, run_system_b  # noqa: E402
sys.path.insert(0, str(ROOT / "data/external/vex-bench/src"))
from utils.repo import parse_owner_repo  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--model", required=True)
ap.add_argument("--systems", default="A,B")
ap.add_argument("--seeds", default="0,1,2")
ap.add_argument("--workers", type=int, default=8)
ap.add_argument("--tasks", default=str(ROOT / "results/v2/e7/subset_tasks.jsonl"))
ap.add_argument("--limit", type=int, default=0)
ap.add_argument("--out", default=str(ROOT / "runs/e7"))
args = ap.parse_args()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("e7")
tasks = [json.loads(l) for l in Path(args.tasks).read_text().splitlines() if l.strip()]
if args.limit:
    tasks = tasks[: args.limit]
REPOS = ROOT / "data/external/vex-bench/benchmark/repos"
FN = {"A": run_system_a, "B": run_system_b}


def job(system, task, seed):
    d = Path(args.out) / system / args.model / task["task_id"] / f"run_{seed + 1:03d}"
    if (d / "result.json").exists():
        return "cached"
    d.mkdir(parents=True, exist_ok=True)
    owner, repo = parse_owner_repo(task["repo_url"])
    src = REPOS / owner / repo / task["commit_sha"]
    adv = load_advisory(task["cve_id"], task["metadata"]["language"])
    try:
        r = FN[system](src, task, adv, args.model, seed)
    except Exception as e:  # noqa: BLE001
        (d / "error.txt").write_text(traceback.format_exc())
        return f"error {e}"
    meta = {"system": system, "model": args.model, "seed": seed, "task_id": task["task_id"],
            "category": r.category, "abstained": r.abstained, "tool_calls": r.tool_calls, "turns": r.turns,
            "prompt_tokens": r.prompt_tokens, "completion_tokens": r.completion_tokens,
            "seconds": round(r.seconds, 1), "end_reason": r.end_reason, **{k: v for k, v in r.extra.items() if k in ("rule", "state", "proposals", "verifier_searches")}}
    (d / "trace.json").write_text(json.dumps({"trace": r.trace, "extra": r.extra}, indent=1, default=str))
    (d / "meta.json").write_text(json.dumps(meta, indent=1))
    (d / "error.txt").unlink(missing_ok=True)
    (d / "result.json").write_text(r.raw_output)  # written last = completion marker
    return f"{r.category} tools={r.tool_calls} {r.end_reason} {r.seconds:.0f}s"


jobs = [(s, t, seed) for seed in [int(x) for x in args.seeds.split(",")] for t in tasks for s in args.systems.split(",")]
log.info("model=%s jobs=%d workers=%d", args.model, len(jobs), args.workers)
t0 = time.time()
with ThreadPoolExecutor(args.workers) as ex:
    futs = {ex.submit(job, *j): j for j in jobs}
    for i, f in enumerate(as_completed(futs), 1):
        s, t, seed = futs[f]
        try:
            msg = f.result()
        except Exception as e:  # noqa: BLE001
            msg = f"crash {e}"
        log.info("[%d/%d %.0fs] %s %s seed%d -> %s", i, len(jobs), time.time() - t0, s, t["task_id"], seed, msg)
log.info("ALL DONE")
