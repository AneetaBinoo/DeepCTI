"""E0 retrospective question audit (Paper 2): run deepcti.inquiry.audit over existing Paper 1 run logs.

No LLM calls; CPU only. Inputs: non-attack, non-pilot blocks under runs/{test,calib} and runs/d7/{test,calib}
(attack blocks E5/KM are excluded: their tool outputs depend on attack carriers the audit does not model).
Outputs (results/inquiry/e0/):
  episodes.csv.gz  one row per episode (labels from the unsealed Paper 1 test/calib labels)
  calls.csv.gz     one row per tool call
  run_meta.json    inputs, counts, replay-mismatch and failure counts

  .venv/bin/python scripts/inquiry/audit_e0.py [--workers 100] [--blocks test/E2,d7/test/X2] [--limit-per-file N]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from multiprocessing import Pool
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

EXCLUDE = {"E5", "KM"}
FIXTURE_CACHE_MAX = 16      # host fixtures hold whole root file systems in memory: keep few per worker
MIN_AVAILABLE_GB = 64.0     # watchdog: kill the pool before the machine (and other users' servers) runs out
SPLITS = ("test", "calib")
OUT = ROOT / "results" / "inquiry" / "e0"


def block_files(only: set[str] | None) -> list[Path]:
    files = []
    for base in ("runs", "runs/d7"):
        for split in SPLITS:
            d = ROOT / base / split
            if not d.is_dir():
                continue
            for blk in sorted(p for p in d.iterdir() if p.is_dir()):
                name = blk.name
                if name in EXCLUDE or any(t in name for t in ("pilot", "smoke", "validation", "_final")):
                    continue
                tag = f"{'d7/' if base.endswith('d7') else ''}{split}/{name}"
                if only and tag not in only:
                    continue
                files += sorted(blk.glob("*.jsonl"))
    return files


_LABELS: dict = {}


def labels_for(dataset: str, split: str) -> dict:
    from deepcti.eval import data
    k = (dataset, split)
    if k not in _LABELS:
        data.set_dataset(dataset)
        _LABELS[k] = data.load_labels(split, allow_sealed=True)
    return _LABELS[k]


def work(task: tuple[str, int, int]) -> tuple[list[dict], list[dict], list[str]]:
    from deepcti.eval import data  # noqa: F811
    from deepcti.eval.metrics import episode_metrics
    from deepcti.inquiry.audit import audit_record, record_dataset
    path, lo, hi = task
    eps, calls, fails = [], [], []
    with open(path) as fh:
        for i, line in enumerate(fh):
            if i < lo:
                continue
            if i >= hi:
                break
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("error") or r.get("attack"):
                continue
            if data._fixture.cache_info().currsize > FIXTURE_CACHE_MAX:  # noqa: SLF001
                data._fixture.cache_clear()  # noqa: SLF001
            try:
                ds = record_dataset(r)
                labels = labels_for(ds, r.get("split", "test"))
                data.set_dataset(ds)
                ep, rows = audit_record(r)
                m = episode_metrics(r, labels)
                ep.update({"gold_label": m["gold"], "pred": m["pred"], "loss": m["loss"],
                           "dangerous": bool(m["dangerous"]), "correct": bool(m["correct"]),
                           "covered": bool(m["covered"]), "source_file": str(Path(path).relative_to(ROOT))})
                eps.append(ep)
                calls += [{"key": r["key"], "source_file": ep["source_file"], **row} for row in rows]
            except Exception:  # noqa: BLE001 - recorded, never silently dropped
                fails.append(f"{path}:{i}:{r.get('key')}: {traceback.format_exc(limit=3)}")
    return eps, calls, fails


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--blocks", default="")
    ap.add_argument("--chunk", type=int, default=400)
    ap.add_argument("--limit-per-file", type=int, default=0)
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()
    only = set(args.blocks.split(",")) if args.blocks else None
    files = block_files(only)
    tasks = []
    for f in files:
        n = sum(1 for _ in open(f))
        if args.limit_per_file:
            n = min(n, args.limit_per_file)
        tasks += [(str(f), lo, min(lo + args.chunk, n)) for lo in range(0, n, args.chunk)]
    t0 = time.time()
    eps, calls, fails = [], [], []
    import threading

    def available_gb() -> float:
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1e6
        return float("inf")

    stop = threading.Event()
    with Pool(args.workers, maxtasksperchild=1) as pool:
        def watchdog() -> None:
            while not stop.is_set():
                if available_gb() < MIN_AVAILABLE_GB:
                    print(f"WATCHDOG: available memory {available_gb():.0f} GB < {MIN_AVAILABLE_GB} GB; terminating",
                          flush=True)
                    pool.terminate()
                    return
                stop.wait(2.0)
        threading.Thread(target=watchdog, daemon=True).start()
        for i, (e, c, fl) in enumerate(pool.imap_unordered(work, tasks, chunksize=1)):
            eps += e
            calls += c
            fails += fl
            if (i + 1) % 50 == 0 or i + 1 == len(tasks):
                print(f"[{i + 1}/{len(tasks)}] episodes {len(eps)} failures {len(fails)} {time.time() - t0:.0f}s "
                      f"avail {available_gb():.0f} GB", flush=True)
        stop.set()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    edf = pd.DataFrame(eps).sort_values("key")
    cdf = pd.DataFrame(calls).sort_values(["key", "call_id"])
    edf.to_csv(out / "episodes.csv.gz", index=False)
    cdf.to_csv(out / "calls.csv.gz", index=False)
    (out / "failures.txt").write_text("\n".join(fails))
    meta = {"files": [str(Path(f).relative_to(ROOT)) for f in files], "episodes": len(edf), "calls": len(cdf),
            "failures": len(fails), "replay_mismatch_episodes": int((edf["replay_mismatches"] > 0).sum()),
            "gold_oracle_vs_label_disagree": int((edf["gold"] != edf["gold_label"]).sum()),
            "seconds": round(time.time() - t0, 1)}
    (out / "run_meta.json").write_text(json.dumps(meta, indent=1))
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    main()
