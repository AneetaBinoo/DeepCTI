"""Shared paths and helpers for the E11 scripts."""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from deepcti.judge.evidence import context_block, dc_state_item, evidence_block, replay
from deepcti.judge.llm import JUDGES, Cache, JudgeLLM

OUT = ROOT / "results" / "v3" / "e11"
CACHE = OUT / "cache"
RUNS = ROOT / "runs" / "test" / "E2"
GENERATORS = ["gemma4_31b", "granite41_8b", "llama31_8b", "mistral_small_24b", "qwen3_14b", "qwen3_4b"]
SYSTEMS = ["DC", "S2", "S3", "S4", "S5"]
ARMS = ["tracker", "withheld"]
JUDGE_NAMES = list(JUDGES)
SEED = 20261005


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def load_sampled_records() -> dict[str, dict]:
    """Raw E2 records of the sampled episodes, keyed by record key."""
    import pandas as pd
    sample = pd.read_csv(OUT / "sample.csv")
    want = set(sample["key"])
    out = {}
    for m in GENERATORS:
        for line in (RUNS / f"{m}.jsonl").read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if r["key"] in want:
                out[r["key"]] = r
    return out


class EpisodeView:
    """Replayed evidence and prompt blocks for one record."""

    def __init__(self, rec: dict):
        self.rec = rec
        self.items, self.check = replay(rec)
        self.context = context_block(rec, self.check)
        self.ids = [it["id"] for it in self.items]
        self.state = dc_state_item(rec) if rec["system"] == "DC" else None

    def evidence(self, *, with_state: bool = True, only: set[str] | None = None) -> str:
        items = list(self.items)
        if with_state and self.state is not None and only is None:
            items.append(self.state)
        return evidence_block(items, self.rec["system"], only=only)

    def evidence_text_all(self) -> str:
        return "\n".join(it["output"] for it in self.items) + "\n" + (self.state["output"] if self.state else "")


_caches: dict[str, Cache] = {}
_clients: dict[tuple, JudgeLLM] = {}
_lock = threading.Lock()


def client(name: str, purpose: str, max_tokens: int = 700) -> JudgeLLM:
    with _lock:
        if purpose not in _caches:
            _caches[purpose] = Cache(CACHE / f"{purpose}.jsonl")
        k = (name, purpose, max_tokens)
        if k not in _clients:
            _clients[k] = JudgeLLM(name, _caches[purpose], max_tokens)
        return _clients[k]


# concurrency per endpoint: gemma/mistral/qwen are otherwise idle; granite/nemotron are shared with panel runs
CONCURRENCY = {"gemma_4_31b": 32, "mistral_small_24b": 32, "qwen3_14b": 32, "granite_41_30b": 16,
               "nemotron_super_49b": 16}


def run_parallel(tasks: list[tuple[str, Callable[[], dict]]], per_judge: int | None = None, log_every: int = 500,
                 label: str = "") -> list[dict]:
    """tasks: (judge name, thunk). Runs with a bounded pool per judge; returns results in task order."""
    import time
    results: list[dict | None] = [None] * len(tasks)
    by_judge: dict[str, list[int]] = {}
    for i, (j, _) in enumerate(tasks):
        by_judge.setdefault(j, []).append(i)
    t0 = time.time()
    done = [0]
    pools = {j: ThreadPoolExecutor(max_workers=per_judge or CONCURRENCY.get(j, 16)) for j in by_judge}
    futs = {}
    for j, idxs in by_judge.items():
        for i in idxs:
            futs[pools[j].submit(tasks[i][1])] = i
    for f in as_completed(futs):
        results[futs[f]] = f.result()
        done[0] += 1
        if done[0] % log_every == 0 or done[0] == len(tasks):
            print(f"[{label}] {done[0]}/{len(tasks)} {time.time() - t0:.0f}s", flush=True)
    for p in pools.values():
        p.shutdown()
    return results  # type: ignore[return-value]
