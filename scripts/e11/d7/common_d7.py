"""Shared paths and helpers for E11 on D7 (H15: DCv21 vs DC analyst-note faithfulness).

Same protocol as results/v3/e11/PROTOCOL.md (prompts, schemas, judges, soft labels, bootstrap); differences are
listed in results/v3/e11_d7/E11_D7_REPORT.md ("Deviations / adaptations").
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from deepcti.eval import data
from deepcti.judge.d7 import context_block_d7, replay_d7, state_item
from deepcti.judge.evidence import evidence_block
from deepcti.judge.llm import Cache, JudgeLLM

data.set_dataset("d7")

OUT = ROOT / "results" / "v3" / "e11_d7"
CACHE = OUT / "cache"
RUNS = ROOT / "runs" / "d7" / "test" / "X2"
GENERATORS = ["gemma4_31b", "granite41_30b", "granite41_8b", "llama31_8b", "mistral_small_24b", "qwen3_14b",
              "qwen3_4b"]
SYSTEMS = ["DC", "DCv21"]
ARMS = ["tracker", "withheld", "blind"]
E11_OUT = ROOT / "results" / "v3" / "e11"
VALIDATED = json.loads((E11_OUT / "validated_judges.json").read_text())["validated"]  # E11 judges that PASSED
SEED = 20261005
PER_SERVER = 16  # concurrency cap per judge endpoint (shared servers)


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
    import pandas as pd
    want = set(pd.read_csv(OUT / "sample.csv")["key"])
    out = {}
    for m in GENERATORS:
        for line in (RUNS / f"{m}.jsonl").read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if r["key"] in want:
                out[r["key"]] = r
    return out


class EpisodeView:
    """Replayed evidence (D7 environment) and prompt blocks for one record."""

    def __init__(self, rec: dict):
        self.rec = rec
        self.items, self.check = replay_d7(rec)
        self.context = context_block_d7(rec, self.check)
        self.ids = [it["id"] for it in self.items]
        self.state = state_item(rec)  # controller state (DC's prompt input); used for DC primary + DCv21 sensitivity

    def evidence(self, *, with_state: bool, only: set[str] | None = None) -> str:
        items = list(self.items)
        if with_state and self.state is not None and only is None:
            items.append(self.state)
        return evidence_block(items, "DC", only=only)  # DC/DCv21: 3,000-char cap (PROTOCOL §2)

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


def run_parallel(tasks: list[tuple[str, Callable[[], dict]]], per_judge: int = PER_SERVER, log_every: int = 500,
                 label: str = "") -> list[dict]:
    """tasks: (endpoint name, thunk); bounded pool per endpoint (≤ PER_SERVER); results in task order."""
    per_judge = min(per_judge, PER_SERVER)
    results: list[dict | None] = [None] * len(tasks)
    t0 = time.time()
    done = 0
    pools: dict[str, ThreadPoolExecutor] = {}
    futs = {}
    for i, (j, fn) in enumerate(tasks):
        if j not in pools:
            pools[j] = ThreadPoolExecutor(max_workers=per_judge)
        futs[pools[j].submit(fn)] = i
    for f in as_completed(futs):
        results[futs[f]] = f.result()
        done += 1
        if done % log_every == 0 or done == len(tasks):
            print(f"[{label}] {done}/{len(tasks)} {time.time() - t0:.0f}s", flush=True)
    for p in pools.values():
        p.shutdown()
    return results  # type: ignore[return-value]
