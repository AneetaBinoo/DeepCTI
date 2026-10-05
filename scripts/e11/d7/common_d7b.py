"""Shared paths and helpers for the POST HOC E11-D7b analysis (DEVIATIONS D23): DCv21b vs DC (and vs DCv21).

The pipeline is the E11-D7 (H15) pipeline unchanged (common_d7.EpisodeView, judge.d7 replay/context, same prompts,
same judges, same metrics/bootstrap/sign-flip); only the inputs differ:
- DCv21b episodes: runs/d7/test/X2B/<model>.jsonl (exactly the H15 sample triples of DCv21);
- DC / DCv21 claims and judgements are REUSED from results/v3/e11_d7 (not re-judged);
- DCv21b LLM calls are cached in results/v3/e11_d7b/cache/ (the E11-D7 caches are read-only here).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from common_d7 import GENERATORS, OUT, ROOT, read_jsonl  # noqa: F401  (also sets dataset d7, sys.path)

from deepcti.judge.llm import Cache, JudgeLLM

OUT_B = ROOT / "results" / "v3" / "e11_d7b"
CACHE_B = OUT_B / "cache"
RUNS_B = ROOT / "runs" / "d7" / "test" / "X2B"
SYSTEM_B = "DCv21b"
OUT_A = OUT  # results/v3/e11_d7 (H15 inputs: DC, DCv21)

_caches: dict[str, Cache] = {}
_clients: dict[tuple, JudgeLLM] = {}
_lock = threading.Lock()


def client(name: str, purpose: str, max_tokens: int = 700) -> JudgeLLM:
    """As common_d7.client, but cached in results/v3/e11_d7b/cache/."""
    with _lock:
        if purpose not in _caches:
            _caches[purpose] = Cache(CACHE_B / f"{purpose}.jsonl")
        k = (name, purpose, max_tokens)
        if k not in _clients:
            _clients[k] = JudgeLLM(name, _caches[purpose], max_tokens)
        return _clients[k]


def load_b_records() -> dict[str, dict]:
    """All X2B (DCv21b) records, keyed by record key."""
    out = {}
    for m in GENERATORS:
        for line in (RUNS_B / f"{m}.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                assert r["system"] == SYSTEM_B, r["key"]
                out[r["key"]] = r
    return out


def h15_triples() -> set[tuple[str, str, str]]:
    """(case_id, model, arm) of the DCv21 rows of the H15 sample."""
    import pandas as pd
    s = pd.read_csv(OUT_A / "sample.csv")
    s = s[s.system == "DCv21"]
    return set(zip(s.case_id, s.model, s.arm))
