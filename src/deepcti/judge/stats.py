"""Agreement statistics and CVE-clustered bootstrap for E11."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence

import numpy as np
import pandas as pd


def cohen_kappa(a: Sequence, b: Sequence) -> float:
    assert len(a) == len(b) and len(a) > 0
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[k] * cb.get(k, 0) for k in ca) / (n * n)
    return float("nan") if pe == 1 else (po - pe) / (1 - pe)


def fleiss_kappa(counts: Sequence[Sequence[int]]) -> float:
    """counts[i][j] = number of raters assigning item i to category j (same rater count per item)."""
    m = np.asarray(counts, dtype=float)
    n_items, _ = m.shape
    r = m.sum(axis=1)
    assert np.all(r == r[0]) and r[0] >= 2
    r = r[0]
    p_j = m.sum(axis=0) / (n_items * r)
    p_i = ((m * m).sum(axis=1) - r) / (r * (r - 1))
    pbar, pe = p_i.mean(), (p_j ** 2).sum()
    return float("nan") if pe == 1 else float((pbar - pe) / (1 - pe))


def cluster_bootstrap(df: pd.DataFrame, cluster: str, stat: Callable[[pd.DataFrame], float], n: int = 2000,
                      seed: int = 0, alpha: float = 0.05) -> tuple[float, float, float]:
    """Point estimate and percentile CI, resampling clusters with replacement."""
    est = float(stat(df))
    groups = {k: g for k, g in df.groupby(cluster, sort=True)}
    keys = list(groups)
    if len(keys) < 2:
        return est, float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n):
        pick = rng.integers(0, len(keys), len(keys))
        sample = pd.concat([groups[keys[i]] for i in pick], ignore_index=True)
        v = stat(sample)
        if v == v:
            vals.append(v)
    lo, hi = np.quantile(vals, [alpha / 2, 1 - alpha / 2]) if vals else (float("nan"), float("nan"))
    return est, float(lo), float(hi)


def ratio_ci(df: pd.DataFrame, cluster: str, num: str, den: str, n: int = 2000, seed: int = 0,
             alpha: float = 0.05) -> tuple[float, float, float]:
    """Ratio Σnum/Σden with a cluster percentile bootstrap (fast path: per-cluster sums)."""
    g = df.groupby(cluster)[[num, den]].sum()
    a, b = g[num].to_numpy(float), g[den].to_numpy(float)
    if b.sum() == 0:
        return float("nan"), float("nan"), float("nan")
    est = a.sum() / b.sum()
    if len(a) < 2:
        return float(est), float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(a), (n, len(a)))
    bs, bd = a[idx].sum(1), b[idx].sum(1)
    vals = bs[bd > 0] / bd[bd > 0]
    lo, hi = np.quantile(vals, [alpha / 2, 1 - alpha / 2])
    return float(est), float(lo), float(hi)


def ratio_diff_ci(a: pd.DataFrame, b: pd.DataFrame, cluster: str, num: str, den: str, n: int = 2000, seed: int = 0,
                  alpha: float = 0.05) -> tuple[float, float, float]:
    """(Σnum/Σden)_a − (Σnum/Σden)_b with a paired cluster bootstrap (same clusters resampled for both)."""
    ga = a.groupby(cluster)[[num, den]].sum()
    gb = b.groupby(cluster)[[num, den]].sum()
    keys = sorted(set(ga.index) | set(gb.index))
    ga, gb = ga.reindex(keys, fill_value=0), gb.reindex(keys, fill_value=0)
    an, ad = ga[num].to_numpy(float), ga[den].to_numpy(float)
    bn, bd = gb[num].to_numpy(float), gb[den].to_numpy(float)
    est = an.sum() / ad.sum() - bn.sum() / bd.sum()
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(keys), (n, len(keys)))
    sa, sb = ad[idx].sum(1), bd[idx].sum(1)
    ok = (sa > 0) & (sb > 0)
    vals = an[idx].sum(1)[ok] / sa[ok] - bn[idx].sum(1)[ok] / sb[ok]
    lo, hi = np.quantile(vals, [alpha / 2, 1 - alpha / 2])
    return float(est), float(lo), float(hi)
