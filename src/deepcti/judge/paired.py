"""Paired, CVE-clustered tests for a difference of two ratio estimators (E11-D7 / H15)."""

from __future__ import annotations

import numpy as np
import pandas as pd


def cluster_sums(a: pd.DataFrame, b: pd.DataFrame, cluster: str, num: str, den: str
                 ) -> tuple[list, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    ga = a.groupby(cluster)[[num, den]].sum()
    gb = b.groupby(cluster)[[num, den]].sum()
    keys = sorted(set(ga.index) | set(gb.index))
    ga, gb = ga.reindex(keys, fill_value=0), gb.reindex(keys, fill_value=0)
    return (keys, ga[num].to_numpy(float), ga[den].to_numpy(float), gb[num].to_numpy(float),
            gb[den].to_numpy(float))


def signflip_ratio_diff(a: pd.DataFrame, b: pd.DataFrame, cluster: str, num: str, den: str, n: int = 10000,
                        seed: int = 0) -> tuple[float, float]:
    """Two-sided cluster sign-flip (label-swap) p-value for (Σnum/Σden)_a − (Σnum/Σden)_b.

    Under H0 the system labels are exchangeable within a cluster, so each cluster's a- and b-sums are swapped
    with probability 1/2 and the ratio difference is recomputed. p = (1 + #{|T*| >= |T_obs|}) / (1 + n).
    """
    _, an, ad, bn, bd = cluster_sums(a, b, cluster, num, den)
    t_obs = an.sum() / ad.sum() - bn.sum() / bd.sum()
    rng = np.random.default_rng(seed)
    f = rng.integers(0, 2, (n, len(an))).astype(bool)
    xa_n = np.where(f, bn, an).sum(1)
    xa_d = np.where(f, bd, ad).sum(1)
    xb_n = np.where(f, an, bn).sum(1)
    xb_d = np.where(f, ad, bd).sum(1)
    t = xa_n / xa_d - xb_n / xb_d
    p = (1 + int(np.sum(np.abs(t) >= abs(t_obs) - 1e-12))) / (1 + n)
    return float(t_obs), float(p)
