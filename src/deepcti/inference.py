from __future__ import annotations

import math
from collections.abc import Mapping

import numpy as np


def bootstrap_mean_ci(
    values: list[float],
    *,
    seed: int,
    resamples: int = 20_000,
    confidence: float = 0.95,
) -> tuple[float, float]:
    array = np.asarray(values, dtype=float)
    if array.size == 0:
        return (0.0, 0.0)
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, array.size, size=(resamples, array.size))
    estimates = array[indices].mean(axis=1)
    tail = (1.0 - confidence) / 2.0
    lower, upper = np.quantile(estimates, [tail, 1.0 - tail])
    return (float(lower), float(upper))


def paired_sign_flip_pvalue(
    differences: list[float],
    *,
    seed: int,
    permutations: int = 100_000,
    batch_size: int = 10_000,
) -> float:
    values = np.asarray(differences, dtype=float)
    if values.size == 0:
        return 1.0
    observed = abs(float(values.mean()))
    rng = np.random.default_rng(seed)
    extreme = 0
    completed = 0
    while completed < permutations:
        current = min(batch_size, permutations - completed)
        signs = rng.choice(np.array([-1.0, 1.0]), size=(current, values.size))
        permuted = np.abs((signs * values).mean(axis=1))
        extreme += int(np.count_nonzero(permuted >= observed - 1e-15))
        completed += current
    return (extreme + 1) / (permutations + 1)


def paired_standardized_mean_difference(differences: list[float]) -> float:
    values = np.asarray(differences, dtype=float)
    if values.size < 2:
        return 0.0
    standard_deviation = float(values.std(ddof=1))
    if math.isclose(standard_deviation, 0.0):
        return math.inf if values.mean() > 0 else -math.inf if values.mean() < 0 else 0.0
    return float(values.mean() / standard_deviation)


def holm_adjust(p_values: Mapping[str, float]) -> dict[str, float]:
    ordered = sorted(p_values.items(), key=lambda item: item[1])
    adjusted: dict[str, float] = {}
    running_maximum = 0.0
    count = len(ordered)
    for rank, (name, value) in enumerate(ordered):
        candidate = min(1.0, (count - rank) * float(value))
        running_maximum = max(running_maximum, candidate)
        adjusted[name] = running_maximum
    return adjusted
