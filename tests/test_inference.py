import math

from deepcti.inference import (
    bootstrap_mean_ci,
    holm_adjust,
    paired_sign_flip_pvalue,
    paired_standardized_mean_difference,
)


def test_bootstrap_constant_difference_is_exact() -> None:
    lower, upper = bootstrap_mean_ci([0.5] * 30, seed=7, resamples=1_000)
    assert lower == 0.5
    assert upper == 0.5


def test_sign_flip_detects_consistent_paired_gain() -> None:
    p_value = paired_sign_flip_pvalue([0.5] * 30, seed=7, permutations=10_000)
    assert p_value < 0.001
    assert paired_standardized_mean_difference([0.5] * 30) == math.inf


def test_holm_adjustment_is_monotone() -> None:
    adjusted = holm_adjust({"a": 0.01, "b": 0.03, "c": 0.04})
    assert adjusted == {"a": 0.03, "b": 0.06, "c": 0.06}
