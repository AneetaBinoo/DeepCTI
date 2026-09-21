import pytest

from deepcti.cli import select_cases


def test_select_cases_locks_confirmatory_suffix() -> None:
    cases = list(range(100))
    assert select_cases(cases, start=10, maximum=90) == list(range(10, 100))


def test_select_cases_rejects_invalid_ranges() -> None:
    with pytest.raises(ValueError):
        select_cases([1, 2], start=-1, maximum=1)
    with pytest.raises(ValueError):
        select_cases([1, 2], start=0, maximum=0)
