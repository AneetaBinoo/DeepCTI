"""Shared test configuration: the active dataset is process-global state; reset it around every test."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


@pytest.fixture(autouse=True)
def _reset_dataset():
    from deepcti.eval import data
    data.set_dataset("d1")
    yield
    data.set_dataset("d1")
