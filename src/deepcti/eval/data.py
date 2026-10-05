"""Loading D1 cases, fixtures, CVE metadata, advisories and (non-sealed) labels."""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

import yaml

from ..env.host import Fixture

ROOT = Path(__file__).resolve().parents[3]
D1 = ROOT / "data" / "d1"
SEALED = ROOT / "data" / "sealed"
_DS = {"name": "d1"}  # active dataset: d1 (v2 benchmark) or d7 (v3 DeepCTI-Live-X)
SEALED_LABELS = {"d1": "test_labels.jsonl", "d7": "d7_test_labels.jsonl"}
PRECONDITIONS = {"d1": "config_preconditions.yaml", "d7": "config_preconditions_v3.yaml"}


def set_dataset(name: str) -> None:
    if name not in SEALED_LABELS:
        raise ValueError(f"unknown dataset {name}")
    _DS["name"] = name


def dataset() -> str:
    return _DS["name"]


def ds_root() -> Path:
    return ROOT / "data" / _DS["name"]


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_cases(split: str, root: Path | None = None) -> list[dict]:
    return read_jsonl((root or ds_root()) / "cases" / f"{split}.jsonl")


def cve_meta() -> dict[str, dict]:
    return _cve_meta(_DS["name"])


@lru_cache(maxsize=4)
def _cve_meta(ds: str) -> dict[str, dict]:
    return {row["cve"]: row for row in read_jsonl(ROOT / "data" / ds / "cve_meta.jsonl")}


def preconditions() -> dict[str, dict]:
    return _preconditions(_DS["name"])


@lru_cache(maxsize=4)
def _preconditions(ds: str) -> dict[str, dict]:
    path = ROOT / "config" / PRECONDITIONS[ds]
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None
    items = data.get("preconditions", data) if isinstance(data, dict) else (data or [])
    if isinstance(items, dict):
        items = [dict(v, cve=k) for k, v in items.items()]
    return {item["cve"]: item for item in items if isinstance(item, dict) and "cve" in item}


def advisories(cve: str) -> dict[str, str]:
    return _advisories(_DS["name"], cve)


@lru_cache(maxsize=8192)
def _advisories(ds: str, cve: str) -> dict[str, str]:
    path = ROOT / "data" / ds / "advisories" / f"{cve}.json"
    if not path.exists():
        return {}
    return {k: str(v) for k, v in json.loads(path.read_text(encoding="utf-8")).items()}


def fixture(host_id: str) -> Fixture:
    return _fixture(_DS["name"], host_id)


@lru_cache(maxsize=4096)
def _fixture(ds: str, host_id: str) -> Fixture:
    return Fixture.load(ROOT / "data" / ds / "hosts" / host_id)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_labels(split: str, *, allow_sealed: bool = False) -> dict[str, dict]:
    """Labels by case_id. Test labels are only readable after the pre-registration tag."""
    if split != "test":
        return {c["case_id"]: {"label": c["label"], "atoms": c.get("atoms", {})} for c in load_cases(split)}
    if not allow_sealed:
        raise PermissionError("test labels are sealed; pass allow_sealed=True only after tag prereg-v1")
    return {r["case_id"]: r for r in read_jsonl(SEALED / SEALED_LABELS[_DS["name"]])}
