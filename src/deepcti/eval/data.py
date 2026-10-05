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


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_cases(split: str, root: Path = D1) -> list[dict]:
    return read_jsonl(root / "cases" / f"{split}.jsonl")


@lru_cache(maxsize=1)
def cve_meta() -> dict[str, dict]:
    return {row["cve"]: row for row in read_jsonl(D1 / "cve_meta.jsonl")}


@lru_cache(maxsize=1)
def preconditions() -> dict[str, dict]:
    path = ROOT / "config" / "config_preconditions.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None
    items = data.get("preconditions", data) if isinstance(data, dict) else (data or [])
    if isinstance(items, dict):
        items = [dict(v, cve=k) for k, v in items.items()]
    return {item["cve"]: item for item in items if isinstance(item, dict) and "cve" in item}


@lru_cache(maxsize=4096)
def advisories(cve: str) -> dict[str, str]:
    path = D1 / "advisories" / f"{cve}.json"
    if not path.exists():
        return {}
    return {k: str(v) for k, v in json.loads(path.read_text(encoding="utf-8")).items()}


@lru_cache(maxsize=4096)
def fixture(host_id: str) -> Fixture:
    return Fixture.load(D1 / "hosts" / host_id)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_labels(split: str, *, allow_sealed: bool = False) -> dict[str, dict]:
    """Labels by case_id. Test labels are only readable after the pre-registration tag."""
    if split != "test":
        return {c["case_id"]: {"label": c["label"], "atoms": c.get("atoms", {})} for c in load_cases(split)}
    if not allow_sealed:
        raise PermissionError("test labels are sealed; pass allow_sealed=True only after tag prereg-v1")
    return {r["case_id"]: r for r in read_jsonl(SEALED / "test_labels.jsonl")}
