"""Shared helpers for the DeepCTI v2 data pipeline (paths, cached HTTP, manifests, versions)."""

from __future__ import annotations

import hashlib
import json
import os
import random
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from debian.debian_support import Version

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
MIRRORS = DATA / "mirrors"
SNAP_DATE = "2026-10-05"
SEED = 20261005
RELEASES = ("bullseye", "bookworm", "trixie")
RELEASE_NUM = {"bullseye": "11", "bookworm": "12", "trixie": "13"}
UA = "DeepCTI-research-dataset/2.0 (academic; contact via repo)"

_session = requests.Session()
_session.headers["User-Agent"] = UA
_rate_lock = threading.Lock()
_last_call: dict[str, float] = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def mirror_dir(source: str) -> Path:
    d = MIRRORS / source / SNAP_DATE
    d.mkdir(parents=True, exist_ok=True)
    return d


def _throttle(key: str, min_interval: float) -> None:
    with _rate_lock:
        last = _last_call.get(key, 0.0)
        wait = last + min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_call[key] = time.monotonic()


def fetch_cached(
    url: str,
    dest: Path,
    *,
    min_interval: float = 0.0,
    throttle_key: str = "default",
    retries: int = 5,
    ok_status: tuple[int, ...] = (200,),
    timeout: int = 120,
) -> tuple[Path, bool]:
    """Download url to dest unless it already exists. Returns (path, fetched_now).

    A 404 response is cached as a small JSON stub ``{"_status": 404}`` so that resumes skip it.
    """
    if dest.exists() and dest.stat().st_size > 0:
        return dest, False
    dest.parent.mkdir(parents=True, exist_ok=True)
    err: Exception | None = None
    for attempt in range(retries):
        if min_interval:
            _throttle(throttle_key, min_interval)
        try:
            r = _session.get(url, timeout=timeout, stream=True)
            if r.status_code == 404:
                dest.write_text(json.dumps({"_status": 404, "_url": url}))
                return dest, True
            if r.status_code in (403, 429, 500, 502, 503, 504):
                raise requests.HTTPError(f"HTTP {r.status_code} for {url}")
            if r.status_code not in ok_status:
                raise requests.HTTPError(f"HTTP {r.status_code} for {url}")
            tmp = dest.with_suffix(dest.suffix + ".part")
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(1 << 20):
                    f.write(chunk)
            os.replace(tmp, dest)
            return dest, True
        except Exception as e:  # noqa: BLE001 - retry any transport error
            err = e
            time.sleep(min(60, 3 * 2**attempt) + random.random())
    raise RuntimeError(f"failed to fetch {url}: {err}")


class Manifest:
    """MANIFEST.json for one mirror source/date (outside raw/)."""

    def __init__(self, source: str, license_note: str):
        self.dir = mirror_dir(source)
        self.path = self.dir / "MANIFEST.json"
        self.lock = threading.Lock()
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
        else:
            self.data = {"source": source, "snapshot_date": SNAP_DATE, "license": license_note, "files": {}}
        self.data["license"] = license_note

    def add(self, url: str, path: Path, retrieved_at: str | None = None, **extra: Any) -> None:
        rel = str(path.relative_to(self.dir))
        with self.lock:
            prev = self.data["files"].get(rel)
            if prev and prev.get("bytes") == path.stat().st_size and retrieved_at is None:
                return
            self.data["files"][rel] = {
                "url": url,
                "retrieved_at": retrieved_at or (prev or {}).get("retrieved_at") or now_iso(),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                **extra,
            }

    def save(self) -> None:
        with self.lock:
            self.data["n_files"] = len(self.data["files"])
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True))
            os.replace(tmp, self.path)


def vcmp(a: str, b: str) -> int:
    """dpkg --compare-versions semantics via python-debian."""
    va, vb = Version(a), Version(b)
    return (va > vb) - (va < vb)


def upstream_of(v: str) -> str:
    return Version(v).upstream_version


def read_jsonl(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=False) + "\n")


ARCHIVE_SUITES = {
    "bullseye": ["bullseye", "bullseye-updates", "bullseye-security"],
    "bookworm": ["bookworm", "bookworm-updates", "bookworm-security"],
    "trixie": ["trixie", "trixie-updates", "trixie-security"],
}


def load_packages(release: str) -> dict[str, dict]:
    """Binary package name -> Packages paragraph (highest version over release, -updates, -security).

    Each paragraph gets an extra key "_suite". Cached as JSON under data/cache/.
    """
    import lzma

    from debian.deb822 import Packages

    cache = DATA / "cache" / f"packages_{release}_{SNAP_DATE}.json"
    if cache.exists():
        return json.loads(cache.read_text())
    out: dict[str, dict] = {}
    for suite in ARCHIVE_SUITES[release]:
        p = MIRRORS / "debian_archive" / SNAP_DATE / "raw" / suite / "main_binary-amd64_Packages.xz"
        with lzma.open(p, "rt", encoding="utf-8") as f:
            for para in Packages.iter_paragraphs(f, use_apt_pkg=False):
                d = dict(para)
                d["_suite"] = suite
                name = d["Package"]
                if name not in out or Version(d["Version"]) > Version(out[name]["Version"]):
                    out[name] = d
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(out))
    return out


def src_of(para: dict) -> tuple[str, str]:
    """(source name, source version) of a Packages/status paragraph."""
    src = para.get("Source", para["Package"]).strip()
    if "(" in src:
        name, ver = src.split("(", 1)
        return name.strip(), ver.rstrip(")").strip()
    return src, para["Version"]
