"""Fetch official debian:<release>-slim (linux/amd64) via the Docker Registry v2 HTTP API (anonymous).

Only etc/, var/lib/dpkg/ and usr/lib/os-release are extracted into data/base_images/<release>/rootfs.
Layer blobs are cached in data/mirrors/docker_hub/<date>/raw/ ; digests go to MANIFEST.json and
data/base_images/<release>/IMAGE.json.
"""

from __future__ import annotations

import json
import shutil
import sys
import tarfile
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA, Manifest, now_iso, sha256_file  # noqa: E402

REG = "https://registry-1.docker.io/v2/library/debian"
ACCEPT_INDEX = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
)
ACCEPT_MANIFEST = ", ".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
KEEP_PREFIXES = ("etc/", "var/lib/dpkg/")
KEEP_FILES = ("usr/lib/os-release",)


def token() -> str:
    r = requests.get(
        "https://auth.docker.io/token",
        params={"service": "registry.docker.io", "scope": "repository:library/debian:pull"},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["token"]


def fetch(release: str, man: Manifest) -> dict:
    tag = f"{release}-slim"
    tok = token()
    h = {"Authorization": f"Bearer {tok}", "Accept": ACCEPT_INDEX}
    r = requests.get(f"{REG}/manifests/{tag}", headers=h, timeout=60)
    r.raise_for_status()
    index_digest = r.headers.get("Docker-Content-Digest")
    index = r.json()
    raw = man.dir / "raw" / release
    raw.mkdir(parents=True, exist_ok=True)
    (man.dir / f"{release}_index.json").write_text(json.dumps(index, indent=1))
    man.add(f"{REG}/manifests/{tag}", man.dir / f"{release}_index.json", now_iso(), digest=index_digest)
    amd = [
        m
        for m in index["manifests"]
        if m.get("platform", {}).get("architecture") == "amd64"
        and m["platform"].get("os") == "linux"
        and not m["platform"].get("variant")
    ]
    mdigest = amd[0]["digest"]
    h["Accept"] = ACCEPT_MANIFEST
    r = requests.get(f"{REG}/manifests/{mdigest}", headers=h, timeout=60)
    r.raise_for_status()
    manifest = r.json()
    (man.dir / f"{release}_manifest_amd64.json").write_text(json.dumps(manifest, indent=1))
    man.add(
        f"{REG}/manifests/{mdigest}", man.dir / f"{release}_manifest_amd64.json", now_iso(), digest=mdigest
    )
    layers = []
    for layer in manifest["layers"]:
        dg = layer["digest"]
        dest = raw / (dg.replace(":", "_") + ".tar.gz")
        if not dest.exists() or sha256_file(dest) != dg.split(":")[1]:
            with requests.get(
                f"{REG}/blobs/{dg}", headers={"Authorization": f"Bearer {tok}"}, stream=True, timeout=300
            ) as rr:
                rr.raise_for_status()
                with open(dest, "wb") as f:
                    for chunk in rr.iter_content(1 << 20):
                        f.write(chunk)
            assert sha256_file(dest) == dg.split(":")[1], "layer digest mismatch"
        man.add(f"{REG}/blobs/{dg}", dest, now_iso(), digest=dg)
        layers.append(dest)
    root = DATA / "base_images" / release / "rootfs"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    for lp in layers:
        with tarfile.open(lp, "r:gz") as tf:
            members = [
                m
                for m in tf.getmembers()
                if (m.name.lstrip("./").startswith(KEEP_PREFIXES) or m.name.lstrip("./") in KEEP_FILES)
                and (m.isfile() or m.isdir() or m.issym())
            ]
            tf.extractall(root, members=members, filter="tar")
    info = {
        "release": release,
        "image": f"debian:{tag}",
        "index_digest": index_digest,
        "manifest_digest_amd64": mdigest,
        "reference": f"debian:{tag}@{index_digest}",
        "layers": [m["digest"] for m in manifest["layers"]],
        "retrieved_at": now_iso(),
        "extracted": list(KEEP_PREFIXES) + list(KEEP_FILES),
    }
    (DATA / "base_images" / release / "IMAGE.json").write_text(json.dumps(info, indent=1))
    return info


def main() -> None:
    man = Manifest("docker_hub", "Debian official images (Docker Official Images); DFSG-free contents")
    for rel in ("bullseye", "bookworm", "trixie"):
        info = fetch(rel, man)
        print(rel, info["reference"], info["manifest_digest_amd64"])
    man.save()


if __name__ == "__main__":
    main()
