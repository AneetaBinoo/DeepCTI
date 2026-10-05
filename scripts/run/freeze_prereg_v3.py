"""Append the hash block to prereg/PREREGISTRATION_V3.md. Run once, then commit and tag prereg-v3."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "run"))
from freeze_prereg import sha, tree_hash  # noqa: E402


def main() -> None:
    hosts, n = tree_hash(ROOT / "data" / "d7" / "hosts")
    (ROOT / "data" / "d7" / "HOSTS_TREE.sha256").write_text(f"{hosts}  files={n}\n")
    files = ["data/sealed/d7_test_labels.jsonl", "data/d7/cases/test.jsonl", "data/d7/cases/dev.jsonl",
             "data/d7/cases/calib.jsonl", "data/d7/cve_meta.jsonl", "config/source_profiles_v3.yaml",
             "config/priors_v3.yaml", "config/config_preconditions_v3.yaml", "config/models.yaml",
             "prompts/core_spec_v3.md", "scripts/paper/analyze_v3.py", "scripts/data/build_drift_v3.py",
             "src/deepcti/core/versions.py", "src/deepcti/extraction/verifier.py"]
    commit = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    block = ["", f"Code commit at freeze: `{commit}`", "", "| file | SHA-256 |", "|---|---|"]
    block += [f"| `{f}` | `{sha(ROOT / f)}` |" for f in files]
    block += [f"| `data/d7/hosts (tree)` | `{hosts}` ({n} files) |", ""]
    path = ROOT / "prereg" / "PREREGISTRATION_V3.md"
    text = path.read_text().split("## 5. Hashes (filled at tag time)")[0]
    path.write_text(text + "## 5. Hashes (filled at tag time)\n" + "\n".join(block))
    print("\n".join(block))
    _ = hashlib


if __name__ == "__main__":
    main()
