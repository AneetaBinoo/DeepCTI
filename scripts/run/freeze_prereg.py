"""Append the hash block to prereg/PREREGISTRATION.md and write policies/*.cedar + data manifests.

Run once, then commit and `git tag prereg-v1`.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from deepcti.policy.pdp import POLICIES, lint_policy, write_policy_files  # noqa: E402


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_hash(root: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode())
            h.update(sha(p).encode())
            n += 1
    return h.hexdigest(), n


def main() -> None:
    files = write_policy_files(ROOT / "policies")
    lint = {name: lint_policy(p.read_text(), {"present": POLICIES[name].k_world,
                                              "in_affected_range": POLICIES[name].k_world,
                                              "vuln_config_enabled": POLICIES[name].k_world})
            for name, p in files.items()}
    hosts_hash, n_hosts_files = tree_hash(ROOT / "data" / "d1" / "hosts")
    (ROOT / "data" / "d1" / "HOSTS_TREE.sha256").write_text(f"{hosts_hash}  files={n_hosts_files}\n")
    entries = {
        "data/sealed/test_labels.jsonl": sha(ROOT / "data/sealed/test_labels.jsonl"),
        "data/d1/cases/test.jsonl": sha(ROOT / "data/d1/cases/test.jsonl"),
        "data/d1/cases/dev.jsonl": sha(ROOT / "data/d1/cases/dev.jsonl"),
        "data/d1/cases/calib.jsonl": sha(ROOT / "data/d1/cases/calib.jsonl"),
        "data/d1/cve_meta.jsonl": sha(ROOT / "data/d1/cve_meta.jsonl"),
        "data/d1/hosts (tree)": f"{hosts_hash} ({n_hosts_files} files)",
        "prompts/core_spec.md": sha(ROOT / "prompts/core_spec.md"),
        "config/source_profiles.yaml": sha(ROOT / "config/source_profiles.yaml"),
        "config/priors.yaml": sha(ROOT / "config/priors.yaml"),
        "config/config_preconditions.yaml": sha(ROOT / "config/config_preconditions.yaml"),
        "config/models.yaml": sha(ROOT / "config/models.yaml"),
        "scripts/paper/analyze.py": sha(ROOT / "scripts/paper/analyze.py"),
        "scripts/data/build_d2_d3.py": sha(ROOT / "scripts/data/build_d2_d3.py"),
        **{f"policies/{p.name}": sha(p) for p in files.values()},
    }
    commit = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    block = ["", f"Code commit at freeze (parent of the tag commit): `{commit}`", "",
             "| file | SHA-256 |", "|---|---|"]
    block += [f"| `{k}` | `{v}` |" for k, v in entries.items()]
    block += ["", "Policy linter (T4 positive-threshold fragment): " + json.dumps(
        {k: ("ok" if not v else f"{len(v)} violations (expected for P0/P1)") for k, v in lint.items()}), ""]
    path = ROOT / "prereg" / "PREREGISTRATION.md"
    text = path.read_text(encoding="utf-8")
    marker = "## 8. Hashes (filled at tag time by scripts/run/freeze_prereg.py)"
    text = text.split(marker)[0] + marker + "\n" + "\n".join(block)
    path.write_text(text, encoding="utf-8")
    print("\n".join(block))


if __name__ == "__main__":
    main()
