"""Export the E2 test-split episodes as a long CSV for the GLMM (scripts/stats/glmm.R).

    .venv/bin/python scripts/stats/export_long.py [--out results/v3/glmm/e2_test_long.csv]

Post-hoc addition to v2 (V3 plan G8; the plan §8.2 GLMM replaces the v2 GEE fallback). Reads sealed test labels,
which is permitted after tag ``prereg-v1`` (checked below). Filtering is identical to scripts/paper/summarize.py
``load_runs``: error records dropped, records whose label disagrees with the start-of-episode world excluded,
duplicate keys keep the last record. Only the main E2 configuration is kept (budget 60, no attack, no drift, no
prompt defence, temperature 0, seed 0).
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from deepcti.eval import data  # noqa: E402
from deepcti.eval.metrics import episode_metrics  # noqa: E402
from deepcti.llm.client import load_models  # noqa: E402

COLUMNS = ["case_id", "cve", "base_image", "system", "model", "arm", "correct", "loss",
           # extra columns (not required by the core model): H6 covariate and descriptors
           "size_b", "log_size", "release", "variant", "family", "host_id", "gold", "pred"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=str(ROOT / "runs" / "test" / "E2"))
    ap.add_argument("--out", default=str(ROOT / "results" / "v3" / "glmm" / "e2_test_long.csv"))
    a = ap.parse_args()
    tags = subprocess.check_output(["git", "-C", str(ROOT), "tag", "--list", "prereg-v1"], text=True).split()
    if "prereg-v1" not in tags:
        raise SystemExit("tag prereg-v1 missing: test labels stay sealed")
    labels = data.load_labels("test", allow_sealed=True)
    cases = {c["case_id"]: c for c in data.load_cases("test")}
    sizes = {k: float(v["size_b"]) for k, v in load_models().items()}
    rows: dict[str, dict] = {}
    n_err = n_mismatch = n_other = 0
    for path in sorted(Path(a.runs).glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("error"):
                n_err += 1
                rows.pop(r["key"], None)
                continue
            if (float(r.get("budget", 60)) != 60.0 or r.get("attack") or r.get("drift") or r.get("prompt_defense")
                    or float(r.get("temperature", 0)) != 0.0 or int(r.get("seed", 0)) != 0):
                n_other += 1
                continue
            m = episode_metrics(r, labels)
            if m["label_world_mismatch"]:
                n_mismatch += 1
                rows.pop(r["key"], None)
                continue
            c = cases[r["case_id"]]
            size = sizes.get(r["model"])
            rows[r["key"]] = {
                "case_id": r["case_id"], "cve": r["cve"], "base_image": c["base_image"], "system": r["system"],
                "model": r["model"], "arm": r["arm"], "correct": int(bool(m["correct"])), "loss": m["loss"],
                "size_b": "" if size is None else size, "log_size": "" if size is None else round(math.log(size), 6),
                "release": c["release"], "variant": r.get("variant"), "family": r.get("family"),
                "host_id": r["host_id"], "gold": m["gold"], "pred": m["pred"] or "invalid",
            }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        for k in sorted(rows):
            w.writerow(rows[k])
    print(f"{out}: {len(rows)} rows (dropped: {n_err} error, {n_mismatch} label/world mismatch, "
          f"{n_other} non-main configuration)")


if __name__ == "__main__":
    main()
