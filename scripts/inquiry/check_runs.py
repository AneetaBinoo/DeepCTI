"""Phase 0 (Paper 2): completeness of the Paper 1 run logs against their manifests (read-only).

For every runs/**/<block>/<model>.manifest.json: n_jobs (manifest) vs records in <model>.jsonl, error records,
duplicate keys. Pilot/smoke blocks are listed but flagged. Output: docs/inquiry/RUNS_INVENTORY.md
  .venv/bin/python scripts/inquiry/check_runs.py
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ATTACK_BLOCKS = {"E5", "KM", "E5_final", "E5_pilot", "KM_final", "KM_pilot"}


def main() -> None:
    rows = []
    for man in sorted((ROOT / "runs").rglob("*.manifest.json")):
        block_dir = man.parent
        model = man.name.removesuffix(".manifest.json")
        js = block_dir / f"{model}.jsonl"
        m = json.loads(man.read_text())
        n_jobs = m.get("n_jobs")
        keys, err = Counter(), 0
        if js.exists():
            for line in js.read_text().splitlines():
                if line.strip():
                    r = json.loads(line)
                    keys[r.get("key")] += 1
                    err += r.get("error") is not None
        rel = block_dir.relative_to(ROOT / "runs")
        pilot = any(t in block_dir.name for t in ("pilot", "smoke", "validation"))
        rows.append({"block": str(rel), "model": model, "n_jobs": n_jobs, "records": sum(keys.values()),
                     "unique": len(keys), "dups": sum(v - 1 for v in keys.values() if v > 1), "errors": err,
                     "complete": n_jobs is not None and len(keys) >= n_jobs, "pilot": pilot,
                     "attack": block_dir.name in ATTACK_BLOCKS})
    md = ["# Paper 2 Phase 0 — Paper 1 run-log inventory (scripts/inquiry/check_runs.py)", "",
          "`runs/` is gitignored and local to the experiment machine. A block is *complete* when its unique record keys",
          "reach the manifest's `n_jobs`. Attack blocks (E5, KM) are excluded from the E0 audit; pilots are listed only.",
          ""]
    by_status = Counter()
    md += ["| block | model | n_jobs | records | unique | dups | errors | complete | pilot | attack |",
           "|---|---|---:|---:|---:|---:|---:|---|---|---|"]
    for r in rows:
        md.append("| {block} | {model} | {n_jobs} | {records} | {unique} | {dups} | {errors} | {complete} | {pilot} | {attack} |"
                  .format(**r))
        by_status[(r["pilot"], r["complete"])] += 1
    main_rows = [r for r in rows if not r["pilot"]]
    md += ["", f"Non-pilot manifests: {len(main_rows)}; complete: {sum(r['complete'] for r in main_rows)}; "
           f"records {sum(r['records'] for r in main_rows):,}; errors {sum(r['errors'] for r in main_rows)}; "
           f"duplicate keys {sum(r['dups'] for r in main_rows)}.",
           "Incomplete non-pilot blocks: " + (", ".join(f"{r['block']}/{r['model']} ({r['unique']}/{r['n_jobs']})"
                                                    for r in main_rows if not r["complete"]) or "none") + "."]
    (ROOT / "docs" / "inquiry" / "RUNS_INVENTORY.md").write_text("\n".join(md) + "\n")
    print("\n".join(md[-2:]))


if __name__ == "__main__":
    main()
