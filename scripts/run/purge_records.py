"""Remove records that must be re-run (prereg/DEVIATIONS.md D8, D9); removed records are kept in runs/purged/.

  python scripts/run/purge_records.py --infra            # LLM request failures (errors without truncation)
  python scripts/run/purge_records.py --system DC_q2 --exp E5
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test")
    ap.add_argument("--infra", action="store_true")
    ap.add_argument("--system", default=None)
    ap.add_argument("--exp", default=None)
    ap.add_argument("--model", default=None)
    args = ap.parse_args()
    pattern = f"{args.exp or '*'}/{args.model or '*'}.jsonl"
    for path in sorted((ROOT / "runs" / args.split).glob(pattern)):
        keep, drop = [], []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            u = r.get("usage") or {}
            infra = u.get("infra_errors", 0) > 0 or (u.get("errors", 0) > 0 and u.get("truncations", 0) == 0)
            if (args.infra and infra) or (args.system and r.get("system") == args.system):
                drop.append(line)
            else:
                keep.append(line)
        if drop:
            out = ROOT / "runs" / "purged" / args.split / path.parent.name / path.name
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("a", encoding="utf-8") as fh:
                fh.write("\n".join(drop) + "\n")
            path.write_text("\n".join(keep) + "\n", encoding="utf-8")
            print(f"{path.relative_to(ROOT)}: purged {len(drop)}, kept {len(keep)}")


if __name__ == "__main__":
    main()
