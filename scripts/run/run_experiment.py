"""Build and run one experiment block for one model (resumable). Run inside tmux.

Examples:
  python scripts/run/run_experiment.py --exp E2 --split dev --model none
  python scripts/run/run_experiment.py --exp E2 --split test --model qwen3_14b --concurrency 32
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from deepcti.eval import data  # noqa: E402
from deepcti.eval.runner import Job, Spec, manifest, run_jobs  # noqa: E402
from deepcti.llm.client import load_models  # noqa: E402

LLM_FREE = ["S0_trivy", "S0_grype", "S0_osv", "S1", "S1p"]
E2_LLM = ["S2", "S3", "S4", "S5", "DC"]
E3_SYSTEMS = ["DC", "DC_entropy", "DC_checklist", "DC_llmchoose", "DC_random"]
ABLATIONS = ["DC_noverify", "DC_k1", "DC_nofresh"]
BUDGETS = [5.0, 10.0, 20.0, 40.0]


def require_prereg() -> None:
    tags = subprocess.check_output(["git", "-C", str(ROOT), "tag", "-l", "prereg-v1"], text=True).strip()
    if tags != "prereg-v1":
        sys.exit("refusing to run on the test split: tag prereg-v1 does not exist")
    rc = subprocess.call(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", "prereg-v1", "HEAD"])
    if rc != 0:
        sys.exit("refusing to run: HEAD does not descend from prereg-v1")


def stratified_subset(cases: list[dict], n: int, seed: int = 20261005) -> list[dict]:
    rng = random.Random(seed)
    by: dict[tuple, list[dict]] = {}
    for c in cases:
        by.setdefault((c.get("variant"), c.get("family")), []).append(c)
    pools = [rng.sample(v, len(v)) for _, v in sorted(by.items())]
    out: list[dict] = []
    while len(out) < n and any(pools):
        for pool in pools:
            if pool and len(out) < n:
                out.append(pool.pop())
    return sorted(out, key=lambda c: c["case_id"])


def build_jobs(exp: str, split: str, model: str, limit: int | None) -> list[Job]:
    cases = data.load_cases(split)
    if limit:
        cases = stratified_subset(cases, limit)
    jobs: list[Job] = []
    llm = model != "none"

    if exp == "E2":
        for c in cases:
            for arm in ("tracker", "withheld"):
                for s in (E2_LLM if llm else LLM_FREE):
                    jobs.append(Job(Spec(exp, c["case_id"], s, model, arm=arm), c))
    elif exp == "E3":
        for c in cases:
            for b in BUDGETS:
                for s in (E3_SYSTEMS + ["S3"] if llm else ["S1p"]):
                    jobs.append(Job(Spec(exp, c["case_id"], s, model, budget=b), c))
    elif exp == "ABL":
        for c in cases:
            for s in ABLATIONS:
                jobs.append(Job(Spec(exp, c["case_id"], s, model), c))
    elif exp == "E9":
        subset = stratified_subset(cases, 150)
        for c in subset:
            for seed in range(5):
                for s in ("S3", "DC"):
                    jobs.append(Job(Spec(exp, c["case_id"], s, model, temperature=0.7, seed=seed), c))
    elif exp == "E4":
        episodes = data.read_jsonl(ROOT / "data" / "d2" / f"{split}.jsonl")
        all_cases = {c["case_id"]: c for c in data.load_cases(split)}
        systems = ["DC", "DC_nofresh", "DC_k1", "S3", "S4"] if llm else ["S1p", "S1"]
        for ep in episodes[: limit or None]:
            c = all_cases[ep["case_id"]]
            for s in systems:
                jobs.append(Job(Spec(exp, c["case_id"], s, model, drift=ep["episode_id"]), c, None, ep["drift"]))
    elif exp in ("E5", "KM"):
        episodes = data.read_jsonl(ROOT / "data" / "d3" / f"{split}.jsonl")
        all_cases = {c["case_id"]: c for c in data.load_cases(split)}
        if exp == "E5":
            configs = ([("S3", "P0", False), ("S3", "P1", False), ("S3", "P1", True), ("S3", "P3", False),
                        ("DC", "P2", False), ("DC", "P3", False), ("DC_q2", "P3", False)]
                       if llm else [("S1p", "P3", False)])
        else:
            configs = [("DC", p, False) for p in ("P2", "P3", "P3k3")]
        for ep in episodes[: limit or None]:
            if exp == "KM" and ep["attacker"] not in ("none", "m1", "m2", "m3"):
                continue
            c = all_cases[ep["case_id"]]
            for s, pol, defense in configs:
                jobs.append(Job(Spec(exp, c["case_id"], s, model, policy=pol, attack=ep["episode_id"],
                                     prompt_defense=defense), c, ep.get("attack"), None))
    else:
        raise SystemExit(f"unknown experiment {exp}")
    return jobs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", required=True)
    ap.add_argument("--split", required=True, choices=["dev", "calib", "test"])
    ap.add_argument("--model", required=True)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--concurrency", type=int, default=None)
    ap.add_argument("--tag", default="")
    args = ap.parse_args()
    if args.split == "test":
        require_prereg()
    jobs = build_jobs(args.exp, args.split, args.model, args.limit)
    models = load_models()
    conc = args.concurrency or (int(models[args.model].get("concurrency", 16)) if args.model != "none" else 32)
    out_dir = ROOT / "runs" / args.split / (args.exp + (f"_{args.tag}" if args.tag else ""))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{args.model}.jsonl"
    manifest(out_dir / f"{args.model}.manifest.json", {"exp": args.exp, "split": args.split, "model": args.model,
                                                       "n_jobs": len(jobs), "limit": args.limit,
                                                       "argv": sys.argv})
    stats = run_jobs(jobs, out, model_name=args.model, concurrency=conc)
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
