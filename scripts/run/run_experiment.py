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
BUDGETS = [5.0, 10.0, 20.0, 40.0, 60.0]


def require_prereg(tag: str = "prereg-v1") -> None:
    tags = subprocess.check_output(["git", "-C", str(ROOT), "tag", "-l", tag], text=True).strip()
    if tags != tag:
        sys.exit(f"refusing to run on the test split: tag {tag} does not exist")
    rc = subprocess.call(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", tag, "HEAD"])
    if rc != 0:
        sys.exit(f"refusing to run: HEAD does not descend from {tag}")


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


V3_LLM = ["S2", "S3", "DC", "DCv21", "DC_noverify"]
V3_FREE = ["S0_trivy", "S0_grype", "S0_osv", "S1", "S1p"]
V3_ARMS = ("tracker", "withheld", "blind")
NEW_MODELS = {"granite41_30b", "nemotron_super_49b", "glm45_air", "mistral_medium_128b"}


def build_jobs(exp: str, split: str, model: str, limit: int | None, dataset: str = "d1",
               spec: str = "v2") -> list[Job]:
    data.set_dataset(dataset)
    cases = data.load_cases(split)
    kw = {"dataset": dataset, "spec": spec}
    if limit:
        cases = stratified_subset(cases, limit)
    jobs: list[Job] = []
    llm = model != "none"

    if exp == "X2":  # v3 main study on D7 (three arms)
        for c in cases:
            for arm in V3_ARMS:
                for s in (V3_LLM if llm else V3_FREE):
                    jobs.append(Job(Spec(exp, c["case_id"], s, model, arm=arm, **kw), c))
        return jobs
    if exp == "X2B":  # post-hoc (DEVIATIONS D23): DCv21b on the H15-sampled (case, model, arm) triples
        import csv
        rows = list(csv.DictReader((ROOT / "results" / "v3" / "e11_d7" / "sample.csv").open()))
        by = {c["case_id"]: c for c in cases}
        for r in rows:
            if r["system"] == "DCv21" and r["model"] == model and r["case_id"] in by:
                jobs.append(Job(Spec(exp, r["case_id"], "DCv21b", model, arm=r["arm"], **kw), by[r["case_id"]]))
        return jobs
    if exp == "X2C":  # prereg-v4 H16: DCv21b on a fresh sample (scripts/data/sample_h16.py) disjoint from H15
        import csv
        rows = list(csv.DictReader((ROOT / "data" / "d7" / "h16_sample.csv").open()))
        by = {c["case_id"]: c for c in cases}
        for r in rows:
            if r["model"] == model and r["case_id"] in by:
                jobs.append(Job(Spec(exp, r["case_id"], "DCv21b", model, arm=r["arm"], **kw), by[r["case_id"]]))
        return jobs
    if exp == "X6":  # prereg-v4 H18: decoy version strings in documentation / CMDB notes, tracker arm
        from deepcti.env.host import HostEnv
        def has_decoy(c: dict) -> bool:  # only cases where a decoy can be planted (HostEnv.apply_decoys)
            env = HostEnv(c, data.fixture(c["host_id"]), data.cve_meta().get(c["cve"], {}), data.preconditions(), {})
            return env.apply_decoys() is not None
        for c in [c for c in cases if has_decoy(c)]:
            for s in (["DC", "DC_noverify", "S3"] if llm else ["S1p"]):
                jobs.append(Job(Spec(exp, c["case_id"], s, model, arm="tracker", decoy=True, **kw), c))
        return jobs
    if exp == "X7":  # prereg-v4 H17: DC with dev+calib-estimated scanner trust (DCt), withheld arm
        for c in cases:
            for s in (["DCt"] if llm else []):
                jobs.append(Job(Spec(exp, c["case_id"], s, model, arm="withheld", **kw), c))
        return jobs
    if exp == "X2V":  # post-hoc sensitivity (DEVIATIONS D21): vendor cases, DC family, verifier fixes
        for c in cases:
            if c.get("ecosystem") != "vendor":
                continue
            for arm in V3_ARMS:
                for s in (["DC", "DCv21", "DC_noverify"] if llm else ["S1p"]):
                    jobs.append(Job(Spec(exp, c["case_id"], s, model, arm=arm, **kw), c))
        return jobs
    if exp == "X2I":  # v3 third-party ReAct baseline (Inspect AI) on D7, tracker + withheld arms
        for c in cases:
            for arm in ("tracker", "withheld"):
                jobs.append(Job(Spec(exp, c["case_id"], "S3I", model, arm=arm, **kw), c))
        return jobs
    if exp == "X3":  # v3 acquisition on D7 where scanners are noisy (withheld) or absent (blind)
        for c in stratified_subset(cases, limit or 200):
            for arm in ("withheld", "blind"):
                for b in BUDGETS:
                    for s in (E3_SYSTEMS + ["S3"] if llm else ["S1p"]):
                        jobs.append(Job(Spec(exp, c["case_id"], s, model, arm=arm, budget=b, **kw), c))
        return jobs
    if exp == "X5":  # v3 independent drift test on D7 (episodes from scripts/data/build_drift_v3.py)
        episodes = data.read_jsonl(ROOT / "data" / f"drift_{dataset}" / f"{split}.jsonl")
        all_cases = {c["case_id"]: c for c in data.load_cases(split)}
        for ep in episodes[: limit or None]:
            c = all_cases[ep["case_id"]]
            for s in (["DC", "DCv21", "S3", "S2"] if llm else ["S1p", "S1"]):
                jobs.append(Job(Spec(exp, c["case_id"], s, model, drift=ep["episode_id"], **kw), c, None, ep["drift"]))
        return jobs
    if exp == "X4":  # v3 drift study on D2 (D1 test drift episodes) with the v3 spec and DC v2.1
        episodes = data.read_jsonl(ROOT / "data" / "d2" / f"{split}.jsonl")
        all_cases = {c["case_id"]: c for c in data.load_cases(split)}
        for ep in episodes[: limit or None]:
            c = all_cases[ep["case_id"]]
            for s in (["DC", "DCv21", "S3", "S2"] if llm else ["S1p", "S1"]):
                jobs.append(Job(Spec(exp, c["case_id"], s, model, drift=ep["episode_id"], **kw), c, None, ep["drift"]))
        return jobs
    if exp == "E2":
        for c in cases:
            for arm in ("tracker", "withheld"):
                for s in (E2_LLM if llm else LLM_FREE):
                    jobs.append(Job(Spec(exp, c["case_id"], s, model, arm=arm), c))
    elif exp == "E10":  # post-hoc exploratory (DEVIATIONS D10): no tracker and no scanner coverage
        for c in cases:
            for s in (["DC", "S2", "S3"] if llm else ["S1p", "S1", "S0_trivy"]):
                jobs.append(Job(Spec(exp, c["case_id"], s, model, arm="blind"), c))
    elif exp == "E3":
        for c in cases:
            for b in BUDGETS:
                for s in (E3_SYSTEMS + ["S3"] if llm else ["S1p"]):
                    jobs.append(Job(Spec(exp, c["case_id"], s, model, budget=b), c))
    elif exp == "ABL":
        for c in cases:
            for arm in ("tracker", "withheld"):
                for s in ABLATIONS:
                    jobs.append(Job(Spec(exp, c["case_id"], s, model, arm=arm), c))
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
                        ("DC", "P2", False), ("DC", "P3", False), ("DC_q2", "P3", False),
                        ("DC_noverify", "P3", False)]
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
    ap.add_argument("--dataset", default="d1", choices=["d1", "d7"])
    ap.add_argument("--spec", default="v2", choices=["v2", "v3"])
    args = ap.parse_args()
    if args.split == "test":
        require_prereg()
        if args.spec == "v3" or args.exp.startswith("X") or args.model in NEW_MODELS:
            require_prereg("prereg-v2")
        if args.dataset == "d7":
            require_prereg("prereg-v3")
        if args.exp in ("X2C", "X6", "X7") or args.model == "glm45_air":
            require_prereg("prereg-v4")
    jobs = build_jobs(args.exp, args.split, args.model, args.limit, args.dataset, args.spec)
    models = load_models()
    conc = args.concurrency or (int(models[args.model].get("concurrency", 16)) if args.model != "none" else 32)
    base = ROOT / "runs" if args.dataset == "d1" else ROOT / "runs" / args.dataset
    out_dir = base / args.split / (args.exp + (f"_{args.tag}" if args.tag else ""))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{args.model}.jsonl"
    manifest(out_dir / f"{args.model}.manifest.json", {"exp": args.exp, "split": args.split, "model": args.model,
                                                       "n_jobs": len(jobs), "limit": args.limit,
                                                       "argv": sys.argv})
    if args.exp == "X2I":
        from deepcti.inspect_harness.s3i import run_jobs_s3i
        stats = run_jobs_s3i(jobs, out, model_name=args.model, concurrency=conc)
    else:
        stats = run_jobs(jobs, out, model_name=args.model, concurrency=conc)
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
