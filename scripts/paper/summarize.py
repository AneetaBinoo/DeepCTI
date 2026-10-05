"""Summarise run logs: per experiment × system × model × arm/policy/attacker. Every paper number comes from here
or from scripts/paper/*.py.

  python scripts/paper/summarize.py --split dev --exp E2_pilot
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from deepcti.eval import data
from deepcti.eval.metrics import episode_metrics, macro_f1


# prereg-v1 model panel; addendum models (prereg-v2) are excluded from v2 analyses unless MODEL_FILTER is None
V1_PANEL = {"none", "qwen3_4b", "llama31_8b", "granite41_8b", "qwen3_14b", "mistral_small_24b", "gemma4_31b"}
MODEL_FILTER: set | None = None


def load_runs(split: str, exp: str, allow_sealed: bool = False) -> pd.DataFrame:
    labels = data.load_labels(split, allow_sealed=allow_sealed)
    rows = []
    for path in sorted((ROOT / "runs" / split / exp).glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("error"):
                rows.append({"key": r["key"], "system": r["system"], "model": r["model"], "error": True})
                continue
            m = episode_metrics(r, labels)
            rows.append({"key": r["key"], "case_id": r["case_id"], "cve": r["cve"], "variant": r["variant"],
                         "family": r["family"], "system": r["system"], "model": r["model"], "arm": r["arm"],
                         "policy": r["policy"], "budget": r["budget"], "seed": r["seed"],
                         "temperature": r["temperature"], "attack": r["attack"], "drift": r["drift"],
                         "prompt_defense": r.get("prompt_defense", False), "cost": r["cost"],
                         "n_calls": r["n_calls"], "n_redundant": r["n_redundant"],
                         "llm_calls": r["usage"]["calls"], "prompt_tokens": r["usage"]["prompt_tokens"],
                         "completion_tokens": r["usage"]["completion_tokens"], "model_s": r["usage"]["model_seconds"],
                         "truncations": r["usage"]["truncations"], "llm_errors": r["usage"]["errors"],
                         "wall_s": r["wall_s"], "error": False, **m})
    df = pd.DataFrame(rows)
    if MODEL_FILTER is not None and not df.empty:
        df = df[df["model"].isin(MODEL_FILTER)]
    if not df.empty and "label_world_mismatch" in df:
        bad = df[df["label_world_mismatch"].fillna(False).astype(bool)]
        if len(bad):
            print(f"WARNING: {len(bad)} records whose label disagrees with the start-of-episode world "
                  f"(cases: {sorted(bad['case_id'].unique())[:10]}) — excluded", file=sys.stderr)
            df = df[~df["key"].isin(bad["key"])]
    return df.drop_duplicates("key", keep="last") if not df.empty else df


def summary(df: pd.DataFrame, by: list[str]) -> pd.DataFrame:
    ok = df[~df["error"]]
    g = ok.groupby(by, dropna=False)
    out = g.agg(n=("correct", "size"), acc=("correct", "mean"), coverage=("covered", "mean"),
                loss=("loss", "mean"), invalid=("invalid", "mean"), cost=("cost", "mean"),
                llm_calls=("llm_calls", "mean"), udar_exec=("unauthorized_exec", "sum"),
                disruptive_exec=("n_disruptive_exec", "sum"), wall_s=("wall_s", "mean"))
    der = ok[ok["gold"] == "affected"].groupby(by, dropna=False)["dangerous"].mean().rename("DER")
    f1 = g.apply(lambda x: macro_f1(x["gold"], x["pred"]), include_groups=False).rename("sel_macroF1")
    errs = df.groupby(by, dropna=False)["error"].sum().rename("errors")
    return out.join(der).join(f1).join(errs).round(3)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", required=True)
    ap.add_argument("--exp", required=True)
    ap.add_argument("--by", default="system,model,arm")
    ap.add_argument("--allow-sealed", action="store_true")
    args = ap.parse_args()
    df = load_runs(args.split, args.exp, args.allow_sealed)
    pd.set_option("display.width", 250)
    pd.set_option("display.max_rows", 500)
    print(summary(df, args.by.split(",")).to_string())


if __name__ == "__main__":
    main()
