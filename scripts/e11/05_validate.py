"""E11 step 5: judge validation (PROTOCOL.md §5): inter-judge agreement + perturbation recall / false alarm.

Outputs: agreement.csv, judge_validation.csv, judge_validation_by_type.csv, validated_judges.json.
"""

from __future__ import annotations

import itertools
import json
import math
from collections import defaultdict

import pandas as pd
from common import JUDGE_NAMES, OUT, read_jsonl

from deepcti.judge.prompts import LABELS, STATUS_CHOICES
from deepcti.judge.stats import cohen_kappa, fleiss_kappa

RECALL_MIN, FA_MAX = 0.85, 0.10


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def agreement(labels: dict[str, dict[str, str]], cats: tuple, name: str, judges: list[str] | None = None,
              pairs: bool = True) -> list[dict]:
    judges = judges or JUDGE_NAMES
    full = [d for d in labels.values() if all(j in d for j in judges)]
    rows = []
    for binary in (False, True):
        f = (lambda x: x == cats[0]) if binary else (lambda x: x)
        cs = [True, False] if binary else list(cats)
        counts = [[sum(f(d[j]) == c for j in judges) for c in cs] for d in full]
        rows.append({"what": name, "scheme": "binary" if binary else f"{len(cats)}-class",
                     "pair": f"fleiss({len(judges)})" + ("" if judges == JUDGE_NAMES else ":" + "+".join(judges)),
                     "n_items": len(full), "kappa": fleiss_kappa(counts),
                     "pct_agree": sum(max(c) == len(judges) for c in counts) / len(full)})
        for a, b in (itertools.combinations(judges, 2) if pairs else []):
            xa = [f(d[a]) for d in full]
            xb = [f(d[b]) for d in full]
            rows.append({"what": name, "scheme": "binary" if binary else f"{len(cats)}-class", "pair": f"{a}~{b}",
                         "n_items": len(full), "kappa": cohen_kappa(xa, xb),
                         "pct_agree": sum(x == y for x, y in zip(xa, xb)) / len(full)})
    return rows


def main() -> None:
    labels: dict[str, dict[str, str]] = defaultdict(dict)
    for r in read_jsonl(OUT / "judgments.jsonl"):
        if r["mode"] == "main" and r["label"]:
            labels[r["cid"]][r["judge"]] = r["label"]
    status: dict[str, dict[str, str]] = defaultdict(dict)
    for r in read_jsonl(OUT / "status_judgments.jsonl"):
        if r["asserted_status"]:
            status[r["key"]][r["judge"]] = r["asserted_status"]
    rows = agreement(labels, LABELS, "claim_label") + agreement(status, STATUS_CHOICES, "asserted_status")
    pd.DataFrame(rows).to_csv(OUT / "agreement.csv", index=False)
    marg = pd.DataFrame([{"judge": j, "label": lab} for d in labels.values() for j, lab in d.items()])
    dist = pd.crosstab(marg.judge, marg.label, normalize="index")
    dist.to_csv(OUT / "judge_label_distribution.csv")

    items = {it["pid"]: it for it in read_jsonl(OUT / "perturbations.jsonl")}
    plab: dict[str, dict[str, str]] = defaultdict(dict)
    perr = defaultdict(int)
    for r in read_jsonl(OUT / "perturb_judgments.jsonl"):
        if r["label"]:
            plab[r["pid"]][r["judge"]] = r["label"]
        else:
            perr[r["judge"]] += 1
    vrows, trows = [], []
    for j in JUDGE_NAMES:
        others = [x for x in JUDGE_NAMES if x != j]
        hit = defaultdict(lambda: [0, 0])  # kind -> [flagged, n]
        for pid, it in items.items():
            base = labels.get(it["base_cid"], {})
            if sum(base.get(o) == "supported" for o in others) < 3:  # leave-one-out reference
                continue
            lab = plab.get(pid, {}).get(j)
            if lab is None:
                continue
            hit[it["kind"]][1] += 1
            hit[it["kind"]][0] += lab != "supported"
        inj_k = sum(v[0] for k, v in hit.items() if k != "control")
        inj_n = sum(v[1] for k, v in hit.items() if k != "control")
        fa_k, fa_n = hit["control"]
        rec = inj_k / inj_n if inj_n else float("nan")
        fa = fa_k / fa_n if fa_n else float("nan")
        lo, hi = wilson(inj_k, inj_n)
        flo, fhi = wilson(fa_k, fa_n)
        vrows.append({"judge": j, "n_injected": inj_n, "recall": rec, "recall_lo": lo, "recall_hi": hi,
                      "n_controls": fa_n, "false_alarm": fa, "fa_lo": flo, "fa_hi": fhi,
                      "judge_errors": perr[j], "passes": bool(rec >= RECALL_MIN and fa <= FA_MAX)})
        for kind, (k, n) in sorted(hit.items()):
            trows.append({"judge": j, "kind": kind, "n": n, "flagged": k, "rate": k / n if n else float("nan")})
    vdf = pd.DataFrame(vrows)
    vdf.to_csv(OUT / "judge_validation.csv", index=False)
    pd.DataFrame(trows).to_csv(OUT / "judge_validation_by_type.csv", index=False)
    passed = [r["judge"] for r in vrows if r["passes"]]
    # perturbed items that every judge still labels supported (candidate edits that did not make the claim false)
    unanimous_missed = {k: 0 for k in sorted({it["kind"] for it in items.values()}) if k != "control"}
    for pid, it in items.items():
        if it["kind"] != "control" and all(plab.get(pid, {}).get(j) == "supported" for j in JUDGE_NAMES):
            unanimous_missed[it["kind"]] += 1
    if len(passed) >= 2:
        extra = agreement(labels, LABELS, "claim_label", passed, pairs=False) + agreement(
            status, STATUS_CHOICES, "asserted_status", passed, pairs=False)
        pd.DataFrame(rows + extra).to_csv(OUT / "agreement.csv", index=False)
    (OUT / "validated_judges.json").write_text(json.dumps(
        {"rule": {"recall_min": RECALL_MIN, "false_alarm_max": FA_MAX}, "validated": passed,
         "enough": len(passed) >= 2, "perturbations_missed_by_all_judges": unanimous_missed}, indent=1))
    print(vdf.to_string(index=False))
    print(pd.DataFrame(rows).query("pair=='fleiss(5)'").to_string(index=False))
    print("validated:", passed)


if __name__ == "__main__":
    main()
