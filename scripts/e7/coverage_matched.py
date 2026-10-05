"""Coverage-matched comparison: on the (task, seed) pairs where B did NOT abstain,
compare B's and A's status / category accuracy on exactly those pairs."""
import csv
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "results/v2/e7"
rows = list(csv.DictReader((OUT / "e7_per_case.csv").open()))
idx = {(r["system"], r["model"], r["task_id"], r["seed"]): r for r in rows}
res = []
for model in ["gemma_4_31b", "qwen3_14b"]:
    pairs = [(r["task_id"], r["seed"]) for r in rows if r["system"] == "B" and r["model"] == model and r["abstained"] == "False"]
    for sys_ in ["A", "B"]:
        sel = [idx[(sys_, model, t, s)] for t, s in pairs]
        res.append({"model": model, "system": sys_, "n_pairs": len(sel),
                    "status_acc": sum(r["pred"] == r["gt"] for r in sel) / len(sel),
                    "category_acc": sum(r["pred_category"] == r["gt_category"] for r in sel) / len(sel),
                    "exploitable_gt_share": sum(r["gt"] == "exploitable" for r in sel) / len(sel)})
with (OUT / "e7_coverage_matched.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(res[0]))
    w.writeheader(); w.writerows(res)
for r in res:
    print(r)
