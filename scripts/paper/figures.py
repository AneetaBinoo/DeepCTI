"""Paper figures (vector PDF) generated from raw run logs and committed result tables.

  python scripts/paper/figures.py            # writes paper/figs/*.pdf
Palette: dataviz reference categorical slots (validated: all checks pass, light surface); fixed identity per system.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from deepcti.eval import data  # noqa: E402
from deepcti.eval.metrics import episode_metrics  # noqa: E402

OUT = ROOT / "paper" / "figs"
OUT.mkdir(parents=True, exist_ok=True)

# ----------------------------------------------------------------------------- style
INK, INK2, MUTED, GRID, AXIS, SURF = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#ffffff"
C = {"DC": "#2a78d6", "S3": "#eb6834", "S1p": "#1baf7a", "DCv21": "#4a3aa7", "S2": "#eda100",
     "S1": "#a9a8a2", "S0_trivy": "#6e6d68", "S3I": "#c3c2b7", "DCv21b": "#4a3aa7", "DC_noverify": "#a9a8a2"}
NAME = {"DC": "DeepCTI", "DCv21": "DeepCTI v2.1", "DCv21b": "DeepCTI v2.1b", "S1p": "S1′ controller (no LLM)",
        "S1": "S1 tracker lookup", "S0_trivy": "S0 Trivy", "S2": "S2 direct LLM", "S3": "S3 ReAct",
        "S3I": "S3I Inspect ReAct", "DC_noverify": "DeepCTI w/o verifier"}
SHORT = {"qwen3_4b": "Qwen3-4B", "llama31_8b": "Llama-3.1-8B", "granite41_8b": "Granite-8B", "qwen3_14b": "Qwen3-14B",
         "mistral_small_24b": "Mistral-24B", "granite41_30b": "Granite-30B", "gemma4_31b": "Gemma-31B",
         "nemotron_super_49b": "Nemotron-49B", "mistral_medium_128b": "Mistral-128B"}
SIZE = {"qwen3_4b": 4, "llama31_8b": 8, "granite41_8b": 8, "qwen3_14b": 14, "mistral_small_24b": 24,
        "granite41_30b": 30, "gemma4_31b": 31, "nemotron_super_49b": 49, "mistral_medium_128b": 128}
SINGLE, DOUBLE = 3.45, 7.16

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 7, "axes.titlesize": 7.5, "axes.labelsize": 7,
    "xtick.labelsize": 6.5, "ytick.labelsize": 6.5, "legend.fontsize": 6.5, "axes.edgecolor": AXIS,
    "axes.linewidth": 0.6, "xtick.color": INK2, "ytick.color": INK2, "axes.labelcolor": INK2,
    "text.color": INK, "axes.titlecolor": INK, "xtick.major.width": 0.5, "ytick.major.width": 0.5,
    "xtick.major.size": 2, "ytick.major.size": 2, "axes.spines.top": False, "axes.spines.right": False,
    "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02, "figure.facecolor": SURF,
    "axes.facecolor": SURF,
})


def grid(ax, axis="x"):
    ax.grid(axis=axis, color=GRID, linewidth=0.5, zorder=0)
    ax.set_axisbelow(True)


def save(fig, name):
    fig.savefig(OUT / f"{name}.pdf")
    fig.savefig(OUT / f"{name}.png", dpi=200)
    plt.close(fig)
    print("wrote", OUT / f"{name}.pdf")


# ----------------------------------------------------------------------------- data
def records(dataset: str, exp: str, split: str = "test"):
    base = ROOT / "runs" / ("" if dataset == "d1" else dataset) / split / exp
    for path in sorted(base.glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                if not r.get("error"):
                    yield r


def frame(dataset: str, exp: str, models: set | None = None) -> pd.DataFrame:
    data.set_dataset(dataset)
    labels = data.load_labels("test", allow_sealed=True)
    rows = []
    for r in records(dataset, exp):
        if models is not None and r["model"] not in models:
            continue
        if r["case_id"] not in labels and not r.get("drift"):
            continue
        m = episode_metrics(r, labels)
        rows.append({"case_id": r["case_id"], "cve": r["cve"], "system": r["system"], "model": r["model"],
                     "arm": r["arm"], "drift": r.get("drift", ""), "policy": r.get("policy"), "attack": r.get("attack"),
                     "loss": m["loss"], "correct": m["correct"], "dangerous": m["dangerous"], "gold": m["gold"],
                     "cost": r["cost"], "budget": r.get("budget"), "t_decision": r.get("t_decision"), "udar": m["unauthorized_exec"] > 0,
                     "warranted": m["warranted"], "remediated": m["remediated"],
                     "denied": m["denied_disruptive"] > 0, "prompt_defense": r.get("prompt_defense", False)})
    return pd.DataFrame(rows)


def boot_ci(df: pd.DataFrame, value="loss", n=1000, seed=7):
    """CVE-clustered percentile bootstrap of the mean (per-case means first)."""
    per = df.groupby(["cve", "case_id"])[value].mean().reset_index()
    groups = [g[value].to_numpy() for _, g in per.groupby("cve")]
    rng = np.random.default_rng(seed)
    stats = []
    for _ in range(n):
        pick = rng.integers(0, len(groups), len(groups))
        vals = np.concatenate([groups[i] for i in pick])
        stats.append(vals.mean())
    return float(per[value].mean()), float(np.percentile(stats, 2.5)), float(np.percentile(stats, 97.5))


V1_PANEL = {"none", "qwen3_4b", "llama31_8b", "granite41_8b", "qwen3_14b", "mistral_small_24b", "gemma4_31b"}


# ----------------------------------------------------------------------------- F1 main loss
def fig_main():
    d1 = frame("d1", "E2", V1_PANEL)
    d7 = frame("d7", "X2")
    panels = [("D1 (Debian)\ntracker available", d1, "tracker"), ("D1 (Debian)\nno tracker", d1, "withheld"),
              ("D7 (4 ecosystems)\ntracker available", d7, "tracker"), ("D7\nno tracker", d7, "withheld"),
              ("D7\nno tracker, no scanners", d7, "blind")]
    systems = ["DC", "S1p", "S1", "S0_trivy", "S3", "S2"]
    fig, axes = plt.subplots(1, 5, figsize=(DOUBLE, 2.05), sharey=True)
    for ax, (title, df, arm) in zip(axes, panels):
        sub = df[df["arm"] == arm]
        ys, xs, lo, hi, cols = [], [], [], [], []
        for i, s in enumerate(systems):
            g = sub[sub["system"] == s]
            if g.empty:
                continue
            m, a, b = boot_ci(g)
            ys.append(i)
            xs.append(m)
            lo.append(m - a)
            hi.append(b - m)
            cols.append(C[s])
        ax.barh(ys, xs, color=cols, height=0.68, edgecolor=SURF, linewidth=1.0, zorder=2)
        ax.errorbar(xs, ys, xerr=[lo, hi], fmt="none", ecolor=INK2, elinewidth=0.6, capsize=1.2, zorder=3)
        for y, x, h in zip(ys, xs, hi):
            ax.text(x + h + 0.05, y, f"{x:.2f}", va="center", ha="left", fontsize=6, color=INK2)
        ax.set_title(title, loc="left", fontsize=6.8)
        ax.set_xlim(0, 2.75)
        grid(ax)
        ax.invert_yaxis()
    axes[0].set_yticks(range(len(systems)), [NAME[s] for s in systems])
    axes[2].set_xlabel("Mean decision loss (lower is better; miss = 10, needless change = 1, abstain = 0.5)")
    save(fig, "fig_main_loss")


# ----------------------------------------------------------------------------- F2 scaling
def fig_scaling():
    d1 = frame("d1", "E2")
    d7 = frame("d7", "X2")
    fig, axes = plt.subplots(1, 2, figsize=(SINGLE, 1.75), sharey=True)
    for ax, (title, df) in zip(axes, [("D1 · no tracker", d1), ("D7 · no tracker", d7)]):
        sub = df[(df["arm"] == "withheld")]
        s3 = sub[sub["system"] == "S3"].groupby("model")["loss"].mean()
        dc = sub[sub["system"] == "DC"]["loss"].mean()
        xs = [SIZE[m] for m in s3.index]
        ax.scatter(xs, s3.values, s=14, color=C["S3"], edgecolor=SURF, linewidth=0.6, zorder=3, label="S3 ReAct")
        ax.axhline(dc, color=C["DC"], linewidth=1.4, zorder=2)
        ax.text(3.3, dc - 0.07, f"DeepCTI {dc:.2f}, every model", color=C["DC"], fontsize=5.6, ha="left",
                va="top")
        ax.set_xscale("log", base=2)
        ax.set_xticks([4, 8, 16, 32, 64, 128], ["4", "8", "16", "32", "64", "128"])
        ax.set_title(title, loc="left", fontsize=6.8)
        ax.set_xlim(3, 180)
        ax.set_ylim(-0.25, 2.75)
        grid(ax, "y")
    axes[0].set_ylabel("Mean decision loss")
    fig.text(0.55, -0.04, "Model size (B parameters, log scale)", ha="center", color=INK2, fontsize=6.8)
    save(fig, "fig_scaling")


# ----------------------------------------------------------------------------- F3 drift
def fig_drift():
    x4 = frame("d1", "X4")
    x5 = frame("d7", "X5")
    eps = {e["episode_id"]: e["kind"] for e in data.read_jsonl(ROOT / "data" / "d2" / "test.jsonl")}
    eps7 = {e["episode_id"]: e["kind"] for e in data.read_jsonl(ROOT / "data" / "drift_d7" / "test.jsonl")}
    x4["kind"] = x4["drift"].map(eps)
    x5["kind"] = x5["drift"].map(eps7)
    kinds = [("upgrade_no_restart", "upgraded,\nnot restarted"), ("upgrade_restart", "upgraded\n+ restarted"),
             ("rollback", "rolled\nback"), ("remove", "package\nremoved")]
    systems = ["DC", "DCv21", "S3"]
    fig, axes = plt.subplots(1, 2, figsize=(DOUBLE, 1.6), sharey=True)
    w = 0.25
    for ax, (title, df) in zip(axes, [("D1 drift (D2 episodes)", x4), ("D7 drift (fresh episodes)", x5)]):
        for j, s in enumerate(systems):
            vals = [df[(df["kind"] == k) & (df["system"] == s)]["loss"].mean() for k, _ in kinds]
            pos = np.arange(len(kinds)) + (j - 1) * w
            ax.bar(pos, vals, width=w, color=C[s], edgecolor=SURF, linewidth=0.8, zorder=2,
                   label=NAME[s] if ax is axes[0] else None)
            for p, v in zip(pos, vals):
                if v > 1.0:
                    ax.text(p, v + 0.15, f"{v:.1f}", ha="center", fontsize=5.2, color=INK2)
        ax.set_xticks(range(len(kinds)), [k[1] for k in kinds], fontsize=6.2)
        ax.set_title(title, loc="left", fontsize=6.8)
        grid(ax, "y")
    axes[0].set_ylabel("Mean decision loss")
    fig.legend(frameon=False, loc="lower center", bbox_to_anchor=(0.5, 0.98), ncol=3, handlelength=1, fontsize=5.8)
    save(fig, "fig_drift")


# ----------------------------------------------------------------------------- F4 LTT
def fig_ltt():
    t = pd.read_csv(ROOT / "results" / "v3" / "test" / "tables" / "ltt_blind.csv")
    piv = t.pivot_table(index="model", columns="alpha", values="mean_coverage")
    risk = t[t["alpha"] == 0.05].set_index("model")["mean_risk"]
    base = t.groupby("model")["base_coverage"].first()
    order = piv[0.05].sort_values().index.tolist()
    fig, ax = plt.subplots(figsize=(SINGLE, 1.9))
    for i, m in enumerate(order):
        ax.plot([base[m], piv.loc[m, 0.05]], [i, i], color=AXIS, linewidth=1.2, zorder=1)
        ax.scatter(base[m], i, s=16, color=C["S1p"], zorder=3, edgecolor=SURF, linewidth=0.6)
        ax.scatter(piv.loc[m, 0.05], i, s=20, color=C["DC"], zorder=3, edgecolor=SURF, linewidth=0.6)
        ax.scatter(piv.loc[m, 0.1], i, s=16, facecolor=SURF, edgecolor=C["DC"], linewidth=0.9, zorder=2)
        ax.text(1.005, i, f"risk {risk[m] * 100:.1f}%", va="center", fontsize=5.6, color=INK2,
                transform=ax.get_yaxis_transform())
    ax.set_yticks(range(len(order)), [SHORT.get(m, m) for m in order])
    ax.set_xlim(0.25, 1.0)
    ax.set_xlabel("Coverage (share of cases decided)")
    grid(ax)
    from matplotlib.lines import Line2D
    h = [Line2D([], [], marker="o", ls="", color=C["S1p"], label="DeepCTI abstaining (no trusted feed)"),
         Line2D([], [], marker="o", ls="", color=C["DC"], label="+ LTT release, α = 0.05"),
         Line2D([], [], marker="o", ls="", markerfacecolor=SURF, markeredgecolor=C["DC"], label="α = 0.10")]
    ax.legend(handles=h, frameon=False, loc="lower center", bbox_to_anchor=(0.45, 1.0), ncol=3, fontsize=5.6,
              handletextpad=0.2, columnspacing=0.8)
    save(fig, "fig_ltt")


# ----------------------------------------------------------------------------- F5 extraction
def fig_extraction():
    t = pd.read_csv(ROOT / "results" / "v3" / "test" / "tables" / "x2_extraction.csv")
    t = t[t["source"].isin(["fs", "proc"]) & t["system"].isin(["DC", "DC_noverify"])]
    acc = t.groupby(["system", "source"])["accepted"].mean()
    err = t[t["accepted"]].groupby(["system", "source"])["wrong"].mean()
    fig, axes = plt.subplots(1, 2, figsize=(SINGLE, 1.45))
    w = 0.36
    srcs = [("fs", "files"), ("proc", "process banners")]
    for ax, (series, title, fmt) in zip(axes, [(acc, "Proposals accepted", "{:.0%}"),
                                                (err, "Accepted facts that are wrong", "{:.1%}")]):
        for j, s in enumerate(["DC", "DC_noverify"]):
            vals = [series.get((s, src), np.nan) for src, _ in srcs]
            pos = np.arange(2) + (j - 0.5) * w
            ax.bar(pos, vals, width=w, color=C[s], edgecolor=SURF, linewidth=0.8, zorder=2,
                   label="verified" if s == "DC" else "unverified (ablation)")
            for p, v in zip(pos, vals):
                ax.text(p, v + max(series) * 0.03, fmt.format(v), ha="center", fontsize=5.5, color=INK2)
        ax.set_xticks(range(2), [s[1] for s in srcs])
        ax.set_title(title, loc="left", fontsize=6.8)
        grid(ax, "y")
        ax.set_yticks([])
        ax.spines["left"].set_visible(False)
    fig.legend(*axes[0].get_legend_handles_labels(), frameon=False, fontsize=5.6, loc="lower center",
               bbox_to_anchor=(0.5, 0.98), ncol=2, handlelength=1)
    save(fig, "fig_extraction")


# ----------------------------------------------------------------------------- F6 security (v2 E5)
def fig_security():
    df = frame("d1", "E5", V1_PANEL | {"none"})
    eps = {e["episode_id"]: e for e in data.read_jsonl(ROOT / "data" / "d3" / "test.jsonl")}
    df["attacker"] = df["attack"].map(lambda a: eps.get(a, {}).get("attacker"))
    df["config"] = df["system"] + "+" + df["policy"] + np.where(df["prompt_defense"], "+def", "")
    configs = [("S3+P0", "ReAct, no gating"), ("S3+P1", "ReAct, argument gating"),
               ("S3+P1+def", "ReAct, arg. gating + prompt defence"), ("S3+P3", "ReAct, evidence gating (P3)"),
               ("DC+P3", "DeepCTI, evidence gating (P3)")]
    ben = df[df["attacker"] == "none"]
    att = df[df["attacker"].isin(["u_static", "u_adaptive"])]
    fig, ax = plt.subplots(figsize=(SINGLE, 1.55))
    w = 0.38
    for j, (sub, lab, col) in enumerate([(ben, "benign episodes", C["S3"]), (att, "injected text", "#b3471c")]):
        vals = [sub[sub["config"] == c]["udar"].mean() * 100 for c, _ in configs]
        pos = np.arange(len(configs)) + (j - 0.5) * w
        ax.barh(pos, vals, height=w, color=col, edgecolor=SURF, linewidth=0.8, zorder=2, label=lab)
        for p, v in zip(pos, vals):
            ax.text(v + 0.15, p, f"{v:.1f}%", va="center", fontsize=5.5, color=INK2)
    ax.set_yticks(range(len(configs)), [c[1] for c in configs])
    ax.invert_yaxis()
    ax.set_xlabel("Episodes with an unauthorized disruptive action (%)")
    grid(ax)
    ax.legend(frameon=False, fontsize=5.6, loc="lower right", handlelength=1)
    save(fig, "fig_security")


# ----------------------------------------------------------------------------- F7 acquisition
def fig_acquisition():
    df = frame("d7", "X3")
    sub = df[df["arm"] == "withheld"]
    systems = [("DC", "EC² VOI (DeepCTI)", C["DC"]), ("DC_entropy", "entropy-greedy", C["S1p"]),
               ("DC_checklist", "fixed checklist", C["DCv21"]), ("DC_random", "random order", MUTED),
               ("S3", "S3 ReAct", C["S3"])]
    fig, axes = plt.subplots(1, 2, figsize=(SINGLE, 1.6))
    for s, lab, col in systems:
        g = sub[sub["system"] == s].groupby("budget").agg(c=("t_decision", "mean"), l=("loss", "mean"))
        axes[0].plot(g.index, g["c"], marker="o", ms=3, lw=1.4, color=col, label=lab)
        if s in ("DC", "S3"):
            axes[1].plot(g.index, g["l"], marker="o", ms=3, lw=1.4, color=col)
    axes[1].text(5.2, 0.42, "all DeepCTI acquisition rules\nreach the same loss", fontsize=5.3, color=INK2)
    axes[0].set_title("Cost to decision", loc="left", fontsize=6.8)
    axes[1].set_title("Decision loss", loc="left", fontsize=6.8)
    for ax in axes:
        ax.set_xscale("log", base=2)
        ax.set_xticks([5, 10, 20, 40, 60], ["5", "10", "20", "40", "60"])
        ax.set_xlabel("Tool budget")
        grid(ax, "y")
    fig.legend(*axes[0].get_legend_handles_labels(), frameon=False, fontsize=5.4, loc="lower center",
               bbox_to_anchor=(0.5, 0.98), ncol=3, handlelength=1.2, columnspacing=0.8)
    save(fig, "fig_acquisition")


# ----------------------------------------------------------------------------- F8 notes (E11)
def fig_notes():
    t = pd.read_csv(ROOT / "results" / "v3" / "e11_d7b" / "metrics_system.csv").set_index("system")
    rows = [("DeepCTI (unvalidated note)", t.loc["DC", "faithfulness"], t.loc["DC", "consistency"], C["DC"]),
            ("v2.1 validated (pre-registered)", t.loc["DCv21", "faithfulness"], t.loc["DCv21", "consistency"],
             C["DCv21"]),
            ("v2.1b validated (post hoc)", t.loc["DCv21b", "faithfulness"], t.loc["DCv21b", "consistency"],
             C["S1p"])]
    fig, axes = plt.subplots(1, 2, figsize=(SINGLE, 1.2), sharey=True)
    for ax, k, title in [(axes[0], 1, "Claim faithfulness"), (axes[1], 2, "Note states the decision")]:
        vals = [r[k] for r in rows]
        ax.barh(range(3), vals, color=[r[3] for r in rows], height=0.6, edgecolor=SURF, zorder=2)
        for i, v in enumerate(vals):
            if v is not None:
                ax.text(v + 0.01, i, f"{v:.1%}", va="center", fontsize=5.6, color=INK2)
        ax.set_xlim(0, 1.18)
        ax.set_xticks([0, 0.5, 1.0], ["0%", "50%", "100%"])
        ax.set_title(title, loc="left", fontsize=6.8)
        grid(ax)
    axes[0].set_yticks(range(3), [r[0] for r in rows])
    axes[0].invert_yaxis()
    save(fig, "fig_notes")


# ----------------------------------------------------------------------------- F0 architecture
def fig_architecture():
    fig, ax = plt.subplots(figsize=(DOUBLE, 2.05))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 30)
    ax.axis("off")

    def box(x, y, w, h, title, body, fill, edge):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=1.2", facecolor=fill,
                                    edgecolor=edge, linewidth=0.8))
        ax.text(x + w / 2, y + h - 1.4, title, ha="center", va="top", fontsize=6.2, weight="bold", color=INK)
        ax.text(x + w / 2, y + h - 4.3, body, ha="center", va="top", fontsize=5.0, color=INK2, linespacing=1.3)

    def arrow(x1, y1, x2, y2, txt=None, col=MUTED):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=6, color=col, lw=0.8))
        if txt:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 0.8, txt, ha="center", fontsize=5.1, color=INK2)

    blue_f, blue_e = "#eaf2fc", C["DC"]
    gray_f, gray_e = "#f4f4f1", AXIS
    org_f, org_e = "#fdeee7", C["S3"]
    box(0.5, 16, 16.5, 13, "Host & feeds", "package DB · files\nservices · CMDB\nscanners · tracker/VEX\nadvisory text",
        gray_f, gray_e)
    box(20.5, 16, 17, 13, "Policy decision point", "Cedar policies P0–P3\nevery tool call mediated\n(complete mediation)",
        org_f, org_e)
    box(41, 16, 17.5, 13, "Evidence log → state", "observations with source,\ntrust class, group, time\nBelnap N/T/F/B per atom",
        blue_f, blue_e)
    box(62, 16, 17, 13, "Decision table", "VEX status +\njustification; B → conflict,\nN → missing (abstain)",
        blue_f, blue_e)
    box(82.5, 16, 17.2, 13, "Validated synthesis", "LLM note citing call ids\ncheck → 1 repair →\ndeterministic fallback",
        gray_f, gray_e)
    box(20.5, 0.5, 17, 12, "VOI acquisition", "EC² over hypotheses;\nnext tool by value\nper unit cost", blue_f, blue_e)
    box(41, 0.5, 17.5, 12, "Verified extraction", "span must be verbatim,\nname the component,\nparse as a version",
        gray_f, gray_e)
    box(62, 0.5, 17, 12, "Gated remediation", "patch / restart only if\ngating atoms are T with\nκ⁺ ≥ k independent groups",
        org_f, org_e)
    box(82.5, 0.5, 17.2, 12, "Risk control", "Learn-then-Test releases\nhint-based decisions\nat risk ≤ α", gray_f, gray_e)
    arrow(17.3, 22.5, 20.2, 22.5)
    arrow(38.0, 22.5, 40.7, 22.5)
    arrow(58.8, 22.5, 61.7, 22.5)
    arrow(79.3, 22.5, 82.2, 22.5)
    arrow(29, 13.0, 29, 15.7, col=C["DC"])
    arrow(49.75, 13.0, 49.75, 15.7, col=MUTED)
    arrow(70.5, 15.7, 70.5, 13.0, col=C["S3"])
    arrow(78.5, 15.7, 84.5, 13.0, col=MUTED)
    save(fig, "fig_architecture")


if __name__ == "__main__":
    which = sys.argv[1:] or ["architecture", "main", "scaling", "drift", "ltt", "extraction", "security",
                             "acquisition", "notes"]
    for w in which:
        globals()[f"fig_{w}"]()
