from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd

EVAL_ONLY_HINTS = [
    "reference", "target", "ground", "expected", "rubric", "required", "disallowed",
    "evaluation", "score", "label"
]

@dataclass
class Case:
    case_id: str
    question: str
    initial_context: str
    baseline: str
    stage_evidence: List[str]
    reference: str
    raw: Dict[str, Any]


def _clean(x: Any) -> str:
    if pd.isna(x):
        return ""
    return str(x).strip()


def _find_col(cols, candidates):
    low = {c.lower().strip(): c for c in cols}
    for cand in candidates:
        if cand.lower() in low:
            return low[cand.lower()]
    for c in cols:
        cl = c.lower()
        if any(cand.lower() in cl for cand in candidates):
            return c
    return None


def _join_columns(row: pd.Series, cols: List[str]) -> str:
    parts = []
    for c in cols:
        val = _clean(row.get(c, ""))
        if val:
            parts.append(f"{c}: {val}")
    return "\n".join(parts)


def load_cases(path: str | Path, max_cases: int | None = None) -> List[Case]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    xl = pd.ExcelFile(path)
    sheet = "DeepCTI_Run_Input" if "DeepCTI_Run_Input" in xl.sheet_names else xl.sheet_names[0]
    df = pd.read_excel(path, sheet_name=sheet)
    df = df.dropna(how="all").reset_index(drop=True)
    if max_cases:
        df = df.head(max_cases)

    cols = list(df.columns)
    id_col = _find_col(cols, ["case_id", "case id", "id"])
    q_col = _find_col(cols, ["Questions", "Question", "analyst_question", "analyst question"])
    ref_col = _find_col(cols, ["Evaluation_Target_Text", "Final_Mitigation_Reference", "Ground_truth", "ground truth", "final ground-truth mitigation target", "final target"])
    baseline_col = _find_col(cols, ["Baseline_Mitigation", "baseline mitigation", "baseline"])

    stage_cols = [c for c in cols if re.search(r"scenario step\s*\d+|stage_?\d+|new info arrives|evidence update", c, re.I)]
    if not stage_cols:
        stage_cols = [c for c in cols if "evidence" in c.lower() and not any(h in c.lower() for h in EVAL_ONLY_HINTS)]
    # stable order
    def stage_key(c):
        m = re.search(r"(\d+)", c)
        return int(m.group(1)) if m else 999
    stage_cols = sorted(set(stage_cols), key=stage_key)

    input_cols = []
    for c in cols:
        cl = c.lower()
        if c in stage_cols or c == ref_col:
            continue
        if any(h in cl for h in EVAL_ONLY_HINTS):
            continue
        if c in [id_col, q_col, baseline_col]:
            continue
        input_cols.append(c)

    cases: List[Case] = []
    for idx, row in df.iterrows():
        case_id = _clean(row.get(id_col, "")) if id_col else f"CASE-{idx+1:03d}"
        question = _clean(row.get(q_col, "")) if q_col else "What mitigation should be recommended?"
        reference = _clean(row.get(ref_col, "")) if ref_col else ""
        baseline = _clean(row.get(baseline_col, "")) if baseline_col else ""
        initial_context = _join_columns(row, input_cols)
        stages = [_clean(row.get(c, "")) for c in stage_cols if _clean(row.get(c, ""))]
        cases.append(Case(case_id, question, initial_context, baseline, stages, reference, dict(row)))
    return cases
