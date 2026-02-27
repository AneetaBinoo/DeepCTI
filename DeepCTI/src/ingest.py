from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence
import pandas as pd


@dataclass
class Case:
    case_id: str
    baseline: Dict[str, Any]
    scenario_updates: List[str]
    expected_updates: List[str]
    ground_truth: str
    question: str
    raw_row_index: int


EXPECTED_EMPTY = {"", "nan", "none", "null", "na", "n/a"}


def _safe_str(x: Any) -> str:
    if pd.isna(x):
        return ""
    return str(x).strip()


def _is_nonempty_text(x: Any) -> bool:
    s = _safe_str(x)
    return s.lower() not in EXPECTED_EMPTY


def load_cases(
    xlsx_path: str,
    scenario_cols: Sequence[str],
    expected_update_cols: Sequence[str] | None = None,
    exclude_from_baseline: Sequence[str] = (),
    ground_truth_col: str = "Ground_truth",
    question_col: str = "Questions",
) -> List[Case]:
    df = pd.read_excel(xlsx_path)

    scenario_cols = tuple(scenario_cols)
    expected_update_cols = tuple(expected_update_cols or ())

    missing = [c for c in scenario_cols if c not in df.columns]
    if missing:
        raise ValueError(
            f"Scenario columns not found in dataset: {missing}\n"
            f"Available columns: {list(df.columns)}\n"
            f"Fix src/config.py scenario_cols to match your Excel."
        )

    if expected_update_cols:
        missing_exp = [c for c in expected_update_cols if c not in df.columns]
        if missing_exp:
            raise ValueError(f"Expected update columns not found: {missing_exp}")

    cases: List[Case] = []

    for idx, row in df.iterrows():
        # Case ID strategy
        if "id" in df.columns and _is_nonempty_text(row["id"]):
            case_id = f"case_{_safe_str(row['id'])}"
        elif "ID" in df.columns and _is_nonempty_text(row["ID"]):
            case_id = f"case_{_safe_str(row['ID'])}"
        elif "CVE" in df.columns and _is_nonempty_text(row["CVE"]):
            case_id = f"case_{_safe_str(row['CVE']).replace(':','_').replace('/','_')}"
        else:
            case_id = f"case_{idx+1:03d}"

        baseline: Dict[str, Any] = {}
        for col in df.columns:
            if col in scenario_cols or col in expected_update_cols:
                continue
            if col in exclude_from_baseline:
                continue
            baseline[col] = row[col]

        scenario_updates: List[str] = []
        expected_updates: List[str] = []
        for i, sc in enumerate(scenario_cols):
            sc_txt = _safe_str(row[sc])
            if not sc_txt:
                continue
            scenario_updates.append(sc_txt)
            if expected_update_cols and i < len(expected_update_cols):
                expected_updates.append(_safe_str(row[expected_update_cols[i]]))
            else:
                expected_updates.append("")

        ground_truth = _safe_str(row.get(ground_truth_col, "")) if hasattr(row, "get") else ""
        question = _safe_str(row.get(question_col, "")) if hasattr(row, "get") else ""

        cases.append(
            Case(
                case_id=case_id,
                baseline=baseline,
                scenario_updates=scenario_updates,
                expected_updates=expected_updates,
                ground_truth=ground_truth,
                question=question,
                raw_row_index=int(idx),
            )
        )

    return cases