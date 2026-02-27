from __future__ import annotations

from typing import Any, Dict
import json
import re
import requests


def _repair_common_json_issues(text: str) -> str:
    """
    Best-effort repair for malformed LLM JSON:
    - remove markdown fences
    - normalize smart quotes
    - escape raw newlines/tabs/control chars inside quoted strings
    """
    t = (text or "").strip()

    # Remove markdown fences if present
    t = re.sub(r"^```(?:json)?\s*", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\s*```$", "", t)

    # Normalize quotes
    t = t.replace("\u201c", '"').replace("\u201d", '"').replace("\u2018", "'").replace("\u2019", "'")

    # Keep only likely JSON span
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        t = t[start:end + 1]

    # Escape raw control chars ONLY inside strings
    out = []
    in_str = False
    escape = False
    for ch in t:
        if in_str:
            if escape:
                out.append(ch)
                escape = False
                continue
            if ch == "\\":
                out.append(ch)
                escape = True
                continue
            if ch == '"':
                out.append(ch)
                in_str = False
                continue
            if ch == "\n":
                out.append("\\n")
                continue
            if ch == "\r":
                out.append("\\r")
                continue
            if ch == "\t":
                out.append("\\t")
                continue
            # Other ASCII control chars
            if ord(ch) < 32:
                out.append(" ")
                continue
            out.append(ch)
        else:
            out.append(ch)
            if ch == '"':
                in_str = True

    return "".join(out)


def _regex_field(text: str, key: str) -> str:
    # Extract simple string fields even from malformed JSON
    m = re.search(rf'"{re.escape(key)}"\s*:\s*"(.+?)"\s*(,|\}})', text, flags=re.DOTALL)
    if not m:
        return ""
    val = m.group(1)
    val = val.replace("\r", " ").replace("\n", " ").strip()
    return val


def _safe_json_fallback(text: str) -> Dict[str, Any]:
    """
    Last-resort parser so the pipeline does not crash.
    Returns a minimally valid object.
    """
    return {
        "updated_answer": _regex_field(text, "updated_answer") or "Model returned malformed JSON; partial output recovered.",
        "recommended_action": _regex_field(text, "recommended_action"),
        "decision_support": (_regex_field(text, "decision_support") or "uncertain").lower(),
        "operational_risks": [],
        "regression_risks": [],
        "assumptions": ["Malformed JSON output from model; fields partially recovered."],
        "claims": [],
        "missing_info": [],
        "followup_query": "",
    }


def _extract_json(text: str) -> Dict[str, Any]:
    raw = (text or "").strip()

    # 1) Try direct parse
    try:
        return json.loads(raw)
    except Exception:
        pass

    # 2) Try extracting JSON span directly
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        snippet = raw[start:end + 1]
        try:
            return json.loads(snippet)
        except Exception:
            # 3) Repair and retry
            repaired = _repair_common_json_issues(snippet)
            try:
                return json.loads(repaired)
            except Exception:
                # 4) Fallback (don't crash the whole experiment)
                return _safe_json_fallback(snippet)

    # 5) No braces at all -> fallback
    return _safe_json_fallback(raw)


def call_ollama(ollama_url: str, model: str, prompt: str, timeout_sec: int = 300) -> Dict[str, Any]:
    """
    Calls Ollama with explicit logs so hangs are visible.
    Handles accidental OLLAMA_URL values ending in /api.
    """
    base = (ollama_url or "http://localhost:11434").strip().rstrip("/")

    # Defensive fix: if user sets OLLAMA_URL=http://localhost:11434/api, normalize it
    if base.endswith("/api"):
        base = base[:-4]

    url = f"{base}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1},
    }

    print(f"[LLM] Calling Ollama -> model={model} url={url}")
    print(f"[LLM] Prompt chars={len(prompt)} timeout={timeout_sec}s")

    try:
        r = requests.post(url, json=payload, timeout=(10, timeout_sec))
    except requests.exceptions.ReadTimeout:
        raise TimeoutError(
            f"Ollama generation timed out after {timeout_sec}s. "
            f"Try a smaller model or increase LLM_TIMEOUT_SEC."
        )
    except requests.exceptions.ConnectionError as e:
        raise ConnectionError(
            f"Could not connect to Ollama at {base}. "
            f"Make sure 'ollama serve' is running."
        ) from e

    print(f"[LLM] HTTP status={r.status_code}")

    if r.status_code == 404:
        body_preview = (r.text or "")[:300].replace("\n", " ")
        if "model" in body_preview.lower() and "not found" in body_preview.lower():
            raise RuntimeError(
                f"Ollama model not found: {model}\n"
                f"Response: {body_preview}\n"
                "Run 'ollama list' to see installed models or 'ollama pull <model>'."
            )

        diag = []
        for ep in ["/", "/api/tags", "/api/version"]:
            try:
                rr = requests.get(f"{base}{ep}", timeout=(5, 10))
                diag.append(f"{ep} -> {rr.status_code}")
            except Exception as e:
                diag.append(f"{ep} -> ERROR:{e.__class__.__name__}")

        raise RuntimeError(
            "Received HTTP 404 from Ollama /api/generate.\n"
            f"Base URL used: {base}\n"
            f"Diagnostics: {', '.join(diag)}\n"
            f"Response preview: {body_preview}"
        )

    r.raise_for_status()

    data = r.json()
    raw = data.get("response", "") or ""
    print(f"[LLM] Response chars={len(raw)}")
    return {"text": raw}


def build_prompt(working_context: Dict[str, Any], evidence_block: str) -> str:
    return f"""
You are a cybersecurity CTI decision-support reasoning agent.
Return ONLY valid JSON. Do not include markdown, comments, or extra text.
Every string value must be JSON-escaped. Do not paste raw newlines inside string values.
Use ONLY the provided evidence IDs for cited claims.

OUTPUT JSON SCHEMA:
{{
  "updated_answer": "short summary paragraph",
  "recommended_action": "string",
  "decision_support": "accept|modify|reject|uncertain",
  "operational_risks": ["string"],
  "regression_risks": ["string"],
  "assumptions": ["string"],
  "claims": [
    {{
      "claim": "string",
      "evidence_ids": ["ev_xxx"],
      "confidence": "high|medium|low"
    }}
  ],
  "missing_info": ["string"],
  "followup_query": "optional short retrieval query"
}}

WORKING CONTEXT:
{json.dumps(working_context, indent=2, ensure_ascii=False)}

EVIDENCE (cite only these IDs; do not copy metadata text into JSON strings):
{evidence_block}
""".strip()


def _normalize_output(obj: Dict[str, Any]) -> Dict[str, Any]:
    defaults = {
        "updated_answer": "",
        "recommended_action": "",
        "decision_support": "uncertain",
        "operational_risks": [],
        "regression_risks": [],
        "assumptions": [],
        "claims": [],
        "missing_info": [],
        "followup_query": "",
    }
    out = {**defaults, **(obj or {})}

    for key in ["operational_risks", "regression_risks", "assumptions", "claims", "missing_info"]:
        if not isinstance(out.get(key), list):
            out[key] = []

    ds = str(out.get("decision_support", "uncertain")).strip().lower()
    if ds not in {"accept", "modify", "reject", "uncertain"}:
        ds = "uncertain"
    out["decision_support"] = ds

    # Sanitize claims structure
    clean_claims = []
    for c in out.get("claims", []):
        if not isinstance(c, dict):
            continue
        clean_claims.append(
            {
                "claim": str(c.get("claim", "")),
                "evidence_ids": c.get("evidence_ids", []) if isinstance(c.get("evidence_ids", []), list) else [],
                "confidence": str(c.get("confidence", "low")).lower(),
            }
        )
    out["claims"] = clean_claims

    return out


def run_llm(settings, working_context: Dict[str, Any], evidence_block: str) -> Dict[str, Any]:
    prompt = build_prompt(working_context, evidence_block)

    if settings.llm_mode == "ollama":
        raw = call_ollama(
            settings.ollama_url,
            settings.ollama_model,
            prompt,
            timeout_sec=max(120, int(getattr(settings, "llm_timeout_sec", 180))),
        )["text"]

        preview = raw[:300].replace("\n", " ")
        print(f"[LLM] Raw preview: {preview}")

        parsed = _extract_json(raw)
        return _normalize_output(parsed)

    if settings.llm_mode == "openai":
        raise RuntimeError("OpenAI mode not wired in this script. Use Ollama or extend run_llm().")

    raise ValueError(f"Unknown LLM_MODE={settings.llm_mode}")