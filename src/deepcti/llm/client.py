"""OpenAI-compatible client for the vLLM model panel (config/models.yaml)."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import openai
import yaml

ROOT = Path(__file__).resolve().parents[3]


def load_env(path: Path = ROOT / ".env") -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def load_models(path: Path = ROOT / "config" / "models.yaml") -> dict[str, dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["models"]


@dataclass
class Usage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    model_seconds: float = 0.0
    errors: int = 0
    truncations: int = 0

    def add(self, other: Usage) -> None:
        for k in ("calls", "prompt_tokens", "completion_tokens", "model_seconds", "errors", "truncations"):
            setattr(self, k, getattr(self, k) + getattr(other, k))

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class ChatResult:
    message: Any
    content: str
    tool_calls: list[dict]
    usage: Usage
    finish_reason: str = ""
    raw: dict = field(default_factory=dict)


class LLM:
    def __init__(self, name: str, spec: dict, *, temperature: float = 0.0, seed: int | None = None):
        load_env()
        self.name = name
        self.spec = spec
        self.model = spec["served_name"]
        key = os.environ.get(spec.get("api_key_env", ""), "EMPTY") if spec.get("api_key_env") else "EMPTY"
        self.client = openai.OpenAI(base_url=spec["base_url"], api_key=key, timeout=180, max_retries=0)
        self.temperature = temperature
        self.seed = seed
        self.max_tokens = int(spec.get("max_tokens", 1024))
        self.context = int(spec.get("context", 32768))

    def chat(self, messages: list[dict], *, tools: list[dict] | None = None, tool_choice: Any = None,
             json_schema: dict | None = None, max_tokens: int | None = None) -> ChatResult:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": max_tokens or self.max_tokens,
        }
        if self.seed is not None:
            kwargs["seed"] = self.seed
        extra = dict(self.spec.get("extra_body", {}) or {})
        if json_schema is not None:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "answer", "schema": json_schema, "strict": True},
            }
        if extra:
            kwargs["extra_body"] = extra
        if tools:
            kwargs["tools"] = tools
            if tool_choice is not None:
                kwargs["tool_choice"] = tool_choice
        usage = Usage(calls=1)
        last_exc: Exception | None = None
        for attempt in range(4):
            start = time.monotonic()
            try:
                resp = self.client.chat.completions.create(**kwargs)
                usage.model_seconds += time.monotonic() - start
                break
            except openai.BadRequestError as exc:  # context overflow or schema problem: not retryable
                usage.model_seconds += time.monotonic() - start
                usage.errors += 1
                if "maximum context" in str(exc).lower() or "too long" in str(exc).lower():
                    usage.truncations += 1
                return ChatResult(None, "", [], usage, "error", {"error": str(exc)[:500]})
            except (openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError,
                    openai.RateLimitError) as exc:
                usage.model_seconds += time.monotonic() - start
                last_exc = exc
                time.sleep(2 * (attempt + 1))
        else:
            usage.errors += 1
            return ChatResult(None, "", [], usage, "error", {"error": str(last_exc)[:500]})
        choice = resp.choices[0]
        msg = choice.message
        if resp.usage:
            usage.prompt_tokens += resp.usage.prompt_tokens or 0
            usage.completion_tokens += resp.usage.completion_tokens or 0
        if choice.finish_reason == "length":
            usage.truncations += 1
        calls = []
        for tc in msg.tool_calls or []:
            calls.append({"id": tc.id, "name": tc.function.name, "arguments": tc.function.arguments})
        return ChatResult(msg, msg.content or "", calls, usage, choice.finish_reason or "")


def parse_json_object(text: str) -> dict | None:
    """Parse the first JSON object in ``text`` (tolerates code fences and leading prose)."""
    if not text:
        return None
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL)
    candidates = [fence.group(1)] if fence else []
    start = cleaned.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(cleaned)):
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(cleaned[start : i + 1])
                    break
    for cand in candidates:
        try:
            value = json.loads(cand)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue
    return None
