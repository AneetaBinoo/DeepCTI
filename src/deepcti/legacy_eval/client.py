"""Async, disk-cached OpenAI-compatible chat client with JSON-schema structured output.

The cache is an append-only JSONL file keyed by a hash of (endpoint, model, messages, schema, sampling
parameters); re-running a script therefore resumes instead of repeating calls. API keys are read from the
environment only and are never written to the cache or logs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import openai

ROOT = Path(__file__).resolve().parents[3]
NO_THINK = {"chat_template_kwargs": {"enable_thinking": False}}


@dataclass(frozen=True)
class Endpoint:
    name: str
    base_url: str
    model: str
    api_key_env: str | None = None
    extra_body: dict[str, Any] | None = None
    concurrency: int = 16


ENDPOINTS = {
    "qwen3_4b": Endpoint("qwen3_4b", "http://127.0.0.1:8302/v1", "qwen3_4b", extra_body=NO_THINK),
    "granite_41_8b": Endpoint("granite_41_8b", "http://127.0.0.1:8321/v1", "granite_41_8b"),
    "llama31_8b": Endpoint(
        "llama31_8b",
        "http://10.116.34.176:8008/v1",
        "meta-llama/Llama-3.1-8B-Instruct",
        api_key_env="LLAMA8B_API_KEY",
    ),
    "qwen3_14b": Endpoint("qwen3_14b", "http://127.0.0.1:8309/v1", "qwen3_14b", extra_body=NO_THINK),
    "mistral_small_24b": Endpoint("mistral_small_24b", "http://127.0.0.1:8310/v1", "mistral_small_24b"),
    "gemma_4_31b": Endpoint("gemma_4_31b", "http://127.0.0.1:8103/v1", "gemma_4_31b"),
}


def load_env(path: Path = ROOT / ".env") -> None:
    """Load KEY=VALUE lines into os.environ without echoing anything."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


class CachedChat:
    def __init__(self, cache_path: Path, *, max_tokens: int = 1024) -> None:
        load_env()
        self.cache_path = cache_path
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache: dict[str, dict[str, Any]] = {}
        if cache_path.exists():
            for line in cache_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    row = json.loads(line)
                    self.cache[row["key"]] = row
        self.max_tokens = max_tokens
        self._clients: dict[str, openai.AsyncOpenAI] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._handle = cache_path.open("a", encoding="utf-8")
        self.calls = 0
        self.errors = 0

    def _client(self, ep: Endpoint) -> openai.AsyncOpenAI:
        if ep.name not in self._clients:
            key = os.environ.get(ep.api_key_env, "EMPTY") if ep.api_key_env else "EMPTY"
            self._clients[ep.name] = openai.AsyncOpenAI(
                base_url=ep.base_url, api_key=key, timeout=180, max_retries=2
            )
            self._sems[ep.base_url] = self._sems.get(ep.base_url) or asyncio.Semaphore(ep.concurrency)
        return self._clients[ep.name]

    @staticmethod
    def key(ep: Endpoint, messages: list[dict], schema: dict, temperature: float, seed: int, tag: str) -> str:
        blob = json.dumps(
            [ep.base_url, ep.model, messages, schema, temperature, seed, ep.extra_body, tag], sort_keys=True
        )
        return hashlib.sha256(blob.encode()).hexdigest()

    async def json_chat(
        self,
        ep: Endpoint,
        messages: list[dict],
        schema: dict,
        *,
        temperature: float = 0.0,
        seed: int = 20261005,
        tag: str = "",
    ) -> dict[str, Any]:
        """Return {'parsed': dict|None, 'raw': str, 'error': str|None, 'tokens': int, 'latency_s': float}."""
        key = self.key(ep, messages, schema, temperature, seed, tag)
        if key in self.cache:
            return self.cache[key]
        client = self._client(ep)
        kwargs: dict[str, Any] = {
            "model": ep.model,
            "messages": messages,
            "temperature": temperature,
            "seed": seed,
            "max_tokens": self.max_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "output", "schema": schema, "strict": True},
            },
        }
        if ep.extra_body:
            kwargs["extra_body"] = ep.extra_body
        start = time.perf_counter()
        raw, parsed, error, tokens = "", None, None, 0
        async with self._sems[ep.base_url]:
            try:
                response = await client.chat.completions.create(**kwargs)
                raw = response.choices[0].message.content or ""
                tokens = response.usage.total_tokens if response.usage else 0
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError as exc:
                    error = f"json_decode: {exc}"
            except Exception as exc:  # noqa: BLE001 - record any transport/server error
                error = f"{type(exc).__name__}: {str(exc)[:200]}"
        self.calls += 1
        row = {
            "key": key,
            "endpoint": ep.name,
            "parsed": parsed,
            "raw": raw,
            "error": error,
            "tokens": tokens,
            "latency_s": round(time.perf_counter() - start, 3),
        }
        if error is None or error.startswith("json_decode"):
            self.cache[key] = row
            self._handle.write(json.dumps(row) + "\n")
            self._handle.flush()
        else:
            self.errors += 1
        return row

    def close(self) -> None:
        self._handle.close()
