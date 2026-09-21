from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import requests

from .schemas import UsageRecord


@dataclass
class Generation:
    content: dict[str, Any]
    raw_text: str
    usage: UsageRecord
    parse_error: str | None = None


class OllamaClient:
    def __init__(
        self, base_url: str, *, timeout_seconds: int = 900, num_predict: int = 2048
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.num_predict = num_predict
        self._models_cache: list[dict[str, Any]] | None = None

    def models(self) -> list[dict[str, Any]]:
        response = requests.get(f"{self.base_url}/api/tags", timeout=15)
        response.raise_for_status()
        self._models_cache = list(response.json().get("models", []))
        return self._models_cache

    def model_digest(self, model: str) -> str:
        inventory = self._models_cache if self._models_cache is not None else self.models()
        for item in inventory:
            if item.get("name") == model or item.get("model") == model:
                return str(item.get("digest", ""))
        return ""

    def generate(self, *, model: str, prompt: str, temperature: float = 0.0) -> Generation:
        started = time.perf_counter()
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
        # Keep the response token budget consistent.
                "think": False,
                "format": "json",
                "options": {
                    "temperature": temperature,
                    "seed": 20260819,
                    "num_predict": self.num_predict,
                },
            },
            timeout=(15, self.timeout_seconds),
        )
        response.raise_for_status()
        body = response.json()
        raw = str(body.get("response", ""))
        usage = UsageRecord(
            prompt_tokens=int(body.get("prompt_eval_count", 0)),
            completion_tokens=int(body.get("eval_count", 0)),
            total_duration_ms=float(body.get("total_duration", 0)) / 1_000_000
            or (time.perf_counter() - started) * 1000,
            load_duration_ms=float(body.get("load_duration", 0)) / 1_000_000,
            model_digest=self.model_digest(str(body.get("model", model))),
        )
        try:
            content = json.loads(raw)
        except json.JSONDecodeError as exc:
            return Generation(
                content={},
                raw_text=raw,
                usage=usage,
                parse_error=f"{exc.__class__.__name__}: {exc}",
            )
        return Generation(content=content, raw_text=raw, usage=usage)

    def generate_text(self, *, model: str, prompt: str, temperature: float = 0.0) -> Generation:
        started = time.perf_counter()
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "think": False,
                "options": {
                    "temperature": temperature,
                    "seed": 20260819,
                    "num_predict": self.num_predict,
                },
            },
            timeout=(15, self.timeout_seconds),
        )
        response.raise_for_status()
        body = response.json()
        raw = str(body.get("response", ""))
        usage = UsageRecord(
            prompt_tokens=int(body.get("prompt_eval_count", 0)),
            completion_tokens=int(body.get("eval_count", 0)),
            total_duration_ms=float(body.get("total_duration", 0)) / 1_000_000
            or (time.perf_counter() - started) * 1000,
            load_duration_ms=float(body.get("load_duration", 0)) / 1_000_000,
            model_digest=self.model_digest(str(body.get("model", model))),
        )
        return Generation(content={}, raw_text=raw, usage=usage)


class MockClient:
    def models(self) -> list[dict[str, Any]]:
        return [{"name": "mock"}]

    def generate(self, *, model: str, prompt: str, temperature: float = 0.0) -> Generation:
        evidence_ids = []
        for token in prompt.replace("[", " ").replace("]", " ").split():
            if token.startswith("ev_") and token not in evidence_ids:
                evidence_ids.append(token)
        content = {
            "applicability": "uncertain",
            "facts": {"summary": "Mock output; no model inference was performed."},
            "information_needs": ["Confirm affected version and local reachability."],
            "candidate_actions": ["Collect version and dependency evidence."],
            "selected_action": "Collect additional evidence.",
            "claims": [
                {
                    "claim_id": "claim_1",
                    "text": "Evidence was supplied for this case.",
                    "evidence_ids": evidence_ids[:1],
                    "confidence": "low",
                    "claim_type": "fact",
                }
            ],
            "final_answer": "Additional authoritative and local evidence is required before mitigation.",
        }
        return Generation(content=content, raw_text=json.dumps(content), usage=UsageRecord())

    def generate_text(self, *, model: str, prompt: str, temperature: float = 0.0) -> Generation:
        return Generation(content={}, raw_text="Answer: M1021, M1038", usage=UsageRecord())
