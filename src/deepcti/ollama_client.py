from __future__ import annotations
import requests


def generate_ollama(model: str, prompt: str, temperature: float = 0.1, timeout: int = 900) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_ctx": 8192}
    }
    r = requests.post("http://localhost:11434/api/generate", json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json().get("response", "").strip()
