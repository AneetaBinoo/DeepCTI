from typing import Any

from deepcti.ollama import OllamaClient


def test_ollama_requests_enforce_output_token_budget(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {
                "model": "test:latest",
                "response": "Answer: M1021",
                "prompt_eval_count": 1,
                "eval_count": 1,
                "total_duration": 1,
                "load_duration": 0,
            }

    def fake_post(url: str, **kwargs: Any) -> Response:
        captured.update(kwargs["json"])
        return Response()

    monkeypatch.setattr("deepcti.ollama.requests.post", fake_post)
    client = OllamaClient("http://127.0.0.1:11434", num_predict=2048)
    client._models_cache = [{"name": "test:latest", "digest": "abc"}]
    client.generate_text(model="test:latest", prompt="test")
    assert captured["options"]["num_predict"] == 2048


def test_ollama_records_malformed_json_as_a_parse_failure(monkeypatch) -> None:
    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {
                "model": "test:latest",
                "response": '{"final_answer": "M1021"',
                "prompt_eval_count": 10,
                "eval_count": 4,
                "total_duration": 2_000_000,
                "load_duration": 0,
            }

    monkeypatch.setattr("deepcti.ollama.requests.post", lambda *args, **kwargs: Response())
    client = OllamaClient("http://127.0.0.1:11434")
    client._models_cache = [{"name": "test:latest", "digest": "abc"}]

    generation = client.generate(model="test:latest", prompt="test")

    assert generation.content == {}
    assert generation.raw_text == '{"final_answer": "M1021"'
    assert generation.parse_error and generation.parse_error.startswith("JSONDecodeError:")
    assert generation.usage.completion_tokens == 4
