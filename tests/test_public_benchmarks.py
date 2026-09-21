import json

from deepcti.datasets import load_athenabench_cases
from deepcti.metrics import extract_athenabench_rms_answer, mitigation_id_prf
from deepcti.ollama import Generation
from deepcti.orchestrator import run_athenabench_model_only_case
from deepcti.prompts import analysis_prompt
from deepcti.schemas import KnowledgeState, UsageRecord


def test_mitigation_id_metric_is_multilabel() -> None:
    result = mitigation_id_prf("Use M1021 and M1038.", "M1021, M1047")
    assert result == {"precision": 0.5, "recall": 0.5, "f1": 0.5}


def test_athenabench_extractor_uses_final_nonempty_line() -> None:
    response = "M1021 appears in the explanation.\n\nAnswer: M1038, M1042\n"
    assert extract_athenabench_rms_answer(response) == "M1038, M1042"


def test_athenabench_adapter(tmp_path) -> None:
    row = {
        "technique_id": "T1218.001",
        "description": "Adversaries may abuse CHM files.",
        "scenario": "An attacker executed a payload through hh.exe.",
        "prompt": "Example: M1037, M1041. Return two mitigation IDs.",
        "answer": "M1021, M1038",
        "prompt_hash": "abc123def456",
    }
    path = tmp_path / "rms.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    attack = tmp_path / "enterprise-attack-19.1.json"
    attack.write_text(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {
                        "type": "course-of-action",
                        "id": "course-of-action--one",
                        "name": "Restrict Web-Based Content",
                        "description": "Block risky help-document content.",
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": "M1021",
                                "url": "https://attack.mitre.org/mitigations/M1021/",
                            }
                        ],
                    },
                    {
                        "type": "attack-pattern",
                        "id": "attack-pattern--one",
                        "name": "Compiled HTML File",
                        "description": "Adversaries abuse CHM files and hh.exe.",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1218.001"}
                        ],
                    },
                    {
                        "type": "relationship",
                        "id": "relationship--one",
                        "relationship_type": "mitigates",
                        "source_ref": "course-of-action--one",
                        "target_ref": "attack-pattern--one",
                        "description": "Restrict CHM files received from untrusted sources.",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    cases = load_athenabench_cases(path, attack_corpus_path=attack, attack_retrieval_k=1)
    assert cases[0].case_id == "ATHENA-RMS-abc123def456"
    assert cases[0].reference["mitigation_ids"] == "M1021, M1038"
    assert cases[0].cve_id == ""
    assert cases[0].benchmark_prompt == row["prompt"]
    assert "M1037" not in cases[0].question
    assert "T1218.001" not in cases[0].initial_evidence[0].text
    assert cases[0].initial_evidence[1].metadata["mitigation_id"] == "M1021"
    prompt = analysis_prompt(
        question=cases[0].question,
        state=KnowledgeState(case_id=cases[0].case_id),
        evidence=cases[0].initial_evidence,
        mode="initial_one_shot",
        task_profile="mitigation_benchmark",
    )
    assert "Do not invent asset state, impact, residual risk, or rollback plans" in prompt
    assert "Required decision fields: affected_assets" not in prompt


def test_model_only_runner_uses_original_prompt_and_official_extraction(tmp_path) -> None:
    row = {
        "technique_id": "T1218.001",
        "description": "Adversaries may abuse CHM files.",
        "scenario": "An attacker executed a payload through hh.exe.",
        "prompt": "ORIGINAL BENCHMARK PROMPT",
        "answer": "M1021, M1038",
        "prompt_hash": "abc123def456",
    }
    path = tmp_path / "rms.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    case = load_athenabench_cases(path)[0]

    class SpyClient:
        prompt = ""

        def generate_text(self, *, model: str, prompt: str, temperature: float = 0.0) -> Generation:
            self.prompt = prompt
            return Generation({}, "Reasoning mentions M1042.\nAnswer: M1021, M1038", UsageRecord())

    client = SpyClient()
    result = run_athenabench_model_only_case(
        case=case, model="test", client=client, temperature=0.0
    )
    assert client.prompt == "ORIGINAL BENCHMARK PROMPT"
    assert "M1021" not in client.prompt
    assert result["final_answer"] == "M1021, M1038"
    assert result["alignment"]["f1"] == 1.0
