from __future__ import annotations
import argparse, json, os, time
from pathlib import Path
from typing import List
from .dataset import load_cases, Case
from .prompts import make_prompt, dry_answer
from .ollama_client import generate_ollama

MODES = ["one_shot", "no_memory", "iterative"]
DEFAULT_MODELS = ["gemma4:e4b", "llama3.1:8b", "qwen2.5:14b", "mistral-nemo:12b", "gemma3:12b", "deepseek-r1:8b"]


def extract_final_target(answer: str) -> str:
    marker = "FINAL MITIGATION TARGET:"
    if marker.lower() not in answer.lower():
        return answer.strip()[:1200]
    idx = answer.lower().find(marker.lower()) + len(marker)
    rest = answer[idx:]
    # cut at next all-caps section heading
    for h in ["EVIDENCE USED:", "WHY THIS MITIGATION:", "VERIFICATION", "RETRIEVAL", "TRACE"]:
        j = rest.lower().find(h.lower())
        if j >= 0:
            rest = rest[:j]
            break
    return rest.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-path", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--models", default=",".join(DEFAULT_MODELS))
    ap.add_argument("--modes", default=",".join(MODES))
    ap.add_argument("--max-cases", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    pred_path = out / "predictions.jsonl"
    err_path = out / "errors.jsonl"
    log_path = out / "run_log.txt"
    cases = load_cases(args.data_path, args.max_cases)
    models = ["dryrun"] if args.dry_run else [m.strip() for m in args.models.split(",") if m.strip()]
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    if args.no_resume and pred_path.exists(): pred_path.unlink()
    if args.no_resume and err_path.exists(): err_path.unlink()

    done = 0; failed = 0
    with open(log_path, "a", encoding="utf-8") as log, open(pred_path, "a", encoding="utf-8") as pred, open(err_path, "a", encoding="utf-8") as err:
        def L(s):
            line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {s}"
            print(line); log.write(line+"\n"); log.flush()
        L(f"cases={len(cases)} models={models} modes={modes} dry_run={args.dry_run}")
        total = len(cases)*len(models)*len(modes)
        n=0
        for case in cases:
            for model in models:
                for mode in modes:
                    n += 1
                    L(f"[{n}/{total}] RUN case={case.case_id} model={model} mode={mode}")
                    try:
                        prompt = make_prompt(case, mode)
                        answer = dry_answer(case, mode) if args.dry_run else generate_ollama(model, prompt, timeout=args.timeout)
                        rec = {
                            "case_id": case.case_id,
                            "model": model,
                            "mode": mode,
                            "question": case.question,
                            "answer": answer,
                            "final_mitigation_target": extract_final_target(answer),
                            "reference": case.reference,
                            "initial_context": case.initial_context,
                            "baseline": case.baseline,
                            "stage_evidence": case.stage_evidence,
                            "prompt_chars": len(prompt),
                            "answer_chars": len(answer),
                        }
                        pred.write(json.dumps(rec, ensure_ascii=False)+"\n"); pred.flush()
                        done += 1
                        L(f"OK answer_chars={len(answer)} final_target_chars={len(rec['final_mitigation_target'])}")
                    except Exception as e:
                        failed += 1
                        err.write(json.dumps({"case_id": case.case_id, "model": model, "mode": mode, "error": repr(e)}, ensure_ascii=False)+"\n"); err.flush()
                        L(f"ERROR {repr(e)}")
        L(f"completed={done} failed={failed} predictions={pred_path}")
        if done == 0:
            raise SystemExit("No predictions were written. Check dataset path/model backend.")

if __name__ == "__main__":
    main()
