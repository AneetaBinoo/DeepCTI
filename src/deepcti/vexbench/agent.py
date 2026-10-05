"""Systems A (open ReAct harness) and B (same harness + evidence-state discipline)
for VEX-Bench. Both share: the VEX-Bench task prompt (verbatim), the offline
advisory digest, the 4 read-only code tools, a 30-code-tool-call budget, a
45-turn limit, a 600 s wall-clock limit, max 2048 output tokens per turn, and an
identical context-trimming policy.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import openai

from deepcti.vexbench.advisory import Advisory
from deepcti.vexbench.tools import TOOL_SPECS, RepoTools, dispatch
from deepcti.vexbench.verifier import ATOMS, Verifier, decide

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "data/external/vex-bench/src"))
from evaluate.prompts import VULNERABILITY_ANALYSIS_PROMPT  # noqa: E402  (their prompt, verbatim)
from evaluate.result_parser import parse_category  # noqa: E402

MAX_TOOL_CALLS = 30
MAX_TURNS = 45
WALL_SECONDS = 600
MAX_OUT_TOKENS = 2048
CONTEXT_CHAR_LIMIT = 60000
MITIGATION_WINDOW = 4  # B: extra code-tool calls allowed for a mitigation search once reach=T

MODELS = {
    "gemma_4_31b": {"base_url": "http://127.0.0.1:8103/v1", "extra_body": {}},
    "qwen3_14b": {"base_url": "http://127.0.0.1:8309/v1",
                  "extra_body": {"chat_template_kwargs": {"enable_thinking": False}}},
}

COMMON_ENV_NOTE = """
<ENVIRONMENT_NOTE>
This harness has NO network access. Instead of looking the CVE up online, use the
advisory digest below (compiled offline from OSV and the GitHub Advisory Database).
The repository root is '.'. You can only use the provided read-only tools
(list_dir, read_file, grep, find_symbol_usages). Budget: at most {budget} tool calls.
Repository language: {language}.
</ENVIRONMENT_NOTE>

<ADVISORY_DIGEST>
{digest}
</ADVISORY_DIGEST>
"""

A_SUFFIX = """
When you have enough evidence (or the budget is nearly used up), stop calling tools and reply with the final JSON object exactly as specified in OUTPUT_FORMAT.
"""

B_SUFFIX = """
<EVIDENCE_PROTOCOL>
In this harness you do NOT output the category yourself. Instead you submit evidence
atoms with the `propose_atom` tool. A deterministic verifier checks every atom against
the repository, and the final category is computed from the verified atoms by a fixed
rule that follows the precedence order above. Atoms:
  - dependency_present (true: span in a manifest/lockfile/vendored path naming the affected package;
      false: claim absence -- the verifier will search the whole repository for the package name)
  - vulnerable_version_used (1-3 spans on the manifest/lockfile/property line(s) that together name the package AND its
      resolved version; true if inside the affected range, false if outside)
  - vulnerable_symbol_referenced (true: span in first-party code whose text contains a vulnerable
      symbol/package name from the advisory; false: claim the package is never referenced from
      first-party source -- the verifier re-checks by search)
  - vulnerable_path_reachable_from_entry (true: 1-5 spans in non-test code from an entry point down to
      the call site; the LAST span must contain the vulnerable symbol; false: claim that only test /
      example code references the package -- the verifier re-checks by search)
  - mitigating_config (true only: span on a configuration/flag/default that must be changed for the
      vulnerable behaviour to be exploitable)
Every span = {{"path": file path, "start_line": int, "end_line": int, "snippet": text copied
VERBATIM from those lines}}. Copy snippets exactly from read_file output (without the line-number
prefixes). Rejected atoms come back with the reason; you may fix and resubmit.
Call `finish` when you cannot gather more decisive evidence.
</EVIDENCE_PROTOCOL>
"""

B_TOOLS = [
    {"type": "function", "function": {
        "name": "propose_atom",
        "description": "Submit one evidence atom with span pointers for deterministic verification.",
        "parameters": {"type": "object", "properties": {
            "atom": {"type": "string", "enum": ATOMS},
            "value": {"type": "boolean"},
            "spans": {"type": "array", "items": {"type": "object", "properties": {
                "path": {"type": "string"}, "start_line": {"type": "integer"},
                "end_line": {"type": "integer"}, "snippet": {"type": "string"}},
                "required": ["path", "start_line", "end_line", "snippet"]}},
            "note": {"type": "string"}},
            "required": ["atom", "value"]}}},
    {"type": "function", "function": {
        "name": "finish", "description": "Stop the investigation; the verdict is computed from verified atoms.",
        "parameters": {"type": "object", "properties": {}}}},
]

CODE_TOOLS = {"list_dir", "read_file", "grep", "find_symbol_usages"}


def task_prompt(cve_id: str, language: str, adv: Advisory) -> str:
    base = VULNERABILITY_ANALYSIS_PROMPT.replace("{cve_id}", cve_id)
    return base + "\n" + COMMON_ENV_NOTE.format(budget=MAX_TOOL_CALLS, language=language, digest=adv.digest())


@dataclass
class RunResult:
    category: str | None
    reasoning: str | None
    raw_output: str
    abstained: bool
    tool_calls: int
    turns: int
    prompt_tokens: int
    completion_tokens: int
    seconds: float
    end_reason: str
    trace: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)


class Harness:
    def __init__(self, model: str, seed: int, temperature: float = 0.7):
        spec = MODELS[model]
        self.model = model
        self.extra_body = spec["extra_body"]
        self.client = openai.OpenAI(base_url=spec["base_url"], api_key="EMPTY", timeout=300, max_retries=2)
        self.seed = seed
        self.temperature = temperature
        self.ptok = 0
        self.ctok = 0

    def _trim(self, messages: list[dict]) -> None:
        def size() -> int:
            return sum(len(json.dumps(m, default=str)) for m in messages)
        i = 2
        while size() > CONTEXT_CHAR_LIMIT and i < len(messages) - 2:
            m = messages[i]
            if m.get("role") == "tool" and not m.get("_elided"):
                m["content"] = "[older tool output elided to fit the context window; re-run the tool if needed]"
                m["_elided"] = True
            i += 1

    def chat(self, messages: list[dict], tools: list[dict] | None, tool_choice: str = "auto"):
        self._trim(messages)
        clean = [{k: v for k, v in m.items() if not k.startswith("_")} for m in messages]
        kw = dict(model=self.model, messages=clean, temperature=self.temperature, seed=self.seed,
                  max_tokens=MAX_OUT_TOKENS, extra_body=self.extra_body)
        if tools:
            kw["tools"] = tools
            kw["tool_choice"] = tool_choice
        for attempt in range(3):
            try:
                r = self.client.chat.completions.create(**kw)
                break
            except openai.BadRequestError as e:
                # context overflow: elide everything but the last tool message, retry
                for m in messages[2:-1]:
                    if m.get("role") == "tool":
                        m["content"] = "[elided]"
                        m["_elided"] = True
                kw["messages"] = [{k: v for k, v in m.items() if not k.startswith("_")} for m in messages]
                if attempt == 2:
                    raise RuntimeError(f"bad request: {e}") from e
        if r.usage:
            self.ptok += r.usage.prompt_tokens or 0
            self.ctok += r.usage.completion_tokens or 0
        return r.choices[0].message, r.choices[0].finish_reason


def _assistant_msg(msg) -> dict:
    d = {"role": "assistant", "content": msg.content or ""}
    if msg.tool_calls:
        d["tool_calls"] = [{"id": tc.id, "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                           for tc in msg.tool_calls]
    return d


def _args(tc) -> dict:
    try:
        a = json.loads(tc.function.arguments or "{}")
        return a if isinstance(a, dict) else {}
    except json.JSONDecodeError:
        return {"_parse_error": tc.function.arguments}


def run_system_a(repo: Path, task: dict, adv: Advisory, model: str, seed: int) -> RunResult:
    tools = RepoTools(repo)
    h = Harness(model, seed)
    t0 = time.time()
    msgs = [{"role": "system", "content": "You are a careful security analyst agent with read-only code-inspection tools."},
            {"role": "user", "content": task_prompt(task["cve_id"], task["metadata"]["language"], adv) + A_SUFFIX}]
    trace, n_tools, turns, end = [], 0, 0, "budget"
    final_text = ""
    nudges = 0
    while turns < MAX_TURNS:
        turns += 1
        out_of_budget = n_tools >= MAX_TOOL_CALLS or time.time() - t0 > WALL_SECONDS or turns >= MAX_TURNS
        if out_of_budget:
            msgs.append({"role": "user", "content": "Tool budget exhausted. Output your final JSON object now (no more tool calls)."})
            msg, fr = h.chat(msgs, TOOL_SPECS, tool_choice="none")
            final_text = msg.content or ""
            trace.append({"turn": turns, "assistant": final_text, "forced": True})
            end = "budget_forced_answer"
            break
        msg, fr = h.chat(msgs, TOOL_SPECS)
        msgs.append(_assistant_msg(msg))
        if not msg.tool_calls:
            final_text = msg.content or ""
            trace.append({"turn": turns, "assistant": final_text})
            if parse_category(final_text)[0] is None and nudges < 2:
                nudges += 1
                msgs.append({"role": "user", "content": "Reply with ONLY the final JSON object {\"category\": ..., \"reasoning\": ...} using one of the 12 category names, or continue investigating with tools."})
                continue
            end = "answered"
            break
        for tc in msg.tool_calls:
            a = _args(tc)
            n_tools += 1
            res = dispatch(tools, tc.function.name, a) if n_tools <= MAX_TOOL_CALLS else "ERROR: tool budget exhausted"
            msgs.append({"role": "tool", "tool_call_id": tc.id, "content": res})
            trace.append({"turn": turns, "tool": tc.function.name, "args": a, "result_chars": len(res), "result_head": res[:400]})
    cat, reasoning = parse_category(final_text)
    return RunResult(category=cat, reasoning=reasoning, raw_output=final_text,
                     abstained=(cat is None or cat == "uncertain"), tool_calls=n_tools, turns=turns,
                     prompt_tokens=h.ptok, completion_tokens=h.ctok, seconds=time.time() - t0,
                     end_reason=end, trace=trace)


def _status(ver: Verifier) -> tuple[str, str]:
    st = ver.ev.state
    order = ["dependency_present", "vulnerable_version_used", "vulnerable_symbol_referenced",
             "vulnerable_path_reachable_from_entry", "mitigating_config"]
    nxt = next((a for a in order if st[a] == "U"), "mitigating_config")
    hints = {
        "dependency_present": "inspect manifests/lockfiles/vendor dirs (go.mod, go.sum, pom.xml, build.gradle, requirements*.txt, pyproject.toml, poetry.lock, uv.lock, setup.py)",
        "vulnerable_version_used": "read the manifest/lockfile line(s) with the resolved version",
        "vulnerable_symbol_referenced": "find_symbol_usages / grep for the vulnerable symbols or the package import in first-party code",
        "vulnerable_path_reachable_from_entry": "trace callers of the call site back to an entry point (handler, main, CLI, server)",
        "mitigating_config": "look for configuration, flags or defaults that disable the vulnerable behaviour",
    }
    s = "EVIDENCE STATE: " + ", ".join(f"{a}={st[a]}" for a in order)
    return s, (f"Next atom to resolve (greedy, decision-rule order): {nxt} -- suggested: {hints[nxt]}. "
               "Submit it with propose_atom as soon as you have a supporting span (or a verifiable absence claim).")


def run_system_b(repo: Path, task: dict, adv: Advisory, model: str, seed: int) -> RunResult:
    tools = RepoTools(repo)
    ver = Verifier(tools, adv)
    h = Harness(model, seed)
    t0 = time.time()
    msgs = [{"role": "system", "content": "You are a careful security analyst agent with read-only code-inspection tools."},
            {"role": "user", "content": task_prompt(task["cve_id"], task["metadata"]["language"], adv) + B_SUFFIX}]
    all_tools = TOOL_SPECS + B_TOOLS
    trace, n_tools, turns, n_props, end = [], 0, 0, 0, "budget"
    reach_t_at: int | None = None
    nudges = 0
    stop = False
    while turns < MAX_TURNS and not stop:
        if n_tools >= MAX_TOOL_CALLS or time.time() - t0 > WALL_SECONDS:
            end = "budget"
            break
        turns += 1
        msg, fr = h.chat(msgs, all_tools)
        msgs.append(_assistant_msg(msg))
        if not msg.tool_calls:
            trace.append({"turn": turns, "assistant": (msg.content or "")[:2000]})
            if nudges >= 2:
                end = "no_tool_call"
                break
            nudges += 1
            s, nx = _status(ver)
            msgs.append({"role": "user", "content": f"{s}\n{nx}\nUse the tools: propose_atom to submit evidence, or finish."})
            continue
        for tc in msg.tool_calls:
            a = _args(tc)
            name = tc.function.name
            if name in CODE_TOOLS:
                n_tools += 1
                res = dispatch(tools, name, a) if n_tools <= MAX_TOOL_CALLS else "ERROR: tool budget exhausted"
                trace.append({"turn": turns, "tool": name, "args": a, "result_chars": len(res), "result_head": res[:400]})
            elif name == "propose_atom":
                n_props += 1
                if n_props > 20:
                    res = "ERROR: proposal limit (20) reached; call finish."
                else:
                    rec = ver.propose(str(a.get("atom", "")), a.get("value"), a.get("spans") or [], str(a.get("note", "")))
                    res = f"{rec['verdict'].upper()}: {rec['reason']}"
                    trace.append({"turn": turns, "propose": a, "verdict": rec["verdict"], "reason": rec["reason"]})
            elif name == "finish":
                res = "finished"
                end = "finish"
                stop = True
                trace.append({"turn": turns, "finish": True})
            else:
                res = f"ERROR: unknown tool {name}"
            # stopping rule
            cat, rule = decide(ver.ev.state)
            if not stop and rule in ("R1", "R2", "R4", "R5"):
                stop, end = True, f"decisive_{rule}"
            if not stop and rule == "R6":
                if reach_t_at is None:
                    reach_t_at = n_tools
                elif n_tools - reach_t_at >= MITIGATION_WINDOW:
                    stop, end = True, "decisive_R6_after_mitigation_window"
            s, nx = _status(ver)
            msgs.append({"role": "tool", "tool_call_id": tc.id, "content": f"{res}\n\n{s}\n{nx}"})
    cat, rule = decide(ver.ev.state)
    abstained = cat is None
    category = cat or "uncertain"
    reasoning_lines = [f"Decision rule {rule} over verified evidence state {ver.ev.state}."]
    for r in ver.ev.accepted:
        sp = "; ".join(f"{s.get('path')}:{s.get('start_line')}-{s.get('end_line')}" for s in r["spans"]) or "repository-wide search"
        reasoning_lines.append(f"{r['atom']}={r['value']} [{sp}] ({r['reason']}) {r.get('note', '')}".strip())
    raw = json.dumps({"category": category, "reasoning": "\n".join(reasoning_lines)})
    pc, preason = parse_category(raw)
    return RunResult(category=pc, reasoning=preason, raw_output=raw, abstained=abstained,
                     tool_calls=n_tools, turns=turns, prompt_tokens=h.ptok, completion_tokens=h.ctok,
                     seconds=time.time() - t0, end_reason=end, trace=trace,
                     extra={"rule": rule, "state": ver.ev.state, "accepted": ver.ev.accepted,
                            "rejected": ver.ev.rejected, "proposals": n_props,
                            "verifier_searches": ver.ev.verifier_searches})
