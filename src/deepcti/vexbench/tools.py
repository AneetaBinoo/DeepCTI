"""Read-only, repo-sandboxed code-inspection tools shared by systems A and B.

Every path is resolved and must stay inside the case repository root; there is
no network access and no write operation. Outputs are truncated identically for
both systems (same tool costs: 1 unit per call).
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

MAX_OUT_CHARS = 6000
MAX_READ_LINES = 150
SOURCE_GLOBS = ["*.go", "*.java", "*.kt", "*.scala", "*.groovy", "*.py", "*.pyi"]
SKIP_DIRS = [".git", "node_modules", ".venv", "__pycache__"]
TEST_RE = re.compile(r"(^|/)(test|tests|testing|testdata|e2e|it|examples?|docs?|benchmarks?)(/|$)|_test\.go$|(^|/)test_[^/]*\.py$|[^/]*_test\.py$|Test[^/]*\.java$|[^/]*Test\.java$|[^/]*Tests\.java$|(^|/)src/test/", re.I)
VENDOR_RE = re.compile(r"(^|/)(vendor|third_party|third-party|node_modules|site-packages)(/|$)")


def is_test_path(rel: str) -> bool:
    return bool(TEST_RE.search(rel))


def is_vendor_path(rel: str) -> bool:
    return bool(VENDOR_RE.search(rel))


class SandboxError(Exception):
    pass


class RepoTools:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    # ---------- sandbox ----------
    def resolve(self, path: str | None) -> Path:
        p = (path or ".").strip() or "."
        p = p.lstrip("/") if not p.startswith(str(self.root)) else os.path.relpath(p, self.root)
        full = (self.root / p).resolve()
        if full != self.root and self.root not in full.parents:
            raise SandboxError(f"path escapes the repository sandbox: {path}")
        return full

    def rel(self, full: Path) -> str:
        return str(full.relative_to(self.root)) if full != self.root else "."

    @staticmethod
    def _clip(s: str) -> str:
        if len(s) > MAX_OUT_CHARS:
            return s[:MAX_OUT_CHARS] + f"\n...[output truncated at {MAX_OUT_CHARS} chars]"
        return s

    # ---------- tools ----------
    def list_dir(self, path: str = ".") -> str:
        full = self.resolve(path)
        if not full.is_dir():
            return f"ERROR: not a directory: {path}"
        entries = sorted(os.listdir(full))
        out = []
        for e in entries[:300]:
            if e == ".git":
                continue
            out.append(e + ("/" if (full / e).is_dir() else ""))
        more = f"\n...({len(entries) - 300} more entries)" if len(entries) > 300 else ""
        return self._clip(f"{self.rel(full)}:\n" + "\n".join(out) + more)

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        full = self.resolve(path)
        if not full.is_file():
            return f"ERROR: not a file: {path}"
        try:
            lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e}"
        start = max(1, int(start_line or 1))
        end = int(end_line) if end_line else start + MAX_READ_LINES - 1
        end = min(end, start + MAX_READ_LINES - 1, len(lines))
        body = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
        return self._clip(f"{self.rel(full)} (lines {start}-{end} of {len(lines)}):\n{body}")

    def _grep(self, args: list[str], path: str) -> list[str]:
        full = self.resolve(path)
        cmd = ["grep", "-rnI", "--no-messages"]
        for d in SKIP_DIRS:
            cmd.append(f"--exclude-dir={d}")
        cmd += args + ["--", self.rel(full)]
        try:
            r = subprocess.run(cmd, cwd=self.root, capture_output=True, text=True, timeout=60, errors="replace")
        except subprocess.TimeoutExpired:
            return ["ERROR: search timed out"]
        return [ln for ln in r.stdout.splitlines() if ln]

    def grep(self, pattern: str, path: str = ".", glob: str | None = None, max_results: int = 60) -> str:
        if not pattern:
            return "ERROR: empty pattern"
        extra = [f"--include={glob}"] if glob else []
        try:
            re.compile(pattern)
            mode = ["-E"]
        except re.error:
            mode = ["-F"]
        hits = self._grep(mode + extra + ["-e", pattern], path)
        return self._fmt_hits(hits, max_results, f"grep {pattern!r} in {path}")

    def find_symbol_usages(self, symbol: str, path: str = ".", max_results: int = 60) -> str:
        if not symbol:
            return "ERROR: empty symbol"
        inc = [f"--include={g}" for g in SOURCE_GLOBS]
        hits = self._grep(["-F", "-w"] + inc + ["-e", symbol], path)
        return self._fmt_hits(hits, max_results, f"usages of {symbol!r} in source files under {path}", annotate=True)

    def _fmt_hits(self, hits: list[str], max_results: int, title: str, annotate: bool = False) -> str:
        max_results = max(1, min(int(max_results or 60), 100))
        out = []
        for h in hits[:max_results]:
            f = h.split(":", 1)[0]
            tag = ""
            if annotate:
                tag = " [vendor]" if is_vendor_path(f) else (" [test]" if is_test_path(f) else "")
            out.append(h[:300] + tag)
        more = f"\n...({len(hits) - max_results} more matches not shown)" if len(hits) > max_results else ""
        return self._clip(f"{title}: {len(hits)} matches\n" + "\n".join(out) + more)

    # ---------- deterministic helpers for the verifier (not exposed to the LLM) ----------
    def count_fixed(self, token: str, include_globs: list[str] | None = None) -> list[str]:
        args = ["-F", "-l"] + [f"--include={g}" for g in (include_globs or [])] + ["-e", token]
        return [ln for ln in self._grep(args, ".") if not ln.startswith("ERROR")]

    def file_lines(self, path: str) -> list[str] | None:
        try:
            full = self.resolve(path)
        except SandboxError:
            return None
        if not full.is_file():
            return None
        return full.read_text(encoding="utf-8", errors="replace").splitlines()


TOOL_SPECS = [
    {"type": "function", "function": {
        "name": "list_dir", "description": "List entries of a directory in the repository (read-only).",
        "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "Directory path relative to repo root"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "read_file", "description": f"Read a file with line numbers; at most {MAX_READ_LINES} lines per call.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "grep", "description": "Recursive regex (ERE) search over the repository; returns file:line:text matches.",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}, "path": {"type": "string", "description": "Subdirectory to search (default '.')"},
            "glob": {"type": "string", "description": "Optional filename glob, e.g. '*.go' or 'pom.xml'"},
            "max_results": {"type": "integer"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "find_symbol_usages", "description": "Whole-word search for a symbol in source files (.go/.java/.kt/.scala/.groovy/.py); hits in test or vendored paths are tagged.",
        "parameters": {"type": "object", "properties": {
            "symbol": {"type": "string"}, "path": {"type": "string"}, "max_results": {"type": "integer"}}, "required": ["symbol"]}}},
]


def dispatch(tools: RepoTools, name: str, args: dict) -> str:
    try:
        if name == "list_dir":
            return tools.list_dir(args.get("path", "."))
        if name == "read_file":
            return tools.read_file(args.get("path", ""), args.get("start_line", 1), args.get("end_line"))
        if name == "grep":
            return tools.grep(args.get("pattern", ""), args.get("path", "."), args.get("glob"), args.get("max_results", 60))
        if name == "find_symbol_usages":
            return tools.find_symbol_usages(args.get("symbol", ""), args.get("path", "."), args.get("max_results", 60))
    except SandboxError as e:
        return f"ERROR: {e}"
    except (TypeError, ValueError) as e:
        return f"ERROR: bad arguments: {e}"
    return f"ERROR: unknown tool {name}"
