"""System B: deterministic atom verifier, Belnap-style evidence state and the fixed
decision rule that maps verified atoms onto VEX-Bench's category space.

Atom states: "U" (unknown), "T" (verified true), "F" (verified false),
"B" (both a T and an F proposal were verified -- conflict).

Verification (all deterministic, no LLM):
  span check      file exists inside the repo; 1 <= start <= end <= len, end-start < 40;
                  the snippet (each line stripped of surrounding whitespace, blank lines
                  dropped) is a contiguous substring of the stripped lines start..end.
  dependency_present        T: span ok and snippet contains a package token
                               (Go stdlib CVEs: a go.mod 'go'/'toolchain' directive).
                            F: zero files in the whole repo contain any package token
                               (not available for Go stdlib CVEs).
  vulnerable_version_used   T: 1-3 spans ok; their union names the package (token, or for
                               this atom only its first '-'-separated stem of >=4 chars, to
                               allow Maven version properties; stdlib: go directive) and has
                               a version inside an advisory affected range.
                            F: same, but every parsable version lies outside all ranges.
  vulnerable_symbol_referenced
                            T: span ok, non-vendored file, snippet contains an advisory
                               symbol token (explicit advisory symbols if the advisory
                               lists any, else advisory identifiers + import tokens).
                            F: zero non-vendored source files contain any import token.
  vulnerable_path_reachable_from_entry
                            T: 1-5 spans, all ok, all in non-test non-vendored files,
                               last span contains an advisory symbol token.
                            F: every non-vendored source file containing an import token
                               is a test/example/doc path (or there is none).
  mitigating_config         T: span ok in a non-vendored file and not comment-only
                               (semantics NOT verifiable).
                            F: not accepted (absence of a mitigation is unverifiable).

Decision rule (evaluated in VEX-Bench's own precedence order):
  1. dep F                      -> code_not_present
  2. version F (not B)          -> code_not_present  (patched version: vulnerable code absent)
  3. dep U                      -> ABSTAIN
  4. sym F or reach F           -> code_not_reachable
  5. reach T and mitig T        -> requires_configuration
  6. reach T                    -> vulnerable
  7. otherwise                  -> ABSTAIN
ABSTAIN is emitted as VEX-Bench's own fallback category "uncertain" (binary: not_exploitable).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from deepcti.vexbench.advisory import Advisory
from deepcti.vexbench.tools import SOURCE_GLOBS, RepoTools, is_test_path, is_vendor_path

ATOMS = ["dependency_present", "vulnerable_version_used", "vulnerable_symbol_referenced",
         "vulnerable_path_reachable_from_entry", "mitigating_config"]
VERSION_RE = re.compile(r"(?<![\w.])v?\d+\.\d+(?:\.\d+)*(?:[-.+~][\w.+-]*)?")
COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*|<!--|--|;)")
GO_DIRECTIVE_RE = re.compile(r"^\s*(go|toolchain)\s+(go)?\d", re.M)


def _norm_lines(s: str) -> list[str]:
    return [ln.strip() for ln in s.replace("\r", "").split("\n") if ln.strip()]


@dataclass
class EvidenceState:
    state: dict[str, str] = field(default_factory=lambda: {a: "U" for a in ATOMS})
    accepted: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    verifier_searches: int = 0

    def set(self, atom: str, value: bool) -> None:
        cur = self.state[atom]
        new = "T" if value else "F"
        if cur == "U":
            self.state[atom] = new
        elif cur != new and cur != "B":
            self.state[atom] = "B"


def decide(st: dict[str, str]) -> tuple[str | None, str]:
    """Return (category or None for abstain, rule id)."""
    dep, ver, sym, reach, mit = (st[a] for a in ATOMS)
    if dep == "F":
        return "code_not_present", "R1"
    if ver == "F":
        return "code_not_present", "R2"
    if dep == "U":
        return None, "R3"
    if sym == "F" or reach == "F":
        return "code_not_reachable", "R4"
    if reach == "T" and mit == "T":
        return "requires_configuration", "R5"
    if reach == "T":
        return "vulnerable", "R6"
    return None, "R7"


class Verifier:
    def __init__(self, tools: RepoTools, adv: Advisory):
        self.tools = tools
        self.adv = adv
        self.ev = EvidenceState()
        self._import_files: list[str] | None = None

    # ---------- helpers ----------
    def _span_ok(self, sp: dict) -> tuple[bool, str, str]:
        try:
            path = str(sp.get("path", "")).strip()
            s, e = int(sp.get("start_line")), int(sp.get("end_line"))
        except (TypeError, ValueError):
            return False, "span needs path, integer start_line and end_line", ""
        snippet = str(sp.get("snippet", ""))
        lines = self.tools.file_lines(path)
        if lines is None:
            return False, f"file not found in repo: {path}", ""
        if not (1 <= s <= e <= len(lines)) or e - s >= 40:
            return False, f"bad line range {s}-{e} (file has {len(lines)} lines; max 40 lines)", ""
        sn = _norm_lines(snippet)
        if sum(len(x) for x in sn) < 3:
            return False, "snippet too short", ""
        region = _norm_lines("\n".join(lines[s - 1:e]))
        joined, needle = "\n".join(region), "\n".join(sn)
        if needle not in joined:
            return False, f"snippet does not occur verbatim at {path}:{s}-{e}", ""
        return True, "ok", needle

    def _has_pkg(self, text: str, stems: bool = False) -> bool:
        low = text.lower()
        if self.adv.is_go_stdlib and GO_DIRECTIVE_RE.search(text):
            return True
        toks = list(self.adv.package_tokens())
        if stems:  # e.g. Maven property <dep.netty.version> for artifact netty-common
            toks += [t.split("-")[0] for t in toks if len(t.split("-")[0]) >= 4]
        return any(t.lower() in low for t in toks)

    def _versions(self, text: str) -> list[bool | None]:
        res = []
        for v in VERSION_RE.findall(text):
            for p in self.adv.packages:
                if p.intervals:
                    res.append(p.contains(v))
        return res

    def _first_party_import_files(self) -> list[str]:
        if self._import_files is None:
            files: set[str] = set()
            for tok in self.adv.import_tokens():
                self.ev.verifier_searches += 1
                files |= {f for f in self.tools.count_fixed(tok, SOURCE_GLOBS) if not is_vendor_path(f)}
            self._import_files = sorted(files)
        return self._import_files

    # ---------- main entry ----------
    def propose(self, atom: str, value, spans: list | None, note: str = "") -> dict:
        rec = {"atom": atom, "value": value, "spans": spans or [], "note": note}
        ok, why = self._check(atom, value, spans or [])
        rec["verdict"] = "accepted" if ok else "rejected"
        rec["reason"] = why
        if ok:
            self.ev.set(atom, bool(value))
            self.ev.accepted.append(rec)
        else:
            self.ev.rejected.append(rec)
        return rec

    def _check(self, atom: str, value, spans: list) -> tuple[bool, str]:
        if atom not in ATOMS:
            return False, f"unknown atom {atom!r}"
        if not isinstance(value, bool):
            return False, "value must be true or false"
        if not isinstance(spans, list):
            return False, "spans must be a list"
        adv = self.adv

        if atom == "dependency_present":
            if value:
                if not spans:
                    return False, "a true claim needs a span"
                ok, why, txt = self._span_ok(spans[0])
                if not ok:
                    return False, why
                if not self._has_pkg(txt):
                    return False, f"snippet does not name the affected package (expected one of {adv.package_tokens()[:6] or ['go directive']})"
                return True, "verified"
            if adv.is_go_stdlib or not adv.package_tokens():
                return False, "absence cannot be verified for this advisory (standard library / no package name)"
            for tok in adv.package_tokens():
                self.ev.verifier_searches += 1
                hits = self.tools.count_fixed(tok)
                if hits:
                    return False, f"package token {tok!r} occurs in {len(hits)} file(s), e.g. {hits[0]}"
            return True, "verified: no file in the repository mentions the package"

        if atom == "vulnerable_version_used":
            if not (1 <= len(spans) <= 3):
                return False, "a version claim needs 1-3 spans (manifest/lockfile/property lines)"
            texts = []
            for sp in spans:
                ok, why, t = self._span_ok(sp)
                if not ok:
                    return False, why
                texts.append(t)
            txt = "\n".join(texts)
            if not self._has_pkg(txt, stems=True):
                return False, "the spans do not name the affected package"
            vs = [v for v in self._versions(txt) if v is not None]
            if not vs:
                return False, "no version in the snippet could be checked against the affected ranges"
            if value and any(vs):
                return True, "verified: version inside an affected range"
            if not value and not any(vs):
                return True, "verified: version outside all affected ranges"
            return False, "version check contradicts the claim"

        if atom == "vulnerable_symbol_referenced":
            if value:
                if not spans:
                    return False, "a true claim needs a span"
                ok, why, txt = self._span_ok(spans[0])
                if not ok:
                    return False, why
                if is_vendor_path(str(spans[0].get("path", ""))):
                    return False, "span is in vendored/third-party code, not first-party"
                if not any(t in txt for t in adv.symbol_tokens()):
                    return False, f"snippet contains none of the advisory symbols {adv.symbol_tokens()[:8]}"
                return True, "verified"
            files = self._first_party_import_files()
            if files:
                return False, f"first-party source references the package in {len(files)} file(s), e.g. {files[0]}"
            return True, "verified: no first-party source file references the package"

        if atom == "vulnerable_path_reachable_from_entry":
            if value:
                if not (1 <= len(spans) <= 5):
                    return False, "a reachability claim needs 1-5 spans (entry point ... call site)"
                for sp in spans:
                    ok, why, txt = self._span_ok(sp)
                    if not ok:
                        return False, why
                    p = str(sp.get("path", ""))
                    if is_test_path(p) or is_vendor_path(p):
                        return False, f"span {p} is test/example/vendored code, not a production path"
                if not any(t in txt for t in adv.symbol_tokens()):
                    return False, f"last span (call site) contains none of the advisory symbols {adv.symbol_tokens()[:8]}"
                return True, "verified"
            files = self._first_party_import_files()
            prod = [f for f in files if not is_test_path(f)]
            if prod:
                return False, f"non-test source references the package in {len(prod)} file(s), e.g. {prod[0]}"
            return True, "verified: package referenced only from test/example code (or not at all)"

        if atom == "mitigating_config":
            if not value:
                return False, "absence of a mitigation cannot be verified; simply do not claim one"
            if not spans:
                return False, "a mitigation claim needs a span"
            ok, why, txt = self._span_ok(spans[0])
            if not ok:
                return False, why
            if is_vendor_path(str(spans[0].get("path", ""))):
                return False, "span is in vendored code"
            if not any(not COMMENT_RE.match(ln) for ln in txt.split("\n")):
                return False, "snippet consists only of comments; point at the effective setting/code"
            return True, "span verified (semantics not machine-checkable)"
        return False, "unreachable"
