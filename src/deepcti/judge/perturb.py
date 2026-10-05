"""Deterministic minimal edits that turn a supported claim into a false one (E11 judge validation).

Every function returns the edited claim, or None if the edit type does not apply to the claim.
"""

from __future__ import annotations

import re

VERSION_RE = re.compile(r"(?<![\w.:~+\-])(?:\d+:)?\d+(?:\.\d+)+[0-9A-Za-z.+~:\-]*")
CALL_CITE_RE = re.compile(r"\[([^\]]*)\]")
CALL_ID_RE = re.compile(r"\b[ch](\d{3})\b")

_NOUNS = (r"range|ranges|version|versions|package|packages|component|code|binary|binaries|release|releases|source|"
          r"feature|features|function|functions|configuration|library|libraries|setting|path|module")
STATUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bnot[ _]affected\b", re.IGNORECASE), "affected"),
    (re.compile(r"\bunder[ _]investigation\b", re.IGNORECASE), "fixed"),
    (re.compile(r"\bnot vulnerable\b", re.IGNORECASE), "vulnerable"),
    (re.compile(rf"\baffected\b(?![ _\-](?:{_NOUNS})\b)", re.IGNORECASE), "not affected"),
    (re.compile(rf"\bvulnerable\b(?![ _\-](?:{_NOUNS})\b)", re.IGNORECASE), "not vulnerable"),
    (re.compile(r"\bfixed\b(?![ _\-](?:version|versions|in|upstream|release|releases|package|packages)\b)", re.IGNORECASE),
     "affected"),
]
AUX = r"is|are|was|were|has|have|had|does|do|did|can"
NEG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(rf"\b({AUX}) not\b", re.IGNORECASE), r"\1"),
    (re.compile(r"\b(is|are|was|were|has|have|had|does|do|did)n't\b", re.IGNORECASE), r"\1"),
    (re.compile(r"\bcan't\b", re.IGNORECASE), "can"),
    (re.compile(r"\bcannot\b", re.IGNORECASE), "can"),
    (re.compile(r"\bnot\s+", re.IGNORECASE), ""),
]
INSERT_RE = re.compile(rf"\b({AUX})\b", re.IGNORECASE)


def versions_in(text: str) -> list[str]:
    return [m.group(0).rstrip(".,;:)-") for m in VERSION_RE.finditer(text or "")]


def _bump(version: str, k: int) -> str:
    m = re.match(r"(\d+:)?(\d+)(.*)", version, re.DOTALL)
    epoch, major, rest = m.group(1) or "", int(m.group(2)), m.group(3)
    return f"{epoch}{major + k}{rest}"


def wrong_version(claim: str, evidence_text: str) -> str | None:
    found = versions_in(claim)
    if not found:
        return None
    v = found[0]
    for k in range(1, 50):
        new = _bump(v, k)
        if new not in evidence_text and new not in claim:
            idx = claim.index(v)
            return claim[:idx] + new + claim[idx + len(v):]
    return None


def status_match(claim: str) -> tuple[re.Match, str] | None:
    best = None
    for pat, repl in STATUS_PATTERNS:
        m = pat.search(claim)
        if m and (best is None or m.start() < best[0].start()):
            best = (m, repl)
    return best


def wrong_status(claim: str) -> str | None:
    hit = status_match(claim)
    if hit is None:
        return None
    m, repl = hit
    return claim[:m.start()] + repl + claim[m.end():]


def flipped_polarity(claim: str) -> str | None:
    if status_match(claim) is not None:  # status claims belong to wrong_status
        return None
    best = None
    for pat, repl in NEG_PATTERNS:
        m = pat.search(claim)
        if m and (best is None or m.start() < best[0].start()):
            best = (m, repl, pat)
    if best is not None:
        m, repl, pat = best
        return claim[:m.start()] + m.expand(repl) + claim[m.end():]
    m = INSERT_RE.search(claim)
    if m is None:
        return None
    return claim[:m.end()] + " not" + claim[m.end():]


def fake_id(existing_ids: list[str]) -> str:
    nums = [int(i[1:]) for i in existing_ids if re.fullmatch(r"[ch]\d{3}", i)]
    return f"c{(max(nums) if nums else 0) + 5:03d}"


def invented_id(claim: str, existing_ids: list[str]) -> str:
    fid = fake_id(existing_ids)
    for grp in CALL_CITE_RE.finditer(claim):
        inner = grp.group(1)
        m = CALL_ID_RE.search(inner)
        if m:
            start = grp.start(1) + m.start()
            return claim[:start] + fid + claim[start + 4:]
    stripped = claim.rstrip()
    if stripped.endswith("."):
        return stripped[:-1] + f" [{fid}]."
    return stripped + f" [{fid}]"


TYPES = ("wrong_version", "flipped_polarity", "wrong_status", "invented_id")


def perturb(kind: str, claim: str, *, evidence_text: str, existing_ids: list[str]) -> str | None:
    if kind == "wrong_version":
        return wrong_version(claim, evidence_text)
    if kind == "flipped_polarity":
        return flipped_polarity(claim)
    if kind == "wrong_status":
        return wrong_status(claim)
    if kind == "invented_id":
        return invented_id(claim, existing_ids)
    raise ValueError(kind)
