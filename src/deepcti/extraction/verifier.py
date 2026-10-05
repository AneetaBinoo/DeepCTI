"""Verified extraction (plan §5.3): accept an LLM-proposed atom only if

(a) the cited span occurs verbatim in the bound tool output,
(b) the span parses under the atom's grammar (a valid Debian version, a package name of the case),
(c) the derived atoms follow by a fixed function (version comparison against the case program),
(d) the tool's source class is bound to the proposed fact kind (BINDINGS).

Accepted facts inherit the trust class and independence group of the tool. Everything else is
returned as a rejected proposal (a hint), never as an observation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from debian.debian_support import Version

from ..env.host import ToolResult
from .parsers import BINDINGS, VersionFact, source_class

VERSION_RE = re.compile(r"(?<![\w.+~:-])((?:\d+:)?\d[A-Za-z0-9.+~-]*(?:-[A-Za-z0-9.+~]+)?)(?![\w.+~:-])")


@dataclass
class Proposal:
    kind: str  # "installed_version"
    package: str
    value: str
    span: str


@dataclass
class Verdict:
    proposal: Proposal
    accepted: bool
    reason: str
    fact: VersionFact | None = None

    def to_dict(self) -> dict:
        return {"kind": self.proposal.kind, "package": self.proposal.package, "value": self.proposal.value,
                "span": self.proposal.span[:200], "accepted": self.accepted, "reason": self.reason}


def verify(proposal: Proposal, result: ToolResult, case: dict) -> Verdict:
    if result.status != "ok":
        return Verdict(proposal, False, "tool call not ok")
    if proposal.kind != "installed_version":
        return Verdict(proposal, False, f"kind {proposal.kind!r} not verifiable")
    if "version" not in BINDINGS.get(source_class(result.source), set()):
        return Verdict(proposal, False, f"source {result.source.name} not bound to version facts")
    span = proposal.span
    if not span or span not in result.output:
        return Verdict(proposal, False, "span not found verbatim in tool output")
    # Grammar of the bound source: where in the output a version fact may come from.
    cls = source_class(result.source)
    if cls == "fs":
        path = str(result.args.get("path", "")).lstrip("/")
        if not re.fullmatch(r"usr/share/doc/[a-z0-9][a-z0-9+.-]*/changelog\.Debian", path):
            return Verdict(proposal, False, "fs version facts only from usr/share/doc/<pkg>/changelog.Debian")
        first_line = result.output.splitlines()[0] if result.output else ""
        if span not in first_line:
            return Verdict(proposal, False, "span not in the changelog header line")
    if cls == "proc":
        lines = [ln for ln in result.output.splitlines() if span in ln]
        if not any("started from package" in ln for ln in lines):
            return Verdict(proposal, False, "span not in a process start line")
    names = {case["src_package"], *case.get("binary_packages", [])}
    named = [n for n in names if re.search(rf"(?<![\w.+-]){re.escape(n)}(?![\w.+-])", span)]
    if not named:
        return Verdict(proposal, False, "span does not name the case component")
    value = proposal.value.strip()
    if value not in span:
        return Verdict(proposal, False, "version value not inside span")
    if value not in {m.group(1) for m in VERSION_RE.finditer(span)}:
        return Verdict(proposal, False, "value is not a complete version token in span")
    try:
        Version(value)
    except ValueError:
        return Verdict(proposal, False, "not a valid Debian version")
    if not re.search(r"\d", value):
        return Verdict(proposal, False, "not a valid Debian version")
    package = proposal.package if proposal.package in names else named[0]
    fact = VersionFact(result.source, value, package, result.t, result.h, result.call_id)
    return Verdict(proposal, True, "accepted", fact)
