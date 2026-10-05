"""Prompts and JSON schemas for E11 claim extraction, claim judging and status-consistency judging."""

from __future__ import annotations

import re

STATUS_SPEC = """VEX status labels:
- affected: a binary package built from the vulnerable source package is installed, its installed version is inside
  the vulnerable range for the release (fixed version not reached), and any advisory configuration precondition is met.
- fixed: installed and its version is at or above the distribution's fixed version (Debian version semantics,
  including backports whose upstream number looks old).
- not_affected: component_not_present (no binary package of the source package installed) / vulnerable_code_not_present
  (installed but this release/version is not affected) / requires_configuration (vulnerable feature disabled).
- under_investigation: evidence missing or contradictory; no safe decision."""

EXTRACT_SYSTEM = """You split an analyst note about a vulnerability assessment of one host into atomic factual claims.

Rules:
1. One claim = one checkable statement about the host, its packages, versions, services, configuration, the CVE's
   advisories/tracker/scanner results, or the host's vulnerability status.
2. Make each claim self-contained: replace pronouns and vague references with the named host/package/CVE from the note.
3. Copy names, numbers, versions and ids exactly as written. Do not add, infer, correct or omit facts.
4. If the sentence carries bracketed evidence ids (e.g. [c003], [pkgdb]), keep them at the end of every claim derived
   from that sentence and list them in "citations" (without brackets).
5. Include the note's overall conclusion about the host (e.g. "host X is not affected by CVE-Y") as a claim.
6. Skip statements only about the writing process or instructions ("no new facts were added", "the decision was given
   as ..."), recommendations or next steps, and generic definitions not about this host or CVE.
7. The EPISODE CONTEXT is only for resolving references (host name, CVE, package). Never extract claims from the
   context itself; every claim must come from the ANALYST NOTE.
8. At most 12 claims. If the note contains no factual claim, return an empty list."""

EXTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "claims": {
            "type": "array",
            "maxItems": 12,
            "items": {
                "type": "object",
                "properties": {"claim": {"type": "string"},
                               "citations": {"type": "array", "items": {"type": "string"}}},
                "required": ["claim", "citations"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["claims"],
    "additionalProperties": False,
}

JUDGE_SYSTEM = f"""You are a strict fact-checker for vulnerability-assessment notes. You receive the EPISODE CONTEXT, the
EVIDENCE (the exact tool outputs the assessing system observed, each labelled with its evidence id, tool, source and
status) and one CLAIM. Decide whether the evidence supports the claim.

Labels:
- supported: the claim is stated in the evidence or follows from it by direct reasoning (e.g. comparing an installed
  Debian package version with the fixed version from the tracker/advisory; "not installed" from a dpkg-query error;
  a status that follows from the evidence under the status definitions). Paraphrase is fine.
- contradicted: the evidence shows the claim is false (a different version, the opposite installation/service/config
  state, a different tracker status, a status that conflicts with the evidence under the status definitions).
- not_in_evidence: the evidence neither supports nor contradicts the claim (invented details, facts from general
  knowledge that are not in the outputs).

Citations: bracketed ids are part of the claim. An id like [c003] asserts that output c003 shows the fact; a name like
[pkgdb] asserts that an output from that source shows it. If a cited id/source does not exist in the evidence, the claim
is not_in_evidence. If the cited output does not show the fact, the claim is not supported (contradicted if the cited
output shows the opposite, otherwise not_in_evidence).
Use only the context and evidence, never your own knowledge about the CVE. Check every number, version, name, status
and negation in the claim.

{STATUS_SPEC}

Answer with JSON: {{"reasoning": "<at most two sentences>", "label": "supported" | "contradicted" | "not_in_evidence"}}."""

LABELS = ("supported", "contradicted", "not_in_evidence")
JUDGE_SCHEMA = {
    "type": "object",
    "properties": {"reasoning": {"type": "string", "maxLength": 600},
                   "label": {"type": "string", "enum": list(LABELS)}},
    "required": ["reasoning", "label"],
    "additionalProperties": False,
}

STATUS_SYSTEM = f"""You read an analyst note about whether one CVE affects one host and report which VEX status the note
asserts for the host. Use only the note.

{STATUS_SPEC}

Answer "none" if the note asserts no status or asserts conflicting statuses. Answer with JSON
{{"asserted_status": "affected" | "not_affected" | "fixed" | "under_investigation" | "none"}}."""

STATUS_CHOICES = ("affected", "not_affected", "fixed", "under_investigation", "none")
STATUS_SCHEMA = {
    "type": "object",
    "properties": {"asserted_status": {"type": "string", "enum": list(STATUS_CHOICES)}},
    "required": ["asserted_status"],
    "additionalProperties": False,
}


def extract_user(context: str, explanation: str) -> str:
    return f"EPISODE CONTEXT: {context}\n\nANALYST NOTE:\n{explanation}"


def judge_user(context: str, evidence: str, claim: str) -> str:
    # evidence first, claim last: maximises prefix-cache reuse across the claims of one episode
    return f"EPISODE CONTEXT: {context}\n\nEVIDENCE:\n{evidence}\n\nCLAIM: {claim}"


def status_user(context: str, explanation: str) -> str:
    return f"EPISODE CONTEXT: {context}\n\nANALYST NOTE:\n{explanation}"


CITE_RE = re.compile(r"\[([A-Za-z0-9_:\-, ]+)\]")
CALL_ID_RE = re.compile(r"\b([ch]\d{3})\b")


def call_ids_in(text: str) -> list[str]:
    """Evidence call ids (c001/h001) cited in bracketed groups of ``text``, in order, unique."""
    out: list[str] = []
    for grp in CITE_RE.findall(text or ""):
        for cid in CALL_ID_RE.findall(grp):
            if cid not in out:
                out.append(cid)
    return out
