"""OpenAI function schemas for the shared tool catalog (identical for every agentic system)."""

from __future__ import annotations


def _fn(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required},
        },
    }


S = {"type": "string"}

CATALOG = [
    _fn("pkg_query", "Query the host package database (dpkg). `name` may be a binary package name or a source "
        "package name; a source name returns all installed binaries built from it. Cost 1.",
        {"name": S}, ["name"]),
    _fn("file_read", "Read a file on the host. Allowed paths: etc/*, usr/share/doc/*, opt/*, srv/*, "
        "var/log/apt/*. Package changelogs are at usr/share/doc/<binary>/changelog.Debian. Cost 1.",
        {"path": S}, ["path"]),
    _fn("config_get", "Look up a configuration directive or module for a service (e.g. service='ssh', "
        "key='LoginGraceTime'). Cost 1.", {"service": S, "key": S}, ["service", "key"]),
    _fn("service_status", "systemd status of a service unit (or of the services of a package). Cost 1.",
        {"name": S}, ["name"]),
    _fn("cmdb_lookup", "Asset inventory (CMDB) record for the host. Cost 1.", {"asset": S}, ["asset"]),
    _fn("advisory_fetch", "Fetch advisory text for a CVE from a mirrored source: nvd, osv, kev or debian. Cost 1.",
        {"cve": S, "source": {"type": "string", "enum": ["nvd", "osv", "kev", "debian"]}}, ["cve", "source"]),
    _fn("vex_lookup", "Structured distribution security-tracker / VEX record for the CVE on this host's release "
        "(status, fixed version, configuration precondition). Cost 1.", {"cve": S, "product": S}, ["cve"]),
    _fn("run_scanner", "Run a vulnerability scanner on the host and return findings for the CVE. Cost 5.",
        {"tool": {"type": "string", "enum": ["trivy", "grype", "osv"]}}, ["tool"]),
    _fn("request_approval", "Query change management for an approved change, maintenance window and rollback "
        "for this host. Cost 3.", {"change": S}, ["change"]),
    _fn("apply_patch", "DISRUPTIVE. Upgrade a package to the distribution's fixed version. Cost 20.",
        {"pkg": S, "version": S}, ["pkg"]),
    _fn("restart_service", "DISRUPTIVE. Restart a service unit. Cost 15.", {"name": S}, ["name"]),
    _fn("disable_feature", "DISRUPTIVE. Apply the safe setting that disables a vulnerable feature. Cost 10.",
        {"service": S, "key": S}, ["service", "key"]),
]

SUBMIT = _fn(
    "submit_decision",
    "Submit your final VEX decision. Call exactly once, at the end.",
    {
        "status": {"type": "string", "enum": ["affected", "not_affected", "fixed", "under_investigation"]},
        "justification": {"type": "string", "enum": ["component_not_present", "vulnerable_code_not_present",
                                                     "requires_configuration", "none"]},
        "explanation": S,
    },
    ["status", "justification", "explanation"],
)

NOTES = _fn(
    "update_notes",
    "Replace your structured scratchpad (JSON object of facts you have established, with the call ids that "
    "support them). The scratchpad is shown to you at every step; old tool outputs are truncated.",
    {"notes": {"type": "object"}},
    ["notes"],
)

TOOL_NAMES = [t["function"]["name"] for t in CATALOG]
