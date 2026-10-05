"""Offline advisory digest + deterministic token sets for one CVE.

Built only from public advisory records (OSV CVE/GHSA/GO/PYSEC + GitHub Advisory
DB) pre-fetched by scripts/e7/fetch_advisories.py. References/URLs are dropped
so the per-repository fix PR (VEX-Bench metadata.pr_url) can never leak.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ADV_DIR = ROOT / "data/external/vex-bench-advisories"

ECOSYSTEM = {"go": "Go", "java": "Maven", "python": "PyPI"}

# PyPI distribution -> import name, for well-known mismatches (fixed table).
PY_IMPORT = {
    "pillow": "PIL", "pyyaml": "yaml", "scikit-learn": "sklearn", "beautifulsoup4": "bs4",
    "python-jose": "jose", "pycryptodome": "Crypto", "protobuf": "google.protobuf",
    "opencv-python": "cv2", "python-multipart": "multipart", "pyjwt": "jwt",
    "python-ldap": "ldap", "msgpack-python": "msgpack", "brotli": "brotli",
    "llama-index-core": "llama_index", "llama-index": "llama_index",
    "langchain-community": "langchain_community", "langchain-core": "langchain_core",
    "pyopenssl": "OpenSSL",
}

_STOP = {
    "The", "This", "These", "There", "When", "Before", "After", "Prior", "Users", "Versions",
    "GitHub", "JavaScript", "TypeScript", "PoC", "DoS", "NVD", "CVE", "CVSS", "HTTP", "HTTPS",
    "JSON", "XML", "YAML", "URL", "API", "Apache", "Note", "Impact", "Patches", "Workarounds",
    "References", "Description", "Summary", "Details", "Credits", "Java", "Python", "Golang",
    "True", "False", "None", "null", "true", "false", "PyPI", "ReDoS", "FasterXML",
}


def _ver_tuple(v: str) -> tuple[int, ...] | None:
    """Leading numeric tuple of a version string (qualifiers ignored)."""
    m = re.match(r"v?(\d+(?:\.\d+)*)", v.strip())
    if not m:
        return None
    t = tuple(int(x) for x in m.group(1).split("."))
    while len(t) > 1 and t[-1] == 0:
        t = t[:-1]
    return t


@dataclass
class PackageRange:
    name: str
    intervals: list[tuple[tuple[int, ...] | None, tuple[int, ...] | None, bool]]  # (introduced, fixed_or_last, last_inclusive)
    versions_text: str

    def contains(self, ver: str) -> bool | None:
        t = _ver_tuple(ver)
        if t is None or not self.intervals:
            return None
        for lo, hi, incl in self.intervals:
            if lo is not None and t < lo:
                continue
            if hi is None or t < hi or (incl and t == hi):
                return True
        return False


@dataclass
class Advisory:
    cve: str
    language: str
    summary: str
    details: str
    packages: list[PackageRange] = field(default_factory=list)
    go_imports: dict[str, list[str]] = field(default_factory=dict)  # import path -> symbols
    vulnerable_functions: list[str] = field(default_factory=list)
    text_identifiers: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)

    # ---- token sets used by the deterministic verifier ----
    @property
    def is_go_stdlib(self) -> bool:
        return any(p.name in ("stdlib", "toolchain") for p in self.packages)

    def package_tokens(self) -> list[str]:
        """Strings whose presence in a manifest/lockfile/vendored path evidences the dependency."""
        toks: set[str] = set()
        for p in self.packages:
            if p.name in ("stdlib", "toolchain"):
                continue
            if self.language == "java" and ":" in p.name:
                toks.add(p.name.split(":", 1)[1])  # artifactId
            elif self.language == "python":
                n = p.name.lower()
                toks |= {n, n.replace("-", "_"), n.replace("_", "-")}
            else:
                toks.add(p.name)
        return sorted(t for t in toks if len(t) >= 3)

    def import_tokens(self) -> list[str]:
        """Strings whose presence in first-party source evidences use of the package."""
        toks: set[str] = set()
        for p in self.packages:
            if self.language == "java" and ":" in p.name:
                g, a = p.name.split(":", 1)
                toks.add(g)
                if g.count(".") >= 3:
                    toks.add(".".join(g.split(".")[:3]))
            elif self.language == "python":
                n = p.name.lower()
                toks.add(PY_IMPORT.get(n, n.replace("-", "_")))
            elif p.name not in ("stdlib", "toolchain"):
                toks.add(p.name)
        toks |= set(self.go_imports)
        return sorted(t for t in toks if len(t) >= 2)

    def symbol_tokens(self) -> list[str]:
        """Names a symbol-atom snippet must contain (explicit advisory symbols if any,
        otherwise advisory-text identifiers + import tokens)."""
        explicit = set(self.vulnerable_functions)
        for syms in self.go_imports.values():
            explicit |= {s.split(".")[-1] for s in syms}
        if explicit:
            return sorted(explicit)
        return sorted(set(self.text_identifiers) | set(self.import_tokens()))

    def all_negative_check_tokens(self) -> list[str]:
        """Tokens searched (all must be absent) before a negative symbol claim is accepted."""
        toks = set(self.import_tokens()) | set(self.symbol_tokens())
        if self.go_imports:
            toks |= set(self.go_imports)
        return sorted(toks)

    def digest(self) -> str:
        lines = [f"ID: {self.cve}"]
        if self.summary:
            lines.append(f"Summary: {self.summary}")
        if self.cwes:
            lines.append("CWE: " + ", ".join(self.cwes))
        if self.packages:
            lines.append(f"Affected packages ({ECOSYSTEM[self.language]}):")
            for p in self.packages[:12]:
                lines.append(f"  - {p.name}: {p.versions_text}")
            if len(self.packages) > 12:
                lines.append(f"  - ... and {len(self.packages) - 12} more")
        if self.go_imports:
            lines.append("Affected Go import paths and symbols:")
            for path, syms in list(self.go_imports.items())[:10]:
                lines.append(f"  - {path}: {', '.join(syms[:20]) or '(whole package)'}")
        if self.vulnerable_functions:
            lines.append("Vulnerable functions: " + ", ".join(self.vulnerable_functions[:20]))
        d = re.sub(r"https?://\S+", "[link removed]", self.details or "")
        if len(d) > 3000:
            d = d[:3000] + " ...[truncated]"
        lines.append("Details:\n" + d)
        return "\n".join(lines)


def _identifiers(text: str) -> list[str]:
    ids: set[str] = set()
    for m in re.findall(r"`([^`\n]{3,60})`", text):
        for part in re.findall(r"[A-Za-z_][A-Za-z0-9_.]*[A-Za-z0-9_]", m):
            if len(part) >= 4:
                ids.add(part.split(".")[-1] if part.count(".") > 2 else part)
    ids |= {m for m in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*\(", text)
            if m[0].islower() or "_" in m or re.match(r"[A-Z][a-z0-9]+[A-Z]", m)}
    ids |= {m for m in re.findall(r"\b([A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+)\b", text)}
    ids |= {m for m in re.findall(r"\b([A-Za-z_]\w+\.[A-Za-z_]\w+)\b", text)
            if not re.search(r"\.(com|org|io|net|dev|html|md)$", m)}
    def specific(i: str) -> bool:  # drop plain English-like words ("version", "Session")
        return "." in i or "_" in i or any(c.isupper() for c in i[1:])
    return sorted(i for i in ids if i not in _STOP and not i.isdigit() and len(i) >= 4 and specific(i))


def load_advisory(cve: str, language: str) -> Advisory:
    rec = json.loads((ADV_DIR / f"{cve}.json").read_text())
    eco = ECOSYSTEM[language]
    gh = rec.get("github") or []
    osv_cve = rec.get("osv_cve") or {}
    aliases = rec.get("osv_aliases") or {}
    ghsa = next((v for k, v in aliases.items() if k.startswith("GHSA-") and "_error" not in v), {})
    summary = (gh[0].get("summary") if gh else None) or ghsa.get("summary") or osv_cve.get("summary") or ""
    details = (gh[0].get("description") if gh else None) or ghsa.get("details") or osv_cve.get("details") or ""
    cwes = sorted({c["cwe_id"] for g in gh for c in (g.get("cwes") or [])})

    pkgs: dict[str, PackageRange] = {}
    go_imports: dict[str, list[str]] = {}
    for aid, rec_a in aliases.items():
        if "_error" in rec_a:
            continue
        for aff in rec_a.get("affected", []) or []:
            pk = aff.get("package", {})
            if pk.get("ecosystem") != eco:
                continue
            name = pk.get("name", "")
            pr = pkgs.setdefault(name, PackageRange(name, [], ""))
            texts = []
            for rg in aff.get("ranges", []) or []:
                if rg.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                lo = None
                for ev in rg.get("events", []):
                    if "introduced" in ev:
                        lo = _ver_tuple(ev["introduced"])
                        lo_s = ev["introduced"]
                    elif "fixed" in ev:
                        pr.intervals.append((lo, _ver_tuple(ev["fixed"]), False))
                        texts.append(f">= {lo_s}, < {ev['fixed']}")
                        lo = None
                    elif "last_affected" in ev:
                        pr.intervals.append((lo, _ver_tuple(ev["last_affected"]), True))
                        texts.append(f">= {lo_s}, <= {ev['last_affected']}")
                        lo = None
                if lo is not None:
                    pr.intervals.append((lo, None, False))
                    texts.append(f">= {lo_s} (no fix)")
            if texts:
                pr.versions_text = "; ".join(sorted(set(pr.versions_text.split("; ") + texts) - {""}))
            for imp in (aff.get("ecosystem_specific") or {}).get("imports", []) or []:
                go_imports.setdefault(imp["path"], [])
                go_imports[imp["path"]] = sorted(set(go_imports[imp["path"]]) | set(imp.get("symbols", [])))
    # GitHub advisory DB ranges/functions as a fallback
    vf: set[str] = set()
    gh_eco = {"go": "go", "java": "maven", "python": "pip"}[language]
    for g in gh:
        for v in g.get("vulnerabilities") or []:
            if (v.get("package") or {}).get("ecosystem") != gh_eco:
                continue
            vf |= set(v.get("vulnerable_functions") or [])
            name = v["package"]["name"]
            if name not in pkgs:
                pkgs[name] = PackageRange(name, [], v.get("vulnerable_version_range") or "")
                for part in [(v.get("vulnerable_version_range") or "")]:
                    lo = hi = None
                    incl = False
                    for c in part.split(","):
                        c = c.strip()
                        if c.startswith(">="):
                            lo = _ver_tuple(c[2:])
                        elif c.startswith("<="):
                            hi, incl = _ver_tuple(c[2:]), True
                        elif c.startswith("<"):
                            hi = _ver_tuple(c[1:])
                        elif c.startswith("="):
                            lo = hi = _ver_tuple(c[1:])
                            incl = True
                    if lo or hi:
                        pkgs[name].intervals.append((lo, hi, incl))
    for p in pkgs.values():
        if not p.versions_text:
            p.versions_text = "(range unknown)"
    ident = _identifiers(summary + "\n" + details)
    return Advisory(cve=cve, language=language, summary=summary.strip(), details=details.strip(),
                    packages=list(pkgs.values()), go_imports=go_imports,
                    vulnerable_functions=sorted(vf), text_identifiers=ident, cwes=cwes)
