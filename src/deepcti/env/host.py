"""In-memory host model over a rootfs fixture and the shared tool catalog (plan §5.2).

Every system sees the same tools, costs and outputs. The environment never executes code from
the fixture. Disruptive tools mutate the in-memory copy only. A simulated clock advances by
each tool's cost; observations carry that clock as their collection time.
"""

from __future__ import annotations

import copy
import fnmatch
import json
import re
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import io
import yaml
import zipfile
from debian.deb822 import Deb822
from debian.debian_support import Version

from ..core import versions
from ..core.belnap import Source, content_hash
from ..policy.pdp import TOOL_TIERS

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_COSTS = {
    "pkg_query": 1,
    "file_read": 1,
    "config_get": 1,
    "service_status": 1,
    "cmdb_lookup": 1,
    "advisory_fetch": 1,
    "vex_lookup": 1,
    "run_scanner": 5,
    "request_approval": 3,
    "lang_pkg_query": 1,
    "list_dir": 1,
    "apply_patch": 20,
    "restart_service": 15,
    "disable_feature": 10,
}
SCANNERS = ("trivy", "grype", "osv")
ADVISORY_SOURCES = ("nvd", "osv", "kev", "debian", "vendor", "ubuntu")
FILE_ALLOW = ("etc/*", "usr/share/doc/*", "opt/*", "var/log/apt/*", "srv/*")
CONFIG_DEFAULTS = {
    "ssh": ["etc/ssh/sshd_config", "etc/ssh/sshd_config.d/*"],
    "sshd": ["etc/ssh/sshd_config", "etc/ssh/sshd_config.d/*"],
    "nginx": ["etc/nginx/nginx.conf", "etc/nginx/conf.d/*", "etc/nginx/sites-enabled/*"],
    "apache2": ["etc/apache2/apache2.conf", "etc/apache2/mods-enabled/*", "etc/apache2/sites-enabled/*"],
    "samba": ["etc/samba/smb.conf"],
    "smbd": ["etc/samba/smb.conf"],
    "bind9": ["etc/bind/named.conf", "etc/bind/named.conf.options", "etc/bind/named.conf.local"],
    "named": ["etc/bind/named.conf", "etc/bind/named.conf.options", "etc/bind/named.conf.local"],
    "exim4": ["etc/exim4/update-exim4.conf.conf", "etc/exim4/exim4.conf.template"],
    "postfix": ["etc/postfix/main.cf", "etc/postfix/master.cf"],
}


def load_yaml(path: Path, default: Any) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else default


def source_profiles() -> dict[str, dict]:
    """Trust classes estimated on dev (config/source_profiles.yaml, written by estimate_trust.py)."""
    data = load_yaml(ROOT / "config" / "source_profiles.yaml", {}) or {}
    return data.get("sources", {})


def tool_source(tool: str, args: dict, profiles: dict[str, dict] | None = None) -> Source:
    profiles = source_profiles() if profiles is None else profiles

    def trust(name: str, default: str) -> str:
        return str(profiles.get(name, {}).get("trust", default))

    if tool == "pkg_query":
        return Source("pkgdb", "T", "pkgdb")
    if tool == "lang_pkg_query":  # language package metadata (dist-info) vs. the artifact itself (jar)
        if args.get("ecosystem") == "maven":
            return Source("artifact", "T", "artifact")
        return Source("langdb", "T", "langdb")
    if tool == "list_dir":
        return Source("fs", "T", "fs")
    if tool in ("file_read", "config_get"):
        return Source("fs", "T", "fs")
    if tool == "service_status":
        return Source("proc", "T", "proc")
    if tool == "cmdb_lookup":
        return Source("cmdb", trust("cmdb", "U"), "cmdb")
    if tool == "run_scanner":
        name = f"scanner:{args.get('tool', '?')}"
        # Scanners read the same dpkg database: they share the pkgdb independence group.
        return Source(name, trust(name, "U"), "pkgdb")
    if tool == "advisory_fetch":
        name = f"advisory:{args.get('source', '?')}"
        return Source(name, "U", name)
    if tool == "vex_lookup":
        return Source("debian_tracker", "T", "debian_tracker")
    if tool == "request_approval":
        return Source("change", "T", "change")
    return Source(f"action:{tool}", "U", f"action:{tool}")


@dataclass
class ToolResult:
    tool: str
    args: dict
    status: str  # ok | denied | invalid | error
    output: str
    structured: Any
    source: Source
    cost: float
    t: float
    h: str
    call_id: str = ""

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "tool": self.tool,
            "args": self.args,
            "status": self.status,
            "output": self.output,
            "source": [self.source.name, self.source.trust, self.source.group],
            "cost": self.cost,
            "t": self.t,
            "h": self.h,
        }


# ----------------------------------------------------------------------------- fixture
def parse_dpkg_status(text: str) -> dict[str, dict[str, str]]:
    packages = {}
    for para in Deb822.iter_paragraphs(text.splitlines(keepends=True)):
        name = para.get("Package")
        if name:
            packages[name] = dict(para)
    return packages


def source_name(stanza: dict[str, str]) -> str:
    src = stanza.get("Source", stanza.get("Package", ""))
    return src.split(" ")[0].strip()


def stanza_text(stanza: dict[str, str]) -> str:
    order = ["Package", "Status", "Priority", "Section", "Installed-Size", "Maintainer", "Architecture",
             "Multi-Arch", "Source", "Version", "Depends", "Description"]
    keys = [k for k in order if k in stanza] + [k for k in stanza if k not in order]
    return "\n".join(f"{k}: {stanza[k]}" for k in keys)


def installed(stanza: dict[str, str]) -> bool:
    return stanza.get("Status", "").strip() == "install ok installed"


@dataclass
class Fixture:
    host_dir: Path
    host: dict
    packages: dict[str, dict[str, str]]
    files: dict[str, str]  # rootfs-relative path -> text (lazy-loaded allow-listed files)
    scans: dict[str, Any]
    lang: list[dict] = field(default_factory=list)  # language packages found in the rootfs (v3)
    binaries: list[str] = field(default_factory=list)  # allow-listed binary files (e.g. jars), listed only

    @classmethod
    def load(cls, host_dir: str | Path) -> Fixture:
        host_dir = Path(host_dir)
        host = json.loads((host_dir / "host.json").read_text(encoding="utf-8"))
        rootfs = host_dir / "rootfs"
        status = (rootfs / "var/lib/dpkg/status").read_text(encoding="utf-8", errors="replace")
        files: dict[str, str] = {}
        lang: list[dict] = []
        binaries: list[str] = []
        for path in rootfs.rglob("*"):
            if path.is_file():
                rel = path.relative_to(rootfs).as_posix()
                if rel.startswith("var/lib/dpkg/"):
                    continue
                if rel.startswith("opt/") and rel.endswith("/METADATA") and "/site-packages/" in rel \
                        and ".dist-info/" in rel:
                    lang.extend(_dist_info(path, rel))
                if rel.startswith("opt/") and rel.endswith("/_vendor/vendor.txt"):
                    lang.extend(_vendored(path, rel))
                if rel.endswith((".jar", ".war", ".ear")):
                    if rel.startswith("opt/"):
                        lang.extend(_jar_info(path, rel))
                    if any(fnmatch.fnmatch(rel, pat) for pat in FILE_ALLOW):
                        binaries.append(rel)
                    continue
                if any(fnmatch.fnmatch(rel, pat) for pat in FILE_ALLOW):
                    try:
                        files[rel] = path.read_text(encoding="utf-8", errors="replace")[:20000]
                    except OSError:
                        continue
        scans = {}
        for name in SCANNERS:
            p = host_dir / "scans" / f"{name}.json"
            if p.exists():
                try:
                    scans[name] = json.loads(p.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    scans[name] = None
        return cls(host_dir, host, parse_dpkg_status(status), files, scans, lang, sorted(binaries))


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _dist_info(path: Path, rel: str) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    meta = {}
    for line in text.splitlines():
        if not line.strip():
            break  # headers end at the first blank line
        if ":" in line:
            k, v = line.split(":", 1)
            meta.setdefault(k.strip(), v.strip())
    if "Name" not in meta or "Version" not in meta:
        return []
    return [{"ecosystem": "pypi", "name": meta["Name"], "version": meta["Version"],
             "path": rel.rsplit("/", 1)[0], "evidence": "dist-info METADATA"}]


def _vendored(path: Path, rel: str) -> list[dict]:
    """pip-vendored copies listed in _vendor/vendor.txt whose package directory really exists (as the labeller)."""
    out = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    for ln in lines:
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)==([^\s#;]+)", ln)
        if not m:
            continue
        mod = m.group(1).lower().replace("-", "_")
        if (path.parent / mod / "__init__.py").is_file():
            out.append({"ecosystem": "pypi", "name": m.group(1), "version": m.group(2),
                        "path": f"{rel.rsplit('/', 1)[0]}/{mod}", "evidence": "vendor.txt (vendored copy)"})
    return out


def _jar_info(path: Path, rel: str, data: bytes | None = None) -> list[dict]:
    out = []
    try:
        with zipfile.ZipFile(io.BytesIO(data) if data is not None else path) as zf:
            manifest = ""
            if "META-INF/MANIFEST.MF" in zf.namelist():
                manifest = zf.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
            impl = dict(re.findall(r"^(Implementation-(?:Title|Version|Vendor)):\s*(.+?)\s*$", manifest, re.M))
            for name in zf.namelist():
                if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
                    props = dict(re.findall(r"^\s*([A-Za-z]+)\s*=\s*(.+?)\s*$",
                                            zf.read(name).decode("utf-8", "replace"), re.M))
                    if props.get("artifactId") and props.get("version"):
                        out.append({"ecosystem": "maven", "group": props.get("groupId", ""),
                                    "name": props["artifactId"], "version": props["version"], "path": rel,
                                    "manifest_version": impl.get("Implementation-Version"),
                                    "evidence": f"{name}"})
            if data is None:  # jars nested in Spring Boot / WAR archives (one level, as the labeller)
                for name in zf.namelist():
                    if name.endswith(".jar") and name.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")):
                        out.extend(_jar_info(path, f"{rel}!/{name}", zf.read(name)))
    except (OSError, zipfile.BadZipFile, KeyError):
        return []
    return out


# ----------------------------------------------------------------------------- scanner filtering
def scanner_findings(name: str, report: Any, cve: str) -> list[dict]:
    """Normalise a raw scanner report to findings for one CVE."""
    out: list[dict] = []
    if not report:
        return out
    if name == "trivy":
        for res in report.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                if v.get("VulnerabilityID") == cve:
                    out.append({"package": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                                "fixed": v.get("FixedVersion"), "status": v.get("Status"),
                                "severity": v.get("Severity"), "title": v.get("Title", "")})
    elif name == "grype":
        for m in report.get("matches", []) or []:
            vuln = m.get("vulnerability", {})
            ids = {vuln.get("id")} | {r.get("id") for r in m.get("relatedVulnerabilities", []) or []}
            if cve in ids:
                art = m.get("artifact", {})
                fix = vuln.get("fix", {}) or {}
                out.append({"package": art.get("name"), "installed": art.get("version"),
                            "fixed": ",".join(fix.get("versions", []) or []), "status": fix.get("state"),
                            "severity": vuln.get("severity"), "title": vuln.get("description", "")[:300]})
    elif name == "osv":
        for res in report.get("results", []) or []:
            for pkg in res.get("packages", []) or []:
                for v in pkg.get("vulnerabilities", []) or []:
                    ids = {v.get("id")} | set(v.get("aliases", []) or []) | set(v.get("upstream", []) or [])
                    if cve in ids:
                        info = pkg.get("package", {})
                        out.append({"package": info.get("name"), "installed": info.get("version"),
                                    "fixed": "", "status": "", "severity": "",
                                    "title": (v.get("summary") or v.get("details") or "")[:300]})
    return out


# ----------------------------------------------------------------------------- environment
@dataclass
class Attack:
    """Adversarial modifications (D3). Carriers: untrusted text; compromised: trusted groups in M."""

    carriers: dict[str, str] = field(default_factory=dict)  # carrier -> injected text
    forged: dict[str, Any] = field(default_factory=dict)  # group -> forged payload
    goal: str = ""
    name: str = ""
    compromised_groups: list = field(default_factory=list)


class HostEnv:
    def __init__(
        self,
        case: dict,
        fixture: Fixture,
        cve_meta: dict,
        preconditions: dict[str, dict],
        advisories: dict[str, str],
        *,
        tracker_available: bool = True,
        scanners_available: bool = True,
        attack: Attack | None = None,
        drift: list[dict] | None = None,
        costs: dict[str, float] | None = None,
        profiles: dict[str, dict] | None = None,
    ):
        self.case = case
        self.fx = fixture
        self.meta = cve_meta
        self.pre = preconditions.get(case["cve"])
        self.advisories = advisories
        self.tracker_available = tracker_available
        self.scanners_available = scanners_available
        self.attack = attack or Attack()
        self.drift = sorted(drift or [], key=lambda d: d["at"])
        self.costs = dict(DEFAULT_COSTS, **(costs or {}))
        self.profiles = source_profiles() if profiles is None else profiles
        self.packages = copy.deepcopy(fixture.packages)
        self.files = dict(fixture.files)
        self.services = copy.deepcopy(fixture.host.get("services", {}))
        for svc in self.services.values():  # version loaded in memory at service start
            svc.setdefault("loaded_version", self._pkg_version(svc.get("package", "")))
        self.cmdb = copy.deepcopy(fixture.host.get("cmdb", {}))
        self.change = copy.deepcopy(fixture.host.get("change", {}))
        self.rollback = bool(fixture.host.get("rollback_available", False))
        self.clock = 0.0
        self.calls: list[ToolResult] = []
        self.actions: list[dict] = []
        self._n = 0
        # v3: non-Debian ecosystems (deb-debian keeps the exact v2 code paths)
        self.eco = case.get("ecosystem", "deb-debian")
        self.lang = copy.deepcopy(fixture.lang)
        self.apps = copy.deepcopy(fixture.host.get("apps", []))
        self.binaries = list(fixture.binaries)
        for svc in self.services.values():
            if svc.get("loaded_version") is None and svc.get("component"):
                svc["loaded_version"] = svc.get("version")

    # ---------------------------------------------------------------- ecosystems (v3)
    def is_deb(self) -> bool:
        return self.eco in ("deb-debian", "deb-ubuntu")

    def names(self) -> set[str]:
        c = self.case
        out = {c["src_package"], *c.get("binary_packages", []), *c.get("aliases", [])}
        comp = c.get("component")
        if comp:
            out |= {comp, comp.split(":")[-1]}
        return {n for n in out if n}

    def tracker_entry(self) -> dict:
        """Distribution tracker entry in Debian semantics (status, fixed_version; '0' = not affected)."""
        release = self.case["release"]
        if self.eco == "deb-ubuntu":
            e = (self.meta.get("ubuntu") or {}).get(release) or {}
            st = str(e.get("status", "")).lower()
            if st == "released" and e.get("fixed_version"):
                return {"status": "resolved", "fixed_version": e["fixed_version"], "raw_status": st}
            if st in ("not-affected", "dne"):
                return {"status": "resolved", "fixed_version": "0", "raw_status": st}
            if st:
                return {"status": "open", "fixed_version": None, "raw_status": st}
            return {}
        return (self.meta.get("debian") or {}).get(release) or {}

    def ranges(self) -> list[dict]:
        return list(self.meta.get("ranges") or [])

    def instances(self) -> list[dict]:
        """Installed instances of a non-deb component: {version, path}."""
        comp = self.case.get("component") or self.case["src_package"]
        if self.eco == "pypi":
            return [e for e in self.lang if e["ecosystem"] == "pypi" and pep503(e["name"]) == pep503(comp)]
        if self.eco == "maven":
            g, _, a = comp.rpartition(":")
            return [e for e in self.lang if e["ecosystem"] == "maven" and e["name"] == a and (not g or e["group"] == g)]
        names = {n.lower() for n in self.names()}
        return [a for a in self.apps if str(a.get("component", "")).lower() in names and a.get("version")]

    def running_versions(self) -> list[str]:
        names = {n.lower() for n in self.names()}
        out = []
        for key, svc in self.services.items():
            owner = str(svc.get("component") or svc.get("package") or key or "").lower()
            if owner in names and svc.get("loaded_version") and svc.get("active", True):
                out.append(str(svc["loaded_version"]))
        return out

    def set_instance_version(self, inst: dict, new: str) -> None:
        """Change a non-deb instance's version AND the evidence that shows it (paths, version files)."""
        old = str(inst["version"])
        if old == new:
            return
        inst["version"] = new
        base = str(inst.get("path", "")).split("!/")[0]
        if self.eco == "vendor":  # rewrite version strings in the product's text files
            for p in [p for p in self.files if base and p.startswith(base.rstrip("/") + "/")]:
                if p.endswith("ap_release.h"):  # httpd splits its version over three #defines
                    parts = (new.split(".") + ["0", "0"])[:3]
                    for name, val in zip(("MAJORVERSION", "MINORVERSION", "PATCHLEVEL"), parts):
                        self.files[p] = re.sub(rf"(#define\s+AP_SERVER_{name}_NUMBER\s+)\d+", rf"\g<1>{val}",
                                               self.files[p])
                    continue
                if old in self.files[p]:  # whole version tokens only (9.0.1 must not hit 9.0.10)
                    self.files[p] = re.sub(rf"(?<![\w.]){re.escape(old)}(?![\w]|\.\d)", new, self.files[p])
        elif self.eco == "pypi":  # rename the dist-info directory (and its files) and rewrite Version: / vendor.txt
            for p in [p for p in self.files if base and p.startswith(base)]:
                text = self.files.pop(p)
                if p.endswith("/METADATA"):
                    text = re.sub(rf"(?m)^Version:\s*{re.escape(old)}\s*$", f"Version: {new}", text)
                self.files[p.replace(f"-{old}.dist-info", f"-{new}.dist-info")] = text
            inst["path"] = base.replace(f"-{old}.dist-info", f"-{new}.dist-info")
            vt = base.rsplit("/", 1)[0] + "/vendor.txt" if "/_vendor/" in base else None
            if vt and vt in self.files:
                self.files[vt] = re.sub(rf"(?mi)^({re.escape(inst['name'])})=={re.escape(old)}\b", rf"\1=={new}",
                                        self.files[vt])
        elif self.eco == "maven":  # the jar file name and its manifest carry the version
            if inst.get("manifest_version") == old:
                inst["manifest_version"] = new
            jar = base
            full = str(inst.get("path", ""))
            if "!/" in full:  # nested jar: rename the inner entry
                outer, inner = full.split("!/", 1)
                if inner.endswith(f"-{old}.jar"):
                    inst["path"] = f"{outer}!/{inner[: -len(f'-{old}.jar')]}-{new}.jar"
            elif jar.endswith(f"-{old}.jar"):
                new_jar = jar[: -len(f"-{old}.jar")] + f"-{new}.jar"
                self.binaries = [new_jar if b == jar else b for b in self.binaries]
                inst["path"] = new_jar

    def _restart_non_deb(self, svc: dict, new: str) -> None:
        """Restart a non-deb service: the process now runs the on-disk version and prints it in its banner."""
        old = str(svc.get("loaded_version") or svc.get("version") or "")
        if svc.get("banner") and old and old != new:
            svc["banner"] = re.sub(rf"(?<![\w.]){re.escape(old)}(?![\w]|\.\d)", new, svc["banner"])
        svc["loaded_version"] = new
        svc["version"] = new
        svc["active"] = True

    def non_deb_target(self, current: str) -> str | None:
        for r in self.ranges():
            lo, hi = r.get("introduced"), r.get("fixed")
            if hi and (lo in (None, "", "0") or versions.compare(self.eco, current, lo) >= 0) and \
                    versions.compare(self.eco, current, hi) < 0:
                return str(hi)
        return None

    # ---------------------------------------------------------------- helpers
    def _pkg_version(self, name: str) -> str | None:
        st = self.packages.get(name)
        return st.get("Version") if st and installed(st) else None

    def src_binaries(self, src: str) -> list[str]:
        return sorted(n for n, st in self.packages.items() if installed(st) and source_name(st) == src)

    def asset(self) -> str:
        return self.fx.host.get("hostname") or self.case["host_id"]

    def tick(self, cost: float) -> None:
        self.clock += cost
        while self.drift and self.drift[0]["at"] <= self.clock:
            self.apply_drift(self.drift.pop(0))

    def apply_drift(self, event: dict) -> None:
        kind = event["kind"]
        if not self.is_deb() and kind in ("upgrade", "downgrade", "restart", "remove"):
            if kind in ("upgrade", "downgrade"):  # on-disk instances change; running processes keep their version
                for inst in self.instances():
                    self.set_instance_version(inst, str(event["version"]))
            elif kind == "restart":
                insts = self.instances()
                for key, svc in self.services.items():
                    owner = str(svc.get("component") or svc.get("package") or key or "").lower()
                    if insts and owner in {n.lower() for n in self.names()}:
                        self._restart_non_deb(svc, str(insts[0]["version"]))
            else:
                drop = {id(i) for i in self.instances()}
                self.lang = [e for e in self.lang if id(e) not in drop]
                self.apps = [a for a in self.apps if id(a) not in drop]
                for key, svc in self.services.items():
                    if str(svc.get("component") or svc.get("package") or key).lower() in {n.lower() for n in self.names()}:
                        svc["active"] = False
            self.actions.append({"t": self.clock, "drift": event})
            return
        if kind == "upgrade" or kind == "downgrade":  # package upgraded on disk; running services keep the old binary
            for name in self.src_binaries(event["src"]):
                self.packages[name]["Version"] = event["version"]
            self._changelog_refresh(event["src"])
        elif kind == "remove":
            for name in self.src_binaries(event["src"]):
                self.packages[name]["Status"] = "deinstall ok config-files"
                self.files.pop(f"usr/share/doc/{name}/changelog.Debian", None)
            for svc in self.services.values():
                if self.packages.get(svc.get("package", ""), {}).get("Status") != "install ok installed":
                    svc["active"] = False
                    svc["loaded_version"] = None
        elif kind == "restart":
            for svc in self.services.values():
                if svc.get("package") in self.src_binaries(event["src"]):
                    svc["loaded_version"] = self._pkg_version(svc["package"])
                    svc["active"] = svc["loaded_version"] is not None
        elif kind == "config":
            self.files[event["file"]] = event["text"]
        elif kind == "service_stop":
            for svc in self.services.values():
                if svc.get("package") in event.get("packages", []):
                    svc["active"] = False
        self.actions.append({"t": self.clock, "drift": event})

    def _changelog_refresh(self, src: str) -> None:
        for name in self.src_binaries(src):
            path = f"usr/share/doc/{name}/changelog.Debian"
            version = self.packages[name]["Version"]
            dist = f"{self.case['release']}-security"
            self.files[path] = (
                f"{src} ({version}) {dist}; urgency=medium\n\n  * Security update.\n\n"
                f" -- Debian Security Team <team@security.debian.org>\n"
            )

    def run_history(self, calls: list[tuple[str, dict]], at: float = -30.0) -> list[ToolResult]:
        """Evidence from a previous assessment (collected at clock ``at`` on the pre-drift host), then apply
        every drift event scheduled at t <= 0. History calls cost nothing in this episode."""
        self.clock = at
        history = []
        for tool, args in calls:
            r = self.call(tool, args)
            r.call_id = "h" + r.call_id[1:]
            history.append(r)
        self.calls = []
        self.clock = 0.0
        self.tick(0.0)
        return history

    # ---------------------------------------------------------------- dispatch
    def call(self, tool: str, args: dict) -> ToolResult:
        self._n += 1
        cost = float(self.costs.get(tool, 1))
        source = tool_source(tool, args, self.profiles)
        fn: Callable[[dict], tuple[str, str, Any]] | None = getattr(self, f"_t_{tool}", None)
        if fn is None or tool not in TOOL_TIERS:
            status, output, structured = "invalid", f"unknown tool {tool}", None
        else:
            try:
                status, output, structured = fn(dict(args or {}))
            except (KeyError, TypeError, ValueError) as exc:
                status, output, structured = "invalid", f"invalid arguments: {exc}", None
        self.tick(cost)
        result = ToolResult(tool, dict(args or {}), status, output, structured, source, cost, self.clock,
                            content_hash(output), call_id=f"c{self._n:03d}")
        self.calls.append(result)
        return result

    def denied(self, tool: str, args: dict, reason: str) -> ToolResult:
        self._n += 1
        source = tool_source(tool, args, self.profiles)
        result = ToolResult(tool, dict(args or {}), "denied", f"DENIED by policy: {reason}", None, source,
                            0.0, self.clock, content_hash(reason), call_id=f"c{self._n:03d}")
        self.calls.append(result)
        return result

    def args_ok(self, tool: str, args: dict) -> bool:
        """Argument-only validation (P1): well-formed arguments for a known tool."""
        try:
            if tool == "file_read":
                path = str(args["path"]).lstrip("/")
                return ".." not in path and any(fnmatch.fnmatch(path, p) for p in FILE_ALLOW)
            if tool == "apply_patch":
                name = str(args["pkg"])
                return bool(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name))
            if tool in ("restart_service", "service_status"):
                return bool(re.fullmatch(r"[A-Za-z0-9@_.-]+", str(args["name"])))
            if tool == "disable_feature":
                return bool(args.get("service")) and bool(args.get("key"))
            if tool == "run_scanner":
                return args.get("tool") in SCANNERS
            if tool == "lang_pkg_query":
                return args.get("ecosystem") in ("pypi", "maven") and bool(str(args.get("name", "")).strip())
            if tool == "list_dir":
                path = str(args["path"]).strip().strip("/")
                return ".." not in path and (path in ("opt", "srv", "etc", "usr/share/doc", "var/log/apt")
                                             or any(fnmatch.fnmatch(path, p) for p in FILE_ALLOW))
            if tool == "advisory_fetch":
                return args.get("source") in ADVISORY_SOURCES
            return tool in TOOL_TIERS
        except (KeyError, TypeError):
            return False

    def args_in_scope(self, tool: str, args: dict) -> bool:
        """Disruptive call targets the case's component (used by evidence-gated policies)."""
        src = self.case["src_package"]
        if tool == "apply_patch" and not self.is_deb():
            return str(args.get("pkg", "")) in self.names()
        if tool == "apply_patch":
            name = str(args.get("pkg", ""))
            return name == src or name in self.src_binaries(src) or name in self.case.get("binary_packages", [])
        if tool == "restart_service":
            return any(
                svc.get("package") in self.src_binaries(src) and str(args.get("name")) in (key, svc.get("unit"))
                for key, svc in self.services.items()
            )
        if tool == "disable_feature":
            return self.pre is not None and str(args.get("key")) == str(self.pre.get("key"))
        return True

    # ---------------------------------------------------------------- R0 tools
    def _forged(self, group: str) -> Any:
        return self.attack.forged.get(group)

    def _t_pkg_query(self, args: dict) -> tuple[str, str, Any]:
        name = str(args["name"]).strip()
        forged = self._forged("pkgdb")
        packages = self.packages
        if forged and forged.get("src") == self.case["src_package"]:
            packages = copy.deepcopy(self.packages)
            for stanza in forged["stanzas"]:
                packages[stanza["Package"]] = stanza
        hits = [st for n, st in sorted(packages.items()) if installed(st) and (n == name or source_name(st) == name)]
        if not hits:
            return "ok", f"dpkg-query: package '{name}' is not installed and no information is available", {
                "query": name, "installed": []}
        text = "\n\n".join(stanza_text(st) for st in hits)
        return "ok", text, {"query": name, "installed": [
            {"package": st["Package"], "source": source_name(st), "version": st.get("Version")} for st in hits]}

    def _t_file_read(self, args: dict) -> tuple[str, str, Any]:
        path = str(args["path"]).lstrip("/")
        if not self.args_ok("file_read", {"path": path}):
            return "invalid", f"path not allow-listed: {path}", None
        carrier = self.attack.carriers.get(f"file:{path}")
        if carrier and path not in self.files and path.endswith("/changelog.Debian"):
            carrier = None  # untrusted text may only be appended to existing changelogs, never become a header
        if path in self.files or carrier:
            text = self.files.get(path, "")
            forged = self._forged("fs")
            if forged and path.endswith("/changelog.Debian") and text:
                lines = text.splitlines()
                lines[0] = re.sub(r"\(([^)]*)\)", f"({forged['version']})", lines[0], count=1)
                text = "\n".join(lines) + "\n"
            if carrier:
                text = (text + "\n" + carrier) if text else carrier
            return "ok", text[:8000], {"path": path}
        listing = sorted(p for p in self.files if p.startswith(path.rstrip("/") + "/"))
        if listing:
            return "ok", "directory listing:\n" + "\n".join(listing[:200]), {"path": path, "listing": True}
        return "ok", f"cat: /{path}: No such file or directory", {"path": path, "missing": True}

    def _config_files(self, service: str) -> list[str]:
        patterns = list(CONFIG_DEFAULTS.get(service, []))
        for svc_key, svc in self.services.items():
            if service in (svc_key, svc.get("unit"), svc.get("unit", "").removesuffix(".service")):
                patterns += svc.get("config_files", [])
        if self.pre and service in (self.pre.get("service"), self.case["src_package"], None):
            patterns.append(self.pre["file"])
            patterns.append(self.pre["file"].rstrip("/") + "/*")
        return sorted({p for pat in patterns for p in self.files if fnmatch.fnmatch(p, pat)})

    def _t_config_get(self, args: dict) -> tuple[str, str, Any]:
        service, key = str(args["service"]), str(args["key"])
        files = self._config_files(service)
        if not files:
            return "ok", f"no configuration files found for service '{service}'", {
                "service": service, "key": key, "files": [], "matches": []}
        matches = []
        for path in files:
            if key.lower() in path.rsplit("/", 1)[-1].lower():
                matches.append({"file": path, "line": 0, "text": f"<file {path} exists>"})
            for i, line in enumerate(self.files[path].splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped[0] in "#;":
                    continue
                if re.match(rf"^{re.escape(key)}(\s|=|$)", stripped, flags=re.IGNORECASE):
                    matches.append({"file": path, "line": i, "text": stripped})
        pred = (self.pre or {}).get("predicate") or {}
        if self.pre and pred.get("kind") == "regex_present" and key == str(self.pre.get("key")):
            path = self.pre["file"]
            body = regex_text(self.files.get(path, ""))
            hits = [m.group(0) for m in re.finditer(str(pred["pattern"]), body, re.M)]
            matches = [{"file": path, "line": -1, "text": h, "regex": True} for h in hits]
            text = (f"{path}: active (non-comment) matches for {key}:\n" + "\n".join(hits)) if hits else \
                f"{path}: no active (non-comment) {key} found"
            return "ok", text, {"service": service, "key": key, "files": [path] if path in self.files else [],
                                "matches": matches, "regex": True}
        if not matches:
            text = f"'{key}' is not set in: " + ", ".join(files)
        else:
            text = "\n".join(f"{m['file']}:{m['line']}: {m['text']}" for m in matches)
        return "ok", text, {"service": service, "key": key, "files": files, "matches": matches}

    def _t_service_status(self, args: dict) -> tuple[str, str, Any]:
        name = str(args["name"])
        forged = self._forged("proc")
        units = []
        for key, svc in sorted(self.services.items()):
            unit = svc.get("unit", f"{key}.service")
            if name in (key, unit, unit.removesuffix(".service"), svc.get("package"), svc.get("component")) or (
                self.packages.get(svc.get("package", ""), {}) and name == source_name(self.packages[svc["package"]])
            ):
                units.append((key, svc, unit))
        if not units:
            return "ok", f"Unit {name}.service could not be found.", {"name": name, "units": []}
        blocks = []
        for key, svc, unit in units:
            loaded = svc.get("loaded_version")
            if forged and forged.get("unit") == unit:
                loaded = forged["version"]
            active = "active (running)" if svc.get("active", True) and loaded else "inactive (dead)"
            pid = 700 + (zlib.crc32(unit.encode()) % 300)
            lines = [
                f"● {unit} - {key} service",
                f"     Loaded: loaded (/lib/systemd/system/{unit}; enabled; preset: enabled)",
                f"     Active: {active}",
            ]
            running = bool(svc.get("active", True) and loaded)
            if running and svc.get("banner"):  # v3 services also print their own banner
                lines += [f"   Main PID: {pid} ({key})"]
                if svc.get("package"):  # distribution package: the package-level start line comes first
                    lines.append(f"{self.asset()} {key}[{pid}]: started from package {svc.get('package')} "
                                 f"(binary build {loaded})")
                lines.append(f"{self.asset()} {key}[{pid}]: server banner: {svc['banner']}")
            elif running:
                lines += [
                    f"   Main PID: {pid} ({key})",
                    f"{self.asset()} {key}[{pid}]: started from package {svc.get('package')} "
                    f"(binary build {loaded})",
                ]
            blocks.append("\n".join(lines))
        return "ok", "\n\n".join(blocks), {"name": name, "units": [u for _, _, u in units]}

    def _t_cmdb_lookup(self, args: dict) -> tuple[str, str, Any]:
        record = copy.deepcopy(self.cmdb)
        if "cmdb_notes" in self.attack.carriers:
            record["notes"] = (record.get("notes", "") + " " + self.attack.carriers["cmdb_notes"]).strip()
        forged = self._forged("cmdb")
        if forged:
            record["software"] = forged["software"]
        return "ok", json.dumps(record, indent=1, sort_keys=True), record

    def _t_advisory_fetch(self, args: dict) -> tuple[str, str, Any]:
        cve, src = str(args.get("cve", self.case["cve"])), str(args["source"])
        if src not in ADVISORY_SOURCES:
            return "invalid", f"unknown advisory source {src}", None
        if src in ("debian", "ubuntu", "osv") and not self.tracker_available:
            return "ok", f"advisory source '{src}' is not available for this asset (no distribution feed)", None
        if cve != self.case["cve"]:
            return "ok", f"no mirrored advisory for {cve}", None
        text = self.advisories.get(src, f"no {src} advisory mirrored for {cve}")
        carrier = self.attack.carriers.get(f"advisory:{src}")
        if carrier:
            text = text + "\n\n" + carrier
        return "ok", text[:8000], {"cve": cve, "source": src}

    def _t_vex_lookup(self, args: dict) -> tuple[str, str, Any]:
        cve = str(args.get("cve", self.case["cve"]))
        if not self.tracker_available:
            return "ok", "vex_lookup: no structured VEX/tracker feed is available for this product", None
        if cve != self.case["cve"]:
            return "ok", f"vex_lookup: no record for {cve}", None
        release = self.case["release"]
        if self.eco == "deb-ubuntu":
            entry = self.tracker_entry()
            record = {"cve": cve, "ecosystem": self.eco, "source_package": self.case["src_package"],
                      "release": release, "status": entry.get("status", "not-listed"),
                      "ubuntu_status": entry.get("raw_status"), "fixed_version": entry.get("fixed_version"),
                      "config_precondition": None}
        elif not self.is_deb():
            record = {"cve": cve, "ecosystem": self.eco, "component": self.case.get("component"),
                      "status": "ranges" if self.ranges() else "not-listed", "affected_ranges": self.ranges(),
                      "fixed_version": None, "config_precondition": None}
        else:
            entry = (self.meta.get("debian") or {}).get(release)
            record = {
                "cve": cve,
                "source_package": self.meta.get("src_package", self.case["src_package"]),
                "release": release,
                "status": entry.get("status") if entry else "not-listed",
                "fixed_version": entry.get("fixed_version") if entry else None,
                "urgency": entry.get("urgency") if entry else None,
                "config_precondition": None,
            }
        if self.pre:
            record["config_precondition"] = {
                "service": self.pre.get("service"),
                "file": self.pre.get("file"),
                "key": self.pre.get("key"),
                "predicate": self.pre.get("predicate"),
                "safe_setting": self.pre.get("safe_setting"),
            }
            if self.pre.get("applies_to_versions"):
                record["config_precondition"]["applies_to_versions"] = self.pre["applies_to_versions"]
        return "ok", json.dumps(record, indent=1, sort_keys=True), record

    def _t_lang_pkg_query(self, args: dict) -> tuple[str, str, Any]:
        eco, name = str(args["ecosystem"]), str(args["name"]).strip()
        if eco not in ("pypi", "maven"):
            return "invalid", f"unsupported ecosystem {eco}", None
        if eco == "pypi":
            hits = [e for e in self.lang if e["ecosystem"] == "pypi" and pep503(e["name"]) == pep503(name)]
            text = "\n---\n".join(f"Name: {e['name']}\nVersion: {e['version']}\nLocation: /{e['path']}" for e in hits)
            if not hits:
                text = f"WARNING: Package(s) not found: {name}"
        else:
            g, _, a = name.rpartition(":")
            hits = [e for e in self.lang if e["ecosystem"] == "maven" and e["name"] == a and (not g or e["group"] == g)]
            text = "\n".join(f"/{e['path']}: groupId={e['group']} artifactId={e['name']} version={e['version']}"
                             + (f" (Implementation-Version: {e['manifest_version']})" if e.get("manifest_version")
                                else "") for e in hits)
            if not hits:
                text = f"no Maven artifact matching '{name}' found in any jar on this host"
        structured = {"ecosystem": eco, "query": name,
                      "installed": [{"name": e["name"], "version": e["version"], "path": e["path"]} for e in hits]}
        return "ok", text, structured

    def _t_list_dir(self, args: dict) -> tuple[str, str, Any]:
        path = str(args["path"]).strip().strip("/")
        if not self.args_ok("list_dir", {"path": path}):
            return "invalid", f"path not allow-listed: {path}", None
        prefix = path + "/"
        entries = set()
        for p in list(self.files) + list(self.binaries):
            if p.startswith(prefix):
                rest = p[len(prefix):]
                entries.add(rest.split("/", 1)[0] + ("/" if "/" in rest else ""))
        if not entries:
            return "ok", f"ls: cannot access '/{path}': No such file or directory", {"path": path, "entries": []}
        listing = sorted(entries)[:300]
        return "ok", "\n".join(listing), {"path": path, "entries": listing}

    # ---------------------------------------------------------------- R1 tools
    def _t_run_scanner(self, args: dict) -> tuple[str, str, Any]:
        name = str(args["tool"])
        if name not in SCANNERS:
            return "invalid", f"unknown scanner {name}", None
        if not self.scanners_available:
            return "error", f"{name}: no scanner coverage for this asset", None
        if name not in self.fx.scans or self.fx.scans[name] is None:
            return "error", f"{name}: scan report unavailable for this host", None
        forged = self._forged(f"scanner:{name}")
        findings = forged["findings"] if forged else scanner_findings(name, self.fx.scans[name], self.case["cve"])
        if "scanner_note" in self.attack.carriers:
            for f in findings:
                f["title"] = (f.get("title", "") + " " + self.attack.carriers["scanner_note"]).strip()
            if not findings:
                findings = []
        body = {"scanner": name, "target": self.asset(), "cve": self.case["cve"], "findings": findings}
        if "scanner_note" in self.attack.carriers and not findings:
            body["note"] = self.attack.carriers["scanner_note"]
        return "ok", json.dumps(body, indent=1), body

    def _t_request_approval(self, args: dict) -> tuple[str, str, Any]:
        forged = self._forged("change")
        ticket = forged if forged else self.change.get("ticket")
        if not ticket:
            body = {"asset": self.asset(), "ticket": None, "approved": False,
                    "rollback_available": self.rollback, "maintenance_window_open": False,
                    "message": "no approved change ticket covers this asset"}
        else:
            body = {"asset": self.asset(), "ticket": ticket.get("id"), "approved": bool(ticket.get("approved")),
                    "rollback_available": self.rollback,
                    "maintenance_window_open": bool(ticket.get("window_open")),
                    "requested_change": str(args.get("change", ""))[:200]}
        return "ok", json.dumps(body, indent=1, sort_keys=True), body

    # ---------------------------------------------------------------- R2 tools
    def fixed_version(self) -> str | None:
        if not self.is_deb():
            insts = self.instances()
            return self.non_deb_target(insts[0]["version"]) if insts else None
        entry = self.tracker_entry() if self.eco == "deb-ubuntu" else \
            (self.meta.get("debian") or {}).get(self.case["release"]) or {}
        fv = entry.get("fixed_version")
        return None if fv in (None, "", "0") else str(fv)

    def _t_apply_patch(self, args: dict) -> tuple[str, str, Any]:
        name = str(args["pkg"])
        if not self.is_deb():
            if name not in self.names():
                self.actions.append({"t": self.clock, "action": "apply_patch", "pkg": name, "changed": False})
                return "ok", f"{name}: no pending security update in this scenario; nothing changed.", \
                    {"changed": False}
            changed = []
            for inst in self.instances():
                target = self.non_deb_target(inst["version"])
                if target:
                    changed.append((inst.get("path"), inst["version"], target))
                    self.set_instance_version(inst, target)
            self.actions.append({"t": self.clock, "action": "apply_patch", "pkg": name, "changed": bool(changed),
                                 "detail": changed})
            if not changed:
                return "ok", f"{name}: already at a non-vulnerable version.", {"changed": False}
            return "ok", "Upgraded " + ", ".join(f"/{p}: {a} -> {b}" for p, a, b in changed), {"changed": True}
        src = name if self.src_binaries(name) else source_name(self.packages.get(name, {"Package": name}))
        binaries = self.src_binaries(src)
        if not binaries:
            return "error", f"E: Package '{name}' is not installed", None
        if src != self.case["src_package"]:
            self.actions.append({"t": self.clock, "action": "apply_patch", "pkg": name, "changed": False})
            return "ok", f"{name}: no pending security update in this scenario; nothing changed.", {"changed": False}
        target = self.fixed_version()
        current = min((self.packages[b]["Version"] for b in binaries), key=Version)
        if target is None or Version(current) >= Version(target):
            self.actions.append({"t": self.clock, "action": "apply_patch", "pkg": name, "changed": False})
            return "ok", f"{src} is already the newest version ({current}).", {"changed": False}
        for b in binaries:
            if Version(self.packages[b]["Version"]) < Version(target):
                self.packages[b]["Version"] = target
        self._changelog_refresh(src)
        self.actions.append({"t": self.clock, "action": "apply_patch", "pkg": name, "changed": True,
                             "from": current, "to": target})
        return "ok", f"Upgraded {', '.join(binaries)} from {current} to {target}.", {"changed": True, "to": target}

    def _t_restart_service(self, args: dict) -> tuple[str, str, Any]:
        name = str(args["name"])
        for key, svc in self.services.items():
            unit = svc.get("unit", f"{key}.service")
            if name in (key, unit, unit.removesuffix(".service")):
                if not self.is_deb():
                    insts = self.instances()
                    if insts:
                        self._restart_non_deb(svc, str(insts[0]["version"]))
                    self.actions.append({"t": self.clock, "action": "restart_service", "unit": unit})
                    return "ok", f"Restarted {unit}.", {"unit": unit}
                svc["loaded_version"] = self._pkg_version(svc.get("package", ""))
                svc["active"] = svc["loaded_version"] is not None
                self.actions.append({"t": self.clock, "action": "restart_service", "unit": unit})
                return "ok", f"Restarted {unit}.", {"unit": unit}
        return "error", f"Failed to restart {name}.service: Unit not found.", None

    def _t_disable_feature(self, args: dict) -> tuple[str, str, Any]:
        service, key = str(args["service"]), str(args["key"])
        if not self.pre or key != self.pre.get("key"):
            self.actions.append({"t": self.clock, "action": "disable_feature", "key": key, "changed": False})
            return "error", f"no managed setting '{key}' for {service}", None
        path = self.pre["file"]
        safe = str(self.pre.get("safe_setting", ""))
        pred = (self.pre.get("predicate") or {}).get("kind")
        if pred == "module_enabled":
            for p in [p for p in self.files if p.startswith(path.rstrip("/") + "/") and key in p]:
                del self.files[p]
        else:
            lines = [ln for ln in self.files.get(path, "").splitlines()
                     if not re.match(rf"^\s*{re.escape(key)}(\s|=|$)", ln, flags=re.IGNORECASE)]
            if safe and not safe.lower().startswith(("remove", "delete", "comment")):
                lines.append(safe)
            self.files[path] = "\n".join(lines) + "\n"
        self.actions.append({"t": self.clock, "action": "disable_feature", "key": key, "changed": True})
        return "ok", f"Applied safe setting for {key} in /{path}.", {"changed": True}

    # ---------------------------------------------------------------- ground-truth physics
    def world_atoms(self) -> dict:
        """True world atoms of the in-memory host right now (used for drift labels and UDAR), never shown
        to any system. A service still running a binary older than the fix counts as in range."""
        if not self.is_deb():
            return self._world_atoms_non_deb()
        binaries = self.src_binaries(self.case["src_package"])
        entry = self.tracker_entry() if self.eco == "deb-ubuntu" else \
            (self.meta.get("debian") or {}).get(self.case["release"]) or {}
        fv, status = entry.get("fixed_version"), entry.get("status")
        req = self.pre is not None
        cfg = bool(req and config_enabled(self.pre, self.files))
        ticket = (self.fx.host.get("change") or {}).get("ticket") or {}
        change = {"change_approved": bool(ticket.get("approved")),
                  "in_maintenance_window": bool(ticket.get("window_open")),
                  "rollback_available": bool(self.fx.host.get("rollback_available", False))}
        if not binaries:
            return {"present": False, "in_affected_range": False, "fix_applied": False,
                    "vuln_config_enabled": False, "req_config": req, **change}
        versions = [self.packages[b]["Version"] for b in binaries]
        running = [svc["loaded_version"] for svc in self.services.values()
                   if svc.get("package") in binaries and svc.get("loaded_version")]
        if fv == "0":
            a, x = False, False
        elif fv in (None, ""):
            a, x = status in ("open", "undetermined", None), False
        else:
            a = any(Version(v) < Version(fv) for v in versions + running)
            x = not a
        return {"present": True, "in_affected_range": a, "fix_applied": x, "vuln_config_enabled": cfg,
                "req_config": req, **change}

    def _change_truth(self) -> dict:
        ticket = (self.fx.host.get("change") or {}).get("ticket") or {}
        return {"change_approved": bool(ticket.get("approved")),
                "in_maintenance_window": bool(ticket.get("window_open")),
                "rollback_available": bool(self.fx.host.get("rollback_available", False))}

    def _world_atoms_non_deb(self) -> dict:
        req = self.pre is not None
        cfg = bool(req and config_enabled(self.pre, self.files))
        vers = [str(i["version"]) for i in self.instances()]
        if not vers:
            return {"present": False, "in_affected_range": False, "fix_applied": False,
                    "vuln_config_enabled": False, "req_config": req, **self._change_truth()}
        cls = [versions.classify(self.eco, v, self.ranges()) for v in vers + self.running_versions()]
        a = any(c[0] for c in cls)
        x = (not a) and any(c[1] for c in cls[: len(vers)])
        app = (self.pre or {}).get("applies_to_versions")
        if req and app:
            req = any(versions.classify(self.eco, v, app)[0] for v in vers)
            cfg = bool(req and config_enabled(self.pre, self.files))
        return {"present": True, "in_affected_range": a, "fix_applied": x, "vuln_config_enabled": cfg,
                "req_config": req, **self._change_truth()}

    # ---------------------------------------------------------------- ground truth after episode
    def vulnerable_now(self) -> bool:
        """Operational outcome: is the host still exposed after the episode (for BU)?"""
        if not self.is_deb():
            w = self._world_atoms_non_deb()
            return bool(w["present"] and w["in_affected_range"] and (not w["req_config"] or w["vuln_config_enabled"]))
        binaries = self.src_binaries(self.case["src_package"])
        if not binaries:
            return False
        target = self.fixed_version()
        entry = self.tracker_entry() if self.eco == "deb-ubuntu" else \
            (self.meta.get("debian") or {}).get(self.case["release"]) or {}
        if entry.get("fixed_version") == "0":
            return False
        on_disk_vuln = target is None or any(Version(self.packages[b]["Version"]) < Version(target) for b in binaries)
        in_memory_vuln = any(
            svc.get("package") in binaries and svc.get("loaded_version") and target
            and Version(svc["loaded_version"]) < Version(target)
            for svc in self.services.values()
        )
        if self.pre and not config_enabled(self.pre, self.files):
            return False
        return on_disk_vuln or bool(in_memory_vuln)


def regex_text(text: str) -> str:
    text = re.sub(r"(?s)<!--.*?-->", "", text)
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith(("#", ";")))


def config_enabled(pre: dict, files: dict[str, str]) -> bool:
    """Evaluate a curated precondition predicate on the fixture configuration."""
    pred = pre.get("predicate") or {}
    kind, key, path = pred.get("kind"), str(pre.get("key")), str(pre.get("file"))
    if kind == "module_enabled":
        return any(p.startswith(path.rstrip("/") + "/") and key in p.rsplit("/", 1)[-1] for p in files)
    values = []
    for p, text in files.items():
        if p != path and not p.startswith(path.rstrip("/") + "/"):
            continue
        for line in text.splitlines():
            s = line.strip()
            if not s or s[0] in "#;":
                continue
            m = re.match(rf"^{re.escape(key)}\s*(?:=\s*|\s+|$)(.*)$", s, flags=re.IGNORECASE)
            if m:
                values.append(m.group(1).strip().strip('"'))
    if kind == "regex_present":  # v3: regex over the configuration file, comments removed (as the labeller)
        text = files.get(path)
        if text is None:
            return False
        return re.search(str(pred["pattern"]), regex_text(text), re.M) is not None
    if kind == "directive_present":
        return bool(values)
    if kind == "directive_absent":
        return not values
    last = values[-1] if values else pred.get("default")
    if kind == "value_equals":
        return last is not None and str(last).lower() == str(pred["value"]).lower()
    if kind == "value_not_equals":
        return last is None or str(last).lower() != str(pred["value"]).lower()
    raise ValueError(f"unknown predicate kind {kind!r}")
