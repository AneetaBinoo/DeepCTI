"""Tiny synthetic host fixture for HostEnv / Mediator / Controller tests (no data/ access)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from deepcti.agents.mediator import Mediator
from deepcti.env.host import Attack, Fixture, HostEnv
from deepcti.policy.pdp import PolicyDecisionPoint

CVE = "CVE-2024-6387"
OLD = "1:9.2p1-2+deb12u2"
FIXED = "1:9.2p1-2+deb12u3"

CASE = {"case_id": "T-1", "cve": CVE, "src_package": "openssh", "binary_packages": ["openssh-client", "openssh-server"],
        "release": "bookworm", "host_id": "h_test"}
META = {"cve": CVE, "src_package": "openssh", "debian": {"bookworm": {"status": "resolved", "fixed_version": FIXED}}}
PRE = {CVE: {"cve": CVE, "src_package": "openssh", "service": "ssh", "file": "etc/ssh/sshd_config",
             "key": "LoginGraceTime", "predicate": {"kind": "value_not_equals", "value": "0"},
             "safe_setting": "LoginGraceTime 0"}}


def stanza(pkg: str, version: str, source: str = "openssh", status: str = "install ok installed") -> str:
    return (f"Package: {pkg}\nStatus: {status}\nArchitecture: amd64\nSource: {source}\nVersion: {version}\n"
            f"Description: test\n")


def build_host(root: Path, *, versions: dict | None = None, extra_files: dict | None = None,
               scans: dict | None = None, ticket: dict | None = None, rollback: bool = True,
               sshd: str = "LoginGraceTime 120\n") -> Path:
    versions = versions or {"openssh-client": OLD, "openssh-server": OLD}
    host = root / "h_test"
    rootfs = host / "rootfs"
    (rootfs / "var/lib/dpkg").mkdir(parents=True)
    paras = [stanza(p, v) for p, v in versions.items()] + [stanza("zlib1g", "1:1.2.13.dfsg-1", "zlib")]
    (rootfs / "var/lib/dpkg/status").write_text("\n".join(paras))
    (rootfs / "etc/ssh").mkdir(parents=True)
    (rootfs / "etc/ssh/sshd_config").write_text(sshd)
    (rootfs / "etc/os-release").write_text('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_CODENAME=bookworm\n')
    for p, v in versions.items():
        d = rootfs / "usr/share/doc" / p
        d.mkdir(parents=True)
        (d / "changelog.Debian").write_text(f"openssh ({v}) bookworm-security; urgency=medium\n\n  * fix.\n")
    for rel, text in (extra_files or {}).items():
        (rootfs / rel).parent.mkdir(parents=True, exist_ok=True)
        (rootfs / rel).write_text(text)
    if scans:
        (host / "scans").mkdir()
        for name, body in scans.items():
            (host / "scans" / f"{name}.json").write_text(body if isinstance(body, str) else json.dumps(body))
    (host / "host.json").write_text(json.dumps({
        "host_id": "h_test", "hostname": "srv-test", "release": "bookworm",
        "services": {"ssh": {"unit": "ssh.service", "active": True, "package": "openssh-server"}},
        "cmdb": {"asset": "srv-test", "software": [{"name": "openssh-server", "version": OLD}], "notes": "tier 2"},
        "change": {"ticket": ticket if ticket is not None else {"id": "CHG1", "approved": True, "window_open": True}},
        "rollback_available": rollback,
    }))
    return host


@pytest.fixture
def make_env(tmp_path):
    counter = {"n": 0}

    def _make(*, meta=None, pre=None, attack=None, drift=None, profiles=None, case=None, policy="P2",
              use_freshness=True, **host_kw):
        counter["n"] += 1
        root = tmp_path / f"r{counter['n']}"
        root.mkdir()
        fx = Fixture.load(build_host(root, **host_kw))
        env = HostEnv(dict(case or CASE), fx, meta if meta is not None else META, PRE if pre is None else pre, {},
                      attack=Attack(**attack) if attack else None, drift=drift,
                      profiles={} if profiles is None else profiles)
        med = Mediator(env, PolicyDecisionPoint(policy), use_freshness=use_freshness)
        return env, med

    return _make
