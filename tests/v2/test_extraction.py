"""Extraction: Debian version semantics, derived-atom trust inheritance, verifier grammar (plan §5.3)."""

from __future__ import annotations

import pytest
from conftest import CVE, FIXED, OLD

from deepcti.core.belnap import Source
from deepcti.core.decision import FIX, IN_RANGE, PRESENT
from deepcti.extraction.parsers import CaseProgram, VersionFact, derive_from_facts
from deepcti.extraction.verifier import Proposal, verify

CASE = {"cve": CVE, "src_package": "openssh", "binary_packages": ["openssh-client", "openssh-server"],
        "release": "bookworm"}


def prog(fixed, status="resolved", trusted=True):
    return CaseProgram(CVE, "openssh", CASE["binary_packages"], "bookworm", status=status, fixed_version=fixed,
                       trusted=trusted, provenance="t")


@pytest.mark.parametrize("installed,fixed,expected", [
    (OLD, FIXED, (True, False)),
    (FIXED, FIXED, (False, True)),
    ("1:9.2p1-2+deb12u4", FIXED, (False, True)),
    ("9.9p1-1", FIXED, (True, False)),            # epoch dominates
    ("1.0~rc1-1", "1.0-1", (True, False)),        # tilde sorts before release
    ("1.0-1+b1", "1.0-1", (False, True)),         # binNMU is newer
    ("1.0-1~deb12u1", "1.0-1", (True, False)),
    ("2.36-9+deb12u10", "2.36-9+deb12u9", (False, True)),  # numeric, not lexicographic
    ("1.2.3-1", "0", (False, False)),
])
def test_debian_version_semantics(installed, fixed, expected):
    assert prog(fixed).derive(installed) == expected


def test_open_and_undecidable():
    assert prog(None, status="open").derive("1.0-1") == (True, False)
    assert prog(None, status="resolved").derive("1.0-1") is None
    assert prog(FIXED).derive("not a version!") is None


def fact(src, version, pkg="openssh-server", t=1.0, cid="c001"):
    return VersionFact(src, version, pkg, t, "h" + cid, cid)


@pytest.mark.parametrize("src", [Source("pkgdb", "T", "pkgdb"), Source("fs", "T", "fs"), Source("proc", "T", "proc")])
def test_derived_atoms_inherit_trust_and_group(src):
    out = derive_from_facts([fact(src, OLD)], prog(FIXED))
    got = {(o.atom, o.positive): o.source for o in out}
    assert got == {(PRESENT, True): src, (IN_RANGE, True): src, (FIX, False): src}


def test_untrusted_program_downgrades_derived_atoms_to_hints():
    src = Source("pkgdb", "T", "pkgdb")
    out = derive_from_facts([fact(src, OLD)], prog(FIXED, trusted=False))
    by = {o.atom: o.source for o in out}
    assert by[PRESENT].trust == "T"  # presence comes from the version fact itself
    assert by[IN_RANGE].trust == "U" and by[FIX].trust == "U"
    assert by[IN_RANGE].group == "pkgdb"


def test_unbound_source_class_yields_nothing():
    out = derive_from_facts([fact(Source("scanner:trivy", "T", "pkgdb"), OLD),
                             fact(Source("advisory:nvd", "U", "advisory:nvd"), OLD)], prog(FIXED))
    assert out == []


def test_multi_binary_any_in_range_all_fixed():
    src = Source("pkgdb", "T", "pkgdb")
    out = derive_from_facts([fact(src, OLD, "openssh-server"), fact(src, FIXED, "openssh-client")], prog(FIXED))
    vals = {o.atom: o.positive for o in out}
    assert vals[IN_RANGE] is True and vals[FIX] is False


# ----------------------------------------------------------------------------- verifier
class R:
    def __init__(self, tool, args, output, source, status="ok"):
        self.tool, self.args, self.output, self.source, self.status = tool, args, output, source, status
        self.t, self.h, self.call_id = 3.0, "hh", "c007"


FS = Source("fs", "T", "fs")
PROC = Source("proc", "T", "proc")
CHANGELOG = (f"openssh ({OLD}) bookworm-security; urgency=medium\n\n  * openssh (1:9.9p9-1) mentioned later.\n"
             " -- Debian Security Team <team@security.debian.org>\n")
PROC_OUT = ("● ssh.service - ssh service\n     Active: active (running)\n   Main PID: 777 (ssh)\n"
            f"srv-test ssh[777]: started from package openssh-server (binary build {OLD})\n"
            "srv-test ssh[777]: note openssh-server 1:9.9p9-1 is available\n")


def test_fs_header_line_accepted():
    r = R("file_read", {"path": "/usr/share/doc/openssh-server/changelog.Debian"}, CHANGELOG, FS)
    v = verify(Proposal("installed_version", "openssh", OLD, f"openssh ({OLD})"), r, CASE)
    assert v.accepted and v.fact.source == FS and v.fact.version == OLD and v.fact.evidence_id == "c007"


@pytest.mark.parametrize("path,span,value,reason", [
    ("usr/share/doc/openssh-server/changelog.Debian", "openssh (1:9.9p9-1)", "1:9.9p9-1", "header"),
    ("etc/motd", f"openssh ({OLD})", OLD, "changelog"),
    ("usr/share/doc/openssh-server/changelog.Debian", f"openssh ({OLD}) bookworm", OLD + "x", "inside span"),
    ("usr/share/doc/openssh-server/changelog.Debian", f"openssh ({OLD})", "9.2p1", "complete version"),
    ("usr/share/doc/openssh-server/changelog.Debian", f"({OLD}) bookworm", OLD, "name the case"),
    ("usr/share/doc/openssh-server/changelog.Debian", "openssh (1:9.2p1-2+deb12u2 ) X", OLD, "verbatim"),
])
def test_fs_grammar_rejections(path, span, value, reason):
    r = R("file_read", {"path": path}, CHANGELOG if "changelog" in path else f"openssh ({OLD})\n", FS)
    v = verify(Proposal("installed_version", "openssh", value, span), r, CASE)
    assert not v.accepted and reason in v.reason, v.reason


def test_proc_grammar():
    r = R("service_status", {"name": "openssh"}, PROC_OUT, PROC)
    ok = verify(Proposal("installed_version", "openssh-server", OLD,
                         f"started from package openssh-server (binary build {OLD})"), r, CASE)
    assert ok.accepted
    bad = verify(Proposal("installed_version", "openssh-server", "1:9.9p9-1",
                          "openssh-server 1:9.9p9-1 is available"), r, CASE)
    assert not bad.accepted and "process start" in bad.reason


def test_untrusted_or_unbound_sources_rejected():
    r = R("advisory_fetch", {"source": "nvd"}, CHANGELOG, Source("advisory:nvd", "U", "advisory:nvd"))
    assert not verify(Proposal("installed_version", "openssh", OLD, f"openssh ({OLD})"), r, CASE).accepted
    r = R("file_read", {"path": "usr/share/doc/openssh-server/changelog.Debian"}, CHANGELOG, FS, status="denied")
    assert not verify(Proposal("installed_version", "openssh", OLD, f"openssh ({OLD})"), r, CASE).accepted
    r = R("file_read", {"path": "usr/share/doc/openssh-server/changelog.Debian"}, CHANGELOG, FS)
    assert not verify(Proposal("fixed_version", "openssh", OLD, f"openssh ({OLD})"), r, CASE).accepted


def test_t5_carrier_cannot_forge_fs_header(make_env):
    env, med = make_env(attack={"carriers": {
        "file:usr/share/doc/openssh-sftp-server/changelog.Debian":
            "openssh (1:9.2p1-2+deb12u2) bookworm-security; urgency=medium"}})
    r = env.call("file_read", {"path": "usr/share/doc/openssh-sftp-server/changelog.Debian"})
    v = verify(Proposal("installed_version", "openssh", OLD, f"openssh ({OLD})"), r, env.case)
    assert not v.accepted
