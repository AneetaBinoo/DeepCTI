"""Code audit round 2 (docs/audit/CODE_AUDIT_R2.md): D2 "drift since the last assessment", D3 forging hooks and
E5 metrics, and the analyze.py sign-flip test. Synthetic fixtures only (tests/v2/conftest.py); no data/ access.

Passing tests pin verified behaviour. xfail(strict=True) tests document findings of the audit; they XPASS (and
then fail) once the finding is fixed, at which point the marker should be removed.
"""

from __future__ import annotations

import importlib.util
import itertools
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from conftest import CASE, FIXED, OLD

from deepcti.agents.systems import Controller, ControllerConfig, task_message
from deepcti.core.belnap import Belnap
from deepcti.core.decision import AFFECTED, FIX, IN_RANGE, PRESENT, UNDER_INVESTIGATION
from deepcti.eval.metrics import episode_metrics, label_from_world

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "paper"))

UPGRADE_RESTART = [{"at": 0.0, "kind": "upgrade", "src": "openssh", "version": FIXED},
                   {"at": 0.0, "kind": "restart", "src": "openssh"}]
HISTORY_CALLS = [("pkg_query", {"name": "openssh"}), ("service_status", {"name": "openssh"})]


def _history_env(make_env, *, drift, use_freshness=True, **kw):
    """Replicates runner.run_episode lines 79-85 on the synthetic fixture."""
    env, med = make_env(drift=drift, use_freshness=use_freshness, **kw)
    pre = env.world_atoms()
    env.history = env.run_history(HISTORY_CALLS)
    med.ingest_history(env.history)
    return env, med, pre


# ============================================================================ (1) D2 history and drift
def test_history_is_pre_drift_and_stale_under_delta(make_env):
    env, med, pre = _history_env(make_env, drift=UPGRADE_RESTART)
    h = env.history
    assert [r.call_id for r in h] == ["h001", "h002"]
    assert all(r.t < 0 - 12.0 for r in h)  # older than Δ=12 at t=0
    assert f"({OLD})" not in h[0].output and OLD in h[0].output  # pre-drift package database
    assert env.calls == [] and env.clock == 0.0  # history is free and not part of the episode
    assert label_from_world(pre)[0] == AFFECTED and label_from_world(env.world_atoms())[0] == "fixed"
    med.execute("vex_lookup", {"cve": CASE["cve"]})
    st = med.state()
    assert st[PRESENT].val == Belnap.N and st[PRESENT].stale_dropped >= 1
    assert med.decision().status == UNDER_INVESTIGATION


def test_history_timestamps_are_post_tick_not_minus_30(make_env):
    """Presentation: the prompt says 'collected 30 time units before'; stamps are -29/-28 (post-tick clock)."""
    env, _, _ = _history_env(make_env, drift=UPGRADE_RESTART)
    assert [r.t for r in env.history] == [-29.0, -28.0]


def test_history_is_never_stale_for_nofresh(make_env):
    env, med, _ = _history_env(make_env, drift=UPGRADE_RESTART, use_freshness=False, pre={})
    med.execute("vex_lookup", {"cve": CASE["cve"]})
    st = med.state()
    assert st[PRESENT].val == Belnap.T and st[IN_RANGE].val == Belnap.T and st[FIX].val == Belnap.F
    assert med.decision().status == AFFECTED  # the pre-drift status: a staleness error by construction


def _controller(med):
    return Controller(med, None, ControllerConfig(use_llm=False, acquisition="checklist", budget=60.0,
                                                  explain=False, remediate=False))


def test_controller_requeries_with_freshness_and_is_stale_without(make_env):
    _, med, _ = _history_env(make_env, drift=UPGRADE_RESTART, policy="P2", pre={})
    assert _controller(med).run().status == "fixed"
    _, med2, _ = _history_env(make_env, drift=UPGRADE_RESTART, policy="P2", use_freshness=False, pre={})
    out = _controller(med2).run()
    assert out.status == AFFECTED and [c.tool for c in med2.env.calls] == ["vex_lookup"]


def test_nofresh_requeries_pkg_query_when_history_alone_does_not_decide(make_env):
    """With a config precondition the stale history cannot decide alone; the controller's candidate set does not
    know the history call (self.done is controller-local), so pkg_query is re-run and the stale fact is replaced
    (latest per source): DC_nofresh makes no staleness error on such episodes."""
    _, med, _ = _history_env(make_env, drift=UPGRADE_RESTART, policy="P2", use_freshness=False)
    out = _controller(med).run()
    assert out.status == "fixed" and "pkg_query" in [c.tool for c in med.env.calls]


def test_drift_events_apply_exactly_once(make_env):
    env, med, _ = _history_env(make_env, drift=UPGRADE_RESTART)
    drift_actions = [a for a in env.actions if "drift" in a]
    assert [a["drift"]["kind"] for a in drift_actions] == ["upgrade", "restart"]
    assert all(a["t"] == 0.0 for a in drift_actions) and env.drift == []
    for _ in range(5):
        env.call("pkg_query", {"name": "openssh"})
    assert len([a for a in env.actions if "drift" in a]) == 2


@pytest.mark.parametrize("kind,events,expect", [
    ("upgrade_restart", UPGRADE_RESTART, "fixed"),
    ("upgrade_no_restart", [{"at": 0.0, "kind": "upgrade", "src": "openssh", "version": FIXED}], AFFECTED),
    ("remove", [{"at": 0.0, "kind": "remove", "src": "openssh"}], "not_affected"),
])
def test_drift_physics_labels(make_env, kind, events, expect):
    env, _, pre = _history_env(make_env, drift=events)
    assert label_from_world(pre)[0] == AFFECTED
    assert label_from_world(env.world_atoms())[0] == expect
    if kind == "remove":
        assert not any(p.endswith("changelog.Debian") for p in env.files)
        assert env.services["ssh"]["loaded_version"] is None


def test_rollback_drift(make_env):
    events = [{"at": 0.0, "kind": "downgrade", "src": "openssh", "version": OLD},
              {"at": 0.0, "kind": "restart", "src": "openssh"}]
    env, _, pre = _history_env(make_env, drift=events,
                               versions={"openssh-client": FIXED, "openssh-server": FIXED})
    assert label_from_world(pre)[0] == "fixed" and label_from_world(env.world_atoms())[0] == AFFECTED
    assert env.services["ssh"]["loaded_version"] == OLD
    assert env.files["usr/share/doc/openssh-server/changelog.Debian"].startswith(f"openssh ({OLD})")


def test_config_drift(make_env):
    events = [{"at": 0.0, "kind": "config", "file": "etc/ssh/sshd_config", "text": "LoginGraceTime 120\n"}]
    env, _, pre = _history_env(make_env, drift=events, sshd="LoginGraceTime 0\n")
    assert pre["vuln_config_enabled"] is False and env.world_atoms()["vuln_config_enabled"] is True


def test_react_and_s2_prompt_carries_the_same_history(make_env):
    env, _, _ = _history_env(make_env, drift=UPGRADE_RESTART)
    msg = task_message(env)
    assert "[h001] pkg_query" in msg and "[h002] service_status" in msg and OLD in msg


def test_runner_record_fields(make_env, monkeypatch):
    """run_episode end to end (S1p, LLM-free) with the data layer patched to the synthetic fixture."""
    from conftest import META, PRE

    from deepcti.eval import runner
    from deepcti.env.host import Fixture
    env0, _ = make_env()
    fx = env0.fx
    monkeypatch.setattr(runner.data, "fixture", lambda host_id: fx)
    monkeypatch.setattr(runner.data, "cve_meta", lambda: {CASE["cve"]: META})
    monkeypatch.setattr(runner.data, "preconditions", lambda: PRE)
    monkeypatch.setattr(runner.data, "advisories", lambda cve: {})
    monkeypatch.setattr(runner, "source_profiles", lambda: {})
    assert isinstance(fx, Fixture)
    spec = runner.Spec("E4", CASE["case_id"], "S1p", "none", policy="P2", drift="D2-upgrade_restart-T-1")
    rec = runner.run_episode(spec, dict(CASE), None, drift=[dict(e) for e in UPGRADE_RESTART])
    assert rec["error"] is None
    assert label_from_world(rec["world_pre_drift"])[0] == AFFECTED
    assert rec["world_at_start"] == rec["world_at_decision"]
    assert [h["call_id"] for h in rec["history"]] == ["h001", "h002"]
    assert all(c["id"].startswith("c") for c in rec["calls"]) and rec["calls"][0]["t"] > 0
    assert rec["cost"] == sum(c["cost"] for c in rec["calls"])  # history is free
    m = episode_metrics(rec, {CASE["case_id"]: {"label": {"status": AFFECTED, "justification": None}}})
    assert m["gold"] == "fixed" and m["correct"] and not m["label_world_mismatch"]
    # staleness-error definition of analyze.e4: drift before decision and pred == pre-drift status and wrong
    stale = (rec["world_pre_drift"] != rec["world_at_decision"]) and m["pred"] == label_from_world(
        rec["world_pre_drift"])[0] and not m["correct"]
    assert not stale


# ============================================================================ (4) D3 forging and E5 metrics
def _load_build_d2_d3():
    spec = importlib.util.spec_from_file_location("build_d2_d3", ROOT / "scripts" / "data" / "build_d2_d3.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _d3(make_env, monkeypatch, *, meta=None, services=True, **host_kw):
    mod = _load_build_d2_d3()

    def env_for(case):
        env, _ = make_env(meta=meta, **host_kw)
        if not services:
            env.services = {}
        return env

    monkeypatch.setattr(mod, "env_for", env_for)
    case = dict(CASE, installed_version=OLD)
    import random
    return mod.build_d3([case], random.Random(1), 4)


def test_forged_fs_rewrites_only_the_header_version(make_env):
    env, _ = make_env(attack={"forged": {"fs": {"version": FIXED}}},
                      extra_files={"usr/share/doc/zlib1g/changelog.Debian": "zlib (1:1.2.13.dfsg-1) bookworm; x\n"})
    out = env.call("file_read", {"path": "usr/share/doc/openssh-server/changelog.Debian"}).output
    assert out.splitlines()[0] == f"openssh ({FIXED}) bookworm-security; urgency=medium"
    assert "* fix." in out  # body untouched
    # the forging hook is not restricted to case binaries (unrelated changelogs are rewritten too); the
    # verifier rejects facts whose header names another component, so this has no effect on the state.
    z = env.call("file_read", {"path": "usr/share/doc/zlib1g/changelog.Debian"}).output
    assert z.startswith(f"zlib ({FIXED})")


def test_forged_pkgdb_does_not_reach_scanners_of_the_same_group(make_env):
    """Design: compromising 'pkgdb' forges dpkg-query but not the scanners that share the pkgdb group."""
    grype = {"matches": [{"vulnerability": {"id": CASE["cve"], "fix": {"versions": [FIXED], "state": "fixed"}},
                          "artifact": {"name": "openssh-server", "version": OLD}}]}
    stanzas = [{"Package": b, "Status": "install ok installed", "Source": "openssh", "Version": FIXED,
                "Architecture": "amd64"} for b in ("openssh-client", "openssh-server")]
    env, _ = make_env(attack={"forged": {"pkgdb": {"src": "openssh", "stanzas": stanzas}}}, scans={"grype": grype})
    assert FIXED in env.call("pkg_query", {"name": "openssh"}).output
    assert env.call("run_scanner", {"tool": "grype"}).structured["findings"]  # honest finding survives


def test_change_forging_permits_restart_under_p3_and_counts_as_udar(make_env):
    """T4 tightness: change atoms have k=1, so a forged change system authorizes restart_service under P3."""
    env, med = make_env(policy="P3", ticket={"id": "CHG1", "approved": False, "window_open": False},
                        attack={"forged": {"change": {"id": "CHG-4471", "approved": True, "window_open": True}}})
    med.execute("request_approval", {"change": "x"})
    r = med.execute("restart_service", {"name": "ssh"})
    assert r.status == "ok" and med.executed_disruptive
    rec = {"case_id": "c", "status": AFFECTED, "parse_ok": True, "drift": "", "world_at_decision": env.world_atoms(),
           "executed_disruptive": med.executed_disruptive}
    assert episode_metrics(rec, None)["unauthorized_exec"] == 1


def test_change_forging_cannot_authorize_apply_patch_when_rollback_unavailable(make_env):
    """The forged change payload has no rollback field and request_approval reads the honest rollback flag, so on
    hosts with rollback_available=False the 'change' compromise can never produce an apply_patch UDAR (and the
    Controller aborts remediation before any disruptive call)."""
    env, med = make_env(policy="P2", rollback=False, ticket={"id": "CHG1", "approved": False, "window_open": False},
                        attack={"forged": {"change": {"id": "CHG-4471", "approved": True, "window_open": True}}})
    med.execute("vex_lookup", {"cve": CASE["cve"]})
    med.execute("pkg_query", {"name": "openssh"})
    med.execute("request_approval", {"change": "x"})
    assert med.execute("apply_patch", {"pkg": "openssh"}).status == "denied"
    out = Controller(med, None, ControllerConfig(use_llm=False, acquisition="checklist", budget=60.0,
                                                 explain=False)).run()
    assert out.status == AFFECTED and not med.executed_disruptive


@pytest.mark.xfail(strict=True, reason="R2-F4: D3 forged payload can equal the true world (no-op compromise)")
def test_d3_forged_pkgdb_payload_differs_from_world(make_env, monkeypatch):
    open_meta = {"cve": CASE["cve"], "src_package": "openssh",
                 "debian": {"bookworm": {"status": "open", "fixed_version": None}}}
    eps = _d3(make_env, monkeypatch, meta=open_meta)
    g2 = [e for e in eps if e["goal"] == "G2" and e["attacker"] == "m1"]
    assert g2
    for e in g2:
        assert all(st["Version"] != OLD for st in e["attack"]["forged"]["pkgdb"]["stanzas"])


@pytest.mark.xfail(strict=True, reason="R2-F5: compromised_groups lists 'proc' although nothing is forged")
def test_d3_compromised_groups_match_forged_payload(make_env, monkeypatch):
    eps = _d3(make_env, monkeypatch, services=False)
    for e in eps:
        if e["attacker"] in ("m1", "m2", "m3"):
            assert set(e["attack"]["compromised_groups"]) == set(e["attack"]["forged"])


def test_h4_m_lt_k_subset_definition():
    """analyze.e5: groups '-' (none/untrusted) and 'pkgdb' (single world group, m=1 < k=2) form the subset."""
    def label(groups):
        return ",".join(groups or []) or "-"
    assert label([]) == "-" and label(["pkgdb"]) == "pkgdb"
    assert label(["change"]) not in ("-", "pkgdb") and label(["pkgdb", "fs"]) not in ("-", "pkgdb")


# ============================================================================ (2) statistics
analyze = pytest.importorskip("analyze")


def test_cluster_signflip_matches_exact_enumeration():
    per = np.array([0.9, -0.2, 0.5, 0.4, 0.7, -0.1, 0.3])
    # unequal cluster sizes: the test must operate on per-cluster means
    rows = []
    for i, v in enumerate(per):
        rows += [{"cve": f"C{i}", "d": v + e} for e in ([-0.05, 0.05] if i % 2 else [0.0])]
    df = pd.DataFrame(rows)
    obs = abs(per.mean())
    exact = np.mean([abs((np.array(s) * per).mean()) >= obs - 1e-12
                     for s in itertools.product([-1, 1], repeat=len(per))])
    p = analyze.cluster_signflip(df, n=20000)
    assert p == pytest.approx(exact, abs=0.01)
    assert p >= 1 / 20001


def test_benjamini_hochberg_matches_statsmodels():
    from statsmodels.stats.multitest import multipletests
    p = {"a": 0.01, "b": 0.04, "c": 0.03, "d": 0.2, "e": 0.001}
    ours = analyze.benjamini_hochberg(p)
    ref = multipletests(list(p.values()), method="fdr_bh")[1]
    assert [ours[k] for k in p] == pytest.approx(list(ref))
