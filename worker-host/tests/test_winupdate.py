"""Windows Update restarts (agent-host-build.md 9.2): while one is expected, the host takes no task that could still
be running at [update] windows_restart (03:00), and says restart-pending in its heartbeat."""
from __future__ import annotations

import subprocess
from datetime import datetime

import pytest
from conftest import FakeVault
from test_host import COORD, HOST_A

from workerhost import resources, winupdate
from workerhost.config import Config
from workerhost.host import Host


@pytest.mark.parametrize("out,want", [
    ("1 0\n", True),     # restart flag set
    ("0 2\n", True),     # updates waiting that may restart at 03:00
    ("0 0\n", False),    # nothing waiting
    ("0 -1\n", None),    # the search failed and no flag: unknown
    ("1 -1\n", True),    # the flag wins even if the search failed
    ("garbage", None),
    ("", None),
])
def test_parse(out, want):
    assert winupdate.parse(out) is want


def test_only_windows_updates_own_restart_flag_counts():
    # 19 Nov, dev host: a stale "Component Based Servicing\RebootPending" (from 15 Nov; RebootRequired false, nothing
    # waiting) made the host refuse every task 03:00-08:00 for a restart that never came.
    flag = next(line for line in winupdate.SCRIPT.splitlines() if line.startswith("$reboot"))
    assert r"WindowsUpdate\Auto Update\RebootRequired" in flag
    assert "Component Based Servicing" not in winupdate.SCRIPT and "-or" not in flag


@pytest.mark.winupdate
def test_the_query_runs_windows_powershell_by_full_path_never_a_bare_pwsh(monkeypatch):
    seen = {}

    def run(argv, **kw):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="0 3\n", stderr="")

    monkeypatch.setattr(winupdate.os, "name", "nt")
    assert winupdate.restart_expected(run=run) is True
    assert seen["argv"][0].lower().endswith(r"system32\windowspowershell\v1.0\powershell.exe")
    assert "-EncodedCommand" in seen["argv"]


@pytest.mark.winupdate
def test_a_failed_or_timed_out_query_is_unknown(monkeypatch):
    monkeypatch.setattr(winupdate.os, "name", "nt")
    assert winupdate.restart_expected(run=lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "boom")) is None

    def slow(*a, **k):
        raise subprocess.TimeoutExpired("powershell", 120)

    assert winupdate.restart_expected(run=slow) is None


@pytest.fixture
def host(tmp_path, shared_bus, monkeypatch):
    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(
        100 * resources.GB, 10 * resources.GB, 100 * resources.GB, 128 * resources.GB, 500 * resources.GB, set()))
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", poll_seconds=0, settle_seconds=0,
                 workers_root=tmp_path / "w", home=tmp_path / "home",
                 hosts=[{"agent_name": HOST_A.agent_name, "agent_id": HOST_A.agent_id}])
    h = Host(cfg, bus=shared_bus.client(HOST_A), vault=FakeVault())
    h.pins = {"coordinator": COORD, "host": HOST_A}
    return h


def at(hhmm: str) -> datetime:
    return datetime(2026, 11, 15, int(hhmm[:2]), int(hhmm[3:]))


def test_no_restart_expected_blocks_nothing(host):
    host.restart_pending = False
    assert not host.restart_blocks_claims(at("23:00"))
    host.restart_pending = None  # unknown: a failed query must not stop the host taking work
    assert not host.restart_blocks_claims(at("23:00"))


@pytest.mark.parametrize("hhmm,blocked", [
    ("12:00", False),  # 12:00 + 6 h = 18:00, well before 03:00
    ("20:59", False),  # finishes 02:59
    ("21:01", True),   # could still run at 03:00
    ("02:30", True),
    ("03:00", True),   # inside the restart window: Windows may restart any moment
    ("07:59", True),
    ("08:00", False),  # window over: the next restart is tomorrow 03:00
])
def test_a_pending_restart_refuses_tasks_that_would_run_into_it(host, hhmm, blocked):
    host.restart_pending = True
    assert host.restart_blocks_claims(at(hhmm)) is blocked


def test_the_verdict_and_heartbeat_carry_it(host, monkeypatch):
    host.restart_pending = True
    monkeypatch.setattr(host, "restart_blocks_claims", lambda local=None: True)
    assert host.resource_verdict() == ("restart", {})
    assert "restart-pending@03:00" in host.heartbeat_line()
    host.restart_pending = False
    monkeypatch.setattr(host, "restart_blocks_claims", lambda local=None: False)
    assert "restart-pending" not in host.heartbeat_line()


@pytest.mark.winupdate
def test_the_tick_keeps_the_last_answer_through_one_failed_query(host, monkeypatch):
    answers = iter([True, None, False])
    monkeypatch.setattr(winupdate, "restart_expected", lambda *a, **k: next(answers))
    host.restart_tick(force=True)
    assert host.restart_pending is True
    host.restart_tick(force=True)
    assert host.restart_pending is True  # the failed query did not clear it
    host.restart_tick(force=True)
    assert host.restart_pending is False
