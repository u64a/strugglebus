"""CPU busy % in the heartbeat (monitoring only, for the dev host's move from 16 to 24 workers, 18 Nov)."""
from __future__ import annotations

import sys

import pytest

from conftest import COORD, HOST_A, FakeVault
from workerhost import resources, winapi
from workerhost.config import Config
from workerhost.host import Host


@pytest.mark.parametrize("before,after,want", [
    ((0, 0, 0), (50, 60, 40), 50.0),    # 100 units of time, 50 idle (kernel includes idle)
    ((0, 0, 0), (100, 100, 0), 0.0),    # all idle
    ((0, 0, 0), (0, 30, 70), 100.0),    # never idle
    ((10, 10, 10), (10, 10, 10), None),  # no time passed
])
def test_busy_share(before, after, want):
    assert winapi.cpu_busy_pct(before, after) == want


@pytest.mark.skipif(sys.platform != "win32", reason="GetSystemTimes is Windows-only")
def test_real_system_times_move_forward():
    # The counters tick at the scheduler's clock (about 15.6 ms), so a short busy loop can see none: on CI's Python
    # 3.13 runner (19 Nov) both readings were equal. Spin until they move, for at most 5 seconds.
    import time
    a = winapi.system_times()
    deadline = time.monotonic() + 5
    while True:
        sum(i * i for i in range(100_000))
        b = winapi.system_times()
        if b[1] + b[2] > a[1] + a[2] or time.monotonic() > deadline:
            break
    assert all(y >= x for x, y in zip(a, b)) and b[1] + b[2] > a[1] + a[2]
    pct = winapi.cpu_busy_pct(a, b)
    assert pct is None or 0.0 <= pct <= 100.0


@pytest.fixture
def host(tmp_path, shared_bus, monkeypatch):
    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(
        100 * resources.GB, 10 * resources.GB, 100 * resources.GB, 128 * resources.GB, 500 * resources.GB, set()))
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", poll_seconds=0, settle_seconds=0,
                 workers_root=tmp_path / "w", allowed_models=["claude-opus-5.5"], home=tmp_path / "home",
                 hosts=[{"agent_name": HOST_A.agent_name, "agent_id": HOST_A.agent_id}])
    h = Host(cfg, bus=shared_bus.client(HOST_A), vault=FakeVault())
    h.pins = {"coordinator": COORD, "host": HOST_A}
    return h


def drive(monkeypatch, readings):
    """Feed system_times() a sequence and make every reading 30 s after the last."""
    it = iter(readings)
    clock = [1000.0]
    monkeypatch.setattr(winapi, "system_times", lambda: next(it))

    def mono():
        return clock[0]
    monkeypatch.setattr("workerhost.host.time.monotonic", mono)
    return clock


def test_heartbeat_reports_average_and_peak_then_starts_a_new_window(host, monkeypatch):
    clock = drive(monkeypatch, [(0, 0, 0), (50, 60, 40), (60, 70, 130), (160, 170, 130)])
    for _ in range(4):
        host.sample_cpu()
        clock[0] += 30
    # readings: 50% then 90% then 0%
    line = host.heartbeat_line()
    assert "cpu=47% cpu_max=90%" in line
    host.post = lambda *a, **k: None
    host.refresh_sample = lambda force=False: None
    host.heartbeat()
    assert host.cpu_window == []
    assert "cpu=0%" in host.heartbeat_line() and "cpu_max" not in host.heartbeat_line()  # the latest reading only


def test_a_forced_sample_seconds_later_is_ignored(host, monkeypatch):
    clock = drive(monkeypatch, [(0, 0, 0), (50, 60, 40), (999, 999, 999)])
    host.sample_cpu()
    clock[0] += 30
    host.sample_cpu()
    clock[0] += 2
    host.sample_cpu()  # 2 s later: not read
    assert host.cpu_window == [50.0]


def test_no_cpu_reading_leaves_the_heartbeat_as_it_was(host, monkeypatch):
    def broken():
        raise OSError(5, "denied")
    monkeypatch.setattr(winapi, "system_times", broken)
    host.sample_cpu()
    assert "cpu=" not in host.heartbeat_line()
