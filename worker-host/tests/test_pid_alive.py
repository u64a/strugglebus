"""The host runs in session 0 (scheduled task, Password logon); `wh` and the status window run in the signed-in,
non-elevated session and get ERROR_ACCESS_DENIED opening its process. That must still count as running."""
import json
import os
import time
from types import SimpleNamespace

import pytest

from workerhost import cli, panel, winapi

windows = pytest.mark.skipif(not winapi.IS_WINDOWS, reason="Windows process APIs")


@windows
def test_own_process_is_alive():
    assert winapi.pid_alive(os.getpid())


@windows
def test_a_pid_that_does_not_exist_is_not_alive():
    assert not winapi.pid_alive(0x7FFFFFF0)


@windows
def test_access_denied_counts_as_alive_and_other_errors_do_not(monkeypatch):
    fake = SimpleNamespace(OpenProcess=lambda access, inherit, pid: 0)
    monkeypatch.setattr(winapi, "kernel32", fake)
    monkeypatch.setattr(winapi.ctypes, "get_last_error", lambda: winapi.ERROR_ACCESS_DENIED)
    assert winapi.pid_alive(1234)
    monkeypatch.setattr(winapi.ctypes, "get_last_error", lambda: 87)  # ERROR_INVALID_PARAMETER: no such process
    assert not winapi.pid_alive(1234)


def _status_dir(tmp_path, updated):
    state = tmp_path / "state"
    state.mkdir()
    (state / "status.json").write_text(json.dumps({"pid": 4321, "updated": updated, "state": "idle",
                                                   "bus_state": "ok", "channel": "worker-hosts"}), encoding="utf-8")
    return SimpleNamespace(state_dir=state)


def test_wh_sees_a_running_host_it_cannot_open(tmp_path, monkeypatch):
    cfg = _status_dir(tmp_path, time.time())
    monkeypatch.setattr(winapi, "pid_alive", lambda pid: pid == 4321)
    monkeypatch.setattr(winapi, "process_identity", lambda pid: None)  # what the signed-in session gets
    assert cli.host_status(cfg)["pid"] == 4321


def test_wh_still_treats_a_stale_status_as_not_running(tmp_path, monkeypatch):
    cfg = _status_dir(tmp_path, time.time() - 600)
    monkeypatch.setattr(winapi, "pid_alive", lambda pid: True)
    assert cli.host_status(cfg) is None


def test_the_window_says_online_for_a_running_host_it_cannot_open(tmp_path, monkeypatch):
    cfg = _status_dir(tmp_path, time.time())
    monkeypatch.setattr(winapi, "IS_WINDOWS", True)
    monkeypatch.setattr(winapi, "pid_alive", lambda pid: pid == 4321)
    monkeypatch.setattr(winapi, "process_identity", lambda pid: None)
    assert panel.load(cfg).title == "Online"
