"""A dedicated host and the machine's engine updater (workerhost/engineupdate.py; #humans 29443-29445): it closes
admission while the marker is fresh, turns each new outcome into a host event once, takes Copilot's state from it, and
never runs winget itself."""
from __future__ import annotations

import json
import os
import time

import pytest

from workerhost import engineupdate, hostevents


def result(tmp_path, written_at=100, state="done", results=None):
    p = tmp_path / "result.json"
    p.write_text(json.dumps({"v": 1, "day": "2026-11-29", "state": state, "written_at": written_at, "busy": [],
                             "results": results if results is not None else [
                                 {"tool": "ghcp", "outcome": "updated", "before": "1.0.116", "after": "1.0.118",
                                  "reason": None},
                                 {"tool": "claude", "outcome": "failed", "before": "2.1.332", "after": None,
                                  "reason": "publisher-mismatch"}]}), encoding="utf-8")
    return p


def test_a_marker_closes_admission_however_old_and_a_stopped_heartbeat_is_an_interruption(tmp_path):
    """Fail closed (prox-manager #humans 29453, u64-security 29455): only the updater removes its marker."""
    m = tmp_path / "updating.json"
    assert not engineupdate.marker_present(m) and not engineupdate.marker_interrupted(m)
    m.write_text("{}", encoding="utf-8")
    assert engineupdate.marker_present(m) and not engineupdate.marker_interrupted(m)  # a live run, beating
    old = time.time() - engineupdate.STALE_SECONDS - 5
    os.utime(m, (old, old))
    assert engineupdate.marker_present(m) and engineupdate.marker_interrupted(m)  # died part-way: STILL closed
    old = time.time() - 30 * 24 * 3600
    os.utime(m, (old, old))
    assert engineupdate.marker_present(m)  # no age reopens it


def test_only_a_finished_run_is_read_and_only_what_fits(tmp_path):
    assert engineupdate.read_result(tmp_path / "none.json") is None
    assert engineupdate.read_result(result(tmp_path, state="waiting")) is None
    got = engineupdate.read_result(result(tmp_path, results=[
        {"tool": "ghcp", "outcome": "updated", "before": "1.0.116", "after": "1.0.118"},
        {"tool": "evil", "outcome": "updated"},                                  # not one of ours
        {"tool": "claude", "outcome": "failed", "reason": "Not A Code; rm -rf"},  # free text never passes
        {"tool": "ghcp", "outcome": "updated", "after": "1.0.118; x"}]))
    assert got["results"][0] == {"tool": "ghcp", "outcome": "updated", "before": "1.0.116", "after": "1.0.118",
                                 "reason": None}
    assert got["results"][1]["reason"] == "unknown" and got["results"][2]["after"] is None and len(got["results"]) == 3


def test_the_events_fit_the_contract_the_bus_holds():
    up = hostevents.make("tool-updated", code="ghcp", tool_version="1.0.118")
    failed = hostevents.make("tool-update-failed", code="claude", reason="publisher-mismatch")
    assert hostevents.event_problem(up) is None and up["tool_version"] == "1.0.118"
    assert hostevents.event_problem(failed) is None and failed["reason"] == "publisher-mismatch"
    assert "tool_version" not in hostevents.make("tool-updated", code="ghcp", tool_version="1.0.118; x")
    # and the log lines the host writes become them
    assert hostevents.SIMPLE["tool-updated"] == ("tool-updated", {"code": "tool", "tool_version": "version"})


@pytest.fixture
def dedicated(tmp_path, monkeypatch):
    from conftest import HOST_A, FakeVault, SharedBus
    from workerhost import engines as engines_mod
    from workerhost import ghcp, resources
    from workerhost.config import Config
    from workerhost.host import Host

    monkeypatch.setattr(resources, "sample", lambda root: None)
    monkeypatch.setattr(engines_mod, "resolve", lambda name: "C:\\bin\\copilot.exe")
    monkeypatch.setattr(ghcp, "version", lambda exe, run=None: "1.0.118")
    folder = tmp_path / "engine-update"
    folder.mkdir()
    monkeypatch.setattr(engineupdate, "folder", lambda: folder)
    h = Host(Config(host_name="box1", agent_prefix="host-box1", home=tmp_path / "home", workers_root=tmp_path / "w",
                    dedicated_account=True), bus=SharedBus().client(HOST_A), vault=FakeVault())
    h.pins = {"host": HOST_A, "coordinator": HOST_A}
    logged = []
    h.log = lambda event, **k: logged.append((event, k))
    return h, folder, logged


def test_a_dedicated_host_takes_no_task_while_the_machine_updates_its_tools(dedicated):
    h, folder, logged = dedicated
    assert not h.machine_updating_engines() and h.reported_state() != "maintenance"
    (folder / "updating.json").write_text("{}", encoding="utf-8")
    assert h.resource_verdict() == ("maintenance", {}) and h.reported_state() == "maintenance"
    from workerhost import hoststatus

    facts = h.status_facts()
    assert not facts.engine_update_interrupted  # a live run: closed, but no problem
    old = time.time() - engineupdate.STALE_SECONDS - 5
    os.utime(folder / "updating.json", (old, old))
    facts = h.status_facts()
    assert facts.engine_update_interrupted and hoststatus.problem_of(facts) == "engine-update-interrupted"
    assert h.resource_verdict() == ("maintenance", {})  # and still takes nothing
    h.cfg.dedicated_account = False  # a host on a shared account updates its own per-user tools as before
    assert not h.machine_updating_engines() and h.reported_state() != "maintenance"


def test_each_new_outcome_is_logged_once_and_sets_copilots_state(dedicated, tmp_path):
    h, folder, logged = dedicated
    result(folder, written_at=200)
    h.engine_update_tick()
    assert ("tool-updated", {"tool": "ghcp", "version": "1.0.118", "previous": "1.0.116"}) in logged
    assert ("tool-update-failed", {"tool": "claude", "reason": "publisher-mismatch"}) in logged
    assert h.ghcp_ok is True and h.ghcp_version == "1.0.118"
    logged.clear()
    h.engine_checked = 0.0
    h.engine_update_tick()
    assert logged == []  # the same run is never reported twice
    result(folder, written_at=300, results=[{"tool": "ghcp", "outcome": "failed", "reason": "winget-failed"}])
    h.engine_checked = 0.0
    h.engine_update_tick()
    assert logged == [("tool-update-failed", {"tool": "ghcp", "reason": "winget-failed"})] and h.ghcp_ok is False


def test_the_window_runs_the_hosts_own_update_only_on_a_shared_account(dedicated, monkeypatch):
    from workerhost import host as host_mod

    h, folder, logged = dedicated
    calls = []
    h.update_ghcp = lambda: calls.append("own")
    h.engine_update_tick = lambda: calls.append("machine")
    h.in_window = lambda: True
    h.ghcp_tick(time.time())
    assert calls == ["machine"]  # dedicated: read the machine's updater, never run its own
    h.cfg.dedicated_account = False
    calls.clear()
    h.ghcp_tick(time.time())
    assert calls == ["own"] and h.st.data["ghcp_attempt"] > 0
    calls.clear()
    h.ghcp_tick(time.time())
    assert calls == []  # not again before retry_minutes
    h.st.data["ghcp_attempt"] = 0
    h.runs = {"w1": object()}
    h.ghcp_tick(time.time())
    assert calls == [] and logged[-1] == ("ghcp-deferred", {"reason": "workers-running"})
    h.runs = {}
    h.st.data["last_ghcp_day"] = host_mod.datetime.now().strftime("%Y-%m-%d")
    h.st.data["ghcp_attempt"] = 0
    h.ghcp_tick(time.time())
    assert calls == []  # once a day
    h.update_when_idle = True
    h.ghcp_tick(time.time())
    assert calls == ["own"] and h.update_when_idle is False  # `wh update-ghcp`, when idle


def test_a_dedicated_host_never_runs_winget_itself(dedicated, monkeypatch):
    from workerhost import ghcp

    h, folder, logged = dedicated
    monkeypatch.setattr(ghcp, "update", lambda *a, **k: pytest.fail("a dedicated host ran winget"))
    h.update_ghcp()
    assert logged == [("ghcp-update-skipped", {"reason": "machine-task"})]
