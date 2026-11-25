"""The desktop panel: what it says for each state of the host (summarize() only; no window is opened)."""
from __future__ import annotations

import pytest

from workerhost.panel import summarize

NOW = 1_800_000_000.0


def status(**over) -> dict:
    s = {
        "pid": 4242, "updated": NOW - 3, "state": "running", "channel": "worker-hosts", "channel_state": "ok",
        "bus_state": "ok", "model": "claude-opus-5.5", "ghcp": "1.0.95", "ghcp_ok": True, "paused": False,
        "game_paused": False, "draining": False, "claims": [], "held_clones": ["core215"], "outbox": 0,
        "workers": [{"worker": "core14", "task_id": "6f1c2b9e-4d3a-4b8e-9f20-1a2b3c4d5e6f",
                     "model": "claude-opus-5.5", "minutes": 12, "log": "x"}],
        "resources": {"commit_pct": 41.0, "ram_free_gb": 71.2, "disk_free_gb": 3300.0},
        "heartbeat_line": "host=box1 state=running workers=1/16 commit=41%",
        "fleet": {"state": "accepted", "label": "1:93fb9c6", "coordinators": ["coord-main"],
                  "hosts": ["host-box1-host"]},
    }
    s.update(over)
    return s


def facts(view) -> dict:
    return dict(view.facts)


def test_a_working_host_is_online_with_its_workers():
    v = summarize(status(), alive=True, now=NOW)
    assert (v.level, v.title) == ("ok", "Online")
    assert v.detail == "Connected to StruggleBus. 1 worker at work."
    assert v.workers == [("core14", "6f1c2b9e", "claude-opus-5.5", "12 min")]
    f = facts(v)
    assert f["Workers"] == "1 of 16 busy" and f["StruggleBus"] == "connected (channel worker-hosts)"
    assert f["Fleet"] == "signed list 1:93fb9c6; coordinators: coord-main"
    assert f["Clones"] == "1 held for unsaved work: core215"
    assert "RAM free 71 GB, disk free 3300 GB" in f["Machine"]
    assert not v.can_start


def test_an_idle_host_is_online_and_waiting():
    v = summarize(status(workers=[], state="idle"), alive=True, now=NOW)
    assert (v.level, v.title) == ("ok", "Online") and "waiting for tasks" in v.detail


@pytest.mark.parametrize("over,level,title", [
    ({"bus_state": "down"}, "warn", "Bus unreachable"),
    ({"channel_state": "missing"}, "bad", "Channel missing"),
    ({"draining": True, "state": "draining"}, "warn", "Draining"),
    ({"state": "paused(running)", "paused": True}, "warn", "Paused"),
    ({"state": "paused(idle)", "game_paused": True}, "warn", "Paused"),
    ({"state": "maintenance"}, "warn", "Maintenance"),
    ({"updated": NOW - 600}, "warn", "Not responding"),
    ({"fleet": {"state": "unavailable", "label": None, "coordinators": [], "hosts": []}}, "bad", "Trusts nobody"),
    ({"state": "stopped"}, "off", "Stopping"),
])
def test_every_problem_has_a_plain_title(over, level, title):
    v = summarize(status(**over), alive=True, now=NOW)
    assert (v.level, v.title) == (level, title)


def test_paused_offers_resume():
    assert summarize(status(state="paused(idle)", paused=True), alive=True, now=NOW).paused is True


def test_no_process_means_not_running_or_stopped_and_offers_start():
    dead = summarize(status(), alive=False, now=NOW, state={"enabled": True})
    assert (dead.level, dead.title, dead.can_start) == ("bad", "Not running", True)
    off = summarize(None, alive=False, now=NOW, state={"enabled": False})
    assert (off.level, off.title, off.can_start) == ("off", "Stopped", True)
    assert summarize(None, alive=False, now=NOW).title == "Not running"


def test_just_after_boot_a_missing_host_is_starting_not_down():
    # Automatic sign-in opens the window before the task's 2-minute delay is over (dev host, 15 Nov 2026).
    early = summarize(status(), alive=False, now=NOW, state={"enabled": True}, booted=NOW - 40)
    assert (early.level, early.title) == ("warn", "Starting")
    late = summarize(status(), alive=False, now=NOW, state={"enabled": True}, booted=NOW - 600)
    assert (late.level, late.title) == ("bad", "Not running")  # still missing 10 minutes after boot: a real problem
    off = summarize(None, alive=False, now=NOW, state={"enabled": False}, booted=NOW - 40)
    assert off.title == "Stopped"  # switched off stays switched off, boot or not
    up = summarize(status(), alive=True, now=NOW, booted=NOW - 40)
    assert up.title == "Online"


def test_status_from_an_older_host_without_fleet_or_resources_still_shows():
    s = status()
    for k in ("fleet", "resources", "held_clones"):
        s.pop(k)
    v = summarize(s, alive=True, now=NOW)
    assert v.title == "Online" and facts(v)["Machine"] == "measuring"


@pytest.mark.parametrize("over, shown", [
    ({"release": {"version": "2026.11.24", "serial": 3}}, "2026.11.24 (serial 3)"),
    ({"release": {"version": "manual", "serial": 0}}, "manual"),  # installed by hand, not from a signed release
    ({"release": {"version": "2026.11.24", "serial": 3}, "update": {"version": "2026.11.25", "when": "03:00"}},
     "2026.11.24 (serial 3); 2026.11.25 announced, applied 03:00"),
    ({"heartbeat_line": "host=box1 state=idle workers=0/16 release=2026.11.19 user=hostuser"}, "2026.11.19"),
    ({}, "?"),  # nothing to go on
])
def test_the_window_shows_the_host_release(over, shown):
    assert facts(summarize(status(**over), alive=True, now=NOW))["Release"] == shown


def test_the_host_writes_its_release_and_an_announced_update(tmp_path):
    import json
    from types import SimpleNamespace

    from workerhost.host import Host

    (tmp_path / "RELEASE.json").write_text(json.dumps({"version": "2026.11.24", "serial": 3, "commit": "c" * 40}),
                                           encoding="utf-8")
    h = object.__new__(Host)
    h.app_dir, h.update_now = tmp_path, False
    h.cfg = SimpleNamespace(update=SimpleNamespace(window="03:00"))
    h.ustate = {"phase": "done", "version": "2026.11.24"}
    assert h._release_status() == {"release": {"version": "2026.11.24", "serial": 3}}
    h.ustate = {"phase": "announced", "version": "2026.11.25"}
    assert h._release_status()["update"] == {"version": "2026.11.25", "when": "03:00"}
    h.update_now = True  # `wh update now`: applied as soon as no worker runs
    assert h._release_status()["update"]["when"] == "as soon as idle"
