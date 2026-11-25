"""The status object for the App's hosts page (workerhost/hoststatus.py; docs/app-host-integration.md section 1)."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

from workerhost import hoststatus

BASE = hoststatus.Facts(
    host="box1", agent="host-box1-host", version="2026.11.24.2", serial=4, started_at=1_795_000_000.0,
    interval_s=3600, reported_state="idle", account="sbworker", dedicated=True,
    engines=[{"name": "ghcp", "version": "1.0.114", "signed_in": None, "usable": True, "default": True},
             {"name": "claude", "version": None, "signed_in": True, "usable": True, "default": False}],
    busy=0, max_workers=12, claiming=0, held_clones=1, outbox=0,
    fleet={"source": "git", "serial": 4, "coordinators": ["coord-main"], "state": "accepted"}, listed_in_fleet=True)


def build(**over) -> dict:
    return hoststatus.build(replace(BASE, **over))


def test_the_v1_contract_has_every_field_and_nothing_else():
    s = build()
    assert set(s) == {"v", "host", "agent", "version", "serial", "started_at", "interval_s", "state", "account",
                      "dedicated", "engines", "workers", "held_clones", "outbox", "fleet", "update", "release",
                      "last_command", "problem", "warnings"}
    assert (s["v"], s["state"], s["problem"], s["warnings"]) == (1, "online", None, [])
    assert s["release"] == {"source": "fleet", "serial": BASE.serial}  # added in v1, additive (security review, rule e)
    assert s["started_at"] == hoststatus.iso(BASE.started_at) and s["started_at"].endswith("Z")
    assert s["workers"] == {"busy": 0, "max": 12, "claiming": 0}
    assert s["engines"][1] == {"name": "claude", "version": None, "signed_in": True, "default": False}
    assert "usable" not in s["engines"][0]  # internal only


@pytest.mark.parametrize("over, state", [
    ({"reported_state": "maintenance"}, "updating"),
    ({"fleet": {"state": "unavailable"}}, "error"),
    ({"channel_ok": False}, "error"),
    ({"engines": []}, "needs-sign-in"),
    ({"engines": [{"name": "claude", "signed_in": False, "usable": False, "default": True}]}, "needs-sign-in"),
    ({"listed_in_fleet": False}, "needs-fleet"),
    ({"reported_state": "draining"}, "draining"),
    ({"reported_state": "paused(idle)"}, "paused"),
    ({"reported_state": "running", "busy": 3}, "online"),
])
def test_one_word_state(over, state):
    assert build(**over)["state"] == state


@pytest.mark.parametrize("over, code", [
    ({"channel_ok": False}, "channel-missing"),
    ({"fleet": {"state": "unavailable"}}, "fleet-unavailable"),
    ({"bus_ok": False}, "bus-unreachable"),
    ({"engines": []}, "engine-missing"),
    ({"engines": [{"name": "claude", "signed_in": False, "usable": False, "default": True}]}, "sign-in-needed"),
    ({"rolled_back": True}, "rolled-back"),
    ({"openbao_ok": False}, "openbao-unreachable"),
    ({"leaf_expiring": True}, "leaf-expiring"),
    ({"resource_problem": "disk-low"}, "disk-low"),
])
def test_the_problem_is_a_fixed_code_with_a_fixed_sentence(over, code):
    p = build(**over)["problem"]
    assert p == {"code": code, "text": hoststatus.PROBLEMS[code]}


def test_warnings_are_standing_conditions():
    assert build(dedicated=False)["warnings"] == ["not-dedicated"]
    assert build(dedicated=False, isolation_weak=True)["warnings"] == ["not-dedicated", "isolation-weak"]
    assert build(extra_warnings=["made-up"])["warnings"] == []  # only the fixed list


def test_never_a_path_or_secret_and_well_under_the_cap():
    s = build(update={"version": "2026.11.25", "when": "03:00"})
    text = json.dumps(hoststatus.metadata(s))
    assert "\\" not in text and ":\\" not in text and "secret" not in text and "token" not in text
    assert len(text) < 2000 and s["update"] == {"version": "2026.11.25", "when": "03:00"}
    with pytest.raises(ValueError):
        hoststatus.metadata({"x": "y" * 20000})


def test_the_change_key_moves_with_what_the_app_shows():
    a = hoststatus.change_key(build())
    assert hoststatus.change_key(build(busy=3, reported_state="running")) == a  # busy alone waits for the heartbeat
    for over in ({"reported_state": "paused(idle)"}, {"dedicated": False}, {"bus_ok": False},
                 {"update": {"version": "2026.11.25", "when": "03:00"}}, {"fleet": dict(BASE.fleet, serial=5)}):
        assert hoststatus.change_key(build(**over)) != a, over


def test_a_bus_that_refuses_metadata_still_gets_every_heartbeat(tmp_path, monkeypatch):
    """An older bus refusing message metadata: the post goes again without it, and no metadata is tried until the host
    restarts, so a heartbeat is never lost (an older bus)."""
    from workerhost import host as host_mod
    from workerhost.busclient import BusError

    sent = []

    class OldBus:
        def post(self, channel, kind, text, reply_to=None, metadata=None):
            if metadata is not None:
                raise BusError(422, "metadata not allowed")
            sent.append(text)
            return len(sent)

    h = host_mod.Host.__new__(host_mod.Host)
    h.bus, h.metadata_refused, h.bus_state = OldBus(), False, "ok"
    h.cfg = type("C", (), {"channel": "worker-hosts"})()
    h.log = lambda *a, **k: None
    assert h.post("status", "one", queue=False, metadata={"x": 1}) == 1
    assert h.metadata_refused and h.bus_state == "ok"
    assert h.post("status", "two", queue=False, metadata={"x": 1}) == 2  # not even tried with metadata now
    assert sent == ["one", "two"]


def test_another_bus_error_with_metadata_is_not_mistaken_for_a_refusal():
    from workerhost import host as host_mod
    from workerhost.busclient import BusError

    class DownBus:
        def post(self, *a, **k):
            raise BusError(503, "down")

    h = host_mod.Host.__new__(host_mod.Host)
    h.bus, h.metadata_refused, h.bus_state = DownBus(), False, "ok"
    h.cfg = type("C", (), {"channel": "worker-hosts"})()
    h.log = lambda *a, **k: None
    assert h.post("status", "x", queue=False, metadata={"x": 1}) is None
    assert h.bus_state == "down" and not h.metadata_refused


def test_the_host_sends_its_status_in_the_heartbeats_metadata(tmp_path, monkeypatch):
    from conftest import HOST_A, FakeVault, SharedBus
    from workerhost import resources
    from workerhost.config import Config
    from workerhost.host import Host

    from workerhost import engines as engines_mod

    monkeypatch.setattr(resources, "sample", lambda root: None)
    # Copilot CLI counts as installed here (as conftest makes it usable), so the test does not depend on the machine.
    monkeypatch.setattr(engines_mod, "resolve", lambda name: "C:\\bin\\copilot.exe")
    bus = SharedBus().client(HOST_A)
    h = Host(Config(host_name="box1", agent_prefix="host-box1", home=tmp_path / "home", workers_root=tmp_path / "w"),
             bus=bus, vault=FakeVault())
    h.pins = {"host": HOST_A, "coordinator": HOST_A}
    monkeypatch.setattr(h, "refresh_sample", lambda force=False: None)
    h.heartbeat()
    status = bus.metadata_posts[-1][hoststatus.METADATA_KEY]
    assert bus.channel_posts[-1][1] == "status" and bus.channel_posts[-1][2].startswith("host=box1 ")
    assert (status["host"], status["agent"], status["dedicated"], status["warnings"]) == (
        "box1", "host-box1-host", False, ["not-dedicated"])
    # a change the App shows is posted at once (after 30 s), anything else waits for the next heartbeat
    n = len(bus.metadata_posts)
    h.status_posted_at -= 60
    h.status_if_changed()
    assert len(bus.metadata_posts) == n
    h.st.data["paused"] = True
    h.status_if_changed()
    assert len(bus.metadata_posts) == n + 1 and bus.metadata_posts[-1][hoststatus.METADATA_KEY]["state"] == "paused"
