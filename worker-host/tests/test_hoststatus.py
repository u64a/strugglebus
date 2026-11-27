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


# --- v2: the Hosts dashboard (section 1a) -------------------------------------------------------------------------

# The facts behind contracts/host-status/: a busy host with two workers, one warning and an announced update.
V2 = replace(
    BASE, reported_state="running", busy=2, claiming=1, isolation_weak=True,
    update={"version": "2026.11.28", "when": "03:00"}, release_source="https://github.com/acme/mono#worker-host",
    running=[{"slot": "w01", "engine": "ghcp", "model": "claude-opus-5.5", "minutes": 42},
             {"slot": "w02", "engine": "claude", "model": "claude-sonnet-5.5", "minutes": 7}],
    machine={"cpu_pct": 37.25, "ram_free_gb": 21.04, "disk_free_gb": 812.6, "commit_pct": 48.0},
    bus_state="ok", channel="worker-hosts", channel_state="ok", model="claude-opus-5.5", ghcp_ok=True,
    tasks={"finished": 17, "failed": 2, "timed-out": 1, "refused": 3}, pwsh="7.6.10")
RECEIVED_AT = "2026-11-27T04:00:00Z"  # the bus's clock, in the history vector


def contract(name: str) -> dict:
    from vectors import path

    return json.loads(path("host-status", name).read_text(encoding="utf-8"))


def vector_files() -> dict[str, dict]:
    """What contracts/host-status/ holds, made from V2 by the reference functions."""
    snap = hoststatus.build_v2(V2)
    return {"snapshot-v2.json": snap, "snapshot-v2-device.json": hoststatus.for_device(snap),
            "sample-v2.json": hoststatus.sample(snap, RECEIVED_AT)}


@pytest.mark.parametrize("name", ["snapshot-v2.json", "snapshot-v2-device.json", "sample-v2.json"])
def test_the_contract_vectors_are_what_the_code_makes(name):
    assert contract(name) == vector_files()[name]


def test_v2_is_v1_plus_the_panels_facts():
    v1, v2 = build(), hoststatus.build_v2(BASE)
    assert v2["v"] == 2
    assert all(v2[k] == v1[k] for k in v1 if k not in ("v", "workers"))  # every v1 field, unchanged
    assert set(v2) - set(v1) == {"machine", "bus", "model", "ghcp_ok", "tasks", "pwsh"}
    assert v2["pwsh"] is None  # not found: null, never a guess
    assert v2["workers"] == {"busy": 0, "max": 12, "claiming": 0, "running": []}
    assert v2["machine"] == {"cpu_pct": None, "ram_free_gb": None, "disk_free_gb": None, "commit_pct": None}
    assert list(v2["tasks"]) == list(hoststatus.TASK_OUTCOMES) and set(v2["tasks"].values()) == {0}
    assert build() == v1  # the heartbeat's v1 is untouched by v2's facts (coordinators read it)
    assert hoststatus.build(V2)["v"] == 1 and "machine" not in hoststatus.build(V2)


def test_a_device_without_the_operator_grant_never_sees_the_admin_fields():
    dev = hoststatus.for_device(hoststatus.build_v2(V2))
    assert not {"account", "dedicated", "warnings"} & set(dev)
    assert dev["bus"] == {"state": "ok"}  # channel and channel_state are admin only (bus-dev, 28832)
    assert dev["workers"]["running"][0] == {"slot": "w01", "engine": "ghcp", "model": "claude-opus-5.5", "minutes": 42}
    assert hoststatus.build_v2(V2)["account"] == "sbworker"  # the host sends it; the bus filters on read


@pytest.mark.parametrize("value, sent", [("7.6.10", "7.6.10"), ("7.7.0-preview.3", "7.7.0-preview.3"), ("", None),
                                         ("7.6.10; rm -rf", None), ("x" * 40, None), (None, None)])
def test_the_powershell_version_is_sent_only_when_it_looks_like_one(value, sent):
    assert hoststatus.build_v2(replace(V2, pwsh=value))["pwsh"] == sent


def test_pwsh_is_not_in_the_history_sample():
    """A version doesn't chart, and the latest snapshot shows it (bus-dev, #humans 28936)."""
    assert "pwsh" not in hoststatus.sample(hoststatus.build_v2(V2), RECEIVED_AT)


def test_the_host_asks_pwsh_for_its_version_once_an_hour(pushing, monkeypatch):
    import subprocess as sp

    h, pushes, logged, answer, clock = pushing
    calls = []
    monkeypatch.setattr("workerhost.host.shutil.which", lambda name: "C:\\pwsh.exe")

    def fake_run(cmd, **k):
        calls.append(cmd)
        return sp.CompletedProcess(cmd, 0, "7.6.10\n", "")

    monkeypatch.setattr("workerhost.host.subprocess.run", fake_run)
    assert h.pwsh_version() == "7.6.10" and h.pwsh_version() == "7.6.10" and len(calls) == 1
    clock["t"] += 3601
    h.pwsh_version()
    assert len(calls) == 2
    monkeypatch.setattr("workerhost.host.shutil.which", lambda name: None)
    monkeypatch.setattr("workerhost.host.PWSH_PATHS", ())
    clock["t"] += 3601
    assert h.pwsh_version() is None


def test_the_pinned_pwsh_wins_over_one_on_path(pushing, monkeypatch, tmp_path):
    import subprocess as sp

    h, pushes, logged, answer, clock = pushing
    pinned = tmp_path / "pwsh.exe"
    pinned.write_text("")
    ran = []
    monkeypatch.setattr("workerhost.host.PWSH_PATHS", (str(pinned),))
    monkeypatch.setattr("workerhost.host.shutil.which", lambda name: "C:\\Users\\x\\bin\\pwsh.exe")
    monkeypatch.setattr("workerhost.host.subprocess.run",
                        lambda cmd, **k: ran.append(cmd[0]) or sp.CompletedProcess(cmd, 0, "7.6.10\n", ""))
    assert h.pwsh_version() == "7.6.10" and ran == [str(pinned)]


def test_a_history_sample_is_small_and_uses_the_bus_clock():
    s = hoststatus.sample(hoststatus.build_v2(V2), RECEIVED_AT)
    assert s["received_at"] == RECEIVED_AT and s["workers"] == {"busy": 2, "max": 12}
    assert len(json.dumps(s, separators=(",", ":"))) < 400


def test_v2_never_carries_a_task_id_path_or_secret_and_is_under_the_cap():
    run = {"slot": "w01", "engine": "ghcp", "model": "m", "minutes": 1, "task_id": "abc", "log": "C:\\x\\log.txt"}
    snap = hoststatus.build_v2(replace(V2, running=[run] * 24))
    text = json.dumps(snap)
    assert "task_id" not in text and "abc" not in text and "\\" not in text and "token" not in text
    assert hoststatus.body(snap) is snap and len(text) < 8000  # 24 workers, still well under 16 KB
    with pytest.raises(ValueError):
        hoststatus.body({"x": "y" * 20000})


@pytest.fixture
def pushing(tmp_path, monkeypatch):
    """A real Host whose bus records each status push and answers with the code the test sets."""
    from conftest import HOST_A, FakeVault, SharedBus
    from workerhost import engines as engines_mod
    from workerhost import resources
    from workerhost.config import Config
    from workerhost.host import Host

    monkeypatch.setattr(resources, "sample", lambda root: None)
    monkeypatch.setattr(engines_mod, "resolve", lambda name: "C:\\bin\\copilot.exe")
    bus = SharedBus().client(HOST_A)
    h = Host(Config(host_name="box1", agent_prefix="host-box1", home=tmp_path / "home", workers_root=tmp_path / "w"),
             bus=bus, vault=FakeVault())
    h.pins = {"host": HOST_A, "coordinator": HOST_A}
    pushes, logged, answer = [], [], {"code": 201}

    def call(method, path, body=None, **k):
        if isinstance(answer["code"], Exception):
            raise answer["code"]
        pushes.append((method, path, body))
        return answer["code"], None

    bus.call = call
    h.log = lambda event, **k: logged.append((event, k))
    clock = {"t": 1_800_000_000.0}
    monkeypatch.setattr("workerhost.host.time.time", lambda: clock["t"])
    return h, pushes, logged, answer, clock


def test_the_host_pushes_its_v2_snapshot_as_itself_every_minute_and_on_a_change(pushing):
    h, pushes, logged, answer, clock = pushing
    h.push_status_if_due()
    assert [(m, p) for m, p, _ in pushes] == [("POST", "/api/hosts/status")]
    assert pushes[0][2]["v"] == 2 and pushes[0][2]["host"] == "box1" and "account" in pushes[0][2]
    clock["t"] += 30
    h.push_status_if_due()
    assert len(pushes) == 1  # nothing changed and not a minute yet
    h.st.data["paused"] = True
    clock["t"] += 5
    h.push_status_if_due()
    assert len(pushes) == 2 and pushes[-1][2]["state"] == "paused"  # a change goes at once...
    h.st.data["paused"] = False
    clock["t"] += 3
    h.push_status_if_due()
    assert len(pushes) == 2  # ...but never more than once in 10 s (the bus's limit)
    clock["t"] += 60
    h.push_status_if_due()
    assert len(pushes) == 3
    assert not logged


@pytest.mark.parametrize("code", [404, 403, 422])
def test_a_refusal_is_logged_once_and_retried_hourly_so_a_host_is_ready_before_its_bus(pushing, code):
    h, pushes, logged, answer, clock = pushing
    answer["code"] = code
    h.push_status_if_due()
    assert logged == [("status-push-refused", {"status": code})]
    clock["t"] += 3599
    h.push_status_if_due()
    assert len(pushes) == 1  # backed off for an hour
    clock["t"] += 2
    h.push_status_if_due()
    assert len(pushes) == 2 and len(logged) == 1  # tried again; the same refusal is not logged again
    answer["code"] = 201
    clock["t"] += 3601
    h.push_status_if_due()
    assert logged[-1] == ("status-push-ok", {"after": code}) and h.push_refused is None


def test_a_busy_bus_and_an_unreachable_one_are_not_refusals(pushing):
    h, pushes, logged, answer, clock = pushing
    answer["code"] = 429
    h.push_status_if_due()
    clock["t"] += 61
    h.push_status_if_due()
    assert len(pushes) == 2 and not logged  # 429: a minute's pause, no log
    answer["code"] = OSError("unreachable")
    clock["t"] += 61
    h.push_status_if_due()
    assert logged == [("status-push-failed", {"error": "OSError"})] and h.push_after < clock["t"]


def test_task_totals_count_only_this_host_processes_tasks(pushing):
    h, pushes, logged, answer, clock = pushing
    h.st.data["tasks"] = {
        "old": {"status": "finished", "updated": h.started_at - 1},   # ended before this process started
        "a": {"status": "finished", "updated": h.started_at + 1},
        "b": {"status": "refused", "updated": h.started_at + 2},
        "c": {"status": "started", "updated": h.started_at + 3},       # still running: not a total
    }
    h.push_status_if_due()
    assert pushes[0][2]["tasks"] == {"finished": 1, "failed": 0, "timed-out": 0, "interrupted": 0, "refused": 1,
                                     "yielded": 0, "cancelled": 0}


@pytest.fixture
def events_host(pushing, tmp_path):
    """The pushing host, with the real EventLog (so its lines become queued events)."""
    from workerhost import hostevents

    h, pushes, logged, answer, clock = pushing
    h.log = hostevents.EventLog(tmp_path / "evlogs", tmp_path / "evstate")
    return h, pushes, answer, clock


def event_calls(pushes):
    return [body for _, path, body in pushes if path == "/api/hosts/events"]


def test_queued_events_go_to_the_bus_and_leave_the_queue_once_stored(events_host):
    h, pushes, answer, clock = events_host
    for _ in range(25):
        h.log("pressure")
    h.push_events_if_due()
    (first,) = event_calls(pushes)
    assert first["agent"] == "host-box1-host" and len(first["events"]) == 20 and first["v"] == 1
    assert len(h.log.events.load()) == 5
    clock["t"] += 2
    h.push_events_if_due()
    assert len(event_calls(pushes)) == 1  # at most one call per 5 s
    clock["t"] += 5
    h.push_events_if_due()
    assert len(event_calls(pushes)) == 2 and h.log.events.load() == []


def test_a_bus_without_the_route_keeps_the_events_and_tries_hourly(events_host):
    h, pushes, answer, clock = events_host
    h.log("task-refused", reason="memory-high")
    answer["code"] = 404
    h.push_events_if_due()
    assert len(h.log.events.load()) == 1 and h.events_refused == 404
    clock["t"] += 600
    h.push_events_if_due()
    assert len(event_calls(pushes)) == 1  # backed off
    answer["code"] = 201
    clock["t"] += 3600
    h.push_events_if_due()
    assert len(event_calls(pushes)) == 2 and h.log.events.load() == [] and h.events_refused is None


def test_a_batch_the_bus_can_never_store_is_dropped_not_retried_forever(events_host):
    h, pushes, answer, clock = events_host
    h.log("pressure")
    answer["code"] = 400
    h.push_events_if_due()
    assert h.log.events.load() == []


def test_a_change_of_problem_is_raised_and_cleared_once(events_host):
    h, pushes, answer, clock = events_host
    h.track_problem()
    assert h.log.events.load() == []  # no problem
    h.channel_state = "missing"
    clock["t"] += 11
    h.track_problem()
    clock["t"] += 11
    h.track_problem()
    h.channel_state = "ok"
    clock["t"] += 11
    h.track_problem()
    assert [(e["type"], e.get("code")) for e in h.log.events.load()] == [
        ("problem-raised", "channel-missing"), ("problem-cleared", "channel-missing")]


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
