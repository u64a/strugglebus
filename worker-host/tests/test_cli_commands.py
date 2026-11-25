"""The `wh` commands (workerhost/cli.py), each with the host running and not running. Nothing here starts a host,
touches the scheduled task, reaches the bus or stores a real credential: those edges are faked and recorded."""
from __future__ import annotations

import io
import json
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from workerhost import cli, config, creds, ghcp, update, winapi
from workerhost.busclient import BusError
from workerhost.state import StateStore, take_controls

COORD_ID = "11111111-1111-4111-8111-111111111111"
HOST_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SPN = "sbsp1_" + "7f3e" * 10


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('host_name = "dry"\nagent_prefix = "host-test"\n'
                                      'scheduled_task = "TestHostTask"\n', encoding="utf-8")
    monkeypatch.setenv("WORKERHOST_HOME", str(home))
    return config.load()


@pytest.fixture
def schtasks(monkeypatch):
    """Every schtasks call, as its arguments; each returns 0 unless the test sets `code`."""
    calls = NS(args=[], code=0)

    def fake(cfg, *args):
        calls.args.append(args)
        return calls.code

    monkeypatch.setattr(cli, "_schtasks", fake)
    return calls


def running(cfg, monkeypatch, **over) -> dict:
    status = {"pid": 4321, "updated": time.time(), "heartbeat_line": "host=dry state=idle workers=0/2",
              "channel": "worker-hosts", "channel_state": "ok", "bus_state": "ok", "paused": False,
              "game_paused": False, "outbox": 0, "workers": [], "held_clones": [], "held_reasons": {}}
    status.update(over)
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    (cfg.state_dir / "status.json").write_text(json.dumps(status), encoding="utf-8")
    monkeypatch.setattr(winapi, "pid_alive", lambda pid: pid == 4321)
    return status


def controls(cfg) -> list[tuple[str, dict]]:
    return [(c["cmd"], c["args"]) for c in take_controls(cfg.control_dir)]


def state(cfg) -> dict:
    return StateStore(cfg.state_dir).load()


# --- start, stop, drain, pause, resume ------------------------------------------------------------------------------

def test_start_enables_and_runs_the_scheduled_task(cfg, schtasks, capsys):
    StateStore(cfg.state_dir).update(lambda d: d.update(enabled=False, draining=True))
    assert cli.cmd_start(cfg, None) == 0
    assert (state(cfg)["enabled"], state(cfg)["draining"]) == (True, False)
    assert schtasks.args == [("/Change", "/ENABLE"), ("/Run",)]
    assert "scheduled task enabled and started" in capsys.readouterr().out


def test_start_reports_a_task_that_would_not_run(cfg, schtasks, capsys):
    schtasks.code = 5
    assert cli.cmd_start(cfg, None) == 5
    assert "could not start the scheduled task (5)" in capsys.readouterr().out


def test_start_leaves_a_running_host_alone(cfg, schtasks, monkeypatch, capsys):
    running(cfg, monkeypatch)
    assert cli.cmd_start(cfg, None) == 0
    assert schtasks.args == [] and "host already running" in capsys.readouterr().out


def test_start_without_a_scheduled_task_launches_the_supervisor(cfg, monkeypatch, capsys):
    cfg.scheduled_task = ""
    launched = []
    monkeypatch.setattr(cli.subprocess, "Popen", lambda cmd, **kw: launched.append(cmd))
    assert cli.cmd_start(cfg, None) == 0
    assert launched and launched[0][-3:] == ["--home", str(cfg.home), "supervise"]
    assert "no scheduled task configured" in capsys.readouterr().out


def test_stop_with_no_host_disables_it_for_the_next_boot(cfg, schtasks, capsys):
    assert cli.cmd_stop(cfg, None) == 0
    assert (state(cfg)["enabled"], state(cfg)["draining"]) == (False, False)
    assert schtasks.args == [("/End",), ("/Change", "/DISABLE")]
    assert "until `wh start`" in capsys.readouterr().out


def test_stop_asks_a_running_host_and_does_not_kill_one_that_stops(cfg, schtasks, monkeypatch):
    running(cfg, monkeypatch)
    killed = []
    monkeypatch.setattr(winapi, "terminate_pid", killed.append)
    monkeypatch.setattr(cli, "_wait_until", lambda pred, seconds: True)
    assert cli.cmd_stop(cfg, None) == 0
    assert controls(cfg) == [("stop", {})] and killed == []


def test_stop_kills_a_host_that_does_not_stop_in_30_seconds(cfg, schtasks, monkeypatch, capsys):
    running(cfg, monkeypatch)
    killed = []
    monkeypatch.setattr(winapi, "terminate_pid", killed.append)
    monkeypatch.setattr(cli, "_wait_until", lambda pred, seconds: False)
    assert cli.cmd_stop(cfg, None) == 0
    assert killed == [4321] and state(cfg)["enabled"] is False
    assert "process killed" in capsys.readouterr().out


def test_wait_until_returns_as_soon_as_the_condition_holds():
    assert cli._wait_until(lambda: True, 5)
    assert not cli._wait_until(lambda: False, 0)


def test_drain_with_no_host_disables_it(cfg, schtasks, capsys):
    assert cli.cmd_drain(cfg, None) == 0
    assert state(cfg)["enabled"] is False and schtasks.args == [("/Change", "/DISABLE")]
    assert "host not running; disabled" in capsys.readouterr().out


def test_drain_asks_a_running_host(cfg, schtasks, monkeypatch):
    running(cfg, monkeypatch)
    assert cli.cmd_drain(cfg, None) == 0
    assert controls(cfg) == [("drain", {})] and schtasks.args == []


@pytest.mark.parametrize("cmd,flag", [(cli.cmd_pause, True), (cli.cmd_resume, False)])
def test_pause_and_resume_are_recorded_when_no_host_runs(cfg, cmd, flag, capsys):
    assert cmd(cfg, None) == 0
    assert state(cfg)["paused"] is flag
    assert "recorded for its next start" in capsys.readouterr().out


@pytest.mark.parametrize("cmd,name", [(cli.cmd_pause, "pause"), (cli.cmd_resume, "resume")])
def test_pause_and_resume_go_to_a_running_host(cfg, monkeypatch, cmd, name):
    running(cfg, monkeypatch)
    assert cmd(cfg, None) == 0
    assert controls(cfg) == [(name, {})]


# --- status, set-model, cleanup, update-ghcp ------------------------------------------------------------------------

def test_status_of_a_running_host_shows_workers_holds_fleet_and_strays(cfg, monkeypatch, capsys):
    running(cfg, monkeypatch, workers=[{"worker": "core14", "task_id": "t1", "model": "gpt-5.5", "minutes": 7,
                                        "log": "core14.log"}],
            held_clones=["core3", "core9"], held_reasons={"core3": "git-failed"},
            fleet={"label": "fleet serial 4", "coordinators": ["coord-main"], "hosts": ["host-a"]},
            strays=["notes-tmp"])
    assert cli.cmd_status(cfg, NS(post=True)) == 0
    out = capsys.readouterr().out
    assert "host=dry state=idle" in out and "logon=Password task=TestHostTask" in out
    assert "core14" in out and "model=gpt-5.5 7 min" in out
    assert "held clones: core3 (git-failed), core9" in out
    assert "fleet: fleet serial 4  coordinators: coord-main  hosts: host-a" in out
    assert "not clones" in out and "notes-tmp" in out
    assert controls(cfg) == [("status", {})]


def test_status_of_a_stopped_host_shows_its_flags(cfg, capsys):
    assert cli.cmd_status(cfg, NS(post=False)) == 1
    assert "host not running (enabled=" in capsys.readouterr().out


def test_set_model_refuses_a_model_outside_the_allowed_list(cfg, capsys):
    assert cli.cmd_set_model(cfg, NS(model="no-such-model")) == 2
    assert "does not match models.allowed" in capsys.readouterr().out


def test_set_model_goes_to_a_running_host_or_is_recorded(cfg, monkeypatch):
    model = "gpt-5.5"
    monkeypatch.setattr("workerhost.models.is_allowed", lambda m, allowed, denied: True)
    assert cli.cmd_set_model(cfg, NS(model=model)) == 0
    assert state(cfg)["default_model"] == model
    running(cfg, monkeypatch)
    assert cli.cmd_set_model(cfg, NS(model=model)) == 0
    assert controls(cfg) == [("set-model", {"model": model})]


class FakeHost:
    calls: list = []

    def __init__(self, cfg, **kw):
        pass

    def run_cleanup(self, dry_run, budget):
        FakeHost.calls.append((dry_run, budget))
        return {"deleted": ["core1"], "would_delete": [], "held": ["core2 (dirty)"], "failed": [],
                "strays": ["junk"], "clones": 5, "deferred": 2}


def test_cleanup_with_no_host_sweeps_everything_now(cfg, monkeypatch, capsys):
    FakeHost.calls = []
    monkeypatch.setattr(cli, "Host", FakeHost)
    assert cli.cmd_cleanup(cfg, NS(dry_run=False)) == 0
    assert FakeHost.calls == [(False, False)]  # no time budget: nothing waits on it
    out = capsys.readouterr().out
    assert "deleted: core1" in out and "held: core2 (dirty)" in out and "stray: junk" in out
    assert "clones on disk: 5" in out and "deferred to the next sweep (time budget): 2" in out


def test_cleanup_goes_to_a_running_host_but_a_dry_run_is_done_here(cfg, monkeypatch):
    FakeHost.calls = []
    monkeypatch.setattr(cli, "Host", FakeHost)
    running(cfg, monkeypatch)
    assert cli.cmd_cleanup(cfg, NS(dry_run=False)) == 0
    assert controls(cfg) == [("cleanup", {})] and FakeHost.calls == []
    assert cli.cmd_cleanup(cfg, NS(dry_run=True)) == 0
    assert FakeHost.calls == [(True, True)]


def test_update_ghcp_waits_for_workers_unless_asked_to(cfg, monkeypatch, capsys):
    running(cfg, monkeypatch, workers=[{"worker": "core1"}])
    assert cli.cmd_update_ghcp(cfg, NS(when_idle=False)) == 1
    assert "use --when-idle" in capsys.readouterr().out
    assert cli.cmd_update_ghcp(cfg, NS(when_idle=True)) == 0
    assert controls(cfg) == [("update-ghcp", {"when_idle": True})]


@pytest.mark.parametrize("ok,code", [(True, 0), (False, 1)])
def test_update_ghcp_with_no_host_updates_here(cfg, monkeypatch, capsys, ok, code):
    monkeypatch.setattr(ghcp, "update", lambda exe, backup, winget_id: NS(ok=ok, line="copilot: 1.0.1 -> 1.0.2"))
    assert cli.cmd_update_ghcp(cfg, NS(when_idle=False)) == code
    assert "1.0.1 -> 1.0.2" in capsys.readouterr().out


# --- enrol and pin --------------------------------------------------------------------------------------------------

class FakeStore:
    saved: dict = {}
    spn = None

    def __init__(self, folder=None):
        pass

    def has(self, name):
        return name in FakeStore.saved

    def save(self, name, record):
        FakeStore.saved[name] = record

    def load(self, name):
        return FakeStore.saved[name]

    def has_spn(self):
        return FakeStore.spn is not None

    def save_spn(self, spn):
        FakeStore.spn = spn

    def load_spn(self):
        return FakeStore.spn


@pytest.fixture
def enrol(cfg, monkeypatch):
    """A fake credential store and bus. `bus.coordinators` is what a coordinator lookup finds; `bus.onboard` is the
    onboarding result (a record, or an exception to raise)."""
    FakeStore.saved, FakeStore.spn = {}, None
    monkeypatch.setattr(creds, "Store", FakeStore)
    bus = NS(onboard={"agent_id": HOST_ID, "agent_name": cfg.host_agent, "secret": "s3cret", "base_url": "x"},
             coordinators=set(), bootstrap_error=None, answers=[])

    def onboard(b, spn, name, description):
        if isinstance(bus.onboard, Exception):
            raise bus.onboard
        return bus.onboard

    def bootstrap(b, record, channels):
        if bus.bootstrap_error:
            raise bus.bootstrap_error
        return ["joined worker-hosts"]

    monkeypatch.setattr(cli, "onboard", onboard)
    monkeypatch.setattr(cli, "bootstrap", bootstrap)
    monkeypatch.setattr(cli, "Bus", lambda *a, **k: NS())
    monkeypatch.setattr(cli, "_lookup_coordinator", lambda b, name, channels=("Notes",): set(bus.coordinators))
    monkeypatch.setattr("builtins.input", lambda prompt: bus.answers.pop(0))
    return bus


def enrol_args(**over):
    a = dict(import_identity=None, spn_stdin=True, coordinator_id=None)
    a.update(over)
    return NS(**a)


def pins(cfg) -> dict:
    return json.loads((cfg.state_dir / "pins.json").read_text(encoding="utf-8"))


def test_enrol_stores_the_identity_pins_it_and_the_coordinator_given(cfg, enrol, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(SPN + "\n"))
    assert cli.cmd_enrol(cfg, enrol_args(coordinator_id=COORD_ID)) == 0
    out = capsys.readouterr().out
    assert FakeStore.spn == SPN and FakeStore.saved[cfg.host_agent]["agent_id"] == HOST_ID
    assert pins(cfg)["host"]["agent_id"] == HOST_ID and pins(cfg)["coordinator"]["agent_id"] == COORD_ID
    assert "joined worker-hosts" in out and "coordinator pinned" in out and SPN not in out


@pytest.mark.parametrize("answer,pinned", [("y", True), ("n", False)])
def test_enrol_offers_the_one_coordinator_it_finds(cfg, enrol, monkeypatch, capsys, answer, pinned):
    monkeypatch.setattr("sys.stdin", io.StringIO(SPN + "\n"))
    enrol.coordinators, enrol.answers = {COORD_ID}, [answer]
    assert cli.cmd_enrol(cfg, enrol_args()) == 0
    assert ("coordinator" in pins(cfg)) is pinned
    assert ("NOT pinned" in capsys.readouterr().out) is not pinned


def test_enrol_does_not_guess_between_two_coordinators(cfg, enrol, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(SPN + "\n"))
    enrol.coordinators = {COORD_ID, "22222222-2222-4222-8222-222222222222"}
    assert cli.cmd_enrol(cfg, enrol_args()) == 0
    assert "coordinator NOT pinned" in capsys.readouterr().out


def test_enrol_carries_on_when_the_bootstrap_is_incomplete(cfg, enrol, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(SPN + "\n"))
    enrol.bootstrap_error = BusError(503, "busy")
    assert cli.cmd_enrol(cfg, enrol_args(coordinator_id=COORD_ID)) == 0
    assert "bootstrap incomplete (503); the host retries on start" in capsys.readouterr().out


def test_enrol_refuses_to_re_enrol(cfg, enrol, capsys):
    FakeStore.saved[cfg.host_agent] = {"secret": "x"}
    assert cli.cmd_enrol(cfg, enrol_args()) == 1
    assert "refusing to re-enrol" in capsys.readouterr().out


def test_enrol_refuses_something_that_is_not_an_spn(cfg, enrol, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("password123\n"))
    assert cli.cmd_enrol(cfg, enrol_args()) == 1
    assert FakeStore.spn is None and "does not look like an SPN credential" in capsys.readouterr().out


def test_enrol_that_cannot_reach_the_bus_stores_nothing(cfg, enrol, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(SPN + "\n"))
    cfg.creds_dir.mkdir(parents=True, exist_ok=True)
    (cfg.creds_dir / "spn.bin").write_bytes(b"x")
    enrol.onboard = OSError("unreachable")
    assert cli.cmd_enrol(cfg, enrol_args()) == 1
    assert not (cfg.creds_dir / "spn.bin").exists() and cfg.host_agent not in FakeStore.saved
    assert "could not reach the bus (OSError); nothing stored" in capsys.readouterr().out


def test_enrol_can_adopt_an_existing_identity_file(cfg, enrol, tmp_path, capsys):
    f = tmp_path / "identity.json"
    f.write_text(json.dumps({"agent_id": HOST_ID, "agent_name": "host-test-host", "secret": "s", "extra": 1}))
    assert cli.cmd_enrol(cfg, enrol_args(import_identity=str(f), coordinator_id=COORD_ID)) == 0
    assert set(FakeStore.saved[cfg.host_agent]) == {"agent_id", "agent_name", "secret", "base_url"}
    assert "adopted identity host-test-host" in capsys.readouterr().out


@pytest.mark.parametrize("content", ['{"agent_id": "x"}', "not json"])
def test_enrol_refuses_a_file_that_is_not_an_identity(cfg, enrol, tmp_path, capsys, content):
    f = tmp_path / "identity.json"
    f.write_text(content)
    assert cli.cmd_enrol(cfg, enrol_args(import_identity=str(f))) == 1
    assert "not a bus identity record" in capsys.readouterr().out and FakeStore.saved == {}


def test_lookup_coordinator_collects_its_ids_and_survives_a_bus_error():
    msgs = [{"agent_name": "coord", "agent_id": COORD_ID}, {"agent_name": "other", "agent_id": HOST_ID},
            {"agent_name": "coord", "agent_id": None}]

    class Bus:
        def newest_seq(self, channel):
            if channel == "broken":
                raise BusError(500, "")
            return 2000

        def read_all(self, channel, since):
            assert since == 1000
            return msgs

    assert cli._lookup_coordinator(Bus(), "coord", ("broken", "Notes")) == {COORD_ID}


def test_pin_takes_only_a_uuid(cfg, capsys):
    assert cli.cmd_pin(cfg, NS(coordinator_id="Not-A-UUID")) == 2
    assert cli.cmd_pin(cfg, NS(coordinator_id=COORD_ID)) == 0
    assert pins(cfg)["coordinator"]["agent_id"] == COORD_ID


# --- fleet ----------------------------------------------------------------------------------------------------------

class FakeSync:
    def __init__(self, kept=None, accepted=None):
        self.kept, self._accepted, self.refreshed = kept, accepted or {}, 0

    def load_last_good(self):
        return self.kept

    def accepted(self):
        return self._accepted

    def refresh(self, current, bus=None, source="git"):
        self.refreshed += 1
        return NS(status="unchanged", commit="c" * 40, detail="")


def test_fleet_status_before_any_fleet(cfg, monkeypatch, capsys):
    sync = FakeSync()
    monkeypatch.setattr(cli, "_fleet_sync", lambda c: sync)
    assert cli.cmd_fleet_status(cfg, NS(refresh=True)) == 0
    out = capsys.readouterr().out
    assert sync.refreshed == 1 and "refresh (git): unchanged commit=cccccccccccc" in out
    assert "pinned signers: NONE" in out and "none accepted yet" in out


def test_fleet_status_when_the_kept_copy_no_longer_verifies(cfg, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_fleet_sync", lambda c: FakeSync(accepted={"signer": "alice"}))
    assert cli.cmd_fleet_status(cfg, NS(refresh=False)) == 0
    assert "UNAVAILABLE" in capsys.readouterr().out


def test_fleet_status_lists_the_kept_fleet_and_sends_a_refresh_to_a_running_host(cfg, monkeypatch, capsys):
    coord = NS(agent_name="coord-main", project="app", default_engine="ghcp",
               notes_repo="https://github.com/o/notes", notes_channel="Notes", repos=["https://github.com/o/"],
               worker_rules="one\ntwo", repo_instructions=True)
    kept = NS(serial=3, commit="d" * 40, coordinators=[coord], hosts=[NS(agent_name="host-a", agent_id=HOST_ID)],
              ignored_keys=["future_key"])
    sync = FakeSync(kept, {"signer": "alice"})
    monkeypatch.setattr(cli, "_fleet_sync", lambda c: sync)
    running(cfg, monkeypatch)
    assert cli.cmd_fleet_status(cfg, NS(refresh=True)) == 0
    out = capsys.readouterr().out
    assert controls(cfg) == [("fleet-refresh", {})] and sync.refreshed == 0
    assert "fleet: serial 3, commit dddddddddddd, signed by alice" in out
    assert "worker rules: 2 line(s)" in out and HOST_ID in out and "future_key" in out


def test_signer_lines_list_the_pinned_signers(cfg, monkeypatch):
    signer = NS(fingerprint="SHA256:abc", comment="alice", namespaces="strugglebus-fleet")
    monkeypatch.setattr(cli.signing, "read_signers", lambda path: [signer])
    assert cli.signer_lines(cfg)[1] == "  SHA256:abc  alice  [strugglebus-fleet]"


def fleet_entry_args(**over):
    a = dict(host=False, coordinator=None, project=None, notes_repo=None, notes_channel=None, repos=None,
             engine="ghcp", agent_id=None)
    a.update(over)
    return NS(**a)


COORD_ENTRY = dict(coordinator="coord-main", project="app", notes_repo="https://github.com/o/notes",
                   notes_channel="Notes", repos=["https://github.com/o/"])


def test_fleet_entry_for_this_host(cfg, capsys):
    assert cli.cmd_fleet_entry(cfg, fleet_entry_args(host=True)) == 1
    assert "run wh enrol first" in capsys.readouterr().out
    cli.save_pins(cfg, host=cli.Pin(HOST_ID, cfg.host_agent))
    assert cli.cmd_fleet_entry(cfg, fleet_entry_args(host=True)) == 0
    assert capsys.readouterr().out == (f'[[host]]\nagent_name = "{cfg.host_agent}"\nagent_id   = "{HOST_ID}"\n')


def test_fleet_entry_for_a_coordinator_needs_every_field(cfg, capsys):
    assert cli.cmd_fleet_entry(cfg, fleet_entry_args(coordinator="c")) == 2
    assert "wh fleet entry --coordinator" in capsys.readouterr().out


def test_fleet_entry_for_a_coordinator_with_its_id(cfg, capsys):
    assert cli.cmd_fleet_entry(cfg, fleet_entry_args(agent_id=COORD_ID, **COORD_ENTRY)) == 0
    out = capsys.readouterr().out
    assert out.startswith("[[coordinator]]") and f'agent_id       = "{COORD_ID}"' in out


def test_fleet_entry_refuses_an_entry_that_would_not_be_valid(cfg, capsys):
    bad = dict(COORD_ENTRY, repos=["not a url"])
    assert cli.cmd_fleet_entry(cfg, fleet_entry_args(agent_id=COORD_ID, **bad)) == 1
    assert "would not be valid" in capsys.readouterr().out


def test_fleet_entry_looks_the_coordinator_up(cfg, monkeypatch, capsys):
    assert cli.cmd_fleet_entry(cfg, fleet_entry_args(**COORD_ENTRY)) == 1
    assert "no host credential" in capsys.readouterr().out
    FakeStore.saved, FakeStore.spn = {cfg.host_agent: {"secret": "s"}}, None
    monkeypatch.setattr(creds, "Store", FakeStore)
    monkeypatch.setattr(cli, "Bus", lambda *a, **k: NS())
    found = set()
    monkeypatch.setattr(cli, "_lookup_coordinator", lambda bus, name, channels: set(found))
    assert cli.cmd_fleet_entry(cfg, fleet_entry_args(**COORD_ENTRY)) == 1
    assert "found 0 agent_ids" in capsys.readouterr().out
    found.add(COORD_ID)
    assert cli.cmd_fleet_entry(cfg, fleet_entry_args(**COORD_ENTRY)) == 0
    assert COORD_ID in capsys.readouterr().out


# --- probe, update, supervise, main ---------------------------------------------------------------------------------

@pytest.fixture
def probe_env(cfg, monkeypatch):
    env = NS(copilot="1.0.114", runs_ok=True, dpapi_ok=True)
    monkeypatch.setattr(ghcp, "version", lambda exe: env.copilot)
    monkeypatch.setattr(cli.subprocess, "run", lambda cmd, **kw: NS(returncode=0 if env.runs_ok else 1))

    def protect(data):
        if not env.dpapi_ok:
            raise OSError("no profile")
        return data

    monkeypatch.setattr(winapi, "dpapi_protect", protect)
    monkeypatch.setattr(winapi, "dpapi_unprotect", lambda data: data)
    monkeypatch.setattr(creds, "Store", FakeStore)
    FakeStore.saved, FakeStore.spn = {}, None
    cfg.bus_url, cfg.vault_repo, cfg.fleet_repo = "https://bus.example.lan", "acme/notes", "acme/fleet"
    return env


def test_probe_fails_on_a_missing_site_value_and_says_what_is_off(cfg, probe_env, tmp_path, capsys):
    cfg.bus_url, cfg.vault_repo, cfg.fleet_repo = "", "", ""
    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    cfg.bus_ca = str(ca)
    assert cli.cmd_probe(cfg, NS(out=None)) == 1
    out = capsys.readouterr().out
    assert "FAIL bus_url set" in out and "info fleet_repo: none" in out
    assert "ls-remote of the vault" not in out  # no notes repository configured, so nothing to check


def test_probe_passes_when_every_check_does(cfg, probe_env, tmp_path, capsys):
    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    cfg.bus_ca = str(ca)
    out_file = tmp_path / "probe.txt"
    assert cli.cmd_probe(cfg, NS(out=str(out_file))) == 0
    out = capsys.readouterr().out
    assert "FAIL" not in out and "ok   copilot --version (1.0.114)" in out
    assert "host identity: no (run wh enrol)" in out and "signers pinned: none" in out
    assert out_file.read_text(encoding="utf-8").strip() == out.strip()


def test_probe_fails_on_any_failed_check(cfg, probe_env, capsys):
    probe_env.copilot, probe_env.runs_ok, probe_env.dpapi_ok = None, False, False
    cfg.bus_ca = ""
    assert cli.cmd_probe(cfg, NS(out=None)) == 1
    out = capsys.readouterr().out
    for name in ("copilot --version (?)", "gh auth status", "git ls-remote of the vault", "bus CA file",
                 "DPAPI (user profile loaded)"):
        assert f"FAIL {name}" in out


def test_update_status_shows_what_is_installed_and_in_progress(cfg, capsys):
    (cfg.state_dir).mkdir(parents=True, exist_ok=True)
    (cfg.state_dir / "update.json").write_text(json.dumps({"phase": "staged", "from_version": "a", "version": "b",
                                                           "rejected": [7]}), encoding="utf-8")
    assert cli.cmd_update(cfg, NS(update_cmd=None)) == 0
    out = capsys.readouterr().out
    assert "installed: " in out and "update: staged a -> b" in out and "serial 7" in out


@pytest.mark.parametrize("which,control", [("check", "update-check"), ("now", "update-now")])
def test_update_check_and_now_go_to_a_running_host(cfg, monkeypatch, which, control):
    running(cfg, monkeypatch)
    assert cli.cmd_update(cfg, NS(update_cmd=which)) == 0
    assert controls(cfg) == [(control, {})]


def test_update_now_needs_a_running_host(cfg, capsys):
    assert cli.cmd_update(cfg, NS(update_cmd="now")) == 1
    assert "start it (wh start)" in capsys.readouterr().out


@pytest.mark.parametrize("serial,code,word", [(None, 1, "release (fleet): unsigned"), (10 ** 6, 0, "NEWER")])
def test_update_check_with_no_host_reads_the_signed_release(cfg, monkeypatch, capsys, serial, code, word):
    monkeypatch.setattr(cli, "_fleet_sync", lambda c: FakeSync())
    rel = None if serial is None else update.Release(serial, "2099.01.01", "e" * 40, "f" * 64, True, "n")

    class Source:
        def __init__(self, *a, **k):
            pass

        def read(self):
            return rel, "unsigned"

    monkeypatch.setattr(update, "ReleaseSource", Source)
    assert cli.cmd_update(cfg, NS(update_cmd="check")) == code
    out = capsys.readouterr().out
    assert word in out
    if serial:
        assert "needs install.ps1 by hand" in out


def test_supervise_refuses_a_second_supervisor(cfg, monkeypatch):
    monkeypatch.setattr(winapi, "IS_WINDOWS", True)

    def taken(name):
        raise OSError("exists")

    monkeypatch.setattr(winapi, "single_instance", taken)
    assert cli.cmd_supervise(cfg, None) == 3


def test_supervise_runs_the_supervisor(cfg, monkeypatch):
    names = []
    monkeypatch.setattr(winapi, "single_instance", lambda name: names.append(name) or object())
    monkeypatch.setattr(cli, "Supervisor", lambda cfg, log: NS(run=lambda: 0))
    assert cli.cmd_supervise(cfg, None) == 0
    assert names[0].startswith("Global\\StrugglebusWorkerHostSupervisor-")


def test_supervise_logs_a_crash_and_re_raises_it(cfg, monkeypatch):
    monkeypatch.setattr(winapi, "single_instance", lambda name: object())

    def boom():
        raise RuntimeError("crash")

    monkeypatch.setattr(cli, "Supervisor", lambda cfg, log: NS(run=boom))
    with pytest.raises(RuntimeError):
        cli.cmd_supervise(cfg, None)
    assert "supervisor-fatal" in "".join(p.read_text(encoding="utf-8") for p in Path(cfg.logs_dir).rglob("*")
                                         if p.is_file())


def test_main_without_a_config_says_so(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    assert cli.main(["--home", str(tmp_path), "status"]) == 2
    assert "run install.ps1 first" in capsys.readouterr().out


def test_main_with_a_broken_config_says_so(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('host_name = "x"\nsurprise = 1\n', encoding="utf-8")
    assert cli.main(["--home", str(tmp_path), "status"]) == 2
    assert "config error" in capsys.readouterr().out


def test_main_dispatches_fleet_with_no_subcommand_to_status(cfg, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "cmd_fleet_status", lambda c, a: seen.append(a.refresh) or 0)
    assert cli.main(["--home", str(cfg.home), "fleet"]) == 0
    assert seen == [False]


def test_probe_passes_a_claude_only_host_without_copilot(cfg, probe_env, tmp_path, capsys, monkeypatch):
    from workerhost import engines as engines_mod
    from workerhost.engines import Claude

    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    cfg.bus_ca = str(ca)
    cfg.default_engine, cfg.claude = "claude", Claude()
    probe_env.copilot = None
    monkeypatch.setattr(engines_mod, "resolve", lambda name: "C:\\bin\\claude.exe")
    monkeypatch.setattr(engines_mod, "claude_signed_in", lambda home=None: True)
    assert cli.cmd_probe(cfg, NS(out=None)) == 0
    out = capsys.readouterr().out
    assert "info copilot --version: not installed" in out
    assert "ok   claude installed (yes) and signed in (yes)" in out
    monkeypatch.setattr(engines_mod, "claude_signed_in", lambda home=None: False)
    assert cli.cmd_probe(cfg, NS(out=None)) == 1
    assert "FAIL claude installed (yes) and signed in (no)" in capsys.readouterr().out
