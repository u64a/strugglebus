"""Issue #16: two tasks accepted in one poll, both claimed, both started after the settle window; and a
host loop that never dies silently (loop errors and fatal errors leave a traceback in the errors log)."""
from __future__ import annotations

import json
import os
import time

import pytest

from conftest import COORD, HOST_A, FakeVault, task_body
from workerhost import ghcp, launcher, resources, winapi
from workerhost.config import Config
from workerhost.host import Host

TASK_1 = "6f1c2b9e-4d3a-4b8e-9f20-1a2b3c4d5e6f"
TASK_2 = "7a2d3c0f-5e4b-4c9f-8a31-2b3c4d5e6f70"


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


class FakeProc:
    def __init__(self, pid):
        self.pid = pid

    def poll(self):
        return None


class FakeJob:
    def close(self):
        pass

    def terminate(self, code=1):
        pass


@pytest.fixture
def host(tmp_path, shared_bus, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(time, "time", clock)
    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(
        100 * resources.GB, 10 * resources.GB, 100 * resources.GB, 128 * resources.GB, 500 * resources.GB, set()))
    monkeypatch.setattr(winapi, "process_identity", lambda pid: None)
    monkeypatch.setattr(winapi, "boot_time", lambda: 0.0)
    launched = []

    def prepare_clone(root, worker, repo, branch, gh, git, require_clean=True):
        clone = root / worker
        clone.mkdir(parents=True, exist_ok=True)
        return clone

    def launch(cmd, clone, env, log, temp, worker, task_id, head, job=None, stdin_text=None):
        launched.append(task_id)
        return launcher.WorkerRun(worker, task_id, FakeProc(4000 + len(launched)), FakeJob(), log, temp)

    monkeypatch.setattr(launcher, "prepare_clone", prepare_clone)
    monkeypatch.setattr(launcher, "launch", launch)
    monkeypatch.setattr(launcher, "build", lambda *a, **k: ["copilot"])
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", poll_seconds=10, settle_seconds=20,
                 workers_root=tmp_path / "w", repos={"app-core": "acme/app-core"},
                 allowed_models=["claude-opus-5.5"], home=tmp_path / "home",
                 hosts=[{"agent_name": HOST_A.agent_name, "agent_id": HOST_A.agent_id}])
    vault = FakeVault()
    vault.referenced_files = lambda commit, text, brief: []
    h = Host(cfg, bus=shared_bus.client(HOST_A), vault=vault)
    h.pins = {"coordinator": COORD, "host": HOST_A}
    h.st.data["cursor"] = 0
    h.ensure_identity = lambda agent: None
    h.maintain = lambda: None  # no daily clean-up or ghcp update from a test
    h.clock, h.launched = clock, launched
    return h


def post_task(shared_bus, **over) -> int:
    seq = shared_bus.append(COORD, "question", json.dumps(task_body(**over)))
    shared_bus.messages[-1]["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return seq


def test_two_tasks_in_one_poll_are_both_claimed_and_both_started(host, shared_bus):
    post_task(shared_bus, task_id=TASK_1, worker="core14")
    post_task(shared_bus, task_id=TASK_2, worker="core15")
    host.tick()  # one poll: both accepted, both claims posted
    assert [p["body"]["type"] for p in host.bus.posts] == ["claim", "claim"]
    assert {r["status"] for r in host.st.data["tasks"].values()} == {"claimed"}
    host.clock.t += 21  # the settle window passes
    host.next_poll = 0
    host.tick()
    host.write_status()
    assert sorted(host.launched) == sorted([TASK_1, TASK_2])
    assert sorted(host.runs) == sorted([TASK_1, TASK_2])
    assert [p["body"]["type"] for p in host.bus.posts].count("started") == 2
    assert {host.st.data["tasks"][t]["status"] for t in (TASK_1, TASK_2)} == {"started"}
    log = "".join(p.read_text(encoding="utf-8") for p in host.cfg.logs_dir.glob("host-*.log"))
    assert "loop-error" not in log


def errors_log(h: Host) -> str:
    return "".join(p.read_text(encoding="utf-8") for p in h.cfg.logs_dir.glob("host-*.errors.log"))


def host_log(h: Host) -> str:
    return "".join(p.read_text(encoding="utf-8") for p in h.cfg.logs_dir.glob("host-*.log")
                   if not p.name.endswith(".errors.log"))


@pytest.mark.skipif(os.name != "nt", reason="the replace-over-an-open-file failure is Windows behaviour")
def test_run_survives_status_json_held_open_during_the_settle_window(host, shared_bus, monkeypatch):
    """The dev-machine sequence driven through run(): two claims in one poll, then status.json held open
    (as `wh status` reading it does) while the settle window runs out. Before #16 the os.replace in
    write_status raised PermissionError outside the loop's handler and the process exited 1 with no
    log line. Now it retries, logs `status-error` with the traceback if it still fails, and goes on."""
    post_task(shared_bus, task_id=TASK_1, worker="core14")
    post_task(shared_bus, task_id=TASK_2, worker="core15")
    monkeypatch.setattr(ghcp, "version", lambda exe: "1.0.0")
    held, ticks = {}, [0]

    def sleep(seconds):
        host.clock.t += seconds
        if seconds < 1:
            return  # a replace retry
        ticks[0] += 1
        status = host.cfg.state_dir / "status.json"
        if ticks[0] == 2:
            held["fh"] = open(status, "rb")  # noqa: SIM115 - a reader holding the file across ticks
        elif ticks[0] == 25 and "fh" in held:
            held.pop("fh").close()

    monkeypatch.setattr(time, "sleep", sleep)
    try:
        code = host.run(max_seconds=40)
    finally:
        if "fh" in held:
            held.pop("fh").close()
    assert code == 0
    assert sorted(host.launched) == sorted([TASK_1, TASK_2])
    assert {host.st.data["tasks"][t]["status"] for t in (TASK_1, TASK_2)} == {"started"}
    assert "status-error error=PermissionError" in host_log(host)
    assert "status-error PermissionError =====" in errors_log(host)
    assert "Traceback (most recent call last)" in errors_log(host)
    assert "host-exit why=max-seconds" in host_log(host)


def test_caught_loop_error_logs_type_message_and_traceback(host, shared_bus, monkeypatch):
    monkeypatch.setattr(ghcp, "version", lambda exe: "1.0.0")
    monkeypatch.setattr(time, "sleep", lambda s: setattr(host.clock, "t", host.clock.t + s))
    calls = [0]
    real = host.advance_claims

    def flaky():
        calls[0] += 1
        if calls[0] == 1:
            raise TypeError("boom in advance_claims")
        return real()

    host.advance_claims = flaky
    assert host.run(max_seconds=3) == 0
    log = host_log(host)
    assert "loop-error error=TypeError message=boom_in_advance_claims" in log
    errors = errors_log(host)
    assert errors.count("=====\nTraceback") == 1
    assert "loop-error TypeError =====" in errors and "TypeError: boom in advance_claims" in errors
    assert "in flaky" in errors  # the frame that raised is in the block


def test_fatal_error_is_logged_before_the_process_exits(host, monkeypatch):
    monkeypatch.setattr(ghcp, "version", lambda exe: "1.0.0")

    def broken():
        raise RuntimeError("recover failed")

    host.recover = broken
    with pytest.raises(RuntimeError):
        host.run(max_seconds=3)
    assert "fatal error=RuntimeError message=recover_failed" in host_log(host)
    errors = errors_log(host)
    assert "fatal RuntimeError =====" in errors and "RuntimeError: recover failed" in errors
