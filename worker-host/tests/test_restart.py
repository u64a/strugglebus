"""Issue #13: a terminal task survives a host restart; only a running task with a dead worker is `interrupted`."""
from __future__ import annotations

import json
import time

import pytest

from conftest import COORD, HOST_A, FakeVault
from workerhost import cleanup, resources, winapi
from workerhost.claim import ClaimSession
from workerhost.config import Config
from workerhost.host import Host

TASK_ID = "6f1c2b9e-4d3a-4b8e-9f20-1a2b3c4d5e6f"
TASK_SEQ = 500
PROC_ID = 133700000000000000


class RecordingBus:
    """Posts to the shared bus and records what state.json says about each task at the moment of the post."""

    def __init__(self, inner, state_path):
        self.inner, self.state_path = inner, state_path
        self.seen: list[tuple[str, str | None]] = []

    @property
    def posts(self):
        return self.inner.posts

    def post(self, channel, kind, text, reply_to=None):
        body = json.loads(text) if text.startswith("{") else {}
        try:
            tasks = json.loads(self.state_path.read_text(encoding="utf-8"))["tasks"]
        except FileNotFoundError:
            tasks = {}
        if body.get("task_id"):
            self.seen.append((body["type"], tasks.get(body["task_id"], {}).get("status")))
        return self.inner.post(channel, kind, text, reply_to)

    def __getattr__(self, name):
        return getattr(self.inner, name)


class FakeJob:
    def close(self):
        pass


class FakeRun:
    def __init__(self, tmp, session):
        self.worker, self.session, self.model = "core14", session, "claude-opus-5.5"
        self.started = self.last_output = time.time()
        self.job, self.temp, self.log = FakeJob(), tmp / "tmp-core14", tmp / "core14.log"
        self.warned = self.stalled = False
        self.killed = False

    def kill(self):
        self.killed = True

    def poll(self):
        return -1 if self.killed else None


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(
        100 * resources.GB, 10 * resources.GB, 100 * resources.GB, 128 * resources.GB, 500 * resources.GB, set()))
    monkeypatch.setattr(winapi, "boot_time", lambda: 0.0)  # no reboot since launch: cause is `restart`
    monkeypatch.setattr(winapi, "process_identity", lambda pid: None)  # every recorded worker is dead
    monkeypatch.setattr(cleanup, "unpushed", lambda clone, git_exe="git": "")
    monkeypatch.setattr(cleanup, "clean_after_finish", lambda *a, **k: (True, "clean", []))
    return Config(host_name="alpha", agent_prefix="host-alpha", poll_seconds=0, settle_seconds=0,
                  workers_root=tmp_path / "w", repos={"app-core": "acme/app-core"},
                  allowed_models=["claude-opus-5.5"], home=tmp_path / "home",
                  hosts=[{"agent_name": HOST_A.agent_name, "agent_id": HOST_A.agent_id}])


def make_host(cfg, shared_bus) -> Host:
    bus = RecordingBus(shared_bus.client(HOST_A), cfg.state_dir / "state.json")
    h = Host(cfg, bus=bus, vault=FakeVault())
    h.pins = {"coordinator": COORD, "host": HOST_A}
    return h


def running(h: Host, tmp_path) -> FakeRun:
    """A task as start() leaves it: `started` in state.json with pid and process identity, and a live run."""
    h.st.set_task(TASK_ID, status="started", seq=TASK_SEQ, worker="core14", digest="d" * 64, launched_at=time.time(),
                  pid=4242, proc_id=PROC_ID, resumed=0, by_stop=False)
    session = ClaimSession(h.bus, h.cfg.channel, h.cfg.host_name, TASK_SEQ, TASK_ID, "d" * 64, h.pinned_hosts(),
                           h.coordinators()[0], 0)
    run = FakeRun(tmp_path, session)
    h.runs[TASK_ID] = run
    return run


def replies(h: Host) -> list[dict]:
    return [p["body"] for p in h.bus.posts if isinstance(p["body"], dict) and p["body"].get("task_id") == TASK_ID]


def test_finished_task_is_not_reported_again_by_a_new_host(cfg, shared_bus, tmp_path):
    h = make_host(cfg, shared_bus)
    h.finish(TASK_ID, running(h, tmp_path), 0)
    assert [b["type"] for b in replies(h)] == ["finished"]

    h2 = make_host(cfg, shared_bus)
    h2.recover()
    assert replies(h2) == [] and h2.resumes == []
    assert h2.st.data["tasks"][TASK_ID]["status"] == "finished"


def test_crash_after_finished_post_still_leaves_the_task_terminal(cfg, shared_bus, tmp_path, monkeypatch):
    """The dev-machine case: `finished` posted, then the host died before end() completed."""
    def boom(*a, **k):
        raise OSError("clean-up failed")

    monkeypatch.setattr(cleanup, "clean_after_finish", boom)
    h = make_host(cfg, shared_bus)
    with pytest.raises(OSError):
        h.finish(TASK_ID, running(h, tmp_path), 0)

    h2 = make_host(cfg, shared_bus)
    h2.recover()
    assert replies(h2) == []


def test_running_task_with_dead_worker_gets_exactly_one_interrupted(cfg, shared_bus, tmp_path):
    h = make_host(cfg, shared_bus)
    running(h, tmp_path)

    h2 = make_host(cfg, shared_bus)
    h2.recover()
    out = replies(h2)
    assert len(out) == 1 and out[0]["type"] == "interrupted" and out[0]["cause"] == "restart"
    assert h2.bus.posts[-1]["reply_to"] == TASK_SEQ
    assert h2.bus.seen == [("interrupted", "interrupted")]  # state marked before the post

    h3 = make_host(cfg, shared_bus)
    h3.recover()
    assert replies(h3) == []


def test_live_worker_is_killed_then_interrupted_once(cfg, shared_bus, tmp_path, monkeypatch):
    killed = []
    monkeypatch.setattr(winapi, "process_identity", lambda pid: PROC_ID if pid == 4242 and not killed else None)
    monkeypatch.setattr(winapi, "terminate_pid", lambda pid, code=1: killed.append(pid) or True)
    h = make_host(cfg, shared_bus)
    running(h, tmp_path)

    h2 = make_host(cfg, shared_bus)
    h2.recover()
    assert killed == [4242]
    assert [(b["type"], b["cause"]) for b in replies(h2)] == [("interrupted", "restart")]


def test_reused_pid_is_not_killed(cfg, shared_bus, tmp_path, monkeypatch):
    killed = []
    monkeypatch.setattr(winapi, "process_identity", lambda pid: PROC_ID + 1)  # same pid, different start time
    monkeypatch.setattr(winapi, "terminate_pid", lambda pid, code=1: killed.append(pid) or True)
    h = make_host(cfg, shared_bus)
    running(h, tmp_path)

    h2 = make_host(cfg, shared_bus)
    h2.recover()
    assert killed == [] and [b["type"] for b in replies(h2)] == ["interrupted"]


def test_worker_that_cannot_be_killed_is_not_reported(cfg, shared_bus, tmp_path, monkeypatch):
    monkeypatch.setattr(winapi, "process_identity", lambda pid: PROC_ID)
    monkeypatch.setattr(winapi, "terminate_pid", lambda pid, code=1: False)
    h = make_host(cfg, shared_bus)
    running(h, tmp_path)

    h2 = make_host(cfg, shared_bus)
    h2.recover()
    assert replies(h2) == [] and h2.st.data["tasks"][TASK_ID]["status"] == "started"


@pytest.mark.parametrize("ending, kind", [("finish-0", "finished"), ("finish-1", "failed"),
                                          ("timeout", "timed-out"), ("stop", "interrupted")])
def test_terminal_mark_is_written_before_the_reply(cfg, shared_bus, tmp_path, ending, kind):
    h = make_host(cfg, shared_bus)
    run = running(h, tmp_path)
    if ending.startswith("finish"):
        h.finish(TASK_ID, run, int(ending[-1]))
    elif ending == "timeout":
        run.started = time.time() - cfg.runtime.max_runtime_hours * 3600 - 1
        h.supervise()
    else:
        h.stop_now()
    assert (kind, kind) in h.bus.seen
    assert all(status != "started" for _, status in h.bus.seen)

    h2 = make_host(cfg, shared_bus)
    h2.recover()
    assert replies(h2) == []


@pytest.mark.parametrize("status", ["claimed", "claiming"])
def test_claimed_but_never_started_task_yields_once_on_start_up(cfg, shared_bus, status):
    """Issue #16: the host died after posting two claims; on the next start the tasks sat `claimed` for
    ever. Now they are marked terminal first, then reported with a `yield`, exactly once."""
    h = make_host(cfg, shared_bus)
    h.st.set_task(TASK_ID, status=status, seq=TASK_SEQ, worker="core14", digest="d" * 64)

    h2 = make_host(cfg, shared_bus)
    h2.recover()
    out = replies(h2)
    assert len(out) == 1 and out[0]["type"] == "yield" and out[0]["reason"] == "restart"
    assert out[0]["worker"] == "core14"
    assert h2.bus.posts[-1]["reply_to"] == TASK_SEQ
    assert h2.bus.seen == [("yield", "yielded")]  # state marked before the post
    assert h2.st.data["tasks"][TASK_ID]["status"] == "yielded"
    assert h2.resumes == []

    h3 = make_host(cfg, shared_bus)
    h3.recover()
    assert replies(h3) == []
