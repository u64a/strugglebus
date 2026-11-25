"""Host loop: a task from anyone but the pinned coordinator produces no post; pause stops claims, not workers."""
from __future__ import annotations

import json
import subprocess
import time

import pytest

from conftest import COORD, HOST_A, HOST_B, STRANGER, FakeVault, git, task_body
from workerhost import resources
from workerhost.claim import reply_text
from workerhost.config import Config
from workerhost.host import Host
from workerhost.validate import digest_of


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@pytest.fixture
def host(tmp_path, shared_bus, monkeypatch):
    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(
        100 * resources.GB, 10 * resources.GB, 100 * resources.GB, 128 * resources.GB, 500 * resources.GB, set()))
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", poll_seconds=0, settle_seconds=0, workers_root=tmp_path / "w",
                 repos={"app-core": "acme/app-core"}, allowed_models=["claude-opus-5.5"],
                 home=tmp_path / "home", hosts=[{"agent_name": HOST_A.agent_name, "agent_id": HOST_A.agent_id}])
    h = Host(cfg, bus=shared_bus.client(HOST_A), vault=FakeVault())
    h.pins = {"coordinator": COORD, "host": HOST_A}
    h.st.data["cursor"] = 0
    h.started = []
    h.start = lambda p, session_id=None: h.started.append(p.task["task_id"])
    return h


def post(shared_bus, sender, body, kind="question"):
    seq = shared_bus.append(sender, kind, body if isinstance(body, str) else json.dumps(body))
    shared_bus.messages[-1]["created_at"] = now_iso()
    return seq


def host_log(h) -> str:
    return "".join(p.read_text(encoding="utf-8") for p in h.cfg.logs_dir.glob("host-*.log"))


def test_wrong_sender_task_is_ignored_silently(host, shared_bus):
    post(shared_bus, STRANGER, task_body())
    post(shared_bus, STRANGER, {"v": 1, "type": "status"})
    host.poll()
    host.advance_claims()
    assert host.bus.posts == [] and host.pending == {} and host.started == []
    assert "reason=sender" in host_log(host)


def test_unpinned_coordinator_ignores_everything(host, shared_bus):
    from workerhost.validate import Pin

    host.pins["coordinator"] = Pin("", COORD.agent_name)  # never enrolled: fail closed
    post(shared_bus, COORD, task_body())
    host.poll()
    assert host.bus.posts == [] and host.pending == {}


def test_coordinator_task_is_claimed_and_started(host, shared_bus):
    post(shared_bus, COORD, task_body())
    host.poll()
    host.advance_claims()
    host.advance_claims()
    assert [p["body"]["type"] for p in host.bus.posts] == ["claim"]
    assert host.started == [task_body()["task_id"]]


def test_pause_refuses_new_tasks_but_keeps_running_workers(host, shared_bus):
    host.runs["t-running"] = object()  # a worker already running
    host.handle_control({"cmd": "pause"})
    post(shared_bus, COORD, task_body())
    host.poll()
    assert [(p["body"]["type"], p["body"]["reason"]) for p in host.bus.posts] == [("refuse", "paused")]
    assert "t-running" in host.runs and host.pending == {}
    assert host.reported_state() == "paused(running)"
    host.handle_control({"cmd": "resume"})
    assert host.resource_verdict() is None


def test_game_process_pauses_the_host(host, shared_bus, monkeypatch):
    host.cfg.pause_while_running = ["eldenring"]
    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(
        100 * resources.GB, 10 * resources.GB, 100 * resources.GB, 128 * resources.GB, 500 * resources.GB,
        {"eldenring.exe"}))
    assert host.resource_verdict() == ("game", {})
    assert host.reported_state() == "paused(idle)"


def test_status_message_gets_a_heartbeat_at_once(host, shared_bus):
    seq = post(shared_bus, COORD, {"v": 1, "type": "status"})
    host.poll()
    assert len(host.bus.posts) == 1
    assert host.bus.posts[0]["kind"] == "status" and host.bus.posts[0]["reply_to"] == seq
    assert host.bus.posts[0]["body"].startswith("host=alpha state=idle")


def test_heartbeat_cadence_comes_from_config(host):
    host.cfg.heartbeat_idle_minutes = 60
    host.cfg.heartbeat_running_minutes = 10
    host.heartbeat()
    assert 3590 < host.next_heartbeat - time.time() <= 3600
    host.runs["t"] = object()
    host.heartbeat_if_due()
    assert 590 < host.next_heartbeat - time.time() <= 600


def test_failed_ghcp_update_marks_heartbeat_and_status(host, monkeypatch):
    import workerhost.host as host_mod
    from workerhost.ghcp import Result

    monkeypatch.setattr(host_mod.ghcp, "update", lambda *a, **k: Result(
        False, "1.0.95-3", "1.0.95-3", "ghcp update: failed (exit 2316632151), kept 1.0.95-3"))
    host.ghcp_version = "1.0.95-3"
    assert "ghcp_ok" not in host.heartbeat_line()
    host.update_ghcp()
    assert host.ghcp_ok is False and host.heartbeat_line().endswith("ghcp_ok=False")
    host.write_status()
    status = json.loads((host.cfg.state_dir / "status.json").read_text(encoding="utf-8"))
    assert status["ghcp_ok"] is False and "ghcp_ok=False" in status["heartbeat_line"]
    monkeypatch.setattr(host_mod.ghcp, "update", lambda *a, **k: Result(
        True, "1.0.95-3", "1.0.95-3", "ghcp update: 1.0.95-3 newer than winget 1.0.94, skipped"))
    host.update_ghcp()
    assert host.ghcp_ok is True and "ghcp_ok" not in host.heartbeat_line()


def test_changed_message_after_claim_is_not_started_when_mutable_is_opted_in(host, shared_bus):
    host.cfg.messages_mutable = True
    seq = post(shared_bus, COORD, task_body())
    host.poll()
    host.advance_claims()
    next(m for m in shared_bus.messages if m["seq"] == seq)["body"] = json.dumps(task_body(worker="core15"))
    host.advance_claims()
    assert host.started == []
    assert [p["body"]["type"] for p in host.bus.posts] == ["claim", "yield"]
    assert host.bus.posts[-1]["body"]["reason"] == "changed"


def test_messages_immutable_by_default_but_the_digest_is_still_compared(host, shared_bus):
    """The bus does not allow edits: no re-read before starting, yet every claim carries the digest of
    the validated body and a claim for a different body (from a pinned host) does not count."""
    assert Config(host_name="x").messages_mutable is False and host.cfg.messages_mutable is False
    host.cfg.hosts.append({"agent_name": HOST_B.agent_name, "agent_id": HOST_B.agent_id})
    seq = post(shared_bus, COORD, task_body())
    shared_bus.append(HOST_B, "answer", reply_text("claim", task_body()["task_id"], "f" * 64, "bravo"), reply_to=seq)
    host.still_same = lambda p: pytest.fail("no re-read when messages are immutable")
    host.poll()
    host.advance_claims()
    host.advance_claims()
    claim = host.bus.posts[0]["body"]
    assert (claim["type"], claim["task_id"], claim["digest"]) == ("claim", task_body()["task_id"], digest_of(task_body()))
    assert host.started == [task_body()["task_id"]]


def test_channel_missing_does_not_fall_back(host, shared_bus):
    from workerhost.busclient import BusError

    calls = []

    def missing(channel, since):
        calls.append(channel)
        raise BusError(404, "no such channel")

    host.bus.read_all = missing
    host.poll()
    assert calls == ["worker-hosts"] and host.channel_state == "missing"
    assert "channel-missing" in host_log(host)


def test_task_from_a_host_identity_is_ignored_and_logged(host, shared_bus):
    post(shared_bus, HOST_A, task_body())  # this host's own identity: never the coordinator
    host.poll()
    assert host.bus.posts == [] and host.pending == {}
    assert "reason=sender" in host_log(host)


@pytest.mark.parametrize("status,reply,shown", [
    (401, {"detail": "invalid credential"}, "invalid credential"),
    (422, {"detail": "agent name is outside the SPN prefix"}, "agent name is outside the SPN prefix"),
    (422, {"detail": [{"loc": ["body", "agent_name"], "input": "host-box1-host"}]}, None),  # structured: not shown
    (400, {"detail": "bad token sbsp1_" + "7f3e" * 10}, None),  # echoes the credential: not shown
])
def test_refused_enrolment_stores_and_prints_nothing(tmp_path, monkeypatch, capsys, status, reply, shown):
    import io

    from workerhost import busclient, cli

    secret = "sbsp1_" + "7f3e" * 10
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('host_name = "dry"\nagent_prefix = "host-box1"\nscheduled_task = ""\n',
                                      encoding="utf-8")
    asked = []

    def refuse(self, method, path, *, body=None, query=None, token=None):
        asked.append((path, body["agent_name"]))
        return status, reply

    monkeypatch.setenv("WORKERHOST_HOME", str(home))  # cli.main sets it; restored after the test
    monkeypatch.setattr(busclient.Bus, "call", refuse)
    monkeypatch.setattr("sys.stdin", io.StringIO(secret + "\n"))
    code = cli.main(["--home", str(home), "enrol", "--spn-stdin"])
    out = capsys.readouterr()
    assert code == 1
    assert asked == [("/api/spn/onboarding-packages", "host-box1-host")]
    assert f"onboarding refused by the bus (HTTP {status}); nothing stored, nothing printed" in out.out
    assert "agent_prefix in config.toml must equal the SPN's name" in out.out
    if shown:
        assert f"the bus says: {shown}" in out.out
    else:
        assert "the bus says" not in out.out and "loc" not in out.out
    assert secret not in out.out + out.err
    creds_dir = home / "creds"
    assert not creds_dir.exists() or list(creds_dir.iterdir()) == []
    for f in home.rglob("*"):
        if f.is_file():
            assert secret.encode() not in f.read_bytes()

# --- B-751: WIP save on timeout, kill or unpushed exit ------------------------------------------

class FakeSession:
    def __init__(self):
        self.posts = []

    def post(self, kind, **extra):
        self.posts.append({"type": kind, **extra})
        return len(self.posts)


class FakeJob:
    def close(self):
        pass


class FakeRun:
    def __init__(self, worker, task_id, tmp_path, code=0):
        self.worker, self.task_id, self.code = worker, task_id, code
        self.session, self.job, self.model = FakeSession(), FakeJob(), "claude-opus-5.5"
        self.temp = tmp_path / "tmp-run"
        self.log = tmp_path / "run.log"
        self.started = self.last_output = time.time()
        self.warned = self.stalled = False
        self.killed = False

    def poll(self):
        return self.code

    def kill(self):
        self.killed = True


TASK = "6f1c2b9e-4d3a-4b8e-9f20-1a2b3c4d5e6f"


@pytest.fixture
def wip(host, remote_and_clone, tmp_path):
    origin, clone = remote_and_clone
    host.cfg.workers_root = clone.parent
    (clone / ".ds-worker.json").write_text(json.dumps({"name": "core14", "clone": str(clone), "branch": "work"}))
    host.st.set_task(TASK, status="started", worker="core14", session_id="none")
    run = FakeRun("core14", TASK, tmp_path)
    host.runs[TASK] = run
    return host, origin, clone, run


def og(origin, *args):
    r = subprocess.run(["git", f"--git-dir={origin}", *args], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def origin_log(origin, branch):
    return og(origin, "log", "--format=%s%n%b", branch)


def test_wip_dirty_tree_on_feature_branch_is_committed_and_pushed(wip):
    host, origin, clone, run = wip
    (clone / "new.py").write_text("print(1)\n")
    (clone / "README.md").write_text("changed\n")
    run.code = 1
    host.supervise()
    body = run.session.posts[-1]
    assert body["type"] == "failed" and body["pushed"] == "wip" and body["wip_branch"] == "work"
    log = origin_log(origin, "work")
    assert f"WIP (exit): core14 {TASK}" in log and "Worker-Host: wip" in log
    assert og(origin, "show", "work:new.py") == "print(1)"
    assert git(clone, "status", "--porcelain") == ""
    assert "wip-pushed" in host_log(host)


def test_wip_commits_with_no_git_identity_anywhere(wip, monkeypatch, tmp_path):
    # The dev host (18 Nov): the host's account has no user.name/user.email at any level, so every WIP save that needed
    # a commit failed ("wip-failed step=commit") and the worker's last changes stayed uncommitted in its clone.
    host, origin, clone, run = wip
    git(clone, "config", "--unset", "user.name")
    git(clone, "config", "--unset", "user.email")
    empty = tmp_path / "empty-gitconfig"
    empty.write_text("")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for k in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "EMAIL"):
        monkeypatch.delenv(k, raising=False)
    (clone / "README.md").write_text("changed\n")
    run.code = 0
    host.supervise()
    body = run.session.posts[-1]
    assert body["pushed"] == "wip" and body["wip_branch"] == "work"
    author = og(origin, "log", "-1", "--format=%an <%ae>|%cn <%ce>", "work")
    want = f"{host.cfg.host_agent} (worker host) <{host.cfg.host_agent}@worker-host.invalid>"
    assert author == f"{want}|{want}"


def test_wip_timeout_commit_message_and_envelope(wip):
    host, origin, clone, run = wip
    (clone / "half.txt").write_text("half done\n")
    run.code = None
    run.started -= host.cfg.runtime.max_runtime_hours * 3600 + 1
    host.supervise()
    body = run.session.posts[-1]
    assert run.killed and body["type"] == "timed-out"
    assert body["pushed"] == "wip" and body["wip_branch"] == "work"
    assert f"WIP (timeout): core14 {TASK}" in origin_log(origin, "work")


def test_wip_clean_tree_with_unpushed_commit_is_pushed_only(wip):
    host, origin, clone, run = wip
    (clone / "a.txt").write_text("a\n")
    git(clone, "add", "a.txt")
    git(clone, "commit", "-q", "-m", "worker commit")
    tip = git(clone, "rev-parse", "HEAD")
    host.supervise()
    body = run.session.posts[-1]
    assert body["type"] == "finished" and body["pushed"] == "wip" and body["wip_branch"] == "work"
    assert og(origin, "rev-parse", "work") == tip  # no WIP commit on top
    assert "WIP" not in origin_log(origin, "work")


def test_wip_clean_and_pushed_is_untouched(wip):
    host, origin, clone, run = wip
    before = og(origin, "rev-parse", "work")
    host.supervise()
    body = run.session.posts[-1]
    assert body["type"] == "finished" and body["pushed"] == "yes" and "wip_branch" not in body
    assert og(origin, "rev-parse", "work") == before
    assert "wip-" not in host_log(host)


def test_wip_timeout_clean_and_pushed_keeps_todays_envelope(wip):
    host, origin, clone, run = wip
    run.code = None
    run.started -= host.cfg.runtime.max_runtime_hours * 3600 + 1
    host.supervise()
    body = run.session.posts[-1]
    assert body["type"] == "timed-out" and "pushed" not in body and "wip_branch" not in body


@pytest.mark.parametrize("branch", ["develop", "main", "master"])
def test_wip_never_on_protected_branches(wip, branch):
    host, origin, clone, run = wip
    git(clone, "switch", "-q", "-c", branch) if branch != "main" else git(clone, "switch", "-q", "main")
    (clone / "x.txt").write_text("x\n")
    before = og(origin, "for-each-ref", "--format=%(refname) %(objectname)")
    run.code = 1
    host.supervise()
    body = run.session.posts[-1]
    assert body["type"] == "failed" and body["pushed"] == "no" and "wip_branch" not in body
    assert og(origin, "for-each-ref", "--format=%(refname) %(objectname)") == before
    assert "x.txt" in git(clone, "status", "--porcelain")  # left as it was, not committed
    assert "wip-skipped" in host_log(host) and f"reason=on-{branch}" in host_log(host)


def test_wip_detached_head_is_skipped(wip):
    host, origin, clone, run = wip
    git(clone, "switch", "-q", "--detach")
    (clone / "x.txt").write_text("x\n")
    run.code = 1
    host.supervise()
    assert run.session.posts[-1]["pushed"] == "no"
    assert "reason=detached-head" in host_log(host)


def test_wip_push_failure_still_posts_finish(wip):
    from workerhost.vault import remove_tree

    host, origin, clone, run = wip
    (clone / "x.txt").write_text("x\n")
    remove_tree(origin)
    run.code = 1
    host.supervise()
    body = run.session.posts[-1]
    assert body["type"] == "failed" and body["pushed"] == "no" and "wip_branch" not in body
    assert TASK not in host.runs and host.st.data["tasks"][TASK]["status"] == "failed"
    assert "wip-push-failed" in host_log(host)


def test_wip_never_touches_a_clone_the_host_did_not_create(wip):
    host, origin, clone, run = wip
    (clone / ".ds-worker.json").write_text(json.dumps({"name": "other", "clone": str(clone)}))
    (clone / "x.txt").write_text("x\n")
    before = og(origin, "rev-parse", "work")
    run.code = 1
    host.supervise()
    assert run.session.posts[-1]["pushed"] == "yes"  # as computed today: no unpushed commits
    assert "wip_branch" not in run.session.posts[-1]
    assert og(origin, "rev-parse", "work") == before
    assert "x.txt" in git(clone, "status", "--porcelain")
    assert "reason=not-host-clone" in host_log(host)


def test_wip_on_stop_kill(wip):
    host, origin, clone, run = wip
    (clone / "x.txt").write_text("x\n")
    run.code = None
    host.stop_now()
    body = run.session.posts[-1]
    assert body["type"] == "interrupted" and body["pushed"] == "wip" and body["wip_branch"] == "work"
    assert f"WIP (exit): core14 {TASK}" in origin_log(origin, "work")


def test_finish_posts_even_when_git_is_missing(wip):
    host, origin, clone, run = wip
    host.cfg.git_exe = str(clone / "no-such-git.exe")
    host.supervise()
    body = run.session.posts[-1]
    assert body["type"] == "finished" and body["pushed"] == "no"
    assert TASK not in host.runs


# --- issue #28 ------------------------------------------------------------------------------------

def test_wip_ignores_a_line_ending_only_change(wip):
    from conftest import make_crlf_phantom

    host, origin, clone, run = wip
    make_crlf_phantom(clone)
    before = og(origin, "rev-parse", "work")
    host.supervise()
    body = run.session.posts[-1]
    assert body["type"] == "finished" and body["pushed"] == "yes" and "wip_branch" not in body
    assert og(origin, "rev-parse", "work") == before  # no WIP commit renormalising the file


def test_heartbeat_counts_clones_on_disk_and_only_held_clones_that_exist(host):
    root = host.cfg.workers_root
    for name in ("a", "b", "c"):
        (root / name / ".git").mkdir(parents=True)
    (root / "tmp").mkdir()
    host.st.data["held_clones"] = ["a", "deleted-long-ago"]
    line = host.heartbeat_line()
    assert "clones=3" in line and "held_clones=1" in line


def test_finished_workers_go_by_each_workers_latest_task(host):
    host.st.data["tasks"] = {
        "t1": {"worker": "a", "status": "finished", "cleaned": True, "updated": 1},
        "t2": {"worker": "a", "status": "failed", "cleaned": False, "updated": 2},
        "t3": {"worker": "b", "status": "finished", "cleaned": True, "updated": 1},
        "t4": {"worker": "c", "status": "finished", "cleaned": False, "updated": 1},
    }
    assert host.finished_workers() == {"b"}


def test_cleanup_keeps_reasons_and_the_retry_list(host, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP", str(tmp_path / "no-temp"))
    root = host.cfg.workers_root
    (root / "young" / ".git").mkdir(parents=True)  # held by end(), not idle long enough to be swept
    (root / "half" / "collectors").mkdir(parents=True)  # a delete that stopped half way
    host.st.data["held_reasons"] = {"young": "timed-out", "gone": "failed"}
    host.st.data["delete_failed"] = ["half"]
    report = host.run_cleanup()
    assert report["deleted"] == ["clone:half"]
    assert host.st.data["held_reasons"] == {"young": "timed-out"}
    assert host.st.data["held_clones"] == ["young"] and host.st.data["delete_failed"] == []
    assert "cleanup-done" in host_log(host)


def test_a_sweep_out_of_time_brings_the_next_one_forward(host, tmp_path, monkeypatch):
    import time

    monkeypatch.setenv("TEMP", str(tmp_path / "no-temp"))
    run_temp = host.cfg.workers_root / "tmp" / "core1-1"
    run_temp.mkdir(parents=True)
    old = time.time() - 5 * 86400
    import os
    os.utime(run_temp, (old, old))
    host.cfg.cleanup.sweep_budget_minutes = 0
    report = host.run_cleanup()
    assert report["deferred"] == 1 and run_temp.exists()
    wait = host.st.data["last_cleanup"] + 3600 * host.cfg.cleanup.sweep_hours - time.time()
    assert 800 < wait <= 900
