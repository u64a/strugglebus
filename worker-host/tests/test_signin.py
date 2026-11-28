"""workerhost/signin.py: the host signs itself in again with a device code (docs/app-host-integration.md section 4a).

The output samples are what gh and copilot really printed under a batch logon on the test VM (28 Nov 2026), with a
made-up code. The process is faked; nothing here runs gh or copilot or reaches GitHub.
"""
from __future__ import annotations

import io
import json
import subprocess
import time

import pytest

from workerhost import commands, hostevents, hoststatus, signin

GH_OUT = ("! One-time code (WXYZ-9876) copied to clipboard\n"
          "Open this URL to continue in your web browser: https://github.com/login/device\n")
COPILOT_OUT = ("To authenticate, visit https://github.com/login/device and enter code WXYZ-9876\n"
               "Waiting for authorization...\n")


@pytest.mark.parametrize("text, want", [
    (GH_OUT, "WXYZ-9876"),
    (COPILOT_OUT, "WXYZ-9876"),
    ("", None),                                                             # nothing yet
    ("! One-time code (WXYZ-9876) copied to clipboard\n", None),            # the URL line not yet read
    ("Open this URL to continue in your web browser: https://github.com/login/device.\n", None),  # a code not yet
])
def test_the_code_is_read_only_from_the_whole_device_prompt(text, want):
    assert signin.device_code(text) == want


@pytest.mark.parametrize("text", [
    GH_OUT.replace("https://github.com/login/device", "https://evil.example/login/device"),
    GH_OUT + "see also https://github.com/login/device/select_account\n",   # any other URL, even GitHub's
    COPILOT_OUT + "or enter code ABCD-1234\n",                               # two different codes
    "visit http://github.com/login/device and enter code WXYZ-9876\n",      # not https
])
def test_any_other_url_or_a_second_code_ends_the_attempt(text):
    with pytest.raises(signin.Unexpected):
        signin.device_code(text)


def test_the_commands_are_fixed_and_take_nothing_from_the_document():
    assert signin.command_for("gh", "C:\\gh.exe", "C:\\c.exe") == [
        "C:\\gh.exe", "auth", "login", "--hostname", "github.com", "--git-protocol", "https", "--web"]
    assert signin.command_for("copilot", "C:\\gh.exe", "C:\\c.exe") == ["C:\\c.exe", "login", "--device-code"]
    with pytest.raises(ValueError):
        signin.command_for("claude", "C:\\gh.exe", "C:\\c.exe")


def test_the_child_gets_home_and_never_opens_a_browser():
    env = signin.child_env({"USERPROFILE": "C:\\Users\\sbworker", "HOMEPATH": "\\WINDOWS"})
    assert env["HOME"] == "C:\\Users\\sbworker" and env["GH_BROWSER"] == "cmd /c rem"


class FakeProc:
    def __init__(self, out="", err=""):
        self.stdout, self.stderr = io.StringIO(out), io.StringIO(err)
        self.code, self.killed = None, False

    def poll(self):
        return self.code

    def kill(self):
        self.killed, self.code = True, -9


class Rig:
    def __init__(self, out="", err="", setup_git_code=0):
        self.log_lines, self.procs, self.ran = [], [], []
        self.out, self.err, self.setup_git_code = out, err, setup_git_code
        self.s = signin.SignIns("C:\\gh.exe", "C:\\copilot.exe", self.log, popen=self.popen, run=self.run)

    def log(self, event, **fields):
        self.log_lines.append((event, fields))

    def popen(self, args, **kw):
        assert kw["stdin"] is subprocess.DEVNULL and "HOME" in kw["env"]
        p = FakeProc(self.out, self.err)
        self.procs.append((args, p))
        return p

    def run(self, args, **kw):
        self.ran.append(args)
        return subprocess.CompletedProcess(args, self.setup_git_code, "", "")

    def settle(self):
        """Wait until the reader threads have read all the fake output (a fixed sleep flaked on a slow, covered run)."""
        want = len(self.out) + len(self.err)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            a = self.s.current
            if a is None or len("".join(a.out)) >= want:
                return
            time.sleep(0.01)


def test_a_gh_sign_in_shows_its_code_then_sets_up_git_and_is_done():
    r = Rig(err=GH_OUT)
    r.s.start("gh", "a" * 32, 1000.0)
    r.settle()
    r.s.poll(1001.0)
    st = r.s.status()
    assert st["state"] == "code" and st["code"] == "WXYZ-9876" and st["nonce"] == "a" * 32
    assert st["expires_at"] == time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(1001.0 + signin.CODE_LIFE))
    r.procs[0][1].code = 0  # approved
    r.s.poll(1100.0)
    assert r.ran == [["C:\\gh.exe", "auth", "setup-git"]]
    assert r.s.status() == {"nonce": "a" * 32, "tool": "gh", "state": "done"}  # the code is gone
    assert [e for e, _ in r.log_lines] == ["sign-in-requested", "sign-in-code-issued", "sign-in-done"]


def test_the_code_is_never_in_a_log_line():
    r = Rig(out=COPILOT_OUT)
    r.s.start("copilot", "b" * 32, 1000.0)
    r.settle()
    r.s.poll(1001.0)
    r.procs[0][1].code = 1
    r.s.poll(1002.0)
    assert "WXYZ-9876" not in json.dumps(r.log_lines)
    assert r.s.status() == {"nonce": "b" * 32, "tool": "copilot", "state": "failed", "reason": "tool-exit"}


@pytest.mark.parametrize("out, polls, reason", [
    (GH_OUT.replace("github.com/login/device", "evil.example/x"), [1001.0], "unexpected-prompt"),
    ("", [1000.0 + signin.CODE_WAIT + 1], "no-code"),
    (COPILOT_OUT, [1001.0, 1001.0 + signin.CODE_LIFE + 1], "expired"),
])
def test_an_attempt_ends_and_its_tool_is_stopped(out, polls, reason):
    r = Rig(out=out)
    r.s.start("copilot", "c" * 32, 1000.0)
    r.settle()
    for t in polls:
        r.s.poll(t)
    assert r.s.status()["state"] == "failed" and r.s.status()["reason"] == reason
    assert r.procs[0][1].killed and "code" not in r.s.status()


def test_a_failed_setup_git_fails_the_gh_sign_in():
    r = Rig(err=GH_OUT, setup_git_code=1)
    r.s.start("gh", "d" * 32, 1000.0)
    r.settle()
    r.s.poll(1001.0)
    r.procs[0][1].code = 0
    r.s.poll(1002.0)
    assert r.s.status()["reason"] == "setup-git"


def test_a_new_request_replaces_one_still_running():
    r = Rig(out=COPILOT_OUT)
    r.s.start("copilot", "e" * 32, 1000.0)
    r.s.start("gh", "f" * 32, 1001.0)
    assert r.procs[0][1].killed and r.s.status()["nonce"] == "f" * 32
    assert ("sign-in-failed", {"tool": "copilot", "nonce": "e" * 32, "reason": "replaced"}) in r.log_lines


def test_the_status_field_is_admin_only_absent_unless_asked_and_never_in_a_sample():
    f = hoststatus.Facts(host="h", agent="host-h-host", version="v", serial=1, started_at=0, interval_s=60,
                         reported_state="idle", account="x", dedicated=True, engines=[], busy=0, max_workers=1,
                         claiming=0, held_clones=0, outbox=0, fleet={}, listed_in_fleet=True)
    assert "sign_in" not in hoststatus.build_v2(f)
    f.sign_in = {"nonce": "a" * 32, "tool": "gh", "state": "code", "code": "WXYZ-9876", "expires_at": "Z", "x": 1}
    snap = hoststatus.build_v2(f)
    assert snap["sign_in"] == {"nonce": "a" * 32, "tool": "gh", "state": "code", "code": "WXYZ-9876", "expires_at": "Z"}
    assert "sign_in" not in hoststatus.for_device(snap)                # admin-only
    assert "sign_in" not in hoststatus.build(f)                        # not in the v1 status or the heartbeat
    assert "WXYZ" not in json.dumps(hoststatus.sample(snap, "2026-11-28T00:00:00Z"))
    f.sign_in = {"nonce": "a" * 32, "tool": "gh", "state": "code", "code": "not a code"}
    assert "code" not in hoststatus.build_v2(f)["sign_in"]             # only GitHub's form ever goes out


def test_the_events_carry_the_tool_or_the_reason_never_the_code():
    for etype, fields, want in [
        ("sign-in-requested", {"tool": "gh"}, {"code": "gh"}),
        ("sign-in-code-issued", {"tool": "copilot"}, {"code": "copilot"}),
        ("sign-in-done", {"tool": "gh"}, {"code": "gh"}),
        ("sign-in-failed", {"tool": "gh", "reason": "expired"}, {"reason": "expired"}),
    ]:
        target, mapping = hostevents.SIMPLE[etype]
        event = hostevents.make(target, at=0, **{k: fields[v] for k, v in mapping.items() if v in fields})
        assert {k: v for k, v in event.items() if k not in ("id", "type", "at")} == want


def test_a_verified_sign_in_command_starts_the_sign_in_and_touches_nothing_else(tmp_path, monkeypatch):
    from conftest import HOST_A, FakeVault, SharedBus
    from workerhost import engines as engines_mod
    from workerhost import resources
    from workerhost.config import Config
    from workerhost.host import Host

    monkeypatch.setattr(resources, "sample", lambda root: None)
    monkeypatch.setattr(engines_mod, "resolve", lambda name: "C:\\bin\\copilot.exe")
    h = Host(Config(host_name="box1", agent_prefix="host-box1", home=tmp_path / "home", workers_root=tmp_path / "w"),
             bus=SharedBus().client(HOST_A), vault=FakeVault())
    started = []
    monkeypatch.setattr(h.signins, "start", lambda tool, nonce, now: started.append((tool, nonce)))
    before = dict(h.st.data)
    h.run_command("sign-in-copilot", "a" * 32)
    h.run_command("sign-in-gh", "b" * 32)
    assert started == [("copilot", "a" * 32), ("gh", "b" * 32)]
    assert h.st.data.get("paused") == before.get("paused")  # not a pause, drain or update
    assert h.update_now is False


def test_the_two_verbs_are_commands_with_no_field_of_their_own():
    assert {"sign-in-gh", "sign-in-copilot"} <= set(commands.VERBS)
    assert commands.FIELDS == frozenset({"v", "type", "host", "verb", "nonce", "issued_at", "expires_at"})
