"""Self-update (workerhost/update.py, design.md 10a): signed release.toml, the nightly window, apply, rollback.

Decided with Alice (4 Nov 2026): check at 01:00, announce on the announce channel mentioning every coordinator and stop
taking tasks; at 03:00 apply when idle; at 03:30 push running workers' work, stop them, apply, resume them once.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from conftest import COORD, HOST_A, FakeVault
from workerhost import resources, signing, supervisor as supervisor_mod, update
from workerhost.config import Config
from workerhost.host import Host

pytestmark = pytest.mark.update

COMMIT = "a" * 40
FILES = {"wh.py": b"print('wh')\n", "config.template.toml": b"x = 1\n", "README.md": b"# r\n",
         "workerhost/__init__.py": b"", "workerhost/host.py": b"NEW = True\n"}


def release_toml(serial=2, version="2026.11.06", commit=COMMIT, tree=None, extra="") -> bytes:
    tree = tree or update.tree_sha256(FILES)
    return (f'serial = {serial}\nversion = "{version}"\ncommit = "{commit}"\ntree_sha256 = "{tree}"\n'
            f'notes = "faster claims"\n{extra}').encode()


# --- the file ---------------------------------------------------------------------------------------------------

def test_a_release_parses_and_everything_else_is_refused():
    r = update.parse_release(release_toml())
    assert (r.serial, r.version, r.commit, r.needs_install, r.notes) == (2, "2026.11.06", COMMIT, False, "faster claims")
    for bad, where in ((b'serial = 0\nversion="1"\ncommit="' + b"a" * 40 + b'"\ntree_sha256="' + b"b" * 64 + b'"', "serial"),
                       (release_toml(version="../x"), "version"), (release_toml(commit="abc"), "commit"),
                       (release_toml(tree="z" * 64), "tree_sha256"), (release_toml(extra="needs_install = 1\n"), "needs_install"),
                       (b"not toml [", "toml")):
        with pytest.raises(update.ReleaseError) as e:
            update.parse_release(bad)
        assert e.value.reason == "release-invalid" and e.value.detail.startswith(where)


def test_the_tree_hash_covers_exactly_the_installed_files_in_any_order():
    assert update.tree_sha256(FILES) == update.tree_sha256(dict(reversed(list(FILES.items()))))
    assert update.tree_sha256({**FILES, "workerhost/host.py": b"NEW = False\n"}) != update.tree_sha256(FILES)
    for path, ok in (("wh.py", True), ("workerhost/fleet.py", True), ("README.md", True), ("tests/test_x.py", False),
                     ("workerhost/sub/x.py", False), ("install.ps1", False), ("workerhost/x.txt", False),
                     ("workerhost/../x.py", False)):
        assert update.wanted(path) is ok, path


def test_files_are_read_from_git_by_commit_and_hash_as_the_signer_computed(tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    for path, data in {**FILES, "tests/test_x.py": b"t", "install.ps1": b"i"}.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_bytes(data)
    run = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@x", "-c", "user.name=t", *a],
                                    check=True, capture_output=True)
    run("add", "-A")
    run("commit", "-q", "-m", "x")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    files = update.read_tree("git", None, head, cwd=repo)
    assert files == FILES and update.tree_sha256(files) == update.tree_sha256(FILES)


# --- the window ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("hhmm, phase, busy, expected", [
    ("00:30", "", False, "wait"),
    ("01:05", "", False, "check"),
    ("01:05", "announced", False, "wait"),           # announced: no tasks, nothing applied before 03:00
    ("03:05", "announced", False, "apply"),
    ("03:05", "announced", True, "wait"),            # workers running: wait for them, up to the grace
    ("03:31", "announced", True, "stop-and-apply"),  # grace over: save, stop, apply, resume after
    ("04:31", "announced", False, "give-up"),        # missed (off or asleep): take tasks again
    ("12:00", "announced", False, "give-up"),
    ("12:00", "", False, "wait"),
    ("02:00", "done", False, "check"),               # a new window: check again
])
def test_the_nightly_window(hhmm, phase, busy, expected):
    now = datetime(2026, 11, 6, int(hhmm[:2]), int(hhmm[3:]))
    assert update.decide(now, "01:00", "03:00", 30, {"phase": phase}, busy) == expected


def test_one_check_per_window_and_an_evening_check_belongs_to_the_next_night():
    now = datetime(2026, 11, 6, 1, 5)
    key = update.window_key(now, "01:00", "03:00")
    assert key == "2026-11-06T03:00"
    assert update.decide(now, "01:00", "03:00", 30, {"checked_for": key}, False) == "wait"
    evening = datetime(2026, 11, 5, 23, 10)
    assert update.window_key(evening, "23:00", "03:00") == "2026-11-06T03:00"
    assert update.decide(evening, "23:00", "03:00", 30, {}, False) == "check"
    assert update.decide(datetime(2026, 11, 6, 3, 5), "23:00", "03:00", 30, {"phase": "announced"}, False) == "apply"


def test_the_announcement_names_every_coordinator_and_the_times():
    text = update.announcement("box1", update.parse_release(release_toml()), "2026.11.01", "03:00", 30,
                               ["coord-main", "sb-test-coordinator"])
    assert text.startswith("@coord-main @sb-test-coordinator host box1 updates the worker host from "
                           "2026.11.01 to 2026.11.06 at 03:00")
    assert "by 03:30" in text and "resumed once" in text and "Release notes: faster claims" in text


# --- applying and restoring ---------------------------------------------------------------------------------------

def installed_app(tmp_path) -> Path:
    app = tmp_path / "app"
    update.write_files({"wh.py": b"old\n", "config.template.toml": b"x = 0\n", "README.md": b"old\n",
                        "workerhost/__init__.py": b"", "workerhost/host.py": b"NEW = False\n",
                        "workerhost/gone.py": b"OLD_MODULE\n"}, app)
    (app / "wh.cmd").write_text("@echo off\n")  # written by install.ps1, never by an update
    return app


def test_apply_writes_in_place_backs_up_and_restore_puts_it_all_back(tmp_path):
    app, backup = installed_app(tmp_path), tmp_path / "app.prev"
    before = update.current_files(app)
    rel = update.parse_release(release_toml())
    update.apply_files(FILES, app, backup, rel)
    assert update.current_files(app) == FILES  # gone.py removed: the new release has no such module
    assert (app / "wh.cmd").exists()
    assert update.installed(app) == {"version": "2026.11.06", "serial": 2, "commit": COMMIT, "moved_to": None}
    assert update.restore(app, backup)
    assert update.current_files(app) == before and update.installed(app)["version"] == "manual"
    assert not update.restore(app, tmp_path / "no-backup")


def test_newer_means_a_higher_serial_and_other_code():
    rel = update.parse_release(release_toml(serial=2))
    assert update.is_newer(rel, {"serial": 0, "commit": ""})
    assert not update.is_newer(rel, {"serial": 0, "commit": COMMIT})  # hand-installed that very commit
    assert not update.is_newer(rel, {"serial": 2, "commit": "b" * 40})
    assert update.installed(Path("no-such-dir")) == {"version": "manual", "serial": 0, "commit": "", "moved_to": None}


# --- the signature, from a mirror like the host's -------------------------------------------------------------------

@pytest.fixture(scope="module")
def keygen():
    found = signing.find_ssh_keygen()
    if not found:
        pytest.skip("no ssh-keygen")
    return found


@pytest.fixture
def mirror(tmp_path, keygen):
    keys = tmp_path / "keys"
    keys.mkdir()
    for name in ("alice", "stranger"):
        subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(keys / name)], check=True,
                       capture_output=True)
    pub = (keys / "alice.pub").read_text().split()
    signers = keys / "allowed_signers"
    signers.write_text(f'alice namespaces="strugglebus-fleet,strugglebus-release" {pub[0]} {pub[1]}\n')

    def sign(data: bytes, key="alice", ns="strugglebus-release") -> bytes:
        f = tmp_path / "msg"
        f.write_bytes(data)
        Path(str(f) + ".sig").unlink(missing_ok=True)
        subprocess.run([keygen, "-Y", "sign", "-f", str(keys / key), "-n", ns, str(f)], check=True, capture_output=True)
        return Path(str(f) + ".sig").read_bytes()

    work = tmp_path / "work"
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    g = lambda *a: subprocess.run(["git", "-C", str(work), "-c", "user.email=t@x", "-c", "user.name=t", *a],
                                  check=True, capture_output=True, text=True).stdout.strip()
    update.write_files(FILES, work)
    g("add", "-A")
    g("commit", "-q", "-m", "code")
    code = g("rev-parse", "HEAD")
    bare = tmp_path / "fleet.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)

    def publish(release: bytes | None, sig: bytes | None):
        for name, data in (("release.toml", release), ("release.toml.sig", sig)):
            if data is None:
                (work / name).unlink(missing_ok=True)
            else:
                (work / name).write_bytes(data)
        g("add", "-A")
        g("commit", "-q", "--allow-empty", "-m", "release")
        subprocess.run(["git", "--git-dir", str(bare), "fetch", "-q", str(work), "+refs/heads/main:refs/remotes/origin/main"],
                       check=True, capture_output=True)

    src = update.ReleaseSource(bare, "git", keygen, signers, tmp_path / "tmp")
    return src, sign, publish, code


def test_a_signed_release_is_read_and_its_code_checked(mirror):
    src, sign, publish, code = mirror
    data = release_toml(commit=code)
    publish(data, sign(data))
    rel, status = src.read()
    assert status == "ok" and rel.commit == code
    assert src.files(rel) == FILES


@pytest.mark.parametrize("case, expected", [
    ("missing", "release-missing"), ("unsigned", "release-unsigned"), ("stranger", "release-bad-signature"),
    ("fleet-namespace", "release-bad-signature"), ("edited-after-signing", "release-bad-signature"),
    ("invalid", "release-invalid")])
def test_anything_but_alice_signature_over_exactly_these_bytes_is_refused(mirror, case, expected):
    src, sign, publish, code = mirror
    data = release_toml(commit=code)
    if case == "missing":
        publish(None, None)
    elif case == "unsigned":
        publish(data, None)
    elif case == "stranger":
        publish(data, sign(data, key="stranger"))
    elif case == "fleet-namespace":
        publish(data, sign(data, ns="strugglebus-fleet"))
    elif case == "edited-after-signing":
        publish(data.replace(b"faster claims", b"evil"), sign(data))
    else:
        bad = b'serial = 2\nversion = "x y"\n'
        publish(bad, sign(bad))
    assert src.read() == (None, expected)


def test_code_that_does_not_match_the_signed_tree_is_refused(mirror):
    src, sign, publish, code = mirror
    data = release_toml(commit=code, tree="0" * 64)
    publish(data, sign(data))
    rel, status = src.read()
    with pytest.raises(update.ReleaseError) as e:
        src.files(rel)
    assert e.value.reason == "release-tree"


# --- the host ---------------------------------------------------------------------------------------------------

class RecordingBus:
    def __init__(self):
        self.posts, self.calls = [], []

    def post(self, channel, kind, text, reply_to=None):
        self.posts.append((channel, kind, text))
        return len(self.posts)

    def call(self, method, path, **kw):
        self.calls.append((method, path))
        return 200, {}


class FakeSource:
    def __init__(self, rel, files=FILES):
        self.rel, self._files = rel, files

    def read(self):
        return (self.rel, "ok") if self.rel else (None, "release-missing")

    def files(self, rel):
        if update.tree_sha256(self._files) != rel.tree_sha256:
            raise update.ReleaseError("release-tree")
        return self._files


@pytest.fixture
def uhost(tmp_path, monkeypatch):
    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(
        100 * resources.GB, 10 * resources.GB, 100 * resources.GB, 128 * resources.GB, 500 * resources.GB, set()))
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", workers_root=tmp_path / "w", home=tmp_path / "home",
                 hosts=[{"agent_name": HOST_A.agent_name, "agent_id": HOST_A.agent_id}])
    h = Host(cfg, bus=RecordingBus(), vault=FakeVault(), app_dir=installed_app(tmp_path))
    h.pins = {"coordinator": COORD, "host": HOST_A}
    h.release_source = FakeSource(update.parse_release(release_toml()))
    h.refresh_fleet = lambda force=False: None
    monkeypatch.setattr(update, "run_selftest", lambda python, staged, home, timeout=120: (True, "selftest ok"))
    h.clock = lambda hhmm: monkeypatch.setattr(update, "now_local",
                                               lambda: datetime(2026, 11, 6, int(hhmm[:2]), int(hhmm[3:])))
    h.clock("12:00")  # outside the 01:00-03:30 window unless a test moves it (CI runs at any hour)
    return h


def announcements(h):
    return [text for channel, kind, text in h.bus.posts if channel == "announce" and kind == "announce"]


def test_the_night_check_announces_and_stops_taking_tasks(uhost):
    uhost.clock("01:05")
    uhost.update_tick()
    assert uhost.ustate["phase"] == "announced" and uhost.ustate["version"] == "2026.11.06"
    assert ("PUT", "/api/subscriptions/announce") in uhost.bus.calls
    [text] = announcements(uhost)
    assert text.startswith(f"@{COORD.agent_name} host alpha updates the worker host from manual to 2026.11.06 at 03:00")
    assert uhost.resource_verdict() == ("maintenance", {})
    assert "update=2026.11.06@03:00" in uhost.heartbeat_line() and "release=manual" in uhost.heartbeat_line()
    uhost.update_tick()  # same window: no second check, no second announcement
    assert len(announcements(uhost)) == 1


def test_at_the_window_an_idle_host_applies_and_exits_for_the_supervisor(uhost):
    uhost.clock("01:05")
    uhost.update_tick()
    uhost.clock("03:01")
    uhost.update_tick()
    assert uhost.exit_code == update.EXIT_UPDATE
    assert update.current_files(uhost.app_dir) == FILES and update.installed(uhost.app_dir)["serial"] == 2
    assert update.load_state(uhost.update_file)["phase"] == "applied"
    assert (uhost.cfg.home / "app.prev" / "workerhost" / "gone.py").exists()  # the rollback copy
    assert not (uhost.cfg.home / "app.new").exists()


def test_running_workers_wait_until_the_grace_then_are_saved_stopped_and_resumed(uhost, monkeypatch):
    uhost.clock("01:05")
    uhost.update_tick()

    class Run:
        worker, killed = "core14", False

        def kill(self):
            self.killed = True

        def poll(self):
            return -1

        class job:
            @staticmethod
            def close():
                pass

    run = Run()
    uhost.runs["t1"] = run
    uhost.st.set_task("t1", status="started", worker="core14", seq=5)
    monkeypatch.setattr(uhost, "save_wip", lambda task_id, r, why: {"pushed": "wip", "wip_branch": "feature/x"})
    uhost.clock("03:10")
    uhost.update_tick()
    assert uhost.exit_code is None and not run.killed  # still inside the grace: wait
    uhost.clock("03:31")
    uhost.update_tick()
    assert run.killed and uhost.runs == {} and uhost.exit_code == update.EXIT_UPDATE
    assert uhost.st.data["tasks"]["t1"]["update_stop"] is True and uhost.st.data["tasks"]["t1"]["status"] == "started"


def test_a_failed_selftest_applies_nothing_and_that_release_is_never_retried(uhost, monkeypatch):
    monkeypatch.setattr(update, "run_selftest", lambda *a, **k: (False, "ImportError: boom"))
    uhost.clock("01:05")
    uhost.update_tick()
    uhost.clock("03:01")
    uhost.update_tick()
    assert uhost.exit_code is None and update.installed(uhost.app_dir)["version"] == "manual"
    assert uhost.ustate["phase"] == "failed" and uhost.ustate["rejected"] == [2]
    assert "was not applied (selftest)" in announcements(uhost)[-1]
    assert uhost.resource_verdict() != ("maintenance", {})  # taking tasks again
    uhost.ustate.pop("checked_for")
    uhost.clock("01:10")
    uhost.update_tick()
    assert uhost.ustate["phase"] == "failed"  # not announced again


def test_code_not_matching_its_signature_is_refused(uhost):
    uhost.release_source = FakeSource(update.parse_release(release_toml()), files={**FILES, "wh.py": b"tampered\n"})
    uhost.clock("01:05")
    uhost.update_tick()
    uhost.clock("03:01")
    uhost.update_tick()
    assert uhost.exit_code is None and uhost.ustate["phase"] == "failed"
    assert update.current_files(uhost.app_dir)["wh.py"] == b"old\n"


def test_after_the_restart_the_new_host_reports_done_once_healthy(uhost):
    uhost.ustate.update(phase="applied", version="2026.11.06", from_version="manual")
    uhost.bus_state = "ok"
    uhost.update_tick()
    assert uhost.ustate["phase"] == "applied"  # not yet: runs for HEALTHY_SECONDS first
    uhost.started_at -= uhost.HEALTHY_SECONDS
    uhost.update_tick()
    assert uhost.ustate["phase"] == "done"
    assert "updated from manual to 2026.11.06; taking tasks again" in announcements(uhost)[-1]


def test_a_rollback_is_reported_once(uhost):
    uhost.ustate.update(phase="rolled-back", version="2026.11.06", from_version="2026.11.01", reported=False)
    uhost.update_tick()
    uhost.update_tick()
    assert len(announcements(uhost)) == 1 and "rolled back to 2026.11.01" in announcements(uhost)[0]


def test_needs_install_is_announced_but_never_applied(uhost):
    uhost.release_source = FakeSource(update.parse_release(release_toml(extra="needs_install = true\n")))
    uhost.clock("01:05")
    uhost.update_tick()
    assert uhost.ustate.get("phase", "") != "announced" and "needs install.ps1" in announcements(uhost)[0]


def test_an_update_stop_is_resumed_after_the_restart(uhost):
    uhost.st.set_task("t9", status="started", worker="core1", seq=9, launched_at=10 ** 10, update_stop=True)
    uhost.post = lambda *a, **k: None
    uhost.recover()
    assert uhost.resumes == ["t9"]
    assert uhost.st.data["tasks"]["t9"]["cause"] == "update"


# --- the supervisor -------------------------------------------------------------------------------------------------

class Child:
    def __init__(self, code):
        self.code = code

    def wait(self):
        return self.code


def test_the_supervisor_restarts_at_once_after_an_update_and_rolls_back_after_three_quick_failures(tmp_path):
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", home=tmp_path / "home")
    cfg.state_dir.mkdir(parents=True)
    app = installed_app(tmp_path)
    update.apply_files(FILES, app, cfg.home / "app.prev", update.parse_release(release_toml()))
    update.save_state(cfg.state_dir / "update.json", {"phase": "applied", "serial": 2, "version": "2026.11.06"})
    codes = iter([update.EXIT_UPDATE, 1, 1, 1, 0])
    slept = []
    sup = supervisor_mod.Supervisor(cfg, command=["x"], spawn=lambda cmd: Child(next(codes)), sleep=slept.append,
                                    clock=lambda: 0.0, app_dir=app)
    assert sup.run() == 0
    st = update.load_state(cfg.state_dir / "update.json")
    assert st["phase"] == "rolled-back" and st["rejected"] == [2] and st["reported"] is False
    assert update.current_files(app)["wh.py"] == b"old\n" and update.installed(app)["version"] == "manual"
    assert sum(slept) == 10.0 + 30.0  # backoff after the 1st and 2nd failure; the update restart and rollback: at once


def test_no_rollback_when_no_update_was_applied(tmp_path):
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", home=tmp_path / "home")
    cfg.state_dir.mkdir(parents=True)
    sup = supervisor_mod.Supervisor(cfg, command=["x"], spawn=lambda cmd: Child(0), sleep=lambda s: None,
                                    clock=lambda: 0.0, app_dir=installed_app(tmp_path))
    for _ in range(5):
        assert sup.rollback_if_needed() is False
