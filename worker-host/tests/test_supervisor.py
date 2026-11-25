"""Issue #16: `wh supervise` restarts a crashed host with backoff, and never after a deliberate stop."""
from __future__ import annotations

import sys

import pytest

from workerhost import supervisor
from workerhost.config import Config
from workerhost.state import StateStore
from workerhost.supervisor import Supervisor, backoff


class FakeChild:
    def __init__(self, code, clock, ran):
        self.code, self.clock, self.ran = code, clock, ran

    def wait(self):
        self.clock.t += self.ran
        return self.code


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Rig:
    """A supervisor whose children exit with the given codes after the given run times."""

    def __init__(self, cfg, exits, on_sleep=None):
        self.cfg, self.clock = cfg, Clock()
        self.exits = list(exits)
        self.spawned, self.slept = [], []
        self.on_sleep = on_sleep

    def spawn(self, cmd):
        self.spawned.append(cmd)
        code, ran = self.exits.pop(0)
        if isinstance(code, BaseException):
            raise code
        return FakeChild(code, self.clock, ran)

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.clock.t += seconds
        if self.on_sleep:
            self.on_sleep(self)

    def run(self) -> int:
        sup = Supervisor(self.cfg, command=["host"], spawn=self.spawn, sleep=self.sleep, clock=self.clock)
        return sup.run()

    def log(self) -> str:
        return "".join(p.read_text(encoding="utf-8") for p in self.cfg.logs_dir.glob("host-*.log"))

    def delays(self) -> list[int]:
        out = []
        for line in self.log().splitlines():
            if " supervisor-restart " in line:
                out.append(int(line.split(" delay=")[1].split()[0]))
        return out


@pytest.fixture
def cfg(tmp_path):
    return Config(host_name="alpha", home=tmp_path / "home")


def disable(cfg):
    StateStore(cfg.state_dir).update(lambda d: d.update(enabled=False, draining=False))


def test_backoff_sequence():
    assert [backoff(n) for n in range(7)] == [10, 30, 60, 300, 300, 300, 300]


def test_restarts_after_crash_exits_with_backoff_and_logs_each_restart(cfg):
    rig = Rig(cfg, [(1, 5), (1, 5), (1, 5), (1, 5), (1, 5), (0, 5)])
    assert rig.run() == 0
    assert len(rig.spawned) == 6
    assert rig.delays() == [10, 30, 60, 300, 300]
    assert sum(rig.slept) == 10 + 30 + 60 + 300 + 300
    assert max(rig.slept) <= supervisor.CHECK_EVERY  # waits in short steps, so a stop is noticed
    log = rig.log()
    assert log.count("supervisor-restart exit_code=1") == 5
    assert "attempt=5" in log and "supervisor-exit reason=host-exit-0" in log


def test_no_restart_after_a_clean_exit(cfg):
    """`wh stop` and `wh drain` end the host with exit code 0: the supervisor ends too."""
    rig = Rig(cfg, [(0, 50)])
    assert rig.run() == 0
    assert len(rig.spawned) == 1 and rig.slept == []
    assert "supervisor-restart" not in rig.log()


def test_no_restart_when_another_host_holds_the_home(cfg):
    rig = Rig(cfg, [(supervisor.EXIT_ALREADY_RUNNING, 1)])
    assert rig.run() == supervisor.EXIT_ALREADY_RUNNING
    assert len(rig.spawned) == 1 and rig.slept == []


def test_no_restart_after_wh_stop_killed_a_hung_host(cfg):
    """`wh stop` records enabled=false, then kills a host that did not stop in 30 s (exit code 1)."""
    disable(cfg)
    rig = Rig(cfg, [(1, 50)])
    assert rig.run() == 0
    assert len(rig.spawned) == 1 and rig.slept == []
    assert "supervisor-exit reason=disabled exit_code=1" in rig.log()


def test_stop_during_the_backoff_wait_cancels_the_restart(cfg):
    rig = Rig(cfg, [(1, 5), (1, 5), (0, 5)], on_sleep=lambda r: disable(r.cfg) if len(r.slept) == 7 else None)
    assert rig.run() == 0
    assert len(rig.spawned) == 2  # first restart after 10 s; the stop came 25 s into the 30 s wait
    assert sum(rig.slept) == 10 + 25


def test_backoff_resets_after_a_stable_run(cfg):
    stable = supervisor.STABLE_SECONDS
    rig = Rig(cfg, [(1, 5), (1, 5), (1, stable + 1), (1, 5), (0, 5)])
    assert rig.run() == 0
    assert rig.delays() == [10, 30, 10, 30]


def test_a_failed_spawn_is_retried_like_a_crash(cfg):
    rig = Rig(cfg, [(OSError("python missing"), 0), (0, 5)])
    assert rig.run() == 0
    assert len(rig.spawned) == 2 and rig.delays() == [10]
    assert "supervisor-spawn-error error=OSError" in rig.log()
    assert "OSError: python missing" in next(cfg.logs_dir.glob("host-*.errors.log")).read_text(encoding="utf-8")


def test_real_child_process_is_restarted_until_it_exits_cleanly(cfg, tmp_path):
    """End to end with real processes in the job object: exits 1, 1, then 0."""
    counter = tmp_path / "count.txt"
    script = ("import pathlib,sys; p=pathlib.Path(sys.argv[1]); "
              "n=int(p.read_text()) if p.exists() else 0; p.write_text(str(n+1)); sys.exit(1 if n < 2 else 0)")
    slept = []
    sup = Supervisor(cfg, command=[sys.executable, "-c", script, str(counter)], sleep=slept.append)
    assert sup.run() == 0
    assert counter.read_text() == "3"
    assert sum(slept) == 10 + 30


def test_stop_noticed_after_the_dying_host_briefly_restored_enabled(cfg):
    """Review finding: a save by the killed host can leave enabled=true when the supervisor first looks;
    `wh stop` writes enabled=false again after the kill, and the backoff wait sees it."""
    rig = Rig(cfg, [(1, 5), (0, 5)], on_sleep=lambda r: disable(r.cfg) if len(r.slept) == 1 else None)
    assert rig.run() == 0
    assert len(rig.spawned) == 1
    assert "supervisor-exit reason=disabled" in rig.log()
