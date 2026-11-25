"""`wh supervise`: what the scheduled task runs.

Task Scheduler's RestartOnFailure only covers a task that fails to launch, not an action that exits
non-zero, so a host that crashed stayed down. The supervisor runs `wh.py run` as a child process and
restarts it after a non-zero exit, with backoff: 10 s, 30 s, 60 s, then every 5 minutes (back to 10 s
once a child has run for 10 minutes). Each restart is logged in the host log.

It does not restart after a deliberate end: exit code 0 (`wh stop` and `wh drain` end the host with 0,
as does a disabled host), exit code 3 (another host already holds this home), or `enabled = false` in
state.json (set by `wh stop` / `wh drain`, also when `wh stop` had to kill a host that did not stop).

Self-update (workerhost/update.py): exit code 75 means the host has just written a new release over <home>\\app; the
supervisor restarts it at once, so it runs the new code. The supervisor itself keeps running the code it started
with, which is what makes it the rollback: if the new host then fails three times in a row, each time within the
stable period, it puts <home>\\app.prev back, records "rolled-back" (that release is never retried) and restarts the
host on the previous code. The supervisor's own code changes at the next start of the scheduled task.

Guarantees kept: the child runs in a kill-on-close Job Object held by the supervisor, so ending the
scheduled task (or the supervisor dying) ends the host and, through the host's own worker jobs, every
worker. One supervisor per home (a named mutex), and the host keeps its own single-instance mutex.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Callable

from . import update as update_mod
from . import winapi
from .config import INSTALL_DIR, Config
from .logs import HostLog
from .state import StateStore

BACKOFF = (10.0, 30.0, 60.0)
LATER = 300.0
STABLE_SECONDS = 600.0
EXIT_ALREADY_RUNNING = 3
CHECK_EVERY = 5.0


def backoff(failures: int) -> float:
    """Delay before restart number `failures + 1` in a row."""
    return BACKOFF[failures] if failures < len(BACKOFF) else LATER


def host_command(cfg: Config) -> list[str]:
    return [sys.executable, str(INSTALL_DIR / "wh.py"), "--home", str(cfg.home), "run"]


class Child:
    def __init__(self, proc: subprocess.Popen, job=None):
        self.proc, self.job = proc, job

    def wait(self) -> int:
        try:
            return self.proc.wait()
        finally:
            if self.job is not None:
                self.job.close()


def spawn_in_job(cmd: list[str]) -> Child:
    kwargs = dict(cwd=str(INSTALL_DIR), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL)
    if not winapi.IS_WINDOWS:
        return Child(subprocess.Popen(cmd, **kwargs))
    job = winapi.Job()
    try:
        return Child(winapi.start_in_job(cmd, job, **kwargs), job)
    except BaseException:
        job.close()
        raise


class Supervisor:
    def __init__(self, cfg: Config, log: HostLog | None = None, command: list[str] | None = None,
                 spawn: Callable[[list[str]], Child] = spawn_in_job, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic, app_dir=None):
        self.cfg = cfg
        self.log = log or HostLog(cfg.logs_dir)
        self.command = command or host_command(cfg)
        self.spawn, self.sleep, self.clock = spawn, sleep, clock
        self.app_dir = app_dir or INSTALL_DIR

    def rollback_if_needed(self) -> bool:
        """After a self-update ("applied" in update.json): count a quick failure of the new code; at the third, put
        the previous files back. True when it rolled back (restart at once, on the previous code)."""
        path = self.cfg.state_dir / "update.json"
        st = update_mod.load_state(path)
        if st.get("phase") != "applied":
            return False
        st["failures"] = int(st.get("failures", 0)) + 1
        if st["failures"] < update_mod.ROLLBACK_AFTER:
            update_mod.save_state(path, st)
            return False
        restored = update_mod.restore(self.app_dir, self.cfg.home / "app.prev")
        rejected = st.setdefault("rejected", [])
        if st.get("serial") not in rejected:
            rejected.append(st.get("serial"))
        st.update(phase="rolled-back" if restored else "broken", rolled_back_at=time.time(), reported=False)
        update_mod.save_state(path, st)
        self.log("supervisor-rollback", version=st.get("version"), restored=restored, failures=st["failures"])
        return restored

    def enabled(self) -> bool:
        try:
            return bool(StateStore(self.cfg.state_dir).load().get("enabled", True))
        except (OSError, ValueError):
            return True  # unreadable state is not a stop; `wh stop` also ends the scheduled task

    def wait(self, seconds: float) -> bool:
        """Sleep, checking for a deliberate stop; False if the host was disabled meanwhile."""
        left = seconds
        while left > 0:
            step = min(CHECK_EVERY, left)
            self.sleep(step)
            left -= step
            if not self.enabled():
                return False
        return True

    def run(self) -> int:
        failures = 0
        self.log("supervisor-start", pid=os.getpid())
        while True:
            started = self.clock()
            try:
                child = self.spawn(self.command)
            except Exception as e:  # noqa: BLE001 - a failed spawn is a crash like any other
                self.log.error("supervisor-spawn-error", e)
                code = -1
            else:
                code = child.wait()
            ran = self.clock() - started
            if code == 0:
                self.log("supervisor-exit", reason="host-exit-0")
                return 0
            if code == EXIT_ALREADY_RUNNING:
                self.log("supervisor-exit", reason="already-running", exit_code=code)
                return EXIT_ALREADY_RUNNING
            if code == update_mod.EXIT_UPDATE:
                self.log("supervisor-restart", reason="updated", exit_code=code, delay=0)
                failures = 0
                continue  # at once: the next child runs the new code
            if ran < STABLE_SECONDS and self.rollback_if_needed():
                self.log("supervisor-restart", reason="rolled-back", exit_code=code, delay=0)
                failures = 0
                continue
            if not self.enabled():
                self.log("supervisor-exit", reason="disabled", exit_code=code)
                return 0
            if ran >= STABLE_SECONDS:
                failures = 0
            delay = backoff(failures)
            failures += 1
            self.log("supervisor-restart", exit_code=code, ran_seconds=round(ran), delay=round(delay),
                     attempt=failures)
            if not self.wait(delay):
                self.log("supervisor-exit", reason="disabled", exit_code=code)
                return 0
