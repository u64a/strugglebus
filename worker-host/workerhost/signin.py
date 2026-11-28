"""Signing in again after the lock-down: the host signs itself in (docs/app-host-integration.md section 4a).

A dedicated host account can no longer run interactively (its password exists nowhere; only the scheduled task's
batch logon is allowed), so a lapsed or skipped sign-in is redone by the host itself, as that account, started by a
signed command (sign-in-gh, sign-in-copilot). It runs the tool's device-code sign-in with no window, reads the
one-time code from the tool's own output, and puts it in its status (admin-only) for the App to show to the person
who asked. Nothing else comes from the tool's output: the verification URL must be exactly the pinned one, or the
attempt ends.

Proven on the test VM (28 Nov 2026), under a batch logon with stdin closed: gh prints on stderr
"One-time code (XXXX-XXXX) copied to clipboard" and "Open this URL to continue in your web browser:
https://github.com/login/device"; copilot prints on stdout "To authenticate, visit https://github.com/login/device
and enter code XXXX-XXXX" and "Waiting for authorization...". Both then wait for the approval and exit 0.

The code is never logged and never in an event or a history sample; it is cleared when the attempt ends.
"""
from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field

DEVICE_URL = "https://github.com/login/device"  # the only URL a sign-in may show (u64-security, #humans 29049)
TOOLS = ("gh", "copilot")
CODE_RE = re.compile(r"(?<![A-Za-z0-9-])([A-Z0-9]{4}-[A-Z0-9]{4})(?![A-Za-z0-9-])")
URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]]+")
CODE_WAIT = 60          # seconds for the tool to show a code
CODE_LIFE = 900         # GitHub's device codes last 15 minutes; the attempt ends then
SETUP_GIT_TIMEOUT = 60


class Unexpected(ValueError):
    """The tool's output is not the device-code prompt this host expects."""


def device_code(text: str) -> str | None:
    """The one-time code in a tool's output, or None while there is none yet. Raises Unexpected when the output shows
    a URL other than the pinned one, or more than one code: the attempt is then ended, never shown."""
    urls = {u.rstrip(".,;:") for u in URL_RE.findall(text)}
    if urls - {DEVICE_URL}:
        raise Unexpected("a URL other than " + DEVICE_URL)
    codes = set(CODE_RE.findall(text))
    if len(codes) > 1:
        raise Unexpected("more than one code")
    if not codes or DEVICE_URL not in urls:
        return None  # not (yet) the whole prompt
    return codes.pop()


def command_for(tool: str, gh_exe: str, copilot_exe: str) -> list[str]:
    """The fixed sign-in command for a tool: nothing from the command document goes into it."""
    if tool == "gh":
        return [gh_exe, "auth", "login", "--hostname", "github.com", "--git-protocol", "https", "--web"]
    if tool == "copilot":
        return [copilot_exe, "login", "--device-code"]
    raise ValueError(tool)


def child_env(base: dict | None = None) -> dict:
    """The tool's environment: the host's own, with HOME set to the profile (git and gh take their home from HOME,
    which a batch logon leaves unset) and gh told never to open a browser (it shows the URL instead)."""
    env = dict(os.environ if base is None else base)
    if env.get("USERPROFILE"):
        env["HOME"] = env["USERPROFILE"]
    env["GH_BROWSER"] = "cmd /c rem"
    return env


@dataclass
class Attempt:
    """One sign-in in progress. `state`: starting, code, done or failed."""
    tool: str
    nonce: str
    started: float
    state: str = "starting"
    code: str | None = None
    code_at: float | None = None
    reason: str | None = None
    proc: subprocess.Popen | None = None
    out: list[str] = field(default_factory=list)

    def status(self) -> dict:
        """The admin-only status field (section 4a): the code only while it is current."""
        s = {"nonce": self.nonce, "tool": self.tool, "state": self.state}
        if self.state == "code" and self.code and self.code_at is not None:
            s["code"] = self.code
            s["expires_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.code_at + CODE_LIFE))
        if self.state == "failed":
            s["reason"] = self.reason
        return s


class SignIns:
    """At most one sign-in at a time; a new command replaces one still running (the operator asked again). `log` is
    the host log: every line here is safe to log and becomes a host event (hostevents.SIMPLE); none carries a code."""

    def __init__(self, gh_exe: str, copilot_exe: str, log, popen=subprocess.Popen, run=subprocess.run):
        self.gh_exe, self.copilot_exe, self.log = gh_exe, copilot_exe, log
        self.popen, self.run = popen, run
        self.current: Attempt | None = None

    def start(self, tool: str, nonce: str, now: float) -> None:
        if tool not in TOOLS:
            raise ValueError(tool)
        if self.current and self.current.state in ("starting", "code"):
            self._end(self.current, "failed", "replaced")
        a = Attempt(tool, nonce, now)
        self.current = a
        self.log("sign-in-requested", tool=tool, nonce=nonce)
        try:
            a.proc = self.popen(command_for(tool, self.gh_exe, self.copilot_exe), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env(), text=True,
                                encoding="utf-8", errors="replace",
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError as e:
            self._end(a, "failed", "not-started", error=type(e).__name__)
            return
        for stream in (a.proc.stdout, a.proc.stderr):
            threading.Thread(target=_drain, args=(stream, a.out), daemon=True).start()

    def record(self, tool: str, nonce: str, now: float, *, ok: bool, reason: str | None = None) -> None:
        """A sign-in with no tool to run (Claude Code's sealed token, section 4a): its outcome, as a finished attempt,
        so the status and events read the same as for gh and Copilot."""
        if self.current and self.current.state in ("starting", "code"):
            self._end(self.current, "failed", "replaced")
        a = Attempt(tool, nonce, now)
        self.current = a
        self.log("sign-in-requested", tool=tool, nonce=nonce)
        self._end(a, "done" if ok else "failed", reason)

    def poll(self, now: float) -> None:
        """Called on every host tick: reads the code when it appears, and ends the attempt on exit or timeout."""
        a = self.current
        if a is None or a.state in ("done", "failed"):
            return
        if a.state == "starting":
            try:
                code = device_code("".join(a.out))
            except Unexpected:
                self._end(a, "failed", "unexpected-prompt")
                return
            if code:
                a.state, a.code, a.code_at = "code", code, now
                self.log("sign-in-code-issued", tool=a.tool, nonce=a.nonce)
            elif now - a.started > CODE_WAIT:
                self._end(a, "failed", "no-code")
                return
        exit_code = a.proc.poll() if a.proc else None
        if exit_code is not None:
            if exit_code == 0 and a.state == "code":
                self._finish(a)
            elif a.state == "code":
                self._end(a, "failed", "tool-exit", exit_code=exit_code)
            else:
                self._end(a, "failed", "no-code", exit_code=exit_code)
        elif a.state == "code" and now - (a.code_at or now) > CODE_LIFE:
            self._end(a, "failed", "expired")

    def _finish(self, a: Attempt) -> None:
        if a.tool == "gh":
            # gh as git's GitHub credential for this account, as the bootstrap's step 7 does.
            try:
                r = self.run([self.gh_exe, "auth", "setup-git"], capture_output=True, text=True, env=child_env(),
                             timeout=SETUP_GIT_TIMEOUT, stdin=subprocess.DEVNULL)
                if r.returncode != 0:
                    self._end(a, "failed", "setup-git")
                    return
            except (OSError, subprocess.TimeoutExpired):
                self._end(a, "failed", "setup-git")
                return
        self._end(a, "done", None)

    def _end(self, a: Attempt, state: str, reason: str | None, **extra) -> None:
        if a.proc and a.proc.poll() is None:
            try:
                a.proc.kill()
            except OSError:
                pass
        a.state, a.reason, a.code, a.code_at = state, reason, None, None
        if state == "done":
            self.log("sign-in-done", tool=a.tool, nonce=a.nonce)
        else:
            self.log("sign-in-failed", tool=a.tool, nonce=a.nonce, reason=reason, **extra)

    def status(self) -> dict | None:
        return self.current.status() if self.current else None


def _drain(stream, sink: list[str]) -> None:
    try:
        for line in stream:
            sink.append(line)
    except (OSError, ValueError):
        pass
