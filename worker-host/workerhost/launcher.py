"""Launching a worker (design section 8), the same path as tooling/worker.py:

clone (gh repo clone) or refresh (git fetch), check out the branch, onboard + bootstrap <agent_prefix>-<worker>
(config.agent_name; the prefix is the SPN's name) on first use, then
`copilot -p <fixed preamble + brief> --allow-all-tools --no-auto-update [--no-custom-instructions] --add-dir <home>\\app
[--add-dir <home>\\vault-export\\<commit>] --model <model>` in the clone (prompt.command; the second --add-dir only when the brief names other vault files and
the pinned commit was exported), output logged to <workers_root>\\<worker>.log, exit code captured.

Differences from worker.py: the process runs in a kill-on-close Job Object, gets its own TEMP, its
output passes a redaction filter on the way to the log, the bus credential lives in the DPAPI store
(SB_BUS_STORE) and is decrypted by agent name, and the session id is chosen by the host.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import prompt as prompt_mod
from . import winapi
from .cleanup import uncommitted
from .redact import redact

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
META = ".ds-worker.json"
# Never inherited from the host's own environment: only what the host sets for this task.
NOTES_ENV = {"SB_" + n
             for n in ("TASK_SEQ", "COORDINATOR_ID", "COORDINATOR_NAME", "NOTES_CHANNEL", "PROJECT", "NOTES_NAME")}


class LaunchError(Exception):
    """Carries a fixed reason code, never message text."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _git(git_exe: str, clone: Path, *args: str, timeout: float = 600) -> subprocess.CompletedProcess:
    return subprocess.run([git_exe, "-C", str(clone), *args], capture_output=True, timeout=timeout,
                          stdin=subprocess.DEVNULL)


def resolve_exe(name: str) -> str:
    """An absolute path to a real executable, or LaunchError. Never a bare name: a bare name could be
    found in a worker clone (a repository can contain a copilot.exe)."""
    path = shutil.which(name) if not os.path.isabs(name) else (name if os.path.isfile(name) else None)
    if not path or not os.path.isabs(path):
        raise LaunchError("copilot-missing")
    if Path(path).suffix.lower() in (".cmd", ".bat"):
        # cmd.exe would re-parse the arguments; the prompt must never meet a shell.
        raise LaunchError("copilot-wrapper")
    return path


def tool_path(name: str) -> str | None:
    """Absolute path of a helper tool (git, gh) or None; used before running it with a clone as cwd."""
    if os.path.isabs(name):
        return name if os.path.isfile(name) else None
    found = shutil.which(name)
    return found if found and os.path.isabs(found) else None


def dirty(clone: Path, git_exe: str) -> bool:
    """Uncommitted or untracked changes (other than the meta file and line-ending-only changes, issue
    #28), or anything stashed. A git failure counts as dirty."""
    lines = uncommitted(clone, git_exe)
    if lines is None:
        return True
    stash = _git(git_exe, clone, "stash", "list")
    return bool(lines) or stash.returncode != 0 or bool(stash.stdout.strip())


def _as_url(repo: str) -> str:
    """A checked clone URL, or the old owner/repo form (GitHub)."""
    return repo if "://" in repo else f"https://github.com/{repo}"


def _origin_matches(url: str, repo: str) -> bool:
    """The clone's origin is the task's repository (case-insensitive, .git and trailing slash ignored)."""
    def norm(u: str) -> str:
        return u.strip().lower().removesuffix("/").removesuffix(".git").rstrip("/")
    return norm(url) == norm(_as_url(repo))


def prepare_clone(workers_root: Path, worker: str, repo: str, branch: str, gh_exe: str, git_exe: str,
                  require_clean: bool = True) -> Path:
    """`repo`: the task's checked clone URL (validate.resolve_repo); owner/repo is still taken as GitHub.

    require_clean (every launch but a resume): a clone holding someone's unfinished work is not reused
    for a different task; it stays held for its own resume or for a person. A clone of another repository (two
    projects using one worker name) is refused, never re-pointed: clone-mismatch."""
    clone = Path(workers_root) / worker
    Path(workers_root).mkdir(parents=True, exist_ok=True)
    url = _as_url(repo)
    if not clone.exists():
        if url.lower().startswith("https://github.com/"):
            cmd = [gh_exe, "repo", "clone", url, str(clone), "--", "-q"]  # gh's own sign-in, as before
        else:
            cmd = [git_exe, "clone", "-q", "--", url, str(clone)]  # e.g. the LAN Forgejo
        r = subprocess.run(cmd, capture_output=True, timeout=1800, stdin=subprocess.DEVNULL,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        if r.returncode != 0:
            raise LaunchError("clone")
    else:
        origin = _git(git_exe, clone, "remote", "get-url", "origin")
        if origin.returncode != 0 or not _origin_matches(origin.stdout.decode("utf-8", "replace"), repo):
            raise LaunchError("clone-mismatch")
        if _git(git_exe, clone, "fetch", "-q", "--prune", "origin").returncode != 0:
            raise LaunchError("fetch")
        if require_clean and dirty(clone, git_exe):
            raise LaunchError("clone-dirty")
    if _git(git_exe, clone, "check-ref-format", "--branch", branch).returncode != 0:
        raise LaunchError("branch")
    current = _git(git_exe, clone, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.decode().strip()
    if current != branch:
        if _git(git_exe, clone, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}").returncode == 0:
            r = _git(git_exe, clone, "switch", "-q", branch)
        elif _git(git_exe, clone, "show-ref", "--verify", "--quiet", f"refs/remotes/origin/{branch}").returncode == 0:
            r = _git(git_exe, clone, "switch", "-q", "-c", branch, "--track", f"origin/{branch}")
        else:
            _git(git_exe, clone, "remote", "set-head", "origin", "--auto")
            r = _git(git_exe, clone, "switch", "-q", "--no-track", "-c", branch, "origin/HEAD")
        if r.returncode != 0:
            raise LaunchError("checkout")
    exclude = clone / ".git" / "info" / "exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    existing = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
    if META not in existing.splitlines():
        with open(exclude, "a", encoding="utf-8") as fh:
            fh.write(("" if existing.endswith("\n") or not existing else "\n") + META + "\n")
    os.utime(clone)
    return clone


def write_meta(clone: Path, meta: dict) -> None:
    (clone / META).write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")


def session_ok(session_id: str, clone: Path, home: Path | None = None) -> bool:
    """Resume only a session whose own record says it ran in this worker's clone."""
    if not isinstance(session_id, str) or not UUID_RE.fullmatch(session_id):
        return False
    ws = Path(home or Path.home()) / ".copilot" / "session-state" / session_id / "workspace.yaml"
    try:
        lines = ws.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in lines:
        if line.startswith("cwd:"):
            value = line.split(":", 1)[1].strip().strip("'\"")
            return os.path.normcase(os.path.abspath(value)) == os.path.normcase(os.path.abspath(clone))
    return False


@dataclass
class WorkerRun:
    worker: str
    task_id: str
    proc: subprocess.Popen
    job: object
    log: Path
    temp: Path
    started: float = field(default_factory=time.time)
    last_output: float = field(default_factory=time.time)
    reader: threading.Thread | None = None

    def poll(self) -> int | None:
        code = self.proc.poll()
        if code is not None and self.reader is not None:
            self.reader.join(timeout=5)
        return code

    def kill(self) -> None:
        try:
            self.job.terminate(1)
        except Exception:  # noqa: BLE001
            self.proc.kill()


def _pump(run: WorkerRun) -> None:
    with open(run.log, "a", encoding="utf-8", errors="replace") as fh:
        for raw in iter(run.proc.stdout.readline, b""):
            fh.write(redact(raw.decode("utf-8", "replace")))
            fh.flush()
            run.last_output = time.time()
    run.proc.stdout.close()


def header(fields: dict) -> str:
    return "\n===== worker host task " + " ".join(f"{k}={v}" for k, v in fields.items()) + " =====\n"


def launch(cmd: list[str], clone: Path, env: dict, log: Path, temp: Path, worker: str, task_id: str,
           log_header: str, job=None, stdin_text: str | None = None) -> WorkerRun:
    """stdin_text (Claude Code): the prompt, written to the process's stdin and closed; otherwise stdin is empty."""
    temp.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8", errors="replace") as fh:
        fh.write(log_header)
    job = job or winapi.Job()
    proc = winapi.start_in_job(cmd, job, cwd=str(clone), env=env,
                               stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if stdin_text is not None:
        def feed() -> None:
            try:
                proc.stdin.write(stdin_text.encode("utf-8"))
            except OSError:
                pass  # the process died before reading: its exit code and log say why
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
        threading.Thread(target=feed, daemon=True).start()
    run = WorkerRun(worker, task_id, proc, job, log, temp)
    run.reader = threading.Thread(target=_pump, args=(run,), daemon=True)
    run.reader.start()
    return run


BUS_SECRET_ENV = {"SB_BUS_TOKEN", "SB_BUS_STORE"}


def worker_env(base: dict, *, bus_ca: str, bus_url: str, store: Path | None, temp: Path, gh_exe: str,
               wait_timeout: int, task_seq: int = 0, coordinator=None, notes_channel: str = "",
               project: str = "", token: str | None = None, notes_name: str = "") -> dict:
    """task_seq (the seq the task was posted at), the coordinator pin and its notes channel are what the bus
    client's read-only `notes` command filters on; never anything taken from a message body.

    The worker's bus credential: with OpenBao, `token` goes in SB_BUS_TOKEN only (this process environment,
    never on disk, never logged) and no store is named; without it, SB_BUS_STORE names the DPAPI store as before.
    Whatever the host itself inherited under those names is dropped first, so a worker never sees two.

    Every other variable is set as SB_<name> (section 7.4)."""
    if bool(token) == bool(store):
        raise ValueError("a worker gets exactly one of token or store")
    env = {k: v for k, v in base.items()
           if not k.upper().startswith("WORKERHOST_") and k.upper() not in NOTES_ENV
           and k.upper() not in BUS_SECRET_ENV}
    values = {"BUS_CA": bus_ca, "BUS_URL": bus_url}
    if store:
        values["BUS_STORE"] = str(store)
    else:
        env["SB_BUS_TOKEN"] = token
    if task_seq:
        values["TASK_SEQ"] = str(int(task_seq))
    if coordinator is not None and coordinator.agent_id:
        values["COORDINATOR_ID"] = coordinator.agent_id
        values["COORDINATOR_NAME"] = coordinator.agent_name
    if notes_channel:
        values["NOTES_CHANNEL"] = notes_channel
    if project:
        values["PROJECT"] = project
    if notes_name:
        values["NOTES_NAME"] = notes_name  # phase 2: the stable <prefix>-<worker> that coordinators address
    for name, value in values.items():
        env["SB_" + name] = value
    env.update({"TEMP": str(temp), "TMP": str(temp), "COPILOT_TASK_WAIT_TIMEOUT_SECONDS": str(wait_timeout)})
    gh_dir = str(Path(shutil.which(gh_exe) or gh_exe).parent)
    env["PATH"] = gh_dir + os.pathsep + env.get("PATH", "")
    return env


def build(copilot_exe: str, brief_text: str, busclient: str, model: str, session_id: str, resume: bool,
          vault_export: str | None = None, repo_instructions: bool = True, project=None) -> list[str]:
    prompt = prompt_mod.build_prompt(brief_text, busclient, vault_export, project)
    return prompt_mod.command(resolve_exe(copilot_exe), prompt, model, session_id, resume, vault_export,
                              repo_instructions)


def build_claude(claude_exe: str, brief_text: str, busclient: str, model: str, session_id: str, resume: bool,
                 vault_export: str | None = None, repo_instructions: bool = True,
                 project=None) -> tuple[list[str], str]:
    """Claude Code: (argument list, prompt for stdin). See workerhost/engines.py for the flags and why."""
    from . import engines
    from .config import INSTALL_DIR
    exe = engines.resolve(claude_exe)
    if exe is None:
        raise LaunchError("claude-missing")
    prompt = prompt_mod.build_prompt(brief_text, busclient, vault_export, project,
                                     engines.CLAUDE_REPO_NOTE if repo_instructions else "")
    return engines.claude_command(exe, model, session_id, resume, str(INSTALL_DIR), vault_export), prompt
