"""Self-update from signed releases (docs/design.md section 10a, agent-host-build.md section 9.4).

A release is `release.toml` (+ `release.toml.sig`, namespace strugglebus-release) on this repository's main:

    serial = 3                     # one more on every signed release (sign-config.ps1 enforces it)
    version = "2026.11.06"         # what people and the heartbeat see
    commit = "<40 hex>"            # the code hosts install: a commit on main
    tree_sha256 = "<64 hex>"       # sha256 over the installed files at that commit (tree_sha256() below)
    needs_install = false          # true: hosts announce it but do not apply it (install.ps1 by hand)
    notes = "one line for the announcement"

The host already mirrors this repository for fleet.toml (<home>\\fleet.git). It reads both files at origin/main, checks
the signature against the pinned keys, then reads the code at `commit` from the same mirror, file by file, and accepts
it only if the files hash to `tree_sha256`. Nothing is downloaded from anywhere else and nothing in the repository is
run before that check.

The installed files are the ones install.ps1 copies: wh.py, config.template.toml, README.md and workerhost\\*.py.

The nightly flow (times from config.toml [update], local time):
  check_at (01:00)   fetch; a newer signed release -> announce it on the announce channel (mentioning every
                     coordinator in fleet.toml) and on the host channel, and refuse new tasks ("maintenance").
  window (03:00)     no worker running -> apply.
  window + grace     workers still running -> save each one's work to its branch (as a timeout does), stop it,
  (03:30)            apply; after the restart each such task is resumed once, as after a reboot.
  window + grace + 60 min without having applied (the host was off or asleep) -> give up for tonight and take tasks
                     again; the next check announces it again.
Applying: stage the files, run the staged code's `selftest`, back up the current files to <home>\\app.prev, write the
new ones over <home>\\app, record update.json "applied", exit with EXIT_UPDATE. The supervisor (still running the
previous code) restarts the host at once on the new code. If the new host then fails three times in a row within
the supervisor's stable period, the supervisor puts app.prev back ("rolled-back") and that release is never retried.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from . import signing
from .state import atomic_write_json

FILE, SIG = "release.toml", "release.toml.sig"
EXIT_UPDATE = 75  # the host exits with this after applying an update: the supervisor restarts it at once
ROOT_FILES = ("wh.py", "config.template.toml", "README.md")
PACKAGE = "workerhost"
INSTALLED = "RELEASE.json"  # in <home>\app: what is installed (install.ps1 writes "manual", serial 0)
VERSION_RE = re.compile(r"[0-9][0-9A-Za-z.+-]{0,31}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
ROLLBACK_AFTER = 3  # quick failures of the new code before the supervisor restores the previous files
MAX_BYTES = 16 * 1024


class ReleaseError(ValueError):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason, self.detail = reason, detail


@dataclass(frozen=True)
class Release:
    serial: int
    version: str
    commit: str
    tree_sha256: str
    needs_install: bool = False
    notes: str = ""
    moved_to: tuple[str, str] | None = None  # (repository URL, folder): the signed redirect, see parse_moved_to


# The signed redirect (the security review's rules):
#   moved_to = {repo = "https://github.com/<owner>/<repo>", path = "<folder>"}
# It moves where releases are read from, never what they are checked against: it can name no key, namespace or
# signer, and the same pinned project release key keeps verifying (a). It is recorded only in the installed release's
# RELEASE.json, so it takes effect once that release is installed and a rollback takes it away (recorded only from an
# installed release; one hop per release, d). The installed serial is host state that a redirect never resets, so an
# older signed release at the new source is never applied (b).
MOVED_KEYS = frozenset({"repo", "path"})
MOVED_REPO_RE = re.compile(r"https://[a-z0-9][a-z0-9.-]{0,252}/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")


def parse_moved_to(raw) -> tuple[str, str] | None:
    from .config import RELEASE_PATH_RE  # config imports nothing from here

    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != MOVED_KEYS:
        raise ReleaseError("release-invalid", "moved_to takes exactly repo and path")
    repo, path = raw["repo"], raw["path"]
    if not isinstance(repo, str) or not MOVED_REPO_RE.fullmatch(repo) or repo.endswith((".", ".git")):
        raise ReleaseError("release-invalid", "moved_to.repo")
    if not isinstance(path, str) or not RELEASE_PATH_RE.fullmatch(path):
        raise ReleaseError("release-invalid", "moved_to.path")
    return repo, path


def parse_release(data: bytes) -> Release:
    if len(data) > MAX_BYTES:
        raise ReleaseError("release-invalid", "size")
    try:
        raw = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ReleaseError("release-invalid", f"toml: {e}") from None
    serial = raw.get("serial")
    if not isinstance(serial, int) or isinstance(serial, bool) or serial < 1:
        raise ReleaseError("release-invalid", "serial")
    version, commit, tree = raw.get("version"), raw.get("commit"), raw.get("tree_sha256")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ReleaseError("release-invalid", "version")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise ReleaseError("release-invalid", "commit")
    if not isinstance(tree, str) or not SHA256_RE.fullmatch(tree):
        raise ReleaseError("release-invalid", "tree_sha256")
    needs = raw.get("needs_install", False)
    if type(needs) is not bool:
        raise ReleaseError("release-invalid", "needs_install")
    notes = raw.get("notes", "")
    if not isinstance(notes, str) or len(notes) > 300 or any(ord(c) < 32 for c in notes):
        raise ReleaseError("release-invalid", "notes")
    return Release(serial, version, commit, tree, needs, notes, parse_moved_to(raw.get("moved_to")))


# --- the installed files ----------------------------------------------------------------------------------------

def wanted(path: str) -> bool:
    """A path (POSIX, repository-relative) that install.ps1 copies into <home>\\app."""
    if path in ROOT_FILES:
        return True
    parts = path.split("/")
    return len(parts) == 2 and parts[0] == PACKAGE and parts[1].endswith(".py") and re.fullmatch(r"[A-Za-z0-9_]+\.py", parts[1]) is not None


def tree_sha256(files: dict[str, bytes]) -> str:
    """sha256 over "<sha256 of the file>  <path>\\n" for each file, sorted by path. Independent of git's own object
    format and version, so the signing PC and every host compute the same value."""
    lines = "".join(f"{hashlib.sha256(files[p]).hexdigest()}  {p}\n" for p in sorted(files))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def read_tree(git_exe: str, git_dir: Path | None, commit: str, cwd: Path | None = None,
              prefix: str = "") -> dict[str, bytes]:
    """The installed files at `commit`, read from a repository (a bare mirror with git_dir, or a work tree at cwd).
    With a prefix (the code's folder, e.g. "worker-host"), only that folder is read, and paths are returned relative
    to it, so tree_sha256 is the same wherever the code sits."""
    base = [git_exe] + (["--git-dir", str(git_dir)] if git_dir else [])
    lead = f"{prefix}/" if prefix else ""
    r = subprocess.run(base + ["ls-tree", "-r", "-z", commit, "--"] + [lead + p for p in (*ROOT_FILES, PACKAGE)],
                       capture_output=True, timeout=120, cwd=cwd, stdin=subprocess.DEVNULL)
    if r.returncode != 0:
        raise ReleaseError("release-commit", "ls-tree")
    files: dict[str, bytes] = {}
    for entry in r.stdout.split(b"\0"):
        if not entry:
            continue
        meta, _, path_b = entry.partition(b"\t")
        mode, kind, sha = meta.decode("ascii").split()
        path = path_b.decode("utf-8")
        if lead:
            if not path.startswith(lead):
                continue
            path = path[len(lead):]
        if kind != "blob" or not wanted(path):
            continue
        if mode != "100644":
            raise ReleaseError("release-commit", f"{path} is not a regular file")
        blob = subprocess.run(base + ["cat-file", "blob", sha], capture_output=True, timeout=120, cwd=cwd,
                              stdin=subprocess.DEVNULL)
        if blob.returncode != 0:
            raise ReleaseError("release-commit", f"cat-file {path}")
        files[path] = blob.stdout
    if "wh.py" not in files or not any(p.startswith(PACKAGE + "/") for p in files):
        raise ReleaseError("release-commit", "no host code at that commit")
    return files


def installed(app_dir: Path) -> dict:
    """What is installed. moved_to is the installed release's signed redirect, or None (checked again here: the file
    sits in a folder the host's user can write)."""
    try:
        rec = json.loads((Path(app_dir) / INSTALLED).read_text(encoding="utf-8"))
        if isinstance(rec, dict):
            try:
                moved = parse_moved_to(rec.get("moved_to"))
            except ReleaseError:
                moved = None
            return {"version": str(rec.get("version", "manual")), "serial": int(rec.get("serial", 0) or 0),
                    "commit": str(rec.get("commit", "")), "moved_to": moved}
    except (OSError, ValueError, TypeError):
        pass
    return {"version": "manual", "serial": 0, "commit": "", "moved_to": None}


def is_newer(rel: Release, inst: dict) -> bool:
    """A release is applied when its serial is above the installed one and its code is not what is installed."""
    return rel.serial > int(inst.get("serial", 0)) and rel.commit != inst.get("commit")


# --- reading a release from the mirror ----------------------------------------------------------------------------

@dataclass(frozen=True)
class Where:
    """Where releases are read from: a repository URL ("" = the fleet mirror), the code's folder in it, and why
    (fleet: as always; config: release_repo/release_url set by hand; redirect: the installed release's moved_to)."""
    url: str
    path: str
    origin: str
    refused: str = ""  # an installed redirect that failed the [remotes] fence: its URL (the host uses the fleet)

    def label(self) -> str:
        return "fleet" if self.origin == "fleet" else f"{self.url}#{self.path}" if self.path else self.url


def where(cfg, inst: dict) -> Where:
    """config.toml first (an administrator's explicit choice), then the installed release's signed redirect, then
    the fleet mirror. Whichever it is, releases are checked against the same pinned project release key.

    The installed redirect is read from RELEASE.json, which the host's own account can write, so it is fenced again
    here exactly as an incoming one is (security review): one outside [remotes] allowed is not used, and
    the host falls back to the fleet mirror and reports it."""
    if cfg.release_remote():
        return Where(cfg.release_remote(), cfg.release_path, "config")
    if inst.get("moved_to"):
        url, path = inst["moved_to"]
        if not _within(url, getattr(cfg, "remotes", [])):
            return Where("", cfg.release_path, "fleet", refused=url)
        return Where(url, path, "redirect")
    return Where("", cfg.release_path, "fleet")


def _within(url: str, remotes: list[str]) -> bool:
    from . import urls

    return any(urls.url_matches(url, p) for p in remotes)


def redirect_allowed(rel: Release, remotes: list[str]) -> bool:
    """A redirect only to a repository under the host's [remotes] allowed prefixes (https by MOVED_REPO_RE)."""
    return rel.moved_to is None or _within(rel.moved_to[0], remotes)


def mirror_for(mirrors_dir: Path, url: str) -> Path:
    """One bare mirror per release repository URL, so a changed URL never reuses another repository's objects."""
    return Path(mirrors_dir) / (hashlib.sha256(url.encode("utf-8")).hexdigest()[:16] + ".git")


def fetch_release_mirror(git_exe: str, mirror: Path, url: str, ref: str = "main", timeout: float = 300) -> bool:
    """Fetch only `ref` of `url` into a blob-less bare mirror (security review, rule c): never every ref (GitHub exposes each
    pull request as refs/pull/N/head), and only the blobs actually read. Commits and trees come; a file's content is
    fetched when read_tree reads it, and the signed tree hash checks it.

    The mirror sits in the host's writable state, so its remote settings are set again before EVERY fetch and the
    refspec is given on the command line (security review): an edited remote.origin.fetch or url never
    persists into what is fetched."""
    mirror = Path(mirror)
    refspec = f"+refs/heads/{ref}:refs/remotes/origin/{ref}"

    def git(*args: str, t: float = 120) -> bool:
        return subprocess.run([git_exe, "--git-dir", str(mirror), *args], capture_output=True, timeout=t,
                              stdin=subprocess.DEVNULL).returncode == 0

    try:
        if not (mirror / "HEAD").exists():
            mirror.parent.mkdir(parents=True, exist_ok=True)
            if subprocess.run([git_exe, "init", "--bare", "-q", "--", str(mirror)], capture_output=True, timeout=60,
                              stdin=subprocess.DEVNULL).returncode != 0:
                return False
        git("config", "--unset-all", "remote.origin.fetch")
        for key, value in (("remote.origin.url", url), ("remote.origin.fetch", refspec),
                           ("remote.origin.tagOpt", "--no-tags"), ("remote.origin.followRemoteHEAD", "never"),
                           ("remote.origin.promisor", "true"), ("remote.origin.partialclonefilter", "blob:none")):
            if not git("config", key, value):
                return False
        return git("fetch", "-q", "--no-tags", "--filter=blob:none", "origin", refspec, t=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return False


class ReleaseSource:
    """release.toml at origin/main of a repository mirror: the fleet mirror (as before), or a release repository's
    own mirror, with the code in `path` ("" = its top level)."""

    def __init__(self, mirror: Path, git_exe: str, ssh_keygen: str | None, signers: Path, workdir: Path,
                 ref: str = "refs/remotes/origin/main", path: str = ""):
        self.mirror, self.git_exe, self.ssh_keygen = Path(mirror), git_exe, ssh_keygen
        self.signers, self.workdir, self.ref, self.path = Path(signers), Path(workdir), ref, path

    def _in(self, name: str) -> str:
        return f"{self.path}/{name}" if self.path else name

    def _blob(self, commit: str, path: str) -> bytes | None:
        r = subprocess.run([self.git_exe, "--git-dir", str(self.mirror), "cat-file", "blob", f"{commit}:{path}"],
                           capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        return r.stdout if r.returncode == 0 else None

    def read(self) -> tuple[Release | None, str]:
        """(release, "ok") or (None, a reason: release-missing, release-unsigned, release-bad-signature,
        release-cannot-verify, release-invalid, fetch-failed)."""
        r = subprocess.run([self.git_exe, "--git-dir", str(self.mirror), "rev-parse", "--verify", "--quiet",
                            self.ref + "^{commit}"], capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        head = r.stdout.decode("ascii", "replace").strip()
        if r.returncode != 0 or not COMMIT_RE.fullmatch(head):
            return None, "fetch-failed"
        data = self._blob(head, self._in(FILE))
        if data is None:
            return None, "release-missing"
        sig = self._blob(head, self._in(SIG))
        if sig is None:
            return None, "release-unsigned"
        v = signing.verify(data, sig, signing.NS_RELEASE, self.signers, self.ssh_keygen, self.workdir)
        if not v.ok:
            return None, {"no-signers": "release-cannot-verify", "no-ssh-keygen": "release-cannot-verify",
                          "sig-shape": "release-unsigned"}.get(v.reason, "release-bad-signature")
        try:
            return parse_release(data), "ok"
        except ReleaseError as e:
            return None, e.reason

    def files(self, rel: Release) -> dict[str, bytes]:
        files = read_tree(self.git_exe, self.mirror, rel.commit, prefix=self.path)
        if tree_sha256(files) != rel.tree_sha256:
            raise ReleaseError("release-tree", "the files at that commit do not match the signed tree_sha256")
        return files


# --- staging, applying, restoring ---------------------------------------------------------------------------------

def write_files(files: dict[str, bytes], dest: Path) -> None:
    for path, data in files.items():
        target = Path(dest) / Path(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def current_files(app_dir: Path) -> dict[str, bytes]:
    out = {}
    for name in ROOT_FILES:
        p = Path(app_dir) / name
        if p.is_file():
            out[name] = p.read_bytes()
    pkg = Path(app_dir) / PACKAGE
    if pkg.is_dir():
        for p in pkg.glob("*.py"):
            out[f"{PACKAGE}/{p.name}"] = p.read_bytes()
    return out


def apply_files(files: dict[str, bytes], app_dir: Path, backup_dir: Path, rel: Release) -> None:
    """Back up what is installed (files and RELEASE.json) to backup_dir, write the new files over app_dir in place
    (processes keep app_dir as their working folder, so the folder itself is never renamed), remove package modules
    the new release no longer has, and record the release."""
    app_dir, backup_dir = Path(app_dir), Path(backup_dir)
    if backup_dir.exists():
        shutil.rmtree(backup_dir)
    old = current_files(app_dir)
    write_files(old, backup_dir)
    if (app_dir / INSTALLED).exists():
        shutil.copy2(app_dir / INSTALLED, backup_dir / INSTALLED)
    write_files(files, app_dir)
    for path in old:
        if path.startswith(PACKAGE + "/") and path not in files:
            (app_dir / Path(*path.split("/"))).unlink(missing_ok=True)
    record = {"version": rel.version, "serial": rel.serial, "commit": rel.commit, "tree_sha256": rel.tree_sha256}
    if rel.moved_to:
        record["moved_to"] = {"repo": rel.moved_to[0], "path": rel.moved_to[1]}
    (app_dir / INSTALLED).write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")


def restore(app_dir: Path, backup_dir: Path) -> bool:
    """Put the backed-up files back (the supervisor's rollback). False when there is no backup."""
    app_dir, backup_dir = Path(app_dir), Path(backup_dir)
    old = current_files(backup_dir)
    if "wh.py" not in old:
        return False
    for path in current_files(app_dir):
        if path.startswith(PACKAGE + "/") and path not in old:
            (app_dir / Path(*path.split("/"))).unlink(missing_ok=True)
    write_files(old, app_dir)
    if (backup_dir / INSTALLED).exists():
        shutil.copy2(backup_dir / INSTALLED, app_dir / INSTALLED)
    else:
        (app_dir / INSTALLED).unlink(missing_ok=True)
    return True


# --- update.json: the update's state, shared by the host and the supervisor -----------------------------------------

def load_state(path: Path) -> dict:
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: Path, data: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(Path(path), data)


# --- the window -----------------------------------------------------------------------------------------------------

def _at(day: datetime, hhmm: str) -> datetime:
    h, m = (int(x) for x in hhmm.split(":"))
    return day.replace(hour=h, minute=m, second=0, microsecond=0)


def decide(now: datetime, check_at: str, window: str, grace_minutes: float, state: dict, busy: bool) -> str:
    """Pure: what the host does now. One of: wait, check, apply, stop-and-apply, give-up.

    The window opens at `window` (local) on the day of `now`, or the day before when check_at is after window (a
    check at 23:00 for a 03:00 window). A check happens once per window, between check_at and the window's end."""
    win = _at(now, window)
    chk = _at(now, check_at)
    if chk > win:  # check the evening before
        if now >= chk:
            win += timedelta(days=1)
        else:
            chk -= timedelta(days=1)
    grace_end = win + timedelta(minutes=grace_minutes)
    give_up = grace_end + timedelta(minutes=60)
    phase = state.get("phase", "")
    if phase == "announced":
        if now >= give_up or now < chk:
            return "give-up"
        if now >= grace_end:
            return "stop-and-apply"
        if now >= win:
            return "wait" if busy else "apply"
        return "wait"
    if chk <= now < give_up and state.get("checked_for") != win.strftime("%Y-%m-%dT%H:%M"):
        return "check"
    return "wait"


def window_key(now: datetime, check_at: str, window: str) -> str:
    """Which window a check at `now` belongs to (so there is one check per window)."""
    win, chk = _at(now, window), _at(now, check_at)
    if chk > win and now >= chk:
        win += timedelta(days=1)
    return win.strftime("%Y-%m-%dT%H:%M")


def announcement(host: str, rel: Release, current: str, window: str, grace_minutes: float,
                 coordinators: list[str]) -> str:
    mentions = " ".join(f"@{c}" for c in coordinators)
    until = (_at(datetime(2000, 1, 1), window) + timedelta(minutes=grace_minutes)).strftime("%H:%M")
    text = (f"{mentions} host {host} updates the worker host from {current} to {rel.version} at {window} "
            f"(local; by {until} at the latest). It takes no new tasks until then; a worker still running at {until} "
            f"has its work pushed to its branch and is resumed once after the update.")
    if rel.notes:
        text += f" Release notes: {rel.notes}"
    return text.strip()


def selftest_command(python: str, staged_app: Path, home: Path) -> list[str]:
    return [python, str(Path(staged_app) / "wh.py"), "--home", str(home), "selftest"]


def run_selftest(python: str, staged_app: Path, home: Path, timeout: float = 120) -> tuple[bool, str]:
    try:
        r = subprocess.run(selftest_command(python, staged_app, home), capture_output=True, timeout=timeout,
                           cwd=str(staged_app), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, type(e).__name__
    tail = (r.stdout + r.stderr).decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
    return r.returncode == 0, tail[0][:200]


def now_local() -> datetime:
    return datetime.now()


def stamp() -> float:
    return time.time()
