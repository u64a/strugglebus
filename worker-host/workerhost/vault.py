"""The vault mirror: a bare, fetch-only clone of a notes repository's `main` (design section 3 step 4).

Nothing is ever checked out. Briefs are read by blob SHA after `git ls-tree` shows a regular file.
Every git call is an argument list, paths come after `--`, and the commit is a validated 40-hex SHA.
"""
from __future__ import annotations

import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path

COMMIT_RE = re.compile(r"[0-9a-f]{40}")
# Relative paths a brief might mention, e.g. research/notes.md or tooling/briefs/_common.txt
PATH_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_./-])((?:[A-Za-z0-9_-]+/)+[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,6})")


class GitVault:
    def __init__(self, path: Path, remote: str, git_exe: str = "git", retries: int = 3, retry_wait: float = 20.0):
        self.path = Path(path)
        self.remote = remote
        self.git_exe = git_exe
        self.retries = retries
        self.retry_wait = retry_wait
        self.last_fetch_ok: bool | None = None

    def _git(self, *args: str, timeout: float = 120, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([self.git_exe, "--git-dir", str(self.path), *args], capture_output=True, timeout=timeout,
                              input=input_bytes, stdin=None if input_bytes is not None else subprocess.DEVNULL)

    def ensure(self) -> bool:
        if not self.remote:
            return False  # no notes repository configured (vault_repo unset): nothing to fetch, no brief to read
        if (self.path / "HEAD").exists():
            return True
        self.path.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run([self.git_exe, "init", "--bare", "-q", "--", str(self.path)], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=60)
        if r.returncode != 0:
            return False
        self._git("config", "remote.origin.url", self.remote)
        self._git("config", "remote.origin.fetch", "+refs/heads/main:refs/remotes/origin/main")
        return True

    def fetch(self) -> bool:
        """Three tries over about a minute; a stale mirror is never used for a new task."""
        if not self.ensure():
            self.last_fetch_ok = False
            return False
        for attempt in range(self.retries):
            try:
                r = self._git("fetch", "-q", "--prune", "--no-tags", "origin", timeout=180)
                if r.returncode == 0:
                    self.last_fetch_ok = True
                    return True
            except subprocess.TimeoutExpired:
                pass
            if attempt + 1 < self.retries:
                time.sleep(self.retry_wait)
        self.last_fetch_ok = False
        return False

    def resolve_commit(self, commit: str) -> str | None:
        if not COMMIT_RE.fullmatch(commit):
            return None
        r = self._git("rev-parse", "--verify", "--quiet", "--end-of-options", commit + "^{commit}")
        out = r.stdout.decode("ascii", "replace").strip()
        return out if r.returncode == 0 and COMMIT_RE.fullmatch(out) else None

    def on_main(self, commit: str) -> bool:
        if not COMMIT_RE.fullmatch(commit):
            return False
        r = self._git("merge-base", "--is-ancestor", commit, "refs/remotes/origin/main")
        return r.returncode == 0

    def brief_entry(self, commit: str, path: str) -> tuple[str, str, str, int] | None:
        if not COMMIT_RE.fullmatch(commit):
            return None
        r = self._git("ls-tree", "-l", "--full-tree", commit, "--", path)
        lines = [l for l in r.stdout.decode("utf-8", "replace").splitlines() if l.strip()]
        if r.returncode != 0 or len(lines) != 1:
            return None
        meta, _, name = lines[0].partition("\t")
        parts = meta.split()
        if name != path or len(parts) != 4 or not parts[3].isdigit():
            return None
        mode, kind, sha, size = parts
        return mode, kind, sha, int(size)

    def read_blob(self, sha: str) -> bytes:
        if not COMMIT_RE.fullmatch(sha):
            return b""
        r = self._git("cat-file", "blob", sha)
        return r.stdout if r.returncode == 0 else b""

    def list_files(self, commit: str) -> set[str]:
        if not COMMIT_RE.fullmatch(commit):
            return set()
        r = self._git("ls-tree", "-r", "--name-only", "--full-tree", commit)
        return set(r.stdout.decode("utf-8", "replace").splitlines()) if r.returncode == 0 else set()

    def referenced_files(self, commit: str, brief_text: str, brief_path: str) -> list[str]:
        """Vault files the brief names by relative path (adjustment 4: export only when needed)."""
        tokens = set(PATH_TOKEN_RE.findall(brief_text)) - {brief_path}
        if not tokens:
            return []
        return sorted(tokens & self.list_files(commit))

    def export(self, commit: str, dest_root: Path) -> Path | None:
        """Export the pinned commit read-only to dest_root/<commit>; reused if already there."""
        if not COMMIT_RE.fullmatch(commit):
            return None
        dest = Path(dest_root) / commit
        if (dest / ".export-complete").exists():
            return dest
        if dest.exists():
            remove_tree(dest)
        r = self._git("archive", "--format=tar", commit, timeout=600)
        if r.returncode != 0:
            return None
        dest.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(r.stdout), mode="r:") as tar:
            tar.extractall(dest, filter="data")  # no absolute paths, no links out, no devices
        for root, dirs, files in os.walk(dest):
            for f in files:
                os.chmod(os.path.join(root, f), stat.S_IREAD)
        (dest / ".export-complete").write_text(commit + "\n", encoding="ascii")
        os.chmod(dest / ".export-complete", stat.S_IREAD)
        return dest


def _onerror(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def long_path(path: Path | str) -> str:
    r"""The absolute path, with the Windows extended-length prefix (\\?\ or \\?\UNC\) on Windows.

    Without it every file call fails past MAX_PATH (260 characters) unless LongPathsEnabled is set,
    which it is not on a default install. Run temp roots holding pytest trees up to 274
    characters deep were logged as deleted every day for weeks and never went (135 GB on the dev box)."""
    p = os.path.abspath(str(path))
    if os.name != "nt" or p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


def remove_tree(path: Path) -> bool:
    """Delete a folder tree; True if it is gone afterwards. Errors on single files are retried once
    with the read-only bit cleared and otherwise ignored, so the result is what tells."""
    target = long_path(path)
    # `onexc` is Python 3.12+; on 3.11 (which install.ps1 accepts) passing it raises TypeError, so end()
    # would fail after a finished worker (a source of caught loop-error TypeErrors).
    try:
        if sys.version_info >= (3, 12):
            shutil.rmtree(target, onexc=lambda f, p, e: _onerror(f, p, e))
        else:
            shutil.rmtree(target, onerror=lambda f, p, e: _onerror(f, p, e))
    except OSError:
        pass
    return not os.path.lexists(target)
