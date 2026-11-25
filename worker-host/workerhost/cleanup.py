"""Clean-up (design section 11). A clone is deleted or cleaned only when nothing in it could be lost.

A clone may be deleted only if, after a successful `git fetch origin`: no worker uses it, it has no
uncommitted work (`uncommitted` below), `git stash list` is empty and every local commit is on the
remote (or the branch was squash-merged: `gh` shows a merged PR whose head commit is the local tip).
Anything else is held. If the fetch fails, nothing is deleted.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .vault import remove_tree

KEEP = ".ds-worker.json"


@dataclass
class Verdict:
    safe: bool
    reason: str


def _git(git_exe: str, clone: Path, *args: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run([git_exe, "-C", str(clone), *args], capture_output=True, timeout=timeout,
                          stdin=subprocess.DEVNULL)


def _out(r: subprocess.CompletedProcess) -> str:
    return r.stdout.decode("utf-8", "replace").strip()


def _status_entries(raw: bytes) -> list[tuple[str, str]]:
    """`git status --porcelain=v1 -z` as (XY, path) pairs. A rename or copy is followed by a second
    NUL-separated field (the original path), which is skipped."""
    fields = raw.decode("utf-8", "replace").split("\0")
    entries, i = [], 0
    while i < len(fields):
        rec = fields[i]
        i += 1
        if len(rec) < 4:
            continue
        xy, path = rec[:2], rec[3:]
        if "R" in xy or "C" in xy:
            i += 1
        entries.append((xy, path))
    return entries


def uncommitted(clone: Path, git_exe: str = "git") -> list[str] | None:
    """Uncommitted or untracked work, as "XY path" lines (porcelain v1); None if git failed (unsafe).

    Two things are not work and are left out: the host's meta file, and a tracked file whose only
    change is its line endings. The second: a file committed with CRLF while
    .gitattributes says `eol=lf` shows as modified (` M`) in every fresh checkout on Windows, which
    held ~50 clones of one repository for ever. Only work-tree-only modifications (` M`) are tested that
    way, with `git diff --ignore-cr-at-eol`; staged, added, deleted, renamed, conflicted and untracked
    entries always count."""
    status = _git(git_exe, clone, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=no")
    if status.returncode != 0:
        return None
    entries = [(xy, path) for xy, path in _status_entries(status.stdout) if path != KEEP]
    if any(xy == " M" for xy, _ in entries):
        real = _git(git_exe, clone, "diff", "--ignore-cr-at-eol", "--name-only", "-z")
        if real.returncode != 0:
            return None
        changed = set(real.stdout.decode("utf-8", "replace").split("\0")) - {""}
        entries = [(xy, path) for xy, path in entries if xy != " M" or path in changed]
    return [f"{xy} {path}" for xy, path in entries]


def unpushed(clone: Path, git_exe: str = "git") -> str | None:
    """Local commits not on origin, as rev-list output; None if git failed (treated as unsafe)."""
    r = _git(git_exe, clone, "rev-list", "--branches", "--not", "--remotes=origin")
    return _out(r) if r.returncode == 0 else None


def squash_merged(clone: Path, gh_exe: str, git_exe: str = "git") -> bool:
    """Every unpushed local branch has a merged PR whose head commit equals the branch tip."""
    # gh runs with the clone as cwd: only ever by absolute path, never a bare name a clone could shadow.
    gh = gh_exe if os.path.isabs(gh_exe) else shutil.which(gh_exe)
    if not gh or not os.path.isabs(gh) or not os.path.isfile(gh):
        return False
    r = _git(git_exe, clone, "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads/")
    if r.returncode != 0:
        return False
    for line in _out(r).splitlines():
        branch, _, tip = line.partition(" ")
        on_remote = _git(git_exe, clone, "branch", "-r", "--contains", tip)
        if on_remote.returncode == 0 and _out(on_remote):
            continue
        try:
            pr = subprocess.run([gh, "pr", "list", "--head", branch, "--state", "merged", "--json", "headRefOid",
                                 "--limit", "20"], cwd=str(clone), capture_output=True, timeout=120,
                                stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return False
        if pr.returncode != 0:
            return False
        try:
            heads = {p.get("headRefOid") for p in json.loads(pr.stdout or b"[]")}
        except ValueError:
            return False
        if tip not in heads:
            return False
    return True


def may_delete(clone: Path, in_use: bool, git_exe: str = "git", gh_exe: str = "gh") -> Verdict:
    if in_use:
        return Verdict(False, "in-use")
    if not (clone / ".git").exists():
        return Verdict(False, "not-a-clone")
    try:
        if _git(git_exe, clone, "fetch", "-q", "origin").returncode != 0:
            return Verdict(False, "fetch-failed")
        dirty = uncommitted(clone, git_exe)
        if dirty is None:
            return Verdict(False, "git-failed")
        if dirty:
            return Verdict(False, "uncommitted")
        stash = _git(git_exe, clone, "stash", "list")
        if stash.returncode != 0 or _out(stash):
            return Verdict(False, "stash")
        ahead = unpushed(clone, git_exe)
        if ahead is None:
            return Verdict(False, "git-failed")
        if ahead and not squash_merged(clone, gh_exe, git_exe):
            return Verdict(False, "unpushed")
    except (OSError, subprocess.TimeoutExpired):
        return Verdict(False, "git-failed")
    return Verdict(True, "clean")


def delete_clone(clone: Path, in_use: bool, git_exe: str = "git", gh_exe: str = "gh") -> Verdict:
    verdict = may_delete(clone, in_use, git_exe, gh_exe)
    if verdict.safe and not remove_tree(clone):
        return Verdict(False, "delete-failed")
    return verdict


def clean_after_finish(clone: Path, exit_code: int, salvage_dir: Path, tag: str, cap_mb: int,
                       git_exe: str = "git") -> tuple[bool, str, list[str]]:
    """After a run: `git clean -ffdx` only on exit 0, nothing unpushed, and untracked files salvaged.

    Returns (cleaned, reason, salvaged file names).
    """
    if exit_code != 0:
        return False, "exit-code", []
    try:
        ahead = unpushed(clone, git_exe)
        if ahead is None or ahead:
            return False, "unpushed", []
        r = _git(git_exe, clone, "ls-files", "--others", "--exclude-standard", "-z")
        if r.returncode != 0:
            return False, "git-failed", []
        names = [n for n in r.stdout.decode("utf-8", "replace").split("\0") if n and n != KEEP]
        total = sum((clone / n).stat().st_size for n in names if (clone / n).is_file())
        if total > cap_mb * 1024 * 1024:
            return False, "salvage-too-big", []
        if names:
            salvage_dir.mkdir(parents=True, exist_ok=True)
            safe_tag = re.sub(r"[^A-Za-z0-9_.-]", "_", tag)[:80]
            with zipfile.ZipFile(salvage_dir / f"{safe_tag}.zip", "w", zipfile.ZIP_DEFLATED) as z:
                for n in names:
                    if (clone / n).is_file():
                        z.write(clone / n, n)
        if _git(git_exe, clone, "clean", "-ffdx", "-e", KEEP).returncode != 0:
            return False, "git-failed", names
    except (OSError, subprocess.TimeoutExpired):
        return False, "git-failed", []
    return True, "cleaned", names


def old_files(folder: Path, pattern: str, days: float, now: float | None = None) -> list[Path]:
    now = now or time.time()
    if not folder.exists():
        return []
    return [p for p in folder.glob(pattern) if now - p.stat().st_mtime > days * 86400]


TMP_ROOT = "tmp"


def worker_dirs(workers_root: Path) -> tuple[list[Path], list[Path]]:
    """(clones, strays): the folders directly under the workers root, oldest first.

    A clone is any folder with `.git`, whether or not it has the meta file (clones from before the
    meta file existed are swept too). A stray is any other folder except `tmp` (the run
    temp roots): what a failed clone or a delete that stopped half way leaves. Nothing can show a
    stray is safe to delete, so it is never deleted, only listed (`wh status`)."""
    if not workers_root.exists():
        return [], []
    clones, strays = [], []
    for p in workers_root.iterdir():
        if not p.is_dir() or p.name == TMP_ROOT:
            continue
        (clones if (p / ".git").exists() else strays).append(p)
    return sorted(clones, key=lambda p: p.stat().st_mtime), sorted(strays, key=lambda p: p.stat().st_mtime)


def daily(workers_root: Path, logs_dir: Path, salvage_dir: Path, cfg_cleanup, in_use: set[str],
          git_exe: str = "git", gh_exe: str = "gh", dry_run: bool = False, disk_pressure: bool = False,
          finished: set[str] | frozenset = frozenset(), retry: set[str] | frozenset = frozenset(),
          budget_seconds: float | None = None) -> dict:
    """Old logs and salvage, pytest temp roots, idle clones (oldest first under disk pressure).

    A clone becomes a candidate once idle: `finished_clone_hours` for the workers in `finished` (their
    last task finished with exit 0 and was cleaned), `idle_clone_days` for every other clone. Every
    candidate still has to pass `may_delete`. `retry` names clones whose delete failed earlier (the
    host keeps the list): their remains are deleted again. A delete that leaves anything behind is
    reported under "failed", never "deleted". The report also counts what is left on disk.

    `budget_seconds` bounds the clone part (each check is a fetch, each delete can take seconds): the
    host runs the sweep inside its loop, so past the budget the remaining candidates wait for the next
    sweep and are counted under "deferred". None (no host running) means no limit."""
    sweep = _Sweep(dry_run, budget_seconds)
    _sweep_old_files(sweep, workers_root, logs_dir, salvage_dir, cfg_cleanup)
    tmp_root = workers_root / TMP_ROOT
    if tmp_root.exists():
        for p in old_files(tmp_root, "*", 2):
            if p.name.split("-")[0] not in in_use and not sweep.over():
                sweep.drop(p, f"tmp:{p.name}")
    clones, strays = worker_dirs(workers_root)
    left = len(clones)
    for clone in clones:
        if _sweep_clone(sweep, clone, cfg_cleanup, in_use, finished, retry, disk_pressure, git_exe, gh_exe):
            left -= 1
    for stray in strays:
        # Only what this host itself was deleting (a clone found safe, then not fully removed): its
        # `.git` may be gone already, so it is a stray now, but the check was passed before the delete.
        if stray.name in retry and stray.name not in in_use and not sweep.over():
            sweep.drop(stray, f"clone:{stray.name}")
    sweep.report["clones"] = left
    sweep.report["strays"] = [p.name for p in strays if p.name not in in_use and p.exists()]
    return sweep.report


class _Sweep:
    """The report of one sweep, its deletes (or, in a dry run, what it would delete) and its time budget."""

    def __init__(self, dry_run: bool, budget_seconds: float | None):
        self.dry_run = dry_run
        self.deadline = None if budget_seconds is None else time.monotonic() + budget_seconds
        self.report = {"deleted": [], "held": [], "would_delete": [], "failed": [], "clones": 0, "strays": [],
                       "deferred": 0}

    def drop(self, path: Path, label: str) -> bool:
        """Delete a file or folder; True only if it is gone. Anything left behind is reported as failed."""
        if self.dry_run:
            self.report["would_delete"].append(label)
            return False
        if path.is_dir():
            gone = remove_tree(path)
        else:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            gone = not path.exists()
        self.report["deleted" if gone else "failed"].append(label)
        return gone

    def over(self) -> bool:
        """Past the budget: count one more deferred item."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.report["deferred"] += 1
            return True
        return False


def _sweep_old_files(sweep: _Sweep, workers_root: Path, logs_dir: Path, salvage_dir: Path, cfg_cleanup) -> None:
    """Worker logs, host logs, salvage zips and pytest temp roots past their retention (no time budget)."""
    for p in old_files(workers_root, "*.log", cfg_cleanup.log_retention_days):
        sweep.drop(p, f"log:{p.name}")
    for p in old_files(logs_dir, "host-*.log", cfg_cleanup.host_log_days):
        sweep.drop(p, f"hostlog:{p.name}")
    for p in old_files(salvage_dir, "*.zip", cfg_cleanup.salvage_days):
        sweep.drop(p, f"salvage:{p.name}")
    temp = Path(os.environ.get("TEMP", ""))
    user = os.environ.get("USERNAME", "")
    if temp.exists() and user:
        for p in old_files(temp, f"pytest-of-{user}", cfg_cleanup.pytest_temp_days):
            sweep.drop(p, f"pytest:{p.name}")


def _sweep_clone(sweep: _Sweep, clone: Path, cfg_cleanup, in_use: set[str], finished, retry, disk_pressure: bool,
                 git_exe: str, gh_exe: str) -> bool:
    """Delete one clone if it is idle long enough (or the disk is short) and may_delete passes; True if it's gone."""
    if clone.name in retry and clone.name not in in_use:
        # Passed may_delete before its delete began; what is left is half deleted, not work.
        return not sweep.over() and sweep.drop(clone, f"clone:{clone.name}")
    idle_hours = (time.time() - clone.stat().st_mtime) / 3600
    limit = cfg_cleanup.finished_clone_hours if clone.name in finished else cfg_cleanup.idle_clone_days * 24
    if (idle_hours < limit and not disk_pressure) or sweep.over():
        return False
    verdict = may_delete(clone, clone.name in in_use, git_exe, gh_exe)
    if not verdict.safe:
        sweep.report["held"].append(f"{clone.name}:{verdict.reason}")
        return False
    return sweep.drop(clone, f"clone:{clone.name}")
