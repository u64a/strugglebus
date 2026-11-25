"""GHCP (Copilot CLI) update with rollback (design section 10). Only ever runs with no worker running.

record version -> skip when the live CLI (which self-updates in place) is newer than or equal to
winget's available version -> copy copilot* files to ghcp-backup -> winget upgrade -> version and
--help smoke test -> on failure keep a binary that still answers, otherwise copy the backed-up files
back over it and re-test. Nothing in the package folder is ever deleted.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .vault import remove_tree

VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:-\d+)?)")

Runner = Callable[[list[str], float], tuple[int, str]]


def default_runner(cmd: list[str], timeout: float) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")


def version(copilot_exe: str, run: Runner = default_runner) -> str | None:
    code, out = run([copilot_exe, "--version"], 60)
    m = VERSION_RE.search(out) if code == 0 else None
    return m.group(1) if m else None


def smoke(copilot_exe: str, run: Runner = default_runner) -> bool:
    code, out = run([copilot_exe, "--help"], 60)
    return code == 0 and "--prompt" in out


@dataclass
class Result:
    ok: bool
    before: str | None
    after: str | None
    line: str


def version_key(v: str) -> tuple[int, ...]:
    """1.0.95-3 -> (1, 0, 95, 3); 1.0.94 -> (1, 0, 94, 0), so a self-update build sorts above its base."""
    nums = [int(n) for n in re.findall(r"\d+", v)]
    return tuple(nums + [0] * (4 - len(nums)))


def _strip_v(token: str) -> str:
    """winget prints versions as v1.0.94 on some hosts; drop one leading v or V."""
    return token[1:] if token[:1] in ("v", "V") else token


def winget_available(winget_id: str, run: Runner = default_runner) -> str | None:
    """The Available column of `winget list --id <id> --exact`; None when winget offers no upgrade."""
    code, out = run(["winget", "list", "--id", winget_id, "--exact", "--disable-interactivity",
                     "--accept-source-agreements"], 120)
    lines = [ln.strip() for ln in re.split(r"[\r\n]+", out or "")]
    if not any("Available" in ln.split() for ln in lines):
        return None
    for ln in lines:
        tokens = ln.split()
        idx = next((i for i, t in enumerate(tokens) if t.lower() == winget_id.lower()), None)
        if idx is None:
            continue
        found = [m.group(1) for t in tokens[idx + 1:] if (m := VERSION_RE.fullmatch(_strip_v(t)))]
        return found[1] if len(found) >= 2 else None
    return None


def package_folder(copilot_exe: str) -> Path:
    """The folder that holds the real copilot.exe: the link target's folder, or the file's own folder.

    On a host where the CLI self-updates in place this is winget's Links folder, which also holds
    unrelated portables: treat it as shared and never delete anything in it.
    """
    return Path(shutil.which(copilot_exe) or copilot_exe).resolve().parent


def _backup_names(package: Path) -> list[str]:
    """copilot.exe and its copilot* companions; never .old-* leftovers or anyone else's files."""
    return sorted(p.name for p in package.iterdir()
                  if p.is_file() and p.name.lower().startswith("copilot") and ".old-" not in p.name.lower())


def update(copilot_exe: str, backup_root: Path, winget_id: str, run: Runner = default_runner,
           package_dir: Path | None = None) -> Result:
    before = version(copilot_exe, run)
    if not before:
        return Result(False, None, None, "ghcp update: current version unreadable, not updating")
    available = winget_available(winget_id, run)
    if available and version_key(before) >= version_key(available):
        word = "newer than" if version_key(before) > version_key(available) else "same as"
        return Result(True, before, before, f"ghcp update: {before} {word} winget {available}, skipped")
    package = Path(package_dir) if package_dir else package_folder(copilot_exe)
    backup = Path(backup_root) / before
    try:
        if backup.exists():
            remove_tree(backup)
        backup.mkdir(parents=True)
        names = _backup_names(package)
        if not names:
            raise OSError("no copilot files in the package folder")
        for name in names:
            shutil.copy2(package / name, backup / name)
    except OSError:
        return Result(False, before, before, f"ghcp update: backup failed, kept {before}")
    code, _ = run(["winget", "upgrade", "--id", winget_id, "--exact", "--silent", "--disable-interactivity",
                   "--accept-source-agreements", "--accept-package-agreements"], 1800)
    after = version(copilot_exe, run)
    works = bool(after) and smoke(copilot_exe, run)
    if works and code in (0, 0x8A15002B, -1978335189):  # no applicable update
        if after == before:
            return Result(True, before, after, f"ghcp update: {before} already current")
        return Result(True, before, after, f"ghcp update: {before} -> {after} ok")
    if works:
        return Result(False, before, after, f"ghcp update: failed (exit {code}), kept {after}")
    try:
        for name in names:
            shutil.copy2(backup / name, package / name)
    except OSError:
        return Result(False, before, None, f"ghcp update: failed (exit {code}) and restore failed; needs a person")
    restored = version(copilot_exe, run)
    ok = bool(restored) and smoke(copilot_exe, run)
    return Result(False, before, restored,
                  f"ghcp update: failed (exit {code}), kept {restored}" if ok
                  else f"ghcp update: failed (exit {code}), restore not verified; needs a person")
