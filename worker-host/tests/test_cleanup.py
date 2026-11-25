"""Clean-up (design section 11) never touches a clone with uncommitted or unpushed work."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from conftest import git
from workerhost import cleanup
from workerhost.config import Cleanup


def test_clean_pushed_clone_may_be_deleted(remote_and_clone):
    _, clone = remote_and_clone
    v = cleanup.delete_clone(clone, in_use=False)
    assert (v.safe, v.reason) == (True, "clean")
    assert not clone.exists()


@pytest.mark.parametrize("make_dirty,reason", [
    (lambda c: (c / "README.md").write_text("changed\n"), "uncommitted"),
    (lambda c: (c / "new.txt").write_text("untracked\n"), "uncommitted"),
    (lambda c: (git(c, "add", "README.md"), (c / "README.md").write_text("staged\n"), git(c, "add", "README.md")),
     "uncommitted"),
    (lambda c: ((c / "README.md").write_text("stash me\n"), git(c, "stash", "-q")), "stash"),
    (lambda c: ((c / "a.txt").write_text("a\n"), git(c, "add", "a.txt"), git(c, "commit", "-q", "-m", "local")),
     "unpushed"),
    (lambda c: (git(c, "switch", "-q", "-c", "side"), (c / "s.txt").write_text("s\n"), git(c, "add", "s.txt"),
                git(c, "commit", "-q", "-m", "side"), git(c, "switch", "-q", "work")), "unpushed"),
])
def test_clone_with_work_is_held(remote_and_clone, make_dirty, reason, monkeypatch):
    _, clone = remote_and_clone
    make_dirty(clone)
    monkeypatch.setattr(cleanup, "squash_merged", lambda *a, **k: False)
    v = cleanup.delete_clone(clone, in_use=False)
    assert (v.safe, v.reason) == (False, reason)
    assert clone.exists() and (clone / ".git").exists()


def test_clone_in_use_is_held(remote_and_clone):
    _, clone = remote_and_clone
    assert cleanup.delete_clone(clone, in_use=True).reason == "in-use"
    assert clone.exists()


def test_nothing_is_deleted_when_fetch_fails(remote_and_clone, tmp_path):
    origin, clone = remote_and_clone
    git(clone, "remote", "set-url", "origin", str(tmp_path / "gone.git"))
    v = cleanup.delete_clone(clone, in_use=False)
    assert (v.safe, v.reason) == (False, "fetch-failed")
    assert clone.exists()


def test_unpushed_work_survives_the_after_run_clean(remote_and_clone, tmp_path):
    _, clone = remote_and_clone
    (clone / "a.txt").write_text("a\n")
    git(clone, "add", "a.txt")
    git(clone, "commit", "-q", "-m", "local only")
    (clone / "notes.txt").write_text("untracked\n")
    cleaned, reason, _ = cleanup.clean_after_finish(clone, 0, tmp_path / "salvage", "t", 50)
    assert (cleaned, reason) == (False, "unpushed")
    assert (clone / "notes.txt").exists()


def test_failed_run_is_never_cleaned(remote_and_clone, tmp_path):
    _, clone = remote_and_clone
    (clone / "notes.txt").write_text("untracked\n")
    assert cleanup.clean_after_finish(clone, 1, tmp_path / "salvage", "t", 50)[:2] == (False, "exit-code")
    assert (clone / "notes.txt").exists()


def test_successful_pushed_run_is_cleaned_with_salvage_and_keeps_meta(remote_and_clone, tmp_path):
    _, clone = remote_and_clone
    (clone / "notes.txt").write_text("untracked\n")
    cleaned, reason, names = cleanup.clean_after_finish(clone, 0, tmp_path / "salvage", "core14-x", 50)
    assert (cleaned, reason, names) == (True, "cleaned", ["notes.txt"])
    assert not (clone / "notes.txt").exists()
    assert (clone / ".ds-worker.json").exists()
    assert (tmp_path / "salvage" / "core14-x.zip").exists()


def test_salvage_too_big_holds_the_clone(remote_and_clone, tmp_path):
    _, clone = remote_and_clone
    (clone / "big.bin").write_bytes(b"0" * (2 * 1024 * 1024))
    assert cleanup.clean_after_finish(clone, 0, tmp_path / "salvage", "t", 1)[:2] == (False, "salvage-too-big")
    assert (clone / "big.bin").exists()


def test_daily_cleanup_holds_dirty_idle_clones(remote_and_clone, tmp_path, monkeypatch):
    import os
    import time

    monkeypatch.setenv("TEMP", str(tmp_path / "no-temp"))  # never sweep the real pytest temp roots
    _, clone = remote_and_clone
    (clone / "README.md").write_text("dirty\n")
    old = time.time() - 30 * 86400
    os.utime(clone, (old, old))
    report = cleanup.daily(clone.parent, tmp_path / "logs", tmp_path / "salvage", Cleanup(), in_use=set())
    assert report["held"] == ["core14:uncommitted"] and clone.exists()


def test_squash_merged_requires_matching_merged_pr(remote_and_clone, monkeypatch):
    _, clone = remote_and_clone
    (clone / "a.txt").write_text("a\n")
    git(clone, "add", "a.txt")
    git(clone, "commit", "-q", "-m", "squashed upstream")
    tip = git(clone, "rev-parse", "HEAD")

    class R:
        def __init__(self, out):
            self.returncode, self.stdout = 0, out

    real = subprocess.run

    def fake(cmd, *a, **k):
        if Path(cmd[0]).stem.lower() == "gh":
            return R(f'[{{"headRefOid": "{other}"}}]'.encode())
        return real(cmd, *a, **k)

    other = "0" * 40
    gh = Path(clone.parent) / "bin" / "gh.exe"
    gh.parent.mkdir()
    gh.write_bytes(b"MZ")
    monkeypatch.setattr(cleanup.subprocess, "run", fake)
    monkeypatch.setattr(cleanup.shutil, "which", lambda name: None)
    assert cleanup.delete_clone(clone, in_use=False, gh_exe=str(gh)).reason == "unpushed"
    other = tip
    assert cleanup.delete_clone(clone, in_use=False, gh_exe=str(gh)).safe


def test_squash_check_never_runs_a_bare_gh_from_the_clone(remote_and_clone, monkeypatch):
    """gh runs with the clone as cwd; an unresolved bare name must not be run (the clone could hold gh.exe)."""
    _, clone = remote_and_clone
    (clone / "a.txt").write_text("a\n")
    git(clone, "add", "a.txt")
    git(clone, "commit", "-q", "-m", "local")
    (clone / "gh.exe").write_bytes(b"MZ")
    git(clone, "add", "gh.exe")
    git(clone, "commit", "-q", "-m", "shadow")
    ran = []
    real = subprocess.run
    monkeypatch.setattr(cleanup.subprocess, "run", lambda cmd, *a, **k: ran.append(cmd[0]) or real(cmd, *a, **k))
    monkeypatch.setattr(cleanup.shutil, "which", lambda name: None)
    assert cleanup.delete_clone(clone, in_use=False, gh_exe="gh").reason == "unpushed"
    assert clone.exists() and all(Path(c).stem.lower() != "gh" for c in ran)


def test_a_new_task_never_reuses_a_clone_holding_unfinished_work(remote_and_clone, monkeypatch):
    from workerhost import launcher

    origin, clone = remote_and_clone
    git(clone, "remote", "set-url", "origin", str(origin))
    (clone / "notes.txt").write_text("left by the last task\n")
    monkeypatch.setattr(launcher, "_origin_matches", lambda url, full: True)
    with pytest.raises(launcher.LaunchError) as e:
        launcher.prepare_clone(clone.parent, clone.name, "o/r", "work", "gh", "git")
    assert e.value.reason == "clone-dirty"
    assert (clone / "notes.txt").exists()
    # its own resume may continue in it
    assert launcher.prepare_clone(clone.parent, clone.name, "o/r", "work", "gh", "git", require_clean=False) == clone
    (clone / "notes.txt").unlink()
    git(clone, "stash", "list")
    assert launcher.prepare_clone(clone.parent, clone.name, "o/r", "work", "gh", "git") == clone

# --- issue #28: finished clones were never pruned ---------------------------------------------------

def _age(path: Path, hours: float) -> None:
    import os
    import time

    t = time.time() - hours * 3600
    os.utime(path, (t, t))


def test_line_ending_only_change_is_not_work(remote_and_clone):
    from conftest import make_crlf_phantom
    from workerhost import launcher

    _, clone = remote_and_clone
    make_crlf_phantom(clone)
    assert cleanup.uncommitted(clone) == []
    assert launcher.dirty(clone, "git") is False
    assert cleanup.may_delete(clone, in_use=False).reason == "clean"


def test_a_real_edit_to_that_file_is_still_work(remote_and_clone):
    from conftest import make_crlf_phantom

    _, clone = remote_and_clone
    make_crlf_phantom(clone)
    (clone / "LICENSE.md").write_bytes(b"line one\r\nline CHANGED\r\n")
    assert cleanup.uncommitted(clone) == [" M LICENSE.md"]
    assert cleanup.may_delete(clone, in_use=False).reason == "uncommitted"


def test_staged_renamed_and_untracked_entries_always_count(remote_and_clone):
    _, clone = remote_and_clone
    git(clone, "mv", "README.md", "RENAMED.md")
    (clone / "new file.txt").write_text("n\n")
    assert sorted(cleanup.uncommitted(clone)) == ["?? new file.txt", "R  RENAMED.md"]


def test_paths_longer_than_max_path_are_deleted(tmp_path):
    import os

    from workerhost.vault import long_path, remove_tree

    top = tmp_path / "deep"
    p = long_path(top)
    for _ in range(12):
        p = os.path.join(p, "d" * 24)
    os.makedirs(p)
    with open(os.path.join(p, "f.txt"), "w") as fh:
        fh.write("x")
    assert len(p) > 300
    assert remove_tree(top) is True and not top.exists()


@pytest.mark.skipif(__import__("os").name != "nt", reason="an open file blocks a delete only on Windows")
def test_a_delete_that_leaves_files_behind_is_reported_failed_not_deleted(tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP", str(tmp_path / "no-temp"))
    root = tmp_path / "w"
    run_temp = root / "tmp" / "core9-1"
    run_temp.mkdir(parents=True)
    (run_temp / "open.txt").write_text("x\n")
    _age(run_temp, 5 * 24)
    with open(run_temp / "open.txt", "rb"):
        report = cleanup.daily(root, tmp_path / "logs", tmp_path / "salvage", Cleanup(), in_use=set())
    assert report["failed"] == ["tmp:core9-1"] and report["deleted"] == []


def test_a_finished_clone_goes_after_finished_clone_hours(remote_and_clone, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP", str(tmp_path / "no-temp"))
    _, clone = remote_and_clone
    _age(clone, 13)
    args = (clone.parent, tmp_path / "logs", tmp_path / "salvage", Cleanup())
    kept = cleanup.daily(*args, in_use=set())  # not known finished: the 7 day rule
    assert clone.exists() and kept["held"] == [] and kept["clones"] == 1
    report = cleanup.daily(*args, in_use=set(), finished={"core14"})
    assert report["deleted"] == ["clone:core14"] and not clone.exists() and report["clones"] == 0


def test_a_clone_from_before_the_meta_file_is_swept(remote_and_clone, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP", str(tmp_path / "no-temp"))
    _, clone = remote_and_clone
    (clone / ".ds-worker.json").unlink()
    _age(clone, 8 * 24)
    report = cleanup.daily(clone.parent, tmp_path / "logs", tmp_path / "salvage", Cleanup(), in_use=set())
    assert report["deleted"] == ["clone:core14"]


def test_strays_are_listed_never_deleted_unless_the_host_was_deleting_them(tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP", str(tmp_path / "no-temp"))
    root = tmp_path / "w"
    stray = root / "core421" / "collectors"
    stray.mkdir(parents=True)
    (stray / "left.txt").write_text("x\n")
    (root / "tmp").mkdir()
    _age(root / "core421", 30 * 24)
    args = (root, tmp_path / "logs", tmp_path / "salvage", Cleanup())
    report = cleanup.daily(*args, in_use=set())
    assert report["strays"] == ["core421"] and report["deleted"] == [] and (root / "core421").exists()
    report = cleanup.daily(*args, in_use=set(), retry={"core421"})
    assert report["deleted"] == ["clone:core421"] and report["strays"] == [] and not (root / "core421").exists()


def test_the_sweep_stops_at_its_budget_and_counts_what_waits(remote_and_clone, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP", str(tmp_path / "no-temp"))
    _, clone = remote_and_clone
    for n in range(3):
        run_temp = clone.parent / "tmp" / f"core{n}-1"
        run_temp.mkdir(parents=True)
        _age(run_temp, 5 * 24)
    _age(clone, 8 * 24)
    report = cleanup.daily(clone.parent, tmp_path / "logs", tmp_path / "salvage", Cleanup(), in_use=set(),
                           budget_seconds=0)
    assert report["deferred"] == 4 and report["deleted"] == [] and clone.exists()
