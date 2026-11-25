"""tools/make-release.py against a throwaway repository with its own bare "origin": the release.toml it writes is one
hosts accept, for the right commit and tree; serial, version and notes follow main; it refuses unmerged code and a
second release of the same commit; a real run pushes the release branch and asks for the PR."""
import datetime as dt
import importlib.util
import subprocess
from pathlib import Path

import pytest

from workerhost import update

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("make_release", ROOT / "tools" / "make-release.py")
make_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(make_release)


def run(cwd, *args) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def commit(repo: Path, path: str, text: str, subject: str) -> str:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")
    run(repo, "add", path)
    run(repo, "commit", "-q", "-m", subject)
    return run(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    run(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    run(tmp_path, "init", "-q", "-b", "main", str(work))
    for key, value in (("user.name", "Test"), ("user.email", "test@example.invalid"), ("core.autocrlf", "false"),
                       ("commit.gpgsign", "false")):
        run(work, "config", key, value)
    run(work, "remote", "add", "origin", str(origin))
    commit(work, "wh.py", "print('wh')\n", "wh entry point")
    commit(work, "workerhost/__init__.py", "", "the package")
    commit(work, "README.md", "# host\n", "readme")
    run(work, "push", "-q", "origin", "main")
    monkeypatch.setattr(make_release, "ROOT", work)
    return work


def push(repo):
    run(repo, "push", "-q", "origin", "main")


def released(out: str) -> update.Release:
    text = out.rsplit("\n# ", 1)[0]  # drop the trailing "# <n> files at ..." line (release.toml has comments too)
    return update.parse_release(text.encode("utf-8"))


def day_of(repo, sha) -> str:
    return dt.datetime.fromtimestamp(int(run(repo, "show", "-s", "--format=%ct", sha))).strftime("%Y.%m.%d")


def test_dry_run_prints_a_release_hosts_accept(repo, capsys):
    head = run(repo, "rev-parse", "HEAD")
    assert make_release.main(["--dry-run"]) == 0
    rel = released(capsys.readouterr().out)
    assert (rel.serial, rel.commit, rel.needs_install) == (1, head, False)
    assert rel.tree_sha256 == update.tree_sha256(update.read_tree("git", None, head, cwd=repo))
    assert rel.version == day_of(repo, head)
    assert rel.notes == "readme; the package; wh entry point"
    assert run(repo, "branch", "--show-current") == "main"  # a dry run makes no branch


def test_serial_and_same_day_version_follow_main(repo, capsys):
    first = run(repo, "rev-parse", "HEAD")
    prev = make_release.release_text(4, day_of(repo, first), first, "0" * 64, False, "earlier")
    commit(repo, "release.toml", prev, "release (signed)")
    new = commit(repo, "workerhost/host.py", "x = 1\n", "a fix (#12)")
    push(repo)
    assert make_release.main(["--dry-run", "--needs-install"]) == 0
    rel = released(capsys.readouterr().out)
    assert (rel.serial, rel.commit, rel.needs_install) == (5, new, True)
    assert rel.version == day_of(repo, new) + ".2"
    assert rel.notes == "a fix; release (signed)"  # only commits since the last release, PR numbers dropped


def test_a_tag_with_the_version_also_moves_it_on(repo, capsys):
    head = run(repo, "rev-parse", "HEAD")
    run(repo, "tag", f"v{day_of(repo, head)}")
    assert make_release.main(["--dry-run"]) == 0
    assert released(capsys.readouterr().out).version == day_of(repo, head) + ".2"


def test_refuses_a_commit_that_is_not_on_main(repo):
    run(repo, "switch", "-q", "-c", "side")
    side = commit(repo, "workerhost/x.py", "y = 2\n", "unmerged work")
    with pytest.raises(SystemExit, match="not on origin/main"):
        make_release.main(["--dry-run", "--commit", side])


def test_refuses_a_second_release_of_the_same_commit(repo):
    first = run(repo, "rev-parse", "HEAD")
    commit(repo, "release.toml", make_release.release_text(1, "2026.01.01", first, "0" * 64, False, "n"), "release")
    push(repo)
    with pytest.raises(SystemExit, match="already names"):
        make_release.main(["--dry-run", "--commit", first])


def test_notes_keep_whole_subjects_within_300_characters(repo, capsys):
    for i in range(6):
        commit(repo, f"workerhost/m{i}.py", f"n = {i}\n", f"change {i} " + "x" * 70)
    push(repo)
    assert make_release.main(["--dry-run"]) == 0
    notes = released(capsys.readouterr().out).notes
    assert len(notes) <= 300
    assert notes.startswith("change 5 ") and all(s.startswith("change ") for s in notes.split("; "))
    assert notes.count("; ") == 2  # 79-character subjects: three make 241, a fourth would pass 300


def test_given_notes_are_made_safe_for_toml(repo, capsys):
    assert make_release.main(["--dry-run", "--notes", 'quote " back \\ tab\there']) == 0
    assert released(capsys.readouterr().out).notes == "quote   back   tab here"


def test_a_real_run_pushes_the_release_branch_and_asks_for_the_pr(repo, capsys, monkeypatch):
    asked = {}
    monkeypatch.setattr(make_release, "open_pr", lambda title, body: asked.update(title=title, body=body) or 0)
    head = run(repo, "rev-parse", "HEAD")
    assert make_release.main(["--notes", "first release"]) == 0
    out = capsys.readouterr().out
    rel = released(out)
    branch = f"release-{rel.version}"
    assert run(repo, "branch", "--show-current") == branch
    pushed = run(repo, "--git-dir", str(repo.parent / "origin.git"), "show", f"{branch}:release.toml")
    assert update.parse_release(pushed.encode("utf-8")) == rel
    assert asked["title"] == f"release {rel.version} (to be signed)"
    assert head in asked["body"] and rel.tree_sha256 in asked["body"] and "sign-config.ps1 -Pr" in asked["body"]


def test_the_bootstrap_hash_is_signed_in_and_hosts_still_accept_it(repo, capsys):
    """bootstrap_sha256 lets the App pin the bootstrap it ships against a signed value; hosts ignore the key."""
    import hashlib

    body = b"# bootstrap\nparam([string]$DataFile)\n"
    (repo / "tools").mkdir()
    (repo / "tools" / "bootstrap.ps1").write_bytes(body)
    run(repo, "add", "tools/bootstrap.ps1")
    run(repo, "commit", "-q", "-m", "bootstrap")
    push(repo)
    assert make_release.main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert f'bootstrap_sha256 = "{hashlib.sha256(body).hexdigest()}"' in out
    assert released(out).serial == 1  # parse_release accepts it


def test_without_a_bootstrap_there_is_no_hash_line(repo, capsys):
    assert make_release.main(["--dry-run"]) == 0
    assert "bootstrap_sha256" not in capsys.readouterr().out


def test_the_redirect_release_carries_moved_to_and_hosts_parse_it(repo, capsys):
    assert make_release.main(["--dry-run", "--moved-to", "https://github.com/u64a/strugglebus:worker-host"]) == 0
    rel = released(capsys.readouterr().out)
    assert rel.moved_to == ("https://github.com/u64a/strugglebus", "worker-host")


def test_a_bad_redirect_is_refused_before_anything_is_written(repo):
    with pytest.raises(SystemExit):
        make_release.main(["--dry-run", "--moved-to", "github.com/u64a/strugglebus:worker-host"])
    with pytest.raises(update.ReleaseError):  # parse_release refuses it, exactly as hosts would
        make_release.main(["--dry-run", "--moved-to", "https://github.com/u64a/strugglebus:../up"])


def test_code_in_a_folder_gets_the_same_tree_hash_as_at_the_top(repo, capsys):
    """The monorepo layout: the host's files under worker-host/, its release.toml there too."""
    head = run(repo, "rev-parse", "HEAD")
    top = update.tree_sha256(update.read_tree("git", None, head, cwd=repo))
    for path in ("wh.py", "workerhost/__init__.py", "README.md"):
        target = repo / "worker-host" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((repo / path).read_bytes())
    run(repo, "add", "-A")
    run(repo, "commit", "-q", "-m", "the monorepo layout")
    push(repo)
    assert make_release.main(["--dry-run", "--path", "worker-host"]) == 0
    assert released(capsys.readouterr().out).tree_sha256 == top


def test_a_failed_pr_is_a_failed_run(repo, monkeypatch, capsys):
    monkeypatch.setattr(make_release, "open_pr", lambda title, body: 1)
    assert make_release.main([]) == 1
