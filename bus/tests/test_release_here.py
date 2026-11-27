"""The script that publishes a bus release from this repository: two builds, a signature, a tag."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from release_fixtures import load_script
from release_signing import TEST_KEY

here = load_script("release_here")

COMMIT = "a" * 40
TREE = "b" * 40
VERSION = "0.2.74"
TAG = "bus/v" + VERSION
NOW = datetime(2026, 11, 28, 1, 2, 3, tzinfo=timezone.utc)
NAMES = (
    "SHA256SUMS", "requirements.lock", f"strugglebus-{VERSION}-py3-none-any.whl",
    f"strugglebus-deployment-support-{VERSION}.tar.gz", "strugglebus-release-manifest-v1.json",
)


def fill(directory: Path, changed: str | None = None) -> dict[str, str]:
    directory.mkdir(parents=True)
    for name in NAMES:
        (directory / name).write_bytes(b"other" if name == changed else name.encode())
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in NAMES}


TYPES = {
    "SHA256SUMS": "text/plain", "requirements.lock": "text/plain",
    f"strugglebus-{VERSION}-py3-none-any.whl": "application/vnd.python.wheel",
    f"strugglebus-deployment-support-{VERSION}.tar.gz": "application/gzip",
    "strugglebus-release-manifest-v1.json": "application/json",
}


def served(number: int, name: str, **changed) -> dict:
    """One file of a release as GitHub describes it."""
    return {
        "id": number, "name": name, "state": "uploaded", "label": "", "size": len(name.encode()),
        "content_type": TYPES[name], "digest": "sha256:" + hashlib.sha256(name.encode()).hexdigest(), **changed,
    }


class Commands:
    """Stands in for git, gh and docker: records each command and answers the ones it knows."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[tuple[str, ...]] = []
        self.sent: list[dict] = []
        self.on_main = True
        self.tags = ""
        self.log = "abc1234 2026-11-27 A change\n"
        self.artifacts: list[dict] = [
            {"id": 7, "expired": False, "workflow_run": {"id": 70}},
            {"id": 9, "expired": False, "workflow_run": {"id": 90}},
            {"id": 11, "expired": True, "workflow_run": {"id": 110}},
        ]
        self.github_changed: str | None = None
        good = {
            "path": here.BUILD_WORKFLOW, "event": "workflow_dispatch", "head_sha": COMMIT,
            "head_repository": {"full_name": "u64a/strugglebus"}, "conclusion": "success",
        }
        self.runs: dict[int, dict] = {70: dict(good), 90: dict(good), 110: dict(good)}
        self.refs: list[dict] = []
        self.tag_record: dict = {}
        self.listed: list[dict] = []
        self.fail_on: str | None = None
        self.local_changed: str | None = None
        self.release = {
            "id": 81, "tag_name": TAG, "target_commitish": COMMIT, "draft": False, "prerelease": False,
            "immutable": True,
            "name": TAG, "body": here.release_body(COMMIT, TREE),
            "assets": [served(number, name) for number, name in enumerate(NAMES, 100)],
        }
        self.left_on_draft: list[dict] = []

    def __call__(self, *command: str, cwd: Path | None = None, stdin: str | None = None) -> str:
        self.calls.append(command)
        if stdin is not None:
            self.sent.append(json.loads(stdin))
        return self.answer(command)

    def answer(self, command: tuple[str, ...]) -> str:
        text = " ".join(command)
        if self.fail_on is not None and self.fail_on in text:
            raise here.ReleaseError("the network dropped")
        if "/actions/runs/" in text:
            return json.dumps(self.runs[int(text.rsplit("/", 1)[1])])
        if "/git/matching-refs/tags/" in text:
            return json.dumps(self.refs)
        if "--method GET" in text and "/git/tags/" in text:
            return json.dumps(self.tag_record)
        if text.endswith("/assets?per_page=100"):
            return json.dumps(self.left_on_draft)
        if text.endswith("/releases?per_page=100"):
            return json.dumps(self.listed)
        if text.startswith("gh api --method POST") and text.endswith("/releases --input -"):
            return json.dumps({**self.release, "draft": True})
        if text.startswith("git rev-parse --show-toplevel"):
            return str(self.root) + "\n"
        if text.startswith("git merge-base") and not self.on_main:
            raise here.ReleaseError("not an ancestor")
        if text.startswith("git rev-parse"):
            return TREE + "\n"
        if text.startswith("git tag"):
            return self.tags
        if text.startswith("git log"):
            return self.log
        if "actions/artifacts?name=" in text:
            return json.dumps({"artifacts": self.artifacts})
        if text.startswith("gh run download"):
            fill(Path(command[-1]), self.github_changed)
        if text.startswith("docker run"):
            work = Path(command[command.index("-v") + 3].rsplit(":/out", 1)[0])
            fill(work / "local", self.local_changed)
        if text.startswith("gh api --method POST") and text.endswith("git/tags --input -"):
            return json.dumps({"sha": "c" * 40})
        if text.startswith("gh api --method"):
            return json.dumps(self.release)
        return ""


@pytest.fixture
def commands(tmp_path: Path) -> Commands:
    return Commands(tmp_path / "repository")


def signature_for(files: dict[str, str]) -> str:
    return TEST_KEY.sign(here.release_statement(VERSION, files).encode())


def prepared(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    work = tmp_path / "work"
    files = fill(work / "local")
    fill(work / "github")
    signature = tmp_path / "statement.sig"
    signature.write_text(signature_for(files), encoding="utf-8")
    return work, signature, files


# ---- compare ------------------------------------------------------------------------------------


def test_compare_builds_twice_and_writes_the_statement_to_sign(commands, tmp_path):
    work = tmp_path / "work"

    said = here.compare(commands, COMMIT, work)

    files = here.digests(work / "local")
    assert files == here.digests(work / "github")
    assert (work / here.STATEMENT).read_bytes() == here.release_statement(VERSION, files).encode()
    assert f"Both builds of {COMMIT} are the same five files" in said
    assert "first bus release from this repository" in said
    assert "ssh-keygen -Y sign" in said and "strugglebus-bus-release" in said
    # The newest unexpired artifact is the one compared.
    download = next(call for call in commands.calls if call[:3] == ("gh", "run", "download"))
    assert download[3] == "90" and f"bus-release-{COMMIT}" in download
    docker = next(call for call in commands.calls if call[0] == "docker")
    assert here.IMAGE in docker and f"bash bus/scripts/build_release.sh {COMMIT} /out/local" in docker[-1]
    assert not (work / "clone").exists()


def test_compare_refuses_when_the_builds_differ_and_writes_nothing_to_sign(commands, tmp_path):
    commands.local_changed = "requirements.lock"

    with pytest.raises(here.ReleaseError, match="THE TWO BUILDS DIFFER.*requirements.lock"):
        here.compare(commands, COMMIT, tmp_path / "work")

    assert not (tmp_path / "work" / here.STATEMENT).exists()


def test_compare_lists_what_changed_since_the_last_release(commands, tmp_path):
    commands.tags = "bus/v0.2.73\nbus/v0.2.72\n"

    said = here.compare(commands, COMMIT, tmp_path / "work")

    assert "Commits that touched bus/ since bus/v0.2.73:\nabc1234 2026-11-27 A change" in said
    assert ("git", "log", "--format=%h %ad %s", "--date=short", f"bus/v0.2.73..{COMMIT}", "--", "bus") in commands.calls


def test_a_version_already_tagged_is_never_published_again(commands, tmp_path):
    commands.tags = f"{TAG}\n"

    with pytest.raises(here.ReleaseError, match="already tagged"):
        here.compare(commands, COMMIT, tmp_path / "work")


def test_no_change_to_the_bus_since_the_last_release_is_said(commands, tmp_path):
    commands.tags, commands.log = "bus/v0.2.73\n", ""

    assert "(none)" in here.compare(commands, COMMIT, tmp_path / "work")


@pytest.mark.parametrize("commit", ["abc123", "A" * 40, "main", COMMIT + "0"])
def test_only_a_full_commit_hash_is_taken(commands, tmp_path, commit):
    with pytest.raises(here.ReleaseError, match="40-character"):
        here.compare(commands, commit, tmp_path / "work")

    assert commands.calls == [("git", "rev-parse", "--show-toplevel")]


def test_a_commit_that_is_not_on_main_is_refused(commands, tmp_path):
    commands.on_main = False

    with pytest.raises(here.ReleaseError, match="is not on main"):
        here.compare(commands, COMMIT, tmp_path / "work")

    assert not (tmp_path / "work").exists()


def test_an_existing_work_folder_is_refused(commands, tmp_path):
    (tmp_path / "work").mkdir()

    with pytest.raises(here.ReleaseError, match="already exists"):
        here.compare(commands, COMMIT, tmp_path / "work")


def test_without_githubs_build_there_is_nothing_to_compare(commands, tmp_path):
    commands.artifacts = [{"id": 11, "expired": True, "workflow_run": {"id": 110}}]

    with pytest.raises(here.ReleaseError, match="Start that workflow by hand"):
        here.compare(commands, COMMIT, tmp_path / "work")

    assert not any(call[0] == "docker" for call in commands.calls)


def test_a_difference_in_githubs_build_is_caught_the_same(commands, tmp_path):
    commands.github_changed = "SHA256SUMS"

    with pytest.raises(here.ReleaseError, match="THE TWO BUILDS DIFFER.*SHA256SUMS"):
        here.compare(commands, COMMIT, tmp_path / "work")


def test_a_release_is_exactly_five_plain_files(tmp_path):
    fill(tmp_path / "four")
    (tmp_path / "four" / "SHA256SUMS").unlink()
    fill(tmp_path / "folder")
    (tmp_path / "folder" / "SHA256SUMS").unlink()
    (tmp_path / "folder" / "extra").mkdir()

    for directory in ("four", "folder"):
        with pytest.raises(here.ReleaseError, match="exactly five"):
            here.digests(tmp_path / directory)


def test_a_release_holds_exactly_one_bus_wheel():
    assert here.version_of(dict.fromkeys(NAMES, "x")) == VERSION
    with pytest.raises(here.ReleaseError, match="one bus wheel"):
        here.version_of({"SHA256SUMS": "x"})
    with pytest.raises(here.ReleaseError, match="one bus wheel"):
        here.version_of({NAMES[2]: "x", "strugglebus-0.2.75-py3-none-any.whl": "x"})


# ---- publish ------------------------------------------------------------------------------------


def test_publish_makes_the_signed_tag_then_the_release_and_checks_it(commands, tmp_path):
    work, signature, files = prepared(tmp_path)

    said = here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    assert said == f"Published bus {VERSION} as {TAG} in u64a/strugglebus, from {COMMIT}.\n"
    body = '{"source_commit":"%s","source_repository":"u64a/strugglebus","source_tree":"%s","version":1}' % (COMMIT, TREE)
    tag, ref, release, published = commands.sent
    statement = here.release_statement(VERSION, files)
    assert tag == {
        "message": f"Strugglebus public release mirror v1\n{body}\n{statement}{signature.read_text().strip()}\n",
        "object": COMMIT, "tag": TAG, "type": "commit",
        "tagger": {"date": "2026-11-28T01:02:03Z", "email": here.TAGGER_EMAIL, "name": here.TAGGER_NAME},
    }
    assert ref == {"ref": f"refs/tags/{TAG}", "sha": "c" * 40}
    assert release == {
        "body": body, "draft": True, "name": TAG, "prerelease": False, "tag_name": TAG, "target_commitish": COMMIT,
    }
    assert published == {"draft": False}
    uploads = [call for call in commands.calls if "uploads.github.com" in " ".join(call)]
    assert [(call[5], call[6].rsplit("?name=", 1)[1], Path(call[8]).name) for call in uploads] == [
        (f"Content-Type: {TYPES[name]}", name, name) for name in sorted(NAMES)
    ]
    assert all(call[6].startswith("https://uploads.github.com/repos/u64a/strugglebus/releases/81/assets") for call in uploads)
    # The updater that is installed accepts exactly this tag message.
    from strugglebus.release_signature import signed_digests
    assert signed_digests(tag["message"], VERSION) == files


@pytest.mark.parametrize("signature", ["", "not a signature", None])
def test_nothing_is_published_without_a_release_keys_signature_over_these_files(commands, tmp_path, signature):
    work, path, files = prepared(tmp_path)
    other = {**files, "SHA256SUMS": "0" * 64}
    path.write_text(signature_for(other) if signature is None else signature, encoding="utf-8")

    with pytest.raises(here.ReleaseError, match="not signed by a release key"):
        here.publish(commands, COMMIT, work, path, here.REPOSITORY, NOW)

    assert commands.sent == []


def test_nothing_is_published_if_the_builds_no_longer_agree(commands, tmp_path):
    work, signature, _ = prepared(tmp_path)
    (work / "github" / "SHA256SUMS").write_bytes(b"changed since")

    with pytest.raises(here.ReleaseError, match="THE TWO BUILDS DIFFER"):
        here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    assert commands.sent == []


@pytest.mark.parametrize("field,value,named", [
    ("target_commitish", "main", "its commit"),
    ("draft", True, "being published"), ("prerelease", True, "being published"),
    ("immutable", False, "being immutable"), ("name", "A name", "its tag"),
    ("body", "Something else", "its source"),
])
def test_a_release_that_was_not_published_as_meant_is_reported(commands, tmp_path, field, value, named):
    work, signature, files = prepared(tmp_path)
    leave_tag(commands, files, signature)
    commands.release = {**commands.release, field: value}
    commands.listed = [{**commands.release, "draft": False}]

    with pytest.raises(here.ReleaseError, match=f"not as it was meant, in: {named}"):
        here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)


@pytest.mark.parametrize("field,value", [
    ("target_commitish", "main"), ("body", "Something else"), ("name", "A name"), ("tag_name", "bus/v9.9.9"),
])
def test_a_draft_that_does_not_say_what_this_release_says_is_never_published(commands, tmp_path, field, value):
    """A draft left by a stopped run, or by anyone else, is checked before anything is uploaded to it."""
    work, signature, files = prepared(tmp_path)
    leave_tag(commands, files, signature)
    wrong = {**commands.release, "draft": True, field: value}
    commands.listed = [wrong if field != "tag_name" else {**wrong, "tag_name": TAG, "name": "bus/v9.9.9"}]

    with pytest.raises(here.ReleaseError, match="already exists and does not name this commit and source"):
        here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    assert commands.sent == []
    assert not any("uploads.github.com" in " ".join(call) for call in commands.calls)


def test_a_trial_may_go_to_a_scratch_repository_and_nowhere_else(commands, tmp_path):
    work, signature, _ = prepared(tmp_path)

    said = here.publish(commands, COMMIT, work, signature, "u64a/strugglebus-release-test", NOW)

    assert "in u64a/strugglebus-release-test" in said
    # Whatever the place, the release says it was built from the project's repository.
    assert '"source_repository":"u64a/strugglebus"' in commands.sent[0]["message"]
    for elsewhere in ("someone/strugglebus-release-test", "u64a/other", "NZCypher819/strugglebus-releases"):
        with pytest.raises(here.ReleaseError, match="releases are published to"):
            here.publish(commands, COMMIT, work, signature, elsewhere, NOW)


def test_files_a_stopped_run_left_on_the_draft_are_removed_before_uploading(commands, tmp_path):
    work, signature, _ = prepared(tmp_path)
    commands.left_on_draft = [{"id": 501, "name": "SHA256SUMS"}, {"id": 502, "name": "requirements.lock"}]

    here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    calls = [" ".join(call) for call in commands.calls]
    removed = [index for index, call in enumerate(calls) if "--method DELETE" in call]
    first_upload = next(index for index, call in enumerate(calls) if "uploads.github.com" in call)
    assert [calls[index].rsplit("/", 1)[1] for index in removed] == ["501", "502"]
    assert max(removed) < first_upload


@pytest.mark.parametrize("change", [
    {"content_type": "application/octet-stream"},
    {"size": 1},
    {"digest": "sha256:" + "0" * 64},
    {"state": "starter"},
    {"label": "A label"},
])
def test_files_an_updater_would_refuse_are_caught_before_the_release_is_published(commands, tmp_path, change):
    """A guessed content type, or anything else an installed updater checks, while it can still be put right."""
    work, signature, _ = prepared(tmp_path)
    commands.release = {**commands.release, "assets": [
        served(100 + index, name, **(change if index == 2 else {})) for index, name in enumerate(NAMES)
    ]}

    with pytest.raises(here.ReleaseError, match="not as an updater requires"):
        here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    assert {"draft": False} not in commands.sent


@pytest.mark.parametrize("assets", [[], [served(100, NAMES[0])]])
def test_a_published_release_missing_files_is_reported(commands, tmp_path, assets):
    work, signature, files = prepared(tmp_path)
    leave_tag(commands, files, signature)
    commands.listed = [commands.release]
    commands.release = {**commands.release, "assets": assets}

    with pytest.raises(here.ReleaseError, match="not as it was meant, in: its files"):
        here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)


# ---- which build is GitHub's --------------------------------------------------------------------


@pytest.mark.parametrize("field,value", [
    ("path", ".github/workflows/bus.yml"),
    ("event", "pull_request"),
    ("head_sha", "d" * 40),
    ("head_repository", {"full_name": "someone/strugglebus"}),
    ("head_repository", None),
    ("conclusion", "failure"),
])
def test_an_artifact_of_the_right_name_from_any_other_run_is_not_githubs_build(commands, tmp_path, field, value):
    """A pull request, even from a fork, can offer an artifact with any name and contents."""
    for run in commands.runs.values():
        run[field] = value

    with pytest.raises(here.ReleaseError, match="made by the 'Bus release build' workflow"):
        here.compare(commands, COMMIT, tmp_path / "work")

    assert not any(call[:3] == ("gh", "run", "download") for call in commands.calls)
    assert not any(call[0] == "docker" for call in commands.calls)


def test_a_fork_pull_requests_newer_artifact_does_not_displace_the_real_build(commands, tmp_path):
    commands.runs[90] = {**commands.runs[90], "event": "pull_request", "head_repository": {"full_name": "fork/strugglebus"}}

    here.compare(commands, COMMIT, tmp_path / "work")

    download = next(call for call in commands.calls if call[:3] == ("gh", "run", "download"))
    assert download[3] == "70"


# ---- carrying on after a run that stopped part way ----------------------------------------------


def expected_tag(files: dict[str, str], signature: Path) -> dict:
    signed = here.signed_statement(VERSION, files, signature.read_text(encoding="utf-8"))
    return here.tag_payload(TAG, COMMIT, here.release_body(COMMIT, TREE), signed, NOW)


def leave_tag(commands: Commands, files: dict[str, str], signature: Path, **changed) -> None:
    payload = expected_tag(files, signature)
    commands.refs = [
        {"ref": f"refs/tags/{TAG}-other", "object": {"type": "tag", "sha": "e" * 40}},
        {"ref": f"refs/tags/{TAG}", "object": {"type": "tag", "sha": "c" * 40}},
    ]
    commands.tag_record = {"tag": TAG, "object": {"sha": COMMIT}, "message": payload["message"], **changed}


def test_a_run_that_stopped_after_the_tag_is_finished_by_running_it_again(commands, tmp_path):
    work, signature, files = prepared(tmp_path)
    commands.fail_on = "uploads.github.com"
    with pytest.raises(here.ReleaseError, match="network dropped"):
        here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    # The tag and the draft are there now, and the tag can never be moved.
    leave_tag(commands, files, signature)
    commands.listed = [{"tag_name": "windows/v1.7.3", "id": 5}, {**commands.release, "draft": True}]
    commands.fail_on, commands.sent = None, []

    said = here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    assert said.startswith(f"Published bus {VERSION} as {TAG}")
    # Nothing is made twice: only the release is published.
    assert commands.sent == [{"draft": False}]
    # Four uploads were never tried by the run that stopped at its first; the rerun does all five.
    assert sum("uploads.github.com" in " ".join(call) for call in commands.calls) == 1 + 5


def test_a_run_that_stopped_before_the_draft_makes_only_the_draft(commands, tmp_path):
    work, signature, files = prepared(tmp_path)
    leave_tag(commands, files, signature)

    here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    assert [sorted(sent)[0] for sent in commands.sent] == ["body", "draft"]


def test_a_release_already_published_is_only_checked(commands, tmp_path):
    work, signature, files = prepared(tmp_path)
    leave_tag(commands, files, signature)
    commands.listed = [commands.release]

    here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    assert commands.sent == []
    assert not any("uploads.github.com" in " ".join(call) for call in commands.calls)


@pytest.mark.parametrize("changed", [
    {"object": {"sha": "d" * 40}},
    {"message": "Strugglebus public release mirror v1\nsomething else\n"},
    {"tag": "bus/v9.9.9"},
])
def test_an_existing_tag_that_is_not_this_release_stops_it(commands, tmp_path, changed):
    work, signature, files = prepared(tmp_path)
    leave_tag(commands, files, signature, **changed)

    with pytest.raises(here.ReleaseError, match="already exists and is not this release"):
        here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)

    assert commands.sent == []


def test_an_existing_tag_that_is_not_annotated_stops_it(commands, tmp_path):
    work, signature, files = prepared(tmp_path)
    leave_tag(commands, files, signature)
    commands.refs = [{"ref": f"refs/tags/{TAG}", "object": {"type": "commit", "sha": COMMIT}}]

    with pytest.raises(here.ReleaseError, match="already exists and is not this release"):
        here.publish(commands, COMMIT, work, signature, here.REPOSITORY, NOW)


# ---- the command line ---------------------------------------------------------------------------


def test_the_command_line_runs_each_step_and_reports_a_refusal(monkeypatch, capsys, tmp_path):
    seen = []
    monkeypatch.setattr(here, "compare", lambda run, commit, work: seen.append(("compare", commit, work)) or "compared")
    monkeypatch.setattr(
        here, "publish",
        lambda run, commit, work, signature, repository, now: seen.append(("publish", signature, repository)) or "published",
    )

    assert here.main(["compare", "--commit", COMMIT, "--work", str(tmp_path / "w")]) == 0
    assert here.main(["publish", "--commit", COMMIT, "--work", str(tmp_path / "w"), "--signature", "s.sig"]) == 0
    assert seen == [("compare", COMMIT, (tmp_path / "w").resolve()), ("publish", Path("s.sig"), here.REPOSITORY)]
    assert capsys.readouterr().out == "compared\npublished\n"

    def refuse(run, commit, work):
        raise here.ReleaseError("no")

    monkeypatch.setattr(here, "compare", refuse)
    assert here.main(["compare", "--commit", COMMIT, "--work", str(tmp_path / "w")]) == 1
    assert capsys.readouterr().err == "error: no\n"


def test_a_command_that_fails_or_cannot_start_stops_the_release():
    import sys

    assert here.run(sys.executable, "-c", "print('ok')") == "ok\n"
    assert here.run(sys.executable, "-c", "import sys; print(sys.stdin.read())", stdin="in") == "in\n"
    with pytest.raises(here.ReleaseError, match="failed: .*boom"):
        here.run(sys.executable, "-c", "import sys; sys.exit('boom')")
    with pytest.raises(here.ReleaseError, match="could not run"):
        here.run("no-such-command-anywhere")
