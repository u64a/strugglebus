#!/usr/bin/env python3
"""Publishes a bus release from this repository. Run on the publisher's own computer.

A release is five files built from one commit of main. They are built twice: by the "Bus release
build" workflow on GitHub's runner, and again here in the same container image. Nothing is signed
unless the two builds are the same bytes, so neither builder has to be believed on its own.

    1. Start the workflow for the commit and let it finish.
    2. python scripts/release_here.py compare --commit <commit> --work <new folder>
       Builds here, fetches GitHub's build, compares them, lists what changed since the last
       release, and writes release-statement.txt for the owner to sign.
    3. The owner signs the statement with a release key (the command is printed).
    4. python scripts/release_here.py publish --commit <commit> --work <folder> --signature <file>
       Makes the tag bus/vX.Y.Z carrying the signed statement, and publishes the release.

The tag is made last, at publishing, because it carries the signature and cannot be moved once
made. Needs git, docker and a signed-in gh. Signing needs the owner, their key and a touch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess  # nosec B404 - fixed commands, no shell
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from strugglebus.release_signature import release_statement, signer_of

REPOSITORY = "u64a/strugglebus"
BUILD_WORKFLOW = ".github/workflows/bus-release-build.yml"
TAG_PREFIX = "bus/"
# The image both builds run in, by digest. The workflow names the same one.
IMAGE = "debian@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0"
TAGGER_NAME = "NZCypher819"
TAGGER_EMAIL = "NZCypher819@users.noreply.github.com"
STATEMENT = "release-statement.txt"
FILES_IN_A_RELEASE = 5
_COMMIT = re.compile(r"[0-9a-f]{40}")
_WHEEL = re.compile(r"strugglebus-((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-py3-none-any\.whl")

Run = Callable[..., str]


class ReleaseError(Exception):
    """Something that stops the release, said in words the publisher can act on."""


def run(*command: str, cwd: Path | None = None, stdin: str | None = None) -> str:
    """Runs one fixed command and returns what it printed. Its failure stops the release."""
    try:
        done = subprocess.run(  # nosec B603 - an argument list, never a shell
            command, cwd=cwd, input=stdin, capture_output=True, text=True, encoding="utf-8", check=False,
        )
    except OSError as error:
        raise ReleaseError(f"could not run {command[0]}: {error}") from None
    if done.returncode != 0:
        raise ReleaseError(f"{' '.join(command[:3])} failed: {done.stderr.strip()[-600:]}")
    return done.stdout


def repository_root(run: Run) -> Path:
    return Path(run("git", "rev-parse", "--show-toplevel").strip())


def require_commit_on_main(run: Run, root: Path, commit: str) -> None:
    """A release is built only from a commit that is on main as GitHub has it now."""
    if _COMMIT.fullmatch(commit) is None:
        raise ReleaseError("give the full 40-character commit hash")
    # With the tags, so the list of changes since the last release starts from the newest one.
    run("git", "fetch", "--quiet", "--tags", "origin", "main", cwd=root)
    try:
        run("git", "merge-base", "--is-ancestor", commit, "origin/main", cwd=root)
    except ReleaseError:
        raise ReleaseError(f"{commit} is not on main") from None


def repository_named(name: str) -> str:
    """The real repository, or a scratch one made for trying this script out."""
    if name != REPOSITORY and re.fullmatch(r"u64a/[a-z0-9-]+-release-test", name) is None:
        raise ReleaseError(f"releases are published to {REPOSITORY}, or to a u64a/...-release-test repository")
    return name


# ---- The two builds -----------------------------------------------------------------------------


def digests(directory: Path) -> dict[str, str]:
    """The name and SHA-256 of each file of a release. A release is exactly five plain files."""
    entries = sorted(directory.iterdir())
    if len(entries) != FILES_IN_A_RELEASE or not all(path.is_file() for path in entries):
        raise ReleaseError(f"{directory} does not hold exactly five release files")
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in entries}


def version_of(files: dict[str, str]) -> str:
    wheels = [match.group(1) for match in map(_WHEEL.fullmatch, files) if match is not None]
    if len(wheels) != 1:
        raise ReleaseError("the release does not hold exactly one bus wheel")
    return wheels[0]


def build_here(run: Run, root: Path, commit: str, work: Path) -> Path:
    """The second build: a fresh clone at the commit, in the pinned image, with the same script."""
    clone = work / "clone"
    run("git", "clone", "--quiet", "--no-hardlinks", str(root), str(clone))
    run("git", "checkout", "--quiet", "--detach", commit, cwd=clone)
    output = work / "local"
    output.parent.mkdir(parents=True, exist_ok=True)
    script = (
        "set -euo pipefail; export DEBIAN_FRONTEND=noninteractive; "
        "apt-get update -qq >/dev/null; "
        "apt-get install -y -qq --no-install-recommends git curl ca-certificates >/dev/null 2>&1; "
        "git config --global --add safe.directory '*'; "
        "git clone -q /origin /build/strugglebus; cd /build/strugglebus; "
        f"git checkout -q --detach {commit}; "
        f"bash bus/scripts/build_release.sh {commit} /out/local"
    )
    run(
        "docker", "run", "--rm", "-v", f"{clone}:/origin:ro", "-v", f"{work}:/out", IMAGE,
        "bash", "-c", script,
    )
    return output


def made_by_the_build_workflow(run: Run, artifact: dict[str, Any], commit: str) -> bool:
    """
    Whether an artifact is the real build of this commit. Its name proves nothing: a pull request,
    even from a fork, runs its own copy of a workflow and can offer an artifact of any name. So
    the run behind it must be the build workflow, started by hand in this repository, for this
    commit, and finished well.
    """
    made = api(run, "GET", f"repos/{REPOSITORY}/actions/runs/{int(artifact['workflow_run']['id'])}")
    return (
        made.get("path") == BUILD_WORKFLOW
        and made.get("event") == "workflow_dispatch"
        and made.get("head_sha") == commit
        and (made.get("head_repository") or {}).get("full_name") == REPOSITORY
        and made.get("conclusion") == "success"
    )


def githubs_build(run: Run, commit: str, work: Path) -> Path:
    """GitHub's build of the same commit: the artifact the build workflow offered."""
    listing = json.loads(run("gh", "api", f"repos/{REPOSITORY}/actions/artifacts?name=bus-release-{commit}&per_page=100"))
    offered = [
        item for item in listing.get("artifacts", [])
        if not item.get("expired") and made_by_the_build_workflow(run, item, commit)
    ]
    if not offered:
        raise ReleaseError(
            f"GitHub has no build of {commit} made by the 'Bus release build' workflow. Start that "
            "workflow by hand for this commit while it is the newest on main, and let it finish."
        )
    newest = max(offered, key=lambda item: int(item["id"]))
    output = work / "github"
    run(
        "gh", "run", "download", str(int(newest["workflow_run"]["id"])), "--repo", REPOSITORY,
        "--name", f"bus-release-{commit}", "--dir", str(output),
    )
    return output


def require_same(here: dict[str, str], there: dict[str, str]) -> None:
    """The whole point of two builds: they must agree on every file, or nothing is signed."""
    if here == there:
        return
    names = sorted(set(here) | set(there))
    different = [name for name in names if here.get(name) != there.get(name)]
    raise ReleaseError(
        "THE TWO BUILDS DIFFER. Do not sign. Files that differ: " + ", ".join(different)
    )


def changes_since_last_release(run: Run, root: Path, commit: str, version: str) -> str:
    """What the owner is about to sign for: every commit that touched the bus since the last release."""
    tags = run("git", "tag", "--list", f"{TAG_PREFIX}v*", "--sort=-version:refname", "--merged", commit, cwd=root).split()
    if f"{TAG_PREFIX}v{version}" in tags:
        raise ReleaseError(f"bus {version} is already tagged; a release is never published twice")
    if not tags:
        return "This is the first bus release from this repository, so everything in bus/ is new to it.\n"
    log = run("git", "log", "--format=%h %ad %s", "--date=short", f"{tags[0]}..{commit}", "--", "bus", cwd=root)
    return f"Commits that touched bus/ since {tags[0]}:\n{log or '(none)' + chr(10)}"


def compare(run: Run, commit: str, work: Path) -> str:
    root = repository_root(run)
    require_commit_on_main(run, root, commit)
    if work.exists():
        raise ReleaseError(f"{work} already exists; give a new folder")
    work.mkdir(parents=True)
    there = digests(githubs_build(run, commit, work))
    here = digests(build_here(run, root, commit, work))
    require_same(here, there)
    version = version_of(here)
    statement = release_statement(version, here)
    (work / STATEMENT).write_bytes(statement.encode())
    shutil.rmtree(work / "clone", ignore_errors=True)
    return (
        f"Both builds of {commit} are the same five files.\n\n"
        + changes_since_last_release(run, root, commit, version)
        + f"\nThis would be published as bus {version}. The statement to sign:\n\n{statement}\n"
        "If that is what you mean to release, sign it (a touch and the PIN):\n\n"
        f"  ssh-keygen -Y sign -f <release key> -n strugglebus-bus-release \"{work / STATEMENT}\"\n"
    )


# ---- Publishing ---------------------------------------------------------------------------------


def release_body(commit: str, tree: str) -> str:
    """Exactly what an installed updater expects a release to say about its source."""
    value = {"source_commit": commit, "source_repository": REPOSITORY, "source_tree": tree, "version": 1}
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True)


def signed_statement(version: str, files: dict[str, str], signature: str) -> str:
    """The statement and its signature as the tag carries them. Refused unless a release key signed it."""
    statement = release_statement(version, files)
    armoured = signature.strip()
    if signer_of(armoured, statement) is None:
        raise ReleaseError(
            "the statement is not signed by a release key for these exact files; "
            "sign the release-statement.txt that 'compare' wrote, with a touch and the PIN"
        )
    return statement + armoured + "\n"


def tag_payload(tag: str, commit: str, body: str, signed: str, when: datetime) -> dict[str, Any]:
    return {
        "message": f"Strugglebus public release mirror v1\n{body}\n{signed}",
        "object": commit,
        "tag": tag,
        "tagger": {"date": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "email": TAGGER_EMAIL, "name": TAGGER_NAME},
        "type": "commit",
    }


def release_payload(tag: str, commit: str, body: str) -> dict[str, Any]:
    # The commit hash, not a branch name: an updater checks the release against the tag's commit.
    return {
        "body": body, "draft": True, "name": tag, "prerelease": False,
        "tag_name": tag, "target_commitish": commit,
    }


def api(run: Run, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    command = ["gh", "api", "--method", method, path]
    if payload is None:
        return json.loads(run(*command))
    return json.loads(run(*command, "--input", "-", stdin=json.dumps(payload)))


def require_published_as_meant(record: dict[str, Any], tag: str, commit: str, files: dict[str, str]) -> None:
    """After publishing, GitHub must hold exactly what was signed, and hold it unchangeably."""
    served = {asset["name"]: str(asset.get("digest", "")).removeprefix("sha256:") for asset in record.get("assets", [])}
    checks = {
        "its tag": record.get("tag_name") == tag,
        "its commit": record.get("target_commitish") == commit,
        "being published": record.get("draft") is False and record.get("prerelease") is False,
        "being immutable": record.get("immutable") is True,
        "its files": served == files,
    }
    wrong = [name for name, good in checks.items() if not good]
    if wrong:
        raise ReleaseError("the published release is not as it was meant, in: " + ", ".join(wrong))


def ensure_tag(run: Run, repository: str, payload: dict[str, Any]) -> None:
    """
    Makes the release's tag, or accepts the one already there from a run that stopped part way.

    A bus tag can never be moved or deleted, so a second run must be able to carry on from it. It
    is accepted only if it is an annotated tag on exactly this commit with exactly this message,
    which holds the signed statement. Anything else is someone else's tag and stops the release.
    """
    tag = payload["tag"]
    name = f"refs/tags/{tag}"
    found = json.loads(run("gh", "api", f"repos/{repository}/git/matching-refs/tags/{tag}"))
    existing = [ref for ref in found if ref.get("ref") == name]
    if not existing:
        made = api(run, "POST", f"repos/{repository}/git/tags", payload)
        api(run, "POST", f"repos/{repository}/git/refs", {"ref": name, "sha": made["sha"]})
        return
    target = existing[0].get("object") or {}
    record = api(run, "GET", f"repos/{repository}/git/tags/{target.get('sha')}") if target.get("type") == "tag" else {}
    same = (
        record.get("tag") == tag
        and (record.get("object") or {}).get("sha") == payload["object"]
        and record.get("message") == payload["message"]
    )
    if not same:
        raise ReleaseError(
            f"{tag} already exists and is not this release: not this commit with this signed statement. "
            "It cannot be moved; release the next version instead."
        )


def ensure_draft(run: Run, repository: str, payload: dict[str, Any]) -> dict[str, Any]:
    """The release for the tag: the one a stopped run left, or a new draft."""
    listed = json.loads(run("gh", "api", f"repos/{repository}/releases?per_page=100"))
    for record in listed:
        if record.get("tag_name") == payload["tag_name"]:
            return record
    return api(run, "POST", f"repos/{repository}/releases", payload)


def publish(run: Run, commit: str, work: Path, signature: Path, repository: str, now: datetime) -> str:
    repository = repository_named(repository)
    root = repository_root(run)
    require_commit_on_main(run, root, commit)
    files = digests(work / "local")
    require_same(files, digests(work / "github"))
    version = version_of(files)
    signed = signed_statement(version, files, signature.read_text(encoding="utf-8"))
    tag = f"{TAG_PREFIX}v{version}"
    tree = run("git", "rev-parse", f"{commit}^{{tree}}", cwd=root).strip()
    body = release_body(commit, tree)

    # Each step is safe to run again, so a run that stopped part way is finished by running it again.
    ensure_tag(run, repository, tag_payload(tag, commit, body, signed, now))
    release = ensure_draft(run, repository, release_payload(tag, commit, body))
    if release.get("draft") is True:
        paths = [str(work / "local" / name) for name in sorted(files)]
        run("gh", "release", "upload", tag, *paths, "--clobber", "--repo", repository)
        api(run, "PATCH", f"repos/{repository}/releases/{release['id']}", {"draft": False})
    record = api(run, "GET", f"repos/{repository}/releases/{release['id']}")
    require_published_as_meant(record, tag, commit, files)
    return f"Published bus {version} as {tag} in {repository}, from {commit}.\n"


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("compare", "publish"):
        command = commands.add_parser(name)
        command.add_argument("--commit", required=True)
        command.add_argument("--work", type=Path, required=True)
    commands.choices["publish"].add_argument("--signature", type=Path, required=True)
    commands.choices["publish"].add_argument("--repository", default=REPOSITORY)
    options = parser.parse_args(arguments)
    try:
        if options.command == "compare":
            print(compare(run, options.commit, options.work.resolve()))
        else:
            print(publish(
                run, options.commit, options.work.resolve(), options.signature, options.repository,
                datetime.now(timezone.utc),
            ))
    except ReleaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
