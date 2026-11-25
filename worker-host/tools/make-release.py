"""Prepare a host release for the signer to sign: writes release.toml for a commit on main and opens the PR.

    python tools/make-release.py [--commit <sha on main>] [--notes "one line"] [--needs-install] [--dry-run]

What it does (it signs nothing; signing is tools/sign-config.ps1 -Pr <n> on a signing PC, with the YubiKey):
  1. fetches origin, takes origin/main (or --commit, which must be on origin/main);
  2. reads the installed files at that commit straight from git (wh.py, config.template.toml, README.md,
     workerhost/*.py) and computes tree_sha256 exactly as every host will (workerhost/update.py);
  3. serial = main's release.toml serial + 1 (1 for the first); version = the commit's date, YYYY.MM.DD, with .2, .3 ...
     for a second release the same day; notes = --notes, else the subjects of the commits since the last release;
  4. writes release.toml on a new branch release-<version>, pushes it, opens the PR "release <version> (to be
     signed)" and prints the sign-config command.

needs_install = true is for a release that changes what install.ps1 sets up (the scheduled task, the panel shortcut,
config.toml keys a host must have): hosts announce it but do not apply it.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from workerhost import update  # noqa: E402


def git(*args: str, check: bool = True) -> str:
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    if check and r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def release_text(serial: int, version: str, commit: str, tree: str, needs_install: bool, notes: str,
                 bootstrap: str = "", moved_to: tuple[str, str] | None = None) -> str:
    notes = re.sub(r"[\x00-\x1f\"\\]", " ", notes).strip()[:300]
    # bootstrap_sha256: tools/bootstrap.ps1 at this commit, so the App can pin the file it ships against a signed
    # value (docs/app-host-integration.md 2.1). Hosts ignore it (parse_release reads only the keys it knows).
    extra = (f'bootstrap_sha256 = "{bootstrap}"\n' if bootstrap else "")
    if moved_to:
        # The signed redirect: hosts that install this release read later
        # releases from here. A TOML table, so it comes after every top-level key.
        extra += f'\n[moved_to]\nrepo = "{moved_to[0]}"\npath = "{moved_to[1]}"\n'
    return (f"serial = {serial}\n\n"
            "# release.toml: the worker-host code hosts install, signed by a pinned key (release.toml.sig, namespace\n"
            "# strugglebus-release). Made by tools/make-release.py; signed and merged with tools/sign-config.ps1 -Pr <n>.\n"
            "# Hosts announce it at check_at (01:00) and apply it in their maintenance window (03:00): docs/design.md 10a.\n\n"
            f'version = "{version}"\n'
            f'commit = "{commit}"\n'
            f'tree_sha256 = "{tree}"\n'
            f"needs_install = {'true' if needs_install else 'false'}\n"
            f'notes = "{notes}"\n' + extra)


def at(path: str, name: str) -> str:
    """`name` inside the code's folder (--path; "" = the repository's top level)."""
    return f"{path}/{name}" if path else name


def bootstrap_sha256(commit: str, path: str = "") -> str:
    """SHA-256 of tools/bootstrap.ps1's exact bytes at the commit (it is -text in git), or "" if it has none."""
    r = subprocess.run(["git", "show", f"{commit}:{at(path, 'tools/bootstrap.ps1')}"], cwd=ROOT, capture_output=True)
    return hashlib.sha256(r.stdout).hexdigest() if r.returncode == 0 else ""


def resolve_commit(requested: str) -> tuple[str, str]:
    """(origin/main's head, the commit to release). The commit must be on origin/main: release only merged code."""
    git("fetch", "-q", "origin", "+refs/heads/main:refs/remotes/origin/main")
    main_head = git("rev-parse", "refs/remotes/origin/main")
    commit = git("rev-parse", requested or main_head)
    if subprocess.run(["git", "merge-base", "--is-ancestor", commit, main_head], cwd=ROOT).returncode != 0:
        raise SystemExit(f"{commit} is not on origin/main: release only merged code")
    return main_head, commit


def previous_release(main_head: str, path: str = "") -> dict:
    """release.toml as it is on main, or {} before the first release."""
    r = subprocess.run(["git", "show", f"{main_head}:{at(path, 'release.toml')}"], cwd=ROOT, capture_output=True)
    return tomllib.loads(r.stdout.decode("utf-8")) if r.returncode == 0 else {}


def next_version(commit: str, prev: dict) -> str:
    """The commit's date as YYYY.MM.DD, with .2, .3 ... when main's release or a tag already has that version."""
    day = dt.datetime.fromtimestamp(int(git("show", "-s", "--format=%ct", commit))).strftime("%Y.%m.%d")
    version, n = day, 1
    while str(prev.get("version", "")) == version or git("tag", "-l", f"v{version}"):
        n += 1
        version = f"{day}.{n}"
    return version


def default_notes(prev: dict, commit: str) -> str:
    """The subjects of the commits since the last release (PR numbers dropped), whole subjects only, within the 300
    characters hosts accept."""
    since = f"{prev['commit']}..{commit}" if prev.get("commit") else commit
    subjects = [s.split(" (#")[0] for s in git("log", "--format=%s", "--no-merges", "-n", "8", since).splitlines()]
    notes = ""
    for s in subjects:
        if len(notes) + len(s) + 2 > 300:
            break
        notes = f"{notes}; {s}" if notes else s
    return notes


def pr_body(version: str, serial: int, commit: str, n_files: int, tree: str, notes: str) -> str:
    return (f"Release **{version}**, serial {serial}: the host code at `{commit}` ({n_files} files, tree_sha256 "
            f"`{tree}`).\n\n{notes}\n\nSign it on a signing PC:\n\n"
            "`pwsh -File tools\\sign-config.ps1 -Pr <this PR> -KeyFile <your key handle file>`\n\n"
            "Hosts announce it at their next check (01:00) and apply it in their window (03:00).\n\n"
            "🤖 Generated with [Claude Code](https://claude.com/claude-code)\n")


def open_pr(title: str, body: str) -> int:
    r = subprocess.run(["gh", "pr", "create", "--title", title, "--body", body],
                       cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    print(r.stdout.strip() or r.stderr.strip())
    return r.returncode


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--commit", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--needs-install", action="store_true")
    p.add_argument("--path", default="", help="the code's folder in this repository (e.g. worker-host); default: top")
    p.add_argument("--moved-to", default="", metavar="URL:FOLDER",
                   help="the signed redirect: hosts that install this release read later releases from URL, FOLDER "
                        "(e.g. https://github.com/u64a/strugglebus:worker-host)")
    p.add_argument("--dry-run", action="store_true", help="print release.toml; no branch, no PR")
    return p.parse_args(argv)


def moved_to_arg(value: str) -> tuple[str, str] | None:
    if not value:
        return None
    url, sep, folder = value.rpartition(":")
    if not sep or not url.startswith("https://"):
        raise SystemExit("--moved-to takes https://<host>/<owner>/<repo>:<folder>")
    return url, folder


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    moved = moved_to_arg(args.moved_to)
    main_head, commit = resolve_commit(args.commit)
    files = update.read_tree("git", None, commit, cwd=ROOT, prefix=args.path)
    tree = update.tree_sha256(files)
    prev = previous_release(main_head, args.path)
    if prev.get("commit") == commit:
        raise SystemExit(f"release.toml on main already names {commit[:12]} (version {prev.get('version')})")
    serial = int(prev.get("serial", 0)) + 1
    version = next_version(commit, prev)
    notes = args.notes or default_notes(prev, commit)
    boot = bootstrap_sha256(commit, args.path)
    text = release_text(serial, version, commit, tree, args.needs_install, notes, boot, moved)
    update.parse_release(text.encode("utf-8"))  # what hosts will parse (and refuse a bad moved_to)
    print(text)
    print(f"# {len(files)} files at {commit[:12]}; tree_sha256 {tree}; bootstrap.ps1 sha256 {boot or '-'}")
    if args.dry_run:
        return 0
    branch = f"release-{version}"
    git("switch", "-q", "-c", branch, main_head)
    (ROOT / at(args.path, "release.toml")).write_bytes(text.encode("utf-8"))
    git("add", at(args.path, "release.toml"))
    git("commit", "-q", "-m", f"release {version} (to be signed): serial {serial}, code at {commit[:12]}",
        "-m", "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>")
    git("push", "-q", "-u", "origin", branch)
    body = pr_body(version, serial, commit, len(files), tree, notes)
    return 0 if open_pr(f"release {version} (to be signed)", body) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
