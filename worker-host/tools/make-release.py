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

In a shared repository (u64a/strugglebus), --path names the host's folder: release.toml is written there, the tree
is read from there and the notes come from commits that touched it. Each such release carries moved_to naming its own
place (from origin), so a host that installs it keeps reading from here. The first release at a new place continues the
old place's numbering with --continue-from <its release.toml> (hosts refuse any serial not above the one installed);
it needs --notes, since the old place's commits are not in this repository.
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


def top() -> Path:
    """The repository's top level. ROOT is the host's own folder, which in a shared repository is a subfolder, and
    git ls-tree and git add take paths relative to where they run."""
    return Path(git("rev-parse", "--show-toplevel"))


# The Authenticode certificates allowed to sign bootstrap.ps1 for a release (tools/sign-bootstrap.ps1): their
# thumbprints, current and, once known, the next, so a renewed certificate arrives through a signed release rather
# than a code change. The project's Certum open-source code-signing certificate, valid to 26 Nov 2027.
AUTHENTICODE_THUMBPRINTS = ("3FF059FA28ED74ACB229CBA2E670CEA565015238",)


def release_text(serial: int, version: str, commit: str, tree: str, needs_install: bool, notes: str,
                 bootstrap: str = "", moved_to: tuple[str, str] | None = None,
                 thumbprints: tuple[str, ...] = AUTHENTICODE_THUMBPRINTS) -> str:
    notes = re.sub(r"[\x00-\x1f\"\\]", " ", notes).strip()[:300]
    # bootstrap_sha256: tools/bootstrap.ps1 at this commit, so the App can pin the file it ships against a signed
    # value (docs/app-host-integration.md 2.1). Hosts ignore it (parse_release reads only the keys it knows).
    extra = (f'bootstrap_sha256 = "{bootstrap}"\n' if bootstrap else "")
    if bootstrap and thumbprints:
        # authenticode_thumbprints: who may Authenticode-sign that bootstrap.ps1 (tools/sign-bootstrap.ps1 checks it
        # before and after signing). Signed with the rest, so a new certificate needs a signed release. Hosts ignore it.
        extra += "authenticode_thumbprints = [" + ", ".join(f'"{t}"' for t in thumbprints) + "]\n"
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


def continued(prev: dict, old: str, notes: str) -> dict:
    """With --continue-from: the old place's release (its serial and version, never its commit, which is in another
    repository). Only for the first release at a new place: after that, this place's own release.toml counts."""
    if not old:
        return prev
    if prev:
        raise SystemExit("--continue-from is only for the first release here: main already has a release.toml")
    if not notes:
        raise SystemExit("--continue-from needs --notes (the old place's commits are not in this repository)")
    try:
        raw = tomllib.loads(Path(old).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise SystemExit(f"--continue-from {old}: {e}")
    if not isinstance(raw.get("serial"), int) or raw["serial"] < 1:
        raise SystemExit(f"--continue-from {old}: no serial")
    return {"serial": raw["serial"], "version": str(raw.get("version", ""))}


def next_version(commit: str, prev: dict) -> str:
    """The commit's date as YYYY.MM.DD, with .2, .3 ... when main's release or a tag already has that version."""
    day = dt.datetime.fromtimestamp(int(git("show", "-s", "--format=%ct", commit))).strftime("%Y.%m.%d")
    version, n = day, 1
    # After the day's .2 comes .3, never the bare day again (which would read as going back).
    same_day = re.fullmatch(re.escape(day) + r"(?:\.(\d+))?", str(prev.get("version", "")))
    if same_day:
        n = int(same_day.group(1) or 1) + 1
        version = f"{day}.{n}"
    while str(prev.get("version", "")) == version or git("tag", "-l", f"v{version}"):
        n += 1
        version = f"{day}.{n}"
    return version


def default_notes(prev: dict, commit: str, path: str = "") -> str:
    """The subjects of the commits since the last release (PR numbers dropped), whole subjects only, within the 300
    characters hosts accept. With a path, only commits that touched it (a shared repository has other products)."""
    since = f"{prev['commit']}..{commit}" if prev.get("commit") else commit
    only = ["--", f":(top){path}"] if path else []
    subjects = [s.split(" (#")[0]
                for s in git("log", "--format=%s", "--no-merges", "-n", "8", since, *only).splitlines()]
    notes = ""
    for s in subjects:
        if len(notes) + len(s) + 2 > 300:
            break
        notes = f"{notes}; {s}" if notes else s
    return notes


def sign_command(path: str = "", first_serial: int = 0) -> str:
    """The sign-config.ps1 command for this release's PR. In a shared repository the tool runs from the host's
    folder, names it with -Path, and checks against a signers file you give (the repository carries none)."""
    if not path:
        return "pwsh -File tools\\sign-config.ps1 -Pr <this PR> -KeyFile <your key handle file>"
    first = f" -FirstSerial {first_serial}" if first_serial else ""
    return (f"pwsh -File {path}\\tools\\sign-config.ps1 -Pr <this PR> -Path {path}{first} "
            "-Signers <your allowed_signers file> -KeyFile <your key handle file>")


def pr_body(version: str, serial: int, commit: str, n_files: int, tree: str, notes: str, command: str = "") -> str:
    return (f"Release **{version}**, serial {serial}: the host code at `{commit}` ({n_files} files, tree_sha256 "
            f"`{tree}`).\n\n{notes}\n\nSign it on a signing PC:\n\n"
            f"`{command or sign_command()}`\n\n"
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
    p.add_argument("--continue-from", default="", metavar="RELEASE_TOML",
                   help="the first release at a new place: continue the serial of this (the old place's) release.toml")
    p.add_argument("--dry-run", action="store_true", help="print release.toml; no branch, no PR")
    return p.parse_args(argv)


def origin_url() -> str:
    """origin as https://<host>/<owner>/<repo> (no .git), from an https or git@host:owner/repo remote, or ""."""
    url = git("remote", "get-url", "origin", check=False)
    m = re.fullmatch(r"(?:https://|git@)([^/:@]+)[/:]([^/]+)/([^/]+?)(?:\.git)?/?", url)
    return f"https://{m.group(1).lower()}/{m.group(2)}/{m.group(3)}" if m else ""


def self_redirect(path: str, given: tuple[str, str] | None) -> tuple[str, str] | None:
    """In a shared repository, every release points at its own place. A host records the redirect only from the
    release it has installed, so a release without one sends the host back to its fleet repository: that happened
    on 27 Nov, after the first release here (serial 8) installed with none."""
    if given or not path:
        return given
    url = origin_url()
    if not url:
        raise SystemExit("cannot tell this repository's https address from origin: give --moved-to URL:FOLDER")
    return url, path


def moved_to_arg(value: str) -> tuple[str, str] | None:
    if not value:
        return None
    url, sep, folder = value.rpartition(":")
    if not sep or not url.startswith("https://"):
        raise SystemExit("--moved-to takes https://<host>/<owner>/<repo>:<folder>")
    return url, folder


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    moved = self_redirect(args.path, moved_to_arg(args.moved_to))
    main_head, commit = resolve_commit(args.commit)
    repo_top = top()
    files = update.read_tree("git", None, commit, cwd=repo_top, prefix=args.path)
    tree = update.tree_sha256(files)
    here = previous_release(main_head, args.path)
    if here.get("commit") == commit:
        raise SystemExit(f"release.toml on main already names {commit[:12]} (version {here.get('version')})")
    prev = continued(here, args.continue_from, args.notes)
    serial = int(prev.get("serial", 0)) + 1
    version = next_version(commit, prev)
    notes = args.notes or default_notes(prev, commit, args.path)
    boot = bootstrap_sha256(commit, args.path)
    text = release_text(serial, version, commit, tree, args.needs_install, notes, boot, moved)
    update.parse_release(text.encode("utf-8"))  # what hosts will parse (and refuse a bad moved_to)
    print(text)
    print(f"# {len(files)} files at {commit[:12]}; tree_sha256 {tree}; bootstrap.ps1 sha256 {boot or '-'}")
    if args.dry_run:
        return 0
    branch = f"{args.path}-release-{version}" if args.path else f"release-{version}"
    git("switch", "-q", "-c", branch, main_head)
    (repo_top / at(args.path, "release.toml")).write_bytes(text.encode("utf-8"))
    git("add", "--", f":(top){at(args.path, 'release.toml')}")
    git("commit", "-q", "-m", f"release {version} (to be signed): serial {serial}, code at {commit[:12]}",
        "-m", "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>")
    git("push", "-q", "-u", "origin", branch)
    command = sign_command(args.path, serial if args.continue_from else 0)
    body = pr_body(version, serial, commit, len(files), tree, notes, command)
    title = f"{args.path}: release {version} (to be signed)" if args.path else f"release {version} (to be signed)"
    return 0 if open_pr(title, body) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
