"""Repository URLs: the rules a clone URL must pass (docs/agent-host-build.md section 7.3).

Used by fleet.toml parsing (a coordinator's `repos` and `notes_repo`), config.toml's `[remotes] allowed` fence and
task validation (a task's `repo`). Only https; no user name, password, port, query or fragment; the host lower-case;
the path exactly /<owner>/<repo> with an optional .git; names [A-Za-z0-9_.-]+ and never . or ..; prefixes compared
by whole path segments, so https://github.com/acme/ does not match https://github.com/acme-evil/x.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

SEGMENT_RE = re.compile(r"[A-Za-z0-9_.-]+")

# The outer fence when config.toml has no [remotes] table: GitHub as a whole. A site narrows it to its own owners
# (site.toml `remotes`, filled into config.toml by install.ps1 -SiteFile), and each coordinator's signed fleet.toml
# `repos` narrows it again.
DEFAULT_REMOTES = ("https://github.com/",)


def _segments_ok(parts: list[str]) -> bool:
    return all(SEGMENT_RE.fullmatch(p) and p not in (".", "..") for p in parts)


def split_url(url: str) -> tuple[str, list[str]] | None:
    """(host, path segments) of an https URL with no user, password, port, query or fragment; else None."""
    if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 for c in url):
        return None
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return None
    if (u.scheme != "https" or u.username is not None or u.password is not None or port is not None
            or u.query or u.fragment or "?" in url or "#" in url or not u.hostname or u.netloc != u.hostname
            or u.netloc != u.netloc.lower() or not u.path.startswith("/")):
        return None
    return u.netloc, u.path[1:].split("/")


def repo_url(url: str) -> tuple[str, str, str] | None:
    """(host, owner, repo) for exactly https://<host>/<owner>/<repo>[.git]; else None."""
    parts = split_url(url)
    if not parts:
        return None
    host, segs = parts
    if len(segs) != 2 or not _segments_ok(segs):
        return None
    owner, repo = segs
    repo = repo[:-4] if repo.endswith(".git") else repo
    if not repo or repo in (".", ".."):
        return None
    return host, owner, repo


def canonical(url: str) -> str | None:
    """https://<host>/<owner>/<repo> (no .git, no trailing slash), or None if the URL breaks a rule."""
    parsed = repo_url(url)
    return f"https://{parsed[0]}/{parsed[1]}/{parsed[2]}" if parsed else None


def prefix_ok(prefix: str) -> bool:
    """A `repos` entry: https://<host>/, https://<host>/<owner>/, or an exact repository URL."""
    parts = split_url(prefix)
    if not parts:
        return False
    _, segs = parts
    if prefix.endswith("/"):
        segs = segs[:-1]
        return len(segs) <= 1 and _segments_ok(segs)
    return repo_url(prefix) is not None


def url_matches(url: str, prefix: str) -> bool:
    """Whole path segments only: https://github.com/acme/ does not match https://github.com/acme-evil/x."""
    target, pre = repo_url(url), split_url(prefix)
    if not target or not pre or not prefix_ok(prefix):
        return False
    host, owner, repo = target
    p_host, p_segs = pre
    if p_host != host:
        return False
    if prefix.endswith("/"):
        p_segs = p_segs[:-1]
        return p_segs == [] or p_segs == [owner]
    return repo_url(prefix) == target


def allowed(url: str, prefixes) -> bool:
    return any(url_matches(url, p) for p in prefixes)
