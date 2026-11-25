"""Which models a task may ask for: config.toml [models] (docs/design.md, "Models").

    [models]
    default = "claude-opus-5.5"                      # an exact model id
    allowed = ["claude-*", "gpt-*", "gemini-*"]      # exact ids or families; '*' matches any run of characters
    denied  = ["hydrafusion*"]                       # checked first: a denied match always wins

A model is allowed when its id is shaped like a model id (MODEL_RE), matches no `denied` pattern and matches at least
one `allowed` pattern. Families mean a model released tomorrow (claude-fable-5.2, gpt-6.2-astra) needs no change here:
Copilot CLI and the GitHub Copilot model policy remain the gate on what actually runs. An exact id is a pattern with
no '*', so the old exact lists keep working.

An entry is either an exact model id, or a FAMILY: a literal prefix of at least 3 characters followed by one trailing
'*' ("claude-*", "gpt-*", "hydrafusion*"). So a bare "*", or a near-universal "c*" / "g*" (which would admit local
self-hosted models), is refused, and '*' never appears mid-pattern; '?' and '[...]' are not accepted at all, so
fnmatch's other syntax never applies (a security review point).

Each family is a different provider receiving the code a worker sees, so the template allows only claude-*, gpt-*
and gemini-*; anything else is a per-host opt-in.

The host re-reads [models] when config.toml changes (hot reload, Host.reload_models); nothing else is re-read. Every
change in force (a reload, a failed reload, or a different list found at start) is posted to AUDIT_CHANNEL with the
old and new lists and the file's SHA-256: anything running as the host's account could edit the file, so a widening
must be visible. The channel is a constant, not a config key, so the same edit cannot redirect the audit.
"""
from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

MODEL_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")
FAMILY_RE = re.compile(r"[a-z0-9][a-z0-9.-]{2,62}\*")  # a prefix of 3+ characters, then ONE trailing '*'
KEYS = {"default", "allowed", "denied"}
DEFAULT_MODEL = "claude-opus-5.5"
AUDIT_CHANNEL = "security"


def pattern_ok(p: object) -> bool:
    return isinstance(p, str) and bool(MODEL_RE.fullmatch(p) or FAMILY_RE.fullmatch(p))


def is_allowed(model: object, allowed, denied=()) -> bool:
    """True when `model` is a well-formed id, matches no denied pattern and matches an allowed one."""
    if not isinstance(model, str) or not MODEL_RE.fullmatch(model):
        return False
    if any(fnmatchcase(model, p) for p in denied):
        return False
    return any(fnmatchcase(model, p) for p in allowed)


@dataclass(frozen=True)
class Models:
    default: str
    allowed: tuple[str, ...]
    denied: tuple[str, ...] = ()

    def allows(self, model: object) -> bool:
        return is_allowed(model, self.allowed, self.denied)


def parse(table: object) -> Models:
    """A [models] table (already TOML-parsed) as Models, or ValueError naming the problem."""
    if table is None:
        table = {}
    if not isinstance(table, dict):
        raise ValueError("[models] must be a table")
    unknown = set(table) - KEYS
    if unknown:
        raise ValueError(f"unknown keys in [models]: {sorted(unknown)}")
    default = table.get("default", DEFAULT_MODEL)
    allowed = table.get("allowed", [DEFAULT_MODEL])
    denied = table.get("denied", [])
    for name, value in (("allowed", allowed), ("denied", denied)):
        if not isinstance(value, list) or not all(pattern_ok(p) for p in value):
            raise ValueError(f"models.{name} must be a list of exact model ids or families: lowercase letters, "
                             f"digits, '.' and '-', and a family is a prefix of 3+ characters ending in one '*' "
                             f"(e.g. \"claude-*\")")
    if not allowed:
        raise ValueError("models.allowed must not be empty")
    if not isinstance(default, str) or not MODEL_RE.fullmatch(default):
        raise ValueError("models.default must be one exact model id (no '*')")
    m = Models(default, tuple(allowed), tuple(denied))
    if not m.allows(default):
        raise ValueError("models.default must match models.allowed and no models.denied pattern")
    return m


def read(path: Path) -> Models:
    """Only the [models] table of config.toml: the hot-reload path never touches any other setting."""
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    return parse(raw.get("models"))


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return "unreadable"


def summary(m: "Models | None") -> str:
    """One line for logs and audit posts: default, allowed and denied."""
    if m is None:
        return "none"
    return f"default={m.default} allowed={','.join(m.allowed)} denied={','.join(m.denied) or '-'}"
