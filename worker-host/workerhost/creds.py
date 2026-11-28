"""DPAPI credential store (design section 12): one protected blob per identity, owner-only folder.

  <home>\\creds\\spn.bin           the SPN credential, from `wh enrol` (hidden prompt)
  <home>\\creds\\<agent>.bin       a bus identity record {agent_id, agent_name, secret, ...}

  <home>\\creds\\signin-key.bin    the host's X25519 key for a sealed Claude token (claudesignin.py)
  <home>\\creds\\claude-token.bin  that token and the date it arrived

Nothing secret is ever printed, logged or put on a command line. Two go in a worker's environment, deliberately: a
worker's own bus token with OpenBao (SB_BUS_TOKEN), and the Claude token for Claude Code workers only
(CLAUDE_CODE_OAUTH_TOKEN; docs/app-host-integration.md 4a, accepted by u64-security in #humans 29049).
Honest limit: DPAPI current-user does not protect against processes running as the same user.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from . import winapi

# <agent_prefix (31)>-<worker (31)>: up to 63 characters.
AGENT_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


_SID: str | None = None


def current_sid() -> str:
    """The current user's SID, as icacls takes it (`*S-1-...`). Not USERDOMAIN\\USERNAME: in an SSH session a
    local account's USERDOMAIN is WORKGROUP, which icacls cannot map, and the grant silently does nothing."""
    global _SID
    if _SID is None:
        r = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=60)
        sid = r.stdout.strip().rsplit(",", 1)[-1].strip().strip('"')
        if r.returncode != 0 or not re.fullmatch(r"S-1-[0-9-]+", sid):
            raise OSError("cannot read the current user's SID")
        _SID = sid
    return _SID


def owner_only(path: Path) -> None:
    """Remove inherited ACEs and grant only the current user, by SID. A failure raises: a file that was meant to
    be owner-only and is not must not pass silently."""
    if not winapi.IS_WINDOWS:
        os.chmod(path, 0o700 if Path(path).is_dir() else 0o600)
        return
    who = "*" + current_sid()
    args = ["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:(OI)(CI)F" if Path(path).is_dir() else f"{who}:F"]
    r = subprocess.run(args, capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
    if r.returncode != 0:
        raise OSError(f"icacls could not make {Path(path).name} owner-only")


class Store:
    def __init__(self, folder: Path):
        self.folder = Path(folder)

    def _ensure(self) -> None:
        if not self.folder.exists():
            self.folder.mkdir(parents=True)
            owner_only(self.folder)

    def _path(self, name: str) -> Path:
        if not AGENT_RE.fullmatch(name):
            raise ValueError("bad identity name")
        return self.folder / f"{name}.bin"

    def _write(self, path: Path, data: bytes) -> None:
        self._ensure()
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(winapi.dpapi_protect(data))
        os.replace(tmp, path)
        owner_only(path)

    def _read(self, path: Path) -> bytes:
        return winapi.dpapi_unprotect(path.read_bytes())

    # SPN
    def save_spn(self, secret: str) -> None:
        self._write(self.folder / "spn.bin", secret.strip().encode("utf-8"))

    def load_spn(self) -> str:
        path = self.folder / "spn.bin"
        if not path.exists():
            raise LookupError("no SPN credential stored; run wh enrol")
        return self._read(path).decode("utf-8")

    def has_spn(self) -> bool:
        return (self.folder / "spn.bin").exists()

    # identities
    def has(self, agent: str) -> bool:
        return self._path(agent).exists()

    def save(self, agent: str, record: dict) -> None:
        self._write(self._path(agent), json.dumps(record).encode("utf-8"))

    def load(self, agent: str) -> dict:
        path = self._path(agent)
        if not path.exists():
            raise LookupError(f"no credential stored for {agent}")
        return json.loads(self._read(path).decode("utf-8"))

    def remove(self, agent: str) -> None:
        path = self._path(agent)
        if path.exists():
            path.unlink()
