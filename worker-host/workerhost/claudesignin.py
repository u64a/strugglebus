"""Claude Code signed in again by token (docs/app-host-integration.md 4a): the host's key, and the token it opens.

Claude Code's own /login wants its code pasted back, so a device flow doesn't fit. The operator makes a long-lived
token (`claude setup-token`) on any PC, and the App seals it to this host's key (workerhost/sealed.py): the bus only
ever relays ciphertext.

- **The host's key:** an X25519 pair, made the first time it's needed (the bootstrap makes it, as the account, and
  prints its fingerprint for the App's first pin). The private half is in the DPAPI store as `signin-key`; the public
  half and its fingerprint go in the admin-only status `sign_in_key`.
- **The token:** opened, then kept in the DPAPI store as `claude-token`, with the date it arrived. Claude Code workers
  get it as CLAUDE_CODE_OAUTH_TOKEN, and only they. The host's own records keep only the date.

Exposure, stated plainly (u64-security, #humans 29049): workers run as the same account and can read the token, the
same as the account's other DPAPI secrets and Claude Code's own sign-in file. One token per host; rotate it at least
yearly (the warning `claude-token-old` after 335 days); revoke it at claude.ai when the host is offboarded.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib

from . import cng, sealed

KEY_NAME = "signin-key"
TOKEN_NAME = "claude-token"
OLD_AFTER_DAYS = 335
TOKEN_ENV = "CLAUDE_CODE_OAUTH_TOKEN"


def fingerprint(public: bytes) -> str:
    """As the App shows it, and the bootstrap prints it: SHA256: and the unpadded base64 of SHA-256(public key)."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(public).digest()).decode("ascii").rstrip("=")


def ensure_key(store) -> tuple[bytes, bytes]:
    """This host's (private, public) key, made and stored the first time. `store` is a creds.Store."""
    if store.has(KEY_NAME):
        private = bytes.fromhex(store.load(KEY_NAME)["x25519"])
        return private, cng.x25519_public(private)
    private, public = cng.x25519_generate()
    store.save(KEY_NAME, {"x25519": private.hex()})
    return private, public


def key_status(store) -> dict | None:
    """The status's sign_in_key, or None until the key exists (it is never made just to report it)."""
    if not store.has(KEY_NAME):
        return None
    _, public = ensure_key(store)
    return {"x25519": base64.b64encode(public).decode("ascii"), "fingerprint": fingerprint(public)}


def receive(store, epk: str, ct: str, agent: str, nonce: str, today: dt.date) -> None:
    """Open a token sealed to this host for this command and keep it. Raises sealed.SealError (`decrypt`)."""
    if not store.has(KEY_NAME):
        raise sealed.SealError("no key")
    private, public = ensure_key(store)
    token = sealed.open_sealed(epk, ct, private, public, agent, nonce).strip()
    if not token or any(c.isspace() for c in token):
        raise sealed.SealError("not a token")
    store.save(TOKEN_NAME, {"token": token, "since": today.isoformat()})


def token(store) -> str | None:
    """The stored token, for a Claude Code worker's environment only. Never logged."""
    if not store.has(TOKEN_NAME):
        return None
    return store.load(TOKEN_NAME).get("token") or None


def since(store) -> str | None:
    """The date the token arrived (YYYY-MM-DD), for the admin-only status; never the token."""
    if not store.has(TOKEN_NAME):
        return None
    value = store.load(TOKEN_NAME).get("since")
    return value if isinstance(value, str) else None


def is_old(since_date: str | None, today: dt.date) -> bool:
    if not since_date:
        return False
    try:
        return (today - dt.date.fromisoformat(since_date)).days >= OLD_AFTER_DAYS
    except ValueError:
        return False
