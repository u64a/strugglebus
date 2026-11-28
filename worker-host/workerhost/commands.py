"""Signed host commands from the App (docs/app-host-integration.md section 4, stage D).

A command is a small JSON document signed by a pinned site key in the namespace strugglebus-host-command, carried in
an ordinary bus message's metadata (`sb_host_command: {doc: <base64>, sig: <armored SSHSIG>}`). The bus is only the
carrier: the signature is the authority, so who posted the message does not matter.

The checks, in order (security review M4; the reason code goes in the status's last_command):
  1. the signature over the exact bytes, explicit namespace (bad-signature), then those exact bytes are parsed with
     every key seen, so a repeated key is refused (duplicate-key); anything else malformed is bad-document;
  2. `host` is this host's bus name (not-this-host);
  3. `expires_at` is in the future (expired), at most 10 minutes after `issued_at`, and `issued_at` at most 2 minutes
     ahead of this host's clock (bad-time);
  4. the nonce was not seen in the last 24 hours, kept on disk across restarts (replayed);
  5. no field beyond the fixed seven (unknown-field), and `verb` is one of the fixed list (bad-verb).
The verbs cannot name a version, path, URL or anything to run.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import re
from dataclasses import dataclass
from pathlib import Path

from . import signing
from .state import atomic_write_json

NS_COMMAND = "strugglebus-host-command"
METADATA_KEY = "sb_host_command"
# sign-in-gh / sign-in-copilot (section 4a): the host signs itself in with a device code shown in the App. Like the
# others they carry no field of their own: the tool's command line is fixed in workerhost/signin.py.
VERBS = ("pause", "resume", "drain", "update", "sign-in-gh", "sign-in-copilot", "sign-in-claude")
FIELDS = frozenset({"v", "type", "host", "verb", "nonce", "issued_at", "expires_at"})
# The one verb with fields of its own: both required, nothing else (section 4a). epk: base64 of 32 bytes; ct: base64
# of IV + ciphertext + tag (sealed.py checks them precisely).
VERB_FIELDS = {"sign-in-claude": frozenset({"epk", "ct"})}
B64_RE = re.compile(r"[A-Za-z0-9+/]{4,1024}={0,2}")
MAX_DOC, MAX_SIG = 1024, 4096
MAX_LIFETIME, MAX_AHEAD, NONCE_DAYS = 600, 120, 1
NONCE_RE = re.compile(r"[0-9a-f]{32}")
TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
REASONS = ("bad-document", "bad-signature", "duplicate-key", "not-this-host", "expired", "bad-time", "replayed",
           "unknown-field", "bad-verb")


class Refused(Exception):
    def __init__(self, reason: str, nonce: str | None = None, verb: str | None = None):
        super().__init__(reason)
        self.reason, self.nonce, self.verb = reason, nonce, verb


@dataclass(frozen=True)
class Command:
    verb: str
    nonce: str
    issued_at: float
    expires_at: float
    signer: str  # the signing key's fingerprint
    extra: tuple[tuple[str, str], ...] = ()  # the verb's own fields (VERB_FIELDS), checked


def carried(metadata) -> tuple[bytes, bytes] | None:
    """The document and signature a message carries, or None when it carries no command. Raises Refused when it
    claims to carry one but the shape is wrong."""
    if not isinstance(metadata, dict) or METADATA_KEY not in metadata:
        return None
    c = metadata[METADATA_KEY]
    if not isinstance(c, dict) or not isinstance(c.get("doc"), str) or not isinstance(c.get("sig"), str):
        raise Refused("bad-document")
    if len(c["doc"]) > MAX_DOC * 4 // 3 + 4 or len(c["sig"]) > MAX_SIG:
        raise Refused("bad-document")
    try:
        doc = base64.b64decode(c["doc"], validate=True)
        sig = c["sig"].encode("ascii")
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise Refused("bad-document") from None
    if len(doc) > MAX_DOC:
        raise Refused("bad-document")
    return doc, sig


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise Refused("duplicate-key")
    return dict(pairs)


def parse(doc: bytes) -> dict:
    """The exact signed bytes as a dict, every key seen (Python's json would otherwise let a repeated key win)."""
    try:
        obj = json.loads(doc.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError):
        raise Refused("bad-document") from None
    if not isinstance(obj, dict):
        raise Refused("bad-document")
    return obj


def _time(value) -> float:
    if not isinstance(value, str) or not TIME_RE.fullmatch(value):
        raise Refused("bad-time")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        raise Refused("bad-time") from None


def _content(obj: dict, host: str, now: float, nonces: "NonceStore") -> Command:
    """Checks 2 to 5 on the parsed document."""
    nonce = obj.get("nonce") if isinstance(obj.get("nonce"), str) else None
    verb = obj.get("verb") if isinstance(obj.get("verb"), str) else None
    if obj.get("v") != 1 or obj.get("type") != "sb-host-command" or not isinstance(obj.get("host"), str):
        raise Refused("bad-document", nonce, verb)
    if obj["host"] != host:
        raise Refused("not-this-host", nonce, verb)
    issued, expires = _time(obj.get("issued_at")), _time(obj.get("expires_at"))
    if expires <= now:
        raise Refused("expired", nonce, verb)
    if expires <= issued or expires - issued > MAX_LIFETIME or issued > now + MAX_AHEAD:
        raise Refused("bad-time", nonce, verb)
    if nonce is None or not NONCE_RE.fullmatch(nonce):
        raise Refused("bad-document", None, verb)
    if nonces.seen(nonce, now):
        raise Refused("replayed", nonce, verb)
    own = VERB_FIELDS.get(verb or "", frozenset())
    if set(obj) - FIELDS - own:
        raise Refused("unknown-field", nonce, verb)
    if verb not in VERBS:
        raise Refused("bad-verb", nonce, None)
    if any(not isinstance(obj.get(k), str) or not B64_RE.fullmatch(obj[k]) for k in own):
        raise Refused("bad-document", nonce, verb)
    return Command(verb, nonce, issued, expires, "", tuple(sorted((k, obj[k]) for k in own)))


def check(doc: bytes, sig: bytes, *, host: str, now: float, nonces: "NonceStore", verify) -> Command:
    """The command, or Refused with the first rule it fails. `verify(doc, sig)` is signing.verify bound to the pinned
    signers and NS_COMMAND. On success the nonce is recorded, so the same command is never carried out twice."""
    v = verify(doc, sig)
    if not v.ok:
        raise Refused("bad-signature")
    cmd = _content(parse(doc), host, now, nonces)
    nonces.add(cmd.nonce, now)
    return Command(cmd.verb, cmd.nonce, cmd.issued_at, cmd.expires_at, v.fingerprint, cmd.extra)


def verifier(signers: Path, ssh_keygen: str | None, tmp: Path):
    """signing.verify for commands: the pinned signers, the command namespace and nothing else."""
    return lambda doc, sig: signing.verify(doc, sig, NS_COMMAND, signers, ssh_keygen, tmp)


class NonceStore:
    """Nonces seen in the last 24 hours, on disk (<state>\\command-nonces.json), so a restart does not reopen a replay
    window. Bounded: the oldest go first past 10 000."""

    LIMIT = 10_000

    def __init__(self, path: Path):
        self.path = Path(path)

    def _load(self, now: float) -> dict[str, float]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        horizon = now - NONCE_DAYS * 86400
        return {k: float(t) for k, t in raw.items()
                if isinstance(k, str) and isinstance(t, (int, float)) and t >= horizon}

    def seen(self, nonce: str, now: float) -> bool:
        return nonce in self._load(now)

    def add(self, nonce: str, now: float) -> None:
        kept = self._load(now)
        kept[nonce] = now
        if len(kept) > self.LIMIT:
            kept = dict(sorted(kept.items(), key=lambda kv: kv[1])[-self.LIMIT:])
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.path, kept)
