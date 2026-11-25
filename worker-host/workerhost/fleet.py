"""fleet.toml: who the hosts take tasks from and who the other hosts are (docs/agent-host-build.md section 7.2).

The file lives in the fleet repository and is signed by a key in the hosts' pinned allowed_signers (fleet.toml.sig,
namespace strugglebus-fleet).
Every host fetches it every `fleet_refresh_minutes` into a bare mirror (<home>\\fleet.git), reads both files
at origin/main by blob, checks the signature against the pinned keys and the serial against the last one it
accepted, and only then replaces its list. Nothing else from the repository is read or run.

A host that has never accepted a signed file keeps using config.toml's [coordinator] pin and [[hosts]] list
(the migration path). Once one is accepted, those are ignored.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import signing
from .config import OWNER_RE
from .state import atomic_write_json
from .urls import SEGMENT_RE, prefix_ok, repo_url, split_url, url_matches  # noqa: F401
from .validate import UUID_RE, Pin

AGENT_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
CHANNEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
ENGINES = ("ghcp", "claude")
MAX_BYTES = 64 * 1024  # the bus's site-document cap, the same for every source (docs/app-host-integration.md 3)
MAX_RULES = 4000  # characters of worker_rules per coordinator: they go on every worker's command line
FILE, SIG = "fleet.toml", "fleet.toml.sig"


class FleetError(ValueError):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# --- URLs (section 7.3): workerhost/urls.py, re-exported for callers of fleet --------------------------

# --- the file -------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Coordinator:
    agent_name: str
    agent_id: str
    project: str
    notes_repo: str
    notes_channel: str
    repos: tuple[str, ...]
    default_engine: str = "ghcp"
    # Whether this project's tasks load the repository's AGENTS.md and the like when the task does not say
    # ("repo_instructions"); and the project's own rules, put into every worker's fixed preamble. Signed with the
    # rest of the file, so a project's always-rules do not depend on a file anyone with push access can change.
    repo_instructions: bool = True
    worker_rules: str = ""

    @property
    def pin(self) -> Pin:
        return Pin(self.agent_id, self.agent_name)


@dataclass(frozen=True)
class Fleet:
    serial: int
    coordinators: tuple[Coordinator, ...]
    hosts: tuple[Pin, ...]
    sha256: str
    commit: str = ""
    ignored_keys: tuple[str, ...] = field(default=())
    owner: str = ""  # whose decision merging is, named in every worker's preamble; "" = "the owner"

    def coordinator(self, pin: Pin) -> Coordinator | None:
        return next((c for c in self.coordinators if c.pin == pin), None)

    @property
    def label(self) -> str:
        return f"{self.serial}:{self.commit[:7] or self.sha256[:7]}"


def _str(table: dict, key: str, where: str, pattern: re.Pattern | None = None) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value or (pattern and not pattern.fullmatch(value)):
        raise FleetError("fleet-invalid", f"{where}.{key}")
    return value


def parse(data: bytes, commit: str = "") -> Fleet:
    """The fleet in `data`, or FleetError("fleet-invalid", <where>). Keys this version does not know are
    ignored (and listed), so a newer fleet.toml does not stop an older host."""
    if len(data) > MAX_BYTES:
        raise FleetError("fleet-invalid", "size")
    try:
        raw = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise FleetError("fleet-invalid", f"toml: {e}") from None
    ignored = [k for k in raw if k not in ("serial", "owner", "coordinator", "host")]
    serial = raw.get("serial")
    if not isinstance(serial, int) or isinstance(serial, bool) or serial < 1:
        raise FleetError("fleet-invalid", "serial")
    owner = raw.get("owner", "")
    if not isinstance(owner, str) or (owner and not OWNER_RE.fullmatch(owner)):
        raise FleetError("fleet-invalid", "owner")
    seen = _Seen()
    coords = [seen.add(_coordinator(t, where, ignored), where) for where, t in _tables(raw, "coordinator")]
    hosts = [seen.add(_host(t, where, ignored), where) for where, t in _tables(raw, "host")]
    return Fleet(serial, tuple(coords), tuple(hosts), hashlib.sha256(data).hexdigest(), commit, tuple(ignored),
                 owner)


COORDINATOR_KEYS = {"agent_name", "agent_id", "project", "notes_repo", "notes_channel", "repos", "default_engine",
                    "repo_instructions", "worker_rules"}


class _Seen:
    """No agent_id or agent_name twice anywhere in the fleet, coordinators and hosts together."""

    def __init__(self):
        self.ids, self.names = set(), set()

    def add(self, entry, where: str):
        if entry.agent_id in self.ids or entry.agent_name in self.names:
            raise FleetError("fleet-invalid", f"{where}: duplicate agent")
        self.ids.add(entry.agent_id)
        self.names.add(entry.agent_name)
        return entry


def _tables(raw: dict, key: str):
    """(where, table) for each [[key]] table, e.g. ("host[0]", {...})."""
    tables = raw.get(key, [])
    if not isinstance(tables, list):
        raise FleetError("fleet-invalid", key)
    for i, t in enumerate(tables):
        where = f"{key}[{i}]"
        if not isinstance(t, dict):
            raise FleetError("fleet-invalid", where)
        yield where, t


def _rules_ok(rules) -> bool:
    return (isinstance(rules, str) and len(rules) <= MAX_RULES
            and not any((ord(ch) < 32 and ch not in (chr(10), chr(9))) or ord(ch) == 127 for ch in rules))


def _coordinator(t: dict, where: str, ignored: list[str]) -> Coordinator:
    ignored += [f"{where}.{k}" for k in t if k not in COORDINATOR_KEYS]
    repos = t.get("repos")
    if not isinstance(repos, list) or not repos or not all(isinstance(r, str) and prefix_ok(r) for r in repos):
        raise FleetError("fleet-invalid", f"{where}.repos")
    notes_repo = _str(t, "notes_repo", where)
    if repo_url(notes_repo) is None:
        raise FleetError("fleet-invalid", f"{where}.notes_repo")
    engine = t.get("default_engine", "ghcp")
    if engine not in ENGINES:
        raise FleetError("fleet-invalid", f"{where}.default_engine")
    repo_instructions = t.get("repo_instructions", True)
    if type(repo_instructions) is not bool:
        raise FleetError("fleet-invalid", f"{where}.repo_instructions")
    rules = t.get("worker_rules", "")
    if not _rules_ok(rules):
        raise FleetError("fleet-invalid", f"{where}.worker_rules")
    return Coordinator(_str(t, "agent_name", where, AGENT_RE), _str(t, "agent_id", where, UUID_RE),
                       _str(t, "project", where, PROJECT_RE), notes_repo,
                       _str(t, "notes_channel", where, CHANNEL_RE), tuple(repos), engine,
                       repo_instructions, rules.strip())


def _host(t: dict, where: str, ignored: list[str]) -> Pin:
    ignored += [f"{where}.{k}" for k in t if k not in ("agent_name", "agent_id")]
    return Pin(_str(t, "agent_id", where, UUID_RE), _str(t, "agent_name", where, AGENT_RE))


# --- fetching, checking, keeping ------------------------------------------------------------------

@dataclass(frozen=True)
class Outcome:
    status: str  # fleet-accepted | unchanged | fleet-missing | fleet-unsigned | fleet-bad-signature |
    #              fleet-cannot-verify | fleet-invalid | fleet-old | fetch-failed
    fleet: Fleet | None = None
    detail: str = ""
    commit: str = ""


BUS_PATH = "/api/site-documents/fleet"
SOURCES = ("git", "bus", "either")
# For "either", which answer to report: an acceptance first; then a real problem with a file (a bad signature, an
# invalid file), which is worth saying even when the other source is fine; then unchanged; then one source merely
# behind the other (normal: the App publishes to the bus, the repository may lag); then nothing there at all.
_RANK = {"fleet-accepted": 0, "unchanged": 2, "fleet-old": 3, "fleet-missing": 4, "fetch-failed": 5}


def fetch_from_bus(bus) -> tuple[bytes, bytes] | Outcome:
    """The fleet's exact bytes and signature from the bus's site-document store (agreed with the bus): GET with the host agent's own credential; 200 {"name", "serial", "body": base64, "signature": armored
    SSHSIG, "stored_at"}, 404 when nothing is published. The bus does not check the signature or parse the bytes, and
    its `serial` is only a hint: the signed bytes decide."""
    try:
        status, doc = bus.call("GET", BUS_PATH)
    except (OSError, ValueError):
        return Outcome("fetch-failed", detail="bus")
    if status == 404:
        return Outcome("fleet-missing", detail="bus")
    if status != 200 or not isinstance(doc, dict):
        return Outcome("fetch-failed", detail=f"bus {status}")
    body, sig = doc.get("body"), doc.get("signature")
    if doc.get("name") != "fleet" or not isinstance(body, str) or not isinstance(sig, str):
        return Outcome("fetch-failed", detail="bus reply shape")
    if len(body) > MAX_BYTES * 4 // 3 + 4 or len(sig) > 16384:
        return Outcome("fleet-invalid", detail="bus document too large")
    try:
        return base64.b64decode(body, validate=True), sig.encode("ascii")  # parse() refuses over MAX_BYTES
    except (ValueError, UnicodeEncodeError):
        return Outcome("fetch-failed", detail="bus reply encoding")


def pick(from_bus: Outcome, from_git: Outcome) -> Outcome:
    """For fleet_source "either": the repository was checked against whatever the bus gave, so its acceptance means a
    higher verified serial and wins; otherwise the answer that says most (_RANK; anything unlisted is a real problem)."""
    if from_git.status == "fleet-accepted":
        return from_git
    return min((from_bus, from_git), key=lambda o: _RANK.get(o.status, 1))


class FleetSync:
    """The mirror, the check and the last good copy (<state>\\fleet\\: fleet.toml, fleet.toml.sig, accepted.json)."""

    def __init__(self, mirror: Path, store: Path, remote: str, git_exe: str, ssh_keygen: str | None,
                 signers: Path, ref: str = "main"):
        self.mirror, self.store, self.remote = Path(mirror), Path(store), remote
        self.git_exe, self.ssh_keygen, self.signers, self.ref = git_exe, ssh_keygen, Path(signers), ref

    def _git(self, *args: str, timeout: float = 120) -> subprocess.CompletedProcess:
        return subprocess.run([self.git_exe, "--git-dir", str(self.mirror), *args], capture_output=True,
                              timeout=timeout, stdin=subprocess.DEVNULL)

    def _ensure(self) -> bool:
        if (self.mirror / "HEAD").exists():
            return True
        self.mirror.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run([self.git_exe, "init", "--bare", "-q", "--", str(self.mirror)], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=60)
        if r.returncode != 0:
            return False
        self._git("config", "remote.origin.url", self.remote)
        self._git("config", "remote.origin.fetch", f"+refs/heads/{self.ref}:refs/remotes/origin/{self.ref}")
        return True

    def _blob(self, commit: str, name: str) -> bytes | None:
        r = self._git("cat-file", "blob", f"{commit}:{name}")
        return r.stdout if r.returncode == 0 else None

    def verify(self, data: bytes, sig: bytes) -> signing.Verified:
        return signing.verify(data, sig, signing.NS_FLEET, self.signers, self.ssh_keygen, self.store / "tmp")

    def accepted(self) -> dict:
        try:
            rec = json.loads((self.store / "accepted.json").read_text(encoding="utf-8"))
            return rec if isinstance(rec, dict) else {}
        except (OSError, ValueError):
            return {}

    def load_last_good(self) -> Fleet | None:
        """The last accepted fleet, checked again (the copy sits in a folder the host's user can write)."""
        rec = self.accepted()
        try:
            data, sig = (self.store / FILE).read_bytes(), (self.store / SIG).read_bytes()
        except OSError:
            return None
        if not self.verify(data, sig).ok:
            return None
        try:
            fleet = parse(data, str(rec.get("commit", "")))
        except FleetError:
            return None
        if fleet.sha256 != rec.get("sha256") or fleet.serial != rec.get("serial"):
            return None
        return fleet

    def refresh(self, current: Fleet | None, bus=None, source: str = "git") -> Outcome:
        """Fetch and check the fleet from the fleet repository ("git"), the bus's site-document store ("bus"), or
        both ("either": the higher verified serial). Every copy goes through the same signature, parse and serial
        checks, so where it came from never decides whether it is trusted (docs/app-host-integration.md section 3)."""
        if source == "bus":
            return self.refresh_from_bus(current, bus)
        if source == "either":
            from_bus = self.refresh_from_bus(current, bus)
            held = from_bus.fleet if from_bus.status in ("fleet-accepted", "unchanged") else current
            return pick(from_bus, self.refresh_from_git(held))
        return self.refresh_from_git(current)

    def refresh_from_bus(self, current: Fleet | None, bus) -> Outcome:
        if bus is None:
            return Outcome("fetch-failed", detail="no bus connection")
        got = fetch_from_bus(bus)
        if isinstance(got, Outcome):
            return got
        data, sig = got
        return self.accept(data, lambda: sig, "", current)

    def fetch_mirror(self) -> bool:
        """Only fetch the repository mirror (release.toml is read from it), without touching the fleet."""
        if not self.remote:
            return False
        try:
            return self._ensure() and self._git("fetch", "-q", "--no-tags", "origin", timeout=180).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def refresh_from_git(self, current: Fleet | None) -> Outcome:
        if not self.remote:
            return Outcome("fetch-failed", detail="no fleet_repo")  # this site runs without a signed fleet
        try:
            if not self._ensure():
                return Outcome("fetch-failed", detail="init")
            if self._git("fetch", "-q", "--no-tags", "origin", timeout=180).returncode != 0:
                return Outcome("fetch-failed")
            r = self._git("rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{self.ref}^{{commit}}")
            commit = r.stdout.decode("ascii", "replace").strip()
            if r.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", commit):
                return Outcome("fetch-failed", detail="ref")
            data = self._blob(commit, FILE)
        except (OSError, subprocess.TimeoutExpired):
            return Outcome("fetch-failed")
        if data is None:
            return Outcome("fleet-missing", commit=commit)
        return self.accept(data, lambda: self._blob(commit, SIG), commit, current)

    def accept(self, data: bytes, get_sig, commit: str, current: Fleet | None) -> Outcome:
        """The checks every fetched copy goes through: unchanged, signed by a pinned key, valid, and a higher serial
        than any accepted before. get_sig is called only when the bytes changed."""
        sha = hashlib.sha256(data).hexdigest()
        if current is not None and sha == current.sha256:
            return Outcome("unchanged", current, commit=commit)
        sig = get_sig()
        if sig is None:
            return Outcome("fleet-unsigned", detail="no fleet.toml.sig", commit=commit)
        v = self.verify(data, sig)
        if not v.ok:
            # no-signers / no-ssh-keygen / ssh-keygen-failed are this host's problem, not the file's.
            status = {"sig-shape": "fleet-unsigned", "bad-signature": "fleet-bad-signature"}.get(
                v.reason, "fleet-cannot-verify")
            return Outcome(status, detail=v.reason, commit=commit)
        try:
            fleet = parse(data, commit)
        except FleetError as e:
            return Outcome(e.reason, detail=e.detail, commit=commit)
        last = max(int(self.accepted().get("serial", 0) or 0), current.serial if current else 0)
        if fleet.serial <= last:
            # Lower: an older signed file put back. Equal with different bytes: a serial used twice.
            return Outcome("fleet-old", detail=f"serial {fleet.serial}, last accepted {last}", commit=commit)
        self.store.mkdir(parents=True, exist_ok=True)
        (self.store / FILE).write_bytes(data)
        (self.store / SIG).write_bytes(sig)
        atomic_write_json(self.store / "accepted.json", {"serial": fleet.serial, "sha256": fleet.sha256,
                                                         "commit": commit, "signer": v.fingerprint,
                                                         "accepted_at": time.time()})
        return Outcome("fleet-accepted", fleet, detail=v.fingerprint, commit=commit)
