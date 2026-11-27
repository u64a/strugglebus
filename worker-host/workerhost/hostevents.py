"""Host events for the bus's event log (docs/app-host-integration.md section 1b).

A few of the host's own log lines also become an EVENT from a fixed list, queued on disk and sent to the bus
(`POST /api/hosts/events`) so the App's admin log can show what happened on a host. The local log files are
unchanged and stay the full record (Chris, 27 Nov 2026).

An event is never a log line: only a type from TYPES and a few fields of fixed kinds (a version, a code, a type name,
a small number). Never a message, path, repository or clone name, task id, task text or token. validate_batch() is
the check the bus makes, written here as the reference the contract vectors (contracts/host-events/) are made from.

Writing an event never raises: it runs inside the logger, which runs inside error handlers.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path

from .logs import HostLog

V = 1
MAX_EVENTS = 20         # per call (bus-dev, #humans 28850)
MAX_BYTES = 16 * 1024   # per call
QUEUE_MAX = 200         # kept on disk while the bus can't take them
QUEUE_FILE = "host-events.json"

# What each field may hold. A value that fits none is refused by the bus (400): it stores no free text from a host.
KINDS = {
    "version": re.compile(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}(?:\.[0-9]{1,3})?|manual"),
    "code": re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*"),
    "type-name": re.compile(r"[A-Za-z_][A-Za-z0-9_.]*"),
}
SHORT = 64
FIELDS = {"version": "version", "previous": "version", "reason": "code", "code": "code", "step": "code",
          "error": "type-name", "exit_code": "int", "attempt": "int"}

# type -> the fields it may carry (all optional). The order here is the contract's.
TYPES = {
    "update-found": ("version",),
    "update-applied": ("version", "previous"),
    "update-failed": ("version", "reason"),
    "update-rolled-back": ("version",),
    "update-missed": ("version",),
    "release-source-unreachable": (),
    "release-redirect-refused": (),
    "started": (),
    "stopped": ("reason",),
    "restarted-after-crash": ("exit_code", "attempt"),
    "fatal": ("error",),
    "bus-lost": (),
    "bus-back": (),
    "openbao-lost": (),
    "openbao-back": (),
    "leaf-renew-failed": (),
    "task-refused": ("reason",),
    "wip-save-failed": ("step",),
    "copilot-update-failed": (),
    "pressure": (),
    "problem-raised": ("code",),
    "problem-cleared": ("code",),
}
# Dropped last when the queue is full: what an operator most needs to see afterwards.
KEEP_LONGEST = frozenset({"update-failed", "update-rolled-back", "fatal", "restarted-after-crash",
                          "release-redirect-refused"})
EVENT_KEYS = {"id", "type", "at"}
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def value_ok(name: str, value) -> bool:
    kind = FIELDS.get(name)
    if kind == "int":
        return type(value) is int and -1_000_000 <= value <= 1_000_000
    pattern = KINDS.get(kind or "")
    return isinstance(value, str) and len(value) <= SHORT and pattern is not None and bool(pattern.fullmatch(value))


def make(etype: str, at: float | None = None, **fields) -> dict | None:
    """One event, or None when it doesn't fit the contract (an unknown type, or a value of the wrong kind is left out
    rather than sent: the bus would refuse the whole batch)."""
    if etype not in TYPES:
        return None
    event = {"id": str(uuid.uuid4()), "type": etype, "at": iso(time.time() if at is None else at)}
    for name in TYPES[etype]:
        if name in fields and fields[name] is not None and value_ok(name, fields[name]):
            event[name] = fields[name]
    return event


def event_problem(e) -> str | None:
    """Why one event is refused, or None."""
    if not isinstance(e, dict):
        return "not-an-object"
    if e.get("type") not in TYPES:
        return "unknown-type"
    allowed = EVENT_KEYS | set(TYPES[e["type"]])
    if set(e) - allowed:
        return "unknown-field"
    if not (isinstance(e.get("id"), str) and UUID_RE.fullmatch(e["id"])):
        return "bad-id"
    if not (isinstance(e.get("at"), str) and AT_RE.fullmatch(e["at"])):
        return "bad-at"
    if any(not value_ok(k, v) for k, v in e.items() if k not in EVENT_KEYS):
        return "bad-value"
    return None


def validate_batch(batch, caller_agent: str) -> str | None:
    """The bus's check of one POST body (the reference for contracts/host-events/): None to store it, else the
    reason it is refused whole (400)."""
    if not isinstance(batch, dict) or set(batch) != {"v", "agent", "events"} or batch.get("v") != V:
        return "bad-batch"
    if batch["agent"] != caller_agent:
        return "wrong-agent"
    events = batch["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        return "too-many-events" if isinstance(events, list) and events else "bad-batch"
    if len(json.dumps(batch, separators=(",", ":")).encode()) > MAX_BYTES:
        return "too-large"
    if len({e.get("id") for e in events if isinstance(e, dict)}) != len(events):
        return "duplicate-id"
    for e in events:
        problem = event_problem(e)
        if problem:
            return problem
    return None


def body(agent: str, events: list[dict]) -> dict:
    return {"v": V, "agent": agent, "events": events}


# --- the queue on disk -----------------------------------------------------------------------------------------

class Queue:
    """Events waiting for the bus, in state/host-events.json. The host process and its supervisor both add to it,
    never at once (the supervisor only between host runs). Bounded: when full, the oldest event not in KEEP_LONGEST
    goes first."""

    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / QUEUE_FILE

    def load(self) -> list[dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _save(self, events: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(events, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, self.path)

    def add(self, event: dict | None) -> None:
        if event is None:
            return
        try:
            events = self.load() + [event]
            while len(events) > QUEUE_MAX:
                drop = next((i for i, e in enumerate(events) if e.get("type") not in KEEP_LONGEST), 0)
                events.pop(drop)
            self._save(events)
        except Exception:  # noqa: BLE001 - an event must never turn into a host crash
            pass

    def first(self, agent: str) -> list[dict]:
        """The oldest events that fit one call (MAX_EVENTS, MAX_BYTES)."""
        out = []
        for e in self.load()[:MAX_EVENTS]:
            if len(json.dumps(body(agent, out + [e]), separators=(",", ":")).encode()) > MAX_BYTES:
                break
            out.append(e)
        return out

    def remove(self, ids: set[str]) -> None:
        try:
            self._save([e for e in self.load() if e.get("id") not in ids])
        except Exception:  # noqa: BLE001
            pass


# --- log lines -> events ---------------------------------------------------------------------------------------

class Tap:
    """Turns the host's and the supervisor's log lines into events (one table, below). Lines that repeat while a
    condition lasts (bus unreachable, a renewal failing, an update found) become ONE event per change."""

    def __init__(self, queue: Queue):
        self.queue = queue
        self.bus_lost = False
        self.leaf_failing = False
        self.found: set[str] = set()

    def on_log(self, name: str, fields: dict) -> None:
        try:
            event = self._event(name, fields)
        except Exception:  # noqa: BLE001 - never let an event break a log line
            event = None
        self.queue.add(event)

    def _event(self, name: str, f: dict) -> dict | None:
        simple = SIMPLE.get(name)
        if simple is not None:
            etype, keys = simple
            return make(etype, **{new: f.get(old) for new, old in keys.items()})
        handler = getattr(self, "_" + name.replace("-", "_"), None)
        return handler(f) if handler else None

    def _bus_unreachable(self, f):
        if self.bus_lost:
            return None
        self.bus_lost = True
        return make("bus-lost")

    _bus_error = _bus_unreachable

    def _bus_back(self, f):
        self.bus_lost = False
        return make("bus-back")

    def _leaf_renew_failed(self, f):
        if self.leaf_failing:
            return None
        self.leaf_failing = True
        return make("leaf-renew-failed")

    def _leaf_renewed(self, f):
        self.leaf_failing = False
        return None

    def _update_check(self, f):
        version = f.get("release")
        if str(f.get("newer")) != "True" or not version or version in self.found:
            return None
        self.found.add(version)
        return make("update-found", version=version)

    def _ghcp_update(self, f):
        return None if f.get("ok") else make("copilot-update-failed")

    def _supervisor_restart(self, f):
        if f.get("reason"):  # "updated" or "rolled-back": a planned restart, not a crash
            return None
        return make("restarted-after-crash", exit_code=f.get("exit_code"), attempt=f.get("attempt"))


# log line -> (event type, {event field: log field})
SIMPLE = {
    "update-applied": ("update-applied", {"version": "version", "previous": "previous"}),
    "update-failed": ("update-failed", {"version": "version", "reason": "reason"}),
    "update-missed": ("update-missed", {"version": "version"}),
    "supervisor-rollback": ("update-rolled-back", {"version": "version"}),
    "release-source-unreachable": ("release-source-unreachable", {}),
    "release-redirect-refused": ("release-redirect-refused", {}),
    "host-start": ("started", {}),
    "stopped": ("stopped", {"reason": "why"}),
    "fatal": ("fatal", {"error": "error"}),
    "openbao-unreachable": ("openbao-lost", {}),
    "openbao-reachable": ("openbao-back", {}),
    "task-refused": ("task-refused", {"reason": "reason"}),
    "wip-failed": ("wip-save-failed", {"step": "step"}),
    "wip-push-failed": ("wip-save-failed", {}),
    "pressure": ("pressure", {}),
    "problem-raised": ("problem-raised", {"code": "code"}),
    "problem-cleared": ("problem-cleared", {"code": "code"}),
}


class EventLog(HostLog):
    """The host log, plus events for the lines in the table above. The line is always written first."""

    def __init__(self, folder: Path, state_dir: Path, echo: bool = False):
        super().__init__(folder, echo=echo)
        self.events = Queue(state_dir)
        self.tap = Tap(self.events)

    def __call__(self, event: str, **fields) -> None:
        super().__call__(event, **fields)
        self.tap.on_log(event, fields)
