"""The bus's stored event log: what happened, kept so it can still be found afterwards.

The short log a device reads is held in memory and shows what is happening now. A failed update
last night, or a host that crashed and recovered, has left it by morning. An event here is kept
for thirty days.

An event is a fixed type with a few checked fields. Nothing that is free text from a host or from
an upstream server is stored: a type, a version, a short code, a number. So the log can be shown
and searched without it ever carrying a token, a path or someone's message.

Sources:

- ``host``: what a worker host reports about itself (``POST /api/hosts/events``). These are the
  host's own claims and are shown to administrators only.
- ``update``: the bus's own updates: checked, found, prepared, applied, failed, rolled back.
- ``security``: a release or a request the bus refused on a security check.
- ``bus``: the bus starting and its database changing.

The host contract is ``worker-host/docs/app-host-integration.md`` section 1b, tested against the
files in ``contracts/host-events/``.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Protocol

from strugglebus.host_status import MAX_BYTES, RefusedError, parsed

#: How long an event is kept.
KEEP = timedelta(days=30)
#: A host sends events at most this often.
MINIMUM_GAP = timedelta(seconds=5)
MAX_EVENTS = 20
#: The most rows each source may hold. One noisy source cannot push out another's events.
CAPS = {"host": 5000, "update": 2000, "security": 5000, "bus": 1000}
#: And the most one host may hold of the host source's share.
PER_HOST = 500
#: Sources any enrolled device may read. The rest need the operator grant.
OPEN_SOURCES = ("update", "bus")
ALL_SOURCES = ("host", "update", "security", "bus")

_KINDS = {
    "version": re.compile(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}(?:\.[0-9]{1,3})?|manual"),
    "bus-version": re.compile(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})"),
    "code": re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*"),
    "type-name": re.compile(r"[A-Za-z_][A-Za-z0-9_.]*"),
}
_SHORT = 64
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_EVENT_KEYS = frozenset({"id", "type", "at"})

#: What each field of a host's event may hold.
HOST_FIELDS = {
    "version": "version", "previous": "version", "reason": "code", "code": "code", "step": "code",
    "error": "type-name", "exit_code": "int", "attempt": "int",
}
#: A host's event types: the fields each may carry, and the level the bus gives it. A host sends
#: no level; how much an event matters is the bus's judgement.
HOST_TYPES: dict[str, tuple[tuple[str, ...], str]] = {
    "update-found": (("version",), "info"),
    "update-applied": (("version", "previous"), "info"),
    "update-failed": (("version", "reason"), "error"),
    "update-rolled-back": (("version",), "error"),
    "update-missed": (("version",), "warning"),
    "release-source-unreachable": ((), "warning"),
    "release-redirect-refused": ((), "error"),
    "started": ((), "info"),
    "stopped": (("reason",), "info"),
    "restarted-after-crash": (("exit_code", "attempt"), "warning"),
    "fatal": (("error",), "error"),
    "bus-lost": ((), "warning"),
    "bus-back": ((), "info"),
    "openbao-lost": ((), "warning"),
    "openbao-back": ((), "info"),
    "leaf-renew-failed": ((), "error"),
    "task-refused": (("reason",), "warning"),
    "wip-save-failed": (("step",), "warning"),
    "copilot-update-failed": ((), "warning"),
    "pressure": ((), "warning"),
    "problem-raised": (("code",), "warning"),
    "problem-cleared": (("code",), "info"),
}

#: The bus's own event types, by source: the fields each may carry and its level. ``reason`` is
#: always one of the bus's own short codes, never an upstream message.
BUS_FIELDS = {"version": "bus-version", "previous": "bus-version", "reason": "code", "schema": "int"}
BUS_TYPES: dict[str, dict[str, tuple[tuple[str, ...], str]]] = {
    "update": {
        "update-check-failed": (("reason",), "warning"),
        "update-found": (("version",), "info"),
        "update-blocked": (("version", "reason"), "warning"),
        "update-prepared": (("version",), "info"),
        "update-prepare-failed": (("version", "reason"), "error"),
        "update-started": (("version", "previous"), "info"),
        "update-applied": (("version", "previous"), "info"),
        "update-failed": (("version", "previous", "reason"), "error"),
        "update-rolled-back": (("version", "previous", "reason"), "error"),
    },
    "security": {
        "release-signature-refused": (("version",), "error"),
        "release-files-refused": (("version", "reason"), "error"),
    },
    "bus": {
        "started": (("version", "schema"), "info"),
    },
}


def _value_fits(kind: str | None, value: object) -> bool:
    if kind == "int":
        return type(value) is int and -1_000_000 <= value <= 1_000_000
    pattern = _KINDS.get(kind or "")
    return pattern is not None and type(value) is str and len(value) <= _SHORT and bool(pattern.fullmatch(value))


def _matches(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _host_event_type(event: object) -> str | None:
    """The type of one of a host's events, when it is an object with a type the bus knows."""
    if type(event) is not dict:
        return None
    name = event.get("type")
    return name if type(name) is str and name in HOST_TYPES else None


def _stamp_fault(event: dict) -> str | None:
    """Why an event's id or time is refused, or None."""
    if not _matches(event.get("id"), _UUID):
        return "bad-id"
    return None if _matches(event.get("at"), _AT) else "bad-at"


def _host_event_fault(event: object) -> str | None:
    """Why one of a host's events is refused, or None."""
    name = _host_event_type(event)
    if name is None:
        return "unknown-type" if type(event) is dict else "bad-batch"
    extra = {key: value for key, value in event.items() if key not in _EVENT_KEYS}  # type: ignore[union-attr]
    if set(extra) - set(HOST_TYPES[name][0]):
        return "unknown-field"
    fault = _stamp_fault(event)  # type: ignore[arg-type]
    if fault is not None:
        return fault
    return None if all(_value_fits(HOST_FIELDS[key], value) for key, value in extra.items()) else "bad-value"


def _events_fault(events: object) -> str | None:
    """Why a batch's list of events is refused as a list, before any one event is looked at."""
    if type(events) is not list or not events:
        return "bad-batch"
    if len(events) > MAX_EVENTS:
        return "too-many-events"
    if len({event.get("id") for event in events if type(event) is dict}) != len(events):
        return "duplicate-id"
    return None


def host_batch_refusal(batch: object, caller_agent: str) -> str | None:
    """Why a host's batch of events is refused whole, or None to store it."""
    if type(batch) is not dict or set(batch) != {"v", "agent", "events"} or type(batch["v"]) is not int or batch["v"] != 1:
        return "bad-batch"
    if batch["agent"] != caller_agent:
        return "wrong-agent"
    fault = _events_fault(batch["events"])
    if fault is not None:
        return fault
    return next((fault for fault in map(_host_event_fault, batch["events"]) if fault is not None), None)


@dataclass(frozen=True)
class Event:
    """One event as it is stored."""

    event_id: str
    source: str
    level: str
    type: str
    subject: str
    fields: dict[str, Any]
    reported_at: str | None = None


@dataclass(frozen=True)
class StoredEvent:
    """One event as it is read back, with the time the bus received it."""

    received_at: datetime
    event: Event


def bus_event(source: str, type_name: str, subject: str = "", **fields: object) -> Event:
    """
    One of the bus's own events. An unknown type is a mistake in the bus and raises. A field
    that is missing, None or does not fit its kind is left out, so that a strange value from
    outside can never stop an event being recorded, nor be stored.
    """
    allowed, level = BUS_TYPES[source][type_name]
    kept = {
        name: fields[name] for name in allowed
        if fields.get(name) is not None and _value_fits(BUS_FIELDS[name], fields[name])
    }
    return Event(str(uuid.uuid4()), source, level, type_name, subject[:128], kept)


class _Store(Protocol):
    def record_host_events(
        self, agent_id: str, events: list[Event], *, received_at: datetime, minimum_gap: timedelta,
        per_host: int, cap: int,
    ) -> int: ...

    def record_bus_event(self, event: Event, *, received_at: datetime, cap: int) -> bool: ...

    def recent_bus_events(self, sources: tuple[str, ...], limit: int) -> list[StoredEvent]: ...


class BusEventLog:
    def __init__(self, store: _Store, *, clock: Callable[[], datetime]) -> None:
        self._store = store
        self._clock = clock

    def record_from_host(self, agent_id: str, agent_name: str, body: bytes) -> int:
        """Stores a host's batch of events and returns how many were new."""
        batch = parsed(body)
        reason = host_batch_refusal(batch, agent_name)
        if reason is not None:
            raise RefusedError(reason)
        events = [
            Event(
                event_id=item["id"], source="host", level=HOST_TYPES[item["type"]][1], type=item["type"],
                subject=agent_name, reported_at=item["at"],
                fields={name: value for name, value in item.items() if name not in _EVENT_KEYS},
            )
            for item in batch["events"]  # type: ignore[index]
        ]
        return self._store.record_host_events(
            agent_id, events, received_at=self._clock(), minimum_gap=MINIMUM_GAP,
            per_host=PER_HOST, cap=CAPS["host"],
        )

    def record(self, source: str, type_name: str, subject: str = "", **fields: object) -> bool:
        """Records one of the bus's own events. Returns whether it was stored."""
        event = bus_event(source, type_name, subject, **fields)
        return self._store.record_bus_event(event, received_at=self._clock(), cap=CAPS[source])

    def store(self, event: Event) -> bool:
        """Stores an event that already has its id. Returns whether it was new."""
        return self._store.record_bus_event(event, received_at=self._clock(), cap=CAPS[event.source])

    def recent(self, limit: int, *, admin: bool) -> list[StoredEvent]:
        """The newest events, newest first. Without the grant, only the sources any device may read."""
        return self._store.recent_bus_events(ALL_SOURCES if admin else OPEN_SOURCES, limit)


def detail(event: Event) -> str:
    """An event's fields as one short line, for a log row."""
    parts = [f"{name}={value}" for name, value in sorted(event.fields.items())]
    if event.reported_at is not None:
        # The reporter's own time, shown beside the bus's and never sorted by.
        parts.append(f"at={event.reported_at}")
    return " ".join(parts)


def stored_fields(event: Event) -> str:
    return json.dumps(event.fields, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


__all__ = [
    "ALL_SOURCES", "BUS_TYPES", "BusEventLog", "CAPS", "Event", "HOST_TYPES", "KEEP", "MAX_BYTES",
    "MINIMUM_GAP", "OPEN_SOURCES", "PER_HOST", "StoredEvent", "bus_event", "detail",
    "host_batch_refusal", "stored_fields",
]
