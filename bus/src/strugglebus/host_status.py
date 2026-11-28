"""What a worker host reports about itself, for the App's Hosts page.

A host posts a snapshot of what it is doing. The bus checks its shape, keeps the latest one whole
and a small sample of each for twelve hours, and stamps its own time on both. Whose snapshot it is
comes from the authenticated agent, never from the snapshot.

The contract is ``worker-host/docs/app-host-integration.md`` section 1a, and the files in
``contracts/host-status/`` are what both sides are tested against.

A snapshot is the host's own claim about itself. It is shown, never acted on.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Protocol

from strugglebus.errors import DomainValidationError

MAX_BYTES = 16 * 1024
#: A host reports at most this often. A report sooner than this is refused, to be sent again later.
MINIMUM_GAP = timedelta(seconds=10)
#: How long a sample of each report is kept.
HISTORY = timedelta(hours=12)
#: The most samples one history answer holds: twelve hours at the fastest a host may report.
MAX_SAMPLES = 4320

STATES = ("online", "paused", "draining", "needs-sign-in", "needs-fleet", "updating", "error")
TASK_OUTCOMES = ("finished", "failed", "timed-out", "interrupted", "refused", "yielded", "cancelled")
MACHINE = ("cpu_pct", "ram_free_gb", "disk_free_gb", "commit_pct")
#: Returned only with the operator grant. The account and its weaknesses map the weakest machine,
#: and a host's channel may be private.
ADMIN_ONLY = (
    ("account",), ("dedicated",), ("warnings",), ("bus", "channel"), ("bus", "channel_state"),
    # Which keys a host trusts, and anything about signing it in, are for the operator alone.
    ("signers",), ("signers_total",), ("sign_in",), ("sign_in_key",), ("claude_token_since",),
)

_COUNT = ("int", 0, 2_000_000_000)


def _text(longest: int) -> tuple[str, int]:
    return ("str", longest)


def _maybe(spec: object) -> tuple[str, object]:
    return ("maybe", spec)


def _later(spec: object) -> tuple[str, object]:
    """
    A field added after v2 was first agreed. A host that does not send it yet is still accepted,
    so a host and its bus need not be updated at the same moment. When it is sent it is checked
    like any other field. A field the bus has never heard of is still refused.
    """
    return ("later", spec)


def _match(pattern: str) -> tuple[str, re.Pattern[str]]:
    """Text that is exactly this pattern, start to end."""
    return ("match", re.compile(pattern))


_FINGERPRINT = r"SHA256:[A-Za-z0-9+/]{43}"

#: The shape of a v2 snapshot. An object is a dict of exactly these keys: one more or one fewer is
#: refused, so nothing a snapshot must never carry (a task id, a path, message text) can ride in on
#: a field the bus does not know.
SNAPSHOT: dict[str, object] = {
    "v": ("const", 2),
    "host": _text(31),
    "agent": _text(64),
    "version": _text(32),
    "serial": _COUNT,
    "started_at": _text(32),
    "interval_s": _COUNT,
    "state": ("one-of", STATES),
    "account": _text(128),
    "dedicated": "bool",
    "engines": ("list", {
        "name": _maybe(_text(32)), "version": _maybe(_text(32)),
        "signed_in": _maybe("bool"), "default": _maybe("bool"),
    }, 8),
    "workers": {
        "busy": _COUNT, "max": _COUNT, "claiming": _COUNT,
        "running": ("list", {"slot": _text(32), "engine": _text(32), "model": _text(64), "minutes": _COUNT}, 64),
    },
    "held_clones": _COUNT,
    "outbox": _COUNT,
    "fleet": {
        "source": _maybe(_text(32)), "serial": _maybe(_COUNT),
        "coordinators": _maybe(("list", _text(64), 32)), "state": _maybe(_text(32)),
    },
    "update": _maybe({"version": _maybe(_text(32)), "when": _maybe(_text(32))}),
    "release": {"source": _maybe(_text(256)), "serial": _maybe(_COUNT)},
    "last_command": _maybe({
        "nonce": _maybe(_text(128)), "verb": _maybe(_text(32)),
        "result": _maybe(_text(32)), "reason": _maybe(_text(64)),
    }),
    "problem": _maybe({"code": _text(64), "text": _text(256)}),
    "warnings": ("list", _text(32), 8),
    "machine": {name: _maybe("number") for name in MACHINE},
    "bus": {
        "state": ("one-of", ("ok", "down", "unknown")),
        "channel": _maybe(_text(64)),
        "channel_state": ("one-of", ("ok", "missing", "unknown")),
    },
    "model": _maybe(_text(64)),
    "ghcp_ok": _maybe("bool"),
    # The version of PowerShell 7 the host runs its workers with. Hosts get it from a pinned
    # archive that an inventory agent cannot see, so the status is where its version is shown.
    "pwsh": _later(_maybe(_text(32))),
    "tasks": {name: _COUNT for name in TASK_OUTCOMES},
    # The signer keys this host pins, so the App can warn when its own set and a host's differ.
    # Only each key's fingerprint, type and namespaces: never the key or its name. The list is
    # capped and a line the host could not read is left out, so the count of every line the
    # host's file holds goes beside it.
    "signers": _later(("list", {
        "fingerprint": _match(_FINGERPRINT),
        "key_type": _match(r"[a-z0-9@.-]{1,48}"),
        "namespaces": _match(r"[a-z0-9-]{0,64}(?:,[a-z0-9-]{1,64}){0,7}"),
    }, 16)),
    "signers_total": _later(("int", 0, 1000)),
    # Signing a host's tools in from the App. Absent unless a sign-in was asked for. A code is
    # the short code a person types at the tool's own website; it is useless once used or expired.
    "sign_in": _later({
        "nonce": _text(64),
        "tool": _text(32),
        "state": ("one-of", ("starting", "code", "done", "failed")),
        "code": _later(_match(r"[A-Z0-9]{4}-[A-Z0-9]{4}")),
        "expires_at": _later(_text(40)),
        "reason": _later(_maybe(_text(200))),
    }),
    # The host's public key for a token sealed to it, and the day a sealed token arrived.
    "sign_in_key": _later({"x25519": _match(r"[A-Za-z0-9+/]{43}="), "fingerprint": _match(_FINGERPRINT)}),
    "claude_token_since": _later(_match(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")),
}


def _is_number(value: object) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and abs(value) <= 1_000_000_000


_CHECKS: dict[str, Callable[..., bool]] = {
    "const": lambda value, expected: type(value) is type(expected) and value == expected,
    "str": lambda value, longest: type(value) is str and len(value) <= longest,
    "int": lambda value, lowest, highest: type(value) is int and lowest <= value <= highest,
    "one-of": lambda value, allowed: type(value) is str and value in allowed,
    "match": lambda value, pattern: type(value) is str and pattern.fullmatch(value) is not None,
}


def _fits_scalar(value: object, spec: object) -> bool:
    """Whether a value fits a spec that is not an object, a list or optional."""
    if spec == "bool":
        return type(value) is bool
    if spec == "number":
        return _is_number(value)
    kind, *rest = spec  # type: ignore[misc]
    return _CHECKS[kind](value, *rest)


def _fault_in_keys(value: dict, spec: dict[str, object], path: str) -> str | None:
    """Why an object's set of keys is wrong. Names the place, never an unknown key: that is the sender's text."""
    unknown = bool(set(value) - set(spec))
    needed = {name for name, inner in spec.items() if not _is_later(inner)}
    if not unknown and not needed - set(value):
        return None
    kind = "unknown-field" if unknown else "missing-field"
    return f"{kind}:{path}" if path else kind


def _fault_in_object(value: object, spec: dict[str, object], path: str) -> str | None:
    if type(value) is not dict:
        return f"bad-value:{path}" if path else "bad-snapshot"
    fault = _fault_in_keys(value, spec, path)
    if fault is not None:
        return fault
    for name in spec.keys() & value.keys():
        inner = spec[name][1] if _is_later(spec[name]) else spec[name]  # type: ignore[index]
        fault = fault_in(value[name], inner, f"{path}.{name}" if path else name)
        if fault is not None:
            return fault
    return None


def _is_later(spec: object) -> bool:
    return isinstance(spec, tuple) and spec[0] == "later"


def _fault_in_list(value: object, spec: tuple, path: str) -> str | None:
    _, inner, longest = spec
    if type(value) is not list or len(value) > longest:
        return f"bad-value:{path}"
    for item in value:
        fault = fault_in(item, inner, path)
        if fault is not None:
            return fault
    return None


def fault_in(value: object, spec: object, path: str = "") -> str | None:
    """
    Why a value does not fit a spec, or None when it does. The reason names the place in the
    bus's own words and never repeats anything the sender wrote.
    """
    if isinstance(spec, dict):
        return _fault_in_object(value, spec, path)
    if spec[0] == "maybe":  # type: ignore[index]
        return None if value is None else fault_in(value, spec[1], path)  # type: ignore[index]
    if spec[0] == "list":  # type: ignore[index]
        return _fault_in_list(value, spec, path)  # type: ignore[arg-type]
    return None if _fits_scalar(value, spec) else f"bad-value:{path}"


def refusal(snapshot: object, caller_agent: str) -> str | None:
    """Why a host's snapshot is refused, or None to store it."""
    fault = fault_in(snapshot, SNAPSHOT)
    if fault is not None:
        return fault
    # The name in the snapshot is only shown, but one that names another host would mislead.
    return None if snapshot["agent"] == caller_agent else "wrong-agent"  # type: ignore[index]


def for_device(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The snapshot as a device without the operator grant gets it."""
    shown = json.loads(json.dumps(snapshot))
    for *parents, last in ADMIN_ONLY:
        holder = shown
        for name in parents:
            holder = holder.get(name) or {}
        holder.pop(last, None)
    return shown


def sample(snapshot: dict[str, Any], received_at: str) -> dict[str, Any]:
    """One point of a host's history: only the figures a chart needs."""
    return {
        "received_at": received_at,
        "state": snapshot["state"],
        "workers": {"busy": snapshot["workers"]["busy"], "max": snapshot["workers"]["max"]},
        "machine": dict(snapshot["machine"]),
        "outbox": snapshot["outbox"],
        "held_clones": snapshot["held_clones"],
        "tasks": dict(snapshot["tasks"]),
    }


class NotAHostError(DomainValidationError):
    """The caller is not marked as a host, so it may not report as one."""


class TooSoonError(DomainValidationError):
    """The host reported too soon after its last report."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("report again later")
        self.retry_after = retry_after


class RefusedError(DomainValidationError):
    """The report does not fit the contract. ``reason`` is the bus's own fixed words."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class TooLargeError(DomainValidationError):
    """The report is larger than a report may be."""


@dataclass(frozen=True)
class HostStatus:
    """A host as the bus knows it: its mark, and its latest snapshot if it has reported."""

    agent_id: str
    agent: str
    marked_at: str
    received_at: str | None
    snapshot: dict[str, Any] | None


class _Store(Protocol):
    def record_host_status(
        self, agent_id: str, *, snapshot: str, sample: str, received_at: datetime,
        minimum_gap: timedelta, keep: timedelta,
    ) -> None: ...

    def host_statuses(self) -> list[tuple[str, str, str, str | None, str | None]]: ...

    def host_status_samples(self, agent_id: str, *, since: datetime, limit: int) -> list[str] | None: ...


def parsed(body: bytes) -> object:
    """A report's JSON. One that is too large, or is not JSON, is refused before anything reads it."""
    if len(body) > MAX_BYTES:
        raise TooLargeError("report is too large")
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        raise RefusedError("bad-json") from None


class HostStatusService:
    def __init__(self, store: _Store, *, clock: Callable[[], datetime]) -> None:
        self._store = store
        self._clock = clock

    def record(self, agent_id: str, agent_name: str, body: bytes) -> str:
        """Stores a host's report and returns the time the bus stamped on it."""
        snapshot = parsed(body)
        reason = refusal(snapshot, agent_name)
        if reason is not None:
            raise RefusedError(reason)
        now = self._clock()
        received_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        compact = {"ensure_ascii": True, "separators": (",", ":")}
        self._store.record_host_status(
            agent_id,
            snapshot=json.dumps(snapshot, **compact),
            sample=json.dumps(sample(snapshot, received_at), **compact),  # type: ignore[arg-type]
            received_at=now,
            minimum_gap=MINIMUM_GAP,
            keep=HISTORY,
        )
        return received_at

    def now(self) -> str:
        """The bus's own time, so a reader works out how old a report is without its own clock."""
        return self._clock().strftime("%Y-%m-%dT%H:%M:%SZ")

    def latest(self, *, admin: bool) -> list[HostStatus]:
        """Every marked host with its latest snapshot, filtered unless the reader is an admin."""
        hosts = []
        for agent_id, agent, marked_at, received_at, stored in self._store.host_statuses():
            snapshot = None if stored is None else json.loads(stored)
            if snapshot is not None and not admin:
                snapshot = for_device(snapshot)
            hosts.append(HostStatus(agent_id, agent, marked_at, received_at, snapshot))
        return hosts

    def history(self, agent_id: str, since: datetime | None) -> list[dict[str, Any]] | None:
        """A host's samples from ``since``, oldest first, or None if it is not a marked host."""
        earliest = self._clock() - HISTORY
        start = earliest if since is None or since < earliest else since
        stored = self._store.host_status_samples(agent_id, since=start, limit=MAX_SAMPLES)
        return None if stored is None else [json.loads(item) for item in stored]
