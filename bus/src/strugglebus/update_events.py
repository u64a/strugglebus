"""Puts the bus's own updates into the stored event log.

The bus does not update itself. A root maintenance service does (an Ansible install), or a root
updater outside the service (a self-hosted install), and each keeps a small record of its last
attempt that the bus may read. This module reads that record once a minute and writes what it
shows as events, so that last night's failed update can still be found in the morning.

An attempt's events are given ids worked out from the attempt itself. Reading the same record
again therefore stores nothing new: the log refuses an id it already holds.

The bus is stopped while it is being replaced, so it cannot record an update as it happens. It
records it when it next reads the record, which is within a minute of starting again. The time
on such an event is when the bus learned of it.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, Callable

from strugglebus.bus_events import KEEP, BusEventLog, Event, bus_event
from strugglebus.maintenance_types import MaintenanceAttempt, MaintenanceError, MaintenanceStatus
from strugglebus.selfhost_updates import LastCheck

POLL_SECONDS = 60
_NAMESPACE = uuid.UUID("5d0f6a52-6f0b-4f6e-9a55-7b1d1f2c8e31")
#: What a self-hosted updater's result means as an event: the type, and the reason if it has one.
_SELFHOST = {
    "updated": ("update-applied", None),
    "unreachable": ("update-check-failed", "source-unreachable"),
    "invalid": ("update-blocked", "release-refused"),
    "failed": ("update-failed", "install-failed"),
}


def _named(event: Event, *parts: object) -> Event:
    """The event with an id worked out from what it records, so the same record gives the same id."""
    return replace(event, event_id=str(uuid.uuid5(_NAMESPACE, ":".join(str(part) for part in parts))))


def _too_old(moment: int | float, now: datetime) -> bool:
    """Whether something happened longer ago than events are kept. It would only be removed again."""
    return now.timestamp() - moment > KEEP.total_seconds()


def _reason(code: str | None) -> str | None:
    """A maintenance error code as an event's reason: the bus's own word, with hyphens."""
    return None if code is None else code.replace("_", "-")


def attempt_events(status: MaintenanceStatus, now: datetime) -> list[Event]:
    """The events an Ansible install's last maintenance attempt amounts to."""
    attempt = status.attempt
    if attempt is None or _too_old(attempt.finished_at or attempt.started_at, now):
        return []
    version = attempt.candidate_version
    events = []
    if version is not None:
        # Once it has been applied, the version running is the new one and the old is not known.
        previous = status.current_version if status.current_version != version else None
        started = bus_event("update", "update-started", version, version=version, previous=previous)
        events.append(_named(started, attempt.operation_id, "started"))
    events += _finished(attempt, version)
    return events


def _finished(attempt: MaintenanceAttempt, version: str | None) -> list[Event]:
    """How an attempt ended, if it has."""
    if attempt.phase == "succeeded" and version is not None:
        applied = bus_event("update", "update-applied", version, version=version)
        return [_named(applied, attempt.operation_id, "applied")]
    if attempt.phase != "failed":
        # Still going, or it looked and found nothing newer: nothing to record.
        return []
    reason = _reason(attempt.error)
    if version is None:
        failed = bus_event("update", "update-check-failed", reason=reason)
    else:
        failed = bus_event("update", "update-failed", version, version=version, reason=reason)
    return [_named(failed, attempt.operation_id, "failed")]


def selfhost_events(check: LastCheck | None, now: datetime) -> list[Event]:
    """The event a self-hosted updater's last report amounts to, if any."""
    if check is None or check.result not in _SELFHOST or _too_old(check.checked_at.timestamp(), now):
        return []
    type_name, reason = _SELFHOST[check.result]
    version = check.latest_version
    event = bus_event("update", type_name, version, version=version or None, reason=reason)
    return [_named(event, "selfhost", int(check.checked_at.timestamp()), check.result)]


class UpdateEventRecorder:
    def __init__(
        self, log: BusEventLog, updater: Callable[[], Any], *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._log = log
        self._updater = updater
        self._clock = clock
        self._seen: set[str] = set()

    async def _maintenance(self, console: Any, now: datetime) -> list[Event]:
        if console.maintenance is None:
            return []
        try:
            return attempt_events(await console.maintenance.status(), now)
        except MaintenanceError:
            # The maintenance service is away, as it is on any install without one. Not an event.
            return []

    async def poll_once(self) -> int:
        """Reads both records and stores what is new. Returns how many events were stored."""
        console = self._updater()
        if console is None:
            return 0
        now = self._clock()
        events = await self._maintenance(console, now)
        events += selfhost_events(await asyncio.to_thread(console.selfhost.last_check), now)
        stored = 0
        for event in events:
            if event.event_id not in self._seen:
                stored += await asyncio.to_thread(self._log.store, event)
                self._seen.add(event.event_id)
        return stored

    async def run(self) -> None:
        while True:
            try:
                await self.poll_once()
            except Exception:
                # Recording is a help to the operator. It must never stop the bus or fill its log.
                print("strugglebus update events: could not record; retrying", file=sys.stderr, flush=True)
            await asyncio.sleep(POLL_SECONDS)
