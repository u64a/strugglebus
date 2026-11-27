from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta

from strugglebus.bus_events import Event, StoredEvent, stored_fields
from strugglebus.errors import StorageError
from strugglebus.host_status import NotAHostError, TooSoonError
from strugglebus.store._common import _access_freeze_from_connection, _format_utc, _parse_utc
from strugglebus.store._hosts import _seconds_to_wait


def _insert(connection: sqlite3.Connection, event: Event, timestamp: str) -> bool:
    """Stores an event unless its id is already stored. Returns whether it was new."""
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO bus_events (
            event_id, received_at, reported_at, source, level, type, subject, fields
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.event_id, timestamp, event.reported_at, event.source, event.level, event.type,
            event.subject, stored_fields(event),
        ),
    )
    return cursor.rowcount == 1


def _keep_newest(connection: sqlite3.Connection, source: str, subject: str | None, most: int) -> None:
    """Removes the oldest events of a source, or of one subject in it, beyond the most it may hold."""
    if subject is None:
        connection.execute(
            """
            DELETE FROM bus_events WHERE source = ? AND seq <= COALESCE((
                SELECT seq FROM bus_events WHERE source = ? ORDER BY seq DESC LIMIT 1 OFFSET ?
            ), 0)
            """,
            (source, source, most),
        )
        return
    connection.execute(
        """
        DELETE FROM bus_events WHERE source = ? AND subject = ? AND seq <= COALESCE((
            SELECT seq FROM bus_events WHERE source = ? AND subject = ?
            ORDER BY seq DESC LIMIT 1 OFFSET ?
        ), 0)
        """,
        (source, subject, source, subject, most),
    )


def _stored(row: sqlite3.Row) -> StoredEvent:
    received_at = _parse_utc(row["received_at"])
    if received_at is None:
        raise StorageError("database contains an event without received_at")
    return StoredEvent(received_at, Event(
        event_id=row["event_id"], source=row["source"], level=row["level"], type=row["type"],
        subject=row["subject"], fields=json.loads(row["fields"]), reported_at=row["reported_at"],
    ))


class BusEventsMixin:
    def record_host_events(
        self, agent_id: str, events: list[Event], *, received_at: datetime, minimum_gap: timedelta,
        per_host: int, cap: int,
    ) -> int:
        """
        Stores a marked host's events and returns how many were new. An event whose id is already
        stored is passed over, so a batch sent again after a lost answer makes no duplicate.

        Works while agent access is frozen: what the hosts say happened is wanted most then.
        """
        timestamp = _format_utc(received_at)
        with self._transaction() as connection:
            mark = connection.execute(
                "SELECT last_events_at FROM host_agents WHERE agent_id = ?", (agent_id,),
            ).fetchone()
            if mark is None:
                raise NotAHostError("the caller is not marked as a host")
            wait = _seconds_to_wait(mark["last_events_at"], received_at, minimum_gap)
            if wait:
                raise TooSoonError(wait)
            new = sum(_insert(connection, event, timestamp) for event in events)
            for subject in {event.subject for event in events}:
                _keep_newest(connection, "host", subject, per_host)
            _keep_newest(connection, "host", None, cap)
            connection.execute(
                "UPDATE host_agents SET last_events_at = ? WHERE agent_id = ?",
                (received_at.strftime("%Y-%m-%dT%H:%M:%SZ"), agent_id),
            )
        return new

    def record_bus_event(self, event: Event, *, received_at: datetime, cap: int) -> bool:
        """Stores one of the bus's own events. Returns whether it was new."""
        with self._transaction() as connection:
            new = _insert(connection, event, _format_utc(received_at))
            _keep_newest(connection, event.source, None, cap)
        return new

    def recent_bus_events(self, sources: tuple[str, ...], limit: int) -> list[StoredEvent]:
        """The newest events of the sources named, newest first."""
        wanted = [source for source in ("host", "update", "security", "bus") if source in sources]
        with self._read_transaction() as connection:
            rows = connection.execute(
                """
                SELECT * FROM bus_events
                WHERE source IN (SELECT value FROM json_each(?))
                ORDER BY seq DESC LIMIT ?
                """,
                (json.dumps(wanted), limit),
            ).fetchall()
        return [_stored(row) for row in rows]

    def bus_events_after(self, seq: int, limit: int) -> list[tuple[int, StoredEvent]]:
        """Events stored after ``seq``, oldest first, for the audit feed."""
        with self._read_transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM bus_events WHERE seq > ? ORDER BY seq LIMIT ?", (seq, limit),
            ).fetchall()
        return [(int(row["seq"]), _stored(row)) for row in rows]

    def last_bus_event_seq(self) -> int:
        with self._read_transaction() as connection:
            return int(connection.execute("SELECT COALESCE(MAX(seq), 0) FROM bus_events").fetchone()[0])

    def remove_expired_bus_events(self, *, now: datetime, keep: timedelta, batch_size: int) -> int:
        """
        Removes one batch of events older than ``keep``. Nothing is removed while agent access is
        frozen: a freeze marks an incident, and its evidence must not age out underneath it.
        """
        with self._transaction() as connection:
            if _access_freeze_from_connection(connection).frozen:
                return 0
            rows = connection.execute(
                "SELECT seq FROM bus_events WHERE received_at < ? ORDER BY seq LIMIT ?",
                (_format_utc(now - keep), batch_size),
            ).fetchall()
            connection.executemany("DELETE FROM bus_events WHERE seq = ?", [(row["seq"],) for row in rows])
        return len(rows)
