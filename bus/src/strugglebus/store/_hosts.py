from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from strugglebus.errors import AgentNotFoundError, CredentialConflictError
from strugglebus.host_status import NotAHostError, TooSoonError
from strugglebus.models import LifecycleActor
from strugglebus.store._common import (
    _audit_text,
    _canonical_request_id,
    _format_utc,
    _parse_utc,
    _validate_actor,
)

#: Who marked a host when its own enrolment did. Not a person: the bus, following a rule.
ENROLMENT_ACTOR = "host-enrolment"
ENROLMENT_REASON = "registered by the service principal of its host enrolment"


def _record_mark(
    connection: sqlite3.Connection, *, agent_id: str, agent_name: str, action: str,
    actor_type: str, actor_id: str, reason: str, request_id: str | None, timestamp: str,
) -> None:
    connection.execute(
        """
        INSERT INTO host_agent_audit (
            agent_id, agent_name, action, actor_type, actor_id, reason, request_id, occurred_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (agent_id, agent_name, action, actor_type, actor_id, reason, request_id, timestamp),
    )


def mark_enrolled_host(
    connection: sqlite3.Connection, *, agent_id: str, agent_name: str, spn_id: str, timestamp: str,
) -> bool:
    """
    Marks a newly registered agent as a host when it is the host agent of a host enrolment.

    It is one only if the service principal that registered it was made by redeeming a host
    enrolment code, and its name is that enrolment's prefix followed by ``-host``. The workers
    the same principal registers have other names and are not hosts. A name that merely looks
    like a host's never counts: without the enrolment behind it, nothing is marked.
    """
    enrolment = connection.execute(
        "SELECT id, host_prefix FROM host_enrollments WHERE spn_id = ? AND status = 'redeemed'",
        (spn_id,),
    ).fetchone()
    if enrolment is None or agent_name != f"{enrolment['host_prefix']}-host":
        return False
    connection.execute(
        "INSERT INTO host_agents (agent_id, marked_at, marked_by) VALUES (?, ?, 'enrolment')",
        (agent_id, timestamp),
    )
    _record_mark(
        connection, agent_id=agent_id, agent_name=agent_name, action="marked",
        actor_type=ENROLMENT_ACTOR, actor_id=f"host-enrolment:{enrolment['id']}",
        reason=ENROLMENT_REASON, request_id=None, timestamp=timestamp,
    )
    return True


def _stamp(moment: datetime) -> str:
    """A report's time as the bus gives it out: UTC, to the second."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seconds_to_wait(last: str | None, now: datetime, minimum_gap: timedelta) -> int:
    """How long a host must still wait before it may report again; nought when it may now."""
    previous = _parse_utc(last)
    if previous is None:
        return 0
    remaining = (previous + minimum_gap - now).total_seconds()
    # A clock set back must not shut a host out for longer than one gap.
    return 0 if remaining <= 0 else min(int(remaining) + 1, int(minimum_gap.total_seconds()))


class HostsMixin:
    def is_host(self, agent_id: str) -> bool:
        with self._read_transaction() as connection:
            row = connection.execute(
                "SELECT 1 FROM host_agents WHERE agent_id = ?", (agent_id,),
            ).fetchone()
        return row is not None

    def record_host_status(
        self, agent_id: str, *, snapshot: str, sample: str, received_at: datetime,
        minimum_gap: timedelta, keep: timedelta,
    ) -> None:
        """
        Keeps a host's report: the snapshot in place of its last one, and a sample beside the
        earlier ones. Samples of this host older than ``keep`` are removed in the same step, so
        the history never holds more than it should.

        This works while agent access is frozen. A report gives a host no authority, and what
        the hosts are doing is something an operator wants to see during an incident.
        """
        timestamp = _stamp(received_at)
        with self._transaction() as connection:
            mark = connection.execute(
                "SELECT last_status_at FROM host_agents WHERE agent_id = ?", (agent_id,),
            ).fetchone()
            if mark is None:
                raise NotAHostError("the caller is not marked as a host")
            wait = _seconds_to_wait(mark["last_status_at"], received_at, minimum_gap)
            if wait:
                raise TooSoonError(wait)
            connection.execute(
                """
                INSERT INTO host_status (agent_id, received_at, snapshot) VALUES (?, ?, ?)
                ON CONFLICT (agent_id) DO UPDATE
                SET received_at = excluded.received_at, snapshot = excluded.snapshot
                """,
                (agent_id, timestamp, snapshot),
            )
            connection.execute(
                "INSERT INTO host_status_samples (agent_id, received_at, sample) VALUES (?, ?, ?)",
                (agent_id, timestamp, sample),
            )
            connection.execute(
                "DELETE FROM host_status_samples WHERE agent_id = ? AND received_at < ?",
                (agent_id, _stamp(received_at - keep)),
            )
            connection.execute(
                "UPDATE host_agents SET last_status_at = ? WHERE agent_id = ?",
                (timestamp, agent_id),
            )

    def host_statuses(self) -> list[tuple[str, str, str, str | None, str | None]]:
        """Every marked host, by name: its id, name, when it was marked, and its latest report."""
        with self._read_transaction() as connection:
            rows = connection.execute(
                """
                SELECT h.agent_id, a.name, h.marked_at, s.received_at, s.snapshot
                FROM host_agents h
                JOIN agents a ON a.id = h.agent_id
                LEFT JOIN host_status s ON s.agent_id = h.agent_id
                ORDER BY a.name
                """,
            ).fetchall()
        return [tuple(row) for row in rows]

    def host_status_samples(self, agent_id: str, *, since: datetime, limit: int) -> list[str] | None:
        """A marked host's samples from ``since``, oldest first; None for anything else."""
        with self._read_transaction() as connection:
            marked = connection.execute(
                "SELECT 1 FROM host_agents WHERE agent_id = ?", (agent_id,),
            ).fetchone()
            if marked is None:
                return None
            rows = connection.execute(
                """
                SELECT sample FROM (
                    SELECT seq, sample FROM host_status_samples
                    WHERE agent_id = ? AND received_at >= ?
                    ORDER BY seq DESC LIMIT ?
                ) ORDER BY seq
                """,
                (agent_id, _stamp(since), limit),
            ).fetchall()
        return [row["sample"] for row in rows]

    def remove_expired_host_status_samples(self, *, now: datetime, keep: timedelta, batch_size: int) -> int:
        """Removes samples older than ``keep``, for hosts that have stopped reporting."""
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT seq FROM host_status_samples WHERE received_at < ? ORDER BY seq LIMIT ?",
                (_stamp(now - keep), batch_size),
            ).fetchall()
            connection.executemany(
                "DELETE FROM host_status_samples WHERE seq = ?", [(row["seq"],) for row in rows],
            )
        return len(rows)

    def set_host_mark(
        self, agent_id: str, *, marked: bool, expected_name: str, reason: str, request_id: str,
        actor: LifecycleActor, changed_at: datetime,
    ) -> tuple[str, bool]:
        """
        Marks an agent as a host, or takes the mark away. Returns its name and whether anything
        changed: asking for what is already so, or repeating a request, changes nothing.

        Taking the mark away also removes the host's stored status and samples, so a machine
        that is no longer a host stops appearing as one. The record of both actions is kept.
        """
        _canonical_request_id(request_id)
        _audit_text(reason)
        _validate_actor(actor)
        timestamp = _format_utc(changed_at)
        with self._transaction() as connection:
            _validate_actor(actor)
            agent = connection.execute(
                "SELECT name FROM agents WHERE id = ?", (agent_id,),
            ).fetchone()
            if agent is None:
                raise AgentNotFoundError("agent not found")
            if agent["name"] != expected_name:
                raise CredentialConflictError("the agent is not the one that was listed")
            repeated = connection.execute(
                "SELECT 1 FROM host_agent_audit WHERE request_id = ?", (request_id,),
            ).fetchone()
            current = connection.execute(
                "SELECT 1 FROM host_agents WHERE agent_id = ?", (agent_id,),
            ).fetchone()
            if repeated is not None or (current is not None) == marked:
                return agent["name"], False
            if marked:
                connection.execute(
                    "INSERT INTO host_agents (agent_id, marked_at, marked_by) VALUES (?, ?, 'admin')",
                    (agent_id, timestamp),
                )
            else:
                connection.execute("DELETE FROM host_status_samples WHERE agent_id = ?", (agent_id,))
                connection.execute("DELETE FROM host_status WHERE agent_id = ?", (agent_id,))
                connection.execute("DELETE FROM host_agents WHERE agent_id = ?", (agent_id,))
            _record_mark(
                connection, agent_id=agent_id, agent_name=agent["name"],
                action="marked" if marked else "unmarked", actor_type=actor.actor_type,
                actor_id=actor.actor_id, reason=reason, request_id=request_id, timestamp=timestamp,
            )
        return agent["name"], True
