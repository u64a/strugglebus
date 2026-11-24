"""Retention: remove old messages and block agents that have gone silent."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from strugglebus.errors import DomainValidationError
from strugglebus.store._common import (
    SYSTEM_AUTHOR_IDS,
    _access_freeze_from_connection,
    _audit_text,
    _checked_transition_agent,
    _format_utc,
    _invalidate_reconnect_grants,
    _lifecycle_input_hash,
    _parse_utc,
    _record_lifecycle_event,
)

MINIMUM_DAYS = 7
MAXIMUM_DAYS = 3650
RETENTION_ACTOR_ID = "system:retention"


@dataclass(frozen=True, slots=True)
class RetentionSettings:
    """``None`` for a period means keep forever / never block."""

    message_days: int | None
    idle_agent_days: int | None
    changed_at: datetime | None
    changed_by: str
    last_run_at: datetime | None
    last_removed_messages: int
    last_blocked_agents: int
    total_removed_messages: int
    total_blocked_agents: int


@dataclass(frozen=True, slots=True)
class RetentionOverview:
    stored_messages: int
    oldest_message_at: datetime | None
    enabled_agents: int


def _period(value: int | None) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not MINIMUM_DAYS <= value <= MAXIMUM_DAYS:
        raise DomainValidationError(
            f"a retention period is {MINIMUM_DAYS} to {MAXIMUM_DAYS} days, or empty for no limit"
        )
    return value


def _settings(connection) -> RetentionSettings:
    row = connection.execute(
        "SELECT * FROM retention_settings WHERE singleton = 1"
    ).fetchone()
    return RetentionSettings(
        message_days=row["message_days"],
        idle_agent_days=row["idle_agent_days"],
        changed_at=_parse_utc(row["changed_at"]),
        changed_by=row["changed_by"],
        last_run_at=_parse_utc(row["last_run_at"]),
        last_removed_messages=row["last_removed_messages"],
        last_blocked_agents=row["last_blocked_agents"],
        total_removed_messages=row["total_removed_messages"],
        total_blocked_agents=row["total_blocked_agents"],
    )


class RetentionMixin:
    def get_retention(self) -> RetentionSettings:
        with self._read_transaction() as connection:
            return _settings(connection)

    def retention_overview(self) -> RetentionOverview:
        with self._read_transaction() as connection:
            count = connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            oldest = connection.execute(
                "SELECT created_at FROM messages ORDER BY seq LIMIT 1"
            ).fetchone()
            agents = connection.execute(
                "SELECT COUNT(*) FROM agents WHERE revoked_at IS NULL "
                "AND blocked_at IS NULL AND id NOT IN (?, ?)",
                SYSTEM_AUTHOR_IDS,
            ).fetchone()[0]
        return RetentionOverview(
            int(count), None if oldest is None else _parse_utc(oldest[0]), int(agents),
        )

    def set_retention(
        self, *, message_days: int | None, idle_agent_days: int | None,
        changed_by: str, changed_at: datetime,
    ) -> RetentionSettings:
        _period(message_days)
        _period(idle_agent_days)
        _audit_text(changed_by)
        with self._transaction() as connection:
            connection.execute(
                "UPDATE retention_settings SET message_days = ?, idle_agent_days = ?, "
                "changed_at = ?, changed_by = ? WHERE singleton = 1",
                (message_days, idle_agent_days, _format_utc(changed_at), changed_by),
            )
            return _settings(connection)

    def remove_expired_messages(self, *, now: datetime, batch_size: int = 500) -> int:
        """Delete one batch of the oldest messages past the period.

        Returns how many were removed; call again while it returns a full
        batch. Nothing is removed while agent access is frozen: a freeze marks
        an incident, and its evidence must not age out underneath it.
        """

        if type(batch_size) is not int or not 1 <= batch_size <= 5000:
            raise DomainValidationError("invalid retention batch size")
        with self._transaction() as connection:
            days = _settings(connection).message_days
            if days is None or _access_freeze_from_connection(connection).frozen:
                return 0
            cutoff = _format_utc(now - timedelta(days=days))
            expired: list[tuple[int]] = []
            # seq order is age order, so the expired messages are a prefix.
            for row in connection.execute(
                "SELECT seq, created_at FROM messages ORDER BY seq LIMIT ?", (batch_size,),
            ):
                if row["created_at"] >= cutoff:
                    break
                expired.append((row["seq"],))
            connection.executemany("DELETE FROM messages WHERE seq = ?", expired)
            return len(expired)

    def block_idle_agents(self, *, now: datetime, limit: int = 200) -> tuple[str, ...]:
        """Block enabled agents with no sign of life for the idle period.

        Blocking is reversible: the operator unblocks the agent in the console
        and its credential works again. Any lifecycle event inside the period
        (an unblock, a reconnect) counts as life, so an agent just unblocked is
        not blocked again before it has had the period to return.
        """

        if type(limit) is not int or not 1 <= limit <= 1000:
            raise DomainValidationError("invalid retention agent limit")
        timestamp = _format_utc(now)
        blocked: list[str] = []
        with self._transaction() as connection:
            days = _settings(connection).idle_agent_days
            if days is None or _access_freeze_from_connection(connection).frozen:
                return ()
            cutoff = _format_utc(now - timedelta(days=days))
            reason = f"no activity for {days} days"
            rows = connection.execute(
                """
                SELECT a.id, a.credential_epoch FROM agents a
                WHERE a.revoked_at IS NULL AND a.blocked_at IS NULL
                  AND a.id NOT IN (?, ?)
                  AND COALESCE(a.last_seen_at, a.created_at) < ?
                  AND NOT EXISTS (
                      SELECT 1 FROM agent_lifecycle_audit l
                      WHERE l.agent_id = a.id AND l.occurred_at >= ?)
                ORDER BY a.name LIMIT ?
                """,
                (*SYSTEM_AUTHOR_IDS, cutoff, cutoff, limit),
            ).fetchall()
            for row in rows:
                request_id = str(uuid.uuid4())
                agent = _checked_transition_agent(
                    connection, row["id"], "block", row["credential_epoch"],
                )
                _invalidate_reconnect_grants(
                    connection, agent=agent, request_id=request_id,
                    actor_type="system", actor_id=RETENTION_ACTOR_ID,
                    reason=reason, timestamp=timestamp,
                )
                connection.execute(
                    "UPDATE agents SET blocked_at = ?, "
                    "credential_epoch = credential_epoch + 1 "
                    "WHERE id = ? AND credential_epoch = ?",
                    (timestamp, agent.id, agent.credential_epoch),
                )
                _record_lifecycle_event(
                    connection, agent=agent, action="block", request_id=request_id,
                    intent_sha256=_lifecycle_input_hash(
                        "block", agent.id, agent.credential_epoch, reason,
                        "system", RETENTION_ACTOR_ID,
                    ),
                    actor_type="system", actor_id=RETENTION_ACTOR_ID,
                    reason=reason, timestamp=timestamp, resulting_state="blocked",
                )
                blocked.append(agent.name)
        return tuple(blocked)

    def record_retention_run(
        self, *, now: datetime, removed_messages: int, blocked_agents: int,
    ) -> None:
        with self._transaction() as connection:
            connection.execute(
                "UPDATE retention_settings SET last_run_at = ?, "
                "last_removed_messages = ?, last_blocked_agents = ?, "
                "total_removed_messages = total_removed_messages + ?, "
                "total_blocked_agents = total_blocked_agents + ? WHERE singleton = 1",
                (_format_utc(now), removed_messages, blocked_agents,
                 removed_messages, blocked_agents),
            )
