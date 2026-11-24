from __future__ import annotations

import json
import sqlite3

from strugglebus.errors import StorageError
from strugglebus.models import (
    DashboardAgentPage,
    DashboardChannelPage,
    DashboardCounts,
    DashboardSnapshot,
    Message,
)
from strugglebus.store._common import (
    _DASHBOARD_MESSAGE_FILTERS,
    _DASHBOARD_MESSAGE_SELECT,
    HUMAN_OPERATOR_AGENT_ID,
    MAINTENANCE_SYSTEM_AGENT_ID,
    _dashboard_agent_summary_from_row,
    _dashboard_channel_summary_from_rows,
    _message_from_row,
)


def _dashboard_counts_row(connection: sqlite3.Connection) -> sqlite3.Row:
    counts_row = connection.execute(
        """
        SELECT
            (SELECT COUNT(*)
             FROM agents
             WHERE revoked_at IS NULL AND blocked_at IS NULL
               AND id NOT IN (:maintenance_agent, :operator_agent)) AS active_agents,
            (SELECT COUNT(*) FROM agents
             WHERE revoked_at IS NULL AND blocked_at IS NOT NULL
               AND id NOT IN (:maintenance_agent, :operator_agent)) AS blocked_agents,
            (SELECT COUNT(*) FROM agents
             WHERE revoked_at IS NOT NULL
               AND id NOT IN (:maintenance_agent, :operator_agent)) AS retired_agents,
            (SELECT COUNT(*) FROM channels) AS channels,
            (SELECT COUNT(*)
             FROM subscriptions AS s
             JOIN agents AS a ON a.id = s.agent_id
             WHERE a.revoked_at IS NULL AND a.blocked_at IS NULL) AS subscriptions,
            EXISTS(SELECT 1 FROM messages LIMIT 1) AS board_has_messages
        """,
        {
            "maintenance_agent": MAINTENANCE_SYSTEM_AGENT_ID,
            "operator_agent": HUMAN_OPERATOR_AGENT_ID,
        },
    ).fetchone()
    if counts_row is None:
        raise StorageError("dashboard summary could not be read")
    return counts_row


def _channel_id_named(
    connection: sqlite3.Connection, channel_name: str,
) -> str | None:
    channel_row = connection.execute(
        "SELECT id FROM channels WHERE name = ?",
        (channel_name,),
    ).fetchone()
    return None if channel_row is None else channel_row["id"]


def _agent_id_named(
    connection: sqlite3.Connection, agent_name: str,
) -> str | None:
    agent_row = connection.execute(
        """
        SELECT id
        FROM agents
        WHERE name = ?
        """,
        (agent_name,),
    ).fetchone()
    return None if agent_row is None else agent_row["id"]


def _dashboard_message_rows(
    connection: sqlite3.Connection,
    *,
    channel_id: str | None,
    agent_id: str | None,
    before: int | None,
    limit: int,
) -> list[sqlite3.Row]:
    """Newest messages matching the resolved filters, plus one lookahead row."""

    parameters: list[object] = []
    if channel_id is not None:
        parameters.append(channel_id)
    if agent_id is not None:
        parameters.append(agent_id)
    if before is not None:
        parameters.append(before)
    parameters.append(limit + 1)
    filter_key = (
        channel_id is not None,
        agent_id is not None,
        before is not None,
    )
    query = (
        _DASHBOARD_MESSAGE_SELECT
        + _DASHBOARD_MESSAGE_FILTERS[filter_key]
        + " ORDER BY m.seq DESC LIMIT ?"
    )
    return connection.execute(
        query,
        parameters,
    ).fetchall()


def _dashboard_filtered_rows(
    connection: sqlite3.Connection,
    *,
    channel_name: str | None,
    agent_name: str | None,
    before: int | None,
    limit: int,
) -> list[sqlite3.Row]:
    """Message rows for the named filters; a name that matches nothing shows nothing."""

    channel_id = (
        None if channel_name is None else _channel_id_named(connection, channel_name)
    )
    agent_id = (
        None if agent_name is None else _agent_id_named(connection, agent_name)
    )
    filter_is_missing = (
        channel_name is not None
        and channel_id is None
        or agent_name is not None
        and agent_id is None
    )
    if filter_is_missing:
        return []
    return _dashboard_message_rows(
        connection,
        channel_id=channel_id,
        agent_id=agent_id,
        before=before,
        limit=limit,
    )


def _off_page_parent_rows(
    connection: sqlite3.Connection, messages: tuple[Message, ...],
) -> list[sqlite3.Row]:
    """Rows for replied-to messages that are not themselves on the page."""

    visible_sequences = {message.seq for message in messages}
    parent_sequences = sorted(
        {
            message.reply_to
            for message in messages
            if message.reply_to is not None
            and message.reply_to not in visible_sequences
        }
    )
    if not parent_sequences:
        return []
    return connection.execute(
        """
        SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
               a.name AS agent_name, m.body, m.kind, m.reply_to,
               m.meta, m.created_at
        FROM messages AS m
        JOIN channels AS c ON c.id = m.channel_id
        JOIN agents AS a ON a.id = m.agent_id
        WHERE m.seq IN (
            SELECT CAST(value AS INTEGER)
            FROM json_each(?)
        )
        ORDER BY m.seq
        """,
        (json.dumps(parent_sequences),),
    ).fetchall()


class DashboardMixin:
    def list_recent_messages(self, *, limit: int) -> tuple[Message, ...]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
                       a.name AS agent_name, m.body, m.kind, m.reply_to,
                       m.meta, m.created_at
                FROM messages AS m
                JOIN channels AS c ON c.id = m.channel_id
                JOIN agents AS a ON a.id = m.agent_id
                ORDER BY m.seq DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(_message_from_row(row) for row in reversed(rows))

    def dashboard_snapshot(
        self,
        *,
        channel_name: str | None,
        agent_name: str | None,
        before: int | None,
        limit: int,
    ) -> DashboardSnapshot:
        with self._read_transaction() as connection:
            counts_row = _dashboard_counts_row(connection)
            rows = _dashboard_filtered_rows(
                connection,
                channel_name=channel_name,
                agent_name=agent_name,
                before=before,
                limit=limit,
            )
            has_older = len(rows) > limit
            messages = tuple(_message_from_row(row) for row in rows[:limit])
            parent_rows = _off_page_parent_rows(connection, messages)

        return DashboardSnapshot(
            counts=DashboardCounts(
                active_agents=int(counts_row["active_agents"]),
                channels=int(counts_row["channels"]),
                subscriptions=int(counts_row["subscriptions"]),
                blocked_agents=int(counts_row["blocked_agents"]),
                retired_agents=int(counts_row["retired_agents"]),
            ),
            messages=messages,
            parent_messages=tuple(
                _message_from_row(row) for row in parent_rows
            ),
            has_older=has_older,
            board_has_messages=bool(counts_row["board_has_messages"]),
        )

    def dashboard_channels(
        self,
        *,
        after: str | None,
        limit: int,
    ) -> DashboardChannelPage:
        with self._read_transaction() as connection:
            parameters: list[object] = []
            query = "SELECT id, name, purpose, created_at FROM channels"
            if after is not None:
                query += " WHERE name > ?"
                parameters.append(after)
            query += " ORDER BY name LIMIT ?"
            parameters.append(limit + 1)
            rows = connection.execute(query, parameters).fetchall()

            has_more = len(rows) > limit
            page_rows = rows[:limit]
            channel_ids = [row["id"] for row in page_rows]
            activity: dict[str, sqlite3.Row] = {}
            if channel_ids:
                activity_rows = connection.execute(
                    """
                    SELECT c.id AS channel_id,
                           (SELECT COUNT(*) FROM messages AS m
                            WHERE m.channel_id = c.id) AS message_count,
                           (SELECT m2.created_at FROM messages AS m2
                            WHERE m2.channel_id = c.id
                            ORDER BY m2.seq DESC LIMIT 1) AS last_activity_at,
                           (SELECT COUNT(*) FROM subscriptions AS s
                            JOIN agents AS a ON a.id = s.agent_id
                            WHERE s.channel_id = c.id
                              AND a.revoked_at IS NULL AND a.blocked_at IS NULL) AS subscriber_count
                    FROM channels AS c
                    WHERE c.id IN (
                        SELECT value FROM json_each(?)
                    )
                    """,
                    (json.dumps(channel_ids),),
                ).fetchall()
                activity = {row["channel_id"]: row for row in activity_rows}

        summaries = tuple(
            _dashboard_channel_summary_from_rows(row, activity[row["id"]])
            for row in page_rows
        )
        return DashboardChannelPage(channels=summaries, has_more=has_more)

    def dashboard_agents(
        self,
        *,
        after: str | None,
        limit: int,
    ) -> DashboardAgentPage:
        with self._read_transaction() as connection:
            parameters: list[object] = []
            query = (
                "SELECT name, created_at, last_seen_at FROM agents"
                " WHERE revoked_at IS NULL"
            )
            if after is not None:
                query += " AND name > ?"
                parameters.append(after)
            query += " ORDER BY name LIMIT ?"
            parameters.append(limit + 1)
            rows = connection.execute(query, parameters).fetchall()

        has_more = len(rows) > limit
        summaries = tuple(
            _dashboard_agent_summary_from_row(row) for row in rows[:limit]
        )
        return DashboardAgentPage(agents=summaries, has_more=has_more)
