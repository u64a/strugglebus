from __future__ import annotations

import heapq
import sqlite3
from datetime import datetime
from typing import NamedTuple

from strugglebus.errors import (
    ChannelLimitError,
    ChannelNotFoundError,
    DuplicateChannelNameError,
    DomainValidationError,
    ReplyNotFoundError,
    StorageError,
)
from strugglebus.models import (
    AgentOrientation,
    Channel,
    Message,
    OrientationChannel,
    SearchHit,
)
from strugglebus.drain import (
    CatchUpPage,
    CatchUpSnapshot,
    PageBuilder,
)
from strugglebus.store._common import (
    HUMAN_CHANNEL,
    HUMAN_OPERATOR_AGENT_ID,
    MAINTENANCE_SYSTEM_AGENT_ID,
    _AGENT_SELECT,
    _DASHBOARD_MESSAGE_SELECT,
    _accepted_post,
    _channel_from_row,
    _format_utc,
    _message_from_row,
    _parse_utc,
    _post_message,
    _require_active_agent,
)


def _hidden_as_stale(
    row: sqlite3.Row, *, include_stale: bool, stale_cutoff: str,
) -> bool:
    """Old status chatter is skipped unless the reader asked to include it."""

    return (
        not include_stale
        and row["kind"] == "status"
        and row["created_at"] < stale_cutoff
    )


class _UnreadScan:
    """Ascending merge of the index scans behind one agent's unread counts.

    Sources ``0 .. n-1`` are the agent's subscribed channels and the last
    source is its mentions. Each source keeps at most one lookahead row, and
    is marked exhausted once its index has nothing further.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        agent_id: str,
        subscriptions: list[sqlite3.Row],
        mention_after: int,
    ) -> None:
        self._connection = connection
        self._agent_id = agent_id
        self._subscriptions = subscriptions
        self.mention_source = len(subscriptions)
        self.heads: list[tuple[int, int, sqlite3.Row]] = []
        self.exhausted = [False] * (self.mention_source + 1)
        for source, subscription in enumerate(subscriptions):
            self.seek(source, int(subscription["last_seq"]))
        self.seek(self.mention_source, mention_after)

    def _next_row(self, source: int, after: int) -> sqlite3.Row | None:
        if source == self.mention_source:
            return self._connection.execute(
                """
                SELECT message.seq, message.kind, message.created_at
                FROM mentions AS mention INDEXED BY idx_mentions_agent
                CROSS JOIN messages AS message
                WHERE mention.agent_id = ? AND mention.message_seq > ?
                  AND message.seq = mention.message_seq
                ORDER BY mention.message_seq
                LIMIT 1
                """,
                (self._agent_id, after),
            ).fetchone()
        return self._connection.execute(
            """
            SELECT seq, kind, created_at
            FROM messages INDEXED BY idx_messages_channel_seq
            WHERE channel_id = ? AND seq > ?
            ORDER BY seq
            LIMIT 1
            """,
            (self._subscriptions[source]["channel_id"], after),
        ).fetchone()

    def seek(self, source: int, after: int) -> None:
        """Queue the source's next row after a sequence, or mark it exhausted."""

        row = self._next_row(source, after)
        if row is None:
            self.exhausted[source] = True
        else:
            heapq.heappush(self.heads, (int(row["seq"]), source, row))


def _count_unread(
    scan: _UnreadScan,
    *,
    include_stale: bool,
    stale_cutoff: str,
    count_cap: int,
    candidate_limit: int,
) -> tuple[int, int, list[int]]:
    """Count unread messages, pending mentions and per-channel unread.

    Every examined row is charged against ``candidate_limit`` before stale
    filtering, and each count saturates one past ``count_cap``.
    """

    unread = 0
    pending_mentions = 0
    channel_counts = [0] * scan.mention_source
    last_counted_seq = 0
    examined = 0
    while scan.heads and examined < candidate_limit:
        seq, source, row = heapq.heappop(scan.heads)
        examined += 1
        if not _hidden_as_stale(
            row, include_stale=include_stale, stale_cutoff=stale_cutoff,
        ):
            if seq != last_counted_seq:
                unread = min(unread + 1, count_cap + 1)
                last_counted_seq = seq
            if source == scan.mention_source:
                pending_mentions = min(pending_mentions + 1, count_cap + 1)
            else:
                channel_counts[source] = min(
                    channel_counts[source] + 1, count_cap + 1
                )
        scan.seek(source, seq)
    return unread, pending_mentions, channel_counts


def _orientation_channels(
    subscriptions: list[sqlite3.Row],
    channel_counts: list[int],
    exhausted: list[bool],
    count_cap: int,
) -> list[OrientationChannel]:
    return sorted(
        (
            OrientationChannel(
                name=str(subscription["name"]),
                unread=min(channel_counts[source], count_cap),
                unread_capped=(
                    channel_counts[source] > count_cap
                    or not exhausted[source]
                ),
            )
            for source, subscription in enumerate(subscriptions)
        ),
        key=lambda channel: channel.name,
    )


def _last_caught_up_at(
    connection: sqlite3.Connection, agent_id: str,
) -> datetime | None:
    caught_up_row = connection.execute(
        """
        SELECT MAX(updated_at) FROM (
            SELECT updated_at FROM cursors WHERE agent_id = ?
            UNION ALL
            SELECT updated_at FROM mention_cursors WHERE agent_id = ?
        )
        """,
        (agent_id, agent_id),
    ).fetchone()
    return _parse_utc(caught_up_row[0])


def _channels_created_since(
    connection: sqlite3.Connection,
    last_caught_up_at: datetime | None,
    *,
    max_channels: int,
    channel_cap: int,
) -> tuple[tuple[str, ...], bool]:
    """Channels created after the agent last caught up, oldest first.

    The flag reports that the list is incomplete. An agent that has never
    caught up has no baseline, so nothing is new to it.
    """

    if last_caught_up_at is None:
        return (), False
    known_channels = connection.execute(
        """
        SELECT name, created_at FROM channels
        ORDER BY name
        LIMIT ?
        """,
        (max_channels + 1,),
    ).fetchall()
    baseline = _format_utc(last_caught_up_at)
    new_rows = sorted(
        (
            row
            for row in known_channels[:max_channels]
            if row["created_at"] > baseline
        ),
        key=lambda row: (row["created_at"], row["name"]),
    )
    truncated = len(known_channels) > max_channels or len(new_rows) > channel_cap
    return tuple(str(row["name"]) for row in new_rows[:channel_cap]), truncated


def _new_catch_up_snapshot(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    limit: int,
    overlap_since: datetime,
    stale_before: datetime,
    include_stale: bool,
    max_channels: int,
) -> CatchUpSnapshot:
    """Freeze the agent's cursors and the board's high-water mark for a drain."""

    subscriptions = connection.execute(
        """
        SELECT s.channel_id, COALESCE(c.last_seq, 0) AS last_seq
        FROM subscriptions AS s
        LEFT JOIN cursors AS c
          ON c.agent_id = s.agent_id AND c.channel_id = s.channel_id
         AND c.include_stale = ?
        WHERE s.agent_id = ?
        ORDER BY s.channel_id
        LIMIT ?
        """,
        (int(include_stale), agent_id, max_channels + 1),
    ).fetchall()
    if len(subscriptions) > max_channels:
        raise DomainValidationError(
            "catch-up subscriptions exceed configured channel capacity"
        )
    mention = connection.execute(
        """
        SELECT last_seq FROM mention_cursors
        WHERE agent_id = ? AND include_stale = ?
        """,
        (agent_id, int(include_stale)),
    ).fetchone()
    return CatchUpSnapshot(
        agent_id=agent_id,
        subscriptions=tuple(
            (row["channel_id"], row["last_seq"])
            for row in subscriptions
        ),
        mention_cursor=0 if mention is None else mention["last_seq"],
        upper_seq=connection.execute(
            "SELECT COALESCE(MAX(seq), 0) FROM messages"
        ).fetchone()[0],
        overlap_since=overlap_since,
        stale_before=stale_before,
        include_stale=include_stale,
        limit=limit,
    )


class _CatchUpMerge:
    """Ascending merge of a snapshot's channel and mention index scans.

    Nothing past the snapshot's ``upper_seq`` is offered, so every page of one
    drain reads the same board. The last source is the agent's mentions.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        agent_id: str,
        snapshot: CatchUpSnapshot,
        after_seq: int,
    ) -> None:
        self._connection = connection
        self._agent_id = agent_id
        self._upper_seq = snapshot.upper_seq
        self._sources: tuple[str | None, ...] = (
            *dict(snapshot.subscriptions), None,
        )
        self._heads: list[tuple[int, int]] = []
        for source_index in range(len(self._sources)):
            self._advance(source_index, after_seq)

    @property
    def drained(self) -> bool:
        return not self._heads

    def _advance(self, source_index: int, position: int) -> None:
        channel_id = self._sources[source_index]
        if channel_id is None:
            candidate = self._connection.execute(
                """
                SELECT message_seq FROM mentions INDEXED BY idx_mentions_agent
                WHERE agent_id = ? AND message_seq > ? AND message_seq <= ?
                ORDER BY message_seq LIMIT 1
                """,
                (self._agent_id, position, self._upper_seq),
            ).fetchone()
        else:
            candidate = self._connection.execute(
                """
                SELECT seq FROM messages INDEXED BY idx_messages_channel_seq
                WHERE channel_id = ? AND seq > ? AND seq <= ?
                ORDER BY seq LIMIT 1
                """,
                (channel_id, position, self._upper_seq),
            ).fetchone()
        if candidate is not None:
            heapq.heappush(self._heads, (candidate[0], source_index))

    def pop(self) -> tuple[int, bool]:
        """Take the lowest queued sequence and whether it is a mention.

        Every source positioned on that sequence moves past it.
        """

        position = self._heads[0][0]
        mentioned = False
        while self._heads and self._heads[0][0] == position:
            _, source_index = heapq.heappop(self._heads)
            mentioned |= self._sources[source_index] is None
            self._advance(source_index, position)
        return position, mentioned


class _CatchUpSelection(NamedTuple):
    rows: list[sqlite3.Row]
    position: int
    drained: bool
    channel_high_water: dict[str, int]
    mention_high_water: int


def _catch_up_candidate(
    connection: sqlite3.Connection, position: int,
) -> sqlite3.Row:
    candidate = connection.execute(
        "SELECT channel_id, kind, created_at FROM messages WHERE seq = ?",
        (position,),
    ).fetchone()
    if candidate is None:
        raise StorageError("catch-up candidate could not be read")
    return candidate


def _catch_up_message_row(
    connection: sqlite3.Connection, position: int,
) -> sqlite3.Row:
    row = connection.execute(
        _DASHBOARD_MESSAGE_SELECT + " WHERE m.seq = ?",
        (position,),
    ).fetchone()
    if row is None:
        raise StorageError("catch-up message could not be read")
    return row


def _catch_up_eligible(
    candidate: sqlite3.Row,
    *,
    position: int,
    mentioned: bool,
    snapshot: CatchUpSnapshot,
    subscribed: dict[str, int],
    overlap_cutoff: str,
) -> bool:
    """Whether the snapshot owes this message to the agent.

    It is owed when it lies past the relevant cursor, or is recent enough to
    fall inside the re-delivery overlap.
    """

    channel_id = candidate["channel_id"]
    recent = candidate["created_at"] >= overlap_cutoff
    return (
        channel_id in subscribed
        and (position > subscribed[channel_id] or recent)
    ) or (
        mentioned and (position > snapshot.mention_cursor or recent)
    )


def _select_catch_up_rows(
    connection: sqlite3.Connection,
    snapshot: CatchUpSnapshot,
    *,
    agent_id: str,
    after_seq: int,
    candidate_limit: int,
    limit: int,
    include_stale: bool,
) -> _CatchUpSelection:
    """Collect one page of owed messages and the cursor positions they imply."""

    subscribed = dict(snapshot.subscriptions)
    merge = _CatchUpMerge(connection, agent_id, snapshot, after_seq)
    position = after_seq
    examined = 0
    rows: list[sqlite3.Row] = []
    channel_high_water: dict[str, int] = {}
    mention_high_water = 0
    overlap_cutoff = _format_utc(snapshot.overlap_since)
    stale_cutoff = _format_utc(snapshot.stale_before)
    while not merge.drained and examined < candidate_limit and len(rows) < limit:
        position, mentioned = merge.pop()
        examined += 1
        candidate = _catch_up_candidate(connection, position)
        channel_id = candidate["channel_id"]
        if not _catch_up_eligible(
            candidate, position=position, mentioned=mentioned, snapshot=snapshot,
            subscribed=subscribed, overlap_cutoff=overlap_cutoff,
        ) or _hidden_as_stale(
            candidate, include_stale=include_stale, stale_cutoff=stale_cutoff,
        ):
            continue
        rows.append(_catch_up_message_row(connection, position))
        if channel_id in subscribed:
            channel_high_water[channel_id] = position
        if mentioned:
            mention_high_water = position
    return _CatchUpSelection(
        rows, position, merge.drained, channel_high_water, mention_high_water,
    )


def _advance_catch_up_cursors(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    include_stale: bool,
    channel_high_water: dict[str, int],
    mention_high_water: int,
    updated_at: datetime,
) -> None:
    connection.executemany(
        """
        INSERT INTO cursors (
            agent_id, channel_id, include_stale, last_seq, updated_at
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(agent_id, channel_id, include_stale) DO UPDATE SET
            last_seq = MAX(cursors.last_seq, excluded.last_seq),
            updated_at = excluded.updated_at
        """,
        (
            (agent_id, channel_id, int(include_stale), last_seq,
             _format_utc(updated_at))
            for channel_id, last_seq in channel_high_water.items()
        ),
    )
    if mention_high_water:
        connection.execute(
            """
            INSERT INTO mention_cursors (
                agent_id, include_stale, last_seq, updated_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(agent_id, include_stale) DO UPDATE SET
                last_seq = MAX(mention_cursors.last_seq, excluded.last_seq),
                updated_at = excluded.updated_at
            """,
            (agent_id, int(include_stale), mention_high_water,
             _format_utc(updated_at)),
        )


class MessagesMixin:
    def ensure_default_channels(
        self,
        channels: tuple[tuple[str, str], ...],
        *,
        created_at: datetime,
    ) -> None:
        timestamp = _format_utc(created_at)
        with self._transaction() as connection:
            connection.executemany(
                """
                INSERT OR IGNORE INTO channels (
                    id, name, purpose, created_at, created_by
                )
                VALUES (?, ?, ?, ?, NULL)
                """,
                (
                    (name, name, purpose, timestamp)
                    for name, purpose in channels
                ),
            )

    def create_channel(
        self,
        *,
        channel_id: str,
        name: str,
        purpose: str,
        created_at: datetime,
        created_by: str,
        max_channels: int,
    ) -> Channel:
        try:
            with self._transaction() as connection:
                _require_active_agent(connection, created_by)
                channel_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM channels"
                    ).fetchone()[0]
                )
                if channel_count >= max_channels:
                    raise ChannelLimitError(
                        "configured channel capacity has been reached"
                    )
                connection.execute(
                    """
                    INSERT INTO channels (
                        id, name, purpose, created_at, created_by
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        channel_id,
                        name,
                        purpose,
                        _format_utc(created_at),
                        created_by,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT id, name, purpose, created_at, created_by
                    FROM channels
                    WHERE id = ?
                    """,
                    (channel_id,),
                ).fetchone()
        except StorageError as error:
            if (
                isinstance(error.__cause__, sqlite3.IntegrityError)
                and "channels.name" in str(error.__cause__)
            ):
                raise DuplicateChannelNameError(
                    f"channel name {name!r} already exists"
                ) from error
            raise
        if row is None:
            raise StorageError("created channel could not be read back")
        return _channel_from_row(row)

    def list_channels(self) -> tuple[Channel, ...]:
        with self._read_transaction() as connection:
            rows = connection.execute(
                """
                SELECT id, name, purpose, created_at, created_by
                FROM channels
                ORDER BY name
                """
            ).fetchall()
        return tuple(_channel_from_row(row) for row in rows)

    def list_subscriptions(self, agent_id: str) -> tuple[Channel, ...]:
        with self._read_transaction() as connection:
            _require_active_agent(connection, agent_id)
            rows = connection.execute(
                """
                SELECT c.id, c.name, c.purpose, c.created_at, c.created_by
                FROM subscriptions AS s
                JOIN channels AS c ON c.id = s.channel_id
                WHERE s.agent_id = ?
                ORDER BY c.name
                """,
                (agent_id,),
            ).fetchall()
        return tuple(_channel_from_row(row) for row in rows)

    def subscribe(
        self,
        *,
        agent_id: str,
        channel_name: str,
        created_at: datetime,
    ) -> Channel:
        with self._transaction() as connection:
            _require_active_agent(connection, agent_id)
            channel = connection.execute(
                """
                SELECT id, name, purpose, created_at, created_by
                FROM channels
                WHERE name = ?
                """,
                (channel_name,),
            ).fetchone()
            if channel is None:
                raise ChannelNotFoundError(
                    f"channel {channel_name!r} was not found"
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO subscriptions (
                    agent_id, channel_id, created_at
                )
                VALUES (?, ?, ?)
                """,
                (agent_id, channel["id"], _format_utc(created_at)),
            )
        return _channel_from_row(channel)

    def unsubscribe(self, *, agent_id: str, channel_name: str) -> Channel:
        with self._transaction() as connection:
            _require_active_agent(connection, agent_id)
            channel = connection.execute(
                """
                SELECT id, name, purpose, created_at, created_by
                FROM channels
                WHERE name = ?
                """,
                (channel_name,),
            ).fetchone()
            if channel is None:
                raise ChannelNotFoundError(
                    f"channel {channel_name!r} was not found"
                )
            connection.execute(
                """
                DELETE FROM subscriptions
                WHERE agent_id = ? AND channel_id = ?
                """,
                (agent_id, channel["id"]),
            )
        return _channel_from_row(channel)

    def list_messages(
        self,
        channel_name: str,
        *,
        since: int,
        limit: int,
    ) -> tuple[Message, ...]:
        with self._read_transaction() as connection:
            channel = connection.execute(
                "SELECT id FROM channels WHERE name = ?",
                (channel_name,),
            ).fetchone()
            if channel is None:
                raise ChannelNotFoundError(
                    f"channel {channel_name!r} was not found"
                )
            rows = connection.execute(
                """
                SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
                       a.name AS agent_name, m.body, m.kind, m.reply_to,
                       m.meta, m.created_at
                FROM messages AS m
                JOIN channels AS c ON c.id = m.channel_id
                JOIN agents AS a ON a.id = m.agent_id
                WHERE m.channel_id = ? AND m.seq > ?
                ORDER BY m.seq
                LIMIT ?
                """,
                (channel["id"], since, limit),
            ).fetchall()
        return tuple(_message_from_row(row) for row in rows)

    def create_message(
        self,
        *,
        message_id: str,
        channel_name: str,
        agent_id: str,
        body: str,
        kind: str,
        reply_to: int | None,
        metadata_json: str,
        created_at: datetime,
        mentioned_names: tuple[str, ...],
        request_id: str | None = None,
    ) -> Message:
        with self._transaction() as connection:
            _require_active_agent(connection, agent_id)
            message = _post_message(
                connection,
                message_id=message_id, channel_name=channel_name, agent_id=agent_id,
                body=body, kind=kind, reply_to=reply_to, metadata_json=metadata_json,
                created_at=created_at, mentioned_names=mentioned_names,
                request_id=request_id,
            )
        if message is None:
            raise StorageError("created message could not be read back")
        return message

    def create_human_message(
        self,
        *,
        message_id: str,
        body: str,
        kind: str,
        reply_to: int | None,
        metadata_json: str,
        created_at: datetime,
        mentioned_names: tuple[str, ...],
        request_id: str,
    ) -> Message:
        """Post as the shared credential-less operator author, only in #humans.

        This is an operator-plane write: the caller has already authenticated
        an operator session, and the agent-access freeze does not apply.
        """
        with self._transaction() as connection:
            message = _post_message(
                connection, message_id=message_id, channel_name=HUMAN_CHANNEL,
                agent_id=HUMAN_OPERATOR_AGENT_ID, body=body, kind=kind,
                reply_to=reply_to, metadata_json=metadata_json, created_at=created_at,
                mentioned_names=mentioned_names, request_id=request_id,
            )
        if message is None:
            raise StorageError("created message could not be read back")
        return message

    def create_host_command_message(
        self,
        *,
        message_id: str,
        channel_name: str,
        body: str,
        metadata_json: str,
        created_at: datetime,
        request_id: str,
    ) -> Message:
        """Carry a signed host command on a worker hosts' channel, as the operator.

        The one operator post allowed outside #humans, and only in this shape.
        The bus does not read the command: a host acts on it only if its
        signature checks against keys pinned on that host.
        """
        with self._transaction() as connection:
            message = _post_message(
                connection, message_id=message_id, channel_name=channel_name,
                agent_id=HUMAN_OPERATOR_AGENT_ID, body=body, kind="question",
                reply_to=None, metadata_json=metadata_json, created_at=created_at,
                mentioned_names=(), request_id=request_id,
            )
        if message is None:
            raise StorageError("created message could not be read back")
        return message

    def create_maintenance_announcement(
        self,
        *,
        message_id: str,
        body: str,
        metadata_json: str,
        created_at: datetime,
        request_id: str,
    ) -> Message:
        with self._transaction() as connection:
            accepted = _accepted_post(
                connection,
                request_id=request_id,
                agent_id=MAINTENANCE_SYSTEM_AGENT_ID,
                channel_name="announce",
                body=body,
                kind="announce",
                reply_to=None,
                metadata_json=metadata_json,
            )
            if accepted is not None:
                return accepted
            channel = connection.execute(
                "SELECT id FROM channels WHERE name = 'announce'",
            ).fetchone()
            if channel is None:
                raise ChannelNotFoundError("channel 'announce' was not found")
            row = connection.execute(
                _AGENT_SELECT + " WHERE id = ? AND revoked_at IS NULL AND blocked_at IS NULL",
                (MAINTENANCE_SYSTEM_AGENT_ID,),
            ).fetchone()
            if row is None:
                raise StorageError("maintenance system author is unavailable")
            cursor = connection.execute(
                """
                INSERT INTO messages (
                    id, channel_id, agent_id, body, kind, reply_to,
                    meta, created_at, post_request_id
                )
                VALUES (?, ?, ?, ?, 'announce', NULL, ?, ?, ?)
                """,
                (
                    message_id,
                    channel["id"],
                    MAINTENANCE_SYSTEM_AGENT_ID,
                    body,
                    metadata_json,
                    _format_utc(created_at),
                    request_id,
                ),
            )
            row = connection.execute(
                """
                SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
                       a.name AS agent_name, m.body, m.kind, m.reply_to,
                       m.meta, m.created_at
                FROM messages AS m
                JOIN channels AS c ON c.id = m.channel_id
                JOIN agents AS a ON a.id = m.agent_id
                WHERE m.seq = ?
                """,
                (cursor.lastrowid,),
            ).fetchone()
        if row is None:
            raise StorageError("maintenance announcement could not be read back")
        return _message_from_row(row)

    def read_replies(
        self,
        *,
        message_seq: int,
        since: int,
        limit: int,
    ) -> tuple[Message, ...]:
        with self._read_transaction() as connection:
            target = connection.execute(
                "SELECT 1 FROM messages WHERE seq = ?",
                (message_seq,),
            ).fetchone()
            if target is None:
                raise ReplyNotFoundError("reply target was not found")
            rows = connection.execute(
                """
                SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
                       a.name AS agent_name, m.body, m.kind, m.reply_to,
                       m.meta, m.created_at
                FROM messages AS m
                JOIN channels AS c ON c.id = m.channel_id
                JOIN agents AS a ON a.id = m.agent_id
                WHERE m.reply_to = ? AND m.seq > ?
                ORDER BY m.seq
                LIMIT ?
                """,
                (message_seq, since, limit),
            ).fetchall()
        return tuple(_message_from_row(row) for row in rows)

    def agent_orientation(
        self,
        *,
        agent_id: str,
        stale_before: datetime,
        include_stale: bool,
        count_cap: int,
        channel_cap: int,
        candidate_limit: int = 4096,
        max_channels: int = 1000,
    ) -> AgentOrientation:
        """Summarize what an agent has not seen, without moving any cursor.

        Indexed sources omit re-delivery overlap. Charge every examined source
        row before stale filtering, allowing only one lookahead per source.
        Exhaustion and count caps are tracked independently for each metric.
        """

        stale_cutoff = _format_utc(stale_before)
        cursor_flag = int(include_stale)
        with self._read_transaction() as connection:
            _require_active_agent(connection, agent_id)
            subscription_rows = connection.execute(
                """
                SELECT subscription.channel_id, channel.name,
                       COALESCE(cursor.last_seq, 0) AS last_seq
                FROM subscriptions AS subscription
                JOIN channels AS channel ON channel.id = subscription.channel_id
                LEFT JOIN cursors AS cursor
                  ON cursor.agent_id = subscription.agent_id
                 AND cursor.channel_id = subscription.channel_id
                 AND cursor.include_stale = ?
                WHERE subscription.agent_id = ?
                ORDER BY subscription.channel_id
                LIMIT ?
                """,
                (cursor_flag, agent_id, max_channels + 1),
            ).fetchall()
            # On scope overflow this is a lower bound, not an unbounded COUNT.
            subscription_count = len(subscription_rows)
            scope_truncated = subscription_count > max_channels
            subscriptions = subscription_rows[:max_channels]
            mention_cursor = connection.execute(
                """
                SELECT last_seq FROM mention_cursors
                WHERE agent_id = ? AND include_stale = ?
                """,
                (agent_id, cursor_flag),
            ).fetchone()

            scan = _UnreadScan(
                connection,
                agent_id,
                subscriptions,
                int(mention_cursor["last_seq"]) if mention_cursor else 0,
            )
            unread, pending_mentions, channel_counts = _count_unread(
                scan,
                include_stale=include_stale,
                stale_cutoff=stale_cutoff,
                count_cap=count_cap,
                candidate_limit=candidate_limit,
            )
            unread_capped = unread > count_cap or bool(scan.heads) or scope_truncated
            pending_mentions_capped = (
                pending_mentions > count_cap
                or not scan.exhausted[scan.mention_source]
            )
            channels = _orientation_channels(
                subscriptions, channel_counts, scan.exhausted, count_cap,
            )

            latest_row = connection.execute(
                "SELECT COALESCE(MAX(seq), 0) FROM messages"
            ).fetchone()
            latest_seq = int(latest_row[0])

            last_caught_up_at = _last_caught_up_at(connection, agent_id)
            new_channels, new_channels_truncated = _channels_created_since(
                connection,
                last_caught_up_at,
                max_channels=max_channels,
                channel_cap=channel_cap,
            )

        return AgentOrientation(
            latest_seq=latest_seq,
            unread=min(unread, count_cap),
            unread_capped=unread_capped,
            pending_mentions=min(pending_mentions, count_cap),
            pending_mentions_capped=pending_mentions_capped,
            last_caught_up_at=last_caught_up_at,
            channels=tuple(channels[:channel_cap]),
            new_channels=new_channels,
            subscription_count=subscription_count,
            counts_complete=not (unread_capped or pending_mentions_capped),
            subscribed_channels_truncated=(
                scope_truncated or subscription_count > channel_cap
            ),
            new_channels_truncated=new_channels_truncated,
        )

    def catch_up(
        self,
        *,
        agent_id: str,
        limit: int,
        overlap_since: datetime,
        stale_before: datetime,
        include_stale: bool,
        updated_at: datetime,
    ) -> tuple[Message, ...]:
        with self._transaction() as connection:
            _require_active_agent(connection, agent_id)
            rows = connection.execute(
                """
                SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
                       a.name AS agent_name, m.body, m.kind, m.reply_to,
                       m.meta, m.created_at,
                       subscription.agent_id IS NOT NULL AS subscribed,
                       mention.agent_id IS NOT NULL AS mentioned
                FROM messages AS m
                JOIN channels AS c ON c.id = m.channel_id
                JOIN agents AS a ON a.id = m.agent_id
                LEFT JOIN subscriptions AS subscription
                  ON subscription.agent_id = ?
                 AND subscription.channel_id = m.channel_id
                LEFT JOIN mentions AS mention
                  ON mention.agent_id = ?
                 AND mention.message_seq = m.seq
                LEFT JOIN cursors AS cursor
                  ON cursor.agent_id = ?
                 AND cursor.channel_id = m.channel_id
                 AND cursor.include_stale = ?
                LEFT JOIN mention_cursors AS mention_cursor
                  ON mention_cursor.agent_id = ?
                 AND mention_cursor.include_stale = ?
                WHERE (
                    (
                        subscription.agent_id IS NOT NULL
                        AND (
                            m.seq > COALESCE(cursor.last_seq, 0)
                            OR m.created_at >= ?
                        )
                    )
                    OR (
                        mention.agent_id IS NOT NULL
                        AND (
                            m.seq > COALESCE(mention_cursor.last_seq, 0)
                            OR m.created_at >= ?
                        )
                    )
                )
                AND (
                    ? = 1
                    OR m.kind <> 'status'
                    OR m.created_at >= ?
                )
                ORDER BY m.seq
                LIMIT ?
                """,
                (
                    agent_id,
                    agent_id,
                    agent_id,
                    int(include_stale),
                    agent_id,
                    int(include_stale),
                    _format_utc(overlap_since),
                    _format_utc(overlap_since),
                    int(include_stale),
                    _format_utc(stale_before),
                    limit,
                ),
            ).fetchall()
            messages = tuple(_message_from_row(row) for row in rows)
            channel_high_water: dict[str, int] = {}
            mention_high_water = 0
            for row in rows:
                if row["subscribed"]:
                    channel_high_water[row["channel_name"]] = max(
                        channel_high_water.get(row["channel_name"], 0),
                        row["seq"],
                    )
                if row["mentioned"]:
                    mention_high_water = max(mention_high_water, row["seq"])
            connection.executemany(
                """
                INSERT INTO cursors (
                    agent_id, channel_id, include_stale, last_seq, updated_at
                )
                SELECT ?, id, ?, ?, ?
                FROM channels
                WHERE name = ?
                ON CONFLICT(agent_id, channel_id, include_stale) DO UPDATE SET
                    last_seq = MAX(cursors.last_seq, excluded.last_seq),
                    updated_at = excluded.updated_at
                """,
                (
                    (
                        agent_id,
                        int(include_stale),
                        last_seq,
                        _format_utc(updated_at),
                        channel_name,
                    )
                    for channel_name, last_seq in channel_high_water.items()
                ),
            )
            if mention_high_water:
                connection.execute(
                    """
                    INSERT INTO mention_cursors (
                        agent_id, include_stale, last_seq, updated_at
                    )
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(agent_id, include_stale) DO UPDATE SET
                        last_seq = MAX(
                            mention_cursors.last_seq,
                            excluded.last_seq
                        ),
                        updated_at = excluded.updated_at
                    """,
                    (
                        agent_id,
                        int(include_stale),
                        mention_high_water,
                        _format_utc(updated_at),
                    ),
                )
        return messages

    def catch_up_page(
        self,
        *,
        agent_id: str,
        limit: int,
        overlap_since: datetime,
        stale_before: datetime,
        include_stale: bool,
        updated_at: datetime,
        snapshot: CatchUpSnapshot | None,
        after_seq: int,
        candidate_limit: int,
        max_channels: int,
        build_page: PageBuilder,
    ) -> CatchUpPage:
        with self._transaction() as connection:
            _require_active_agent(connection, agent_id)
            if snapshot is None:
                snapshot = _new_catch_up_snapshot(
                    connection,
                    agent_id=agent_id,
                    limit=limit,
                    overlap_since=overlap_since,
                    stale_before=stale_before,
                    include_stale=include_stale,
                    max_channels=max_channels,
                )
            if (
                snapshot.agent_id != agent_id
                or snapshot.limit != limit
                or snapshot.include_stale != include_stale
            ):
                raise DomainValidationError("catch-up snapshot scope mismatch")
            selection = _select_catch_up_rows(
                connection,
                snapshot,
                agent_id=agent_id,
                after_seq=after_seq,
                candidate_limit=candidate_limit,
                limit=limit,
                include_stale=include_stale,
            )
            messages = tuple(_message_from_row(row) for row in selection.rows)
            page = build_page(
                snapshot, messages, selection.position, selection.drained,
            )
            _advance_catch_up_cursors(
                connection,
                agent_id=agent_id,
                include_stale=include_stale,
                channel_high_water=selection.channel_high_water,
                mention_high_water=selection.mention_high_water,
                updated_at=updated_at,
            )
        return page

    def search_messages(
        self,
        *,
        match_expression: str,
        channel_name: str | None,
        limit: int,
        stale_before: datetime,
        include_stale: bool,
    ) -> tuple[SearchHit, ...]:
        with self._read_transaction() as connection:
            if channel_name is not None:
                channel = connection.execute(
                    "SELECT 1 FROM channels WHERE name = ?",
                    (channel_name,),
                ).fetchone()
                if channel is None:
                    raise ChannelNotFoundError(
                        f"channel {channel_name!r} was not found"
                    )
            rows = connection.execute(
                """
                SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
                       a.name AS agent_name, m.body, m.kind, m.reply_to,
                       m.meta, m.created_at,
                       snippet(messages_fts, 0, '', '', ' ... ', 24) AS snippet
                FROM messages_fts
                JOIN messages AS m ON m.seq = messages_fts.rowid
                JOIN channels AS c ON c.id = m.channel_id
                JOIN agents AS a ON a.id = m.agent_id
                WHERE messages_fts MATCH ?
                  AND (? IS NULL OR c.name = ?)
                  AND (
                      ? = 1
                      OR m.kind <> 'status'
                      OR m.created_at >= ?
                  )
                ORDER BY m.seq DESC
                LIMIT ?
                """,
                (
                    match_expression,
                    channel_name,
                    channel_name,
                    int(include_stale),
                    _format_utc(stale_before),
                    limit,
                ),
            ).fetchall()
        return tuple(
            SearchHit(message=_message_from_row(row), snippet=row["snippet"])
            for row in rows
        )

    def list_messages_after(
        self,
        *,
        since: int,
        limit: int,
        channel_name: str | None = None,
    ) -> tuple[Message, ...]:
        with self._read_transaction() as connection:
            if channel_name is None:
                rows = connection.execute(
                    """
                    SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
                           a.name AS agent_name, m.body, m.kind, m.reply_to,
                           m.meta, m.created_at
                    FROM messages AS m
                    JOIN channels AS c ON c.id = m.channel_id
                    JOIN agents AS a ON a.id = m.agent_id
                    WHERE m.seq > ?
                    ORDER BY m.seq
                    LIMIT ?
                    """,
                    (since, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
                           a.name AS agent_name, m.body, m.kind, m.reply_to,
                           m.meta, m.created_at
                    FROM messages AS m
                    JOIN channels AS c ON c.id = m.channel_id
                    JOIN agents AS a ON a.id = m.agent_id
                    WHERE m.seq > ? AND c.name = ?
                    ORDER BY m.seq
                    LIMIT ?
                    """,
                    (since, channel_name, limit),
                ).fetchall()
        return tuple(_message_from_row(row) for row in rows)

    def require_channel(self, channel_name: str) -> None:
        """Raise when a channel name has no matching channel."""

        with self._read_transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM channels WHERE name = ?",
                (channel_name,),
            ).fetchone() is None:
                raise ChannelNotFoundError(
                    f"channel {channel_name!r} was not found"
                )
