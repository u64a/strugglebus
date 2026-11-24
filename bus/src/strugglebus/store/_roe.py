from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime
from collections.abc import Callable

from strugglebus.errors import (
    AgentNotFoundError,
    CredentialNotFoundError,
    RoeConflictError,
    StorageError,
)
from strugglebus.models import (
    EffectiveRoe,
    RoeAcknowledgement,
    RoeRevision,
)
from strugglebus.roe import composition_sha256
from strugglebus.store._common import (
    _ROE_REVISION_SELECT,
    _current_roe_revision,
    _effective_roe_from_connection,
    _format_utc,
    _require_active_agent,
    _require_agent_access,
    _require_live_credential,
    _roe_acknowledgement_from_row,
    _roe_composition_matches,
    _roe_revision_from_row,
    utc_now,
)


def _is_first_global_revision(revision: RoeRevision) -> bool:
    return (
        revision.target_key == "global"
        and revision.scope == "global"
        and revision.agent_id is None
        and revision.version == 1
        and revision.policy_schema_version == 1
    )


def _is_generic_baseline(
    revision: RoeRevision, content_json: str, content_sha256: str,
) -> bool:
    return (
        revision.content_json == content_json
        and revision.content_sha256 == content_sha256
        and revision.author_label == "Strugglebus generic baseline"
        and revision.publisher_type == "system"
        and revision.publisher_identity
        == "system:strugglebus-generic-baseline-v1"
    )


def _insert_initial_global_roe(
    connection: sqlite3.Connection,
    *,
    revision_id: str,
    content_json: str,
    content_sha256: str,
    timestamp: str,
) -> None:
    connection.execute(
        """
        INSERT INTO roe_revisions (
            id, target_key, scope, agent_id, version,
            policy_schema_version, content_json, content_sha256,
            author_label, publisher_type, publisher_identity,
            created_at
        )
        VALUES (?, 'global', 'global', NULL, 1, 1, ?, ?,
                'Strugglebus generic baseline', 'system',
                'system:strugglebus-generic-baseline-v1', ?)
        """,
        (revision_id, content_json, content_sha256, timestamp),
    )
    connection.execute(
        """
        INSERT INTO roe_current (
            target_key, scope, agent_id, revision_id, updated_at
        )
        VALUES ('global', 'global', NULL, ?, ?)
        """,
        (revision_id, timestamp),
    )
    connection.execute(
        """
        INSERT INTO roe_audit (
            id, event_type, target_key, revision_id, actor_type,
            actor_id, occurred_at
        )
        VALUES (?, 'publish', 'global', ?, 'system',
                'system:strugglebus-generic-baseline-v1', ?)
        """,
        (str(uuid.uuid4()), revision_id, timestamp),
    )


def _require_publishable_agent(
    connection: sqlite3.Connection, agent_id: str | None,
) -> None:
    """An agent-scoped revision needs an agent that has not been retired."""

    if agent_id is None:
        return
    agent = connection.execute(
        "SELECT 1 FROM agents WHERE id = ? AND revoked_at IS NULL",
        (agent_id,),
    ).fetchone()
    if agent is None:
        raise AgentNotFoundError(f"agent {agent_id!r} was not found")


def _roe_predecessor_id(
    connection: sqlite3.Connection, target_key: str, revision: RoeRevision,
) -> str | None:
    if revision.version == 1:
        return None
    predecessor_row = connection.execute(
        """
        SELECT id
        FROM roe_revisions
        WHERE target_key = ? AND version = ?
        """,
        (target_key, revision.version - 1),
    ).fetchone()
    return None if predecessor_row is None else predecessor_row["id"]


def _same_roe_target(
    revision: RoeRevision, *, target_key: str, scope: str, agent_id: str | None,
) -> bool:
    return (
        revision.target_key == target_key
        and revision.scope == scope
        and revision.agent_id == agent_id
    )


def _same_roe_content(
    revision: RoeRevision,
    *,
    policy_schema_version: int,
    content_json: str,
    content_sha256: str,
    author_label: str,
    publisher_type: str,
    publisher_identity: str,
) -> bool:
    return (
        revision.policy_schema_version == policy_schema_version
        and revision.content_json == content_json
        and revision.content_sha256 == content_sha256
        and revision.author_label == author_label
        and revision.publisher_type == publisher_type
        and revision.publisher_identity == publisher_identity
    )


def _replayed_roe_publication(
    connection: sqlite3.Connection,
    existing: RoeRevision,
    current: RoeRevision | None,
    *,
    expected_current_revision_id: str | None,
    target_key: str,
    scope: str,
    agent_id: str | None,
    policy_schema_version: int,
    content_json: str,
    content_sha256: str,
    author_label: str,
    publisher_type: str,
    publisher_identity: str,
) -> RoeRevision:
    """Return the revision an identical earlier publish created, or refuse the id.

    A replay is only recognised while that revision is still current and it
    replaced the revision the caller expected.
    """

    predecessor_id = _roe_predecessor_id(connection, target_key, existing)
    if (
        current is not None
        and current.id == existing.id
        and predecessor_id == expected_current_revision_id
        and _same_roe_target(
            existing, target_key=target_key, scope=scope, agent_id=agent_id,
        )
        and _same_roe_content(
            existing,
            policy_schema_version=policy_schema_version,
            content_json=content_json,
            content_sha256=content_sha256,
            author_label=author_label,
            publisher_type=publisher_type,
            publisher_identity=publisher_identity,
        )
    ):
        return existing
    raise RoeConflictError("RoE revision id is already in use")


def _supersede_roe_revision(
    connection: sqlite3.Connection,
    current: RoeRevision,
    *,
    target_key: str,
    agent_id: str | None,
    publisher_type: str,
    publisher_identity: str,
    timestamp: str,
) -> None:
    connection.execute(
        """
        UPDATE roe_revisions
        SET superseded_at = ?
        WHERE id = ? AND superseded_at IS NULL
        """,
        (timestamp, current.id),
    )
    connection.execute(
        """
        INSERT INTO roe_audit (
            id, event_type, target_key, agent_id, revision_id,
            actor_type, actor_id, occurred_at
        )
        VALUES (?, 'supersede', ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            target_key,
            agent_id,
            current.id,
            publisher_type,
            publisher_identity,
            timestamp,
        ),
    )


def _make_roe_revision_current(
    connection: sqlite3.Connection,
    *,
    revision_id: str,
    target_key: str,
    scope: str,
    agent_id: str | None,
    publisher_type: str,
    publisher_identity: str,
    timestamp: str,
) -> None:
    connection.execute(
        """
        INSERT INTO roe_current (
            target_key, scope, agent_id, revision_id, updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(target_key) DO UPDATE SET
            scope = excluded.scope,
            agent_id = excluded.agent_id,
            revision_id = excluded.revision_id,
            updated_at = excluded.updated_at
        """,
        (target_key, scope, agent_id, revision_id, timestamp),
    )
    connection.execute(
        """
        INSERT INTO roe_audit (
            id, event_type, target_key, agent_id, revision_id,
            actor_type, actor_id, occurred_at
        )
        VALUES (?, 'publish', ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            target_key,
            agent_id,
            revision_id,
            publisher_type,
            publisher_identity,
            timestamp,
        ),
    )


class RoeMixin:
    def ensure_initial_roe(
        self,
        *,
        revision_id: str,
        content_json: str,
        content_sha256: str,
        created_at: datetime,
    ) -> None:
        timestamp = _format_utc(created_at)
        with self._transaction() as connection:
            row = connection.execute(
                _ROE_REVISION_SELECT + " WHERE revision.id = ?",
                (revision_id,),
            ).fetchone()
            current = _current_roe_revision(connection, "global")
            if row is None:
                if current is not None:
                    raise StorageError("initial global RoE revision is unavailable")
                _insert_initial_global_roe(
                    connection,
                    revision_id=revision_id,
                    content_json=content_json,
                    content_sha256=content_sha256,
                    timestamp=timestamp,
                )
                return
            revision = _roe_revision_from_row(row)
            if not _is_first_global_revision(revision) or not _is_generic_baseline(
                revision, content_json, content_sha256,
            ):
                raise StorageError("initial global RoE revision is invalid")
            if current is None:
                raise StorageError("current global RoE revision is unavailable")

    def get_effective_roe(
        self,
        agent_id: str | None,
        credential_id: str | None = None,
        *,
        checked_at: datetime | None = None,
    ) -> EffectiveRoe:
        with self._read_transaction() as connection:
            if agent_id is not None:
                _require_active_agent(connection, agent_id)
                if credential_id is not None:
                    _require_live_credential(
                        connection, agent_id, credential_id,
                        checked_at=checked_at or utc_now(),
                    )
            return _effective_roe_from_connection(
                connection,
                agent_id,
                credential_id,
            )

    def publish_roe(
        self,
        *,
        revision_id: str,
        target_key: str,
        scope: str,
        agent_id: str | None,
        expected_current_revision_id: str | None,
        policy_schema_version: int,
        content_json: str,
        content_sha256: str,
        author_label: str,
        publisher_type: str,
        publisher_identity: str,
        created_at: datetime,
    ) -> tuple[RoeRevision, bool]:
        timestamp = _format_utc(created_at)
        with self._transaction() as connection:
            _require_agent_access(connection)
            _require_publishable_agent(connection, agent_id)
            existing_row = connection.execute(
                _ROE_REVISION_SELECT + " WHERE revision.id = ?",
                (revision_id,),
            ).fetchone()
            current = _current_roe_revision(connection, target_key)
            if existing_row is not None:
                existing = _replayed_roe_publication(
                    connection,
                    _roe_revision_from_row(existing_row),
                    current,
                    expected_current_revision_id=expected_current_revision_id,
                    target_key=target_key,
                    scope=scope,
                    agent_id=agent_id,
                    policy_schema_version=policy_schema_version,
                    content_json=content_json,
                    content_sha256=content_sha256,
                    author_label=author_label,
                    publisher_type=publisher_type,
                    publisher_identity=publisher_identity,
                )
                return existing, False
            current_id = None if current is None else current.id
            if current_id != expected_current_revision_id:
                raise RoeConflictError("current RoE revision changed")
            version = 1 if current is None else current.version + 1
            connection.execute(
                """
                INSERT INTO roe_revisions (
                    id, target_key, scope, agent_id, version,
                    policy_schema_version, content_json, content_sha256,
                    author_label, publisher_type, publisher_identity, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    revision_id,
                    target_key,
                    scope,
                    agent_id,
                    version,
                    policy_schema_version,
                    content_json,
                    content_sha256,
                    author_label,
                    publisher_type,
                    publisher_identity,
                    timestamp,
                ),
            )
            if current is not None:
                _supersede_roe_revision(
                    connection,
                    current,
                    target_key=target_key,
                    agent_id=agent_id,
                    publisher_type=publisher_type,
                    publisher_identity=publisher_identity,
                    timestamp=timestamp,
                )
            _make_roe_revision_current(
                connection,
                revision_id=revision_id,
                target_key=target_key,
                scope=scope,
                agent_id=agent_id,
                publisher_type=publisher_type,
                publisher_identity=publisher_identity,
                timestamp=timestamp,
            )
            row = connection.execute(
                _ROE_REVISION_SELECT + " WHERE revision.id = ?",
                (revision_id,),
            ).fetchone()
        if row is None:
            raise StorageError("published RoE revision could not be read back")
        return _roe_revision_from_row(row), True

    def acknowledge_roe(
        self,
        *,
        acknowledgement_id: str,
        agent_id: str,
        global_revision_id: str,
        global_content_sha256: str,
        agent_revision_id: str | None,
        agent_content_sha256: str | None,
        effective_sha256: str,
        acknowledged_at: datetime,
        credential_kind: str,
        credential_id: str,
        credential_record_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> tuple[RoeAcknowledgement, bool]:
        timestamp = _format_utc(acknowledged_at)
        with self._transaction() as connection:
            acknowledged_at = clock() if clock is not None else acknowledged_at
            timestamp = _format_utc(acknowledged_at)
            _require_live_credential(
                connection, agent_id, credential_record_id, checked_at=acknowledged_at,
            )
            credential_row = connection.execute(
                """
                SELECT kind
                FROM agent_credentials
                WHERE id = ? AND agent_id = ?
                  AND status IN ('pending', 'active')
                """,
                (credential_record_id, agent_id),
            ).fetchone()
            if credential_row is None:
                raise CredentialNotFoundError(
                    "authenticated credential is unavailable"
                )
            global_revision = _current_roe_revision(connection, "global")
            agent_revision = _current_roe_revision(
                connection,
                f"agent:{agent_id}",
            )
            if global_revision is None:
                raise StorageError("current global RoE revision is unavailable")
            expected_effective = composition_sha256(
                global_revision,
                agent_revision,
            )
            if not _roe_composition_matches(
                global_revision_id=global_revision_id,
                global_content_sha256=global_content_sha256,
                agent_revision_id=agent_revision_id,
                agent_content_sha256=agent_content_sha256,
                effective_sha256=effective_sha256,
                global_revision=global_revision,
                agent_revision=agent_revision,
                current_effective_sha256=expected_effective,
            ):
                raise RoeConflictError("RoE composition is no longer current")
            existing_row = connection.execute(
                """
                SELECT id, agent_id, global_revision_id,
                       global_content_sha256, agent_revision_id,
                       agent_content_sha256, effective_sha256,
                       acknowledged_at, credential_kind, credential_id,
                       credential_record_id
                FROM roe_acknowledgements
                WHERE credential_record_id = ?
                  AND effective_sha256 = ?
                """,
                (
                    credential_record_id,
                    effective_sha256,
                ),
            ).fetchone()
            if existing_row is not None:
                return _roe_acknowledgement_from_row(existing_row), False
            connection.execute(
                """
                INSERT INTO roe_acknowledgements (
                    id, agent_id, global_revision_id, global_content_sha256,
                    agent_revision_id, agent_content_sha256, effective_sha256,
                    acknowledged_at, credential_kind, credential_id,
                    credential_record_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    acknowledgement_id,
                    agent_id,
                    global_revision_id,
                    global_content_sha256,
                    agent_revision_id,
                    agent_content_sha256,
                    effective_sha256,
                    timestamp,
                    credential_kind,
                    credential_id,
                    credential_record_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO roe_audit (
                    id, event_type, target_key, agent_id,
                    global_revision_id, agent_revision_id, effective_sha256,
                    actor_type, actor_id, occurred_at
                )
                VALUES (?, 'acknowledge', ?, ?, ?, ?, ?, 'agent', ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    f"agent:{agent_id}",
                    agent_id,
                    global_revision_id,
                    agent_revision_id,
                    effective_sha256,
                    f"{credential_kind}:{credential_id}",
                    timestamp,
                ),
            )
            row = connection.execute(
                """
                SELECT id, agent_id, global_revision_id,
                       global_content_sha256, agent_revision_id,
                       agent_content_sha256, effective_sha256,
                       acknowledged_at, credential_kind, credential_id,
                       credential_record_id
                FROM roe_acknowledgements
                WHERE id = ?
                """,
                (acknowledgement_id,),
            ).fetchone()
        if row is None:
            raise StorageError("RoE acknowledgement could not be read back")
        return _roe_acknowledgement_from_row(row), True

    def list_roe_revisions(
        self,
        *,
        target_key: str,
        before_version: int | None,
        limit: int,
    ) -> tuple[RoeRevision, ...]:
        with self._connection() as connection:
            parameters: list[object] = [target_key]
            query = _ROE_REVISION_SELECT + " WHERE revision.target_key = ?"
            if before_version is not None:
                query += " AND revision.version < ?"
                parameters.append(before_version)
            query += " ORDER BY revision.version DESC LIMIT ?"
            parameters.append(limit)
            rows = connection.execute(query, parameters).fetchall()
        return tuple(_roe_revision_from_row(row) for row in rows)
