from __future__ import annotations

import hmac
import sqlite3
import uuid
from datetime import datetime, timedelta
from collections.abc import Callable

from strugglebus.errors import (
    AgentNotFoundError,
    CredentialConflictError,
    CredentialLimitError,
    StorageError,
)
from strugglebus.models import (
    Agent,
    AgentCredential,
    LifecycleActor,
    AuthenticatedIdentity,
)
from strugglebus.store._common import (
    _AGENT_SELECT,
    _CREDENTIAL_SELECT,
    _DUMMY_KEY_HASH,
    _HUMAN_ACTOR_TYPES,
    _access_freeze_from_connection,
    _advance_credential_epoch,
    _agent_from_row,
    _credential_auth_row,
    _credential_from_row,
    _expire_pending_credentials,
    _format_utc,
    _identity_from_auth_row,
    _insert_pending_credential,
    _lifecycle_input_hash,
    _parse_utc,
    _require_active_credential,
    _require_agent_access,
    _require_live_credential,
    _revoke_live_credentials,
    _validate_actor,
    utc_now,
)

_LIVE_CREDENTIAL_STATUSES = frozenset({"pending", "active"})
_ACTIVE_CREDENTIAL_STATUS = frozenset({"active"})
_PENDING_CREDENTIAL_STATUS = frozenset({"pending"})


def _auth_row_is_usable(
    row: sqlite3.Row | None, statuses: frozenset[str],
) -> bool:
    """Whether a credential may authenticate: known, its agent neither retired
    nor blocked, and in one of the accepted states."""

    return (
        row is not None
        and row["agent_revoked_at"] is None
        and row["agent_blocked_at"] is None
        and row["status"] in statuses
    )


def _agent_epoch_row(
    connection: sqlite3.Connection, agent_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT credential_epoch, revoked_at FROM agents WHERE id = ?",
        (agent_id,),
    ).fetchone()


def _credential_state_row(
    connection: sqlite3.Connection, agent_id: str, credential_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT status, version FROM agent_credentials
        WHERE id = ? AND agent_id = ?
        """,
        (credential_id, agent_id),
    ).fetchone()


def _live_agent_epoch_matches(
    agent: sqlite3.Row | None, expected_credential_epoch: int,
) -> bool:
    return (
        agent is not None
        and agent["revoked_at"] is None
        and int(agent["credential_epoch"]) == expected_credential_epoch
    )


def _credential_state_matches(
    credential: sqlite3.Row | None,
    statuses: frozenset[str],
    expected_credential_version: int,
) -> bool:
    return (
        credential is not None
        and credential["status"] in statuses
        and int(credential["version"]) == expected_credential_version
    )


def _require_issuable_agent(
    connection: sqlite3.Connection, agent_id: str, expected_credential_epoch: int,
) -> None:
    agent = _agent_epoch_row(connection, agent_id)
    if agent is None or agent["revoked_at"] is not None:
        raise AgentNotFoundError("authenticated agent is unavailable")
    if int(agent["credential_epoch"]) != expected_credential_epoch:
        raise CredentialConflictError("credential lifecycle state changed")


def _require_active_predecessor(
    connection: sqlite3.Connection, agent_id: str, predecessor_id: str | None,
) -> None:
    """A rotation must replace a credential that is still active."""

    if predecessor_id is None:
        return
    predecessor = connection.execute(
        """
        SELECT status FROM agent_credentials
        WHERE id = ? AND agent_id = ?
        """,
        (predecessor_id, agent_id),
    ).fetchone()
    if predecessor is None or predecessor["status"] != "active":
        raise CredentialConflictError(
            "credential lifecycle state changed"
        )


def _require_credential_capacity(
    connection: sqlite3.Connection, agent_id: str, *, max_active: int, max_pending: int,
) -> None:
    counts = connection.execute(
        """
        SELECT
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END),
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END)
        FROM agent_credentials WHERE agent_id = ?
        """,
        (agent_id,),
    ).fetchone()
    if int(counts[0] or 0) >= max_active or int(counts[1] or 0) >= max_pending:
        raise CredentialLimitError("credential capacity reached")


def _require_rotation_allowance(
    connection: sqlite3.Connection,
    agent_id: str,
    *,
    rotation_not_before: datetime | None,
    max_rotations: int | None,
) -> None:
    if rotation_not_before is None or max_rotations is None:
        return
    rotations = connection.execute(
        """
        SELECT COUNT(*) FROM agent_credential_audit
        WHERE agent_id = ? AND event_type = 'rotate'
          AND occurred_at >= ?
        """,
        (agent_id, _format_utc(rotation_not_before)),
    ).fetchone()[0]
    if int(rotations) >= max_rotations:
        raise CredentialLimitError("credential rotation limit reached")


def _require_active_capacity(
    connection: sqlite3.Connection, agent_id: str, max_active: int,
) -> None:
    active = connection.execute(
        """
        SELECT COUNT(*) FROM agent_credentials
        WHERE agent_id = ? AND status = 'active'
        """,
        (agent_id,),
    ).fetchone()[0]
    if int(active) >= max_active:
        raise CredentialLimitError("active credential capacity reached")


def _require_provable_credential(
    connection: sqlite3.Connection,
    identity: AuthenticatedIdentity,
    *,
    expected_credential_epoch: int,
    expected_credential_version: int,
) -> None:
    """Proof activates a pending credential the caller saw in its current state."""

    agent = _agent_epoch_row(connection, identity.agent.id)
    credential = _credential_state_row(
        connection, identity.agent.id, identity.credential.id,
    )
    if not _live_agent_epoch_matches(
        agent, expected_credential_epoch,
    ) or not _credential_state_matches(
        credential, _PENDING_CREDENTIAL_STATUS, expected_credential_version,
    ):
        raise CredentialConflictError("credential lifecycle state changed")


def _require_retirable_predecessor(
    connection: sqlite3.Connection,
    identity: AuthenticatedIdentity,
    credential_id: str,
    *,
    expected_credential_epoch: int,
    expected_credential_version: int,
) -> None:
    """Only the still-active predecessor of the calling credential may retire."""

    target = _credential_state_row(connection, identity.agent.id, credential_id)
    epoch = connection.execute(
        "SELECT credential_epoch FROM agents WHERE id = ?",
        (identity.agent.id,),
    ).fetchone()
    if (
        credential_id == identity.credential.id
        or identity.credential.predecessor_id != credential_id
        or not _credential_state_matches(
            target, _ACTIVE_CREDENTIAL_STATUS, expected_credential_version,
        )
        or epoch is None
        or int(epoch["credential_epoch"]) != expected_credential_epoch
    ):
        raise CredentialConflictError("credential lifecycle state changed")


class CredentialMixin:
    def authenticate_credential(
        self,
        *,
        kind: str,
        credential_id: str | None,
        candidate_digest: str,
        seen_at_factory: Callable[[], datetime],
        require_access: bool = False,
    ) -> AuthenticatedIdentity | None:
        matched = self._digest_matched_credential(
            kind=kind,
            credential_id=credential_id,
            candidate_digest=candidate_digest,
        )
        if matched is None:
            return None
        if self._liveness_is_fresh(matched, seen_at_factory):
            return self._authenticate_without_refresh(
                kind=kind,
                credential_id=credential_id,
                candidate_digest=candidate_digest,
                require_access=require_access,
            )
        return self._authenticate_and_refresh(
            matched,
            kind=kind,
            credential_id=credential_id,
            candidate_digest=candidate_digest,
            seen_at_factory=seen_at_factory,
            require_access=require_access,
        )

    def _digest_matched_credential(
        self,
        *,
        kind: str,
        credential_id: str | None,
        candidate_digest: str,
    ) -> sqlite3.Row | None:
        """Look up the presented credential without taking a transaction.

        The digest comparison always runs, against a dummy verifier when no
        credential was found, so an unknown credential costs the same as a
        wrong secret.
        """

        with self._connection() as connection:
            matched = _credential_auth_row(
                connection,
                kind=kind,
                credential_id=credential_id,
                candidate_digest=candidate_digest,
            )
        stored_digest = _DUMMY_KEY_HASH if matched is None else matched["secret_hash"]
        digest_matches = hmac.compare_digest(candidate_digest, stored_digest)
        if not digest_matches or not _auth_row_is_usable(
            matched, _LIVE_CREDENTIAL_STATUSES,
        ):
            return None
        return matched

    def _liveness_is_fresh(
        self,
        matched: sqlite3.Row,
        seen_at_factory: Callable[[], datetime],
    ) -> bool:
        """Whether an active credential was seen recently enough to skip the write."""

        last_used_at = _parse_utc(matched["last_used_at"])
        if matched["status"] != "active" or last_used_at is None:
            return False
        seen_at = seen_at_factory()
        return (
            seen_at is not None
            and seen_at - last_used_at
            < timedelta(seconds=self.liveness_refresh_seconds)
        )

    def _authenticate_without_refresh(
        self,
        *,
        kind: str,
        credential_id: str | None,
        candidate_digest: str,
        require_access: bool,
    ) -> AuthenticatedIdentity | None:
        with self._read_transaction() as connection:
            current = _credential_auth_row(
                connection, kind=kind, credential_id=credential_id,
                candidate_digest=candidate_digest,
            )
            if not _auth_row_is_usable(current, _ACTIVE_CREDENTIAL_STATUS):
                return None
            if require_access:
                _require_agent_access(connection)
            return _identity_from_auth_row(current)

    def _authenticate_and_refresh(
        self,
        matched: sqlite3.Row,
        *,
        kind: str,
        credential_id: str | None,
        candidate_digest: str,
        seen_at_factory: Callable[[], datetime],
        require_access: bool,
    ) -> AuthenticatedIdentity | None:
        with self._transaction() as connection:
            current = _credential_auth_row(
                connection, kind=kind, credential_id=credential_id,
                candidate_digest=candidate_digest,
            )
            if not _auth_row_is_usable(current, _LIVE_CREDENTIAL_STATUSES):
                return None
            if require_access:
                _require_agent_access(connection)
            seen_at = seen_at_factory()
            _expire_pending_credentials(
                connection,
                now=seen_at,
                agent_id=matched["agent_id"],
            )
            formatted_seen_at = _format_utc(seen_at)
            updated = connection.execute(
                """
                UPDATE agent_credentials
                SET last_used_at = ?
                WHERE id = ? AND secret_hash = ?
                  AND status IN ('pending', 'active')
                """,
                (formatted_seen_at, matched["id"], candidate_digest),
            )
            if updated.rowcount != 1:
                return None
            connection.execute(
                """
                UPDATE agents SET last_seen_at = ?
                WHERE id = ? AND revoked_at IS NULL
                """,
                (formatted_seen_at, matched["agent_id"]),
            )
            agent_row = connection.execute(
                _AGENT_SELECT + " WHERE id = ? AND revoked_at IS NULL",
                (matched["agent_id"],),
            ).fetchone()
            credential_row = connection.execute(
                _CREDENTIAL_SELECT
                + " WHERE id = ? AND status IN ('pending', 'active')",
                (matched["id"],),
            ).fetchone()
        if agent_row is None or credential_row is None:
            return None
        return AuthenticatedIdentity(
            _agent_from_row(agent_row),
            _credential_from_row(credential_row),
        )

    def verify_credential(
        self,
        *,
        kind: str,
        credential_id: str | None,
        candidate_digest: str,
        checked_at: datetime,
        require_access: bool = False,
    ) -> AuthenticatedIdentity | None:
        with self._transaction() as connection:
            row = _credential_auth_row(
                connection,
                kind=kind,
                credential_id=credential_id,
                candidate_digest=candidate_digest,
            )
            stored_digest = _DUMMY_KEY_HASH if row is None else row["secret_hash"]
            digest_matches = hmac.compare_digest(candidate_digest, stored_digest)
            if not digest_matches or not _auth_row_is_usable(
                row, _LIVE_CREDENTIAL_STATUSES,
            ):
                return None
            if require_access:
                _require_agent_access(connection)
            if (row["status"] == "pending"
                    and row["pending_expires_at"] <= _format_utc(checked_at)):
                if not _access_freeze_from_connection(connection).frozen:
                    _expire_pending_credentials(
                        connection, now=checked_at, agent_id=row["agent_id"],
                    )
                return None
            return _identity_from_auth_row(row)

    def credential_is_active(self, agent_id: str, credential_id: str) -> bool:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM agent_credentials AS credential
                JOIN agents AS agent ON agent.id = credential.agent_id
                WHERE credential.id = ? AND credential.agent_id = ?
                  AND credential.status = 'active'
                  AND agent.revoked_at IS NULL
                  AND agent.blocked_at IS NULL
                  AND (agent.expires_at IS NULL OR agent.expires_at > ?)
                """,
                (credential_id, agent_id, _format_utc(utc_now())),
            ).fetchone()
        return row is not None

    def get_live_credential_id(self, agent_id: str) -> str:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id FROM agent_credentials
                WHERE agent_id = ? AND status IN ('pending', 'active')
                ORDER BY created_at DESC, id DESC
                LIMIT 2
                """,
                (agent_id,),
            ).fetchall()
        if len(rows) != 1:
            raise CredentialConflictError(
                "an exact credential context is required"
            )
        return str(rows[0]["id"])

    def list_credentials(
        self, agent_id: str, *, require_access: bool = True,
    ) -> tuple[AgentCredential, ...]:
        with self._transaction() as connection:
            if require_access:
                _require_agent_access(connection)
            if connection.execute(
                "SELECT 1 FROM agents WHERE id = ? AND revoked_at IS NULL", (agent_id,),
            ).fetchone() is None:
                raise AgentNotFoundError("agent is unavailable")
            _expire_pending_credentials(connection, now=utc_now(), agent_id=agent_id)
            rows = connection.execute(
                _CREDENTIAL_SELECT
                + " WHERE agent_id = ? ORDER BY created_at, id",
                (agent_id,),
            ).fetchall()
        return tuple(_credential_from_row(row) for row in rows)

    def get_credential(self, agent_id: str, credential_id: str) -> AgentCredential:
        """Read one exact credential for protected local administration."""

        with self._read_transaction() as connection:
            row = connection.execute(
                _CREDENTIAL_SELECT + " WHERE id = ? AND agent_id = ?",
                (credential_id, agent_id),
            ).fetchone()
        if row is None:
            raise CredentialConflictError("exact credential was not found for agent")
        return _credential_from_row(row)

    def _request_result(
        self,
        connection: sqlite3.Connection,
        *,
        request_id: str,
        operation: str,
        input_hash: str,
    ) -> AgentCredential | None:
        row = connection.execute(
            """
            SELECT operation, input_sha256, result_credential_id
            FROM agent_credential_requests
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        if row["operation"] != operation or row["input_sha256"] != input_hash:
            raise CredentialConflictError(
                "credential request id is already in use"
            )
        if row["result_credential_id"] is None:
            raise StorageError("credential request result is unavailable")
        credential = connection.execute(
            _CREDENTIAL_SELECT + " WHERE id = ?",
            (row["result_credential_id"],),
        ).fetchone()
        if credential is None:
            raise StorageError("credential request result is unavailable")
        return _credential_from_row(credential)

    def issue_credential(
        self,
        *,
        agent_id: str,
        credential_id: str,
        secret_hash: str,
        request_id: str,
        expected_credential_epoch: int,
        reason: str,
        actor_type: str,
        actor_id: str,
        created_at: datetime,
        pending_expires_at: datetime,
        max_active: int,
        max_pending: int,
    ) -> tuple[AgentCredential, bool]:
        return self._issue_pending(
            operation="issue",
            event_type="issue",
            agent_id=agent_id,
            credential_id=credential_id,
            secret_hash=secret_hash,
            predecessor_id=None,
            request_id=request_id,
            expected_credential_epoch=expected_credential_epoch,
            reason=reason,
            actor_type=actor_type,
            actor_id=actor_id,
            created_at=created_at,
            pending_expires_at=pending_expires_at,
            max_active=max_active,
            max_pending=max_pending,
        )

    def rotate_credential(
        self,
        *,
        identity: AuthenticatedIdentity,
        new_credential_id: str,
        secret_hash: str,
        request_id: str,
        expected_agent_id: str,
        expected_credential_id: str,
        expected_credential_epoch: int,
        reason: str,
        created_at: datetime,
        pending_expires_at: datetime,
        max_active: int,
        max_pending: int,
        rotation_not_before: datetime,
        max_rotations: int,
    ) -> tuple[AgentCredential, bool]:
        if (
            identity.agent.id != expected_agent_id
            or identity.credential.id != expected_credential_id
            or identity.credential.status != "active"
        ):
            raise CredentialConflictError("credential lifecycle state changed")
        return self._issue_pending(
            operation="rotate",
            event_type="rotate",
            agent_id=identity.agent.id,
            credential_id=new_credential_id,
            secret_hash=secret_hash,
            predecessor_id=identity.credential.id,
            request_id=request_id,
            expected_credential_epoch=expected_credential_epoch,
            reason=reason,
            actor_type="agent",
            actor_id=identity.credential.id,
            created_at=created_at,
            pending_expires_at=pending_expires_at,
            max_active=max_active,
            max_pending=max_pending,
            rotation_not_before=rotation_not_before,
            max_rotations=max_rotations,
        )

    def _issue_pending(
        self,
        *,
        operation: str,
        event_type: str,
        agent_id: str,
        credential_id: str,
        secret_hash: str,
        predecessor_id: str | None,
        request_id: str,
        expected_credential_epoch: int,
        reason: str,
        actor_type: str,
        actor_id: str,
        created_at: datetime,
        pending_expires_at: datetime,
        max_active: int,
        max_pending: int,
        rotation_not_before: datetime | None = None,
        max_rotations: int | None = None,
    ) -> tuple[AgentCredential, bool]:
        if operation != "rotate":
            _validate_actor(LifecycleActor(actor_type, actor_id))
        input_hash = _lifecycle_input_hash(
            operation,
            agent_id,
            predecessor_id,
            expected_credential_epoch,
            reason,
        )
        timestamp = _format_utc(created_at)
        expires = _format_utc(pending_expires_at)
        with self._transaction() as connection:
            # Deliberately narrower than the lifecycle exemption: this issues a
            # credential, and nothing that grants access may be created while
            # frozen. Only the protected local CLI is exempt, because it is the
            # documented recovery path.
            if actor_type != "local-admin":
                _require_agent_access(connection)
            if actor_type == "agent":
                _require_active_credential(connection, agent_id, actor_id)
            existing = self._request_result(
                connection,
                request_id=request_id,
                operation=operation,
                input_hash=input_hash,
            )
            if existing is not None:
                return existing, False
            _expire_pending_credentials(
                connection, now=created_at, agent_id=agent_id
            )
            _require_issuable_agent(connection, agent_id, expected_credential_epoch)
            _require_active_predecessor(connection, agent_id, predecessor_id)
            _require_credential_capacity(
                connection, agent_id, max_active=max_active, max_pending=max_pending,
            )
            _require_rotation_allowance(
                connection, agent_id,
                rotation_not_before=rotation_not_before, max_rotations=max_rotations,
            )
            _insert_pending_credential(
                connection, agent_id=agent_id, credential_id=credential_id,
                secret_hash=secret_hash, predecessor_id=predecessor_id,
                method=operation, reason=reason, request_id=request_id,
                timestamp=timestamp, expires_at=expires,
            )
            _advance_credential_epoch(
                connection, agent_id=agent_id, request_id=request_id,
                actor_type=actor_type, actor_id=actor_id, reason=reason, timestamp=timestamp,
            )
            self._record_terminal_request(
                connection,
                request_id=request_id,
                operation=operation,
                input_hash=input_hash,
                agent_id=agent_id,
                credential_id=credential_id,
                event_type=event_type,
                actor_type=actor_type,
                actor_id=actor_id,
                method=operation,
                reason=reason,
                occurred_at=timestamp,
                related_credential_id=predecessor_id,
            )
            row = connection.execute(
                _CREDENTIAL_SELECT + " WHERE id = ?", (credential_id,)
            ).fetchone()
        if row is None:
            raise StorageError("issued credential could not be read back")
        return _credential_from_row(row), True

    def prove_credential(
        self,
        *,
        identity: AuthenticatedIdentity,
        request_id: str,
        expected_agent_id: str,
        expected_agent_name: str,
        expected_credential_epoch: int,
        expected_credential_version: int,
        verified_at: datetime,
        max_active: int,
        clock: Callable[[], datetime] | None = None,
    ) -> AgentCredential:
        input_hash = _lifecycle_input_hash(
            "prove",
            expected_agent_id,
            expected_agent_name,
            identity.credential.id,
            expected_credential_epoch,
            expected_credential_version,
        )
        timestamp = _format_utc(verified_at)
        with self._transaction() as connection:
            verified_at = clock() if clock is not None else verified_at
            timestamp = _format_utc(verified_at)
            _require_live_credential(
                connection, identity.agent.id, identity.credential.id, checked_at=verified_at,
            )
            existing = self._request_result(
                connection,
                request_id=request_id,
                operation="prove",
                input_hash=input_hash,
            )
            if existing is not None:
                return existing
            _expire_pending_credentials(
                connection, now=verified_at, agent_id=identity.agent.id
            )
            if (
                identity.agent.id != expected_agent_id
                or identity.agent.name != expected_agent_name
            ):
                raise CredentialConflictError("expected identity did not match")
            _require_provable_credential(
                connection, identity,
                expected_credential_epoch=expected_credential_epoch,
                expected_credential_version=expected_credential_version,
            )
            _require_active_capacity(connection, identity.agent.id, max_active)
            updated = connection.execute(
                """
                UPDATE agent_credentials
                SET status = 'active', activated_at = ?,
                    identity_verified_at = ?, version = version + 1
                WHERE id = ? AND status = 'pending' AND version = ?
                """,
                (
                    timestamp,
                    timestamp,
                    identity.credential.id,
                    expected_credential_version,
                ),
            )
            if updated.rowcount != 1:
                raise CredentialConflictError("credential lifecycle state changed")
            _advance_credential_epoch(
                connection, agent_id=identity.agent.id, request_id=request_id,
                actor_type="agent", actor_id=identity.credential.id,
                reason="expected stable identity matched", timestamp=timestamp,
            )
            connection.execute(
                """
                INSERT INTO agent_credential_requests (
                    request_id, operation, input_sha256, agent_id,
                    result_credential_id, created_at
                )
                VALUES (?, 'prove', ?, ?, ?, ?)
                """,
                (
                    request_id,
                    input_hash,
                    identity.agent.id,
                    identity.credential.id,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO agent_credential_audit (
                    id, event_type, agent_id, credential_id,
                    actor_type, actor_id, method, reason, request_id, occurred_at
                )
                VALUES (?, 'prove', ?, ?, 'agent', ?, 'identity-proof',
                        'expected stable identity matched', ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    identity.agent.id,
                    identity.credential.id,
                    identity.credential.id,
                    request_id,
                    timestamp,
                ),
            )
            row = connection.execute(
                _CREDENTIAL_SELECT + " WHERE id = ?",
                (identity.credential.id,),
            ).fetchone()
        if row is None:
            raise StorageError("proved credential could not be read back")
        return _credential_from_row(row)

    def retire_credential(
        self,
        *,
        identity: AuthenticatedIdentity,
        credential_id: str,
        request_id: str,
        expected_credential_epoch: int,
        expected_credential_version: int,
        reason: str,
        retired_at: datetime,
    ) -> AgentCredential:
        input_hash = _lifecycle_input_hash(
            "retire",
            identity.agent.id,
            identity.credential.id,
            credential_id,
            expected_credential_epoch,
            expected_credential_version,
            reason,
        )
        timestamp = _format_utc(retired_at)
        with self._transaction() as connection:
            _require_active_credential(
                connection, identity.agent.id, identity.credential.id,
            )
            existing = self._request_result(
                connection,
                request_id=request_id,
                operation="retire",
                input_hash=input_hash,
            )
            if existing is not None:
                return existing
            _require_active_credential(
                connection, identity.agent.id, identity.credential.id
            )
            _require_retirable_predecessor(
                connection, identity, credential_id,
                expected_credential_epoch=expected_credential_epoch,
                expected_credential_version=expected_credential_version,
            )
            connection.execute(
                """
                UPDATE agent_credentials
                SET status = 'retired', retired_at = ?, version = version + 1
                WHERE id = ? AND status = 'active' AND version = ?
                """,
                (timestamp, credential_id, expected_credential_version),
            )
            _advance_credential_epoch(
                connection, agent_id=identity.agent.id, request_id=request_id,
                actor_type="agent", actor_id=identity.credential.id,
                reason=reason, timestamp=timestamp,
            )
            self._record_terminal_request(
                connection,
                request_id=request_id,
                operation="retire",
                input_hash=input_hash,
                agent_id=identity.agent.id,
                credential_id=credential_id,
                event_type="retire",
                actor_type="agent",
                actor_id=identity.credential.id,
                method="rotation-retirement",
                reason=reason,
                occurred_at=timestamp,
                related_credential_id=identity.credential.id,
            )
            row = connection.execute(
                _CREDENTIAL_SELECT + " WHERE id = ?", (credential_id,)
            ).fetchone()
        if row is None:
            raise StorageError("retired credential could not be read back")
        return _credential_from_row(row)

    def _record_terminal_request(
        self,
        connection: sqlite3.Connection,
        *,
        request_id: str,
        operation: str,
        input_hash: str,
        agent_id: str,
        credential_id: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        method: str,
        reason: str,
        occurred_at: str,
        related_credential_id: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO agent_credential_requests (
                request_id, operation, input_sha256, agent_id,
                result_credential_id, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                operation,
                input_hash,
                agent_id,
                credential_id,
                occurred_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO agent_credential_audit (
                id, event_type, agent_id, credential_id,
                related_credential_id, actor_type, actor_id,
                method, reason, request_id, occurred_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                event_type,
                agent_id,
                credential_id,
                related_credential_id,
                actor_type,
                actor_id,
                method,
                reason,
                request_id,
                occurred_at,
            ),
        )

    def revoke_credential(
        self,
        *,
        agent_id: str,
        credential_id: str,
        request_id: str,
        expected_credential_epoch: int,
        expected_credential_version: int,
        reason: str,
        actor_type: str,
        actor_id: str,
        revoked_at: datetime,
    ) -> AgentCredential:
        _validate_actor(LifecycleActor(actor_type, actor_id))
        input_hash = _lifecycle_input_hash(
            "revoke",
            agent_id,
            credential_id,
            expected_credential_epoch,
            expected_credential_version,
            reason,
        )
        timestamp = _format_utc(revoked_at)
        with self._transaction() as connection:
            # Revocation is containment. It must stay available to a human
            # while frozen: without it the freeze would prevent the very action
            # it exists to enable.
            if actor_type not in _HUMAN_ACTOR_TYPES:
                _require_agent_access(connection)
            existing = self._request_result(
                connection,
                request_id=request_id,
                operation="revoke",
                input_hash=input_hash,
            )
            if existing is not None:
                return existing
            agent = _agent_epoch_row(connection, agent_id)
            target = _credential_state_row(connection, agent_id, credential_id)
            if not _live_agent_epoch_matches(
                agent, expected_credential_epoch,
            ) or not _credential_state_matches(
                target, _LIVE_CREDENTIAL_STATUSES, expected_credential_version,
            ):
                raise CredentialConflictError("credential lifecycle state changed")
            connection.execute(
                """
                UPDATE agent_credentials
                SET status = 'revoked', revoked_at = ?, version = version + 1
                WHERE id = ? AND status IN ('pending', 'active') AND version = ?
                """,
                (timestamp, credential_id, expected_credential_version),
            )
            _advance_credential_epoch(
                connection, agent_id=agent_id, request_id=request_id,
                actor_type=actor_type, actor_id=actor_id, reason=reason, timestamp=timestamp,
            )
            self._record_terminal_request(
                connection,
                request_id=request_id,
                operation="revoke",
                input_hash=input_hash,
                agent_id=agent_id,
                credential_id=credential_id,
                event_type="revoke",
                actor_type=actor_type,
                actor_id=actor_id,
                method="targeted-revocation",
                reason=reason,
                occurred_at=timestamp,
            )
            row = connection.execute(
                _CREDENTIAL_SELECT + " WHERE id = ?", (credential_id,)
            ).fetchone()
        if row is None:
            raise StorageError("revoked credential could not be read back")
        return _credential_from_row(row)

    def recover_credential(
        self,
        *,
        agent_id: str,
        credential_id: str,
        secret_hash: str,
        request_id: str,
        expected_credential_epoch: int,
        reason: str,
        actor_type: str,
        actor_id: str,
        created_at: datetime,
        pending_expires_at: datetime,
    ) -> tuple[AgentCredential, bool]:
        _validate_actor(LifecycleActor(actor_type, actor_id))
        input_hash = _lifecycle_input_hash(
            "recover", agent_id, expected_credential_epoch, reason
        )
        timestamp = _format_utc(created_at)
        expires = _format_utc(pending_expires_at)
        with self._transaction() as connection:
            # Recovery issues a fresh credential, so it stays denied while
            # frozen for everything except the protected local CLI, which is
            # the recovery path of last resort.
            if actor_type != "local-admin":
                _require_agent_access(connection)
            existing = self._request_result(
                connection,
                request_id=request_id,
                operation="recover",
                input_hash=input_hash,
            )
            if existing is not None:
                return existing, False
            agent = _agent_epoch_row(connection, agent_id)
            if not _live_agent_epoch_matches(agent, expected_credential_epoch):
                raise CredentialConflictError("credential lifecycle state changed")
            _insert_pending_credential(
                connection, agent_id=agent_id, credential_id=credential_id,
                secret_hash=secret_hash, method="recover", reason=reason,
                request_id=request_id, timestamp=timestamp, expires_at=expires,
            )
            _revoke_live_credentials(
                connection, agent_id=agent_id, request_id=request_id,
                actor_type=actor_type, actor_id=actor_id, reason=reason,
                timestamp=timestamp, event_type="recover", method="admin-recovery",
                related_credential_id=credential_id, exclude_credential_id=credential_id,
            )
            _advance_credential_epoch(
                connection, agent_id=agent_id, request_id=request_id,
                actor_type=actor_type, actor_id=actor_id, reason=reason, timestamp=timestamp,
            )
            connection.execute(
                """
                INSERT INTO agent_credential_requests (
                    request_id, operation, input_sha256, agent_id,
                    result_credential_id, created_at
                )
                VALUES (?, 'recover', ?, ?, ?, ?)
                """,
                (request_id, input_hash, agent_id, credential_id, timestamp),
            )
            connection.execute(
                """
                INSERT INTO agent_credential_audit (
                    id, event_type, agent_id, credential_id,
                    actor_type, actor_id, method, reason, request_id, occurred_at
                )
                VALUES (?, 'recover', ?, ?, ?, ?, 'admin-recovery', ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    agent_id,
                    credential_id,
                    actor_type,
                    actor_id,
                    reason,
                    request_id,
                    timestamp,
                ),
            )
            row = connection.execute(
                _CREDENTIAL_SELECT + " WHERE id = ?", (credential_id,)
            ).fetchone()
        if row is None:
            raise StorageError("recovery credential could not be read back")
        return _credential_from_row(row), True

    def revoke_agent(
        self,
        agent_id: str,
        *,
        revoked_at: datetime,
        request_id: str,
        actor_type: str = "remote-admin",
        actor_id: str = "admin",
        reason: str = "stable agent revoked",
        expected_credential_epoch: int | None = None,
    ) -> Agent:
        actor = LifecycleActor(actor_type, actor_id)
        _validate_actor(actor)
        current = self.get_managed_agent(agent_id, require_access=actor_type not in _HUMAN_ACTOR_TYPES)
        if expected_credential_epoch is None:
            if current.revoked_at is not None:
                return current
            expected_credential_epoch = current.credential_epoch
        self.transition_agent(
            agent_id, action="retire", expected_credential_epoch=expected_credential_epoch,
            request_id=request_id, reason=reason, actor=actor, changed_at=revoked_at,
        )
        return self.get_managed_agent(agent_id, require_access=actor_type not in _HUMAN_ACTOR_TYPES)
