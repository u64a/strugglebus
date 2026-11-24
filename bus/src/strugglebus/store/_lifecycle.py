from __future__ import annotations

import hmac
import re
import sqlite3
import uuid
from datetime import datetime
from collections.abc import Callable

from strugglebus.errors import (
    AgentNotFoundError,
    CredentialConflictError,
    CredentialLimitError,
    CredentialNotFoundError,
    DomainValidationError,
)
from strugglebus.models import (
    Agent,
    AgentCredential,
    AgentLifecycleEvent,
    AgentLifecycleResult,
    AgentReconnectGrant,
    LifecycleActor,
)
from strugglebus.store._common import (
    SYSTEM_AUTHOR_IDS,
    _AGENT_SELECT,
    _CREDENTIAL_SELECT,
    _DUMMY_KEY_HASH,
    _HUMAN_ACTOR_TYPES,
    _LIFECYCLE_TRANSITION_STATES,
    _advance_credential_epoch,
    _agent_from_row,
    _audit_text,
    _canonical_request_id,
    _checked_transition_agent,
    _credential_from_row,
    _format_utc,
    _grant_from_row,
    _insert_pending_credential,
    _invalidate_reconnect_grants,
    _lifecycle_event_from_row,
    _lifecycle_input_hash,
    _record_lifecycle_event,
    _require_agent_access,
    _revoke_live_credentials,
    _validate_actor,
    _validate_expected_epoch,
)


def _validate_reconnect_issuance(
    *, max_outstanding: int, lifetime: float, grant_id: str, secret_hash: str,
) -> None:
    if (type(max_outstanding) is not int or not 1 <= max_outstanding <= 1024
            or not 0 < lifetime <= 900
            or re.fullmatch(r"rcg_[A-Za-z0-9_-]{22}", grant_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", secret_hash) is None):
        raise DomainValidationError("invalid reconnect issuance")


def _require_reconnectable_agent(
    connection: sqlite3.Connection,
    agent_id: str,
    *,
    expected_agent_name: str,
    expected_credential_epoch: int,
) -> Agent:
    """The enabled agent the operator prepared the grant for, unchanged since."""

    row = connection.execute(_AGENT_SELECT + " WHERE id = ?", (agent_id,)).fetchone()
    if row is None:
        raise AgentNotFoundError("agent is unavailable")
    agent = _agent_from_row(row)
    if (agent.name != expected_agent_name or agent.state != "enabled"
            or agent.credential_epoch != expected_credential_epoch):
        raise CredentialConflictError("agent lifecycle state changed")
    return agent


def _require_reconnect_capacity(
    connection: sqlite3.Connection,
    agent_id: str,
    *,
    timestamp: str,
    max_outstanding: int,
) -> None:
    count = connection.execute(
        "SELECT COUNT(*) FROM (SELECT 1 FROM agent_reconnect_grants "
        "WHERE status = 'pending' AND expires_at > ? AND agent_id <> ? LIMIT ?)",
        (timestamp, agent_id, max_outstanding),
    ).fetchone()[0]
    if count >= max_outstanding:
        raise CredentialLimitError("reconnect grant capacity reached")


def _validate_reconnect_credential(
    *,
    redeemed_at: datetime,
    pending_expires_at: datetime,
    credential_id: str,
    secret_hash: str,
) -> None:
    if (pending_expires_at <= redeemed_at
            or re.fullmatch(r"cred_[A-Za-z0-9_-]{22}", credential_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", secret_hash) is None):
        raise DomainValidationError("invalid reconnect credential")


class LifecycleMixin:
    def list_agents(self) -> tuple[Agent, ...]:
        """Managed/local compatibility roster, including blocked identities."""
        with self._read_transaction() as connection:
            rows = connection.execute(
                _AGENT_SELECT
                + """
                WHERE revoked_at IS NULL AND id NOT IN (?, ?)
                ORDER BY name
                """,
                SYSTEM_AUTHOR_IDS,
            ).fetchall()
        return tuple(_agent_from_row(row) for row in rows)

    def list_enabled_agents(self, *, require_access: bool = True) -> tuple[Agent, ...]:
        """List agents visible for discovery.

        Shared by the agent roster and the monitor's read surface. The default
        keeps the agent plane fail-closed; the monitor passes
        ``require_access=False`` because a human watching an incident needs to
        see who is on the board precisely when it is frozen.
        """

        with self._read_transaction() as connection:
            if require_access:
                _require_agent_access(connection)
            rows = connection.execute(
                _AGENT_SELECT
                + " WHERE revoked_at IS NULL AND blocked_at IS NULL AND id NOT IN (?, ?) ORDER BY name",
                SYSTEM_AUTHOR_IDS,
            ).fetchall()
        return tuple(_agent_from_row(row) for row in rows)

    def get_managed_agent(self, agent_id: str, *, require_access: bool = True) -> Agent:
        if agent_id in SYSTEM_AUTHOR_IDS:
            raise AgentNotFoundError("agent is unavailable")
        with self._read_transaction() as connection:
            if require_access:
                _require_agent_access(connection)
            row = connection.execute(_AGENT_SELECT + " WHERE id = ?", (agent_id,)).fetchone()
        if row is None:
            raise AgentNotFoundError("agent is unavailable")
        return _agent_from_row(row)

    def list_managed_agents(
        self, *, state: str = "managed", after_name: str | None = None,
        limit: int = 100, require_access: bool = True,
    ) -> tuple[Agent, ...]:
        filters = {
            "managed": "revoked_at IS NULL",
            "enabled": "revoked_at IS NULL AND blocked_at IS NULL",
            "blocked": "revoked_at IS NULL AND blocked_at IS NOT NULL",
            "retired": "revoked_at IS NOT NULL",
            "all": "1 = 1",
        }
        if state not in filters or type(limit) is not int or not 1 <= limit <= 200:
            raise DomainValidationError("invalid managed roster query")
        if after_name is not None:
            _audit_text(after_name, maximum=128)
        with self._read_transaction() as connection:
            if require_access:
                _require_agent_access(connection)
            rows = connection.execute(
                _AGENT_SELECT + " WHERE " + filters[state]
                + " AND id NOT IN (?, ?) AND name > ? ORDER BY name LIMIT ?",
                (*SYSTEM_AUTHOR_IDS, after_name or "", limit),
            ).fetchall()
        return tuple(_agent_from_row(row) for row in rows)

    def list_agent_lifecycle_events(
        self, agent_id: str, *, after_seq: int = 0, limit: int = 100,
        require_access: bool = True,
    ) -> tuple[AgentLifecycleEvent, ...]:
        if (type(after_seq) is not int or not 0 <= after_seq < 2**63
                or type(limit) is not int or not 1 <= limit <= 200):
            raise DomainValidationError("invalid lifecycle history query")
        with self._read_transaction() as connection:
            if require_access:
                _require_agent_access(connection)
            rows = connection.execute(
                "SELECT * FROM agent_lifecycle_audit WHERE agent_id = ? AND seq > ? "
                "ORDER BY seq LIMIT ?", (agent_id, after_seq, limit),
            ).fetchall()
        return tuple(_lifecycle_event_from_row(row) for row in rows)

    def _lifecycle_request_result(
        self, connection: sqlite3.Connection, *, request_id: str, intent_sha256: str,
    ) -> AgentLifecycleEvent | None:
        row = connection.execute(
            "SELECT * FROM agent_lifecycle_audit WHERE request_id = ? AND action IN "
            "('block', 'unblock', 'retire', 'reconnect-issue', 'reconnect-redeem')",
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        if row["intent_sha256"] != intent_sha256:
            raise CredentialConflictError("lifecycle request id is already in use")
        return _lifecycle_event_from_row(row)

    def transition_agent(
        self, agent_id: str, *, action: str, expected_credential_epoch: int,
        request_id: str, reason: str, actor: LifecycleActor, changed_at: datetime,
    ) -> AgentLifecycleResult:
        if action not in _LIFECYCLE_TRANSITION_STATES:
            raise DomainValidationError("invalid agent lifecycle action")
        _canonical_request_id(request_id)
        _validate_expected_epoch(expected_credential_epoch)
        _audit_text(reason)
        _validate_actor(actor)
        digest = _lifecycle_input_hash(
            action, agent_id, expected_credential_epoch, reason,
            actor.actor_type, actor.actor_id,
        )
        timestamp = _format_utc(changed_at)
        with self._transaction() as connection:
            _validate_actor(actor)
            # Containment remains available to humans; restoring access does not.
            if action == "unblock" or actor.actor_type not in _HUMAN_ACTOR_TYPES:
                _require_agent_access(connection)
            previous = self._lifecycle_request_result(
                connection, request_id=request_id, intent_sha256=digest,
            )
            if previous is not None:
                return AgentLifecycleResult(previous, False)
            agent = _checked_transition_agent(
                connection, agent_id, action, expected_credential_epoch,
            )
            _invalidate_reconnect_grants(
                connection, agent=agent, request_id=request_id,
                actor_type=actor.actor_type, actor_id=actor.actor_id,
                reason=reason, timestamp=timestamp,
            )
            if action == "retire":
                _revoke_live_credentials(
                    connection, agent_id=agent_id, request_id=request_id,
                    actor_type=actor.actor_type, actor_id=actor.actor_id,
                    reason=reason, timestamp=timestamp,
                    event_type="agent-revoke", method="agent-revocation",
                )
            state = {"block": "blocked", "unblock": "enabled", "retire": "retired"}[action]
            connection.execute(
                "UPDATE agents SET blocked_at = ?, revoked_at = ?, "
                "credential_epoch = credential_epoch + 1 WHERE id = ? AND credential_epoch = ?",
                (timestamp if action == "block" else None,
                 timestamp if action == "retire" else None, agent_id, expected_credential_epoch),
            )
            event = _record_lifecycle_event(
                connection, agent=agent, action=action, request_id=request_id,
                intent_sha256=digest, actor_type=actor.actor_type, actor_id=actor.actor_id,
                reason=reason, timestamp=timestamp, resulting_state=state,
            )
        return AgentLifecycleResult(event, True)

    def issue_reconnect_grant(
        self, *, agent_id: str, expected_agent_name: str, expected_credential_epoch: int,
        request_id: str, reason: str, actor: LifecycleActor,
        grant_id: str, secret_hash: str, created_at: datetime, expires_at: datetime,
        checked_at: datetime, max_outstanding: int = 256,
        clock: Callable[[], datetime] | None = None,
    ) -> tuple[AgentReconnectGrant, bool]:
        _canonical_request_id(request_id)
        _validate_expected_epoch(expected_credential_epoch)
        _audit_text(reason)
        _audit_text(expected_agent_name, maximum=128)
        _validate_actor(actor, operator_only=True)
        lifetime = (expires_at - created_at).total_seconds()
        _validate_reconnect_issuance(
            max_outstanding=max_outstanding, lifetime=lifetime,
            grant_id=grant_id, secret_hash=secret_hash,
        )
        digest = _lifecycle_input_hash(
            "reconnect-issue", agent_id, expected_agent_name, expected_credential_epoch,
            reason, actor.actor_type, actor.actor_id, lifetime,
        )
        timestamp = _format_utc(checked_at)
        with self._transaction() as connection:
            checked_at = clock() if clock is not None else checked_at
            timestamp = _format_utc(checked_at)
            _validate_actor(actor, operator_only=True)
            _require_agent_access(connection)
            previous = self._lifecycle_request_result(
                connection, request_id=request_id, intent_sha256=digest,
            )
            if previous is not None:
                row = connection.execute(
                    "SELECT * FROM agent_reconnect_grants WHERE id = ?", (previous.grant_id,)
                ).fetchone()
                return _grant_from_row(row), False
            if not created_at <= checked_at < expires_at:
                raise CredentialConflictError("prepared reconnect grant expired")
            agent = _require_reconnectable_agent(
                connection, agent_id, expected_agent_name=expected_agent_name,
                expected_credential_epoch=expected_credential_epoch,
            )
            _require_reconnect_capacity(
                connection, agent_id, timestamp=timestamp,
                max_outstanding=max_outstanding,
            )
            _advance_credential_epoch(
                connection, agent_id=agent_id, request_id=request_id,
                actor_type=actor.actor_type, actor_id=actor.actor_id,
                reason=reason, timestamp=timestamp,
            )
            _revoke_live_credentials(
                connection, agent_id=agent_id, request_id=request_id,
                actor_type=actor.actor_type, actor_id=actor.actor_id,
                reason=reason, timestamp=timestamp, event_type="revoke",
                method="reconnect-cutoff",
            )
            connection.execute(
                """
                INSERT INTO agent_reconnect_grants (
                    id, agent_id, secret_hash, issuance_request_id, intent_sha256,
                    bound_epoch, status, created_at, expires_at, actor_type, actor_id, reason)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
                """,
                (grant_id, agent_id, secret_hash, request_id, digest,
                 agent.credential_epoch + 1, _format_utc(created_at), _format_utc(expires_at),
                 actor.actor_type, actor.actor_id, reason),
            )
            _record_lifecycle_event(
                connection, agent=agent, action="reconnect-issue", request_id=request_id,
                intent_sha256=digest, actor_type=actor.actor_type, actor_id=actor.actor_id,
                reason=reason, timestamp=timestamp, grant_id=grant_id,
            )
            row = connection.execute(
                "SELECT * FROM agent_reconnect_grants WHERE id = ?", (grant_id,),
            ).fetchone()
        return _grant_from_row(row), True

    def _verified_reconnect_grant(
        self, connection: sqlite3.Connection, *, grant_id: str, candidate_digest: str,
        checked_at: datetime,
    ) -> tuple[sqlite3.Row, Agent] | None:
        row = connection.execute(
            "SELECT * FROM agent_reconnect_grants WHERE id = ?", (grant_id,),
        ).fetchone()
        if (not hmac.compare_digest(
                candidate_digest, _DUMMY_KEY_HASH if row is None else row["secret_hash"])
                or row is None):
            return None
        _require_agent_access(connection)
        agent = _agent_from_row(connection.execute(
            _AGENT_SELECT + " WHERE id = ?", (row["agent_id"],),
        ).fetchone())
        if row["status"] != "pending" or agent.state != "enabled":
            return None
        if row["expires_at"] <= _format_utc(checked_at):
            _invalidate_reconnect_grants(
                connection, agent=agent, request_id=str(uuid.uuid4()),
                actor_type="system", actor_id="system:reconnect-expiry",
                reason="reconnect grant lifetime elapsed", timestamp=_format_utc(checked_at),
            )
            return None
        if row["bound_epoch"] != agent.credential_epoch:
            return None
        return row, agent

    def verify_reconnect_grant(
        self, *, grant_id: str, candidate_digest: str, checked_at: datetime,
        clock: Callable[[], datetime] | None = None,
    ) -> AgentReconnectGrant | None:
        with self._transaction() as connection:
            verified = self._verified_reconnect_grant(
                connection, grant_id=grant_id, candidate_digest=candidate_digest,
                checked_at=clock() if clock is not None else checked_at,
            )
        return None if verified is None else _grant_from_row(verified[0])

    def get_reconnect_grant(
        self, agent_id: str, grant_id: str, *, require_access: bool = True,
    ) -> AgentReconnectGrant:
        with self._read_transaction() as connection:
            if require_access:
                _require_agent_access(connection)
            row = connection.execute(
                "SELECT * FROM agent_reconnect_grants WHERE id = ? AND agent_id = ?",
                (grant_id, agent_id),
            ).fetchone()
        if row is None:
            raise CredentialNotFoundError("reconnect grant is unavailable")
        return _grant_from_row(row)

    def redeem_reconnect_grant(
        self, *, grant_id: str, candidate_digest: str, expected_agent_id: str,
        expected_agent_name: str, request_id: str, credential_id: str,
        secret_hash: str, redeemed_at: datetime, pending_expires_at: datetime,
        clock: Callable[[], datetime] | None = None,
    ) -> tuple[Agent, AgentCredential, AgentReconnectGrant]:
        _canonical_request_id(request_id)
        _audit_text(expected_agent_id, maximum=128)
        _audit_text(expected_agent_name, maximum=128)
        _validate_reconnect_credential(
            redeemed_at=redeemed_at, pending_expires_at=pending_expires_at,
            credential_id=credential_id, secret_hash=secret_hash,
        )
        timestamp = _format_utc(redeemed_at)
        pending_lifetime = pending_expires_at - redeemed_at
        with self._transaction() as connection:
            redeemed_at = clock() if clock is not None else redeemed_at
            timestamp = _format_utc(redeemed_at)
            pending_expires_at = redeemed_at + pending_lifetime
            verified = self._verified_reconnect_grant(
                connection, grant_id=grant_id, candidate_digest=candidate_digest,
                checked_at=redeemed_at,
            )
            if verified is not None:
                grant, agent = verified
                agent_row, credential_row, grant_row = self._redeem_verified_grant(
                    connection, grant, agent, grant_id=grant_id,
                    expected_agent_id=expected_agent_id,
                    expected_agent_name=expected_agent_name, request_id=request_id,
                    credential_id=credential_id, secret_hash=secret_hash,
                    timestamp=timestamp, pending_expires_at=pending_expires_at,
                )
        # Raised only after the transaction commits, so an expiry recorded
        # while verifying the grant is kept.
        if verified is None:
            raise CredentialNotFoundError("reconnect grant is unavailable")
        return (_agent_from_row(agent_row), _credential_from_row(credential_row),
                _grant_from_row(grant_row))

    def _redeem_verified_grant(
        self, connection: sqlite3.Connection, grant: sqlite3.Row, agent: Agent, *,
        grant_id: str, expected_agent_id: str, expected_agent_name: str,
        request_id: str, credential_id: str, secret_hash: str, timestamp: str,
        pending_expires_at: datetime,
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        """Spend a verified grant on one pending credential for its agent.

        Returns the agent, credential and grant rows as the redemption left them.
        """

        if agent.id != expected_agent_id or agent.name != expected_agent_name:
            raise CredentialNotFoundError("reconnect grant is unavailable")
        if (connection.execute(
                "SELECT 1 FROM agent_lifecycle_audit WHERE request_id = ? "
                "UNION ALL SELECT 1 FROM agent_credential_requests WHERE request_id = ?",
                (request_id, request_id)).fetchone() is not None):
            raise CredentialNotFoundError("reconnect grant is unavailable")
        actor_id = f"reconnect:{grant_id}"
        reason = "single-use reconnect redemption"
        _insert_pending_credential(
            connection, agent_id=agent.id, credential_id=credential_id,
            secret_hash=secret_hash, request_id=request_id, method="reconnect",
            reason=reason, timestamp=timestamp, expires_at=_format_utc(pending_expires_at),
        )
        updated = connection.execute(
            "UPDATE agent_reconnect_grants SET status = 'redeemed', redeemed_at = ?, "
            "redemption_request_id = ?, result_credential_id = ?, version = version + 1 "
            "WHERE id = ? AND status = 'pending' AND version = ?",
            (timestamp, request_id, credential_id, grant_id, grant["version"]),
        )
        if updated.rowcount != 1:
            raise CredentialNotFoundError("reconnect grant is unavailable")
        _advance_credential_epoch(
            connection, agent_id=agent.id, request_id=request_id,
            actor_type="reconnect-grant", actor_id=actor_id,
            reason=reason, timestamp=timestamp,
        )
        digest = _lifecycle_input_hash(
            "reconnect-redeem", grant_id, agent.id, agent.name, agent.credential_epoch,
        )
        self._record_terminal_request(
            connection, request_id=request_id, operation="reconnect",
            input_hash=digest, agent_id=agent.id, credential_id=credential_id,
            event_type="issue", actor_type="system", actor_id=actor_id,
            method="reconnect", reason=reason, occurred_at=timestamp,
        )
        _record_lifecycle_event(
            connection, agent=agent, action="reconnect-redeem",
            request_id=request_id, intent_sha256=digest,
            actor_type="reconnect-grant", actor_id=actor_id,
            reason=reason, timestamp=timestamp, grant_id=grant_id,
        )
        agent_row = connection.execute(_AGENT_SELECT + " WHERE id = ?", (agent.id,)).fetchone()
        credential_row = connection.execute(
            _CREDENTIAL_SELECT + " WHERE id = ?", (credential_id,),
        ).fetchone()
        grant_row = connection.execute(
            "SELECT * FROM agent_reconnect_grants WHERE id = ?", (grant_id,),
        ).fetchone()
        return agent_row, credential_row, grant_row

    def get_active_agent(self, agent_id: str) -> Agent:
        """Compatibility managed lookup; non-retired is not permission to operate."""
        with self._read_transaction() as connection:
            row = connection.execute(
                _AGENT_SELECT
                + """
                WHERE id = ? AND revoked_at IS NULL
                """,
                (agent_id,),
            ).fetchone()
        if row is None:
            raise AgentNotFoundError("authenticated agent is unavailable")
        return _agent_from_row(row)

    def get_active_agent_by_name(self, name: str) -> Agent:
        """Protected human remediation also needs to find blocked identities."""
        with self._read_transaction() as connection:
            row = connection.execute(
                _AGENT_SELECT
                + """
                WHERE name = ? AND revoked_at IS NULL
                """,
                (name,),
            ).fetchone()
        if row is None:
            raise AgentNotFoundError(f"agent {name!r} was not found")
        return _agent_from_row(row)
