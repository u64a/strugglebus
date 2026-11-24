from __future__ import annotations

import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timedelta

from strugglebus.errors import (
    AgentNotFoundError,
    DuplicateAgentNameError,
    CredentialConflictError,
    CredentialLimitError,
    CredentialNotFoundError,
    DomainValidationError,
    ServicePrincipalNotFoundError,
    StorageError,
)
from strugglebus.models import (
    LifecycleActor,
    OnboardingIssuance,
    ServicePrincipal,
    ServicePrincipalIdentity,
)
from strugglebus.store._common import (
    _DUMMY_KEY_HASH,
    _SPN_SELECT,
    _canonical_request_id,
    _format_utc,
    _lifecycle_input_hash,
    _parse_utc,
    _require_agent_access,
    _retire_agent,
    _spn_from_row,
    _validate_actor,
    utc_now,
)

#: Bounds one sweep so a backlog of expired identities cannot stall a request;
#: the next issue or retire by the same SPN continues it.
_EXPIRY_SWEEP_LIMIT = 100
#: After a self-rotation the predecessor keeps working this long, so a host
#: whose rotate response was lost can still rotate again.
SELF_ROTATION_OVERLAP = timedelta(seconds=60)


def _require_active_spn(
    connection: sqlite3.Connection, identity: ServicePrincipalIdentity,
) -> None:
    principal = connection.execute(
        """
        SELECT p.status, p.agent_name_prefix
        FROM spn_principals AS p
        JOIN spn_credentials AS c ON c.spn_id = p.id
        WHERE p.id = ? AND c.id = ?
          AND (c.status = 'active' OR (c.status = 'revoked' AND c.revoked_at > ?))
        """,
        (identity.spn_id, identity.credential_id, _format_utc(utc_now())),
    ).fetchone()
    if (
        principal is None
        or principal["status"] != "enabled"
        or principal["agent_name_prefix"] != identity.agent_name_prefix
    ):
        raise CredentialNotFoundError("SPN credential is unavailable")


def _retire_spn_identities(
    connection: sqlite3.Connection,
    spn_id: str,
    timestamp: str,
    *,
    reason: str,
    expired_only: bool,
) -> None:
    """Retire this SPN's live time-limited identities: the expired ones, or all."""

    query = """
        SELECT a.id FROM agents AS a
        JOIN agent_identity_provenance AS p ON p.agent_id = a.id
        WHERE p.creator_principal_type = 'spn' AND p.creator_principal_id = ?
          AND a.revoked_at IS NULL AND a.expires_at IS NOT NULL
    """
    parameters: list[object] = [spn_id]
    if expired_only:
        query += " AND a.expires_at <= ? ORDER BY a.expires_at, a.id LIMIT ?"
        parameters += [timestamp, _EXPIRY_SWEEP_LIMIT]
    for row in connection.execute(query, parameters).fetchall():
        request_id = str(uuid.uuid4())
        _retire_agent(
            connection, agent_id=row["id"], request_id=request_id,
            intent_sha256=_lifecycle_input_hash(
                "spn-identity-sweep", spn_id, row["id"], request_id,
            ),
            actor_type="system", actor_id=f"spn:{spn_id}", reason=reason,
            timestamp=timestamp,
        )

_SPN_TRANSITION_STATUS = {"block": "blocked", "unblock": "enabled", "revoke": "revoked"}
_SPN_TRANSITION_EVENT = {"block": "blocked", "unblock": "unblocked", "revoke": "revoked"}


def _is_duplicate_spn_name(error: StorageError) -> bool:
    return (
        isinstance(error.__cause__, sqlite3.IntegrityError)
        and "spn_principals.name" in str(error.__cause__)
    )


def _spn_request(
    connection: sqlite3.Connection, request_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT operation, intent_sha256, spn_id, result_credential_id
        FROM spn_requests WHERE request_id = ?
        """,
        (request_id,),
    ).fetchone()


def _replayed_spn_request(
    connection: sqlite3.Connection, existing: sqlite3.Row,
) -> tuple[ServicePrincipal, str]:
    """The principal and credential id an earlier identical request produced."""

    row = connection.execute(
        _SPN_SELECT + " WHERE id = ?", (existing["spn_id"],),
    ).fetchone()
    if row is None:
        raise StorageError("SPN request result is unavailable")
    return _spn_from_row(row), existing["result_credential_id"]


def _require_rotatable_spn(
    connection: sqlite3.Connection, spn_id: str, expected_version: int,
) -> None:
    row = connection.execute(
        _SPN_SELECT + " WHERE id = ?", (spn_id,),
    ).fetchone()
    if row is None:
        raise ServicePrincipalNotFoundError(
            "service principal does not exist"
        )
    if row["status"] != "enabled" or int(row["version"]) != expected_version:
        raise CredentialConflictError("service principal state changed")


def _replayed_spn_transition(
    connection: sqlite3.Connection,
    existing: sqlite3.Row,
    *,
    spn_id: str,
    action: str,
    expected_version: int,
    intent: str,
) -> ServicePrincipal:
    """The principal as an earlier identical transition request left it."""

    if (
        existing["spn_id"] != spn_id
        or existing["action"] != action
        or int(existing["expected_version"]) != expected_version
        or existing["intent_sha256"] != intent
    ):
        raise CredentialConflictError(
            "SPN request id is already in use"
        )
    principal = connection.execute(
        _SPN_SELECT + " WHERE id = ?", (spn_id,),
    ).fetchone()
    if principal is None:
        raise StorageError("SPN transition result is unavailable")
    created_at = _parse_utc(principal["created_at"])
    if created_at is None:
        raise StorageError("SPN creation time is unavailable")
    return ServicePrincipal(
        id=principal["id"],
        name=principal["name"],
        agent_name_prefix=principal["agent_name_prefix"],
        status=existing["result_status"],
        created_at=created_at,
        blocked_at=_parse_utc(existing["result_blocked_at"]),
        revoked_at=_parse_utc(existing["result_revoked_at"]),
        version=int(existing["result_version"]),
    )


def _require_spn_transition_allowed(
    row: sqlite3.Row, action: str, expected_version: int,
) -> None:
    expected_state = {"block": "enabled", "unblock": "blocked"}
    if action == "revoke":
        allowed = row["status"] in {"enabled", "blocked"}
    else:
        allowed = row["status"] == expected_state[action]
    if int(row["version"]) != expected_version or not allowed:
        raise CredentialConflictError("service principal state changed")


def _apply_spn_transition(
    connection: sqlite3.Connection,
    spn_id: str,
    *,
    action: str,
    expected_version: int,
    timestamp: str,
) -> None:
    """Move the principal to its new state and contain what it had issued.

    Blocking or revoking withdraws its unredeemed packages and retires the
    time-limited identities it created; revoking also ends its credentials.
    """

    new_status = _SPN_TRANSITION_STATUS[action]
    connection.execute(
        """
        UPDATE spn_principals
        SET status = ?,
            blocked_at = CASE
                WHEN ? = 'blocked' THEN ?
                WHEN ? = 'enabled' THEN NULL
                ELSE blocked_at
            END,
            revoked_at = CASE WHEN ? = 'revoked' THEN ? ELSE NULL END,
            version = version + 1
        WHERE id = ? AND version = ?
        """,
        (
            new_status, new_status, timestamp, new_status, new_status,
            timestamp, spn_id, expected_version,
        ),
    )
    if action in {"block", "revoke"}:
        connection.execute(
            """
            UPDATE agent_enrollments
            SET status = 'revoked', uses_remaining = 0, revoked_at = ?,
                revocation_reason = ?, version = version + 1
            WHERE spn_id = ? AND status = 'pending'
            """,
            (timestamp, f"issuing SPN {action}ed", spn_id),
        )
        _retire_spn_identities(
            connection, spn_id, timestamp,
            reason=f"issuing SPN {action}ed", expired_only=False,
        )
    if action == "revoke":
        connection.execute(
            """
            UPDATE spn_credentials
            SET status = 'revoked', revoked_at = ?, version = version + 1
            WHERE spn_id = ? AND status = 'active'
            """,
            (timestamp, spn_id),
        )


def _record_spn_transition(
    connection: sqlite3.Connection,
    spn_id: str,
    *,
    action: str,
    expected_version: int,
    previous_status: str,
    request_id: str,
    intent: str,
    reason: str,
    actor: LifecycleActor,
    timestamp: str,
) -> sqlite3.Row:
    """Audit an applied transition and remember its result for replays."""

    connection.execute(
        """
        INSERT INTO spn_audit (
            id, event_type, spn_id, actor_type, actor_id, reason,
            request_id, occurred_at, details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            _SPN_TRANSITION_EVENT[action],
            spn_id, actor.actor_type, actor.actor_id, reason, request_id,
            timestamp,
            json.dumps(
                {
                    "previous_status": previous_status,
                    "resulting_status": _SPN_TRANSITION_STATUS[action],
                },
                ensure_ascii=True, separators=(",", ":"),
            ),
        ),
    )
    updated = connection.execute(
        _SPN_SELECT + " WHERE id = ?", (spn_id,),
    ).fetchone()
    if updated is None:
        raise StorageError("updated SPN could not be read back")
    connection.execute(
        """
        INSERT INTO spn_transition_requests (
            request_id, spn_id, action, expected_version, intent_sha256,
            result_status, result_version, result_blocked_at,
            result_revoked_at, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id, spn_id, action, expected_version, intent,
            updated["status"], updated["version"], updated["blocked_at"],
            updated["revoked_at"], timestamp,
        ),
    )
    return updated


class ServicePrincipalMixin:
    def create_service_principal(
        self,
        *,
        spn_id: str,
        name: str,
        agent_name_prefix: str,
        credential_id: str,
        secret_hash: str,
        request_id: str,
        actor: LifecycleActor,
        created_at: datetime,
    ) -> tuple[ServicePrincipal, str, bool]:
        _validate_actor(actor)
        request_id = _canonical_request_id(request_id)
        intent = _lifecycle_input_hash("spn-create", name, agent_name_prefix)
        timestamp = _format_utc(created_at)
        try:
            with self._transaction() as connection:
                _validate_actor(actor)
                _require_agent_access(connection)
                existing = _spn_request(connection, request_id)
                if existing is not None:
                    if (
                        existing["operation"] != "create"
                        or existing["intent_sha256"] != intent
                    ):
                        raise CredentialConflictError(
                            "SPN request id is already in use"
                        )
                    return (*_replayed_spn_request(connection, existing), False)
                connection.execute(
                    """
                    INSERT INTO spn_principals (
                        id, name, agent_name_prefix, status, created_at
                    )
                    VALUES (?, ?, ?, 'enabled', ?)
                    """,
                    (spn_id, name, agent_name_prefix, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO spn_credentials (
                        id, spn_id, kind, secret_hash, status,
                        issuance_request_id, created_at
                    )
                    VALUES (?, ?, 'sbsp1', ?, 'active', ?, ?)
                    """,
                    (credential_id, spn_id, secret_hash, request_id, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO spn_requests (
                        request_id, operation, intent_sha256, spn_id,
                        result_credential_id, created_at
                    )
                    VALUES (?, 'create', ?, ?, ?, ?)
                    """,
                    (request_id, intent, spn_id, credential_id, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO spn_audit (
                        id, event_type, spn_id, credential_id, actor_type,
                        actor_id, reason, request_id, occurred_at, details_json
                    )
                    VALUES (?, 'created', ?, ?, ?, ?, 'service principal created',
                            ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()), spn_id, credential_id,
                        actor.actor_type, actor.actor_id, request_id, timestamp,
                        json.dumps(
                            {"agent_name_prefix": agent_name_prefix},
                            ensure_ascii=True, separators=(",", ":"),
                        ),
                    ),
                )
                row = connection.execute(
                    _SPN_SELECT + " WHERE id = ?", (spn_id,),
                ).fetchone()
        except StorageError as error:
            if _is_duplicate_spn_name(error):
                raise CredentialConflictError(
                    "service principal name is already registered"
                ) from error
            raise
        if row is None:
            raise StorageError("created SPN could not be read back")
        return _spn_from_row(row), credential_id, True

    def list_service_principals(self) -> tuple[ServicePrincipal, ...]:
        with self._read_transaction() as connection:
            rows = connection.execute(_SPN_SELECT + " ORDER BY name").fetchall()
        return tuple(_spn_from_row(row) for row in rows)

    def authenticate_service_principal(
        self,
        *,
        credential_id: str,
        candidate_digest: str,
        seen_at: datetime,
    ) -> ServicePrincipalIdentity | None:
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT c.id, c.kind, c.secret_hash, c.status AS credential_status,
                       c.revoked_at, p.id AS spn_id, p.name, p.agent_name_prefix,
                       p.status AS spn_status
                FROM spn_credentials AS c
                JOIN spn_principals AS p ON p.id = c.spn_id
                WHERE c.id = ?
                """,
                (credential_id,),
            ).fetchone()
            stored = _DUMMY_KEY_HASH if row is None else row["secret_hash"]
            live = row is not None and (
                row["credential_status"] == "active"
                or (
                    row["credential_status"] == "revoked"
                    and row["revoked_at"] > _format_utc(seen_at)
                )
            )
            if (
                not hmac.compare_digest(stored, candidate_digest)
                or not live
                or row["spn_status"] != "enabled"
            ):
                return None
            connection.execute(
                "UPDATE spn_credentials SET last_used_at = ? WHERE id = ?",
                (_format_utc(seen_at), credential_id),
            )
            return ServicePrincipalIdentity(
                spn_id=row["spn_id"],
                spn_name=row["name"],
                agent_name_prefix=row["agent_name_prefix"],
                credential_id=row["id"],
                credential_kind=row["kind"],
            )

    def service_principal_credential_is_active(
        self, spn_id: str, credential_id: str,
    ) -> bool:
        with self._read_transaction() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM spn_credentials AS c
                JOIN spn_principals AS p ON p.id = c.spn_id
                WHERE p.id = ? AND c.id = ?
                  AND p.status = 'enabled'
                  AND (c.status = 'active' OR (c.status = 'revoked' AND c.revoked_at > ?))
                """,
                (spn_id, credential_id, _format_utc(utc_now())),
            ).fetchone()
        return row is not None

    def issue_spn_onboarding(
        self,
        *,
        identity: ServicePrincipalIdentity,
        request_id: str,
        intent_sha256: str,
        enrollment_id: str,
        secret_hash: str,
        agent_name: str,
        description: str,
        created_at: datetime,
        expires_at: datetime,
        max_outstanding: int,
        identity_expires_at: datetime | None = None,
    ) -> tuple[OnboardingIssuance, bool]:
        request_id = _canonical_request_id(request_id)
        timestamp = _format_utc(created_at)
        expiry = _format_utc(expires_at)
        identity_expiry = (
            None if identity_expires_at is None else _format_utc(identity_expires_at)
        )
        with self._transaction() as connection:
            _require_agent_access(connection)
            _require_active_spn(connection, identity)
            _retire_spn_identities(
                connection, identity.spn_id, timestamp,
                reason="identity expired", expired_only=True,
            )
            existing = connection.execute(
                """
                SELECT spn_id, intent_sha256, enrollment_id, agent_name,
                       created_at, expires_at
                FROM spn_onboarding_issuances
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["spn_id"] != identity.spn_id
                    or existing["intent_sha256"] != intent_sha256
                ):
                    raise CredentialConflictError(
                        "onboarding request id is already in use"
                    )
                existing_created_at = _parse_utc(existing["created_at"])
                existing_expires_at = _parse_utc(existing["expires_at"])
                if existing_created_at is None or existing_expires_at is None:
                    raise StorageError("SPN issuance lifetime is unavailable")
                return (
                    OnboardingIssuance(
                        request_id=request_id,
                        spn_id=existing["spn_id"],
                        enrollment_id=existing["enrollment_id"],
                        agent_name=existing["agent_name"],
                        created_at=existing_created_at,
                        expires_at=existing_expires_at,
                    ),
                    False,
                )
            outstanding = connection.execute(
                """
                SELECT COUNT(*)
                FROM spn_onboarding_issuances AS i
                JOIN agent_enrollments AS e ON e.id = i.enrollment_id
                WHERE i.spn_id = ? AND e.status = 'pending' AND e.expires_at > ?
                """,
                (identity.spn_id, timestamp),
            ).fetchone()[0]
            if int(outstanding) >= max_outstanding:
                raise CredentialLimitError("SPN outstanding package limit reached")
            if connection.execute(
                "SELECT 1 FROM agents WHERE name = ?", (agent_name,),
            ).fetchone() is not None:
                raise DuplicateAgentNameError(
                    "claimed agent name is already registered"
                )
            connection.execute(
                """
                INSERT INTO agent_enrollments (
                    id, secret_hash, name_prefix, name_match, description, status,
                    uses_allowed, uses_remaining, created_at, expires_at,
                    actor_type, actor_id, creation_reason, spn_id,
                    identity_expires_at
                )
                VALUES (?, ?, ?, 'exact', ?, 'pending', 1, 1, ?, ?,
                        'system', ?, 'SPN automated onboarding', ?, ?)
                """,
                (
                    enrollment_id, secret_hash, agent_name, description,
                    timestamp, expiry, f"spn:{identity.spn_id}", identity.spn_id,
                    identity_expiry,
                ),
            )
            connection.execute(
                """
                INSERT INTO spn_onboarding_issuances (
                    request_id, spn_id, intent_sha256, enrollment_id,
                    agent_name, created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id, identity.spn_id, intent_sha256, enrollment_id,
                    agent_name, timestamp, expiry,
                ),
            )
            connection.execute(
                """
                INSERT INTO spn_audit (
                    id, event_type, spn_id, credential_id, enrollment_id,
                    actor_type, actor_id, reason, request_id, occurred_at,
                    details_json
                )
                VALUES (?, 'package-issued', ?, ?, ?, 'spn', ?,
                        'automated agent onboarding', ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), identity.spn_id, identity.credential_id,
                    enrollment_id, f"spn:{identity.spn_id}", request_id,
                    timestamp,
                    json.dumps(
                        {
                            "agent_name": agent_name,
                            "identity_expires_at": identity_expiry,
                        },
                        ensure_ascii=True, separators=(",", ":"),
                    ),
                ),
            )
        return (
            OnboardingIssuance(
                request_id=request_id,
                spn_id=identity.spn_id,
                enrollment_id=enrollment_id,
                agent_name=agent_name,
                created_at=created_at,
                expires_at=expires_at,
            ),
            True,
        )

    def transition_service_principal(
        self,
        spn_id: str,
        *,
        action: str,
        expected_version: int,
        request_id: str,
        reason: str,
        actor: LifecycleActor,
        changed_at: datetime,
    ) -> ServicePrincipal:
        if action not in {"block", "unblock", "revoke"}:
            raise DomainValidationError("invalid SPN lifecycle action")
        _validate_actor(actor)
        request_id = _canonical_request_id(request_id)
        timestamp = _format_utc(changed_at)
        intent = _lifecycle_input_hash(
            "spn-transition", spn_id, action, expected_version, reason,
            actor.actor_type, actor.actor_id,
        )
        with self._transaction() as connection:
            _validate_actor(actor)
            existing = connection.execute(
                """
                SELECT spn_id, action, expected_version, intent_sha256,
                       result_status, result_version, result_blocked_at,
                       result_revoked_at
                FROM spn_transition_requests
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if existing is not None:
                return _replayed_spn_transition(
                    connection, existing, spn_id=spn_id, action=action,
                    expected_version=expected_version, intent=intent,
                )
            if connection.execute(
                "SELECT 1 FROM spn_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone() is not None:
                raise CredentialConflictError("SPN request id is already in use")
            row = connection.execute(
                _SPN_SELECT + " WHERE id = ?", (spn_id,),
            ).fetchone()
            if row is None:
                raise ServicePrincipalNotFoundError(
                    "service principal does not exist"
                )
            _require_spn_transition_allowed(row, action, expected_version)
            if action == "unblock":
                _require_agent_access(connection)
            _apply_spn_transition(
                connection, spn_id, action=action,
                expected_version=expected_version, timestamp=timestamp,
            )
            updated = _record_spn_transition(
                connection, spn_id, action=action,
                expected_version=expected_version, previous_status=row["status"],
                request_id=request_id, intent=intent, reason=reason, actor=actor,
                timestamp=timestamp,
            )
        return _spn_from_row(updated)

    def rotate_service_principal_credential(
        self,
        spn_id: str,
        *,
        expected_version: int,
        credential_id: str,
        secret_hash: str,
        request_id: str,
        reason: str,
        actor: LifecycleActor,
        changed_at: datetime,
    ) -> tuple[ServicePrincipal, str, bool]:
        _validate_actor(actor)
        request_id = _canonical_request_id(request_id)
        intent = _lifecycle_input_hash("spn-rotate", spn_id, expected_version, reason)
        timestamp = _format_utc(changed_at)
        with self._transaction() as connection:
            _validate_actor(actor)
            _require_agent_access(connection)
            existing = _spn_request(connection, request_id)
            if existing is not None:
                if (
                    existing["operation"] != "rotate"
                    or existing["intent_sha256"] != intent
                    or existing["spn_id"] != spn_id
                ):
                    raise CredentialConflictError("SPN request id is already in use")
                return (*_replayed_spn_request(connection, existing), False)
            _require_rotatable_spn(connection, spn_id, expected_version)
            connection.execute(
                """
                UPDATE spn_credentials
                SET status = 'revoked', revoked_at = ?, version = version + 1
                WHERE spn_id = ? AND status = 'active'
                """,
                (timestamp, spn_id),
            )
            connection.execute(
                """
                INSERT INTO spn_credentials (
                    id, spn_id, kind, secret_hash, status,
                    issuance_request_id, created_at
                )
                VALUES (?, ?, 'sbsp1', ?, 'active', ?, ?)
                """,
                (credential_id, spn_id, secret_hash, request_id, timestamp),
            )
            connection.execute(
                "UPDATE spn_principals SET version = version + 1 WHERE id = ?",
                (spn_id,),
            )
            connection.execute(
                """
                INSERT INTO spn_requests (
                    request_id, operation, intent_sha256, spn_id,
                    result_credential_id, created_at
                )
                VALUES (?, 'rotate', ?, ?, ?, ?)
                """,
                (request_id, intent, spn_id, credential_id, timestamp),
            )
            connection.execute(
                """
                INSERT INTO spn_audit (
                    id, event_type, spn_id, credential_id, actor_type,
                    actor_id, reason, request_id, occurred_at
                )
                VALUES (?, 'rotated', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), spn_id, credential_id, actor.actor_type,
                    actor.actor_id, reason, request_id, timestamp,
                ),
            )
            updated = connection.execute(
                _SPN_SELECT + " WHERE id = ?", (spn_id,),
            ).fetchone()
        if updated is None:
            raise StorageError("rotated SPN could not be read back")
        return _spn_from_row(updated), credential_id, True

    def retire_spn_identity(
        self,
        *,
        identity: ServicePrincipalIdentity,
        agent_name: str,
        request_id: str,
        retired_at: datetime,
    ) -> datetime:
        """Retire one identity this SPN created; returns when it was retired."""

        request_id = _canonical_request_id(request_id)
        timestamp = _format_utc(retired_at)
        with self._transaction() as connection:
            _require_agent_access(connection)
            _require_active_spn(connection, identity)
            _retire_spn_identities(
                connection, identity.spn_id, timestamp,
                reason="identity expired", expired_only=True,
            )
            row = connection.execute(
                """
                SELECT a.id, a.revoked_at FROM agents AS a
                JOIN agent_identity_provenance AS p ON p.agent_id = a.id
                WHERE a.name = ? AND p.creator_principal_type = 'spn'
                  AND p.creator_principal_id = ?
                """,
                (agent_name, identity.spn_id),
            ).fetchone()
            if row is None:
                raise AgentNotFoundError(
                    "agent is not an identity of this service principal"
                )
            intent = _lifecycle_input_hash("spn-retire", identity.spn_id, row["id"])
            previous = connection.execute(
                """
                SELECT action, intent_sha256, occurred_at FROM agent_lifecycle_audit
                WHERE request_id = ?
                  AND action IN ('block', 'unblock', 'retire', 'reconnect-issue',
                                 'reconnect-redeem')
                """,
                (request_id,),
            ).fetchone()
            if previous is not None:
                if previous["action"] != "retire" or previous["intent_sha256"] != intent:
                    raise CredentialConflictError("retire request id is already in use")
                occurred = _parse_utc(previous["occurred_at"])
            elif row["revoked_at"] is not None:
                occurred = _parse_utc(row["revoked_at"])
            else:
                _retire_agent(
                    connection, agent_id=row["id"], request_id=request_id,
                    intent_sha256=intent, actor_type="system",
                    actor_id=f"spn:{identity.spn_id}",
                    reason="retired by its issuing service principal",
                    timestamp=timestamp,
                )
                occurred = retired_at
        if occurred is None:
            raise StorageError("retirement time is unavailable")
        return occurred

    def rotate_own_spn_credential(
        self,
        *,
        identity: ServicePrincipalIdentity,
        credential_id: str,
        secret_hash: str,
        request_id: str,
        changed_at: datetime,
        max_per_day: int,
    ) -> tuple[str, bool]:
        """Replace the calling SPN's credential; the old one lasts one minute more."""

        request_id = _canonical_request_id(request_id)
        intent = _lifecycle_input_hash("spn-self-rotate", identity.spn_id)
        timestamp = _format_utc(changed_at)
        with self._transaction() as connection:
            _require_agent_access(connection)
            existing = connection.execute(
                """
                SELECT operation, intent_sha256, spn_id, result_credential_id
                FROM spn_requests WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["operation"] != "rotate"
                    or existing["intent_sha256"] != intent
                    or existing["spn_id"] != identity.spn_id
                ):
                    raise CredentialConflictError("SPN request id is already in use")
                return existing["result_credential_id"], False
            _require_active_spn(connection, identity)
            recent = connection.execute(
                """
                SELECT COUNT(*) FROM spn_audit
                WHERE spn_id = ? AND event_type = 'rotated' AND actor_type = 'spn'
                  AND occurred_at > ?
                """,
                (identity.spn_id, _format_utc(changed_at - timedelta(days=1))),
            ).fetchone()[0]
            if int(recent) >= max_per_day:
                raise CredentialLimitError("SPN rotation limit reached")
            connection.execute(
                """
                UPDATE spn_credentials
                SET status = 'revoked', revoked_at = ?, version = version + 1
                WHERE spn_id = ? AND status = 'active'
                """,
                (_format_utc(changed_at + SELF_ROTATION_OVERLAP), identity.spn_id),
            )
            connection.execute(
                """
                INSERT INTO spn_credentials (
                    id, spn_id, kind, secret_hash, status,
                    issuance_request_id, created_at
                )
                VALUES (?, ?, 'sbsp1', ?, 'active', ?, ?)
                """,
                (credential_id, identity.spn_id, secret_hash, request_id, timestamp),
            )
            connection.execute(
                "UPDATE spn_principals SET version = version + 1 WHERE id = ?",
                (identity.spn_id,),
            )
            connection.execute(
                """
                INSERT INTO spn_requests (
                    request_id, operation, intent_sha256, spn_id,
                    result_credential_id, created_at
                )
                VALUES (?, 'rotate', ?, ?, ?, ?)
                """,
                (request_id, intent, identity.spn_id, credential_id, timestamp),
            )
            connection.execute(
                """
                INSERT INTO spn_audit (
                    id, event_type, spn_id, credential_id, actor_type,
                    actor_id, reason, request_id, occurred_at
                )
                VALUES (?, 'rotated', ?, ?, 'spn', ?, 'service principal self-rotation',
                        ?, ?)
                """,
                (
                    str(uuid.uuid4()), identity.spn_id, credential_id,
                    f"spn:{identity.spn_id}", request_id, timestamp,
                ),
            )
        return credential_id, True
