from __future__ import annotations

import hmac
import json
import sqlite3
import uuid
from datetime import datetime
from collections.abc import Callable

from strugglebus.errors import (
    DuplicateAgentNameError,
    CredentialConflictError,
    DomainValidationError,
    EnrollmentInvalidError,
    EnrollmentNotFoundError,
    StorageError,
)
from strugglebus.models import (
    Agent,
    AgentCredential,
    AgentEnrollment,
    IdentityCreationProvenancePage,
    LifecycleActor,
)
from strugglebus.store._hosts import mark_enrolled_host
from strugglebus.store._common import (
    _AGENT_SELECT,
    _CREDENTIAL_SELECT,
    _DUMMY_KEY_HASH,
    _ENROLLMENT_SELECT,
    _agent_from_row,
    _credential_from_row,
    _enrollment_from_row,
    _format_utc,
    _identity_creation_provenance_from_row,
    _lifecycle_input_hash,
    _require_agent_access,
    _validate_actor,
)

_PROVENANCE_CREATOR_TYPES = frozenset({"system", "local-admin", "remote-admin", "spn"})


def _is_duplicate_agent_name(error: StorageError) -> bool:
    """Whether a failed write lost the race for a unique agent name."""

    return (
        isinstance(error.__cause__, sqlite3.IntegrityError)
        and "agents.name" in str(error.__cause__)
    )


def _validate_direct_creator(creator_type: str, creator_id: str) -> None:
    if creator_type not in {"local-admin", "remote-admin"}:
        raise DomainValidationError("invalid direct-registration creator type")
    if not isinstance(creator_id, str) or not 1 <= len(creator_id) <= 256:
        raise DomainValidationError("invalid direct-registration creator id")


def _replayed_registration(
    connection: sqlite3.Connection, request_id: str, input_hash: str,
) -> tuple[Agent, AgentCredential] | None:
    """The result an earlier, identical registration request already produced."""

    existing = connection.execute(
        """
        SELECT agent_id, result_credential_id, operation, input_sha256
        FROM agent_credential_requests
        WHERE request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if existing is None:
        return None
    if (
        existing["operation"] != "register"
        or existing["input_sha256"] != input_hash
    ):
        raise CredentialConflictError(
            "credential request id is already in use"
        )
    agent_row = connection.execute(
        _AGENT_SELECT + " WHERE id = ?",
        (existing["agent_id"],),
    ).fetchone()
    credential_row = connection.execute(
        _CREDENTIAL_SELECT + " WHERE id = ?",
        (existing["result_credential_id"],),
    ).fetchone()
    if agent_row is None or credential_row is None:
        raise StorageError(
            "credential request result is unavailable"
        )
    return _agent_from_row(agent_row), _credential_from_row(credential_row)


def _insert_direct_registration(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    name: str,
    description: str,
    host: str,
    credential_id: str,
    secret_hash: str,
    request_id: str,
    input_hash: str,
    creator_type: str,
    creator_id: str,
    timestamp: str,
    expires: str,
) -> None:
    """Write a directly registered agent, its pending credential and its audit trail."""

    connection.execute(
        """
        INSERT INTO agents (
            id, name, description, host, created_at, credential_epoch
        )
        VALUES (?, ?, ?, ?, ?, 1)
        """,
        (agent_id, name, description, host, timestamp),
    )
    connection.execute(
        """
        INSERT INTO agent_credentials (
            id, agent_id, kind, secret_hash, status,
            creation_method, creation_reason, issuance_request_id,
            created_at, pending_expires_at
        )
        VALUES (?, ?, 'sb1', ?, 'pending', 'registration',
                'initial agent credential', ?, ?, ?)
        """,
        (
            credential_id,
            agent_id,
            secret_hash,
            request_id,
            timestamp,
            expires,
        ),
    )
    connection.execute(
        """
        INSERT INTO agent_credential_requests (
            request_id, operation, input_sha256, agent_id,
            result_credential_id, created_at
        )
        VALUES (?, 'register', ?, ?, ?, ?)
        """,
        (request_id, input_hash, agent_id, credential_id, timestamp),
    )
    connection.execute(
        """
        INSERT INTO agent_credential_audit (
            id, event_type, agent_id, credential_id,
            actor_type, actor_id, method, reason, request_id, occurred_at
        )
        VALUES (?, 'issue', ?, ?, ?, ?,
                'registration', 'initial agent credential', ?, ?)
        """,
        (
            str(uuid.uuid4()),
            agent_id,
            credential_id,
            creator_type,
            creator_id,
            request_id,
            timestamp,
        ),
    )
    if connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'agent_identity_provenance'
        """
    ).fetchone() is not None:
        connection.execute(
            """
            INSERT INTO agent_identity_provenance (
                agent_id, creation_method, creator_principal_type,
                creator_principal_id, originating_request_id,
                created_at
            )
            VALUES (?, 'direct-registration', ?, ?, ?, ?)
            """,
            (
                agent_id, creator_type, creator_id, request_id, timestamp,
            ),
        )


def _require_enrollment_authorization_guard(
    actor_type: str, actor_id: str, authorize: Callable[[], None] | None,
) -> bool:
    """Check the shape of the authorization guard; True for an operator creator."""

    if authorize is not None and not callable(authorize):
        raise DomainValidationError("authorization guard must be callable")
    operator_actor = actor_id.startswith("operator:")
    if operator_actor and (actor_type != "remote-admin" or authorize is None):
        raise DomainValidationError("operator authorization guard is required")
    return operator_actor


def _verified_enrollment(
    connection: sqlite3.Connection, enrollment_id: str, candidate_digest: str,
) -> sqlite3.Row:
    """Find the enrollment, comparing digests even when it does not exist."""

    row = connection.execute(
        _ENROLLMENT_SELECT + " WHERE id = ?", (enrollment_id,)
    ).fetchone()
    stored_digest = (
        row["secret_hash"] if row is not None else _DUMMY_KEY_HASH
    )
    verified = hmac.compare_digest(stored_digest, candidate_digest)
    if row is None or not verified:
        raise EnrollmentInvalidError("enrollment token is not valid")
    return row


def _remaining_enrollment_uses(row: sqlite3.Row, timestamp: str) -> int:
    """How many uses a still-open enrollment has left."""

    remaining = int(row["uses_remaining"])
    if row["status"] != "pending" or remaining <= 0:
        raise EnrollmentInvalidError(
            "enrollment token is no longer available"
        )
    if timestamp >= row["expires_at"]:
        raise EnrollmentInvalidError("enrollment token has expired")
    return remaining


def _enrolled_identity_expiry(
    connection: sqlite3.Connection, enrollment_id: str, timestamp: str,
) -> str | None:
    """When identities created by this enrollment expire, if they do at all."""

    identity_expires_at = connection.execute(
        "SELECT identity_expires_at FROM agent_enrollments WHERE id = ?",
        (enrollment_id,),
    ).fetchone()[0]
    if identity_expires_at is not None and timestamp >= identity_expires_at:
        raise EnrollmentInvalidError("enrollment identity lifetime has passed")
    return identity_expires_at


def _require_claimable_name(
    connection: sqlite3.Connection, row: sqlite3.Row, claimed_name: str,
) -> None:
    prefix = row["name_prefix"]
    if claimed_name != prefix and (
        row["name_match"] != "prefix"
        or not claimed_name.startswith(f"{prefix}-")
    ):
        raise EnrollmentInvalidError(
            "claimed agent name is outside the enrollment allowance"
        )
    # Self-registration may only ever create a new identity. An
    # existing name, including a revoked one, is never re-credentialed
    # through enrollment.
    if connection.execute(
        "SELECT 1 FROM agents WHERE name = ?", (claimed_name,)
    ).fetchone() is not None:
        raise DuplicateAgentNameError(
            "claimed agent name is already registered"
        )


def _consume_enrollment_use(
    connection: sqlite3.Connection,
    enrollment_id: str,
    *,
    remaining: int,
    timestamp: str,
) -> None:
    consumed = remaining - 1
    cursor = connection.execute(
        """
        UPDATE agent_enrollments
        SET uses_remaining = ?,
            last_redeemed_at = ?,
            status = CASE WHEN ? = 0 THEN 'exhausted' ELSE 'pending' END,
            exhausted_at = CASE WHEN ? = 0 THEN ? ELSE NULL END,
            version = version + 1
        WHERE id = ?
          AND status = 'pending'
          AND uses_remaining = ?
        """,
        (
            consumed,
            timestamp,
            consumed,
            consumed,
            timestamp,
            enrollment_id,
            remaining,
        ),
    )
    if cursor.rowcount != 1:
        raise EnrollmentInvalidError(
            "enrollment token was already redeemed"
        )


def _insert_enrolled_identity(
    connection: sqlite3.Connection,
    *,
    enrollment_id: str,
    agent_id: str,
    claimed_name: str,
    description: str,
    host: str,
    identity_expires_at: str | None,
    credential_id: str,
    secret_hash: str,
    request_id: str,
    input_hash: str,
    timestamp: str,
    expires: str,
) -> None:
    """Write a self-registered agent, its pending credential and the redemption."""

    connection.execute(
        """
        INSERT INTO agents (
            id, name, description, host, created_at, credential_epoch,
            expires_at
        )
        VALUES (?, ?, ?, ?, ?, 1, ?)
        """,
        (
            agent_id, claimed_name, description, host, timestamp,
            identity_expires_at,
        ),
    )
    connection.execute(
        """
        INSERT INTO agent_credentials (
            id, agent_id, kind, secret_hash, status,
            creation_method, creation_reason, issuance_request_id,
            created_at, pending_expires_at
        )
        VALUES (?, ?, 'sb1', ?, 'pending', 'enrollment',
                'self-registered through enrollment', ?, ?, ?)
        """,
        (
            credential_id,
            agent_id,
            secret_hash,
            request_id,
            timestamp,
            expires,
        ),
    )
    connection.execute(
        """
        INSERT INTO agent_credential_requests (
            request_id, operation, input_sha256, agent_id,
            result_credential_id, created_at
        )
        VALUES (?, 'enrollment-redeem', ?, ?, ?, ?)
        """,
        (request_id, input_hash, agent_id, credential_id, timestamp),
    )
    connection.execute(
        """
        INSERT INTO agent_credential_audit (
            id, event_type, agent_id, credential_id,
            actor_type, actor_id, method, reason, request_id,
            occurred_at, details_json
        )
        VALUES (?, 'issue', ?, ?, 'system', ?, 'enrollment',
                'self-registered through enrollment', ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            agent_id,
            credential_id,
            enrollment_id,
            request_id,
            timestamp,
            json.dumps(
                {"enrollment_id": enrollment_id},
                ensure_ascii=True,
                separators=(",", ":"),
            ),
        ),
    )
    connection.execute(
        """
        INSERT INTO agent_enrollment_redemptions (
            enrollment_id, agent_id, credential_id, claimed_name,
            request_id, redeemed_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            enrollment_id,
            agent_id,
            credential_id,
            claimed_name,
            request_id,
            timestamp,
        ),
    )


def _record_enrollment_provenance(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    enrollment_id: str,
    agent_id: str,
    request_id: str,
    timestamp: str,
) -> None:
    """Record who created the identity: the enrollment's author or its issuing SPN."""

    spn_id = row["spn_id"]
    if spn_id is None:
        creation_method = "enrollment"
        creator_type = row["actor_type"]
        creator_id = row["actor_id"]
        issuance_request_id = None
    else:
        issuance = connection.execute(
            """
            SELECT request_id
            FROM spn_onboarding_issuances
            WHERE enrollment_id = ? AND spn_id = ?
            """,
            (enrollment_id, spn_id),
        ).fetchone()
        if issuance is None:
            raise StorageError(
                "SPN enrollment issuance evidence is unavailable"
            )
        creation_method = "spn-enrollment"
        creator_type = "spn"
        creator_id = spn_id
        issuance_request_id = issuance["request_id"]
    connection.execute(
        """
        INSERT INTO agent_identity_provenance (
            agent_id, creation_method, creator_principal_type,
            creator_principal_id, originating_request_id,
            originating_enrollment_id,
            originating_issuance_request_id, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            agent_id,
            creation_method,
            creator_type,
            creator_id,
            request_id,
            enrollment_id,
            issuance_request_id,
            timestamp,
        ),
    )


def _validate_provenance_creator(
    creator_type: str | None, creator_id: str | None,
) -> None:
    if creator_type is not None and creator_type not in _PROVENANCE_CREATOR_TYPES:
        raise DomainValidationError("invalid creator principal type")
    if creator_id is not None and (
        not isinstance(creator_id, str) or not 1 <= len(creator_id) <= 256
    ):
        raise DomainValidationError("invalid creator principal id")


def _validate_provenance_cursor(
    after_created_at: datetime | None, after_agent_id: str | None,
) -> None:
    if (after_created_at is None) != (after_agent_id is None):
        raise DomainValidationError(
            "both provenance cursor fields must be supplied"
        )
    if (
        after_created_at is not None
        and (
            after_created_at.tzinfo is None
            or after_created_at.utcoffset() is None
        )
    ):
        raise DomainValidationError(
            "provenance cursor timestamp must include a timezone"
        )
    if after_agent_id is not None and not 1 <= len(after_agent_id) <= 256:
        raise DomainValidationError("invalid provenance cursor agent id")


def _validate_provenance_limit(limit: int) -> None:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
        raise DomainValidationError("invalid provenance result limit")


class EnrollmentMixin:
    def create_agent_with_credential(
        self,
        *,
        agent_id: str,
        name: str,
        description: str,
        host: str,
        credential_id: str,
        secret_hash: str,
        request_id: str,
        created_at: datetime,
        pending_expires_at: datetime,
        require_access: bool = False,
        creator_type: str = "local-admin",
        creator_id: str = "local-service",
    ) -> tuple[Agent, AgentCredential, bool]:
        _validate_direct_creator(creator_type, creator_id)
        timestamp = _format_utc(created_at)
        expires = _format_utc(pending_expires_at)
        input_hash = _lifecycle_input_hash(
            "register", name, description, host
        )
        try:
            with self._transaction() as connection:
                if require_access:
                    _require_agent_access(connection)
                replayed = _replayed_registration(connection, request_id, input_hash)
                if replayed is not None:
                    return (*replayed, False)
                _insert_direct_registration(
                    connection,
                    agent_id=agent_id,
                    name=name,
                    description=description,
                    host=host,
                    credential_id=credential_id,
                    secret_hash=secret_hash,
                    request_id=request_id,
                    input_hash=input_hash,
                    creator_type=creator_type,
                    creator_id=creator_id,
                    timestamp=timestamp,
                    expires=expires,
                )
                agent_row = connection.execute(
                    _AGENT_SELECT + " WHERE id = ?", (agent_id,)
                ).fetchone()
                credential_row = connection.execute(
                    _CREDENTIAL_SELECT + " WHERE id = ?", (credential_id,)
                ).fetchone()
        except StorageError as error:
            if _is_duplicate_agent_name(error):
                raise DuplicateAgentNameError(
                    f"agent name {name!r} is already registered"
                ) from error
            raise
        if agent_row is None or credential_row is None:
            raise StorageError("created agent credential could not be read back")
        return (
            _agent_from_row(agent_row),
            _credential_from_row(credential_row),
            True,
        )

    def create_enrollment(
        self,
        *,
        enrollment_id: str,
        secret_hash: str,
        name_prefix: str,
        name_match: str,
        description: str,
        uses_allowed: int,
        created_at: datetime,
        expires_at: datetime,
        actor_type: str,
        actor_id: str,
        creation_reason: str,
        require_access: bool = False,
        authorize: Callable[[], None] | None = None,
    ) -> AgentEnrollment:
        operator_actor = _require_enrollment_authorization_guard(
            actor_type, actor_id, authorize,
        )
        with self._transaction() as connection:
            if operator_actor:
                _validate_actor(
                    LifecycleActor(actor_type, actor_id, authorize), operator_only=True,
                )
            elif authorize is not None:
                authorize()
            if require_access or operator_actor:
                _require_agent_access(connection)
            connection.execute(
                """
                INSERT INTO agent_enrollments (
                    id, secret_hash, name_prefix, name_match, description, status,
                    uses_allowed, uses_remaining, created_at, expires_at,
                    actor_type, actor_id, creation_reason
                )
                VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    enrollment_id,
                    secret_hash,
                    name_prefix,
                    name_match,
                    description,
                    uses_allowed,
                    uses_allowed,
                    _format_utc(created_at),
                    _format_utc(expires_at),
                    actor_type,
                    actor_id,
                    creation_reason,
                ),
            )
            row = connection.execute(
                _ENROLLMENT_SELECT + " WHERE id = ?", (enrollment_id,)
            ).fetchone()
        if row is None:
            raise StorageError("created enrollment could not be read back")
        return _enrollment_from_row(row)

    def list_enrollments(self) -> tuple[AgentEnrollment, ...]:
        with self._read_transaction() as connection:
            rows = connection.execute(
                _ENROLLMENT_SELECT + " ORDER BY created_at DESC"
            ).fetchall()
        return tuple(_enrollment_from_row(row) for row in rows)

    def revoke_enrollment(
        self,
        *,
        enrollment_id: str,
        reason: str,
        revoked_at: datetime,
    ) -> AgentEnrollment:
        with self._transaction() as connection:
            row = connection.execute(
                _ENROLLMENT_SELECT + " WHERE id = ?", (enrollment_id,)
            ).fetchone()
            if row is None:
                raise EnrollmentNotFoundError("enrollment does not exist")
            if row["status"] != "pending":
                raise EnrollmentInvalidError(
                    "only a pending enrollment can be revoked"
                )
            connection.execute(
                """
                UPDATE agent_enrollments
                SET status = 'revoked',
                    revoked_at = ?,
                    revocation_reason = ?,
                    version = version + 1
                WHERE id = ? AND status = 'pending'
                """,
                (_format_utc(revoked_at), reason, enrollment_id),
            )
            updated = connection.execute(
                _ENROLLMENT_SELECT + " WHERE id = ?", (enrollment_id,)
            ).fetchone()
        if updated is None:
            raise StorageError("revoked enrollment could not be read back")
        return _enrollment_from_row(updated)

    def redeem_enrollment(
        self,
        *,
        enrollment_id: str,
        candidate_digest: str,
        claimed_name: str,
        description: str,
        host: str,
        agent_id: str,
        credential_id: str,
        secret_hash: str,
        request_id: str,
        redeemed_at: datetime,
        pending_expires_at: datetime,
    ) -> tuple[Agent, AgentCredential]:
        """Consume one enrollment use and self-register exactly one new agent."""

        timestamp = _format_utc(redeemed_at)
        expires = _format_utc(pending_expires_at)
        input_hash = _lifecycle_input_hash(
            "enrollment-redeem", claimed_name, description, host
        )
        try:
            with self._transaction() as connection:
                _require_agent_access(connection)
                row = _verified_enrollment(connection, enrollment_id, candidate_digest)
                remaining = _remaining_enrollment_uses(row, timestamp)
                identity_expires_at = _enrolled_identity_expiry(
                    connection, enrollment_id, timestamp,
                )
                _require_claimable_name(connection, row, claimed_name)
                _consume_enrollment_use(
                    connection, enrollment_id, remaining=remaining, timestamp=timestamp,
                )
                _insert_enrolled_identity(
                    connection,
                    enrollment_id=enrollment_id,
                    agent_id=agent_id,
                    claimed_name=claimed_name,
                    description=description,
                    host=host,
                    identity_expires_at=identity_expires_at,
                    credential_id=credential_id,
                    secret_hash=secret_hash,
                    request_id=request_id,
                    input_hash=input_hash,
                    timestamp=timestamp,
                    expires=expires,
                )
                _record_enrollment_provenance(
                    connection,
                    row,
                    enrollment_id=enrollment_id,
                    agent_id=agent_id,
                    request_id=request_id,
                    timestamp=timestamp,
                )
                if row["spn_id"] is not None:
                    # The one moment the new agent, the principal that registered it and that
                    # principal's host enrolment are all in hand.
                    mark_enrolled_host(
                        connection, agent_id=agent_id, agent_name=claimed_name,
                        spn_id=row["spn_id"], timestamp=timestamp,
                    )
                agent_row = connection.execute(
                    _AGENT_SELECT + " WHERE id = ?", (agent_id,)
                ).fetchone()
                credential_row = connection.execute(
                    _CREDENTIAL_SELECT + " WHERE id = ?", (credential_id,)
                ).fetchone()
        except StorageError as error:
            if _is_duplicate_agent_name(error):
                raise DuplicateAgentNameError(
                    "claimed agent name is already registered"
                ) from error
            raise
        if agent_row is None or credential_row is None:
            raise StorageError("redeemed enrollment could not be read back")
        return _agent_from_row(agent_row), _credential_from_row(credential_row)

    def list_identity_creation_provenance(
        self,
        *,
        creator_type: str | None = None,
        creator_id: str | None = None,
        after_created_at: datetime | None = None,
        after_agent_id: str | None = None,
        limit: int = 100,
    ) -> IdentityCreationProvenancePage:
        _validate_provenance_creator(creator_type, creator_id)
        _validate_provenance_cursor(after_created_at, after_agent_id)
        _validate_provenance_limit(limit)
        cursor = (
            _format_utc(after_created_at) if after_created_at is not None else None
        )
        filter_parameters = (creator_type, creator_type, creator_id, creator_id)
        with self._read_transaction() as connection:
            total_count = int(connection.execute(
                """
                SELECT COUNT(*)
                FROM agent_identity_provenance AS p
                WHERE (? IS NULL OR p.creator_principal_type = ?)
                  AND (? IS NULL OR p.creator_principal_id = ?)
                """,
                filter_parameters,
            ).fetchone()[0])
            rows = connection.execute(
                """
                SELECT a.*, p.creation_method, p.creator_principal_type,
                       p.creator_principal_id, p.originating_request_id,
                       p.originating_enrollment_id,
                       p.originating_issuance_request_id,
                       p.created_at AS provenance_created_at
                FROM agent_identity_provenance AS p
                JOIN agents AS a ON a.id = p.agent_id
                WHERE (? IS NULL OR p.creator_principal_type = ?)
                  AND (? IS NULL OR p.creator_principal_id = ?)
                  AND (
                      ? IS NULL
                      OR p.created_at > ?
                      OR (p.created_at = ? AND p.agent_id > ?)
                  )
                ORDER BY p.created_at, p.agent_id
                LIMIT ?
                """,
                (
                    *filter_parameters,
                    cursor,
                    cursor,
                    cursor,
                    after_agent_id,
                    limit + 1,
                ),
            ).fetchall()
        has_more = len(rows) > limit
        items = tuple(
            _identity_creation_provenance_from_row(row) for row in rows[:limit]
        )
        last = items[-1] if has_more else None
        return IdentityCreationProvenancePage(
            items=items,
            total_count=total_count,
            has_more=has_more,
            next_created_at=last.created_at if last is not None else None,
            next_agent_id=last.agent.id if last is not None else None,
        )
