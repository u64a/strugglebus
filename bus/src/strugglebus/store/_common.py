from __future__ import annotations

import hashlib
import json
import sqlite3
import unicodedata
import uuid
from datetime import UTC, datetime

from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    ChannelNotFoundError,
    CredentialConflictError,
    CredentialNotFoundError,
    DomainValidationError,
    PostRequestConflictError,
    ReplyNotFoundError,
    StorageError,
    UnknownMentionError,
)
from strugglebus.access import normalize_access_freeze_reason
from strugglebus.models import (
    AccessFreezeState,
    Agent,
    AgentCredential,
    AgentEnrollment,
    IdentityCreationProvenance,
    AgentLifecycleEvent,
    AgentReconnectGrant,
    LifecycleActor,
    AuthenticatedIdentity,
    ServicePrincipal,
    Channel,
    DashboardAgentSummary,
    DashboardChannelSummary,
    Message,
    MessageClaim,
    EffectiveRoe,
    RoeAcknowledgement,
    RoeRevision,
)
from strugglebus.roe import composition_sha256

_DUMMY_KEY_HASH = "0" * 64
_DASHBOARD_MESSAGE_SELECT = """
    SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
           a.name AS agent_name, m.body, m.kind, m.reply_to,
           m.meta, m.created_at
    FROM messages AS m
    JOIN channels AS c ON c.id = m.channel_id
    JOIN agents AS a ON a.id = m.agent_id
"""
_DASHBOARD_MESSAGE_FILTERS = {
    (False, False, False): "",
    (False, False, True): "WHERE m.seq < ?",
    (True, False, False): "WHERE m.channel_id = ?",
    (True, False, True): "WHERE m.channel_id = ? AND m.seq < ?",
    (False, True, False): "WHERE m.agent_id = ?",
    (False, True, True): "WHERE m.agent_id = ? AND m.seq < ?",
    (True, True, False): "WHERE m.channel_id = ? AND m.agent_id = ?",
    (True, True, True): (
        "WHERE m.channel_id = ? AND m.agent_id = ? AND m.seq < ?"
    ),
}


def utc_now() -> datetime:
    return datetime.now(UTC)


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: str | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StorageError("database contains an invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise StorageError("database contains an invalid timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StorageError("database contains a non-UTC timestamp")
    return parsed.astimezone(UTC)


def _agent_from_row(row: sqlite3.Row) -> Agent:
    created_at = _parse_utc(row["created_at"])
    if created_at is None:
        raise StorageError("database contains an agent without created_at")
    return Agent(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        host=row["host"],
        created_at=created_at,
        last_seen_at=_parse_utc(row["last_seen_at"]),
        revoked_at=_parse_utc(row["revoked_at"]),
        credential_epoch=int(row["credential_epoch"]),
        blocked_at=_parse_utc(row["blocked_at"]),
    )


def _credential_from_row(row: sqlite3.Row) -> AgentCredential:
    created_at = _parse_utc(row["created_at"])
    if created_at is None:
        raise StorageError("database contains a credential without created_at")
    return AgentCredential(
        id=row["id"],
        agent_id=row["agent_id"],
        kind=row["kind"],
        status=row["status"],
        predecessor_id=row["predecessor_id"],
        creation_method=row["creation_method"],
        creation_reason=row["creation_reason"],
        created_at=created_at,
        activated_at=_parse_utc(row["activated_at"]),
        identity_verified_at=_parse_utc(row["identity_verified_at"]),
        pending_expires_at=_parse_utc(row["pending_expires_at"]),
        last_used_at=_parse_utc(row["last_used_at"]),
        retired_at=_parse_utc(row["retired_at"]),
        revoked_at=_parse_utc(row["revoked_at"]),
        expired_at=_parse_utc(row["expired_at"]),
        version=int(row["version"]),
    )


def _enrollment_from_row(row: sqlite3.Row) -> AgentEnrollment:
    created_at = _parse_utc(row["created_at"])
    expires_at = _parse_utc(row["expires_at"])
    if created_at is None or expires_at is None:
        raise StorageError("database contains an enrollment without a lifetime")
    return AgentEnrollment(
        id=row["id"],
        name_prefix=row["name_prefix"],
        name_match=row["name_match"],
        description=row["description"],
        status=row["status"],
        uses_allowed=int(row["uses_allowed"]),
        uses_remaining=int(row["uses_remaining"]),
        created_at=created_at,
        expires_at=expires_at,
        last_redeemed_at=_parse_utc(row["last_redeemed_at"]),
        exhausted_at=_parse_utc(row["exhausted_at"]),
        revoked_at=_parse_utc(row["revoked_at"]),
        revocation_reason=row["revocation_reason"],
        actor_type=row["actor_type"],
        actor_id=row["actor_id"],
        creation_reason=row["creation_reason"],
        version=int(row["version"]),
    )


def _spn_from_row(row: sqlite3.Row) -> ServicePrincipal:
    created_at = _parse_utc(row["created_at"])
    if created_at is None:
        raise StorageError("database contains an SPN without created_at")
    return ServicePrincipal(
        id=row["id"],
        name=row["name"],
        agent_name_prefix=row["agent_name_prefix"],
        status=row["status"],
        created_at=created_at,
        blocked_at=_parse_utc(row["blocked_at"]),
        revoked_at=_parse_utc(row["revoked_at"]),
        version=int(row["version"]),
    )


_AGENT_SELECT = """
    SELECT id, name, description, host, created_at, last_seen_at,
           revoked_at, credential_epoch, blocked_at
    FROM agents
"""

MAINTENANCE_SYSTEM_AGENT_ID = "00000000-0000-4000-8000-000000000018"
HUMAN_OPERATOR_AGENT_ID = "00000000-0000-4000-8000-000000000019"
HUMAN_CHANNEL = "humans"
# Credential-less authors hidden from every agent roster and count.
SYSTEM_AUTHOR_IDS = (MAINTENANCE_SYSTEM_AGENT_ID, HUMAN_OPERATOR_AGENT_ID)

_CREDENTIAL_SELECT = """
    SELECT id, agent_id, kind, status, predecessor_id, creation_method,
           creation_reason, created_at, activated_at, identity_verified_at,
           pending_expires_at, last_used_at, retired_at, revoked_at,
           expired_at, version
    FROM agent_credentials
"""

_ENROLLMENT_SELECT = """
    SELECT id, secret_hash, name_prefix, name_match, description, status, uses_allowed,
           uses_remaining, created_at, expires_at, last_redeemed_at,
           exhausted_at, revoked_at, revocation_reason, actor_type, actor_id,
           creation_reason, version, spn_id
    FROM agent_enrollments
"""

_SPN_SELECT = """
    SELECT id, name, agent_name_prefix, status, created_at, blocked_at,
           revoked_at, version
    FROM spn_principals
"""

_CREDENTIAL_AUTH_BY_ID = """
    SELECT credential.*, agent.name AS agent_name,
           agent.description AS agent_description,
           agent.host AS agent_host,
           agent.created_at AS agent_created_at,
           agent.last_seen_at AS agent_last_seen_at,
           agent.revoked_at AS agent_revoked_at,
           agent.blocked_at AS agent_blocked_at,
           agent.credential_epoch AS agent_credential_epoch,
           agent.expires_at AS agent_expires_at
    FROM agent_credentials AS credential
    JOIN agents AS agent ON agent.id = credential.agent_id
    WHERE credential.id = ? AND credential.kind = ?
"""

_CREDENTIAL_AUTH_BY_HASH = """
    SELECT credential.*, agent.name AS agent_name,
           agent.description AS agent_description,
           agent.host AS agent_host,
           agent.created_at AS agent_created_at,
           agent.last_seen_at AS agent_last_seen_at,
           agent.revoked_at AS agent_revoked_at,
           agent.blocked_at AS agent_blocked_at,
           agent.credential_epoch AS agent_credential_epoch,
           agent.expires_at AS agent_expires_at
    FROM agent_credentials AS credential
    JOIN agents AS agent ON agent.id = credential.agent_id
    WHERE credential.kind = ? AND credential.secret_hash = ?
"""


def _credential_auth_row(
    connection: sqlite3.Connection,
    *,
    kind: str,
    credential_id: str | None,
    candidate_digest: str,
) -> sqlite3.Row | None:
    if credential_id is not None:
        row = connection.execute(
            _CREDENTIAL_AUTH_BY_ID,
            (credential_id, kind),
        ).fetchone()
    else:
        row = connection.execute(
            _CREDENTIAL_AUTH_BY_HASH,
            (kind, candidate_digest),
        ).fetchone()
    # An expired identity authenticates nowhere, even before its sweep
    # retires it; callers then compare against the dummy verifier.
    if (
        row is not None
        and row["agent_expires_at"] is not None
        and row["agent_expires_at"] <= _format_utc(utc_now())
    ):
        return None
    return row


def _identity_from_auth_row(row: sqlite3.Row) -> AuthenticatedIdentity:
    agent_created_at = _parse_utc(row["agent_created_at"])
    if agent_created_at is None:
        raise StorageError("database contains an agent without created_at")
    return AuthenticatedIdentity(
        Agent(
            id=row["agent_id"],
            name=row["agent_name"],
            description=row["agent_description"],
            host=row["agent_host"],
            created_at=agent_created_at,
            last_seen_at=_parse_utc(row["agent_last_seen_at"]),
            revoked_at=_parse_utc(row["agent_revoked_at"]),
            credential_epoch=int(row["agent_credential_epoch"]),
            blocked_at=_parse_utc(row["agent_blocked_at"]),
        ),
        _credential_from_row(row),
    )


def _channel_from_row(row: sqlite3.Row) -> Channel:
    created_at = _parse_utc(row["created_at"])
    if created_at is None:
        raise StorageError("database contains a channel without created_at")
    return Channel(
        id=row["id"],
        name=row["name"],
        purpose=row["purpose"],
        created_at=created_at,
        created_by=row["created_by"],
    )


def _dashboard_channel_summary_from_rows(
    channel_row: sqlite3.Row,
    activity_row: sqlite3.Row,
) -> DashboardChannelSummary:
    created_at = _parse_utc(channel_row["created_at"])
    if created_at is None:
        raise StorageError("database contains a channel without created_at")
    return DashboardChannelSummary(
        name=channel_row["name"],
        purpose=channel_row["purpose"],
        created_at=created_at,
        message_count=int(activity_row["message_count"]),
        last_activity_at=_parse_utc(activity_row["last_activity_at"]),
        active_subscriber_count=int(activity_row["subscriber_count"]),
    )


def _dashboard_agent_summary_from_row(row: sqlite3.Row) -> DashboardAgentSummary:
    created_at = _parse_utc(row["created_at"])
    if created_at is None:
        raise StorageError("database contains an agent without created_at")
    return DashboardAgentSummary(
        name=row["name"],
        created_at=created_at,
        last_seen_at=_parse_utc(row["last_seen_at"]),
    )


def _identity_creation_provenance_from_row(
    row: sqlite3.Row,
) -> IdentityCreationProvenance:
    created_at = _parse_utc(row["provenance_created_at"])
    agent_created_at = _parse_utc(row["created_at"])
    if created_at is None or agent_created_at is None:
        raise StorageError("database contains invalid identity provenance timestamps")
    return IdentityCreationProvenance(
        agent=Agent(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            host=row["host"],
            created_at=agent_created_at,
            last_seen_at=_parse_utc(row["last_seen_at"]),
            revoked_at=_parse_utc(row["revoked_at"]),
            credential_epoch=int(row["credential_epoch"]),
            blocked_at=_parse_utc(row["blocked_at"]),
        ),
        creation_method=row["creation_method"],
        creator_principal_type=row["creator_principal_type"],
        creator_principal_id=row["creator_principal_id"],
        originating_request_id=row["originating_request_id"],
        originating_enrollment_id=row["originating_enrollment_id"],
        originating_issuance_request_id=row[
            "originating_issuance_request_id"
        ],
        created_at=created_at,
    )


def _select_claim(
    connection: sqlite3.Connection, message_seq: int
) -> MessageClaim | None:
    row = connection.execute(
        """
        SELECT mc.message_seq, mc.agent_id, a.name AS agent_name, mc.claimed_at
        FROM message_claims AS mc
        JOIN agents AS a ON a.id = mc.agent_id
        WHERE mc.message_seq = ?
        """,
        (message_seq,),
    ).fetchone()
    if row is None:
        return None
    claimed_at = _parse_utc(row["claimed_at"])
    if claimed_at is None:
        raise StorageError("database contains a claim without claimed_at")
    return MessageClaim(
        message_seq=row["message_seq"],
        agent_id=row["agent_id"],
        agent_name=row["agent_name"],
        claimed_at=claimed_at,
    )


def _message_from_row(row: sqlite3.Row) -> Message:
    created_at = _parse_utc(row["created_at"])
    if created_at is None:
        raise StorageError("database contains a message without created_at")
    try:
        metadata = json.loads(row["meta"])
    except (json.JSONDecodeError, TypeError) as error:
        raise StorageError("database contains invalid message metadata") from error
    if not isinstance(metadata, dict):
        raise StorageError("database contains non-object message metadata")
    return Message(
        seq=row["seq"],
        id=row["id"],
        channel=row["channel_name"],
        agent_id=row["agent_id"],
        agent_name=row["agent_name"],
        body=row["body"],
        kind=row["kind"],
        reply_to=row["reply_to"],
        metadata=metadata,
        created_at=created_at,
    )


def _roe_revision_from_row(row: sqlite3.Row) -> RoeRevision:
    created_at = _parse_utc(row["created_at"])
    if created_at is None:
        raise StorageError("database contains an RoE revision without created_at")
    return RoeRevision(
        id=row["id"],
        target_key=row["target_key"],
        scope=row["scope"],
        agent_id=row["agent_id"],
        version=int(row["version"]),
        policy_schema_version=int(row["policy_schema_version"]),
        content_json=row["content_json"],
        content_sha256=row["content_sha256"],
        author_label=row["author_label"],
        publisher_type=row["publisher_type"],
        publisher_identity=row["publisher_identity"],
        created_at=created_at,
        superseded_at=_parse_utc(row["superseded_at"]),
    )


def _roe_acknowledgement_from_row(row: sqlite3.Row) -> RoeAcknowledgement:
    acknowledged_at = _parse_utc(row["acknowledged_at"])
    if acknowledged_at is None:
        raise StorageError(
            "database contains an RoE acknowledgement without acknowledged_at"
        )
    return RoeAcknowledgement(
        id=row["id"],
        agent_id=row["agent_id"],
        global_revision_id=row["global_revision_id"],
        global_content_sha256=row["global_content_sha256"],
        agent_revision_id=row["agent_revision_id"],
        agent_content_sha256=row["agent_content_sha256"],
        effective_sha256=row["effective_sha256"],
        acknowledged_at=acknowledged_at,
        credential_kind=row["credential_kind"],
        credential_id=row["credential_id"],
        credential_record_id=row["credential_record_id"],
    )


_ROE_REVISION_SELECT = """
    SELECT revision.id, revision.target_key, revision.scope, revision.agent_id,
           revision.version, revision.policy_schema_version,
           revision.content_json, revision.content_sha256,
           revision.author_label, revision.publisher_type,
           revision.publisher_identity, revision.created_at,
           revision.superseded_at
    FROM roe_revisions AS revision
"""


def _current_roe_revision(
    connection: sqlite3.Connection,
    target_key: str,
) -> RoeRevision | None:
    row = connection.execute(
        _ROE_REVISION_SELECT
        + """
          JOIN roe_current AS current ON current.revision_id = revision.id
          WHERE current.target_key = ?
        """,
        (target_key,),
    ).fetchone()
    return None if row is None else _roe_revision_from_row(row)


def _roe_composition_matches(
    *,
    global_revision_id: str,
    global_content_sha256: str,
    agent_revision_id: str | None,
    agent_content_sha256: str | None,
    effective_sha256: str,
    global_revision: RoeRevision,
    agent_revision: RoeRevision | None,
    current_effective_sha256: str,
) -> bool:
    """Whether the named composition is exactly the one currently in force."""

    current_agent_revision_id = None if agent_revision is None else agent_revision.id
    current_agent_content_sha256 = (
        None if agent_revision is None else agent_revision.content_sha256
    )
    return (
        global_revision_id == global_revision.id
        and global_content_sha256 == global_revision.content_sha256
        and agent_revision_id == current_agent_revision_id
        and agent_content_sha256 == current_agent_content_sha256
        and effective_sha256 == current_effective_sha256
    )


def _latest_roe_acknowledgement(
    connection: sqlite3.Connection,
    agent_id: str | None,
    credential_record_id: str | None,
) -> RoeAcknowledgement | None:
    if agent_id is None or credential_record_id is None:
        return None
    acknowledgement_row = connection.execute(
        """
        SELECT id, agent_id, global_revision_id,
               global_content_sha256, agent_revision_id,
               agent_content_sha256, effective_sha256,
               acknowledged_at, credential_kind, credential_id,
               credential_record_id
        FROM roe_acknowledgements
        WHERE agent_id = ? AND credential_record_id = ?
        ORDER BY seq DESC
        LIMIT 1
        """,
        (agent_id, credential_record_id),
    ).fetchone()
    if acknowledgement_row is None:
        return None
    return _roe_acknowledgement_from_row(acknowledgement_row)


def _acknowledgement_status(
    acknowledgement: RoeAcknowledgement | None,
    *,
    global_revision: RoeRevision,
    agent_revision: RoeRevision | None,
    effective_sha256: str,
) -> str:
    if acknowledgement is None:
        return "missing"
    if _roe_composition_matches(
        global_revision_id=acknowledgement.global_revision_id,
        global_content_sha256=acknowledgement.global_content_sha256,
        agent_revision_id=acknowledgement.agent_revision_id,
        agent_content_sha256=acknowledgement.agent_content_sha256,
        effective_sha256=acknowledgement.effective_sha256,
        global_revision=global_revision,
        agent_revision=agent_revision,
        current_effective_sha256=effective_sha256,
    ):
        return "current"
    return "stale"


def _effective_roe_from_connection(
    connection: sqlite3.Connection,
    agent_id: str | None,
    credential_record_id: str | None = None,
) -> EffectiveRoe:
    global_revision = _current_roe_revision(connection, "global")
    if global_revision is None:
        raise StorageError("current global RoE revision is unavailable")
    agent_revision = (
        None
        if agent_id is None
        else _current_roe_revision(connection, f"agent:{agent_id}")
    )
    effective_sha256 = composition_sha256(global_revision, agent_revision)
    acknowledgement = _latest_roe_acknowledgement(
        connection, agent_id, credential_record_id,
    )
    return EffectiveRoe(
        global_revision=global_revision,
        agent_revision=agent_revision,
        effective_sha256=effective_sha256,
        acknowledgement_status=_acknowledgement_status(
            acknowledgement,
            global_revision=global_revision,
            agent_revision=agent_revision,
            effective_sha256=effective_sha256,
        ),
        acknowledgement=acknowledgement,
    )


def _require_active_agent(
    connection: sqlite3.Connection,
    agent_id: str,
) -> None:
    _require_agent_access(connection)
    agent = connection.execute(
        "SELECT 1 FROM agents WHERE id = ? AND revoked_at IS NULL AND blocked_at IS NULL",
        (agent_id,),
    ).fetchone()
    if agent is None:
        raise AgentNotFoundError("authenticated agent is unavailable")


def _require_active_credential(
    connection: sqlite3.Connection,
    agent_id: str,
    credential_id: str,
) -> None:
    _require_live_credential(connection, agent_id, credential_id, checked_at=utc_now())
    credential = connection.execute(
        """
        SELECT 1
        FROM agent_credentials
        WHERE id = ? AND agent_id = ? AND status = 'active'
        """,
        (credential_id, agent_id),
    ).fetchone()
    if credential is None:
        raise CredentialNotFoundError("authenticated credential is unavailable")


def _require_live_credential(
    connection: sqlite3.Connection,
    agent_id: str,
    credential_id: str,
    *,
    checked_at: datetime,
) -> None:
    _require_agent_access(connection)
    row = connection.execute(
        """
        SELECT 1 FROM agent_credentials AS c JOIN agents AS a ON a.id = c.agent_id
        WHERE c.id = ? AND a.id = ? AND a.revoked_at IS NULL AND a.blocked_at IS NULL
          AND (a.expires_at IS NULL OR a.expires_at > ?)
          AND (c.status = 'active' OR (c.status = 'pending' AND c.pending_expires_at > ?))
        """,
        (credential_id, agent_id, _format_utc(checked_at), _format_utc(checked_at)),
    ).fetchone()
    if row is None:
        raise CredentialNotFoundError("authenticated credential is unavailable")


def _initialized_access_state(row: sqlite3.Row) -> AccessFreezeState:
    """The never-changed state: thawed, with no timestamp and no reason."""

    if row["frozen"] or row["changed_at"] is not None or row["reason"] is not None:
        raise StorageError("agent access state is invalid")
    return AccessFreezeState(
        frozen=False,
        transition=row["transition"],
        changed_at=None,
        reason=None,
    )


def _stored_access_change_time(value: str) -> datetime:
    try:
        changed_at = _parse_utc(value)
    except StorageError as error:
        raise StorageError("agent access state is invalid") from error
    if changed_at is None:
        raise StorageError("agent access state is invalid")
    return changed_at


def _stored_access_change_reason(value: str) -> str:
    try:
        reason = normalize_access_freeze_reason(value)
    except DomainValidationError as error:
        raise StorageError("agent access state is invalid") from error
    if reason != value:
        raise StorageError("agent access state is invalid")
    return reason


def _changed_access_state(row: sqlite3.Row) -> AccessFreezeState:
    """A recorded freeze or unfreeze, which must carry when and why."""

    frozen = bool(row["frozen"])
    transition = row["transition"]
    changed_at_value = row["changed_at"]
    reason_value = row["reason"]
    if (
        frozen != (transition == "freeze")
        or not isinstance(changed_at_value, str)
        or not isinstance(reason_value, str)
    ):
        raise StorageError("agent access state is invalid")
    changed_at = _stored_access_change_time(changed_at_value)
    reason = _stored_access_change_reason(reason_value)
    return AccessFreezeState(
        frozen=frozen,
        transition=transition,
        changed_at=changed_at,
        reason=reason,
    )


def _access_freeze_from_connection(
    connection: sqlite3.Connection,
) -> AccessFreezeState:
    rows = connection.execute(
        """
        SELECT singleton, frozen, transition, changed_at, reason
        FROM agent_access_state
        """
    ).fetchall()
    if len(rows) != 1 or rows[0]["singleton"] != 1:
        raise StorageError("agent access state is unavailable")
    row = rows[0]
    if row["frozen"] not in {0, 1} or row["transition"] not in {
        "initialized",
        "freeze",
        "unfreeze",
    }:
        raise StorageError("agent access state is invalid")
    if row["transition"] == "initialized":
        return _initialized_access_state(row)
    return _changed_access_state(row)


def _require_agent_access(connection: sqlite3.Connection) -> None:
    if _access_freeze_from_connection(connection).frozen:
        raise AgentAccessFrozenError("agent access is frozen")


#: Actor types that represent a human operating the service directly, rather
#: than an agent using it. A freeze stops the agent plane; it must not stop the
#: humans containing the incident, or the control prevents the very action it
#: exists to enable. ``local-admin`` was already exempt through the protected
#: CLI, so this generalises an existing property rather than introducing one.
#:
#: This exemption covers reads and containment transitions only. Restoring
#: lifecycle access or creating/redeeming a credential stays denied, because nothing
#: that can grant access should come into existence while the owner has
#: stopped trusting the system's state.
_HUMAN_ACTOR_TYPES = frozenset({"local-admin", "remote-admin"})
_ACCESS_FREEZE_ACTOR_TYPES = frozenset({"system", "local-admin", "remote-admin"})
_LIFECYCLE_TRANSITION_STATES = {
    "block": frozenset({"enabled"}),
    "unblock": frozenset({"blocked"}),
    "retire": frozenset({"enabled", "blocked"}),
}


def _checked_transition_agent(
    connection: sqlite3.Connection, agent_id: str, action: str, expected_epoch: int,
) -> Agent:
    row = connection.execute(_AGENT_SELECT + " WHERE id = ?", (agent_id,)).fetchone()
    if row is None:
        raise AgentNotFoundError("agent is unavailable")
    agent = _agent_from_row(row)
    if agent.credential_epoch != expected_epoch or agent.state not in _LIFECYCLE_TRANSITION_STATES[action]:
        raise CredentialConflictError("agent lifecycle state changed")
    return agent


def _lifecycle_input_hash(operation: str, *values: object) -> str:
    payload = json.dumps(
        [operation, *values],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _canonical_request_id(value: str) -> str:
    try:
        if (
            not isinstance(value, str)
            or len(value) != 36
            or str(uuid.UUID(value)) != value
        ):
            raise ValueError
    except (ValueError, AttributeError):
        raise DomainValidationError("request_id must be a canonical UUID") from None
    return value


def _accepted_post(
    connection: sqlite3.Connection,
    *,
    request_id: str | None,
    agent_id: str,
    channel_name: str,
    body: str,
    kind: str,
    reply_to: int | None,
    metadata_json: str,
) -> Message | None:
    if request_id is None:
        return None
    _canonical_request_id(request_id)
    row = connection.execute(
        """
        SELECT m.seq, m.id, c.name AS channel_name, m.agent_id,
               a.name AS agent_name, m.body, m.kind, m.reply_to,
               m.meta, m.created_at
        FROM messages AS m
        JOIN channels AS c ON c.id = m.channel_id
        JOIN agents AS a ON a.id = m.agent_id
        WHERE m.agent_id = ? AND m.post_request_id = ?
        """,
        (agent_id, request_id),
    ).fetchone()
    if row is None:
        return None
    accepted = (row["channel_name"], row["body"], row["kind"], row["reply_to"], row["meta"])
    intended = (channel_name, body, kind, reply_to, metadata_json)
    if accepted != intended:
        raise PostRequestConflictError(
            "post request_id conflicts with previously accepted input"
        )
    return _message_from_row(row)


def _post_message(
    connection: sqlite3.Connection,
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
    request_id: str | None,
) -> Message | None:
    """Insert one message; None means it committed but could not be read back."""
    accepted = _accepted_post(
        connection,
        request_id=request_id,
        agent_id=agent_id,
        channel_name=channel_name,
        body=body,
        kind=kind,
        reply_to=reply_to,
        metadata_json=metadata_json,
    )
    if accepted is not None:
        return accepted
    channel = connection.execute(
        "SELECT id FROM channels WHERE name = ?",
        (channel_name,),
    ).fetchone()
    if channel is None:
        raise ChannelNotFoundError(
            f"channel {channel_name!r} was not found"
        )
    if reply_to is not None:
        target = connection.execute(
            """
            SELECT 1 FROM messages
            WHERE seq = ? AND channel_id = ?
            """,
            (reply_to, channel["id"]),
        ).fetchone()
        if target is None:
            raise ReplyNotFoundError(
                "reply target was not found in this channel"
            )
    mentioned_agents: dict[str, str] = {}
    for mentioned_name in mentioned_names:
        mentioned_agent = connection.execute(
            """
            SELECT id, name
            FROM agents
            WHERE name = ? AND revoked_at IS NULL
            """,
            (mentioned_name,),
        ).fetchone()
        if mentioned_agent is None:
            raise UnknownMentionError(
                f"mentioned agent {mentioned_name!r} was not found"
            )
        mentioned_agents[mentioned_name] = mentioned_agent["id"]
    cursor = connection.execute(
        """
        INSERT INTO messages (
            id, channel_id, agent_id, body, kind, reply_to,
            meta, created_at, post_request_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            message_id,
            channel["id"],
            agent_id,
            body,
            kind,
            reply_to,
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
    connection.executemany(
        """
        INSERT INTO mentions (message_seq, agent_id)
        VALUES (?, ?)
        """,
        (
            (cursor.lastrowid, mentioned_agents[name])
            for name in mentioned_names
        ),
    )
    if row is None:
        return None
    return _message_from_row(row)


def _audit_text(value: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or len(value) > maximum
        or any(unicodedata.category(char).startswith("C") for char in value)
        or len(value.encode("utf-8")) > 1024
    ):
        raise DomainValidationError("audit text must be bounded, trimmed, printable text")
    return value


def _validate_access_freeze_actor(actor_type: str, actor_id: str) -> None:
    if actor_type not in _ACCESS_FREEZE_ACTOR_TYPES:
        raise DomainValidationError("access-freeze actor type is invalid")
    _audit_text(actor_id)


def _validate_device_actor(actor: LifecycleActor) -> None:
    # An enrolled device acting on its write grant (enrollment from the
    # app). It is only ever built by the mobile routes after the grant is
    # verified, and must bring a revalidator that re-checks the device
    # under the writer lock.
    if actor.actor_type != "remote-admin" or not callable(actor.revalidate):
        raise DomainValidationError("device revalidation is required")


def _validate_operator_actor(actor: LifecycleActor) -> None:
    if actor.actor_type != "remote-admin" or not actor.actor_id.startswith("operator:owner:"):
        raise DomainValidationError("operator context is required")
    correlation = actor.actor_id.removeprefix("operator:owner:")
    try:
        identifier = uuid.UUID(correlation)
    except ValueError:
        raise DomainValidationError("operator actor must contain a UUID") from None
    if correlation not in {str(identifier), identifier.hex}:
        raise DomainValidationError("operator actor must contain a UUID")
    if not callable(actor.revalidate):
        raise DomainValidationError("operator session revalidation is required")


def _validate_actor(actor: LifecycleActor, *, operator_only: bool = False) -> None:
    if not isinstance(actor, LifecycleActor):
        raise DomainValidationError("trusted human context is required")
    if actor.actor_type not in {"local-admin", "remote-admin"}:
        raise DomainValidationError("trusted human context is required")
    _audit_text(actor.actor_id)
    is_operator = actor.actor_id.startswith("operator:")
    if operator_only and actor.actor_id.startswith("device:"):
        _validate_device_actor(actor)
    elif operator_only or is_operator:
        _validate_operator_actor(actor)
    if actor.revalidate is not None:
        actor.revalidate()


def _validate_expected_epoch(value: int) -> None:
    if type(value) is not int or not 0 <= value < 2**63 - 1:
        raise DomainValidationError("expected credential epoch is invalid")


def _grant_from_row(row: sqlite3.Row) -> AgentReconnectGrant:
    values = {name: row[name] for name in AgentReconnectGrant.__dataclass_fields__}
    for name in ("created_at", "expires_at", "redeemed_at", "revoked_at", "expired_at"):
        values[name] = _parse_utc(values[name])
    return AgentReconnectGrant(**values)


def _lifecycle_event_from_row(row: sqlite3.Row) -> AgentLifecycleEvent:
    values = {name: row[name] for name in AgentLifecycleEvent.__dataclass_fields__}
    values["occurred_at"] = _parse_utc(values["occurred_at"])
    return AgentLifecycleEvent(**values)


def _record_lifecycle_event(
    connection: sqlite3.Connection,
    *,
    agent: Agent,
    action: str,
    request_id: str,
    intent_sha256: str,
    actor_type: str,
    actor_id: str,
    reason: str,
    timestamp: str,
    resulting_state: str | None = None,
    advance_epoch: bool = True,
    grant_id: str | None = None,
) -> AgentLifecycleEvent:
    event_id = str(uuid.uuid4())
    connection.execute(
        """
        INSERT INTO agent_lifecycle_audit (
            id, request_id, intent_sha256, agent_id, action,
            previous_state, resulting_state, previous_epoch, resulting_epoch,
            actor_type, actor_id, occurred_at, reason, grant_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, request_id, intent_sha256, agent.id, action, agent.state,
         resulting_state or agent.state, agent.credential_epoch,
         agent.credential_epoch + int(advance_epoch), actor_type, actor_id,
         timestamp, reason, grant_id),
    )
    return _lifecycle_event_from_row(connection.execute(
        "SELECT * FROM agent_lifecycle_audit WHERE id = ?", (event_id,)
    ).fetchone())


def _invalidate_reconnect_grants(
    connection: sqlite3.Connection,
    *,
    agent: Agent,
    request_id: str,
    actor_type: str,
    actor_id: str,
    reason: str,
    timestamp: str,
) -> None:
    row = connection.execute(
        "SELECT * FROM agent_reconnect_grants WHERE agent_id = ? AND status = 'pending'",
        (agent.id,),
    ).fetchone()
    if row is None:
        return
    expired = row["expires_at"] <= timestamp
    status = "expired" if expired else "revoked"
    connection.execute(
        """
        UPDATE agent_reconnect_grants SET status = ?, version = version + 1,
            expired_at = ?, revoked_at = ?
        WHERE id = ? AND status = 'pending' AND version = ?
        """,
        (status, timestamp if expired else None, None if expired else timestamp,
         row["id"], row["version"]),
    )
    _record_lifecycle_event(
        connection, agent=agent,
        action="reconnect-expire" if expired else "reconnect-invalidate",
        request_id=request_id,
        intent_sha256=_lifecycle_input_hash(status, row["id"], request_id, reason),
        actor_type=actor_type, actor_id=actor_id, reason=reason,
        timestamp=timestamp, advance_epoch=False, grant_id=row["id"],
    )


def _advance_credential_epoch(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    request_id: str,
    actor_type: str,
    actor_id: str,
    reason: str,
    timestamp: str,
) -> None:
    agent = _agent_from_row(connection.execute(
        _AGENT_SELECT + " WHERE id = ?", (agent_id,)
    ).fetchone())
    _invalidate_reconnect_grants(
        connection, agent=agent, request_id=request_id, actor_type=actor_type,
        actor_id=actor_id, reason=reason, timestamp=timestamp,
    )
    connection.execute(
        "UPDATE agents SET credential_epoch = credential_epoch + 1 WHERE id = ?",
        (agent_id,),
    )


def _revoke_live_credentials(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    request_id: str,
    actor_type: str,
    actor_id: str,
    reason: str,
    timestamp: str,
    event_type: str,
    method: str,
    related_credential_id: str | None = None,
    exclude_credential_id: str = "",
) -> None:
    rows = connection.execute(
        "SELECT id, version FROM agent_credentials "
        "WHERE agent_id = ? AND status IN ('pending', 'active') AND id <> ? ORDER BY id",
        (agent_id, exclude_credential_id),
    ).fetchall()
    for row in rows:
        connection.execute(
            "UPDATE agent_credentials SET status = 'revoked', revoked_at = ?, "
            "version = version + 1 WHERE id = ? AND version = ?",
            (timestamp, row["id"], row["version"]),
        )
        connection.execute(
            """
            INSERT INTO agent_credential_audit (
                id, event_type, agent_id, credential_id, related_credential_id,
                actor_type, actor_id, method, reason, request_id, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), event_type, agent_id, row["id"], related_credential_id,
             actor_type, actor_id, method, reason, request_id, timestamp),
        )


def _retire_agent(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    request_id: str,
    intent_sha256: str,
    actor_type: str,
    actor_id: str,
    reason: str,
    timestamp: str,
) -> AgentLifecycleEvent:
    """Retire one enabled or blocked identity, as the operator's retire does."""

    agent = _agent_from_row(connection.execute(
        _AGENT_SELECT + " WHERE id = ?", (agent_id,)
    ).fetchone())
    _invalidate_reconnect_grants(
        connection, agent=agent, request_id=request_id, actor_type=actor_type,
        actor_id=actor_id, reason=reason, timestamp=timestamp,
    )
    _revoke_live_credentials(
        connection, agent_id=agent_id, request_id=request_id,
        actor_type=actor_type, actor_id=actor_id, reason=reason,
        timestamp=timestamp, event_type="agent-revoke", method="agent-revocation",
    )
    connection.execute(
        "UPDATE agents SET blocked_at = NULL, revoked_at = ?, "
        "credential_epoch = credential_epoch + 1 WHERE id = ? AND credential_epoch = ?",
        (timestamp, agent_id, agent.credential_epoch),
    )
    return _record_lifecycle_event(
        connection, agent=agent, action="retire", request_id=request_id,
        intent_sha256=intent_sha256, actor_type=actor_type, actor_id=actor_id,
        reason=reason, timestamp=timestamp, resulting_state="retired",
    )


def _insert_pending_credential(
    connection: sqlite3.Connection, *, agent_id: str, credential_id: str,
    secret_hash: str, request_id: str, method: str, reason: str,
    timestamp: str, expires_at: str, predecessor_id: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO agent_credentials (
            id, agent_id, kind, secret_hash, status, predecessor_id,
            creation_method, creation_reason, issuance_request_id,
            created_at, pending_expires_at)
        VALUES (?, ?, 'sb1', ?, 'pending', ?, ?, ?, ?, ?, ?)
        """,
        (credential_id, agent_id, secret_hash, predecessor_id, method, reason,
         request_id, timestamp, expires_at),
    )


def _expire_pending_credentials(
    connection: sqlite3.Connection,
    *,
    now: datetime,
    agent_id: str | None = None,
) -> None:
    timestamp = _format_utc(now)
    parameters: list[object] = [timestamp]
    query = (
        "SELECT id, agent_id, version FROM agent_credentials "
        "WHERE status = 'pending' AND pending_expires_at <= ?"
    )
    if agent_id is not None:
        query += " AND agent_id = ?"
        parameters.append(agent_id)
    rows = connection.execute(query, parameters).fetchall()
    for row in rows:
        request_id = f"expire:{row['id']}:{timestamp}"
        connection.execute(
            """
            UPDATE agent_credentials
            SET status = 'expired', expired_at = ?, version = version + 1
            WHERE id = ? AND status = 'pending' AND version = ?
            """,
            (timestamp, row["id"], row["version"]),
        )
        connection.execute(
            """
            INSERT INTO agent_credential_audit (
                id, event_type, agent_id, credential_id,
                actor_type, actor_id, method, reason, request_id, occurred_at
            )
            VALUES (?, 'expire', ?, ?, 'system', 'system:credential-expiry',
                    'pending-expiry', 'pending credential lifetime elapsed', ?, ?)
            """,
            (str(uuid.uuid4()), row["agent_id"], row["id"], request_id, timestamp),
        )
