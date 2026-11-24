"""Core domain values exposed by the storage and authentication services."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from collections.abc import Callable
from typing import Any


@dataclass(frozen=True, slots=True)
class Agent:
    id: str
    name: str
    description: str
    host: str
    created_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None
    credential_epoch: int
    blocked_at: datetime | None = None

    @property
    def state(self) -> str:
        if self.revoked_at is not None:
            return "retired"
        return "blocked" if self.blocked_at is not None else "enabled"


@dataclass(frozen=True, slots=True)
class IdentityCreationProvenance:
    agent: Agent
    creation_method: str
    creator_principal_type: str
    creator_principal_id: str
    originating_request_id: str
    originating_enrollment_id: str | None
    originating_issuance_request_id: str | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class IdentityCreationProvenancePage:
    items: tuple[IdentityCreationProvenance, ...]
    total_count: int
    has_more: bool
    next_created_at: datetime | None
    next_agent_id: str | None


@dataclass(frozen=True, slots=True)
class LifecycleActor:
    """Trusted adapter context, never constructed from posted actor fields.

    Browser adapters must provide a session revalidator and a server-generated
    ``operator:owner:<UUID>`` audit ID. The callback runs under the writer lock.
    """

    actor_type: str
    actor_id: str
    revalidate: Callable[[], None] | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class AgentLifecycleEvent:
    seq: int
    id: str
    request_id: str
    intent_sha256: str
    agent_id: str
    action: str
    previous_state: str
    resulting_state: str
    previous_epoch: int
    resulting_epoch: int
    actor_type: str
    actor_id: str
    occurred_at: datetime
    reason: str
    grant_id: str | None


@dataclass(frozen=True, slots=True)
class AgentLifecycleResult:
    event: AgentLifecycleEvent
    changed: bool


@dataclass(frozen=True, slots=True)
class AgentReconnectGrant:
    id: str
    agent_id: str
    issuance_request_id: str
    intent_sha256: str
    bound_epoch: int
    status: str
    created_at: datetime
    expires_at: datetime
    actor_type: str
    actor_id: str
    reason: str
    redeemed_at: datetime | None
    revoked_at: datetime | None
    expired_at: datetime | None
    redemption_request_id: str | None
    result_credential_id: str | None
    version: int


@dataclass(frozen=True, slots=True)
class IssuedReconnectGrant:
    grant: AgentReconnectGrant
    token: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class PreparedReconnectGrant:
    """Uncommitted material for bounded, pre-cutoff package serialization."""

    id: str
    created_at: datetime
    expires_at: datetime
    secret_hash: str = field(repr=False)
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RedeemedReconnectGrant:
    agent: Agent
    issued_credential: IssuedCredential
    grant: AgentReconnectGrant


@dataclass(frozen=True, slots=True)
class AgentCredential:
    id: str
    agent_id: str
    kind: str
    status: str
    predecessor_id: str | None
    creation_method: str
    creation_reason: str
    created_at: datetime
    activated_at: datetime | None
    identity_verified_at: datetime | None
    pending_expires_at: datetime | None
    last_used_at: datetime | None
    retired_at: datetime | None
    revoked_at: datetime | None
    expired_at: datetime | None
    version: int


@dataclass(frozen=True, slots=True)
class AuthenticatedIdentity:
    agent: Agent
    credential: AgentCredential

    @property
    def id(self) -> str:
        return self.agent.id

    @property
    def name(self) -> str:
        return self.agent.name

    @property
    def last_seen_at(self) -> datetime | None:
        return self.agent.last_seen_at


@dataclass(frozen=True, slots=True)
class MobileIdentity:
    """A resolved mobile monitor device and the credential that proved it.

    Deliberately not an ``AuthenticatedIdentity``: a monitor is not an agent,
    carries no coordination authority, and must not be passable to anything
    expecting one.
    """

    device_id: str
    device_label: str
    credential_id: str
    credential_kind: str


@dataclass(frozen=True, slots=True)
class ServicePrincipal:
    id: str
    name: str
    agent_name_prefix: str
    status: str
    created_at: datetime
    blocked_at: datetime | None
    revoked_at: datetime | None
    version: int


@dataclass(frozen=True, slots=True)
class ServicePrincipalIdentity:
    spn_id: str
    spn_name: str
    agent_name_prefix: str
    credential_id: str
    credential_kind: str


@dataclass(frozen=True, slots=True)
class IssuedServicePrincipal:
    principal: ServicePrincipal
    credential_id: str
    secret: str | None = field(default=None, repr=False)
    secret_issued: bool = False


@dataclass(frozen=True, slots=True)
class OnboardingIssuance:
    request_id: str
    spn_id: str
    enrollment_id: str
    agent_name: str
    created_at: datetime
    expires_at: datetime
    token: str | None = field(default=None, repr=False)
    secret_issued: bool = False


@dataclass(frozen=True, slots=True)
class IssuedCredential:
    credential: AgentCredential
    secret: str | None = field(default=None, repr=False)
    secret_issued: bool = False


@dataclass(frozen=True, slots=True)
class CreatedAgent:
    agent: Agent
    issued_credential: IssuedCredential

    @property
    def api_key(self) -> str:
        if self.issued_credential.secret is None:
            raise RuntimeError("credential secret is unavailable")
        return self.issued_credential.secret


@dataclass(frozen=True, slots=True)
class AgentEnrollment:
    id: str
    name_prefix: str
    name_match: str
    description: str
    status: str
    uses_allowed: int
    uses_remaining: int
    created_at: datetime
    expires_at: datetime
    last_redeemed_at: datetime | None
    exhausted_at: datetime | None
    revoked_at: datetime | None
    revocation_reason: str | None
    actor_type: str
    actor_id: str
    creation_reason: str
    version: int


@dataclass(frozen=True, slots=True)
class IssuedEnrollment:
    enrollment: AgentEnrollment
    token: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class RedeemedEnrollment:
    agent: Agent
    issued_credential: IssuedCredential
    enrollment_id: str

    @property
    def api_key(self) -> str:
        if self.issued_credential.secret is None:
            raise RuntimeError("credential secret is unavailable")
        return self.issued_credential.secret


@dataclass(frozen=True, slots=True)
class OrientationChannel:
    name: str
    unread: int
    unread_capped: bool = False


@dataclass(frozen=True, slots=True)
class AgentOrientation:
    latest_seq: int
    unread: int
    unread_capped: bool
    pending_mentions: int
    pending_mentions_capped: bool
    last_caught_up_at: datetime | None
    channels: tuple[OrientationChannel, ...]
    new_channels: tuple[str, ...]
    subscription_count: int = 0
    counts_complete: bool = True
    subscribed_channels_truncated: bool = False
    new_channels_truncated: bool = False

    @property
    def last_cursor_update_at(self) -> datetime | None:
        """The last cursor update; last_caught_up_at is a deprecated alias."""

        return self.last_caught_up_at


@dataclass(frozen=True, slots=True)
class AccessFreezeState:
    frozen: bool
    transition: str
    changed_at: datetime | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class RoeRevision:
    id: str
    target_key: str
    scope: str
    agent_id: str | None
    version: int
    policy_schema_version: int
    content_json: str
    content_sha256: str
    author_label: str
    publisher_type: str
    publisher_identity: str
    created_at: datetime
    superseded_at: datetime | None


@dataclass(frozen=True, slots=True)
class RoeAcknowledgement:
    id: str
    agent_id: str
    global_revision_id: str
    global_content_sha256: str
    agent_revision_id: str | None
    agent_content_sha256: str | None
    effective_sha256: str
    acknowledged_at: datetime
    credential_kind: str
    credential_id: str
    credential_record_id: str


@dataclass(frozen=True, slots=True)
class EffectiveRoe:
    global_revision: RoeRevision
    agent_revision: RoeRevision | None
    effective_sha256: str
    acknowledgement_status: str
    acknowledgement: RoeAcknowledgement | None


@dataclass(frozen=True, slots=True)
class Channel:
    id: str
    name: str
    purpose: str
    created_at: datetime
    created_by: str | None


@dataclass(frozen=True, slots=True)
class Message:
    seq: int
    id: str
    channel: str
    agent_id: str
    agent_name: str
    body: str
    kind: str
    reply_to: int | None
    metadata: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class MessageClaim:
    message_seq: int
    agent_id: str
    agent_name: str
    claimed_at: datetime


@dataclass(frozen=True, slots=True)
class SearchHit:
    message: Message
    snippet: str


@dataclass(frozen=True, slots=True)
class DashboardCounts:
    active_agents: int
    channels: int
    subscriptions: int
    blocked_agents: int = 0
    retired_agents: int = 0

    @property
    def enabled_agents(self) -> int:
        return self.active_agents


@dataclass(frozen=True, slots=True)
class DashboardSnapshot:
    counts: DashboardCounts
    messages: tuple[Message, ...]
    parent_messages: tuple[Message, ...]
    has_older: bool
    board_has_messages: bool


@dataclass(frozen=True, slots=True)
class DashboardChannelSummary:
    name: str
    purpose: str
    created_at: datetime
    message_count: int
    last_activity_at: datetime | None
    active_subscriber_count: int


@dataclass(frozen=True, slots=True)
class DashboardChannelPage:
    channels: tuple[DashboardChannelSummary, ...]
    has_more: bool


@dataclass(frozen=True, slots=True)
class DashboardAgentSummary:
    name: str
    created_at: datetime
    last_seen_at: datetime | None


@dataclass(frozen=True, slots=True)
class DashboardAgentPage:
    agents: tuple[DashboardAgentSummary, ...]
    has_more: bool
