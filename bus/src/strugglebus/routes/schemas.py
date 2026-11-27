from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictStr
from pydantic.json_schema import SkipJsonSchema

from strugglebus.models import (
    Agent,
    AgentCredential,
    Channel,
    EffectiveRoe,
    IdentityCreationProvenance,
    Message,
    MessageClaim,
    RoeAcknowledgement,
    RoeRevision,
    SearchHit,
)
from strugglebus.service import MAX_SEQUENCE


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AgentRegistration(StrictModel):
    request_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    host: str = Field(default="", max_length=255)


class EnrollmentRedemption(StrictModel):
    request_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    host: str = Field(default="", max_length=255)


class ReconnectRedemption(StrictModel):
    request_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    expected_agent_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    expected_agent_name: str = Field(min_length=1, max_length=128)


class SPNOnboardingRequest(StrictModel):
    request_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    agent_name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    ttl_seconds: int | None = Field(default=None, ge=60, le=900)
    identity_ttl_seconds: int | None = Field(default=None, ge=60, le=43200)


class SPNRequest(StrictModel):
    request_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )


class AgentResponse(StrictModel):
    id: str
    name: str
    description: str
    host: str
    created_at: datetime
    last_seen_at: datetime | None
    credential_epoch: int

    @classmethod
    def from_domain(cls, agent: Agent) -> AgentResponse:
        return cls(
            id=agent.id,
            name=agent.name,
            description=agent.description,
            host=agent.host,
            created_at=agent.created_at,
            last_seen_at=agent.last_seen_at,
            credential_epoch=agent.credential_epoch,
        )


class IdentityCreationProvenanceResponse(StrictModel):
    agent: AgentResponse
    state: Literal["enabled", "blocked", "retired"]
    creation_method: str
    creator_principal_type: Literal[
        "system", "local-admin", "remote-admin", "spn"
    ]
    creator_principal_id: str
    originating_request_id: str
    originating_enrollment_id: str | None
    originating_issuance_request_id: str | None
    created_at: datetime

    @classmethod
    def from_domain(
        cls, provenance: IdentityCreationProvenance,
    ) -> IdentityCreationProvenanceResponse:
        return cls(
            agent=AgentResponse.from_domain(provenance.agent),
            state=provenance.agent.state,
            creation_method=provenance.creation_method,
            creator_principal_type=provenance.creator_principal_type,
            creator_principal_id=provenance.creator_principal_id,
            originating_request_id=provenance.originating_request_id,
            originating_enrollment_id=provenance.originating_enrollment_id,
            originating_issuance_request_id=(
                provenance.originating_issuance_request_id
            ),
            created_at=provenance.created_at,
        )


class IdentityCreationCursorResponse(StrictModel):
    created_at: datetime
    agent_id: str


class IdentityCreationProvenancePageResponse(StrictModel):
    items: list[IdentityCreationProvenanceResponse]
    page_count: int
    total_count: int
    has_more: bool
    next_cursor: IdentityCreationCursorResponse | None


class CredentialResponse(StrictModel):
    id: str
    agent_id: str
    kind: Literal["legacy-sha256-v1", "sb1"]
    status: Literal["pending", "active", "retired", "revoked", "expired"]
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

    @classmethod
    def from_domain(cls, credential: AgentCredential) -> CredentialResponse:
        return cls(**{
            field: getattr(credential, field)
            for field in cls.model_fields
        })


class IssuedCredentialResponse(StrictModel):
    credential: CredentialResponse
    credential_secret: str | None
    secret_issued: bool


class CreatedAgentResponse(StrictModel):
    agent: AgentResponse
    credential: CredentialResponse
    credential_secret: str | None
    secret_issued: bool
    expected_identity_guidance: str


class RedeemedEnrollmentResponse(StrictModel):
    agent: AgentResponse
    credential: CredentialResponse
    credential_secret: str
    expected_identity_guidance: str
    next_steps: list[str]


class MobileEnrollmentRedemption(StrictModel):
    request_id: str = Field(min_length=1, max_length=128)


class RedeemedMobileResponse(StrictModel):
    device_id: str
    device_label: str
    credential_id: str
    credential_secret: str
    guidance: str


class MobileWriteGrantRequest(StrictModel):
    """Establish a device's write grant by proving the operator password once."""

    request_id: str = Field(min_length=1, max_length=128)
    operator_password: str = Field(min_length=15, max_length=1024)
    reason: str = Field(min_length=1, max_length=256)


class MobileWriteGrantResponse(StrictModel):
    device_id: str
    grant_secret: str
    guidance: str


class MobileConfirmationRequest(StrictModel):
    request_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=64)
    target_id: str = Field(min_length=1, max_length=256)


class MobileConfirmationResponse(StrictModel):
    confirmation_id: str
    action: str
    target_kind: str
    target_id: str
    target_label: str
    expires_at: datetime
    effect: str


class MobileActionRequest(StrictModel):
    """Spend a confirmation.

    ``action`` and ``target_id`` are re-declared rather than read from the
    confirmation, so a client that displayed one thing and spent a
    confirmation bound to another is refused instead of silently executing the
    bound action.
    """

    request_id: str = Field(min_length=1, max_length=128)
    confirmation_id: str = Field(min_length=1, max_length=256)
    action: str = Field(min_length=1, max_length=64)
    target_id: str = Field(min_length=1, max_length=256)
    grant_secret: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=256)


class MobileHumanPostRequest(StrictModel):
    """Post to #humans from a device holding its write grant."""

    request_id: PostRequestId = None
    body: str = Field(min_length=1)
    kind: Literal["chat", "question", "answer"] = "chat"
    reply_to: int | None = Field(default=None, ge=1, le=MAX_SEQUENCE)
    grant_secret: str = Field(min_length=1, max_length=256)


class MobileHostCommandRequest(StrictModel):
    """Carry one signed host command to a worker hosts' channel."""

    request_id: PostRequestId = None
    channel: str = Field(min_length=1, max_length=64)
    #: Base64 of exactly the bytes that were signed. The bus does not read them.
    document: str = Field(min_length=1, max_length=1400)
    signature: str = Field(min_length=1, max_length=4200)
    grant_secret: str = Field(min_length=1, max_length=256)


class MobileAgentEnrollmentRequest(StrictModel):
    """Create a single-use agent enrollment from a device holding its write grant."""

    request_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    reason: str = Field(min_length=1, max_length=256)
    grant_secret: str = Field(min_length=1, max_length=256)


class MobileAgentEnrollmentResponse(StrictModel):
    enrollment_id: str
    agent_name: str
    expires_at: datetime
    package: str


class MobileServicePrincipalRequest(StrictModel):
    """Create a service principal from a device holding its write grant."""

    request_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=64)
    agent_name_prefix: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=256)
    grant_secret: str = Field(min_length=1, max_length=256)


class MobileServicePrincipalResponse(StrictModel):
    service_principal_id: str
    name: str
    agent_name_prefix: str
    secret_issued: bool
    credential_secret: str | None


class MobileHostEnrollmentRequest(StrictModel):
    """Create a single-use code for one worker host, from a device holding its write grant."""

    request_id: str = Field(min_length=1, max_length=128)
    host_prefix: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=256)
    grant_secret: str = Field(min_length=1, max_length=256)


class MobileHostEnrollmentResponse(StrictModel):
    host_prefix: str
    expires_at: datetime
    code_issued: bool
    #: Shown once. None when this request id already minted the code.
    code: str | None


class SiteDocumentResponse(StrictModel):
    """Signed bytes the bus holds for a site. The bus does not verify them."""

    name: str
    serial: int
    #: Base64 of exactly the bytes that were signed.
    body: str
    signature: str
    signer_fingerprint: str
    stored_at: datetime

    @classmethod
    def from_domain(cls, document) -> SiteDocumentResponse:
        return cls(
            name=document.name,
            serial=document.serial,
            body=base64.b64encode(document.body).decode("ascii"),
            signature=document.signature,
            signer_fingerprint=document.signer_fingerprint,
            stored_at=document.stored_at,
        )


class MobileSiteDocumentRequest(StrictModel):
    """Publish a signed document from a device holding its write grant."""

    serial: int = Field(ge=1)
    #: Base64 of exactly the bytes that were signed.
    body: str = Field(min_length=1, max_length=90000)
    signature: str = Field(min_length=1, max_length=4200)
    signer_fingerprint: str = Field(default="", max_length=128)
    reason: str = Field(min_length=1, max_length=256)
    grant_secret: str = Field(min_length=1, max_length=256)


class HostRedemptionRequest(StrictModel):
    """A worker host redeeming its code. The code itself is the bearer token."""

    request_id: str = Field(min_length=36, max_length=36)


class RedeemedHostResponse(StrictModel):
    name: str
    credential: str
    request_id: str


class MobileDeviceEnrollmentRequest(StrictModel):
    """Create a single-use device enrollment from a device holding its write grant."""

    request_id: str = Field(min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=256)
    grant_secret: str = Field(min_length=1, max_length=256)


class MobileDeviceEnrollmentResponse(StrictModel):
    device_label: str
    expires_at: datetime
    payload: str


class MobileActionResponse(StrictModel):
    action: str
    target_id: str
    target_label: str
    applied: bool
    detail: str


class MobileAdminActionOption(StrictModel):
    """One action a listed target currently allows, with its effect in words."""

    action: str
    effect: str


class MobileManagedAgentResponse(StrictModel):
    id: str
    name: str
    description: str
    host: str
    state: Literal["enabled", "blocked", "retired"]
    credential_epoch: int
    created_at: datetime
    last_seen_at: datetime | None
    blocked_at: datetime | None
    retired_at: datetime | None
    actions: list[MobileAdminActionOption]


class MobileManagedDeviceResponse(StrictModel):
    id: str
    label: str
    status: str
    created_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None
    has_write_grant: bool
    this_device: bool
    actions: list[MobileAdminActionOption]


class MobileManagedServicePrincipalResponse(StrictModel):
    id: str
    name: str
    agent_name_prefix: str
    status: str
    version: int
    created_at: datetime
    blocked_at: datetime | None
    revoked_at: datetime | None
    actions: list[MobileAdminActionOption]
    #: Set only for a worker host that joined with a host code: the request id
    #: it redeemed with, the address it came from and when. The operator's
    #: device works out the confirmation code from the request id.
    host_redeem_request_id: str | None = None
    host_redeemed_from: str | None = None
    host_redeemed_at: datetime | None = None


class MobileAgentControlRequest(StrictModel):
    """Act on one agent, naming exactly the agent that was displayed."""

    request_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    action: Literal["block", "unblock", "retire"]
    expected_name: str = Field(min_length=1, max_length=128)
    expected_credential_epoch: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=256)
    grant_secret: str = Field(min_length=1, max_length=256)


class HostReportResponse(StrictModel):
    """A host's report was stored. ``received_at`` is the bus's own time for it."""

    received_at: str


class HostEventsResponse(StrictModel):
    """A host's batch was accepted. ``stored`` counts the events not already stored."""

    stored: int


class MobileFullLogRequest(StrictModel):
    """The whole log, for an administrator: the device's grant and how many rows."""

    grant_secret: str = Field(min_length=1, max_length=256)
    limit: int = Field(default=200, ge=1, le=500)


class MobileHostStatus(StrictModel):
    """One marked host. ``snapshot`` is null until it has reported.

    The snapshot is the host's own claim about itself, checked for shape and
    nothing more. Show every value in it as plain text.
    """

    agent_id: str
    agent: str
    marked_at: str
    received_at: str | None
    snapshot: dict[str, Any] | None


class MobileHostsResponse(StrictModel):
    """Every marked host. ``now`` is the bus's clock: work out a report's age from it."""

    now: str
    hosts: list[MobileHostStatus]


class MobileHostHistoryResponse(StrictModel):
    """Up to twelve hours of one host's samples, oldest first."""

    now: str
    agent_id: str
    samples: list[dict[str, Any]]


class MobileGrantRequest(StrictModel):
    """A read that only an administrator may make: the device's grant, and nothing else."""

    grant_secret: str = Field(min_length=1, max_length=256)


class MobileHostMarkRequest(StrictModel):
    """Mark an agent as a worker host, or take the mark away, naming the agent displayed."""

    request_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    action: Literal["mark", "unmark"]
    expected_name: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=256)
    grant_secret: str = Field(min_length=1, max_length=256)


class MobileServicePrincipalControlRequest(StrictModel):
    """Act on one service principal, naming exactly the one displayed."""

    request_id: str = Field(min_length=1, max_length=128)
    action: Literal["block", "unblock", "rotate", "revoke"]
    expected_name: str = Field(min_length=1, max_length=64)
    expected_version: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=256)
    grant_secret: str = Field(min_length=1, max_length=256)


class MobileLogEntry(StrictModel):
    """One line of the operator's log view.

    ``source`` is ``audit`` (a committed lifecycle row), ``request`` (a
    lifecycle or refused request seen at the gateway) or ``server`` (a line
    from the server process). Only fields the SIEM feed already carries.
    """

    ts: datetime
    source: str
    level: str
    event: str
    subject: str | None
    actor: str | None
    status: int | None
    remote_address: str | None
    detail: str


class MobileLogResponse(StrictModel):
    version: str
    started_at: datetime | None
    entries: list[MobileLogEntry]


class MobileAdminControlResponse(StrictModel):
    """The outcome of a management action.

    ``secret`` is present only when the action minted one - a rotated service
    principal credential - and only on the request that minted it. A replay
    reports ``applied`` false and no secret.
    """

    action: str
    target_id: str
    target_label: str
    applied: bool
    state: str
    detail: str
    secret: str | None = None
    secret_kind: Literal["service-principal-credential"] | None = None


class MobileStatusResponse(StrictModel):
    """Minimal liveness for a mobile monitor.

    The shape is identical frozen or not, so only ``state`` carries meaning.
    Adding fields here erodes the reason this answers during a freeze at all.
    """

    api_version: int
    server_time: datetime
    state: Literal["available", "frozen"]


class OrientationChannelResponse(StrictModel):
    name: str
    unread: int
    unread_at_least: bool


class RequiredActionResponse(StrictModel):
    action: str
    reason: str


class OrientationResponse(StrictModel):
    agent: AgentResponse
    credential: CredentialResponse
    required_actions: list[RequiredActionResponse]
    guidance: str
    unread: int
    unread_at_least: bool
    pending_mentions: int
    pending_mentions_at_least: bool
    latest_seq: int
    last_caught_up_at: datetime | None
    last_cursor_update_at: datetime | None
    subscription_count: int
    counts_complete: bool
    subscribed_channels_truncated: bool
    new_channels_truncated: bool
    subscribed_channels: list[OrientationChannelResponse]
    new_channels: list[str]
    roe_acknowledgement_status: str


class WhoAmIResponse(StrictModel):
    agent: AgentResponse
    credential: CredentialResponse
    subscriptions: list[ChannelResponse]
    expected_identity_guidance: str


class LifecycleRequest(StrictModel):
    request_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    expected_credential_epoch: int = Field(ge=0)


class RotateCredentialRequest(LifecycleRequest):
    expected_agent_id: str = Field(min_length=1, max_length=128)
    expected_credential_id: str = Field(min_length=1, max_length=256)
    reason: str = Field(default="scheduled rotation", min_length=1, max_length=256)


class ProveCredentialRequest(LifecycleRequest):
    expected_agent_id: str = Field(min_length=1, max_length=128)
    expected_agent_name: str = Field(min_length=1, max_length=128)
    expected_credential_version: int = Field(ge=0)


class CredentialTransitionRequest(LifecycleRequest):
    expected_credential_version: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=256)


class AdminIssueCredentialRequest(LifecycleRequest):
    reason: str = Field(min_length=1, max_length=256)


class AdminAgentRevokeRequest(StrictModel):
    request_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )


class ChannelCreate(StrictModel):
    name: str = Field(min_length=1, max_length=64)
    purpose: str = Field(default="", max_length=1024)


class MobileChannelActivity(StrictModel):
    """One channel as the web console's Channels page shows it.

    ``subscriber_count`` counts agents that are neither blocked nor retired.
    ``last_activity_at`` is null for a channel nobody has posted in.
    """

    name: str
    purpose: str
    created_at: datetime
    message_count: int
    subscriber_count: int
    last_activity_at: datetime | None


class ChannelResponse(StrictModel):
    id: str
    name: str
    purpose: str
    created_at: datetime
    created_by: str | None

    @classmethod
    def from_domain(cls, channel: Channel) -> ChannelResponse:
        return cls(
            id=channel.id,
            name=channel.name,
            purpose=channel.purpose,
            created_at=channel.created_at,
            created_by=channel.created_by,
        )


class SubscriptionResponse(StrictModel):
    channel: ChannelResponse
    subscribed: bool


def _non_null_post_request_id(value: object) -> object:
    if value is None:
        raise ValueError("request_id must be a canonical UUID")
    return value


def _post_request_id_schema(schema: dict[str, Any]) -> None:
    schema.pop("default", None)


_CanonicalPostRequestId = Annotated[
    StrictStr,
    Field(
        min_length=36,
        max_length=36,
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    ),
]
PostRequestId = Annotated[
    _CanonicalPostRequestId | SkipJsonSchema[None],
    BeforeValidator(_non_null_post_request_id),
    Field(json_schema_extra=_post_request_id_schema),
]


class MessageCreate(StrictModel):
    body: str = Field(min_length=1)
    kind: Literal["announce", "question", "answer", "status", "chat", "task"] = "chat"
    reply_to: int | None = Field(default=None, ge=1, le=MAX_SEQUENCE)
    metadata: dict[str, Any] = Field(default_factory=dict)
    request_id: PostRequestId = None


class MessageResponse(StrictModel):
    seq: int
    id: str
    channel: str
    agent_id: str
    agent_name: str
    body: str
    kind: Literal["announce", "question", "answer", "status", "chat", "task"]
    reply_to: int | None
    metadata: dict[str, Any]
    created_at: datetime

    @classmethod
    def from_domain(cls, message: Message) -> MessageResponse:
        return cls(
            seq=message.seq,
            id=message.id,
            channel=message.channel,
            agent_id=message.agent_id,
            agent_name=message.agent_name,
            body=message.body,
            kind=message.kind,
            reply_to=message.reply_to,
            metadata=message.metadata,
            created_at=message.created_at,
        )


class SearchHitResponse(MessageResponse):
    snippet: str

    @classmethod
    def from_domain(cls, hit: SearchHit) -> SearchHitResponse:
        return cls(
            **MessageResponse.from_domain(hit.message).model_dump(),
            snippet=hit.snippet,
        )


class MessageClaimResponse(StrictModel):
    message_seq: int
    agent_id: str
    agent_name: str
    claimed_at: datetime

    @classmethod
    def from_domain(cls, claim: MessageClaim) -> MessageClaimResponse:
        return cls(
            message_seq=claim.message_seq,
            agent_id=claim.agent_id,
            agent_name=claim.agent_name,
            claimed_at=claim.claimed_at,
        )


class HealthResponse(StrictModel):
    status: Literal["ok"]


class RoeRevisionResponse(StrictModel):
    id: str
    target_key: str
    scope: Literal["global", "agent"]
    agent_id: str | None
    version: int
    policy_schema_version: Literal[1]
    content_sha256: str
    content: dict[str, Any]
    author_label: str
    publisher_type: Literal["system", "local-admin"]
    publisher_identity: str
    created_at: datetime
    superseded_at: datetime | None

    @classmethod
    def from_domain(cls, revision: RoeRevision) -> RoeRevisionResponse:
        return cls(
            id=revision.id,
            target_key=revision.target_key,
            scope=revision.scope,
            agent_id=revision.agent_id,
            version=revision.version,
            policy_schema_version=revision.policy_schema_version,
            content_sha256=revision.content_sha256,
            content=json.loads(revision.content_json),
            author_label=revision.author_label,
            publisher_type=revision.publisher_type,
            publisher_identity=revision.publisher_identity,
            created_at=revision.created_at,
            superseded_at=revision.superseded_at,
        )


class EffectiveRoeRevisionResponse(StrictModel):
    id: str
    target_key: str
    scope: Literal["global", "agent"]
    agent_id: str | None
    version: int
    policy_schema_version: Literal[1]
    content_sha256: str
    content: dict[str, Any]
    created_at: datetime
    superseded_at: datetime | None

    @classmethod
    def from_domain(
        cls,
        revision: RoeRevision,
    ) -> EffectiveRoeRevisionResponse:
        return cls(
            id=revision.id,
            target_key=revision.target_key,
            scope=revision.scope,
            agent_id=revision.agent_id,
            version=revision.version,
            policy_schema_version=revision.policy_schema_version,
            content_sha256=revision.content_sha256,
            content=json.loads(revision.content_json),
            created_at=revision.created_at,
            superseded_at=revision.superseded_at,
        )


class RoeAcknowledgementResponse(StrictModel):
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

    @classmethod
    def from_domain(
        cls,
        acknowledgement: RoeAcknowledgement,
    ) -> RoeAcknowledgementResponse:
        return cls(
            id=acknowledgement.id,
            agent_id=acknowledgement.agent_id,
            global_revision_id=acknowledgement.global_revision_id,
            global_content_sha256=acknowledgement.global_content_sha256,
            agent_revision_id=acknowledgement.agent_revision_id,
            agent_content_sha256=acknowledgement.agent_content_sha256,
            effective_sha256=acknowledgement.effective_sha256,
            acknowledged_at=acknowledgement.acknowledged_at,
            credential_kind=acknowledgement.credential_kind,
            credential_id=acknowledgement.credential_id,
            credential_record_id=acknowledgement.credential_record_id,
        )


class EffectiveRoeResponse(StrictModel):
    enforcement_mode: Literal["observe", "enforce"]
    receipt_status: Literal["missing", "stale", "current"]
    effective_sha256: str
    global_revision: EffectiveRoeRevisionResponse
    agent_revision: EffectiveRoeRevisionResponse | None
    acknowledgement: RoeAcknowledgementResponse | None

    @classmethod
    def from_domain(
        cls,
        effective: EffectiveRoe,
        *,
        enforcement_mode: Literal["observe", "enforce"],
    ) -> EffectiveRoeResponse:
        return cls(
            enforcement_mode=enforcement_mode,
            receipt_status=effective.acknowledgement_status,
            effective_sha256=effective.effective_sha256,
            global_revision=EffectiveRoeRevisionResponse.from_domain(
                effective.global_revision
            ),
            agent_revision=(
                None
                if effective.agent_revision is None
                else EffectiveRoeRevisionResponse.from_domain(
                    effective.agent_revision
                )
            ),
            acknowledgement=(
                None
                if effective.acknowledgement is None
                else RoeAcknowledgementResponse.from_domain(
                    effective.acknowledgement
                )
            ),
        )


class RoeAcknowledgementCreate(StrictModel):
    global_revision_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    global_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_revision_id: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    agent_content_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    effective_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RoePublishCreate(StrictModel):
    revision_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    expected_current_revision_id: str | None = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    author_label: str = Field(min_length=1, max_length=128)
    policy: dict[str, Any]


class RoePublishResponse(StrictModel):
    revision: RoeRevisionResponse
    created: bool


class RoeRevisionHistoryResponse(StrictModel):
    revisions: list[RoeRevisionResponse]
