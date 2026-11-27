from __future__ import annotations

import asyncio
import functools
import json
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from fastapi.responses import Response, StreamingResponse

from strugglebus.auth import parse_mobile_write_grant
from strugglebus.ca import (
    TrustAnchorError,
    der_base64,
    fingerprint_display,
    load_trust_anchor,
)
from strugglebus.dashboard import onboarding_package_text
from strugglebus.errors import (
    AgentAccessFrozenError,
    ChannelNotFoundError,
    ConfigurationError,
    CredentialConflictError,
    CredentialLimitError,
    CredentialNotFoundError,
    DomainValidationError,
    DuplicateAgentNameError,
    EnrollmentInvalidError,
    MessageTooLargeError,
    PostRequestConflictError,
    ReplyNotFoundError,
    StorageError,
)
from strugglebus.models import (
    LifecycleActor,
    MobileIdentity,
)
from strugglebus.operator_auth import (
    OperatorAuthError, OperatorCapacityError,
)
from strugglebus.integration import COORDINATION_PROTOCOL_VERSION
from strugglebus.service import (
    MAX_CHANNEL_NAME_LENGTH,
    MAX_MESSAGE_LIMIT,
    MAX_SEQUENCE,
    normalize_name,
)
from strugglebus.routes.schemas import (
    AgentResponse,
    MobileEnrollmentRedemption,
    RedeemedMobileResponse,
    MobileWriteGrantRequest,
    MobileWriteGrantResponse,
    MobileConfirmationRequest,
    MobileConfirmationResponse,
    MobileActionRequest,
    MobileAgentEnrollmentRequest,
    MobileAgentEnrollmentResponse,
    MobileDeviceEnrollmentRequest,
    MobileHostCommandRequest,
    MobileHostEnrollmentRequest,
    MobileHostEnrollmentResponse,
    MobileDeviceEnrollmentResponse,
    MobileHumanPostRequest,
    MobileServicePrincipalRequest,
    MobileServicePrincipalResponse,
    MobileActionResponse,
    MobileStatusResponse,
    ChannelResponse,
    MobileChannelActivity,
    MessageResponse,
    SearchHitResponse,
)
from strugglebus.routes.dependencies import _secret_response_headers
from strugglebus.routes.streams import (
    _mobile_revalidator,
    _build_stream,
)


#: What the owner is shown before confirming. Written as the effect, not the
#: verb: a confirmation screen that only names the action invites approving
#: something whose consequence was never stated.
_ACTION_EFFECTS = {
    "revoke-device": (
        "Permanently revoke this device. Its read credential and write grant "
        "both stop working immediately. The label can never be reused, and a "
        "replacement is a new device enrolled from the console."
    ),
    "block-agent": (
        "Block this agent. It loses access immediately; history, keys and "
        "cursors are kept, and it can be unblocked later."
    ),
    "activate-freeze": (
        "Freeze all agent access. Every agent is denied on REST, MCP and SSE, "
        "and open agent streams end. Monitors and the operator console keep "
        "reading, so you can still see what is happening."
    ),
    "clear-freeze": (
        "Restore agent access. Agents you blocked or revoked during the freeze "
        "stay blocked or revoked; this only lifts the global stop."
    ),
}


#: Channels are read a page at a time. A bus holds few, and the number of pages is bounded so a
#: mistake in paging can never loop.
_CHANNEL_PAGE = 100
_CHANNEL_PAGES = 20


def _every_channel(board) -> list:
    """Every channel's activity, by name, read page by page."""

    found: list = []
    after: str | None = None
    for _ in range(_CHANNEL_PAGES):
        page = board.channel_activity(after=after, limit=_CHANNEL_PAGE)
        found.extend(page.channels)
        if not page.has_more or not page.channels:
            break
        after = page.channels[-1].name
    return found


def add_mobile_routes(router: APIRouter) -> None:
    def _mobile_identity(request: Request) -> MobileIdentity:
        identity = getattr(request.state, "mobile_identity", None)
        if identity is None:
            raise HTTPException(
                status_code=401,
                detail="mobile authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return identity

    @router.post(
        "/api/mobile/enrollments/redeem",
        response_model=RedeemedMobileResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"description": "Enrollment token is not valid"},
            409: {"description": "Device label already exists"},
        },
    )
    async def redeem_mobile_enrollment(
        request: Request,
        payload: MobileEnrollmentRedemption,
        response: Response,
    ) -> RedeemedMobileResponse:
        token = request.scope.get("state", {}).get("mobile_enrollment_token")
        if not isinstance(token, str):
            raise HTTPException(
                status_code=401, detail="enrollment authentication required"
            )
        try:
            identity, secret = await asyncio.to_thread(
                request.app.state.mobile_service.redeem_enrollment,
                token,
                request_id=payload.request_id,
            )
        except EnrollmentInvalidError as error:
            raise HTTPException(status_code=401, detail=str(error)) from None
        except DuplicateAgentNameError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except AgentAccessFrozenError:
            raise HTTPException(
                status_code=503, detail="agent access is frozen"
            ) from None
        _secret_response_headers(response)
        return RedeemedMobileResponse(
            device_id=identity.device_id,
            device_label=identity.device_label,
            credential_id=identity.credential_id,
            credential_secret=secret,
            guidance=(
                "Store this secret in device-protected storage and pin both "
                "device_id and device_label. It is shown once and is not "
                "recoverable: a lost response requires a new operator "
                "enrollment, never a retry."
            ),
        )

    async def _describe_target(request: Request, action: str, target_id: str):
        """Resolve what an action would actually affect, before it is confirmed.

        The owner confirms a described effect, so the description has to come
        from current state rather than from whatever the client believed. The
        version is captured here and re-checked at execution, so a target that
        changed between the two cannot be acted on under a stale description.
        """

        if action in {"activate-freeze", "clear-freeze"}:
            # No per-object target. The label is what the owner reads on the
            # confirmation screen, and the version is unused for a global
            # transition, so it is fixed rather than invented.
            return "system", "agent access", 0
        if action == "revoke-device":
            devices = await asyncio.to_thread(
                request.app.state.mobile_service.list_devices
            )
            for device in devices:
                if device["id"] == target_id:
                    if device["status"] != "enabled":
                        raise HTTPException(
                            status_code=409, detail="device is not enabled"
                        )
                    return "device", str(device["label"]), int(device["version"])
            raise HTTPException(status_code=404, detail="device not found")
        agent = await asyncio.to_thread(
            request.app.state.agent_service.get_managed_agent,
            target_id,
            require_access=False,
        )
        if agent.state != "enabled":
            raise HTTPException(status_code=409, detail="agent is not enabled")
        return "agent", agent.name, int(agent.credential_epoch)

    @router.post(
        "/api/mobile/grants",
        response_model=MobileWriteGrantResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"description": "Operator password is not valid"},
            503: {"description": "Agent access is frozen"},
        },
    )
    async def establish_mobile_write_grant(
        request: Request,
        payload: MobileWriteGrantRequest,
        response: Response,
    ) -> MobileWriteGrantResponse:
        """Trade the operator password, once, for a per-device write secret.

        This is the only place the operator password appears on the mobile
        surface, and it is deliberately not stored by the client afterwards.
        The grant that replaces it is per-device and revocable, so a handset
        compromise is contained by revoking the device - which a stored copy of
        the system-wide password would not be.
        """

        identity = _mobile_identity(request)
        authority = request.app.state.operator_auth
        if authority is None or not authority.configured:
            raise HTTPException(
                status_code=503, detail="operator password is not configured"
            )
        # Verification is intentionally expensive, so it is rate limited harder
        # than the rest of the mobile surface: it shares a bounded worker pool
        # with console login, and a burst here must not lock the owner out of
        # their own console.
        try:
            proved = await authority.verify_device_password(
                payload.operator_password, source=f"device:{identity.device_id}",
            )
        except OperatorCapacityError as error:
            raise HTTPException(status_code=429, detail=str(error)) from None
        except OperatorAuthError as error:
            raise HTTPException(status_code=503, detail=str(error)) from None
        if not proved:
            raise HTTPException(status_code=401, detail="operator password is not valid")
        try:
            secret = await asyncio.to_thread(
                request.app.state.mobile_service.establish_write_grant,
                device_id=identity.device_id,
                request_id=payload.request_id,
                reason=payload.reason,
                actor_id=f"device:{identity.device_label}",
            )
        except AgentAccessFrozenError:
            raise HTTPException(
                status_code=503, detail="agent access is frozen"
            ) from None
        except CredentialNotFoundError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except CredentialConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        _secret_response_headers(response)
        return MobileWriteGrantResponse(
            device_id=identity.device_id,
            grant_secret=secret,
            guidance=(
                "Store this in a non-exportable keystore key that requires user "
                "presence, and never display it. It is shown once and is not "
                "recoverable. Establishing a new grant immediately revokes this "
                "one, and revoking or replacing the device revokes it too."
            ),
        )

    @router.post(
        "/api/mobile/confirmations",
        response_model=MobileConfirmationResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            404: {"description": "Target not found"},
            409: {"description": "Target is not in an actionable state"},
            422: {"description": "Action is not available to a device"},
        },
    )
    async def request_mobile_confirmation(
        request: Request,
        payload: MobileConfirmationRequest,
        response: Response,
    ) -> MobileConfirmationResponse:
        """Bind one action to one target, briefly, for this device.

        Deliberately available while frozen. A confirmation authorises nothing
        by itself - it cannot be spent without the write grant - and every
        action it can name is a containment action the owner may need during
        the incident the freeze was declared for.
        """

        identity = _mobile_identity(request)
        service = request.app.state.mobile_service
        if payload.action not in service.CONTAINMENT_ACTIONS:
            raise HTTPException(
                status_code=422,
                detail="action is not a confirmation action; management "
                "actions use /api/mobile/admin",
            )
        target_kind, target_label, target_version = await _describe_target(
            request, payload.action, payload.target_id
        )
        config = request.app.state.config
        try:
            confirmation_id, expires_at = await asyncio.to_thread(
                service.request_confirmation,
                device_id=identity.device_id,
                action=payload.action,
                target_kind=target_kind,
                target_id=payload.target_id,
                target_label=target_label,
                target_version=target_version,
                request_id=payload.request_id,
                lifetime_seconds=config.mobile_confirmation_seconds,
            )
        except EnrollmentInvalidError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        _secret_response_headers(response)
        return MobileConfirmationResponse(
            confirmation_id=confirmation_id,
            action=payload.action,
            target_kind=target_kind,
            target_id=payload.target_id,
            target_label=target_label,
            expires_at=expires_at,
            effect=_ACTION_EFFECTS[payload.action],
        )

    @router.post(
        "/api/mobile/actions",
        response_model=MobileActionResponse,
        responses={
            401: {"description": "Write grant is not valid"},
            409: {"description": "Confirmation does not match this action"},
        },
    )
    async def perform_mobile_action(
        request: Request,
        payload: MobileActionRequest,
        response: Response,
    ) -> MobileActionResponse:
        """Spend a confirmation with the device's second proof.

        Order matters. The grant is checked first, so an attacker without it
        cannot burn confirmations. The confirmation is then consumed with the
        re-declared action and target, and only then is anything executed.
        """

        identity = _mobile_identity(request)
        service = request.app.state.mobile_service
        if not await asyncio.to_thread(
            service.verify_write_grant,
            device_id=identity.device_id,
            secret=payload.grant_secret,
        ):
            raise HTTPException(
                status_code=401, detail="write grant is not valid for this device"
            )
        bound = await asyncio.to_thread(
            service.consume_confirmation,
            confirmation_id=payload.confirmation_id,
            device_id=identity.device_id,
            action=payload.action,
            target_id=payload.target_id,
        )
        if bound is None:
            raise HTTPException(
                status_code=409,
                detail="confirmation is missing, expired, spent, or bound to a "
                "different action or target",
            )
        actor = f"device:{identity.device_label}"
        bound["device_id"] = identity.device_id
        bound["credential_id"] = identity.credential_id
        applied, detail = await _execute_mobile_action(
            request, bound, reason=payload.reason, actor=actor,
            request_id=payload.request_id, grant_secret=payload.grant_secret,
        )
        _secret_response_headers(response)
        return MobileActionResponse(
            action=str(bound["action"]),
            target_id=str(bound["target_id"]),
            target_label=str(bound["target_label"]),
            applied=applied,
            detail=detail,
        )

    async def _execute_mobile_action(
        request: Request,
        bound: dict,
        *,
        reason: str,
        actor: str,
        request_id: str,
        grant_secret: str,
    ) -> tuple[bool, str]:
        action = str(bound["action"])
        target_id = str(bound["target_id"])
        if action == "activate-freeze":
            state, changed = await asyncio.to_thread(
                request.app.state.access_freeze_service.operator_freeze_mobile,
                reason,
                device_id=str(bound["device_id"]),
            )
            return changed, (
                "Agent access is frozen. Agents are denied; monitors and the "
                "console keep reading."
            ) if state.frozen else "Freeze did not take effect."
        if action == "clear-freeze":
            device_id = str(bound["device_id"])
            candidate_digest = parse_mobile_write_grant(grant_secret, device_id)
            result = await asyncio.to_thread(
                request.app.state.access_freeze_service.operator_unfreeze_mobile,
                reason,
                device_id=device_id,
                credential_id=str(bound["credential_id"]),
                candidate_grant_digest=(
                    candidate_digest if candidate_digest is not None else ""
                ),
            )
            if result is None:
                raise HTTPException(
                    status_code=401,
                    detail="device credential or write grant is no longer valid",
                )
            _state, changed = result
            return changed, (
                "Agent access restored. Agents blocked or revoked during the "
                "freeze stay blocked or revoked."
            )
        if action == "revoke-device":
            revoked = await asyncio.to_thread(
                request.app.state.mobile_service.revoke_device,
                target_id, reason=reason, actor_id=actor,
            )
            return revoked, (
                "Device revoked. Its read credential and write grant are both "
                "dead." if revoked else "Device was already revoked."
            )
        # Blocking is reversible and, unlike unblocking, narrows access, which
        # is why it is the one agent lifecycle action a device may perform.
        #
        # The revalidation callback runs under the writer lock and re-checks
        # the device at the moment of the write. A device revoked between the
        # confirmation and the commit must not be able to land this action, and
        # a check performed earlier in the request could not promise that.
        service = request.app.state.mobile_service
        device_id = str(bound["device_id"])

        def still_live() -> None:
            if not service.authorize_device(str(bound["credential_id"])):
                raise DomainValidationError(
                    "device credential is no longer active"
                )
            if not service.device_is_enabled(device_id):
                raise DomainValidationError("device is no longer enabled")

        result = await asyncio.to_thread(
            request.app.state.agent_service.transition_agent,
            target_id,
            action="block",
            expected_credential_epoch=int(bound["target_version"]),
            request_id=request_id,
            reason=reason,
            actor=LifecycleActor(
                actor_type="remote-admin",
                actor_id=actor,
                revalidate=still_live,
            ),
        )
        return result.changed, (
            "Agent blocked. History, keys and cursors are retained."
        )

    @router.post(
        "/api/mobile/humans/messages",
        response_model=MessageResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            400: {"description": "Invalid body, kind or reply target"},
            401: {"description": "Write grant is not valid"},
            409: {"description": "Post request_id conflicts with previously accepted input"},
            413: {"description": "Message body too large"},
        },
    )
    async def create_mobile_human_message(
        request: Request,
        payload: MobileHumanPostRequest,
    ) -> MessageResponse:
        """Post to #humans as human:operator, the same as the console.

        The device credential alone is a read capability, so the per-device
        write grant is required as well. No confirmation is needed: a post
        targets nothing and grants agents nothing. Like the console, this is
        an operator-plane write and continues while agent access is frozen.
        """

        identity = _mobile_identity(request)
        if not await asyncio.to_thread(
            request.app.state.mobile_service.verify_write_grant,
            device_id=identity.device_id,
            secret=payload.grant_secret,
        ):
            raise HTTPException(
                status_code=401, detail="write grant is not valid for this device"
            )
        try:
            message = await asyncio.to_thread(
                request.app.state.board_service.create_human_message,
                body=payload.body,
                kind=payload.kind,
                reply_to=payload.reply_to,
                request_id=payload.request_id,
            )
        except PostRequestConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except ReplyNotFoundError as error:
            raise HTTPException(status_code=400, detail=str(error)) from None
        except MessageTooLargeError as error:
            raise HTTPException(status_code=413, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=400, detail=str(error)) from None
        return MessageResponse.from_domain(message)

    @router.post(
        "/api/mobile/hosts/commands",
        response_model=MessageResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            400: {"description": "Not a command, signature or channel"},
            401: {"description": "Write grant is not valid"},
            404: {"description": "No such channel"},
            409: {"description": "Post request_id conflicts with previously accepted input"},
        },
    )
    async def create_mobile_host_command(
        request: Request,
        payload: MobileHostCommandRequest,
    ) -> MessageResponse:
        """Carry one signed host command to a worker hosts' channel.

        This is the only operator post outside #humans, and only in this one
        shape: a fixed body with the signed command in metadata. The bus is
        the carrier. It checks sizes and never reads the command; a worker
        host acts on it only if the signature checks against keys pinned on
        that host. An unsigned message there is ignored as it always was.
        """

        identity = _mobile_identity(request)
        if not await asyncio.to_thread(
            request.app.state.mobile_service.verify_write_grant,
            device_id=identity.device_id,
            secret=payload.grant_secret,
        ):
            raise HTTPException(
                status_code=401, detail="write grant is not valid for this device"
            )
        try:
            message = await asyncio.to_thread(
                request.app.state.board_service.create_host_command,
                channel_name=payload.channel,
                document=payload.document,
                signature=payload.signature,
                request_id=payload.request_id,
            )
        except PostRequestConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except ChannelNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=400, detail=str(error)) from None
        return MessageResponse.from_domain(message)

    # ---- Enrollment from a device ----------------------------------------
    #
    # These create authority, which containment actions never do. The owner
    # chose to allow it: the device's write grant, released on the device by
    # user presence, is the authorisation, exactly as it is for a #humans
    # post. There is no confirmation step because there is no existing target
    # to bind to. Like their console equivalents they are refused while agent
    # access is frozen, and each is audited as ``device:<label>``.

    async def _require_write_grant(
        request: Request, identity: MobileIdentity, grant_secret: str
    ) -> None:
        if not await asyncio.to_thread(
            request.app.state.mobile_service.verify_write_grant,
            device_id=identity.device_id,
            secret=grant_secret,
        ):
            raise HTTPException(
                status_code=401, detail="write grant is not valid for this device"
            )

    def _device_actor(request: Request, identity: MobileIdentity) -> LifecycleActor:
        service = request.app.state.mobile_service
        checking = False

        def still_live() -> None:
            # Runs under the writer lock: a device revoked after the grant
            # check must not be able to land the write. During an operator
            # operation the store re-validates the actor on every transaction,
            # including the reads below, so the check must not re-enter itself.
            nonlocal checking
            if checking:
                return
            checking = True
            try:
                if not service.authorize_device(identity.credential_id):
                    raise CredentialNotFoundError(
                        "device credential is no longer active"
                    )
                if not service.device_is_enabled(identity.device_id):
                    raise CredentialNotFoundError("device is no longer enabled")
            finally:
                checking = False

        return LifecycleActor(
            actor_type="remote-admin",
            actor_id=f"device:{identity.device_label}",
            revalidate=still_live,
        )

    _ENROLLMENT_RESPONSES = {
        401: {"description": "Write grant or device is not valid"},
        409: {"description": "Name is already taken"},
        422: {"description": "Invalid name"},
        503: {"description": "Agent access is frozen or trust is not configured"},
    }

    @router.post(
        "/api/mobile/enrollments/agents",
        response_model=MobileAgentEnrollmentResponse,
        status_code=status.HTTP_201_CREATED,
        responses=_ENROLLMENT_RESPONSES,
    )
    async def create_mobile_agent_enrollment(
        request: Request,
        payload: MobileAgentEnrollmentRequest,
        response: Response,
    ) -> MobileAgentEnrollmentResponse:
        """Create a single-use, exact-name agent enrollment and its package."""

        identity = _mobile_identity(request)
        await _require_write_grant(request, identity, payload.grant_secret)
        actor = _device_actor(request, identity)
        config = request.app.state.config
        try:
            canonical = normalize_name(payload.name, agent=True)
        except DomainValidationError:
            raise HTTPException(
                status_code=422,
                detail="Agent names are lowercase kebab-case and must contain "
                "at least one hyphen, for example adlab-cli-win.",
            ) from None
        try:
            anchor = await asyncio.to_thread(
                load_trust_anchor, config.ca_bundle_path, config.ca_root_sha256
            )
            issued = await asyncio.to_thread(
                functools.partial(
                    request.app.state.agent_service.create_enrollment,
                    name_prefix=canonical,
                    name_match="exact",
                    description=payload.description.strip(),
                    uses=1,
                    require_access=True,
                    actor_type=actor.actor_type,
                    actor_id=actor.actor_id,
                    reason=payload.reason,
                    authorize=actor.revalidate,
                )
            )
        except CredentialNotFoundError as error:
            raise HTTPException(status_code=401, detail=str(error)) from None
        except (ConfigurationError, DomainValidationError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        except AgentAccessFrozenError:
            raise HTTPException(
                status_code=503, detail="agent access is frozen"
            ) from None
        except (TrustAnchorError, StorageError) as error:
            raise HTTPException(status_code=503, detail=str(error)) from None
        if issued.token is None:
            raise HTTPException(
                status_code=503, detail="the service did not issue a token"
            )
        _secret_response_headers(response)
        return MobileAgentEnrollmentResponse(
            enrollment_id=issued.enrollment.id,
            agent_name=issued.enrollment.name_prefix,
            expires_at=issued.enrollment.expires_at,
            package=onboarding_package_text(
                base_url=config.public_base_url,
                agent_name=issued.enrollment.name_prefix,
                token=issued.token,
                expires_at=issued.enrollment.expires_at,
                pending_seconds=config.credential_pending_seconds,
                ca_root=anchor,
                ca_fingerprint=(
                    fingerprint_display(config.ca_root_sha256)
                    if anchor is not None
                    else None
                ),
            ),
        )

    @router.post(
        "/api/mobile/enrollments/service-principals",
        response_model=MobileServicePrincipalResponse,
        status_code=status.HTTP_201_CREATED,
        responses=_ENROLLMENT_RESPONSES,
    )
    async def create_mobile_service_principal(
        request: Request,
        payload: MobileServicePrincipalRequest,
        response: Response,
    ) -> MobileServicePrincipalResponse:
        """Create a service principal. Its secret is returned once."""

        identity = _mobile_identity(request)
        await _require_write_grant(request, identity, payload.grant_secret)
        actor = _device_actor(request, identity)
        store = request.app.state.agent_service.store

        def create():
            token = store.begin_operator_operation(actor)
            try:
                return request.app.state.spn_service.create(
                    name=payload.name,
                    agent_name_prefix=payload.agent_name_prefix,
                    request_id=payload.request_id,
                    actor=actor,
                )
            finally:
                store.end_operator_operation(token)

        try:
            issued = await asyncio.to_thread(create)
        except CredentialNotFoundError as error:
            raise HTTPException(status_code=401, detail=str(error)) from None
        except CredentialConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (ConfigurationError, DomainValidationError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        except AgentAccessFrozenError:
            raise HTTPException(
                status_code=503, detail="agent access is frozen"
            ) from None
        except StorageError as error:
            raise HTTPException(status_code=503, detail=str(error)) from None
        _secret_response_headers(response)
        return MobileServicePrincipalResponse(
            service_principal_id=issued.principal.id,
            name=issued.principal.name,
            agent_name_prefix=issued.principal.agent_name_prefix,
            secret_issued=issued.secret_issued,
            credential_secret=issued.secret if issued.secret_issued else None,
        )

    @router.post(
        "/api/mobile/enrollments/devices",
        response_model=MobileDeviceEnrollmentResponse,
        status_code=status.HTTP_201_CREATED,
        responses=_ENROLLMENT_RESPONSES,
    )
    async def create_mobile_device_enrollment(
        request: Request,
        payload: MobileDeviceEnrollmentRequest,
        response: Response,
    ) -> MobileDeviceEnrollmentResponse:
        """Create a single-use enrollment for another phone or PC."""

        identity = _mobile_identity(request)
        await _require_write_grant(request, identity, payload.grant_secret)
        actor = _device_actor(request, identity)
        config = request.app.state.config
        try:
            canonical = normalize_name(payload.label)
        except DomainValidationError:
            raise HTTPException(
                status_code=422,
                detail="Device labels are lowercase kebab-case, for example "
                "owner-phone.",
            ) from None
        try:
            anchor = await asyncio.to_thread(
                load_trust_anchor, config.ca_bundle_path, config.ca_root_sha256
            )
            if anchor is None or not config.ca_root_sha256:
                raise TrustAnchorError(
                    "A published LAN CA root is required before a device can "
                    "trust this service."
                )
            await asyncio.to_thread(actor.revalidate)
            token, expires_at = await asyncio.to_thread(
                request.app.state.mobile_service.mint_enrollment,
                device_label=canonical,
                ttl_seconds=config.mobile_enrollment_seconds,
                actor_id=actor.actor_id,
            )
        except CredentialNotFoundError as error:
            raise HTTPException(status_code=401, detail=str(error)) from None
        except DuplicateAgentNameError:
            raise HTTPException(
                status_code=409,
                detail="That label is already registered. Labels stay reserved "
                "even after revocation.",
            ) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        except AgentAccessFrozenError:
            raise HTTPException(
                status_code=503, detail="agent access is frozen"
            ) from None
        except (TrustAnchorError, StorageError) as error:
            raise HTTPException(status_code=503, detail=str(error)) from None
        _secret_response_headers(response)
        # The same payload shape the console renders as a QR code.
        return MobileDeviceEnrollmentResponse(
            device_label=canonical,
            expires_at=expires_at,
            payload=json.dumps(
                {
                    "version": 1,
                    "base_url": config.public_base_url,
                    "ca_der": der_base64(anchor),
                    "ca_sha256": config.ca_root_sha256,
                    "device_label": canonical,
                    "enrollment": token,
                    "expires_at": expires_at.astimezone(UTC).isoformat(),
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ),
        )

    @router.post(
        "/api/mobile/enrollments/hosts",
        response_model=MobileHostEnrollmentResponse,
        status_code=status.HTTP_201_CREATED,
        responses=_ENROLLMENT_RESPONSES,
    )
    async def create_mobile_host_enrollment(
        request: Request,
        payload: MobileHostEnrollmentRequest,
        response: Response,
    ) -> MobileHostEnrollmentResponse:
        """Create a single-use code that lets one worker host join the bus.

        The host redeems it for its own service principal, named exactly
        ``host_prefix``. The code is returned once.
        """

        identity = _mobile_identity(request)
        await _require_write_grant(request, identity, payload.grant_secret)
        actor = _device_actor(request, identity)
        store = request.app.state.agent_service.store

        def mint():
            token = store.begin_operator_operation(actor)
            try:
                return request.app.state.host_enrollment_service.mint(
                    host_prefix=payload.host_prefix,
                    request_id=payload.request_id,
                    reason=payload.reason,
                    actor=actor,
                )
            finally:
                store.end_operator_operation(token)

        try:
            issued = await asyncio.to_thread(mint)
        except CredentialNotFoundError as error:
            raise HTTPException(status_code=401, detail=str(error)) from None
        except DuplicateAgentNameError:
            raise HTTPException(
                status_code=409,
                detail="That host name is already registered. Names stay "
                "reserved even after a host is retired.",
            ) from None
        except (CredentialConflictError, CredentialLimitError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (ConfigurationError, DomainValidationError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        except AgentAccessFrozenError:
            raise HTTPException(
                status_code=503, detail="agent access is frozen"
            ) from None
        except StorageError as error:
            raise HTTPException(status_code=503, detail=str(error)) from None
        _secret_response_headers(response)
        return MobileHostEnrollmentResponse(
            host_prefix=issued.host_prefix,
            expires_at=issued.expires_at,
            code_issued=issued.code is not None,
            code=issued.code,
        )

    @router.get("/api/mobile/status", response_model=MobileStatusResponse)
    async def mobile_status(request: Request) -> MobileStatusResponse:
        """Report liveness and freeze state, and nothing else.

        The shape is identical whether or not the board is frozen, so the
        response shape itself carries no information and only ``state`` does.
        Keeping it minimal is the point: every convenient extra field would
        erode the reason this is the one route that answers while frozen.
        """

        _mobile_identity(request)
        frozen = bool(getattr(request.state, "mobile_frozen", False))
        return MobileStatusResponse(
            api_version=COORDINATION_PROTOCOL_VERSION,
            server_time=datetime.now(UTC),
            state="frozen" if frozen else "available",
        )

    @router.get(
        "/api/mobile/snapshot",
        response_model=list[MessageResponse],
        responses={404: {"description": "Channel not found"}},
    )
    async def mobile_snapshot(
        request: Request,
        channel: Annotated[
            str | None, Query(min_length=1, max_length=MAX_CHANNEL_NAME_LENGTH)
        ] = None,
        agent: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
        before: Annotated[int | None, Query(ge=1, le=MAX_SEQUENCE)] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_MESSAGE_LIMIT)] = 100,
    ) -> list[MessageResponse]:
        """Return the newest matching messages, oldest first, without consuming.

        ``channel`` and ``agent`` narrow the page and ``before`` pages back
        through history, so a monitor can show one conversation or one agent's
        traffic without holding the whole board. An unknown agent is an empty
        page; an unknown channel is 404.

        Built on the non-consuming read, never on catch-up: a monitor must
        never advance an agent's delivery cursor, and a consuming read that
        reports an empty page after losing a message is the exact failure this
        surface is designed to avoid.
        """

        _mobile_identity(request)
        board = request.app.state.board_service
        try:
            if channel is None and agent is None and before is None:
                messages = await asyncio.to_thread(
                    board.recent_activity, limit=limit
                )
            else:
                if channel is not None:
                    await asyncio.to_thread(board.require_channel, channel)
                page = await asyncio.to_thread(
                    functools.partial(
                        board.dashboard_snapshot,
                        channel_name=channel,
                        agent_name=agent,
                        before=before,
                        limit=limit,
                    )
                )
                messages = tuple(reversed(page.messages))
        except ChannelNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return [MessageResponse.from_domain(message) for message in messages]

    @router.get(
        "/api/mobile/search",
        response_model=list[SearchHitResponse],
        responses={404: {"description": "Channel not found"}},
    )
    async def mobile_search(
        request: Request,
        query: Annotated[str, Query(min_length=1, max_length=256)],
        channel: Annotated[
            str | None, Query(min_length=1, max_length=MAX_CHANNEL_NAME_LENGTH)
        ] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_MESSAGE_LIMIT)] = 50,
    ) -> list[SearchHitResponse]:
        """Search message bodies across the whole board, newest first.

        The same bounded search agents have. Stale status posts are included:
        the owner is looking for what was said, not for what is still current.
        """

        _mobile_identity(request)
        try:
            hits = await asyncio.to_thread(
                functools.partial(
                    request.app.state.board_service.search,
                    query,
                    channel_name=channel,
                    limit=limit,
                    include_stale=True,
                )
            )
        except ChannelNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return [SearchHitResponse.from_domain(hit) for hit in hits]

    @router.get("/api/mobile/channels", response_model=list[ChannelResponse])
    async def mobile_channels(request: Request) -> list[ChannelResponse]:
        _mobile_identity(request)
        channels = await asyncio.to_thread(
            request.app.state.board_service.list_channels
        )
        return [ChannelResponse.from_domain(channel) for channel in channels]

    @router.get("/api/mobile/channels/activity", response_model=list[MobileChannelActivity])
    async def mobile_channel_activity(request: Request) -> list[MobileChannelActivity]:
        """Every channel with what it is for, how busy it is and who is listening.

        The same figures as the web console's Channels page, for a device.
        Readable while frozen, like the other monitor reads.
        """

        _mobile_identity(request)
        channels = await asyncio.to_thread(_every_channel, request.app.state.board_service)
        return [
            MobileChannelActivity(
                name=channel.name, purpose=channel.purpose, created_at=channel.created_at,
                message_count=channel.message_count,
                subscriber_count=channel.active_subscriber_count,
                last_activity_at=channel.last_activity_at,
            )
            for channel in channels
        ]

    @router.get("/api/mobile/agents", response_model=list[AgentResponse])
    async def mobile_agents(request: Request) -> list[AgentResponse]:
        _mobile_identity(request)
        # The monitor plane reads while frozen by design: watching an incident
        # is exactly when the owner needs to see who is on the board. The agent
        # plane keeps the default gate and is refused at authentication anyway.
        agents = await asyncio.to_thread(
            functools.partial(
                request.app.state.board_service.list_agents, require_access=False
            )
        )
        return [AgentResponse.from_domain(agent) for agent in agents]

    @router.get("/api/mobile/stream")
    async def mobile_stream(
        request: Request,
        since: Annotated[int, Query(ge=0, le=MAX_SEQUENCE)] = 0,
        channel: Annotated[
            str | None, Query(min_length=1, max_length=MAX_CHANNEL_NAME_LENGTH)
        ] = None,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> StreamingResponse:
        identity = _mobile_identity(request)
        return await _build_stream(
            request,
            since=since,
            channel=channel,
            last_event_id=last_event_id,
            lease_key=f"mobile:{identity.device_id}",
            revalidate=_mobile_revalidator(request, identity),
        )
