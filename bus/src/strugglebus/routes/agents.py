from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import Response

from strugglebus.ca import load_trust_anchor
from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    ConfigurationError,
    CredentialConflictError,
    CredentialLimitError,
    CredentialNotFoundError,
    DomainValidationError,
    DuplicateAgentNameError,
    EnrollmentInvalidError,
    StorageError,
    TrustAnchorError,
)
from strugglebus.integration import (
    IntegrationGuide,
    ServerInfo,
    build_integration_guide,
    build_server_info,
)
from strugglebus.models import (
    Agent,
    AuthenticatedIdentity,
    ServicePrincipalIdentity,
)
from strugglebus.orientation import (
    guidance as orientation_guidance,
    required_actions,
)
from strugglebus.spn import encode_onboarding_package
from strugglebus.routes.schemas import (
    AgentRegistration,
    EnrollmentRedemption,
    ReconnectRedemption,
    SPNOnboardingRequest,
    SPNRequest,
    AgentResponse,
    IdentityCreationProvenanceResponse,
    IdentityCreationCursorResponse,
    IdentityCreationProvenancePageResponse,
    CredentialResponse,
    IssuedCredentialResponse,
    CreatedAgentResponse,
    RedeemedEnrollmentResponse,
    OrientationChannelResponse,
    RequiredActionResponse,
    OrientationResponse,
    WhoAmIResponse,
    RotateCredentialRequest,
    ProveCredentialRequest,
    CredentialTransitionRequest,
    AdminIssueCredentialRequest,
    AdminAgentRevokeRequest,
    ChannelResponse,
)
from strugglebus.routes.dependencies import (
    require_agent,
    require_identity,
    _secret_response_headers,
    _lifecycle_http_error,
    require_admin,
)


def add_agent_routes(router: APIRouter) -> None:
    @router.post(
        "/api/agents",
        response_model=CreatedAgentResponse,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_admin)],
        responses={409: {"description": "Agent name already exists"}},
    )
    async def register_agent(
        request: Request,
        payload: AgentRegistration,
        response: Response,
    ) -> CreatedAgentResponse:
        try:
            created = await asyncio.to_thread(
                request.app.state.agent_service.create_agent,
                payload.name,
                description=payload.description,
                host=payload.host,
                require_access=True,
                request_id=payload.request_id,
                creator_type="remote-admin",
                creator_id=request.state.admin_credential_id,
            )
        except DuplicateAgentNameError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (
            AgentAccessFrozenError,
            ConfigurationError,
            CredentialConflictError,
            CredentialLimitError,
        ) as error:
            raise _lifecycle_http_error(error) from None
        _secret_response_headers(response)
        if not created.issued_credential.secret_issued:
            response.status_code = status.HTTP_200_OK
        return CreatedAgentResponse(
            agent=AgentResponse.from_domain(created.agent),
            credential=CredentialResponse.from_domain(
                created.issued_credential.credential
            ),
            credential_secret=created.issued_credential.secret,
            secret_issued=created.issued_credential.secret_issued,
            expected_identity_guidance=(
                "Pin and compare both agent.id and agent.name, then prove this "
                "credential before reading, posting, subscribing, or streaming."
            ),
        )

    @router.get(
        "/api/admin/identity-provenance",
        response_model=IdentityCreationProvenancePageResponse,
        dependencies=[Depends(require_admin)],
    )
    async def list_identity_creation_provenance(
        request: Request,
        creator_type: Annotated[
            Literal["system", "local-admin", "remote-admin", "spn"] | None,
            Query(),
        ] = None,
        creator_id: Annotated[
            str | None, Query(min_length=1, max_length=256)
        ] = None,
        after_created_at: Annotated[datetime | None, Query()] = None,
        after_agent_id: Annotated[
            str | None, Query(min_length=1, max_length=256)
        ] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> IdentityCreationProvenancePageResponse:
        try:
            page = await asyncio.to_thread(
                request.app.state.agent_service.list_identity_creation_provenance,
                creator_type=creator_type,
                creator_id=creator_id,
                after_created_at=after_created_at,
                after_agent_id=after_agent_id,
                limit=limit,
            )
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        next_cursor = (
            IdentityCreationCursorResponse(
                created_at=page.next_created_at,
                agent_id=page.next_agent_id,
            )
            if page.next_created_at is not None and page.next_agent_id is not None
            else None
        )
        items = [
            IdentityCreationProvenanceResponse.from_domain(item)
            for item in page.items
        ]
        return IdentityCreationProvenancePageResponse(
            items=items,
            page_count=len(items),
            total_count=page.total_count,
            has_more=page.has_more,
            next_cursor=next_cursor,
        )

    @router.post(
        "/api/enrollments/redeem",
        response_model=RedeemedEnrollmentResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"description": "Enrollment token is not valid"},
            409: {"description": "Claimed agent name already exists"},
        },
    )
    async def redeem_enrollment(
        request: Request,
        payload: EnrollmentRedemption,
        response: Response,
    ) -> RedeemedEnrollmentResponse:
        token = request.scope.get("state", {}).get("enrollment_token")
        if not isinstance(token, str):
            raise HTTPException(
                status_code=401, detail="enrollment authentication required"
            )
        try:
            redeemed = await asyncio.to_thread(
                request.app.state.agent_service.redeem_enrollment,
                token,
                claimed_name=payload.name,
                description=payload.description,
                host=payload.host,
                request_id=payload.request_id,
            )
        except EnrollmentInvalidError as error:
            raise HTTPException(status_code=401, detail=str(error)) from None
        except DuplicateAgentNameError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (
            AgentAccessFrozenError,
            ConfigurationError,
            CredentialConflictError,
            CredentialLimitError,
        ) as error:
            raise _lifecycle_http_error(error) from None
        _secret_response_headers(response)
        return RedeemedEnrollmentResponse(
            agent=AgentResponse.from_domain(redeemed.agent),
            credential=CredentialResponse.from_domain(
                redeemed.issued_credential.credential
            ),
            credential_secret=redeemed.api_key,
            expected_identity_guidance=(
                "Store this credential in an owner-protected store, pin both "
                "agent.id and agent.name, and discard the enrollment token. It "
                "is now spent and will never be accepted again."
            ),
            next_steps=[
                "Call orientation: the server reports the remaining bootstrap "
                "steps, unread work, and anything addressed to you.",
                "Call whoami and compare the returned agent id and name with "
                "the values you just pinned; abort on any mismatch.",
                "Call server_info and integration_guide.",
                "Call prove_credential to activate this pending credential.",
                "Call get_effective_roe, then acknowledge_roe with the exact "
                "returned revision IDs and hashes.",
                "Review list_channels and list_subscriptions, then explicitly "
                "choose subscriptions. Consider announce and task-relevant "
                "channels; subscriptions are optional and deliberate mention-only "
                "use is valid.",
                "Call catch_up(start_drain=true), then pass each returned "
                "continuation with the same limit and include_stale until "
                "complete=true, including empty or short pages. Deduplicate by "
                "global seq and act on anything addressed to you.",
            ],
        )

    @router.post("/api/spn/onboarding-packages", status_code=201)
    async def issue_spn_onboarding_package(
        request: Request,
        payload: SPNOnboardingRequest,
    ) -> Response:
        identity = request.scope.get("state", {}).get("spn_identity")
        if not isinstance(identity, ServicePrincipalIdentity):
            raise HTTPException(
                status_code=401,
                detail="service principal authentication required",
            )
        config = request.app.state.config
        try:
            anchor = await asyncio.to_thread(
                load_trust_anchor, config.ca_bundle_path, config.ca_root_sha256
            )
            if anchor is None or not config.ca_root_sha256:
                raise TrustAnchorError(
                    "configured verified trust publication is required"
                )
            prepared = request.app.state.spn_service.prepare_onboarding(
                ttl_seconds=payload.ttl_seconds,
            )
            package = encode_onboarding_package(
                agent_name=payload.agent_name,
                base_url=config.public_base_url,
                ca_root=anchor,
                ca_sha256=config.ca_root_sha256,
                expires_at=prepared.expires_at,
                enrollment_token=prepared.token,
            )
            issuance = await asyncio.to_thread(
                request.app.state.spn_service.issue_onboarding,
                identity,
                request_id=payload.request_id,
                agent_name=payload.agent_name,
                description=payload.description,
                ttl_seconds=payload.ttl_seconds,
                prepared=prepared,
                identity_ttl_seconds=payload.identity_ttl_seconds,
            )
        except DuplicateAgentNameError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (CredentialConflictError, CredentialLimitError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (ConfigurationError, DomainValidationError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        except (AgentAccessFrozenError, StorageError, TrustAnchorError):
            raise HTTPException(
                status_code=503, detail="onboarding package is unavailable"
            ) from None
        body = {
            "status": "new" if issuance.secret_issued else "already-committed",
            "secret_issued": issuance.secret_issued,
            "request_id": issuance.request_id,
            "enrollment_id": issuance.enrollment_id,
            "agent_name": issuance.agent_name,
            "expires_at": issuance.expires_at.isoformat(),
            "identity_expires_at": (
                None if payload.identity_ttl_seconds is None
                else (
                    issuance.created_at
                    + timedelta(seconds=payload.identity_ttl_seconds)
                ).isoformat()
            ),
            "package": package if issuance.secret_issued else None,
        }
        return Response(
            json.dumps(body, ensure_ascii=True, separators=(",", ":")),
            status_code=201 if issuance.secret_issued else 200,
            media_type="application/json",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
            },
        )

    def spn_identity(request: Request) -> ServicePrincipalIdentity:
        identity = request.scope.get("state", {}).get("spn_identity")
        if not isinstance(identity, ServicePrincipalIdentity):
            raise HTTPException(
                status_code=401,
                detail="service principal authentication required",
            )
        return identity

    @router.post("/api/spn/agents/{agent_name}/retire")
    async def retire_spn_agent(
        request: Request,
        agent_name: Annotated[str, Path(min_length=1, max_length=128)],
        payload: SPNRequest,
    ) -> dict[str, str]:
        identity = spn_identity(request)
        try:
            retired_at = await asyncio.to_thread(
                request.app.state.spn_service.retire_identity,
                identity,
                agent_name=agent_name,
                request_id=payload.request_id,
            )
        except (AgentNotFoundError, DomainValidationError):
            raise HTTPException(status_code=404, detail="agent not found") from None
        except CredentialConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (AgentAccessFrozenError, StorageError):
            raise HTTPException(
                status_code=503, detail="retirement is unavailable"
            ) from None
        return {
            "agent_name": agent_name,
            "state": "retired",
            "retired_at": retired_at.isoformat(),
        }

    @router.post("/api/spn/credentials/rotate", status_code=201)
    async def rotate_spn_credential(
        request: Request, payload: SPNRequest,
    ) -> Response:
        identity = spn_identity(request)
        try:
            credential_id, secret = await asyncio.to_thread(
                request.app.state.spn_service.rotate_self,
                identity,
                request_id=payload.request_id,
            )
        except (CredentialConflictError, CredentialLimitError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (AgentAccessFrozenError, StorageError):
            raise HTTPException(
                status_code=503, detail="rotation is unavailable"
            ) from None
        request.scope["state"]["spn_rotated_to"] = credential_id
        body = {
            "status": "new" if secret is not None else "already-committed",
            "secret_issued": secret is not None,
            "credential_id": credential_id,
            "credential": secret,
        }
        return Response(
            json.dumps(body, ensure_ascii=True, separators=(",", ":")),
            status_code=201 if secret is not None else 200,
            media_type="application/json",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
            },
        )

    @router.get("/api/orientation", response_model=OrientationResponse)
    async def orientation_view(
        request: Request,
        identity: Annotated[AuthenticatedIdentity, Depends(require_identity)],
        include_stale: bool = False,
    ) -> OrientationResponse:
        state = request.app.state
        effective = await asyncio.to_thread(
            state.roe_service.get_effective,
            identity.agent.id,
            identity.credential.id,
        )
        summary = await asyncio.to_thread(
            state.board_service.orientation,
            agent_id=identity.agent.id,
            include_stale=include_stale,
        )
        actions = required_actions(
            credential_status=identity.credential.status,
            roe=effective,
            orientation=summary,
        )
        return OrientationResponse(
            agent=AgentResponse.from_domain(identity.agent),
            credential=CredentialResponse.from_domain(identity.credential),
            required_actions=[
                RequiredActionResponse(action=item.action, reason=item.reason)
                for item in actions
            ],
            guidance=orientation_guidance(
                actions=actions, orientation=summary, now=datetime.now(UTC)
            ),
            unread=summary.unread,
            unread_at_least=summary.unread_capped,
            pending_mentions=summary.pending_mentions,
            pending_mentions_at_least=summary.pending_mentions_capped,
            latest_seq=summary.latest_seq,
            last_caught_up_at=summary.last_caught_up_at,
            last_cursor_update_at=summary.last_cursor_update_at,
            subscription_count=summary.subscription_count,
            counts_complete=summary.counts_complete,
            subscribed_channels_truncated=summary.subscribed_channels_truncated,
            new_channels_truncated=summary.new_channels_truncated,
            subscribed_channels=[
                OrientationChannelResponse(
                    name=item.name, unread=item.unread,
                    unread_at_least=item.unread_capped,
                )
                for item in summary.channels
            ],
            new_channels=list(summary.new_channels),
            roe_acknowledgement_status=effective.acknowledgement_status,
        )

    @router.get("/api/whoami", response_model=WhoAmIResponse)
    async def whoami(
        request: Request,
        identity: Annotated[AuthenticatedIdentity, Depends(require_identity)],
    ) -> WhoAmIResponse:
        subscriptions = await asyncio.to_thread(
            request.app.state.board_service.list_subscriptions,
            identity.agent.id,
        )
        return WhoAmIResponse(
            agent=AgentResponse.from_domain(identity.agent),
            credential=CredentialResponse.from_domain(identity.credential),
            subscriptions=[
                ChannelResponse.from_domain(channel) for channel in subscriptions
            ],
            expected_identity_guidance=(
                "Compare both stable agent ID and name with locally pinned expected "
                "values and abort before coordination on any mismatch."
            ),
        )

    @router.post(
        "/api/credentials/rotate",
        response_model=IssuedCredentialResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def rotate_credential(
        request: Request,
        payload: RotateCredentialRequest,
        identity: Annotated[AuthenticatedIdentity, Depends(require_identity)],
        response: Response,
    ) -> IssuedCredentialResponse:
        try:
            issued = await asyncio.to_thread(
                request.app.state.agent_service.rotate,
                identity,
                request_id=payload.request_id,
                expected_agent_id=payload.expected_agent_id,
                expected_credential_id=payload.expected_credential_id,
                expected_credential_epoch=payload.expected_credential_epoch,
                reason=payload.reason,
            )
        except (
            AgentAccessFrozenError,
            ConfigurationError,
            CredentialConflictError,
            CredentialLimitError,
            CredentialNotFoundError,
        ) as error:
            raise _lifecycle_http_error(error) from None
        _secret_response_headers(response)
        if not issued.secret_issued:
            response.status_code = status.HTTP_200_OK
        return IssuedCredentialResponse(
            credential=CredentialResponse.from_domain(issued.credential),
            credential_secret=issued.secret,
            secret_issued=issued.secret_issued,
        )

    @router.post(
        "/api/credentials/prove",
        response_model=CredentialResponse,
    )
    async def prove_credential(
        request: Request,
        payload: ProveCredentialRequest,
        identity: Annotated[AuthenticatedIdentity, Depends(require_identity)],
    ) -> CredentialResponse:
        try:
            credential = await asyncio.to_thread(
                request.app.state.agent_service.prove,
                identity,
                request_id=payload.request_id,
                expected_agent_id=payload.expected_agent_id,
                expected_agent_name=payload.expected_agent_name,
                expected_credential_epoch=payload.expected_credential_epoch,
                expected_credential_version=payload.expected_credential_version,
            )
        except (
            AgentAccessFrozenError,
            ConfigurationError,
            CredentialConflictError,
            CredentialLimitError,
            CredentialNotFoundError,
        ) as error:
            raise _lifecycle_http_error(error) from None
        return CredentialResponse.from_domain(credential)

    @router.post(
        "/api/credentials/{credential_id}/retire",
        response_model=CredentialResponse,
    )
    async def retire_credential(
        request: Request,
        credential_id: Annotated[str, Path(min_length=1, max_length=256)],
        payload: CredentialTransitionRequest,
        identity: Annotated[AuthenticatedIdentity, Depends(require_identity)],
    ) -> CredentialResponse:
        try:
            credential = await asyncio.to_thread(
                request.app.state.agent_service.retire_predecessor,
                identity,
                credential_id=credential_id,
                request_id=payload.request_id,
                expected_credential_epoch=payload.expected_credential_epoch,
                expected_credential_version=payload.expected_credential_version,
                reason=payload.reason,
            )
        except (
            AgentAccessFrozenError,
            ConfigurationError,
            CredentialConflictError,
            CredentialLimitError,
            CredentialNotFoundError,
        ) as error:
            raise _lifecycle_http_error(error) from None
        return CredentialResponse.from_domain(credential)

    @router.get(
        "/api/admin/agents/{agent_name}/credentials",
        response_model=list[CredentialResponse],
        dependencies=[Depends(require_admin)],
    )
    async def admin_list_credentials(
        request: Request,
        agent_name: Annotated[str, Path(min_length=1, max_length=128)],
    ) -> list[CredentialResponse]:
        try:
            credentials = await asyncio.to_thread(
                request.app.state.agent_service.list_credentials,
                agent_name,
            )
        except (
            AgentAccessFrozenError,
            AgentNotFoundError,
            ConfigurationError,
        ) as error:
            raise _lifecycle_http_error(error) from None
        return [CredentialResponse.from_domain(item) for item in credentials]

    async def _admin_issue(
        request: Request,
        agent_name: str,
        payload: AdminIssueCredentialRequest,
        response: Response,
        *,
        recover: bool,
    ) -> IssuedCredentialResponse:
        operation = (
            request.app.state.agent_service.recover_agent
            if recover
            else request.app.state.agent_service.issue_for_agent
        )
        try:
            issued = await asyncio.to_thread(
                operation,
                agent_name,
                request_id=payload.request_id,
                expected_credential_epoch=payload.expected_credential_epoch,
                reason=payload.reason,
            )
        except (
            AgentAccessFrozenError,
            AgentNotFoundError,
            ConfigurationError,
            CredentialConflictError,
            CredentialLimitError,
        ) as error:
            raise _lifecycle_http_error(error) from None
        _secret_response_headers(response)
        if not issued.secret_issued:
            response.status_code = status.HTTP_200_OK
        return IssuedCredentialResponse(
            credential=CredentialResponse.from_domain(issued.credential),
            credential_secret=issued.secret,
            secret_issued=issued.secret_issued,
        )

    @router.post(
        "/api/admin/agents/{agent_name}/credentials",
        response_model=IssuedCredentialResponse,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_admin)],
    )
    async def admin_issue_credential(
        request: Request,
        agent_name: Annotated[str, Path(min_length=1, max_length=128)],
        payload: AdminIssueCredentialRequest,
        response: Response,
    ) -> IssuedCredentialResponse:
        return await _admin_issue(
            request, agent_name, payload, response, recover=False
        )

    @router.post(
        "/api/admin/agents/{agent_name}/credentials/recover",
        response_model=IssuedCredentialResponse,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_admin)],
    )
    async def admin_recover_credential(
        request: Request,
        agent_name: Annotated[str, Path(min_length=1, max_length=128)],
        payload: AdminIssueCredentialRequest,
        response: Response,
    ) -> IssuedCredentialResponse:
        return await _admin_issue(
            request, agent_name, payload, response, recover=True
        )

    @router.post(
        "/api/admin/agents/{agent_name}/credentials/{credential_id}/revoke",
        response_model=CredentialResponse,
        dependencies=[Depends(require_admin)],
    )
    async def admin_revoke_credential(
        request: Request,
        agent_name: Annotated[str, Path(min_length=1, max_length=128)],
        credential_id: Annotated[str, Path(min_length=1, max_length=256)],
        payload: CredentialTransitionRequest,
    ) -> CredentialResponse:
        try:
            credential = await asyncio.to_thread(
                request.app.state.agent_service.revoke_credential,
                agent_name,
                credential_id,
                request_id=payload.request_id,
                expected_credential_epoch=payload.expected_credential_epoch,
                expected_credential_version=payload.expected_credential_version,
                reason=payload.reason,
            )
        except (
            AgentAccessFrozenError,
            AgentNotFoundError,
            ConfigurationError,
            CredentialConflictError,
            CredentialNotFoundError,
        ) as error:
            raise _lifecycle_http_error(error) from None
        return CredentialResponse.from_domain(credential)

    @router.post(
        "/api/admin/agents/{agent_name}/revoke",
        response_model=AgentResponse,
        dependencies=[Depends(require_admin)],
    )
    async def admin_revoke_agent(
        request: Request,
        agent_name: Annotated[str, Path(min_length=1, max_length=128)],
        payload: AdminAgentRevokeRequest,
    ) -> AgentResponse:
        try:
            agent = await asyncio.to_thread(
                request.app.state.agent_service.revoke_agent_by_name,
                agent_name,
                request_id=payload.request_id,
            )
        except (
            AgentAccessFrozenError,
            AgentNotFoundError,
            ConfigurationError,
            CredentialConflictError,
        ) as error:
            raise _lifecycle_http_error(error) from None
        return AgentResponse.from_domain(agent)

    @router.get("/api/agents", response_model=list[AgentResponse])
    async def list_agents(
        request: Request,
        _: Annotated[Agent, Depends(require_agent)],
    ) -> list[AgentResponse]:
        agents = await asyncio.to_thread(
            request.app.state.board_service.list_agents
        )
        return [AgentResponse.from_domain(agent) for agent in agents]

    @router.get(
        "/api/server-info",
        response_model=ServerInfo,
        summary="Return runtime application and protocol version information",
    )
    async def server_info(
        request: Request,
        _: Annotated[Agent, Depends(require_agent)],
    ) -> ServerInfo:
        return build_server_info(request.app.state.config)

    @router.get(
        "/api/integration-guide",
        response_model=IntegrationGuide,
        summary="Return the canonical external agent integration guide",
    )
    async def integration_guide(
        request: Request,
        _: Annotated[Agent, Depends(require_agent)],
    ) -> IntegrationGuide:
        return build_integration_guide(request.app.state.config)


def add_reconnect_routes(router: APIRouter) -> None:
    @router.post("/api/reconnect/redeem", status_code=201)
    async def redeem_reconnect(request: Request) -> Response:
        token = getattr(request.state, "reconnect_token", None)
        if not isinstance(token, str):
            raise HTTPException(status_code=401, detail="reconnect authentication required")

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate field")
                result[key] = value
            return result

        try:
            payload = ReconnectRedemption.model_validate(
                json.loads(
                    (await request.body()).decode("utf-8"), object_pairs_hook=unique_object,
                )
            )
        except (ValueError, UnicodeError, RecursionError):
            raise HTTPException(status_code=422, detail="invalid reconnect request") from None
        try:
            redeemed = await asyncio.to_thread(
                request.app.state.agent_service.redeem_reconnect, token,
                expected_agent_id=payload.expected_agent_id,
                expected_agent_name=payload.expected_agent_name, request_id=payload.request_id,
            )
        except CredentialNotFoundError:
            raise HTTPException(status_code=401, detail="reconnect grant is unavailable") from None
        except (ConfigurationError, DomainValidationError):
            raise HTTPException(status_code=422, detail="invalid reconnect request") from None
        except (CredentialConflictError, CredentialLimitError):
            raise HTTPException(status_code=409, detail="reconnect state changed") from None
        body = {
            "agent": AgentResponse.from_domain(redeemed.agent).model_dump(mode="json"),
            "credential": CredentialResponse.from_domain(
                redeemed.issued_credential.credential
            ).model_dump(mode="json"),
            "credential_secret": redeemed.issued_credential.secret,
        }
        request.state.reconnect_identity = (
            redeemed.agent.id, redeemed.issued_credential.credential.id,
        )
        return Response(
            json.dumps(body, ensure_ascii=True, separators=(",", ":")),
            status_code=201, media_type="application/json",
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
