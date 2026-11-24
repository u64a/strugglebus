from __future__ import annotations

import asyncio
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response

from strugglebus.errors import (
    AgentNotFoundError,
    ConfigurationError,
    DomainValidationError,
    RoeConflictError,
)
from strugglebus.models import AuthenticatedIdentity
from strugglebus.routes.schemas import (
    RoeRevisionResponse,
    RoeAcknowledgementResponse,
    EffectiveRoeResponse,
    RoeAcknowledgementCreate,
    RoePublishCreate,
    RoePublishResponse,
    RoeRevisionHistoryResponse,
)
from strugglebus.routes.dependencies import (
    require_identity,
    require_admin,
)


def add_roe_routes(router: APIRouter) -> None:
    @router.get(
        "/api/roe/effective",
        response_model=EffectiveRoeResponse,
        summary="Return the authenticated agent's exact effective RoE composition",
    )
    async def effective_roe(
        request: Request,
        identity: Annotated[AuthenticatedIdentity, Depends(require_identity)],
    ) -> EffectiveRoeResponse:
        effective = await asyncio.to_thread(
            request.app.state.roe_service.get_effective,
            identity.agent.id,
            identity.credential.id,
        )
        return EffectiveRoeResponse.from_domain(
            effective,
            enforcement_mode=request.app.state.config.roe_enforcement_mode,
        )

    @router.post(
        "/api/roe/acknowledgements",
        response_model=RoeAcknowledgementResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Record receipt of the exact current effective RoE composition",
    )
    async def acknowledge_roe(
        request: Request,
        payload: RoeAcknowledgementCreate,
        identity: Annotated[AuthenticatedIdentity, Depends(require_identity)],
        response: Response,
    ) -> RoeAcknowledgementResponse:
        try:
            acknowledgement, created = await asyncio.to_thread(
                request.app.state.roe_service.acknowledge,
                agent_id=identity.agent.id,
                global_revision_id=payload.global_revision_id,
                global_content_sha256=payload.global_content_sha256,
                agent_revision_id=payload.agent_revision_id,
                agent_content_sha256=payload.agent_content_sha256,
                effective_sha256=payload.effective_sha256,
                credential_kind=identity.credential.kind,
                credential_id=identity.credential.id,
                credential_record_id=identity.credential.id,
            )
        except RoeConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        if not created:
            response.status_code = status.HTTP_200_OK
        return RoeAcknowledgementResponse.from_domain(acknowledgement)

    @router.post(
        "/api/admin/roe/global/revisions",
        response_model=RoePublishResponse,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_admin)],
    )
    async def publish_global_roe(
        request: Request,
        payload: RoePublishCreate,
        response: Response,
    ) -> RoePublishResponse:
        if payload.expected_current_revision_id is None:
            raise HTTPException(
                status_code=422,
                detail="expected_current_revision_id is required",
            )
        try:
            revision, created = await asyncio.to_thread(
                request.app.state.roe_service.publish_global,
                revision_id=payload.revision_id,
                expected_current_revision_id=payload.expected_current_revision_id,
                author_label=payload.author_label,
                policy=payload.policy,
                publisher_kind=request.state.admin_credential_kind,
                publisher_id=request.state.admin_credential_id,
            )
        except RoeConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        if not created:
            response.status_code = status.HTTP_200_OK
        return RoePublishResponse(
            revision=RoeRevisionResponse.from_domain(revision),
            created=created,
        )

    @router.post(
        "/api/admin/roe/agents/{agent_name}/revisions",
        response_model=RoePublishResponse,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_admin)],
    )
    async def publish_agent_roe(
        request: Request,
        agent_name: str,
        payload: RoePublishCreate,
        response: Response,
    ) -> RoePublishResponse:
        try:
            agent = await asyncio.to_thread(
                request.app.state.agent_service.get_active_agent_by_name,
                agent_name,
            )
            revision, created = await asyncio.to_thread(
                request.app.state.roe_service.publish_agent,
                agent_id=agent.id,
                revision_id=payload.revision_id,
                expected_current_revision_id=payload.expected_current_revision_id,
                author_label=payload.author_label,
                policy=payload.policy,
                publisher_kind=request.state.admin_credential_kind,
                publisher_id=request.state.admin_credential_id,
            )
        except AgentNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except RoeConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (ConfigurationError, DomainValidationError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        if not created:
            response.status_code = status.HTTP_200_OK
        return RoePublishResponse(
            revision=RoeRevisionResponse.from_domain(revision),
            created=created,
        )

    @router.get(
        "/api/admin/roe/revisions",
        response_model=RoeRevisionHistoryResponse,
        dependencies=[Depends(require_admin)],
    )
    async def roe_revision_history(
        request: Request,
        scope: Literal["global", "agent"],
        agent: str | None = None,
        before_version: Annotated[int | None, Query(ge=2)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> RoeRevisionHistoryResponse:
        if scope == "global":
            if agent is not None:
                raise HTTPException(
                    status_code=422,
                    detail="agent is not valid for global history",
                )
            target_key = "global"
        else:
            if agent is None:
                raise HTTPException(
                    status_code=422,
                    detail="agent is required for agent history",
                )
            try:
                resolved_agent = await asyncio.to_thread(
                    request.app.state.agent_service.get_active_agent_by_name,
                    agent,
                )
            except (AgentNotFoundError, ConfigurationError) as error:
                raise HTTPException(status_code=404, detail=str(error)) from None
            target_key = f"agent:{resolved_agent.id}"
        revisions = await asyncio.to_thread(
            request.app.state.roe_service.store.list_roe_revisions,
            target_key=target_key,
            before_version=before_version,
            limit=limit,
        )
        return RoeRevisionHistoryResponse(
            revisions=[
                RoeRevisionResponse.from_domain(revision)
                for revision in revisions
            ]
        )
