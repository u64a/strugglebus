from __future__ import annotations

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import Response

from strugglebus.drain import MAX_CONTINUATION_LENGTH
from strugglebus.errors import (
    AgentNotFoundError,
    CatchUpCapacityError,
    CatchUpUnavailableError,
    ChannelNotFoundError,
    ChannelLimitError,
    CredentialNotFoundError,
    DomainValidationError,
    DuplicateChannelNameError,
    MessageTooLargeError,
    PostRequestConflictError,
    MessageClaimConflictError,
    MessageClaimNotFoundError,
    MessageNotClaimableError,
    MessageNotFoundError,
    ReplyNotFoundError,
)
from strugglebus.models import Agent
from strugglebus.service import (
    MAX_MESSAGE_LIMIT,
    MAX_SEQUENCE,
)
from strugglebus.routes.schemas import (
    ChannelCreate,
    ChannelResponse,
    SubscriptionResponse,
    MessageCreate,
    MessageResponse,
    SearchHitResponse,
    MessageClaimResponse,
)
from strugglebus.routes.dependencies import require_agent


def add_message_routes(router: APIRouter) -> None:
    @router.get("/api/channels", response_model=list[ChannelResponse])
    async def list_channels(
        request: Request,
        _: Annotated[Agent, Depends(require_agent)],
    ) -> list[ChannelResponse]:
        channels = await asyncio.to_thread(
            request.app.state.board_service.list_channels
        )
        return [ChannelResponse.from_domain(channel) for channel in channels]

    @router.post(
        "/api/channels",
        response_model=ChannelResponse,
        status_code=status.HTTP_201_CREATED,
        responses={409: {"description": "Channel name already exists"}},
    )
    async def create_channel(
        request: Request,
        payload: ChannelCreate,
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> ChannelResponse:
        try:
            channel = await asyncio.to_thread(
                request.app.state.board_service.create_channel,
                payload.name,
                purpose=payload.purpose,
                created_by=agent.id,
            )
        except DuplicateChannelNameError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except ChannelLimitError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except AgentNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="agent authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return ChannelResponse.from_domain(channel)

    @router.get("/api/subscriptions", response_model=list[ChannelResponse])
    async def list_subscriptions(
        request: Request,
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> list[ChannelResponse]:
        try:
            channels = await asyncio.to_thread(
                request.app.state.board_service.list_subscriptions, agent.id
            )
        except (AgentNotFoundError, CredentialNotFoundError):
            raise HTTPException(
                status_code=401, detail="agent authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        return [ChannelResponse.from_domain(channel) for channel in channels]

    @router.put("/api/subscriptions/{channel}", response_model=SubscriptionResponse)
    @router.delete("/api/subscriptions/{channel}", response_model=SubscriptionResponse)
    async def change_subscription(
        request: Request,
        channel: Annotated[str, Path(min_length=1, max_length=64)],
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> SubscriptionResponse:
        subscribed = request.method == "PUT"
        board = request.app.state.board_service
        try:
            result = await asyncio.to_thread(
                board.subscribe if subscribed else board.unsubscribe,
                channel, agent_id=agent.id,
            )
        except (AgentNotFoundError, CredentialNotFoundError):
            raise HTTPException(
                status_code=401, detail="agent authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except ChannelNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return SubscriptionResponse(
            channel=ChannelResponse.from_domain(result), subscribed=subscribed
        )

    @router.get(
        "/api/channels/{name}/messages",
        response_model=list[MessageResponse],
        responses={404: {"description": "Channel not found"}},
    )
    async def list_messages(
        request: Request,
        name: str,
        _: Annotated[Agent, Depends(require_agent)],
        since: Annotated[int, Query(ge=0, le=MAX_SEQUENCE)] = 0,
        limit: Annotated[int, Query(ge=1, le=MAX_MESSAGE_LIMIT)] = 50,
    ) -> list[MessageResponse]:
        try:
            messages = await asyncio.to_thread(
                request.app.state.board_service.list_messages,
                name,
                since=since,
                limit=limit,
            )
        except ChannelNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return [MessageResponse.from_domain(message) for message in messages]

    @router.post(
        "/api/channels/{name}/messages",
        response_model=MessageResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            400: {"description": "Invalid reply or metadata"},
            404: {"description": "Channel not found"},
            413: {"description": "Message body too large"},
            409: {"description": "Post request_id conflicts with previously accepted input"},
        },
    )
    async def create_message(
        request: Request,
        name: str,
        payload: MessageCreate,
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> MessageResponse:
        try:
            message = await asyncio.to_thread(
                request.app.state.board_service.create_message,
                name,
                agent_id=agent.id,
                body=payload.body,
                kind=payload.kind,
                reply_to=payload.reply_to,
                metadata=payload.metadata,
                request_id=payload.request_id,
            )
        except PostRequestConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except ChannelNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except ReplyNotFoundError as error:
            raise HTTPException(status_code=400, detail=str(error)) from None
        except MessageTooLargeError as error:
            raise HTTPException(status_code=413, detail=str(error)) from None
        except AgentNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="agent authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=400, detail=str(error)) from None
        return MessageResponse.from_domain(message)

    @router.get(
        "/api/messages/{message_seq}/replies",
        response_model=list[MessageResponse],
        responses={404: {"description": "Reply target not found"}},
    )
    async def read_replies(
        request: Request,
        message_seq: Annotated[int, Path(ge=1, le=MAX_SEQUENCE)],
        _: Annotated[Agent, Depends(require_agent)],
        since: Annotated[int, Query(ge=0, le=MAX_SEQUENCE)] = 0,
        limit: Annotated[int, Query(ge=1, le=MAX_MESSAGE_LIMIT)] = 50,
    ) -> list[MessageResponse]:
        try:
            messages = await asyncio.to_thread(
                request.app.state.board_service.read_replies,
                message_seq,
                since=since,
                limit=limit,
            )
        except ReplyNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return [MessageResponse.from_domain(message) for message in messages]

    def _claim_conflict(error: MessageClaimConflictError) -> HTTPException:
        claim = MessageClaimResponse.from_domain(error.claim)
        return HTTPException(
            status_code=409,
            detail={"message": str(error), "claim": claim.model_dump(mode="json")},
        )

    @router.post(
        "/api/messages/{message_seq}/claim",
        response_model=MessageClaimResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            200: {"description": "Already claimed by this agent"},
            404: {"description": "Message not found"},
            409: {"description": "Claimed by another agent, or not a task"},
        },
    )
    async def claim_message(
        request: Request,
        response: Response,
        message_seq: Annotated[int, Path(ge=1, le=MAX_SEQUENCE)],
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> MessageClaimResponse:
        try:
            claim, created = await asyncio.to_thread(
                request.app.state.board_service.claim_message,
                message_seq,
                agent_id=agent.id,
            )
        except MessageNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except MessageNotClaimableError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except MessageClaimConflictError as error:
            raise _claim_conflict(error) from None
        except AgentNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="agent authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        if not created:
            response.status_code = status.HTTP_200_OK
        return MessageClaimResponse.from_domain(claim)

    @router.get(
        "/api/messages/{message_seq}/claim",
        response_model=MessageClaimResponse,
        responses={404: {"description": "Message not found or not claimed"}},
    )
    async def get_message_claim(
        request: Request,
        message_seq: Annotated[int, Path(ge=1, le=MAX_SEQUENCE)],
        _: Annotated[Agent, Depends(require_agent)],
    ) -> MessageClaimResponse:
        try:
            claim = await asyncio.to_thread(
                request.app.state.board_service.get_message_claim, message_seq
            )
        except (MessageNotFoundError, MessageClaimNotFoundError) as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        return MessageClaimResponse.from_domain(claim)

    @router.delete(
        "/api/messages/{message_seq}/claim",
        status_code=status.HTTP_204_NO_CONTENT,
        responses={
            404: {"description": "Message not claimed"},
            409: {"description": "Claimed by another agent"},
        },
    )
    async def release_message_claim(
        request: Request,
        message_seq: Annotated[int, Path(ge=1, le=MAX_SEQUENCE)],
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> Response:
        try:
            await asyncio.to_thread(
                request.app.state.board_service.release_message_claim,
                message_seq,
                agent_id=agent.id,
            )
        except MessageClaimNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except MessageClaimConflictError as error:
            raise _claim_conflict(error) from None
        except AgentNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="agent authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get("/api/catch-up", response_model=list[MessageResponse])
    async def catch_up(
        request: Request,
        response: Response,
        agent: Annotated[Agent, Depends(require_agent)],
        limit: Annotated[int, Query(ge=1, le=MAX_MESSAGE_LIMIT)] = 50,
        include_stale: bool = False,
        start_drain: bool = False,
        continuation: Annotated[
            str | None, Query(max_length=MAX_CONTINUATION_LENGTH)
        ] = None,
    ) -> list[MessageResponse]:
        try:
            page = await asyncio.to_thread(
                request.app.state.board_service.catch_up_page,
                agent_id=agent.id,
                limit=limit,
                include_stale=include_stale,
                start_drain=start_drain,
                continuation=continuation,
            )
        except (AgentNotFoundError, CredentialNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="agent authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except CatchUpCapacityError as error:
            raise HTTPException(status_code=429, detail=str(error)) from None
        except CatchUpUnavailableError as error:
            raise HTTPException(status_code=410, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        response.headers["Cache-Control"] = "no-store"
        response.headers["Catch-Up-Mode"] = page.mode
        if page.complete is not None:
            response.headers["Catch-Up-Complete"] = str(page.complete).lower()
            response.headers["Catch-Up-Snapshot-Seq"] = str(page.snapshot_seq)
        if page.continuation is not None:
            response.headers["Catch-Up-Continuation"] = page.continuation
        if page.expires_at is not None:
            response.headers["Catch-Up-Expires-At"] = page.expires_at.isoformat()
        return [MessageResponse.from_domain(message) for message in page.messages]

    @router.get("/api/search", response_model=list[SearchHitResponse])
    async def search(
        request: Request,
        _: Annotated[Agent, Depends(require_agent)],
        query: Annotated[str, Query(min_length=1, max_length=256)],
        channel: Annotated[str | None, Query(max_length=64)] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_MESSAGE_LIMIT)] = 50,
        include_stale: bool = False,
    ) -> list[SearchHitResponse]:
        try:
            hits = await asyncio.to_thread(
                request.app.state.board_service.search,
                query,
                channel_name=channel,
                limit=limit,
                include_stale=include_stale,
            )
        except ChannelNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from None
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return [SearchHitResponse.from_domain(hit) for hit in hits]
