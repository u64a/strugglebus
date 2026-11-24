from __future__ import annotations

import asyncio
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    ChannelNotFoundError,
    CredentialNotFoundError,
    DomainValidationError,
    RoeAcknowledgementRequiredError,
    StorageError,
)
from strugglebus.models import (
    AuthenticatedIdentity,
    MobileIdentity,
)
from strugglebus.rate_limit import ConcurrentConnectionLimiter
from strugglebus.satellite import SITE_CERT_HEADER, site_fingerprint
from strugglebus.service import (
    MAX_CHANNEL_NAME_LENGTH,
    MAX_SEQUENCE,
    normalize_name,
)
from strugglebus.routes.schemas import MessageResponse
from strugglebus.routes.dependencies import require_identity


class LeasedStreamingResponse(StreamingResponse):
    """Release a connection lease around the complete ASGI response call."""

    def __init__(
        self,
        content: Any,
        *,
        lease_limiter: ConcurrentConnectionLimiter,
        lease_key: str,
        **kwargs: Any,
    ) -> None:
        self._lease_limiter = lease_limiter
        self._lease_key = lease_key
        super().__init__(content, **kwargs)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._lease_limiter.release(self._lease_key)


def _never_shutting_down() -> bool:
    """Default for an application that is not behind a managed server.

    Tests and embedded uses construct the app without a Uvicorn server, and a
    stream there should behave exactly as it always has.
    """

    return False


def _agent_revalidator(request: Request, identity: AuthenticatedIdentity):
    """Freeze, credential and receipt checks for an agent stream.

    Ordering is part of the contract: freeze first, then credential
    activity, then the receipt, each with its own terminal event.
    """

    agent = identity.agent
    credential = identity.credential
    header = request.headers.get(SITE_CERT_HEADER)
    site = None if header is None else site_fingerprint(header)

    async def revalidate() -> str | None:
        try:
            state = await asyncio.to_thread(
                request.app.state.access_freeze_service.status
            )
            if state.frozen:
                raise AgentAccessFrozenError("agent access is frozen")
            active = await asyncio.to_thread(
                request.app.state.agent_service.store.credential_is_active,
                agent.id,
                credential.id,
            )
            if not active:
                raise CredentialNotFoundError("authenticated credential is inactive")
            if site is not None and not await asyncio.to_thread(
                request.app.state.satellite_service.admits, site,
            ):
                return (
                    "event: satellite_site_revoked\n"
                    'data: {"detail":"satellite site is no longer admitted"}\n\n'
                )
            await asyncio.to_thread(
                request.app.state.roe_service.require_current_receipt,
                agent.id,
                credential.id,
            )
        except AgentAccessFrozenError:
            return (
                "event: agent_access_frozen\n"
                'data: {"detail":"agent access is frozen"}\n\n'
            )
        except (AgentNotFoundError, CredentialNotFoundError):
            return (
                "event: credential_inactive\n"
                'data: {"detail":"authenticated credential is inactive"}\n\n'
            )
        except RoeAcknowledgementRequiredError:
            return (
                "event: roe_acknowledgement_required\n"
                'data: {"detail":"current rules of engagement receipt required"}\n\n'
            )
        except StorageError:
            return (
                "event: agent_access_unavailable\n"
                'data: {"detail":"agent access is unavailable"}\n\n'
            )
        return None

    return revalidate


def _mobile_revalidator(request: Request, identity: MobileIdentity):
    """Device-liveness check for a non-consuming mobile stream.

    Mobile monitor reads deliberately survive the agent-access freeze, so
    only device revocation and storage failure terminate this stream.
    """

    async def revalidate() -> str | None:
        try:
            live = await asyncio.to_thread(
                request.app.state.mobile_service.authorize_device,
                identity.credential_id,
            )
            if not live:
                raise CredentialNotFoundError("mobile credential is inactive")
        except CredentialNotFoundError:
            return (
                "event: credential_inactive\n"
                'data: {"detail":"authenticated credential is inactive"}\n\n'
            )
        except StorageError:
            return (
                "event: agent_access_unavailable\n"
                'data: {"detail":"agent access is unavailable"}\n\n'
            )
        return None

    return revalidate


async def _stream_channel_filter(request: Request, channel: str | None) -> str | None:
    """Normalize the requested channel and require that it exists."""

    if channel is None:
        return None
    # An unknown channel is refused at connect rather than streaming
    # nothing, so a typo cannot masquerade as a quiet channel.
    try:
        channel_filter = normalize_name(channel)
        await asyncio.to_thread(
            request.app.state.board_service.require_channel,
            channel_filter,
        )
    except DomainValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    except ChannelNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    return channel_filter


def _resume_position(since: int, last_event_id: str | None) -> int:
    """The later of ``since`` and a reconnecting client's Last-Event-ID."""

    if last_event_id is None:
        return since
    try:
        header_since = int(last_event_id)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Last-Event-ID must be zero or greater",
        ) from None
    if header_since < 0 or header_since > MAX_SEQUENCE:
        raise HTTPException(
            status_code=422,
            detail=f"Last-Event-ID must be between 0 and {MAX_SEQUENCE}",
        )
    return max(since, header_since)


async def _build_stream(
    request: Request,
    *,
    since: int,
    channel: str | None,
    last_event_id: str | None,
    lease_key: str,
    revalidate,
) -> StreamingResponse:
    """One live-tail implementation, parameterised by principal.

    Writing a second loop for a second principal is how the freeze
    invariant gets broken in a later refactor, so both share this one.
    Revalidation stays inside the per-message emit loop below and the
    terminal return stays an early return: a batch/filter/emit shape would
    preserve happy-path bytes while losing the denial guarantee.
    """

    channel_filter = await _stream_channel_filter(request, channel)
    since = _resume_position(since, last_event_id)

    config = request.app.state.config
    if not request.app.state.sse_limiter.acquire(
        lease_key,
        config.sse_max_connections_per_agent,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="concurrent stream limit exceeded",
            headers={"Retry-After": "1"},
        )

    async def events():
        cursor = since
        loop = asyncio.get_running_loop()
        deadline = loop.time() + config.sse_connection_seconds
        heartbeat_at = loop.time() + config.sse_heartbeat_seconds

        access_event = revalidate
        # Uvicorn sets its exit flag on SIGTERM and only then waits for open
        # connections to drain, so a stream that polls until its own
        # deadline holds the shutdown open for as long as that deadline
        # allows. Observing the flag here is what makes a restart prompt;
        # a lifespan hook cannot help, because lifespan shutdown runs after
        # the drain it would need to interrupt.
        #
        # Read it from application state on each pass rather than binding it
        # once: the generator body does not run until the first response
        # byte is requested, so a value captured here would be whatever was
        # set before the stream opened, not what is true during shutdown.
        state = request.app.state

        while loop.time() < deadline:
            if await request.is_disconnected():
                break
            if getattr(state, "shutdown_requested", _never_shutting_down)():
                # Terminal and deliberate. A client that reconnects with
                # Last-Event-ID resumes exactly where this stopped.
                yield (
                    "event: server_stopping\n"
                    'data: {"detail":"server is stopping; reconnect shortly"}'
                    "\n\n"
                )
                return
            denial = await access_event()
            if denial is not None:
                yield denial
                return
            try:
                messages = await asyncio.to_thread(
                    request.app.state.board_service.stream_messages,
                    since=cursor,
                    limit=config.sse_batch_size,
                    channel_name=channel_filter,
                )
            except (
                AgentAccessFrozenError,
                AgentNotFoundError,
                CredentialNotFoundError,
                RoeAcknowledgementRequiredError,
            ):
                denial = await access_event()
                if denial is None:
                    raise
                yield denial
                return
            if messages:
                for message in messages:
                    denial = await access_event()
                    if denial is not None:
                        yield denial
                        return
                    payload = json.dumps(
                        MessageResponse.from_domain(message).model_dump(
                            mode="json"
                        ),
                        ensure_ascii=True,
                        separators=(",", ":"),
                    )
                    yield (
                        f"id: {message.seq}\n"
                        "event: message\n"
                        f"data: {payload}\n\n"
                    )
                    cursor = message.seq
                heartbeat_at = loop.time() + config.sse_heartbeat_seconds
                continue
            if loop.time() >= heartbeat_at:
                yield ": heartbeat\n\n"
                heartbeat_at = loop.time() + config.sse_heartbeat_seconds
            await asyncio.sleep(config.sse_poll_interval_ms / 1000)

    limiter = request.app.state.sse_limiter
    try:
        return LeasedStreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
            lease_limiter=limiter,
            lease_key=lease_key,
        )
    except BaseException:
        limiter.release(lease_key)
        raise


def add_stream_routes(router: APIRouter) -> None:
    @router.get("/api/stream")
    async def stream(
        request: Request,
        identity: Annotated[AuthenticatedIdentity, Depends(require_identity)],
        since: Annotated[int, Query(ge=0, le=MAX_SEQUENCE)] = 0,
        channel: Annotated[
            str | None, Query(min_length=1, max_length=MAX_CHANNEL_NAME_LENGTH)
        ] = None,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> StreamingResponse:
        return await _build_stream(
            request,
            since=since,
            channel=channel,
            last_event_id=last_event_id,
            lease_key=identity.agent.id,
            revalidate=_agent_revalidator(request, identity),
        )
