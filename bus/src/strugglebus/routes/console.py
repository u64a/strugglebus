from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response

from strugglebus.ca import fingerprint_display, load_trust_anchor
from strugglebus.errors import (
    AgentAccessFrozenError,
    ConfigurationError,
    DomainValidationError,
    StorageError,
    TrustAnchorError,
)
from strugglebus.dashboard import (
    DASHBOARD_STYLESHEET,
    DASHBOARD_STYLESHEET_PATH,
    DASHBOARD_TEASER_LIMIT,
    dashboard_headers,
    dashboard_stylesheet_headers,
    parse_cursor_query,
    parse_dashboard_query,
    render_activity,
    render_channels,
    render_dashboard_error,
    render_onboarding_package,
    render_overview,
    render_register,
    render_system,
)
from strugglebus.integration import build_server_info
from strugglebus.operator_web import (
    authority_for,
    context_for,
    operator_form,
    managed_agents_view,
)
from strugglebus.service import normalize_name


def add_console_routes(router: APIRouter) -> None:
    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def overview_view(request: Request) -> HTMLResponse:
        configured_limit = request.app.state.config.human_activity_limit
        try:
            snapshot = await asyncio.to_thread(
                request.app.state.board_service.dashboard_snapshot,
                channel_name=None,
                agent_name=None,
                before=None,
                limit=min(DASHBOARD_TEASER_LIMIT, configured_limit),
            )
        except StorageError:
            return HTMLResponse(
                render_dashboard_error(
                    title="Dashboard unavailable",
                    detail="The service could not load this read-only view.",
                    active="overview",
                ),
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                headers=dashboard_headers(),
            )
        return HTMLResponse(
            render_overview(
                snapshot,
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
            ),
            headers=dashboard_headers(),
        )

    @router.get(
        DASHBOARD_STYLESHEET_PATH,
        response_class=Response,
        include_in_schema=False,
    )
    async def dashboard_stylesheet() -> Response:
        return Response(
            DASHBOARD_STYLESHEET,
            media_type="text/css",
            headers=dashboard_stylesheet_headers(),
        )

    @router.get("/activity", response_class=HTMLResponse, include_in_schema=False)
    async def activity_view(request: Request) -> HTMLResponse:
        configured_limit = request.app.state.config.human_activity_limit
        try:
            query = parse_dashboard_query(
                request.query_params.multi_items(),
                configured_limit=configured_limit,
            )
            snapshot = await asyncio.to_thread(
                request.app.state.board_service.dashboard_snapshot,
                channel_name=query.channel,
                agent_name=query.agent,
                before=query.before,
                limit=query.limit,
            )
        except DomainValidationError:
            return HTMLResponse(
                render_dashboard_error(
                    title="Invalid dashboard filters",
                    detail="Use one value each for channel, agent, before, and limit.",
                    active="activity",
                ),
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                headers=dashboard_headers(),
            )
        except StorageError:
            return HTMLResponse(
                render_dashboard_error(
                    title="Dashboard unavailable",
                    detail="The service could not load this read-only view.",
                    active="activity",
                ),
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                headers=dashboard_headers(),
            )
        return HTMLResponse(
            render_activity(
                snapshot,
                query,
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
                configured_limit=configured_limit,
            ),
            headers=dashboard_headers(),
        )

    @router.get("/channels", response_class=HTMLResponse, include_in_schema=False)
    async def channels_view(request: Request) -> HTMLResponse:
        configured_limit = request.app.state.config.human_activity_limit
        try:
            query = parse_cursor_query(
                request.query_params.multi_items(),
                configured_limit=configured_limit,
                agent=False,
            )
            page = await asyncio.to_thread(
                request.app.state.board_service.channel_activity,
                after=query.after,
                limit=query.limit,
            )
        except DomainValidationError:
            return HTMLResponse(
                render_dashboard_error(
                    title="Invalid dashboard filters",
                    detail="Use one canonical value each for after and limit.",
                    active="channels",
                ),
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                headers=dashboard_headers(),
            )
        except StorageError:
            return HTMLResponse(
                render_dashboard_error(
                    title="Dashboard unavailable",
                    detail="The service could not load this read-only view.",
                    active="channels",
                ),
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                headers=dashboard_headers(),
            )
        return HTMLResponse(
            render_channels(
                page,
                query,
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
            ),
            headers=dashboard_headers(),
        )

    @router.get("/agents", response_class=HTMLResponse, include_in_schema=False)
    async def agents_view(request: Request) -> HTMLResponse:
        return await managed_agents_view(request)

    @router.get("/system", response_class=HTMLResponse, include_in_schema=False)
    async def system_view(request: Request) -> HTMLResponse:
        return HTMLResponse(
            render_system(
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
            ),
            headers=dashboard_headers(),
        )

    @router.get("/ca-root.crt", include_in_schema=False)
    async def ca_root(request: Request) -> Response:
        config = request.app.state.config
        try:
            anchor = await asyncio.to_thread(
                load_trust_anchor, config.ca_bundle_path, config.ca_root_sha256
            )
        except TrustAnchorError as error:
            raise HTTPException(status_code=503, detail=str(error)) from None
        if anchor is None:
            raise HTTPException(status_code=404, detail="not found")
        return Response(
            content=anchor,
            media_type="application/x-pem-file",
            headers={
                "Content-Disposition": (
                    'attachment; filename="strugglebus-lan-root.crt"'
                ),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": (
                    "default-src 'none'; base-uri 'none'; form-action 'none'; "
                    "frame-ancestors 'none'"
                ),
            },
        )

    @router.get("/register", response_class=HTMLResponse, include_in_schema=False)
    async def register_view(request: Request) -> HTMLResponse:
        return HTMLResponse(
            render_register(
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
                csrf_token=context_for(request).csrf_token,
            ),
            headers=dashboard_headers(),
        )

    @router.post("/register", response_class=HTMLResponse, include_in_schema=False)
    async def register_submit(request: Request) -> HTMLResponse:
        config = request.app.state.config
        server_info = build_server_info(config)
        fields = await operator_form(
            request, fields={"name", "description"}, required={"name"},
        )
        name = fields.get("name", "").strip()
        description = fields.get("description", "").strip()

        def problem(detail: str, code: int) -> HTMLResponse:
            return HTMLResponse(
                render_register(
                    server_info,
                    generated_at=datetime.now(UTC),
                    error=detail,
                    name=name,
                    description=description,
                    csrf_token=context_for(request).csrf_token,
                ),
                status_code=code,
                headers=dashboard_headers(),
            )

        if not name:
            return problem("Enter a name for the agent.", 422)
        try:
            # The form takes the exact identity, so it must be a valid agent
            # name, not merely a valid prefix: a prefix without a hyphen can
            # never be claimed as the name shown in the package.
            canonical = normalize_name(name, agent=True)
        except DomainValidationError:
            return problem(
                "That name will not work. Agent names use lowercase letters, "
                "digits and hyphens, with at least one hyphen, for example "
                "adlab-cli-win.",
                422,
            )
        try:
            anchor = await asyncio.to_thread(
                load_trust_anchor, config.ca_bundle_path, config.ca_root_sha256
            )
        except TrustAnchorError as error:
            return problem(str(error), 503)
        try:
            issued = await asyncio.to_thread(
                request.app.state.agent_service.create_dashboard_enrollment,
                name=canonical,
                description=description,
                operator=context_for(request),
                authorize=lambda: authority_for(request).require_active(
                    context_for(request)
                ),
            )
        except ConfigurationError as error:
            return problem(str(error), 422)
        except AgentAccessFrozenError:
            return problem("Agent access is frozen.", 503)
        except StorageError:
            return problem("The service could not create an enrollment.", 503)
        if issued.token is None:
            return problem("The service did not issue a token.", 503)
        return HTMLResponse(
            render_onboarding_package(
                server_info,
                generated_at=datetime.now(UTC),
                base_url=config.public_base_url,
                agent_name=issued.enrollment.name_prefix,
                token=issued.token,
                expires_at=issued.enrollment.expires_at,
                enrollment_id=issued.enrollment.id,
                pending_seconds=config.credential_pending_seconds,
                ca_root=anchor,
                ca_fingerprint=(
                    fingerprint_display(config.ca_root_sha256)
                    if anchor is not None
                    else None
                ),
            ),
            status_code=status.HTTP_201_CREATED,
            headers={
                **dashboard_headers(), "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
            },
        )
