from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse

from strugglebus.dashboard import (
    dashboard_headers,
    render_site_bundle,
    render_site_revocation,
    render_sites,
)
from strugglebus.errors import (
    AgentAccessFrozenError,
    ConfigurationError,
    DomainValidationError,
    DuplicateAgentNameError,
    StorageError,
)
from strugglebus.integration import build_server_info
from strugglebus.operator_auth import OperatorAuthError, OperatorCapacityError
from strugglebus.operator_web import authority_for, context_for, operator_form
from strugglebus.service import normalize_name


def add_site_routes(router: APIRouter) -> None:
    async def _sites_page(
        request: Request,
        *,
        code: int = 200,
        error: str | None = None,
        notice: str | None = None,
        label: str = "",
    ) -> HTMLResponse:
        config = request.app.state.config
        try:
            sites = await asyncio.to_thread(request.app.state.satellite_service.list_sites)
        except StorageError:
            # Never render an empty roster on failure: "no sites" and "the
            # roster could not be read" must not look alike.
            sites = ()
            if error is None:
                code = 503
                error = "The site roster is unavailable. This is not an empty roster."
        return HTMLResponse(
            render_sites(
                build_server_info(config),
                sites,
                generated_at=datetime.now(UTC),
                csrf_token=context_for(request).csrf_token,
                hostname=config.satellite_hostname,
                cert_days=config.satellite_cert_days,
                error=error,
                notice=notice,
                label=label,
            ),
            status_code=code,
            headers=dashboard_headers(),
        )

    @router.get("/sites", response_class=HTMLResponse, include_in_schema=False)
    async def sites_view(request: Request) -> HTMLResponse:
        return await _sites_page(request)

    @router.post("/sites", response_class=HTMLResponse, include_in_schema=False)
    async def sites_add(request: Request) -> HTMLResponse:
        fields = await operator_form(
            request,
            fields={"label", "join_request", "password", "confirm"},
            required={"label", "join_request", "password", "confirm"},
        )
        label = fields.get("label", "").strip()
        if fields.get("confirm") != "add":
            return await _sites_page(
                request, code=422, error="Explicit confirmation is required.", label=label,
            )
        try:
            canonical = normalize_name(label)
        except DomainValidationError:
            return await _sites_page(
                request, code=422, label=label,
                error="Site labels are lowercase kebab-case, for example devbox-one.",
            )
        # Proved in this request, immediately before a certificate is signed.
        try:
            await authority_for(request).reauthenticate(
                context_for(request),
                fields["password"],
                source=request.state.operator_source,
            )
        except OperatorCapacityError:
            return await _sites_page(
                request, code=429, label=canonical,
                error="Too many attempts. Wait, then retry.",
            )
        except OperatorAuthError:
            return await _sites_page(
                request, code=401, label=canonical,
                error="Reauthentication failed. No site was added.",
            )
        try:
            issued = await asyncio.to_thread(
                request.app.state.satellite_service.add_site,
                label=canonical,
                join_request=fields["join_request"],
                actor_id=context_for(request).actor_id,
            )
        except DuplicateAgentNameError:
            return await _sites_page(
                request, code=409, label=canonical,
                error="That label is already registered. Labels stay reserved "
                "after revocation.",
            )
        except DomainValidationError as error:
            return await _sites_page(request, code=422, label=canonical, error=str(error))
        except ConfigurationError:
            return await _sites_page(
                request, code=503, label=canonical,
                error="Satellite sites are not configured on this deployment.",
            )
        except AgentAccessFrozenError:
            return await _sites_page(
                request, code=503, label=canonical, error="Agent access is frozen.",
            )
        except StorageError:
            return await _sites_page(
                request, code=503, label=canonical,
                error="The service could not add the site.",
            )
        return HTMLResponse(
            render_site_bundle(
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
                site_label=canonical,
                bundle=issued.bundle,
                expires_at=issued.expires_at,
            ),
            status_code=status.HTTP_201_CREATED,
            headers={
                **dashboard_headers(), "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
            },
        )

    async def _enabled_site(request: Request, site_id: str) -> dict[str, object] | None:
        try:
            if str(UUID(site_id)) != site_id:
                return None
        except ValueError:
            return None
        sites = await asyncio.to_thread(request.app.state.satellite_service.list_sites)
        for site in sites:
            if site.get("id") == site_id and site.get("status") == "enabled":
                return site
        return None

    @router.get("/sites/{site_id}/revoke", response_class=HTMLResponse, include_in_schema=False)
    async def site_revoke_view(request: Request, site_id: str) -> HTMLResponse:
        try:
            site = await _enabled_site(request, site_id)
        except StorageError:
            return await _sites_page(request, code=503, error="The site roster is unavailable.")
        if site is None:
            return await _sites_page(
                request, code=404, error="That site is unavailable or already revoked.",
            )
        return HTMLResponse(
            render_site_revocation(
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
                csrf_token=context_for(request).csrf_token,
                site_id=site_id,
                site_label=str(site.get("label", "")),
            ),
            headers=dashboard_headers(),
        )

    @router.post("/sites/{site_id}/revoke", response_class=HTMLResponse, include_in_schema=False)
    async def site_revoke_submit(request: Request, site_id: str) -> HTMLResponse:
        fields = await operator_form(
            request,
            fields={"label", "reason", "confirm"},
            required={"label", "reason", "confirm"},
        )
        try:
            site = await _enabled_site(request, site_id)
        except StorageError:
            return await _sites_page(request, code=503, error="The site roster is unavailable.")
        if site is None:
            return await _sites_page(
                request, code=404, error="That site is unavailable or already revoked.",
            )
        if fields.get("confirm") != "revoke" or fields.get("label") != site.get("label"):
            return await _sites_page(
                request, code=422,
                error="Exact label confirmation is required. Nothing was revoked.",
            )
        reason = fields.get("reason", "").strip()
        if not reason or len(reason) > 256:
            return await _sites_page(
                request, code=422, error="A bounded, non-secret reason is required.",
            )
        try:
            revoked = await asyncio.to_thread(
                request.app.state.satellite_service.revoke_site,
                site_id,
                reason=reason,
                actor_id=context_for(request).actor_id,
            )
        except StorageError:
            return await _sites_page(
                request, code=503,
                error="The revocation is unavailable. No action is implied.",
            )
        if not revoked:
            return await _sites_page(
                request, code=409, error="That site changed state. Reload before retrying.",
            )
        return await _sites_page(
            request,
            notice=f"Revoked {site.get('label', '')}. It can no longer reach the "
            "agent plane.",
        )
