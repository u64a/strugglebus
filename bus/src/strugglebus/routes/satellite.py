"""Routes a satellite calls for itself: certificate renewal and its release.

The middleware admits these only on the satellite path, with the verified site
certificate as the sole authority, so no agent key is involved.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import Field

from strugglebus.errors import (
    AgentAccessFrozenError,
    ConfigurationError,
    CredentialConflictError,
    DomainValidationError,
    StorageError,
)
from strugglebus.routes.schemas import StrictModel
from strugglebus.satellite import release_directory, release_manifest


class SiteRenewal(StrictModel):
    join_request: str = Field(min_length=1, max_length=4096)


def _site(request: Request) -> str:
    site = request.scope.get("state", {}).get("satellite_site")
    if not isinstance(site, str):
        raise HTTPException(status_code=403, detail="satellite path required")
    return site


def add_satellite_routes(router: APIRouter) -> None:
    @router.post("/api/satellite/renew", include_in_schema=False)
    async def renew(request: Request, payload: SiteRenewal) -> dict[str, str]:
        site = _site(request)
        try:
            issued = await asyncio.to_thread(
                request.app.state.satellite_service.renew_site,
                site,
                join_request=payload.join_request,
            )
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        except CredentialConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except AgentAccessFrozenError:
            raise HTTPException(status_code=503, detail="agent access is frozen") from None
        except (ConfigurationError, StorageError):
            raise HTTPException(
                status_code=503, detail="satellite renewal is unavailable"
            ) from None
        return {"bundle": issued.bundle, "expires_at": issued.expires_at.isoformat()}

    async def _manifest(request: Request) -> dict[str, object]:
        _site(request)
        try:
            return await asyncio.to_thread(release_manifest)
        except (ConfigurationError, OSError):
            raise HTTPException(
                status_code=503, detail="the running release files are unavailable"
            ) from None

    @router.get("/api/satellite/release", include_in_schema=False)
    async def release(request: Request) -> dict[str, object]:
        return await _manifest(request)

    @router.get("/api/satellite/release/wheel", include_in_schema=False)
    async def release_wheel(request: Request) -> FileResponse:
        manifest = await _manifest(request)
        name = manifest["wheel"]["name"]  # type: ignore[index]
        return FileResponse(release_directory() / str(name), filename=str(name))

    @router.get("/api/satellite/release/requirements-lock", include_in_schema=False)
    async def release_lock(request: Request) -> FileResponse:
        await _manifest(request)
        return FileResponse(release_directory() / "requirements.lock")
