from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request, status

from strugglebus.errors import (
    ConfigurationError,
    StorageError,
)
from strugglebus.routes.schemas import HealthResponse


def add_health_routes(router: APIRouter) -> None:
    @router.get(
        "/healthz",
        response_model=HealthResponse,
        responses={503: {"description": "Service is not ready"}},
    )
    async def healthz(request: Request) -> HealthResponse:
        try:
            if (
                not request.app.state.configuration_initialized
                or request.app.state.admin_verifier is None
            ):
                raise StorageError("application initialization is incomplete")
            await asyncio.to_thread(
                request.app.state.board_service.check_readiness
            )
            await asyncio.to_thread(
                request.app.state.roe_service.check_readiness
            )
        except (ConfigurationError, StorageError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="service is not ready",
            ) from None
        return HealthResponse(status="ok")
