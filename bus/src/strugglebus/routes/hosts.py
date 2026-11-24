from __future__ import annotations

import asyncio

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from strugglebus.errors import (
    AgentAccessFrozenError,
    DomainValidationError,
    DuplicateAgentNameError,
    EnrollmentExpiredError,
    EnrollmentInvalidError,
    StorageError,
)
from strugglebus.errors import ConfigurationError
from strugglebus.models import Agent
from strugglebus.routes.dependencies import _secret_response_headers, require_agent
from strugglebus.routes.schemas import (
    HostRedemptionRequest,
    RedeemedHostResponse,
    SiteDocumentResponse,
)

#: The only things this route ever says in ``detail``. A worker host prints
#: them, so they are fixed words and never text from an error.
BAD_REQUEST = "bad-request"
UNKNOWN_OR_USED = "unknown-or-used-code"
EXPIRED = "expired"
NAME_TAKEN = "name-taken"
UNAVAILABLE = "unavailable"


def _refusal(error: Exception) -> HTTPException:
    """Expired and name-taken are only raised for a caller who held the right code."""

    if isinstance(error, EnrollmentExpiredError):
        return HTTPException(status_code=410, detail=EXPIRED)
    if isinstance(error, EnrollmentInvalidError):
        return HTTPException(status_code=404, detail=UNKNOWN_OR_USED)
    if isinstance(error, DuplicateAgentNameError):
        return HTTPException(status_code=409, detail=NAME_TAKEN)
    if isinstance(error, DomainValidationError):
        return HTTPException(status_code=400, detail=BAD_REQUEST)
    return HTTPException(status_code=503, detail=UNAVAILABLE)


def add_host_routes(router: APIRouter) -> None:
    @router.post(
        "/api/hosts/enrollments/redeem",
        response_model=RedeemedHostResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            200: {"description": "The same request again; the credential is replaced"},
            400: {"description": "bad-request"},
            404: {"description": "unknown-or-used-code"},
            409: {"description": "name-taken"},
            410: {"description": "expired"},
            503: {"description": "unavailable"},
        },
    )
    async def redeem_host_enrollment(
        request: Request,
        payload: HostRedemptionRequest,
        response: Response,
    ) -> RedeemedHostResponse:
        """Exchange a worker host's one-time code for its own service principal.

        The code is the bearer token; a host holds nothing else yet. Repeating
        the call with the same ``request_id`` before the code expires succeeds
        again and replaces the credential, so a lost answer is recoverable.
        """

        state = request.scope.get("state", {})
        code = state.get("host_enrollment_token")
        if not isinstance(code, str):
            raise HTTPException(status_code=404, detail=UNKNOWN_OR_USED)
        try:
            redeemed = await asyncio.to_thread(
                request.app.state.host_enrollment_service.redeem,
                code,
                request_id=payload.request_id,
                source=str(state.get("host_enrollment_source") or "unknown"),
            )
        except (
            AgentAccessFrozenError, DomainValidationError, StorageError,
        ) as error:
            raise _refusal(error) from None
        _secret_response_headers(response)
        if not redeemed.created:
            response.status_code = status.HTTP_200_OK
        return RedeemedHostResponse(
            name=redeemed.name,
            credential=redeemed.credential,
            request_id=payload.request_id,
        )

    @router.get(
        "/api/site-documents/{name}",
        response_model=SiteDocumentResponse,
        responses={404: {"description": "Nothing has been published under that name"}},
    )
    async def read_site_document(
        request: Request,
        name: str,
        _: Annotated[Agent, Depends(require_agent)],
    ) -> SiteDocumentResponse:
        """Return a site's signed document exactly as it was published.

        The bus has not verified it. Check the signature against keys you
        pinned yourself, and refuse a serial lower than one you have accepted.
        """

        try:
            document = await asyncio.to_thread(
                request.app.state.site_document_service.read, name,
            )
        except ConfigurationError:
            document = None
        except StorageError:
            raise HTTPException(status_code=503, detail=UNAVAILABLE) from None
        if document is None:
            raise HTTPException(status_code=404, detail="no such document")
        return SiteDocumentResponse.from_domain(document)
