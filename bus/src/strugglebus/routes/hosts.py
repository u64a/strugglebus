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
from strugglebus import fleet_offers
from strugglebus.host_status import NotAHostError, RefusedError, TooLargeError, TooSoonError
from strugglebus.models import Agent
from strugglebus.routes.dependencies import _secret_response_headers, require_agent
from strugglebus.routes.schemas import (
    HostRedemptionRequest,
    HostEventsResponse,
    HostReportResponse,
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


NOT_A_HOST = "not-a-host"
TOO_LARGE = "too-large"
TOO_SOON = "too-soon"


def _report_refusal(error: Exception) -> HTTPException:
    """Why a host's report was not stored, in fixed words a host can act on."""

    if isinstance(error, TooLargeError):
        return HTTPException(status_code=413, detail=TOO_LARGE)
    if isinstance(error, NotAHostError):
        return HTTPException(status_code=403, detail=NOT_A_HOST)
    if isinstance(error, TooSoonError):
        return HTTPException(
            status_code=429, detail=TOO_SOON, headers={"Retry-After": str(error.retry_after)},
        )
    if isinstance(error, RefusedError):
        return HTTPException(status_code=400, detail=error.reason)
    return HTTPException(status_code=503, detail=UNAVAILABLE)


FLEET_HELD = "fleet-held"


def _offer_refusal(error: Exception) -> HTTPException:
    """Why a host's fleet offer was not kept, in fixed words a host can act on."""
    if isinstance(error, fleet_offers.FleetHeldError):
        return HTTPException(status_code=409, detail=FLEET_HELD)
    if isinstance(error, fleet_offers.TooLargeError):
        return HTTPException(status_code=413, detail=TOO_LARGE)
    if isinstance(error, fleet_offers.NotAHostError):
        return HTTPException(status_code=403, detail=NOT_A_HOST)
    if isinstance(error, fleet_offers.TooSoonError):
        return HTTPException(
            status_code=429, detail=TOO_SOON, headers={"Retry-After": str(error.retry_after)},
        )
    if isinstance(error, fleet_offers.RefusedError):
        return HTTPException(status_code=400, detail=error.reason)
    return HTTPException(status_code=503, detail=UNAVAILABLE)


def add_host_routes(router: APIRouter) -> None:
    @router.post(
        "/api/hosts/fleet-offer",
        status_code=status.HTTP_204_NO_CONTENT,
        responses={
            400: {"description": "The offer does not fit the contract; the detail says how"},
            403: {"description": "not-a-host"},
            409: {"description": "fleet-held: the bus already holds a fleet, stop offering"},
            413: {"description": "too-large"},
            429: {"description": "too-soon"},
            503: {"description": "unavailable"},
        },
    )
    async def offer_fleet(
        request: Request,
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> Response:
        """A worker host offers the fleet it already accepts, while the bus holds none.

        The body is ``{"serial", "fleet", "sig"}``: the serial, base64 of the
        exact accepted bytes, and the signature file's text. Only an agent the
        bus has marked as a host may offer, at most once a minute. The bus
        checks the shape and nothing else: an administrator's App verifies the
        signature before it publishes anything.
        """

        body = await request.body()
        try:
            await asyncio.to_thread(
                request.app.state.fleet_offer_service.offer, agent.id, agent.name, body,
            )
        except (DomainValidationError, StorageError) as error:
            raise _offer_refusal(error) from None
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.post(
        "/api/hosts/status",
        response_model=HostReportResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            400: {"description": "The snapshot does not fit the contract; the detail says where"},
            403: {"description": "not-a-host"},
            413: {"description": "too-large"},
            429: {"description": "too-soon"},
            503: {"description": "unavailable"},
        },
    )
    async def report_host_status(
        request: Request,
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> HostReportResponse:
        """A worker host reports what it is doing, for the App's Hosts page.

        The body is the v2 snapshot, at most 16 KB, at most once every ten
        seconds. Only an agent the bus has marked as a host may report, and
        the report is stored under the caller's own identity whatever it says.
        """

        body = await request.body()
        try:
            received_at = await asyncio.to_thread(
                request.app.state.host_status_service.record, agent.id, agent.name, body,
            )
        except (DomainValidationError, StorageError) as error:
            raise _report_refusal(error) from None
        return HostReportResponse(received_at=received_at)

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

    @router.post(
        "/api/hosts/events",
        response_model=HostEventsResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            400: {"description": "The batch is refused whole; the detail is the reason"},
            403: {"description": "not-a-host"},
            413: {"description": "too-large"},
            429: {"description": "too-soon"},
            503: {"description": "unavailable"},
        },
    )
    async def report_host_events(
        request: Request,
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> HostEventsResponse:
        """A worker host reports things that happened on it, for the bus's event log.

        One to twenty events, at most 16 KB, at most once every five seconds.
        Each event is a fixed type with a few checked fields; the bus stores no
        free text from a host. An event id is stored once, so sending a batch
        again after a lost answer makes no duplicate.
        """

        body = await request.body()
        try:
            stored = await asyncio.to_thread(
                request.app.state.event_log.record_from_host, agent.id, agent.name, body,
            )
        except (DomainValidationError, StorageError) as error:
            raise _report_refusal(error) from None
        return HostEventsResponse(stored=stored)

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
