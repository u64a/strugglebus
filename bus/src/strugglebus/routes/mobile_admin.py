"""Operator management from an enrolled device.

The owner chose to let an enrolled, granted device do what the console does:
list agents, devices and service principals, and unblock, retire, rotate and
revoke them. These restore or mint authority, which the containment
confirmations in ``routes/mobile.py`` never do, so they follow the device
enrollment routes instead: the per-device write grant, released on the device
by user presence, is the authorisation, and every write is audited as
``device:<label>``.

Each write names the exact target the owner was shown - its identifier, name
and version - and is refused if any of the three no longer matches, the same
binding the console's control form uses. Lists are operator-class reads and
need only the device credential, like every other monitor read.
"""

from __future__ import annotations

import asyncio
import functools
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import Response

from strugglebus import __version__, audit_feed, server_log
from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    ConfigurationError,
    CredentialConflictError,
    CredentialLimitError,
    CredentialNotFoundError,
    DomainValidationError,
    ServicePrincipalNotFoundError,
    StorageError,
)
from strugglebus.models import Agent, LifecycleActor, MobileIdentity, ServicePrincipal
from strugglebus.site_documents import decode_document
from strugglebus.store._host_enrollment import HostEnrollmentRecord
from strugglebus.routes.dependencies import _secret_response_headers
from strugglebus.routes.schemas import (
    MobileAdminActionOption,
    MobileAdminControlResponse,
    MobileAgentControlRequest,
    MobileGrantRequest,
    MobileHostHistoryResponse,
    MobileHostMarkRequest,
    MobileHostsResponse,
    MobileHostStatus,
    MobileLogEntry,
    MobileLogResponse,
    MobileManagedAgentResponse,
    MobileManagedDeviceResponse,
    MobileManagedServicePrincipalResponse,
    MobileServicePrincipalControlRequest,
    MobileSiteDocumentRequest,
    SiteDocumentResponse,
)

#: What the owner reads before approving. Written as the effect, not the verb.
AGENT_ACTION_EFFECTS = {
    "block": (
        "Block this agent. It loses access immediately; history, keys and "
        "cursors are kept, and it can be unblocked later."
    ),
    "unblock": (
        "Unblock this agent. Its existing credentials work again straight "
        "away."
    ),
    "retire": (
        "Retire this agent permanently. Its credentials are revoked, its name "
        "stays reserved, and it cannot be brought back; a replacement is a "
        "new agent with a new name."
    ),
}
_AGENT_ACTIONS_BY_STATE = {
    "enabled": ("block", "retire"),
    "blocked": ("unblock", "retire"),
}

SPN_ACTION_EFFECTS = {
    "block": (
        "Block this service principal. It can no longer onboard agents until "
        "it is unblocked. Agents it already onboarded are not changed."
    ),
    "unblock": "Unblock this service principal. It can onboard agents again.",
    "rotate": (
        "Replace this service principal's credential. The current secret "
        "stops working and the new one is shown once."
    ),
    "revoke": (
        "Revoke this service principal permanently. Its credential stops "
        "working and it cannot be restored. Agents it already onboarded are "
        "not changed."
    ),
}
_SPN_ACTIONS_BY_STATUS = {
    "enabled": ("block", "rotate", "revoke"),
    "blocked": ("unblock", "revoke"),
}

_DEVICE_REVOKE_EFFECT = (
    "Permanently revoke this device. Its read credential and write grant both "
    "stop working immediately, and the label can never be reused. Uses the "
    "revoke-device confirmation."
)


def _timestamp(value: object) -> datetime | None:
    return datetime.fromisoformat(value) if isinstance(value, str) else None


def _options(actions: tuple[str, ...], effects: dict[str, str]) -> list[MobileAdminActionOption]:
    return [MobileAdminActionOption(action=action, effect=effects[action]) for action in actions]


def _agent_response(agent: Agent) -> MobileManagedAgentResponse:
    return MobileManagedAgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        host=agent.host,
        state=agent.state,
        credential_epoch=agent.credential_epoch,
        created_at=agent.created_at,
        last_seen_at=agent.last_seen_at,
        blocked_at=agent.blocked_at,
        retired_at=agent.revoked_at,
        actions=_options(_AGENT_ACTIONS_BY_STATE.get(agent.state, ()), AGENT_ACTION_EFFECTS),
    )


def _spn_response(
    principal: ServicePrincipal, host: HostEnrollmentRecord | None = None,
) -> MobileManagedServicePrincipalResponse:
    return MobileManagedServicePrincipalResponse(
        host_redeem_request_id=None if host is None else host.redeem_request_id,
        host_redeemed_from=None if host is None else host.redeemed_from,
        host_redeemed_at=None if host is None else host.redeemed_at,
        id=principal.id,
        name=principal.name,
        agent_name_prefix=principal.agent_name_prefix,
        status=principal.status,
        version=principal.version,
        created_at=principal.created_at,
        blocked_at=principal.blocked_at,
        revoked_at=principal.revoked_at,
        actions=_options(_SPN_ACTIONS_BY_STATUS.get(principal.status, ()), SPN_ACTION_EFFECTS),
    )


def _document_subject(row: dict[str, object]) -> str | None:
    if row["document"] is None:
        return None
    return f"{row['document']} serial {row['serial']}"


def _audit_subject(row: dict[str, object]) -> str | None:
    """What an audit row is about: the first of these it has."""

    candidates = (
        row["agent_name"], row["spn_id"], row["agent_id"], row["credential_id"],
        row["host_prefix"], _document_subject(row),
    )
    return next((str(value) for value in candidates if value), None)


def _audit_entry(row: dict[str, object]) -> MobileLogEntry:
    moment = datetime.fromisoformat(str(row["ts"]))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)

    actor = ":".join(str(part) for part in (row["actor_type"], row["actor_id"]) if part)
    return MobileLogEntry(
        ts=moment,
        source="audit",
        level="info",
        event=str(row["event"]),
        subject=_audit_subject(row),
        actor=actor or None,
        status=None,
        remote_address=None,
        detail=str(row["table"]).removesuffix("_audit").replace("_", " "),
    )


def _failure(error: Exception) -> HTTPException:
    if isinstance(error, CredentialNotFoundError):
        # Raised by the device revalidation: the device or its credential died
        # between the grant check and the write.
        return HTTPException(status_code=401, detail=str(error))
    if isinstance(error, (AgentNotFoundError, ServicePrincipalNotFoundError)):
        return HTTPException(status_code=404, detail=str(error))
    if isinstance(error, (CredentialConflictError, CredentialLimitError)):
        return HTTPException(
            status_code=409,
            detail="The target changed or a limit was reached. Reload the list "
            "before trying again.",
        )
    if isinstance(error, (ConfigurationError, DomainValidationError)):
        return HTTPException(status_code=422, detail=str(error))
    if isinstance(error, AgentAccessFrozenError):
        return HTTPException(
            status_code=503,
            detail="agent access is frozen; this action restores or creates "
            "access and is refused until the freeze is cleared",
        )
    if isinstance(error, StorageError):
        return HTTPException(status_code=503, detail=str(error))
    raise error


_CONTROL_ERRORS = (
    AgentAccessFrozenError, AgentNotFoundError, ConfigurationError,
    CredentialConflictError, CredentialLimitError, CredentialNotFoundError,
    DomainValidationError, ServicePrincipalNotFoundError, StorageError,
)

_CONTROL_RESPONSES = {
    401: {"description": "Write grant or device is not valid"},
    404: {"description": "Target not found"},
    409: {"description": "Target changed since it was listed"},
    422: {"description": "Action is not valid for this target"},
    503: {"description": "Agent access is frozen"},
}


def add_mobile_admin_routes(router: APIRouter) -> None:
    def _identity(request: Request) -> MobileIdentity:
        identity = getattr(request.state, "mobile_identity", None)
        if identity is None:
            raise HTTPException(
                status_code=401,
                detail="mobile authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return identity

    async def _require_write_grant(
        request: Request, identity: MobileIdentity, grant_secret: str
    ) -> None:
        if not await asyncio.to_thread(
            request.app.state.mobile_service.verify_write_grant,
            device_id=identity.device_id,
            secret=grant_secret,
        ):
            raise HTTPException(
                status_code=401, detail="write grant is not valid for this device"
            )

    def _device_actor(request: Request, identity: MobileIdentity) -> LifecycleActor:
        service = request.app.state.mobile_service
        checking = False

        def still_live() -> None:
            # Runs under the writer lock, so a device revoked after the grant
            # check cannot land the write. The store re-validates the actor on
            # every transaction of an operator operation, including the reads
            # below, so the check must not re-enter itself.
            nonlocal checking
            if checking:
                return
            checking = True
            try:
                if not service.authorize_device(identity.credential_id):
                    raise CredentialNotFoundError(
                        "device credential is no longer active"
                    )
                if not service.device_is_enabled(identity.device_id):
                    raise CredentialNotFoundError("device is no longer enabled")
            finally:
                checking = False

        return LifecycleActor(
            actor_type="remote-admin",
            actor_id=f"device:{identity.device_label}",
            revalidate=still_live,
        )

    async def _operator_operation(request: Request, actor: LifecycleActor, function):
        store = request.app.state.agent_service.store

        def run():
            token = store.begin_operator_operation(actor)
            try:
                return function()
            finally:
                store.end_operator_operation(token)

        return await asyncio.to_thread(run)

    # ---- Worker hosts ----------------------------------------------------

    def _hosts(request: Request, *, admin: bool) -> MobileHostsResponse:
        service = request.app.state.host_status_service
        return MobileHostsResponse(
            now=service.now(),
            hosts=[
                MobileHostStatus(
                    agent_id=host.agent_id, agent=host.agent, marked_at=host.marked_at,
                    received_at=host.received_at, snapshot=host.snapshot,
                )
                for host in service.latest(admin=admin)
            ],
        )

    @router.get("/api/mobile/hosts/status", response_model=MobileHostsResponse)
    async def mobile_hosts_status(request: Request) -> MobileHostsResponse:
        """What every worker host last reported, for any enrolled device.

        The account a host runs as, whether that account is its own, its
        warnings and its channel are left out: those are for an administrator,
        on ``POST /api/mobile/admin/hosts/status``.
        """

        _identity(request)
        try:
            return await asyncio.to_thread(_hosts, request, admin=False)
        except StorageError as error:
            raise HTTPException(status_code=503, detail=str(error)) from None

    @router.post("/api/mobile/admin/hosts/status", response_model=MobileHostsResponse)
    async def mobile_admin_hosts_status(
        request: Request, payload: MobileGrantRequest, response: Response,
    ) -> MobileHostsResponse:
        """What every worker host last reported, whole, for an administrator.

        A read, sent as a POST so the grant travels in the body and never in an
        address or a header that a log might keep.
        """

        identity = _identity(request)
        await _require_write_grant(request, identity, payload.grant_secret)
        _secret_response_headers(response)
        try:
            return await asyncio.to_thread(_hosts, request, admin=True)
        except StorageError as error:
            raise HTTPException(status_code=503, detail=str(error)) from None

    @router.get(
        "/api/mobile/hosts/{agent_id}/status/history",
        response_model=MobileHostHistoryResponse,
        responses={404: {"description": "Not a marked worker host"}},
    )
    async def mobile_host_history(
        request: Request,
        agent_id: str,
        since: Annotated[datetime | None, Query()] = None,
    ) -> MobileHostHistoryResponse:
        """Up to twelve hours of one host's samples, oldest first, for charts."""

        _identity(request)
        if since is not None and since.tzinfo is None:
            raise HTTPException(status_code=422, detail="since must name its time zone")
        service = request.app.state.host_status_service
        try:
            samples = await asyncio.to_thread(service.history, agent_id, since)
        except StorageError as error:
            raise HTTPException(status_code=503, detail=str(error)) from None
        if samples is None:
            raise HTTPException(status_code=404, detail="not a worker host")
        return MobileHostHistoryResponse(now=service.now(), agent_id=agent_id, samples=samples)

    @router.post(
        "/api/mobile/admin/agents/{agent_id}/host",
        response_model=MobileAdminControlResponse,
        responses=_CONTROL_RESPONSES,
    )
    async def mobile_admin_host_mark(
        request: Request,
        agent_id: str,
        payload: MobileHostMarkRequest,
        response: Response,
    ) -> MobileAdminControlResponse:
        """Mark an agent as a worker host, or take the mark away.

        Only a marked agent may report host status and host events. A host
        enrolled with a host code is marked by the bus when it registers; this
        is for a host enrolled before that, and for one that is a host no
        longer. Taking the mark away also removes its stored status. Both work
        during a freeze: the mark lets a machine report, and gives it no access.
        """

        identity = _identity(request)
        await _require_write_grant(request, identity, payload.grant_secret)
        actor = _device_actor(request, identity)
        store = request.app.state.agent_service.store
        marked = payload.action == "mark"

        def run():
            return store.set_host_mark(
                agent_id, marked=marked, expected_name=payload.expected_name,
                reason=payload.reason, request_id=payload.request_id, actor=actor,
                changed_at=datetime.now(UTC),
            )

        try:
            name, applied = await _operator_operation(request, actor, run)
        except _CONTROL_ERRORS as error:
            raise _failure(error) from None
        _secret_response_headers(response)
        state = "a worker host" if marked else "not a worker host"
        return MobileAdminControlResponse(
            action=payload.action, target_id=agent_id, target_label=name,
            applied=applied, state=state,
            detail=f"Agent is now {state}." if applied else f"Nothing changed. Agent is {state}.",
        )

    # ---- Lists -----------------------------------------------------------

    @router.get(
        "/api/mobile/admin/agents",
        response_model=list[MobileManagedAgentResponse],
    )
    async def mobile_admin_agents(
        request: Request,
        state: Annotated[
            str, Query(pattern="^(managed|enabled|blocked|retired|all)$")
        ] = "managed",
        after: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 200,
    ) -> list[MobileManagedAgentResponse]:
        """The managed roster by name, with the actions each state allows.

        Unlike ``/api/mobile/agents`` this includes blocked and retired
        agents. ``after`` is the last name of the previous page.
        """

        _identity(request)
        try:
            agents = await asyncio.to_thread(
                functools.partial(
                    request.app.state.agent_service.list_managed_agents,
                    state=state, after_name=after, limit=limit,
                    require_access=False,
                )
            )
        except DomainValidationError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return [_agent_response(agent) for agent in agents]

    @router.get(
        "/api/mobile/admin/devices",
        response_model=list[MobileManagedDeviceResponse],
    )
    async def mobile_admin_devices(request: Request) -> list[MobileManagedDeviceResponse]:
        """Every enrolled device, including revoked ones, by label."""

        identity = _identity(request)
        devices = await asyncio.to_thread(request.app.state.mobile_service.list_devices)
        return [
            MobileManagedDeviceResponse(
                id=str(device["id"]),
                label=str(device["label"]),
                status=str(device["status"]),
                created_at=_timestamp(device["created_at"]),
                last_seen_at=_timestamp(device["last_seen_at"]),
                revoked_at=_timestamp(device["revoked_at"]),
                has_write_grant=int(device["active_write_grants"]) > 0,
                this_device=device["id"] == identity.device_id,
                actions=(
                    [MobileAdminActionOption(action="revoke-device", effect=_DEVICE_REVOKE_EFFECT)]
                    if device["status"] == "enabled" else []
                ),
            )
            for device in devices
        ]

    @router.get(
        "/api/mobile/admin/service-principals",
        response_model=list[MobileManagedServicePrincipalResponse],
    )
    async def mobile_admin_service_principals(
        request: Request,
    ) -> list[MobileManagedServicePrincipalResponse]:
        _identity(request)
        principals = await asyncio.to_thread(request.app.state.spn_service.list)
        hosts = await asyncio.to_thread(
            request.app.state.host_enrollment_service.records,
        )
        return [_spn_response(principal, hosts.get(principal.id)) for principal in principals]

    # ---- Logs ------------------------------------------------------------

    @router.get("/api/mobile/admin/logs", response_model=MobileLogResponse)
    async def mobile_admin_logs(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
    ) -> MobileLogResponse:
        """Recent bus activity, newest first, for diagnosing from a device.

        Committed audit rows come from their tables and survive a restart.
        Request and server lines are held in memory since the last start,
        whose time is ``started_at`` (null when the server is not running
        under ``strugglebus serve``).
        """

        _identity(request)
        store = request.app.state.agent_service.store
        audit = await asyncio.to_thread(audit_feed.recent, store, limit)
        entries = [_audit_entry(row) for row in audit]
        entries += [MobileLogEntry(**entry) for entry in server_log.RECENT.recent(limit)]
        entries.sort(key=lambda entry: entry.ts, reverse=True)
        installed = server_log.RECENT in server_log.AUDIT_LOGGER.handlers
        return MobileLogResponse(
            version=__version__,
            started_at=server_log.RECENT.started_at if installed else None,
            entries=entries[:limit],
        )

    # ---- Site documents --------------------------------------------------

    @router.get(
        "/api/mobile/site-documents/{name}",
        response_model=SiteDocumentResponse,
        responses={404: {"description": "Nothing has been published under that name"}},
    )
    async def mobile_site_document(request: Request, name: str) -> SiteDocumentResponse:
        """The site's signed document as it is stored. The bus has not verified it."""

        _identity(request)
        try:
            document = await asyncio.to_thread(
                request.app.state.site_document_service.read, name,
            )
        except ConfigurationError:
            document = None
        if document is None:
            raise HTTPException(status_code=404, detail="no such document")
        return SiteDocumentResponse.from_domain(document)

    @router.post(
        "/api/mobile/site-documents/{name}",
        response_model=SiteDocumentResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"description": "Write grant or device is not valid"},
            409: {"description": "The serial is not higher than the stored one"},
            422: {"description": "Not a valid document, signature or name"},
        },
    )
    async def mobile_publish_site_document(
        request: Request, name: str, payload: MobileSiteDocumentRequest,
    ) -> SiteDocumentResponse:
        """Publish a signed document, replacing the stored one.

        The bus stores the bytes and the signature and checks neither. It
        refuses a serial that does not rise, which guards against a mistake;
        the check that matters is each host's own. Allowed while agent access
        is frozen, so a fleet can be changed during an incident.
        """

        identity = _identity(request)
        await _require_write_grant(request, identity, payload.grant_secret)
        actor = _device_actor(request, identity)
        service = request.app.state.site_document_service

        def run():
            return service.publish(
                name=name, serial=payload.serial, body=decode_document(payload.body),
                signature=payload.signature,
                signer_fingerprint=payload.signer_fingerprint,
                reason=payload.reason, actor=actor,
            )

        try:
            document = await _operator_operation(request, actor, run)
        except CredentialNotFoundError as error:
            raise HTTPException(status_code=401, detail=str(error)) from None
        except CredentialConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from None
        except (ConfigurationError, DomainValidationError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        except StorageError as error:
            raise HTTPException(status_code=503, detail=str(error)) from None
        return SiteDocumentResponse.from_domain(document)

    # ---- Agent control ---------------------------------------------------

    @router.post(
        "/api/mobile/admin/agents/{agent_id}/control",
        response_model=MobileAdminControlResponse,
        responses=_CONTROL_RESPONSES,
    )
    async def mobile_admin_agent_control(
        request: Request,
        agent_id: str,
        payload: MobileAgentControlRequest,
        response: Response,
    ) -> MobileAdminControlResponse:
        """Block, unblock or retire an agent.

        Blocking and retiring narrow access and work during a freeze.
        Unblocking restores it and is refused until the freeze is cleared.
        Issuing a reconnect package stays on the console: the reconnect
        grant table accepts only a console operator as its issuer.
        """

        identity = _identity(request)
        await _require_write_grant(request, identity, payload.grant_secret)
        actor = _device_actor(request, identity)
        service = request.app.state.agent_service

        def run():
            agent = service.get_managed_agent(agent_id, require_access=False)
            if agent.name != payload.expected_name:
                raise CredentialConflictError("agent name does not match")
            result = service.transition_agent(
                agent_id, action=payload.action,
                expected_credential_epoch=payload.expected_credential_epoch,
                request_id=payload.request_id, reason=payload.reason, actor=actor,
            )
            return agent, result.changed, result.event.resulting_state

        try:
            agent, applied, state = await _operator_operation(request, actor, run)
        except _CONTROL_ERRORS as error:
            raise _failure(error) from None
        _secret_response_headers(response)
        return MobileAdminControlResponse(
            action=payload.action, target_id=agent.id, target_label=agent.name,
            applied=applied, state=state,
            detail=(
                f"Agent is now {state}." if applied
                else f"This request was already applied. Agent is {state}."
            ),
        )

    # ---- Service principal control ---------------------------------------

    @router.post(
        "/api/mobile/admin/service-principals/{spn_id}/control",
        response_model=MobileAdminControlResponse,
        responses=_CONTROL_RESPONSES,
    )
    async def mobile_admin_service_principal_control(
        request: Request,
        spn_id: str,
        payload: MobileServicePrincipalControlRequest,
        response: Response,
    ) -> MobileAdminControlResponse:
        """Block, unblock, rotate or revoke a service principal."""

        identity = _identity(request)
        await _require_write_grant(request, identity, payload.grant_secret)
        actor = _device_actor(request, identity)
        service = request.app.state.spn_service

        def run():
            current = next(
                (principal for principal in service.list() if principal.id == spn_id),
                None,
            )
            if current is None:
                raise ServicePrincipalNotFoundError("service principal does not exist")
            if current.name != payload.expected_name:
                raise CredentialConflictError("service principal name does not match")
            if payload.action == "rotate":
                issued = service.rotate(
                    spn_id, expected_version=payload.expected_version,
                    request_id=payload.request_id, reason=payload.reason, actor=actor,
                )
                secret = issued.secret if issued.secret_issued else None
                return issued.principal, issued.secret_issued, secret
            principal = service.transition(
                spn_id, action=payload.action,
                expected_version=payload.expected_version,
                request_id=payload.request_id, reason=payload.reason, actor=actor,
            )
            return principal, True, None

        try:
            principal, applied, secret = await _operator_operation(request, actor, run)
        except _CONTROL_ERRORS as error:
            raise _failure(error) from None
        _secret_response_headers(response)
        if payload.action == "rotate":
            detail = (
                "Credential replaced. Copy the new secret now; it is not shown "
                "again and the old one no longer works."
                if applied else
                "This rotation already happened. The secret cannot be shown "
                "again; rotate once more if it was lost."
            )
        else:
            detail = f"Service principal is now {principal.status}."
        return MobileAdminControlResponse(
            action=payload.action, target_id=principal.id, target_label=principal.name,
            applied=applied, state=principal.status, detail=detail,
            secret=secret,
            secret_kind="service-principal-credential" if secret else None,
        )
