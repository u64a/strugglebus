"""REST router assembly and the request-body middleware."""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import UTC, datetime
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

from strugglebus.auth import (
    parse_enrollment_token,
    parse_host_enrollment_token,
    parse_mobile_enrollment_token,
    parse_spn_enrollment_token,
)
from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    CredentialNotFoundError,
    RoeAcknowledgementRequiredError,
    StorageError,
)
from strugglebus.dashboard import (
    DASHBOARD_STYLESHEET_PATH,
    dashboard_headers,
)
from strugglebus.models import LifecycleActor
from strugglebus.operator_auth import (
    CHALLENGE_COOKIE, SESSION_COOKIE, OperatorAuthError, OperatorCapacityError,
    operator_cookie,
)
from strugglebus.operator_web import add_operator_routes
from strugglebus import capabilities
from strugglebus.audit_feed import emit as emit_audit, request_line
from strugglebus.satellite import SITE_CERT_HEADER, site_fingerprint
from strugglebus.routes.agents import add_agent_routes, add_reconnect_routes
from strugglebus.routes.console import add_console_routes
from strugglebus.routes.dependencies import AdminVerifier as AdminVerifier
from strugglebus.routes.devices import add_device_routes
from strugglebus.routes.health import add_health_routes
from strugglebus.routes.hosts import add_host_routes
from strugglebus.routes.join import add_join_routes
from strugglebus.routes.messages import add_message_routes
from strugglebus.routes.mobile import add_mobile_routes
from strugglebus.routes.mobile_admin import add_mobile_admin_routes
from strugglebus.routes.roe import add_roe_routes
from strugglebus.routes.satellite import add_satellite_routes
from strugglebus.routes.sites import add_site_routes
from strugglebus.routes.schemas import (
    AgentResponse as AgentResponse,
    CredentialResponse as CredentialResponse,
    EffectiveRoeResponse as EffectiveRoeResponse,
    MessageResponse as MessageResponse,
    OrientationResponse as OrientationResponse,
    PostRequestId as PostRequestId,
    RedeemedEnrollmentResponse as RedeemedEnrollmentResponse,
    RoeAcknowledgementResponse as RoeAcknowledgementResponse,
    WhoAmIResponse as WhoAmIResponse,
)
from strugglebus.routes.streams import (
    LeasedStreamingResponse as LeasedStreamingResponse,
    add_stream_routes,
)


def create_api_router() -> APIRouter:
    router = APIRouter()
    add_health_routes(router)
    add_agent_routes(router)
    add_roe_routes(router)
    add_message_routes(router)
    add_stream_routes(router)
    add_mobile_routes(router)
    add_mobile_admin_routes(router)
    add_console_routes(router)
    add_device_routes(router)
    add_site_routes(router)
    add_satellite_routes(router)
    add_reconnect_routes(router)
    add_host_routes(router)
    add_operator_routes(router)
    add_join_routes(router)
    return router


_HUMAN_VIEW_PATHS = frozenset(
    {"/", "/activity", "/channels", "/agents", "/register", "/system"}
)
_PUBLIC_PATHS = frozenset({
    "/healthz", "/openapi.json",
    "/.well-known/oauth-protected-resource/mcp",
    # Fetched by an agent that has no credential yet; see routes/join.py.
    "/join.sh", "/join.ps1",
    # The public certificate root. A PC needs it before its browser trusts
    # this bus, which is before anyone can sign in; the person checks its
    # fingerprint against the one the installer printed.
    "/ca-root.crt",
})
HUMAN_FORM_MAX_BYTES = 8 * 1024
_AUDITED_CAPABILITIES = frozenset({
    capabilities.ADMIN, capabilities.ENROLLMENT, capabilities.RECONNECT,
    capabilities.SPN_ONBOARDING, capabilities.MOBILE_ENROLLMENT,
    capabilities.HOST_ENROLLMENT,
})
_AUDITED_REFUSALS = frozenset({401, 403, 429})

# The plane a request belongs to decides which gates apply to it.
_PLANE_REST = "rest"
_PLANE_MCP = "mcp"
_PLANE_CONSOLE = "console"
_PLANE_CONSOLE_ASSET = "console-asset"
_PLANE_PUBLIC = "public"

_SAFE_METHODS = frozenset({"GET", "HEAD"})
_OPERATOR_SESSION_ROUTES = frozenset({"/login", "/logout", "/setup"})
_FORM_CONTENT_TYPES = frozenset({
    b"application/x-www-form-urlencoded",
    b"application/x-www-form-urlencoded;charset=utf-8",
})
_JSON_CONTENT_TYPES = (
    [b"application/json"], [b"application/json;charset=utf-8"],
)


def _request_plane(path: str) -> str:
    if path.startswith("/api/"):
        return _PLANE_REST
    if path == "/mcp" or path.startswith("/mcp/"):
        return _PLANE_MCP
    if path == DASHBOARD_STYLESHEET_PATH:
        return _PLANE_CONSOLE_ASSET
    if path in _PUBLIC_PATHS:
        return _PLANE_PUBLIC
    # Everything else is the operator console, including unknown paths, so
    # an unrecognised page is never served without an operator session.
    return _PLANE_CONSOLE


def _header_values(scope: dict[str, Any], name: bytes) -> list[bytes]:
    """Every value sent for one header, in order; ``name`` is lowercase."""

    return [
        value for key, value in scope.get("headers", ()) if key.lower() == name
    ]


def _content_types(scope: dict[str, Any]) -> list[bytes]:
    return [
        value.lower().replace(b" ", b"")
        for value in _header_values(scope, b"content-type")
    ]


def _is_json_request(scope: dict[str, Any]) -> bool:
    return _content_types(scope) in _JSON_CONTENT_TYPES


async def _send_error(
    send: Any,
    status_code: int,
    detail: str,
    *,
    retry_after: int | None = None,
    www_authenticate: bool = False,
) -> None:
    body = json.dumps(
        {"detail": detail},
        separators=(",", ":"),
    ).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if retry_after is not None:
        headers.append(
            (b"retry-after", str(retry_after).encode("ascii"))
        )
    if www_authenticate:
        headers.append((b"www-authenticate", b"Bearer"))
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": headers,
        }
    )
    await send({"type": "http.response.body", "body": body})


@dataclasses.dataclass(slots=True)
class _RequestContext:
    """What the middleware has established about one request so far."""

    scope: dict[str, Any]
    receive: Any
    send: Any
    state: Any
    path: str
    plane: str
    # The address limits and lockouts are keyed on. Becomes ``site:<id>``
    # once an admitted satellite site is identified.
    source: str
    host: bytes = b""
    site: str | None = None
    token: str | None = None
    capability: str | None = None

    @property
    def is_console(self) -> bool:
        return self.plane in {_PLANE_CONSOLE, _PLANE_CONSOLE_ASSET}

    @property
    def is_safe_method(self) -> bool:
        return self.scope["method"] in _SAFE_METHODS

    @property
    def request_state(self) -> dict[str, Any]:
        """The per-request state handlers read the admitted identity from."""

        return self.scope.setdefault("state", {})


@dataclasses.dataclass(frozen=True, slots=True)
class _AgentAdmission:
    """Which standing gate, if any, an admitted request stays subject to.

    An operational agent request holds a rules-of-engagement receipt; a
    bootstrap request holds only a live credential. Enrollment and admin
    requests hold neither.
    """

    receipt_identity: Any = None
    bootstrap_identity: Any = None


class _ResponseGuard:
    """Re-check the caller's authority at the moment the response starts.

    A handler can run for a while. If the authority that admitted the
    request was withdrawn meanwhile, the handler's response is discarded
    and a refusal is sent in its place.
    """

    def __init__(self, send: Any) -> None:
        self._send = send
        self.started = False
        self.denied = False

    async def _refusal(self) -> tuple[int, str] | None:
        raise NotImplementedError

    async def send(self, message: dict[str, Any]) -> None:
        if self.denied:
            return
        if message["type"] == "http.response.start":
            refusal = await self._refusal()
            if refusal is not None:
                self.denied = True
                await _send_error(self._send, *refusal)
                return
            self.started = True
        await self._send(message)


class _OperatorSessionGuard(_ResponseGuard):
    """The operator's session must still be active when the page is sent."""

    def __init__(self, send: Any, authority: Any, context: Any) -> None:
        super().__init__(send)
        self._authority = authority
        self._context = context

    async def _refusal(self) -> tuple[int, str] | None:
        if self._context is None:
            return None
        try:
            self._authority.require_active(self._context)
        except OperatorAuthError:
            return 401, "operator session is unavailable"
        except StorageError:
            return 503, "service is unavailable"
        return None


class _AgentIdentityGuard(_ResponseGuard):
    """The agent's receipt or bootstrap credential must still stand."""

    def __init__(self, send: Any, state: Any, admission: _AgentAdmission) -> None:
        super().__init__(send)
        self._state = state
        self._admission = admission

    async def _recheck(self) -> None:
        receipt = self._admission.receipt_identity
        bootstrap = self._admission.bootstrap_identity
        if receipt is not None:
            await asyncio.to_thread(
                self._state.roe_service.require_current_receipt,
                receipt.agent.id, receipt.credential.id,
            )
        elif bootstrap is not None:
            await asyncio.to_thread(
                self._state.agent_service.require_live_identity,
                bootstrap.agent.id, bootstrap.credential.id,
            )

    async def _refusal(self) -> tuple[int, str] | None:
        try:
            await self._recheck()
        except RoeAcknowledgementRequiredError:
            return 428, "current rules of engagement receipt required"
        except (AgentNotFoundError, CredentialNotFoundError):
            return 401, "agent credential is unavailable"
        except (AgentAccessFrozenError, StorageError):
            return 503, "agent access is unavailable"
        return None


class _ReconnectIdentityGuard(_ResponseGuard):
    """A credential issued by a reconnect must be live before it is sent."""

    def __init__(self, send: Any, state: Any, scope: dict[str, Any]) -> None:
        super().__init__(send)
        self._state = state
        self._scope = scope

    async def _refusal(self) -> tuple[int, str] | None:
        issued_identity = self._scope.get("state", {}).get("reconnect_identity")
        if issued_identity is None:
            return None
        try:
            await asyncio.to_thread(
                self._state.agent_service.require_live_identity, *issued_identity,
            )
        except (AgentNotFoundError, CredentialNotFoundError):
            return 401, "reconnect credential is unavailable"
        except (AgentAccessFrozenError, StorageError):
            return 503, "agent access is unavailable"
        return None


class _SpnIdentityGuard(_ResponseGuard):
    """The service principal must still be active and access unfrozen."""

    def __init__(
        self, send: Any, state: Any, scope: dict[str, Any], identity: Any,
    ) -> None:
        super().__init__(send)
        self._state = state
        self._scope = scope
        self._identity = identity

    async def _refusal(self) -> tuple[int, str] | None:
        # A self-rotation revokes the credential that authorized it,
        # so its response is guarded by the successor instead.
        successor = self._scope["state"].get("spn_rotated_to")
        checked = self._identity if successor is None else dataclasses.replace(
            self._identity, credential_id=successor,
        )
        try:
            active, freeze = await asyncio.gather(
                asyncio.to_thread(
                    self._state.spn_service.identity_is_active, checked,
                ),
                asyncio.to_thread(self._state.access_freeze_service.status),
            )
        except StorageError:
            return 503, "service principal access is unavailable"
        if freeze.frozen:
            return 503, "agent access is frozen"
        if not active:
            return 401, "service principal credential is unavailable"
        return None


class _BodyTooLarge(Exception):
    """More request body arrived than the route accepts."""


def _declared_content_length(scope: dict[str, Any]) -> int | None:
    """The single Content-Length a request declares, or None for none.

    Raises ValueError for a repeated, non-decimal or unparseably long value.
    """

    lengths = _header_values(scope, b"content-length")
    if len(lengths) > 1:
        raise ValueError("repeated content length")
    if not lengths:
        return None
    if re.fullmatch(rb"[0-9]+", lengths[0]) is None:
        raise ValueError("content length is not decimal")
    return int(lengths[0])


async def _read_body(receive: Any, max_bytes: int) -> bytes | None:
    """Read a whole body up to a hard cap; None when the client went away."""

    body = bytearray()
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None
        body.extend(message.get("body", b""))
        if len(body) > max_bytes:
            raise _BodyTooLarge
        if not message.get("more_body", False):
            return bytes(body)


def _replay_body(body: bytes) -> Any:
    """An ASGI receive that delivers a buffered body once, then disconnects."""

    delivered = False

    async def replay() -> dict[str, Any]:
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }

    return replay


class RequestBodyLimitMiddleware:
    """Authenticate, rate-limit, then bounded-buffer REST request bodies.

    Every request passes through ``_handle``, which applies the gates in a
    fixed order:

    1. Classify the path. Public paths pass straight through.
    2. Require exactly one approved Host header (421).
    3. Admit an asserted satellite site, which reaches agent routes only.
    4. Hand the request to its plane:

       - console: source limit, operator setup/configuration, session
         authentication, login redirect; for a form post additionally the
         login admission, origin, content type and a bounded, timed body.
       - console asset: source limit only.
       - MCP: agent authentication and its per-credential limit.
       - REST: default-deny on an undeclared capability, the site
         capability restriction, then the gate of the route's capability
         (service principal, satellite, mobile, reconnect, enrollment,
         mobile enrollment, admin or agent) and a bounded body.
    """

    def __init__(self, app: Any, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self._capabilities = capabilities.build_resolver()

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        status = 0

        async def recording_send(message: dict[str, Any]) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self._handle(scope, receive, recording_send)
        finally:
            self._audit_request(scope, status)

    def _is_lifecycle_request(self, method: str, path: str) -> bool:
        template = self._capabilities.template(method, path)
        if self._capabilities.resolve(method, path) in _AUDITED_CAPABILITIES:
            return True
        return template is not None and (
            template.startswith("/api/credentials/")
            # A signed host command is carried, not interpreted. That it was
            # sent, and from where, is still worth a line.
            or template == "/api/mobile/hosts/commands"
        )

    def _audit_template(self, method: str, path: str) -> str:
        """The route template to record, never the raw path of a miss."""

        template = self._capabilities.template(method, path)
        if template is not None:
            return template
        return "/mcp" if _request_plane(path) == _PLANE_MCP else "other"

    def _audit_request(self, scope: dict[str, Any], status: int) -> None:
        """Feed lifecycle requests and every refused login to the SIEM."""

        path = scope.get("path", "")
        method = scope.get("method", "")
        lifecycle = self._is_lifecycle_request(method, path)
        if not status or not (lifecycle or status in _AUDITED_REFUSALS):
            return
        state = scope["app"].state
        headers = {key.lower(): value for key, value in scope.get("headers", ())}
        identity = scope.get("state", {}).get("spn_identity")
        emit_audit(
            request_line(
                ts=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                event=f"{method} {self._audit_template(method, path)}",
                status=status,
                remote_address=self._source_address(
                    scope, headers, state.config.trusted_proxy_sources,
                ),
                spn_id=getattr(identity, "spn_id", None),
            ),
        )

    async def _handle(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        path = scope.get("path", "")
        plane = _request_plane(path)
        if plane == _PLANE_PUBLIC:
            await self.app(scope, receive, send)
            return
        state = scope["app"].state
        headers = {
            key.lower(): value
            for key, value in scope.get("headers", ())
        }
        request = _RequestContext(
            scope=scope, receive=receive, send=send, state=state, path=path,
            plane=plane,
            source=self._source_address(
                scope, headers, state.config.trusted_proxy_sources,
            ),
        )
        if not await self._require_approved_host(request):
            return
        if not await self._admit_satellite_site(request):
            return
        if plane == _PLANE_CONSOLE:
            await self._handle_console(request)
        elif plane == _PLANE_CONSOLE_ASSET:
            await self._handle_console_asset(request)
        elif plane == _PLANE_MCP:
            await self._handle_mcp(request)
        else:
            await self._handle_rest(request)

    # -- gates shared by every plane ------------------------------------

    async def _require_approved_host(self, request: _RequestContext) -> bool:
        host_values = _header_values(request.scope, b"host")
        if len(host_values) != 1 or not self._host_allowed(
            host_values[0],
            request.state.config.allowed_hosts,
        ):
            await self._error(request.send, 421, "unapproved request host")
            return False
        request.host = host_values[0]
        return True

    async def _admit_satellite_site(self, request: _RequestContext) -> bool:
        """Identify and admit a site asserted by the satellite proxy."""

        state, send = request.state, request.send
        site_values = _header_values(
            request.scope, SITE_CERT_HEADER.encode("ascii"),
        )
        if not site_values:
            return True
        # Arrived through the satellite path. A site reaches the agent
        # plane only, and only while the operator has not revoked it.
        site = site_fingerprint(site_values[0]) if len(site_values) == 1 else None
        # Only the satellite proxy may assert a site. Its requests all come
        # from the gateway's tunnel address; a LAN client cannot, because
        # replies to that address go back into the tunnel.
        if request.source != state.config.satellite_gateway_wg_address:
            site = None
        if request.is_console or site is None:
            await self._error(send, 403, "satellite sites reach agent routes only")
            return False
        try:
            admitted = await asyncio.to_thread(state.satellite_service.admits, site)
        except StorageError:
            await self._error(send, 503, "service is unavailable")
            return False
        if not admitted:
            await self._error(send, 403, "satellite site is not admitted")
            return False
        # Every site arrives from the gateway's tunnel address, so the site
        # itself is what source limits and lockouts must tell apart.
        request.site = site
        request.source = f"site:{site}"
        return True

    async def _refuse_source(
        self,
        request: _RequestContext,
        status_code: int,
        detail: str,
        *,
        www_authenticate: bool = False,
    ) -> None:
        """Refuse an unauthenticated caller, counting it against its source.

        A source already over its limit gets the 429 instead of the refusal.
        """

        if not await self._limit_source(request.state, request.source, request.send):
            return
        await self._error(
            request.send, status_code, detail, www_authenticate=www_authenticate,
        )

    async def _require_unfrozen(
        self, request: _RequestContext, *, unavailable: str, frozen: str,
    ) -> bool:
        """Refuse with 503 while agent access is frozen or cannot be read."""

        try:
            freeze = await asyncio.to_thread(
                request.state.access_freeze_service.status
            )
        except StorageError:
            await self._error(request.send, 503, unavailable)
            return False
        if freeze.frozen:
            await self._error(request.send, 503, frozen)
            return False
        return True

    async def _bounded_receive_in_time(
        self, request: _RequestContext, max_bytes: int, timeout_detail: str,
    ) -> Any | None:
        """Buffer a small body against the operator form deadline."""

        try:
            async with asyncio.timeout(
                request.state.config.operator_form_timeout_seconds
            ):
                return await self._bounded_receive(
                    request.receive, request.send, max_bytes, request.scope,
                )
        except TimeoutError:
            await self._error(request.send, 408, timeout_detail)
            return None

    # -- the operator console -------------------------------------------

    async def _handle_console(self, request: _RequestContext) -> None:
        scope, state = request.scope, request.state
        if not await self._limit_source(state, request.source, request.send):
            return
        # The console is deliberately NOT denied while frozen. A freeze
        # stops the agent plane; the operator plane is how the incident
        # gets contained, and blacking it out meant the freeze prevented
        # the very revocation it exists to enable. Credential creation
        # stays denied inside the storage layer, for every actor type.
        authority = state.operator_auth
        route = request.path.rstrip("/")
        if not await self._require_operator_plane(request, authority, route):
            return
        context = authority.authenticate(
            operator_cookie(scope.get("headers", []), SESSION_COOKIE)
        )
        request.request_state["operator_source"] = request.source
        scope["state"]["operator_context"] = context
        if route not in {"/login", "/setup"} and context is None:
            await self._demand_operator_login(request)
            return
        if request.is_safe_method:
            await self._dispatch_console(request, authority, context, route, request.receive)
            return
        form = await self._admit_operator_form(request, authority, route)
        if form is None:
            return
        await self._dispatch_console(request, authority, context, route, form)

    async def _require_operator_plane(
        self, request: _RequestContext, authority: Any, route: str,
    ) -> bool:
        """Operator sign-in must exist, or be in the middle of first setup."""

        if authority is not None and authority.setup_pending:
            # First use: only the setup page exists until a password is set.
            if route == "/setup":
                return True
            if request.is_safe_method:
                await RedirectResponse(
                    "/setup", status_code=303, headers=dashboard_headers(),
                )(request.scope, request.receive, request.send)
            else:
                await self._error(request.send, 503, "operator access is unavailable")
            return False
        if authority is None or not authority.configured:
            await self._error(request.send, 503, "operator access is unavailable")
            return False
        return True

    async def _demand_operator_login(self, request: _RequestContext) -> None:
        if request.is_safe_method:
            await RedirectResponse(
                "/login",
                status_code=303, headers=dashboard_headers(),
            )(request.scope, request.receive, request.send)
        else:
            await self._error(request.send, 401, "operator authentication required")

    async def _admit_operator_form(
        self, request: _RequestContext, authority: Any, route: str,
    ) -> Any | None:
        """Gate a console form post and return its buffered body.

        Order: login admission, then origin, then content type, and only
        then is any body read, against a size cap and a deadline.
        """

        if route == "/login" and not await self._admit_login_post(request, authority):
            return None
        if not self._operator_origin_approved(request):
            await self._error(request.send, 403, "operator origin rejected")
            return None
        types = _content_types(request.scope)
        if len(types) != 1 or types[0] not in _FORM_CONTENT_TYPES:
            await self._error(request.send, 415, "operator form content type required")
            return None
        return await self._bounded_receive_in_time(
            request, request.state.config.operator_form_bytes,
            "operator form timed out",
        )

    async def _admit_login_post(
        self, request: _RequestContext, authority: Any,
    ) -> bool:
        try:
            authority.require_challenge(
                operator_cookie(request.scope.get("headers", []), CHALLENGE_COOKIE)
            )
            authority.admit("login-body", request.source)
        except OperatorCapacityError:
            await self._error(request.send, 429, "operator request limit reached")
            return False
        except OperatorAuthError:
            await self._error(request.send, 401, "invalid operator login")
            return False
        return True

    @staticmethod
    def _operator_origin_approved(request: _RequestContext) -> bool:
        """A form post must come from the console's own HTTPS origin."""

        origin_values = _header_values(request.scope, b"origin")
        approved = request.state.config.public_base_url.rstrip("/")
        parsed_origin = urlsplit(approved)
        return not (
            parsed_origin.scheme != "https"
            or parsed_origin.username is not None
            or parsed_origin.password is not None
            or origin_values != [approved.encode("ascii")]
            or request.host.lower() != parsed_origin.netloc.encode("ascii").lower()
        )

    async def _dispatch_console(
        self,
        request: _RequestContext,
        authority: Any,
        context: Any,
        route: str,
        receive_request: Any,
    ) -> None:
        """Run a console handler as the signed-in operator.

        The sign-in pages themselves run without an operator actor, even
        when a session cookie happens to be present.
        """

        send = request.send
        actor_context = None if route in _OPERATOR_SESSION_ROUTES else context
        guard = _OperatorSessionGuard(send, authority, actor_context)
        tokens: list[tuple[Any, Any]] = []
        try:
            if actor_context is not None:
                self._begin_operator_operations(
                    request.state, authority, actor_context, tokens,
                )
            await self.app(request.scope, receive_request, guard.send)
        except (OperatorAuthError, AgentAccessFrozenError, StorageError) as error:
            if guard.started or guard.denied:
                raise
            await self._error(
                send, 401 if isinstance(error, OperatorAuthError) else 503,
                "operator access is unavailable",
            )
        finally:
            for store, operation in reversed(tokens):
                store.end_operator_operation(operation)

    @staticmethod
    def _begin_operator_operations(
        state: Any, authority: Any, context: Any, tokens: list[tuple[Any, Any]],
    ) -> None:
        """Mark every store as acting for this operator.

        Each begun operation is recorded in ``tokens`` as it starts, so the
        caller ends exactly those that began even if a later one refuses.
        """

        actor = LifecycleActor(
            "remote-admin", context.actor_id,
            lambda: authority.require_active(context),
        )
        for store in dict.fromkeys((
            state.agent_service.store, state.board_service.store,
            state.roe_service.store,
        )):
            tokens.append((store, store.begin_operator_operation(actor)))

    async def _handle_console_asset(self, request: _RequestContext) -> None:
        if not await self._limit_source(request.state, request.source, request.send):
            return
        await self.app(request.scope, request.receive, request.send)

    # -- the agent plane: MCP and REST ----------------------------------

    def _read_credential(self, request: _RequestContext) -> None:
        """Record the bearer token and the capability the route declares."""

        authorization_values = _header_values(request.scope, b"authorization")
        request.token = (
            self._bearer_token(authorization_values[0])
            if len(authorization_values) == 1
            else None
        )
        request.capability = self._capabilities.resolve(
            request.scope["method"], request.path,
        )

    async def _handle_mcp(self, request: _RequestContext) -> None:
        self._read_credential(request)
        identity = await self._authenticate_agent(request)
        if identity is None:
            return
        await self._dispatch_agent(request, _AgentAdmission(), request.receive)

    async def _handle_rest(self, request: _RequestContext) -> None:
        self._read_credential(request)
        capability = request.capability
        if capability is None:
            # Default-deny. A governed route that declares no capability is
            # refused rather than inheriting one, so a gating mistake cannot
            # fail open.
            await self._error(request.send, 403, "route declares no capability")
            return
        if request.site is not None and capability not in capabilities.SITE_CAPABILITIES:
            await self._error(
                request.send, 403, "satellite sites reach agent routes only",
            )
            return
        if capability == capabilities.SPN_ONBOARDING:
            await self._dispatch_spn(request)
        elif capability == capabilities.SATELLITE:
            await self._dispatch_satellite(request)
        elif capability in capabilities.MOBILE_CAPABILITIES:
            await self._dispatch_mobile(request)
        elif capability == capabilities.RECONNECT:
            await self._dispatch_reconnect(request)
        else:
            await self._dispatch_governed(request)

    async def _dispatch_governed(self, request: _RequestContext) -> None:
        """Admit an enrollment, admin or agent request, then bound its body."""

        admission = await self._admit_governed(request)
        if admission is None:
            return
        if request.is_safe_method:
            await self._dispatch_agent(request, admission, request.receive)
            return
        bounded = await self._bounded_receive(
            request.receive, request.send, self.max_bytes, request.scope,
        )
        if bounded is not None:
            await self._dispatch_agent(request, admission, bounded)

    async def _admit_governed(
        self, request: _RequestContext,
    ) -> _AgentAdmission | None:
        capability = request.capability
        if capability == capabilities.ENROLLMENT:
            admitted = await self._admit_enrollment(request)
        elif capability == capabilities.MOBILE_ENROLLMENT:
            admitted = await self._admit_mobile_enrollment(request)
        elif capability == capabilities.HOST_ENROLLMENT:
            admitted = await self._admit_host_enrollment(request)
        elif capability == capabilities.ADMIN:
            admitted = await self._admit_admin(request)
        else:
            return await self._admit_agent(request)
        return _AgentAdmission() if admitted else None

    async def _admit_enrollment(self, request: _RequestContext) -> bool:
        # The enrollment token is the only credential a self-registering
        # agent holds. Verify its shape and the freeze before any body is
        # read; the single-use allowance is consumed transactionally in the
        # handler so a malformed or replayed token never reaches storage.
        send, token = request.send, request.token
        if not await self._limit_source(request.state, request.source, send):
            return False
        if token is None:
            await self._error(
                send,
                401,
                "enrollment authentication required",
                www_authenticate=True,
            )
            return False
        if (
            parse_enrollment_token(token) is None
            and parse_spn_enrollment_token(token) is None
        ):
            await self._error(send, 401, "enrollment token is not valid")
            return False
        if not await self._require_unfrozen(
            request, unavailable="service is unavailable",
            frozen="agent access is frozen",
        ):
            return False
        request.request_state["enrollment_token"] = token
        return True

    async def _admit_mobile_enrollment(self, request: _RequestContext) -> bool:
        # A mobile allowance is the only credential an unenrolled device
        # holds. Shape and freeze are checked before any body is read; the
        # verifier and remaining use are checked again inside the
        # redemption transaction.
        send, token = request.send, request.token
        if not await self._limit_source(request.state, request.source, send):
            return False
        if token is None or parse_mobile_enrollment_token(token) is None:
            await self._error(
                send,
                401,
                "enrollment authentication required",
                www_authenticate=True,
            )
            return False
        if not await self._require_unfrozen(
            request, unavailable="service is unavailable",
            frozen="agent access is frozen",
        ):
            return False
        request.request_state["mobile_enrollment_token"] = token
        return True

    async def _admit_host_enrollment(self, request: _RequestContext) -> bool:
        # A host code is the only thing an unjoined worker host holds. The
        # source is rate limited, and the code's shape and the freeze are
        # checked, before any body is read. Whether the code is the right one
        # is decided inside the redemption transaction.
        send, token = request.send, request.token
        if not await self._limit_source(request.state, request.source, send):
            return False
        if token is None or parse_host_enrollment_token(token) is None:
            await self._error(
                send,
                401,
                "host code required",
                www_authenticate=True,
            )
            return False
        if not await self._require_unfrozen(
            request, unavailable="unavailable", frozen="unavailable",
        ):
            return False
        request.request_state["host_enrollment_token"] = token
        request.request_state["host_enrollment_source"] = request.source
        return True

    async def _admit_admin(self, request: _RequestContext) -> bool:
        state, token = request.state, request.token
        verifier = state.admin_verifier
        if token is None:
            await self._refuse_source(
                request, 401, "admin authentication required",
                www_authenticate=True,
            )
            return False
        if verifier is None or not verifier.verify(token):
            await self._refuse_source(request, 403, "admin credential rejected")
            return False
        if not await self._limit(
            state,
            f"admin:{request.source}",
            state.config.authenticated_requests_per_minute,
            request.send,
        ):
            return False
        if not await self._require_unfrozen(
            request, unavailable="service is unavailable",
            frozen="service is unavailable",
        ):
            return False
        request.request_state["admin_authenticated"] = True
        (
            request.scope["state"]["admin_credential_kind"],
            request.scope["state"]["admin_credential_id"],
        ) = verifier.credential_context
        return True

    async def _authenticate_agent(self, request: _RequestContext) -> Any | None:
        """Resolve the bearer token to an agent identity, or refuse."""

        state, send, token = request.state, request.send, request.token
        if token is None:
            await self._refuse_source(
                request, 401, "agent authentication required",
                www_authenticate=True,
            )
            return None
        try:
            identity = await asyncio.to_thread(
                state.agent_service.authorize,
                token,
            )
        except AgentAccessFrozenError:
            await self._error(send, 503, "agent access is frozen")
            return None
        except StorageError:
            await self._error(send, 503, "agent access is unavailable")
            return None
        if identity is None:
            await self._refuse_source(
                request, 401, "invalid agent credential", www_authenticate=True,
            )
            return None
        if not await self._limit(
            state,
            f"credential:{identity.credential.id}",
            state.config.authenticated_requests_per_minute,
            send,
        ):
            return None
        request.request_state["authenticated_agent"] = identity.agent
        request.scope["state"]["authenticated_identity"] = identity
        request.scope["state"]["credential_kind"] = identity.credential.kind
        request.scope["state"]["credential_id"] = identity.credential.id
        return identity

    async def _admit_agent(
        self, request: _RequestContext,
    ) -> _AgentAdmission | None:
        """Authenticate an agent for a REST route and apply its standing gate.

        Bootstrap routes need only a live credential. Every other route
        needs a proved credential and a current rules-of-engagement receipt.
        """

        identity = await self._authenticate_agent(request)
        if identity is None:
            return None
        if request.capability == capabilities.AGENT_BOOTSTRAP:
            return _AgentAdmission(bootstrap_identity=identity)
        if identity.credential.status == "pending":
            await self._error(
                request.send,
                403,
                "credential identity proof required",
            )
            return None
        try:
            await asyncio.to_thread(
                request.state.roe_service.require_current_receipt,
                identity.agent.id,
                identity.credential.id,
            )
        except RoeAcknowledgementRequiredError:
            await self._error(
                request.send,
                428,
                "current rules of engagement receipt required",
            )
            return None
        return _AgentAdmission(receipt_identity=identity)

    async def _dispatch_agent(
        self,
        request: _RequestContext,
        admission: _AgentAdmission,
        receive_request: Any,
    ) -> None:
        """Run the handler while holding the admission's standing gate."""

        state, send = request.state, request.send
        receipt = admission.receipt_identity
        bootstrap_identity = admission.bootstrap_identity
        token = (
            state.roe_service.begin_operational(
                receipt.agent.id,
                receipt.credential.id,
            )
            if receipt is not None
            else None
        )
        bootstrap = (
            state.agent_service.begin_bootstrap(
                bootstrap_identity.agent.id, bootstrap_identity.credential.id,
            ) if bootstrap_identity is not None else None
        )
        guard = _AgentIdentityGuard(send, state, admission)
        try:
            await self.app(request.scope, receive_request, guard.send)
        except (
            RoeAcknowledgementRequiredError, AgentNotFoundError,
            CredentialNotFoundError, AgentAccessFrozenError,
        ) as error:
            if guard.started or guard.denied:
                raise
            await self._refuse_withdrawn_agent(send, error)
        finally:
            state.roe_service.end_operational(token)
            if bootstrap is not None:
                state.agent_service.end_bootstrap(bootstrap)

    async def _refuse_withdrawn_agent(self, send: Any, error: Exception) -> None:
        """Answer a handler that found the agent's authority withdrawn."""

        if isinstance(error, RoeAcknowledgementRequiredError):
            await self._error(
                send,
                428,
                "current rules of engagement receipt required",
            )
            return
        await self._error(
            send, 503 if isinstance(error, AgentAccessFrozenError) else 401,
            "agent access is unavailable",
        )

    async def _dispatch_satellite(self, request: _RequestContext) -> None:
        # The admitted site certificate is the whole authority here, so
        # these routes exist only on the satellite path.
        state, send, site = request.state, request.send, request.site
        if site is None:
            await self._error(send, 403, "satellite path required")
            return
        if not await self._limit(
            state, f"site:{site}", state.config.authenticated_requests_per_minute, send,
        ):
            return
        request.request_state["satellite_site"] = site
        bounded = await self._bounded_receive(request.receive, send, 8192, request.scope)
        if bounded is not None:
            await self.app(request.scope, bounded, send)

    async def _dispatch_reconnect(self, request: _RequestContext) -> None:
        scope, state, send = request.scope, request.state, request.send
        if not await self._verify_reconnect_grant(request):
            return
        if not _is_json_request(scope):
            await self._error(send, 415, "reconnect JSON content type required")
            return
        request.request_state["reconnect_token"] = request.token
        bounded = await self._bounded_receive_in_time(
            request, min(2048, state.config.operator_form_bytes),
            "reconnect request timed out",
        )
        if bounded is None:
            return
        guard = _ReconnectIdentityGuard(send, state, scope)
        await self.app(scope, bounded, guard.send)

    async def _verify_reconnect_grant(self, request: _RequestContext) -> bool:
        state, send, token = request.state, request.send, request.token
        try:
            state.operator_auth.admit("reconnect-redeem", request.source)
            frozen = await asyncio.to_thread(state.access_freeze_service.status)
            if frozen.frozen:
                raise AgentAccessFrozenError("agent access is frozen")
            grant = (
                None if token is None
                else await asyncio.to_thread(state.agent_service.verify_reconnect, token)
            )
        except OperatorCapacityError:
            await self._error(send, 429, "reconnect request limit reached")
            return False
        except (AgentAccessFrozenError, StorageError):
            await self._error(send, 503, "agent access is unavailable")
            return False
        if grant is None:
            await self._error(send, 401, "reconnect grant is unavailable")
            return False
        return True

    async def _authenticate_spn(self, request: _RequestContext) -> Any | None:
        state, send, token = request.state, request.send, request.token
        if token is None:
            await self._refuse_source(
                request, 401, "service principal authentication required",
                www_authenticate=True,
            )
            return None
        try:
            identity = await asyncio.to_thread(state.spn_service.authorize, token)
        except StorageError:
            await self._error(send, 503, "service principal access is unavailable")
            return None
        if identity is None:
            await self._refuse_source(
                request, 401, "invalid service principal credential",
                www_authenticate=True,
            )
            return None
        if not await self._limit(
            state,
            f"spn:{identity.spn_id}",
            state.config.spn_issues_per_minute,
            send,
        ):
            return None
        return identity

    async def _dispatch_spn(self, request: _RequestContext) -> None:
        scope, state, send = request.scope, request.state, request.send
        identity = await self._authenticate_spn(request)
        if identity is None:
            return
        if not await self._require_unfrozen(
            request, unavailable="service principal access is unavailable",
            frozen="agent access is frozen",
        ):
            return
        if not _is_json_request(scope):
            await self._error(send, 415, "SPN onboarding JSON content type required")
            return
        request.request_state["spn_identity"] = identity
        bounded = await self._bounded_receive(request.receive, send, 4096, scope)
        if bounded is None:
            return
        guard = _SpnIdentityGuard(send, state, scope, identity)
        await self.app(scope, bounded, guard.send)

    @staticmethod
    async def _bounded_receive(
        receive: Any,
        send: Any,
        max_bytes: int,
        scope: dict[str, Any],
    ) -> Any | None:
        """Buffer a request body to a hard cap, or reject and return None."""

        try:
            declared = _declared_content_length(scope)
        except ValueError:
            await _send_error(send, 400, "invalid content length")
            return None
        if declared is not None and declared > max_bytes:
            await RequestBodyLimitMiddleware._reject(send)
            return None
        try:
            body = await _read_body(receive, max_bytes)
        except _BodyTooLarge:
            await RequestBodyLimitMiddleware._reject(send)
            return None
        if body is None:
            return None
        if declared is not None and declared != len(body):
            await _send_error(send, 400, "invalid content length")
            return None
        return _replay_body(body)

    @staticmethod
    async def _reject(send: Any) -> None:
        await _send_error(send, 413, "request body too large")

    @staticmethod
    def _bearer_token(value: bytes | None) -> str | None:
        if value is None:
            return None
        try:
            scheme, token = value.decode("latin-1").split(" ", 1)
        except ValueError:
            return None
        if scheme.lower() != "bearer" or not token:
            return None
        return token

    @staticmethod
    def _source_address(
        scope: dict[str, Any],
        headers: dict[bytes, bytes],
        trusted_sources: tuple[str, ...],
    ) -> str:
        client = scope.get("client")
        direct = client[0] if client is not None else "unknown"
        if direct not in trusted_sources:
            return direct
        forwarded = headers.get(b"x-forwarded-for")
        if forwarded is None:
            return direct
        candidate = forwarded.decode("latin-1").rsplit(",", 1)[-1].strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return direct

    @staticmethod
    def _host_allowed(value: bytes, allowed_hosts: tuple[str, ...]) -> bool:
        try:
            host = value.decode("ascii").lower()
        except UnicodeDecodeError:
            return False
        for pattern in allowed_hosts:
            candidate = pattern.lower()
            if candidate.endswith(":*") and (
                host == candidate[:-2] or host.startswith(f"{candidate[:-2]}:")
            ):
                return True
            if host == candidate:
                return True
        return False

    @staticmethod
    async def _limit_source(state: Any, source: str, send: Any) -> bool:
        return await RequestBodyLimitMiddleware._limit(
            state,
            f"source:{source}",
            state.config.unauthenticated_requests_per_minute,
            send,
        )

    @staticmethod
    async def _limit(
        state: Any,
        key: str,
        limit: int,
        send: Any,
    ) -> bool:
        allowed, retry_after = state.rate_limiter.allow(key, limit)
        if allowed:
            return True
        await _send_error(
            send,
            429,
            "request rate limit exceeded",
            retry_after=retry_after,
        )
        return False

    async def _authenticate_mobile(self, request: _RequestContext) -> Any | None:
        state, send, token = request.state, request.send, request.token
        if token is None:
            await self._refuse_source(
                request, 401, "mobile authentication required",
                www_authenticate=True,
            )
            return None
        service = getattr(state, "mobile_service", None)
        if service is None:
            await self._error(send, 503, "mobile access is unavailable")
            return None
        try:
            identity = await asyncio.to_thread(service.authorize, token)
        except StorageError:
            await self._error(send, 503, "mobile access is unavailable")
            return None
        if identity is None:
            await self._refuse_source(
                request, 401, "invalid mobile credential", www_authenticate=True,
            )
            return None
        if not await self._limit(
            state,
            f"mobile:{identity.credential_id}",
            state.config.authenticated_requests_per_minute,
            send,
        ):
            return None
        return identity

    async def _dispatch_mobile(self, request: _RequestContext) -> None:
        """Authenticate a mobile monitor and apply its own gates.

        A monitor holds no coordination authority, so the agent proof and
        rules-of-engagement gates are meaningless for it and are not applied.
        That exemption is a property of the principal, expressed here once,
        rather than a path prefix that would silently cover any route added
        under it later.
        """

        state = request.state
        identity = await self._authenticate_mobile(request)
        if identity is None:
            return
        try:
            frozen = await asyncio.to_thread(state.access_freeze_service.status)
        except StorageError:
            await self._error(request.send, 503, "mobile access is unavailable")
            return
        # Reads stay available while frozen. The freeze stops the agent plane;
        # the monitor is how the owner watches an incident, and denying it data
        # means watching blind. ``status`` still reports ``state=frozen``, so
        # the state is unmistakable and a frozen board can never be mistaken
        # for an empty one. Enrollment redemption is a separate capability and
        # remains denied, so nothing that grants access is created while
        # frozen.
        #
        # Containment writes reach their routes while frozen too. Blocking an
        # agent, revoking a device and clearing the freeze are the responses to
        # the incident a freeze is declared for, so a freeze that blocked them
        # would be the control preventing its own use. The one write that
        # creates authority - establishing a grant - is refused inside its own
        # write transaction rather than here, so the check cannot be bypassed
        # by a later route being added under the same capability.
        request.request_state["mobile_identity"] = identity
        request.scope["state"]["mobile_frozen"] = frozen.frozen
        await self.app(request.scope, request.receive, request.send)

    _error = staticmethod(_send_error)
