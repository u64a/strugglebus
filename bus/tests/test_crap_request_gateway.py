"""The request gateway, driven directly as an ASGI middleware.

Every request to the server passes through ``RequestBodyLimitMiddleware``.
These tests stand it on a scripted world of collaborators so that each gate
can be made to refuse on its own, and they record the order in which the
collaborators are consulted: the order of the checks is part of the contract.

This file holds the harness and covers what every plane shares, plus the
operator console. ``test_crap_request_agent_plane.py`` covers MCP and REST.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest

from strugglebus.api import RequestBodyLimitMiddleware
from strugglebus.dashboard import DASHBOARD_STYLESHEET_PATH, dashboard_headers
from strugglebus.errors import AgentAccessFrozenError, StorageError
from strugglebus.operator_auth import (
    CHALLENGE_COOKIE,
    SESSION_COOKIE,
    OperatorAuthError,
    OperatorCapacityError,
)
from strugglebus.satellite import SITE_CERT_HEADER

CLIENT = "192.0.2.7"
PROXY = "10.0.0.1"
GATEWAY = "10.9.0.1"
SITE = "ab" * 32
SESSION = "s" * 43
CHALLENGE = "c" * 43
ORIGIN = "https://bus.lan"
FORM = "application/x-www-form-urlencoded"


class World:
    """Scripted collaborators that record every check made against them."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._counts: dict[str, int] = {}
        self._failures: dict[tuple[str, int | None], BaseException] = {}
        self.limited: set[str] = set()
        self.frozen = False
        self.admitted_sites = {SITE}
        self.sessions = {SESSION: SimpleNamespace(actor_id="operator-1")}
        self.agents: dict[str, Any] = {}
        self.receipts: set[tuple[str, str]] = set()
        self.reconnect_grants: set[str] = set()
        self.principals: dict[str, Any] = {}
        self.active_principals: set[str] = set()
        self.devices: dict[str, Any] = {}
        self.admin_tokens = {"admin-secret"}

    def fail(self, step: str, error: BaseException, *, call: int | None = None) -> None:
        """Make ``step`` raise, every time or only on its ``call``-th use."""

        self._failures[(step, call)] = error

    def step(self, name: str) -> None:
        self.calls.append(name)
        count = self._counts[name] = self._counts.get(name, 0) + 1
        error = self._failures.get((name, count)) or self._failures.get((name, None))
        if error is not None:
            raise error

    def steps(self, *prefixes: str) -> list[str]:
        return [call for call in self.calls if call.startswith(prefixes)]


class _Limiter:
    def __init__(self, world: World) -> None:
        self._world = world

    def allow(self, key: str, limit: int) -> tuple[bool, int]:
        self._world.calls.append(f"limit {key} {limit}")
        return key not in self._world.limited, 7


class _Freeze:
    def __init__(self, world: World) -> None:
        self._world = world

    def status(self) -> Any:
        self._world.step("freeze")
        return SimpleNamespace(frozen=self._world.frozen)


class _Store:
    def __init__(self, world: World, name: str) -> None:
        self._world = world
        self.name = name
        self.actors: list[Any] = []

    def begin_operator_operation(self, actor: Any) -> str:
        self._world.step(f"begin-operator {self.name}")
        self.actors.append(actor)
        return f"operation-{self.name}"

    def end_operator_operation(self, operation: str) -> None:
        self._world.calls.append(f"end-operator {operation}")


class _Agents:
    def __init__(self, world: World, store: _Store) -> None:
        self._world = world
        self.store = store

    def authorize(self, token: str) -> Any:
        self._world.step("authorize")
        return self._world.agents.get(token)

    def verify_reconnect(self, token: str) -> Any:
        self._world.step("reconnect-verify")
        return "grant" if token in self._world.reconnect_grants else None

    def require_live_identity(self, agent_id: str, credential_id: str) -> None:
        self._world.step(f"live {agent_id} {credential_id}")

    def begin_bootstrap(self, agent_id: str, credential_id: str) -> str:
        self._world.step(f"begin-bootstrap {agent_id} {credential_id}")
        return "bootstrap-lease"

    def end_bootstrap(self, lease: str) -> None:
        self._world.calls.append(f"end-bootstrap {lease}")


class _Roe:
    def __init__(self, world: World, store: _Store) -> None:
        self._world = world
        self.store = store

    def require_current_receipt(self, agent_id: str, credential_id: str) -> None:
        self._world.step("receipt")
        if (agent_id, credential_id) not in self._world.receipts:
            from strugglebus.errors import RoeAcknowledgementRequiredError

            raise RoeAcknowledgementRequiredError("receipt required")

    def begin_operational(self, agent_id: str, credential_id: str) -> str:
        self._world.step(f"begin-operational {agent_id} {credential_id}")
        return "operational-lease"

    def end_operational(self, lease: str | None) -> None:
        self._world.calls.append(f"end-operational {lease}")


class _Principals:
    def __init__(self, world: World) -> None:
        self._world = world
        self.checked: list[Any] = []

    def authorize(self, token: str) -> Any:
        self._world.step("spn-authorize")
        return self._world.principals.get(token)

    def identity_is_active(self, identity: Any) -> bool:
        self._world.step("spn-active")
        self.checked.append(identity)
        return identity.credential_id in self._world.active_principals


class _Devices:
    def __init__(self, world: World) -> None:
        self._world = world

    def authorize(self, token: str) -> Any:
        self._world.step("mobile-authorize")
        return self._world.devices.get(token)


class _Sites:
    def __init__(self, world: World) -> None:
        self._world = world

    def admits(self, site: str) -> bool:
        self._world.step(f"site-admits {site}")
        return site in self._world.admitted_sites


class _AdminVerifier:
    credential_context = ("admin-token", "admin-credential-1")

    def __init__(self, world: World) -> None:
        self._world = world

    def verify(self, token: str) -> bool:
        self._world.step("admin-verify")
        return token in self._world.admin_tokens


class _Authority:
    def __init__(self, world: World) -> None:
        self._world = world
        self.setup_pending = False
        self.configured = True

    def authenticate(self, token: str | None) -> Any:
        self._world.step("session")
        return self._world.sessions.get(token)

    def require_active(self, context: Any) -> None:
        self._world.step("session-active")

    def require_challenge(self, token: str | None) -> None:
        self._world.step("login-challenge")
        if token != CHALLENGE:
            raise OperatorAuthError("no challenge")

    def admit(self, scope: str, source: str) -> None:
        self._world.step(f"admit {scope} {source}")


class Handler:
    """The application behind the gateway; records what reached it."""

    def __init__(self, world: World) -> None:
        self._world = world
        self.reached = False
        self.state: dict[str, Any] = {}
        self.received: list[dict[str, Any]] = []
        self.reads = 1
        self.before_response: Any = None
        self.error: BaseException | None = None
        self.error_after_start: BaseException | None = None

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.reached = True
        self._world.calls.append("handler")
        self.state = dict(scope.get("state", {}))
        if scope["type"] != "http":
            return
        for _ in range(self.reads):
            self.received.append(await receive())
        if self.before_response is not None:
            self.before_response(scope)
        if self.error is not None:
            raise self.error
        await send({"type": "http.response.start", "status": 200, "headers": []})
        if self.error_after_start is not None:
            raise self.error_after_start
        await send({"type": "http.response.body", "body": b"handled"})

    @property
    def body(self) -> bytes:
        return b"".join(message.get("body", b"") for message in self.received)


class Reply:
    def __init__(self, sent: list[dict[str, Any]]) -> None:
        self.sent = sent
        starts = [m for m in sent if m["type"] == "http.response.start"]
        # A refusal replaces the handler's response; it never follows it.
        assert len(starts) <= 1, sent
        self.status = starts[0]["status"] if starts else None
        self.headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in (starts[0]["headers"] if starts else [])
        }
        self.body = b"".join(
            m.get("body", b"") for m in sent if m["type"] == "http.response.body"
        )

    @property
    def detail(self) -> str:
        return json.loads(self.body)["detail"]

    @property
    def refusal(self) -> tuple[int | None, str]:
        return self.status, self.detail


class Gateway:
    def __init__(self, *, max_bytes: int = 32) -> None:
        self.world = World()
        world = self.world
        self.handler = Handler(world)
        self.authority = _Authority(world)
        self.stores = [_Store(world, name) for name in ("agents", "board", "roe")]
        self.principals = _Principals(world)
        self.config = SimpleNamespace(
            trusted_proxy_sources=(PROXY,),
            allowed_hosts=("bus.lan", "console.lan:*"),
            satellite_gateway_wg_address=GATEWAY,
            public_base_url="https://bus.lan/",
            operator_form_timeout_seconds=5,
            operator_form_bytes=16,
            authenticated_requests_per_minute=600,
            unauthenticated_requests_per_minute=30,
            spn_issues_per_minute=6,
        )
        self.state = SimpleNamespace(
            config=self.config,
            rate_limiter=_Limiter(world),
            access_freeze_service=_Freeze(world),
            agent_service=_Agents(world, self.stores[0]),
            board_service=SimpleNamespace(store=self.stores[1]),
            roe_service=_Roe(world, self.stores[2]),
            spn_service=self.principals,
            mobile_service=_Devices(world),
            satellite_service=_Sites(world),
            admin_verifier=_AdminVerifier(world),
            operator_auth=self.authority,
        )
        self.middleware = RequestBodyLimitMiddleware(self.handler, max_bytes=max_bytes)

    async def call(
        self,
        method: str,
        path: str,
        *,
        headers: tuple[tuple[str, str | bytes], ...] = (),
        body: bytes = b"",
        messages: list[dict[str, Any]] | None = None,
        host: str | bytes | None = "bus.lan",
        client: tuple[str, int] | None = (CLIENT, 4000),
        token: str | None = None,
        scope_type: str = "http",
    ) -> Reply:
        raw: list[tuple[bytes, bytes]] = []
        if host is not None:
            raw.append((b"Host", host if isinstance(host, bytes) else host.encode()))
        if token is not None:
            raw.append((b"authorization", f"Bearer {token}".encode()))
        for key, value in headers:
            raw.append((key.encode(), value if isinstance(value, bytes) else value.encode()))
        scope = {
            "type": scope_type, "method": method, "path": path, "headers": raw,
            "client": client, "app": SimpleNamespace(state=self.state),
        }
        pending = (
            [{"type": "http.request", "body": body, "more_body": False}]
            if messages is None else list(messages)
        )

        async def receive() -> dict[str, Any]:
            if pending:
                return pending.pop(0)
            await asyncio.Event().wait()  # the client sends nothing more
            raise AssertionError("unreachable")

        sent: list[dict[str, Any]] = []

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        self.scope = scope
        await self.middleware(scope, receive, send)
        return Reply(sent)

    async def site_call(self, method: str, path: str, **kwargs: Any) -> Reply:
        """A request relayed by the satellite proxy on behalf of ``SITE``."""

        headers = ((SITE_CERT_HEADER, SITE), *kwargs.pop("headers", ()))
        kwargs.setdefault("client", (GATEWAY, 4000))
        return await self.call(method, path, headers=headers, **kwargs)

    async def console(self, method: str, path: str, **kwargs: Any) -> Reply:
        """A console request carrying a valid operator session cookie."""

        headers = (("cookie", f"{SESSION_COOKIE}={SESSION}"), *kwargs.pop("headers", ()))
        return await self.call(method, path, headers=headers, **kwargs)

    async def form(self, path: str, **kwargs: Any) -> Reply:
        """A well-formed same-origin console form post from the operator."""

        headers = (
            ("origin", ORIGIN), ("content-type", FORM), *kwargs.pop("headers", ()),
        )
        kwargs.setdefault("body", b"csrf=1")
        return await self.console("POST", path, headers=headers, **kwargs)


@pytest.fixture
def gateway() -> Gateway:
    return Gateway()


# -- classification and the gates every plane shares ----------------------


@pytest.mark.parametrize(
    "path",
    ["/healthz", "/openapi.json", "/join.sh", "/join.ps1", "/ca-root.crt",
     "/.well-known/oauth-protected-resource/mcp"],
)
async def test_public_paths_pass_straight_through_without_any_gate(
    gateway: Gateway, path: str,
) -> None:
    # Not even the Host check applies: a PC fetches the CA root and the join
    # script before it knows this bus by an approved name.
    reply = await gateway.call("GET", path, host="anything.example")

    assert reply.status == 200
    assert gateway.world.calls == ["handler"]


async def test_non_http_scopes_are_not_inspected(gateway: Gateway) -> None:
    reply = await gateway.call("GET", "/activity", scope_type="lifespan", host=None)

    assert gateway.handler.reached
    assert reply.sent == []
    assert gateway.world.calls == ["handler"]


@pytest.mark.parametrize("path", ["/activity", "/api/channels", "/mcp", DASHBOARD_STYLESHEET_PATH])
@pytest.mark.parametrize(
    "hosts",
    [
        (),
        ("evil.example",),
        ("bus.lan", "bus.lan"),
        ("bus.lan:8443",),
        ("console.lanx",),
        (b"bus.lan\xff",),
    ],
)
async def test_an_unapproved_host_is_refused_before_anything_else(
    gateway: Gateway, path: str, hosts: tuple[str | bytes, ...],
) -> None:
    reply = await gateway.call(
        "GET", path, host=None, headers=tuple(("host", host) for host in hosts),
        token="anything",
    )

    assert reply.refusal == (421, "unapproved request host")
    assert reply.headers["cache-control"] == "no-store"
    assert reply.headers["content-type"] == "application/json"
    assert int(reply.headers["content-length"]) == len(reply.body)
    # No limiter, no authentication, no handler.
    assert gateway.world.calls == []


@pytest.mark.parametrize("host", ["BUS.LAN", "console.lan", "console.lan:8443", "Console.Lan:1"])
async def test_approved_hosts_match_case_insensitively_and_by_port_wildcard(
    gateway: Gateway, host: str,
) -> None:
    reply = await gateway.call("GET", DASHBOARD_STYLESHEET_PATH, host=host)

    assert reply.status == 200


@pytest.mark.parametrize(
    ("client", "forwarded", "expected"),
    [
        ((CLIENT, 1), None, CLIENT),
        # Only the configured proxy may speak for another address.
        ((CLIENT, 1), "203.0.113.9", CLIENT),
        ((PROXY, 1), None, PROXY),
        # The proxy appends the peer it saw, so the last hop is the truth.
        ((PROXY, 1), "198.51.100.1, 203.0.113.9", "203.0.113.9"),
        ((PROXY, 1), " 2001:DB8::1 ", "2001:db8::1"),
        ((PROXY, 1), "not-an-address", PROXY),
        (None, "203.0.113.9", "unknown"),
    ],
)
async def test_limits_are_keyed_on_the_address_only_the_trusted_proxy_may_forward(
    gateway: Gateway, client: tuple[str, int] | None, forwarded: str | None, expected: str,
) -> None:
    headers = () if forwarded is None else (("x-forwarded-for", forwarded),)

    await gateway.call("GET", DASHBOARD_STYLESHEET_PATH, client=client, headers=headers)

    assert gateway.world.calls == [f"limit source:{expected} 30", "handler"]


# -- satellite sites --------------------------------------------------------


@pytest.mark.parametrize("path", ["/activity", "/login", DASHBOARD_STYLESHEET_PATH])
async def test_a_satellite_site_never_reaches_the_console(gateway: Gateway, path: str) -> None:
    reply = await gateway.site_call("GET", path)

    assert reply.refusal == (403, "satellite sites reach agent routes only")
    # Refused before the site is even looked up, and before any console gate.
    assert gateway.world.calls == []


@pytest.mark.parametrize(
    ("client", "certificates"),
    [
        # Only the gateway's tunnel address may assert a site.
        ((CLIENT, 1), (SITE,)),
        ((PROXY, 1), (SITE,)),
        ((GATEWAY, 1), (SITE, SITE)),
        ((GATEWAY, 1), ("not-a-fingerprint",)),
        ((GATEWAY, 1), ("",)),
    ],
)
async def test_a_site_assertion_that_cannot_be_trusted_is_refused_not_ignored(
    gateway: Gateway, client: tuple[str, int], certificates: tuple[str, ...],
) -> None:
    reply = await gateway.call(
        "GET", "/api/channels", client=client, token="agent-key",
        headers=tuple((SITE_CERT_HEADER, value) for value in certificates),
    )

    assert reply.refusal == (403, "satellite sites reach agent routes only")
    assert gateway.world.calls == []


async def test_a_revoked_site_is_refused(gateway: Gateway) -> None:
    gateway.world.admitted_sites.clear()

    reply = await gateway.site_call("GET", "/api/channels", token="agent-key")

    assert reply.refusal == (403, "satellite site is not admitted")
    assert gateway.world.calls == [f"site-admits {SITE}"]


async def test_a_site_is_refused_when_its_admission_cannot_be_read(gateway: Gateway) -> None:
    gateway.world.fail(f"site-admits {SITE}", StorageError("disk"))

    reply = await gateway.site_call("GET", "/api/channels", token="agent-key")

    assert reply.refusal == (503, "service is unavailable")
    assert not gateway.handler.reached


async def test_an_admitted_site_is_limited_as_itself_not_as_the_shared_gateway(
    gateway: Gateway,
) -> None:
    reply = await gateway.site_call("GET", "/api/channels")

    assert reply.refusal == (401, "agent authentication required")
    assert gateway.world.calls == [f"site-admits {SITE}", f"limit source:site:{SITE} 30"]


# -- the operator console ---------------------------------------------------


async def test_console_requests_are_source_limited_before_operator_state_is_read(
    gateway: Gateway,
) -> None:
    gateway.world.limited.add(f"source:{CLIENT}")
    gateway.state.operator_auth = None

    reply = await gateway.console("GET", "/activity")

    assert reply.refusal == (429, "request rate limit exceeded")
    assert reply.headers["retry-after"] == "7"
    assert gateway.world.calls == [f"limit source:{CLIENT} 30"]


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("missing", ["authority", "credential"])
async def test_console_is_unavailable_without_a_configured_operator(
    gateway: Gateway, method: str, missing: str,
) -> None:
    if missing == "authority":
        gateway.state.operator_auth = None
    else:
        gateway.authority.configured = False

    reply = await gateway.console(method, "/activity")

    assert reply.refusal == (503, "operator access is unavailable")
    assert gateway.world.steps("session", "handler") == []


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("path", ["/", "/activity", "/login", "/operator/session"])
async def test_first_use_redirects_every_page_to_setup(
    gateway: Gateway, method: str, path: str,
) -> None:
    gateway.authority.setup_pending = True
    gateway.authority.configured = False

    reply = await gateway.console(method, path)

    assert reply.status == 303
    assert reply.headers["location"] == "/setup"
    for name, value in dashboard_headers().items():
        assert reply.headers[name.lower()] == value
    assert gateway.world.steps("session", "handler") == []


async def test_first_use_refuses_writes_to_anything_but_setup(gateway: Gateway) -> None:
    gateway.authority.setup_pending = True
    gateway.authority.configured = False

    reply = await gateway.form("/login")

    assert reply.refusal == (503, "operator access is unavailable")
    assert not gateway.handler.reached


@pytest.mark.parametrize("path", ["/setup", "/setup/"])
async def test_first_use_serves_the_setup_page_and_accepts_its_form(
    gateway: Gateway, path: str,
) -> None:
    gateway.authority.setup_pending = True
    gateway.authority.configured = False
    gateway.world.sessions.clear()

    page = await gateway.call("GET", path)
    posted = await gateway.call(
        "POST", path, headers=(("origin", ORIGIN), ("content-type", FORM)), body=b"password=x",
    )

    assert (page.status, posted.status) == (200, 200)
    assert gateway.handler.body == b"password=x"
    assert gateway.handler.state["operator_context"] is None


@pytest.mark.parametrize("method", ["GET", "HEAD"])
async def test_a_page_without_a_session_redirects_to_login(gateway: Gateway, method: str) -> None:
    reply = await gateway.call(method, "/activity")

    assert reply.status == 303
    assert reply.headers["location"] == "/login"
    for name, value in dashboard_headers().items():
        assert reply.headers[name.lower()] == value
    assert gateway.world.calls == [f"limit source:{CLIENT} 30", "session"]


@pytest.mark.parametrize("cookie", [None, f"{SESSION_COOKIE}={'x' * 43}"])
async def test_a_write_without_a_session_is_refused_before_its_body_is_read(
    gateway: Gateway, cookie: str | None,
) -> None:
    headers = [("origin", ORIGIN), ("content-type", FORM)]
    if cookie is not None:
        headers.append(("cookie", cookie))

    reply = await gateway.call("POST", "/register", headers=tuple(headers), messages=[])

    assert reply.refusal == (401, "operator authentication required")
    assert "www-authenticate" not in reply.headers
    assert not gateway.handler.reached


async def test_the_login_page_is_served_without_a_session(gateway: Gateway) -> None:
    reply = await gateway.call("GET", "/login/")

    assert reply.status == 200
    assert gateway.handler.state == {"operator_source": CLIENT, "operator_context": None}
    # No operator actor exists, so no store is told an operator is acting.
    assert gateway.world.steps("begin-operator", "session-active") == []


async def test_a_signed_in_page_runs_as_the_operator_in_every_store(gateway: Gateway) -> None:
    reply = await gateway.console("GET", "/activity")

    assert reply.status == 200
    assert reply.body == b"handled"
    context = gateway.world.sessions[SESSION]
    assert gateway.handler.state == {"operator_source": CLIENT, "operator_context": context}
    assert gateway.world.calls == [
        f"limit source:{CLIENT} 30",
        "session",
        "begin-operator agents",
        "begin-operator board",
        "begin-operator roe",
        "handler",
        # Re-checked at the moment the page is sent.
        "session-active",
        "end-operator operation-roe",
        "end-operator operation-board",
        "end-operator operation-agents",
    ]
    actor = gateway.stores[0].actors[0]
    assert (actor.actor_type, actor.actor_id) == ("remote-admin", "operator-1")
    actor.revalidate()
    assert gateway.world.calls[-1] == "session-active"


async def test_stores_shared_between_services_are_entered_once(gateway: Gateway) -> None:
    shared = gateway.stores[0]
    gateway.state.board_service.store = shared
    gateway.state.roe_service.store = shared

    await gateway.console("GET", "/activity")

    assert gateway.world.steps("begin-operator", "end-operator") == [
        "begin-operator agents", "end-operator operation-agents",
    ]


@pytest.mark.parametrize("path", ["/login", "/logout", "/setup"])
async def test_sign_in_pages_never_run_as_an_operator_even_with_a_session(
    gateway: Gateway, path: str,
) -> None:
    reply = await gateway.console("GET", path)

    assert reply.status == 200
    assert gateway.world.steps("begin-operator", "session-active") == []


@pytest.mark.parametrize(
    ("error", "refusal"),
    [
        (OperatorAuthError("revoked"), (401, "operator session is unavailable")),
        (StorageError("disk"), (503, "service is unavailable")),
    ],
)
async def test_a_page_is_withheld_when_the_session_ended_while_it_rendered(
    gateway: Gateway, error: Exception, refusal: tuple[int, str],
) -> None:
    gateway.world.fail("session-active", error)

    reply = await gateway.console("GET", "/activity")

    assert reply.refusal == refusal
    # The handler's own start and body were both discarded.
    assert b"handled" not in reply.body
    assert len(reply.sent) == 2
    assert gateway.world.steps("end-operator") == [
        "end-operator operation-roe", "end-operator operation-board",
        "end-operator operation-agents",
    ]


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (OperatorAuthError("revoked"), 401),
        (AgentAccessFrozenError("frozen"), 503),
        (StorageError("disk"), 503),
    ],
)
async def test_a_handler_that_loses_operator_authority_is_answered_with_a_refusal(
    gateway: Gateway, error: Exception, status: int,
) -> None:
    gateway.handler.error = error

    reply = await gateway.console("GET", "/activity")

    assert reply.refusal == (status, "operator access is unavailable")
    assert len(gateway.world.steps("end-operator")) == 3


async def test_a_failure_after_the_page_started_is_not_disguised_as_a_refusal(
    gateway: Gateway,
) -> None:
    gateway.handler.error_after_start = StorageError("disk")

    with pytest.raises(StorageError):
        await gateway.console("GET", "/activity")

    assert len(gateway.world.steps("end-operator")) == 3


async def test_a_store_that_refuses_the_operator_ends_only_what_began(gateway: Gateway) -> None:
    gateway.world.fail("begin-operator board", OperatorAuthError("revoked"))

    reply = await gateway.console("GET", "/activity")

    assert reply.refusal == (401, "operator access is unavailable")
    assert not gateway.handler.reached
    assert gateway.world.steps("end-operator") == ["end-operator operation-agents"]


# -- console form posts -----------------------------------------------------


async def test_a_form_post_is_gated_then_buffered_then_replayed_once(gateway: Gateway) -> None:
    gateway.handler.reads = 2

    reply = await gateway.form(
        "/register", body=b"csrf=1&name=a", headers=(("content-length", "13"),),
    )

    assert reply.status == 200
    assert gateway.handler.received == [
        {"type": "http.request", "body": b"csrf=1&name=a", "more_body": False},
        {"type": "http.disconnect"},
    ]
    # Only a login post consults the challenge and the login admission.
    assert gateway.world.steps("admit", "login") == []


async def test_a_login_post_needs_its_challenge_and_an_admission_slot(gateway: Gateway) -> None:
    gateway.world.sessions.clear()
    cookie = ("cookie", f"{CHALLENGE_COOKIE}={CHALLENGE}")

    reply = await gateway.call(
        "POST", "/login", body=b"password=x",
        headers=(cookie, ("origin", ORIGIN), ("content-type", FORM)),
    )

    assert reply.status == 200
    assert gateway.handler.body == b"password=x"
    assert gateway.world.calls == [
        f"limit source:{CLIENT} 30", "session", "login-challenge",
        f"admit login-body {CLIENT}", "handler",
    ]


async def test_a_login_post_without_a_challenge_is_refused_before_admission(
    gateway: Gateway,
) -> None:
    reply = await gateway.call(
        "POST", "/login", messages=[],
        headers=(("origin", ORIGIN), ("content-type", FORM)),
    )

    assert reply.refusal == (401, "invalid operator login")
    assert gateway.world.steps("admit", "handler") == []


async def test_a_login_post_over_capacity_is_refused_before_its_origin_is_judged(
    gateway: Gateway,
) -> None:
    gateway.world.fail(f"admit login-body {CLIENT}", OperatorCapacityError("busy"))

    reply = await gateway.call(
        "POST", "/login", messages=[],
        headers=(("cookie", f"{CHALLENGE_COOKIE}={CHALLENGE}"), ("origin", "https://evil.example")),
    )

    assert reply.refusal == (429, "operator request limit reached")
    assert "retry-after" not in reply.headers


@pytest.mark.parametrize(
    ("origins", "host", "base_url"),
    [
        ((), "bus.lan", "https://bus.lan"),
        (("https://evil.example",), "bus.lan", "https://bus.lan"),
        (("https://bus.lan", "https://bus.lan"), "bus.lan", "https://bus.lan"),
        (("https://bus.lan/",), "bus.lan", "https://bus.lan"),
        (("null",), "bus.lan", "https://bus.lan"),
        # The Host must be the published one, not merely an approved one.
        (("https://bus.lan",), "console.lan", "https://bus.lan"),
        # A console published over plain HTTP accepts no forms at all.
        (("http://bus.lan",), "bus.lan", "http://bus.lan"),
        (("https://user@bus.lan",), "user@bus.lan", "https://user@bus.lan"),
        (("https://user:pw@bus.lan",), "bus.lan", "https://user:pw@bus.lan"),
    ],
)
async def test_a_form_post_from_any_other_origin_is_refused_unread(
    gateway: Gateway, origins: tuple[str, ...], host: str, base_url: str,
) -> None:
    gateway.config.public_base_url = base_url
    gateway.config.allowed_hosts = ("bus.lan", "console.lan", "user@bus.lan")

    reply = await gateway.console(
        "POST", "/register", host=host, messages=[],
        headers=(*(("origin", origin) for origin in origins), ("content-type", "text/plain")),
    )

    # 403, not the 415 the content type alone would have earned.
    assert reply.refusal == (403, "operator origin rejected")
    assert not gateway.handler.reached


async def test_the_published_host_matches_case_insensitively(gateway: Gateway) -> None:
    gateway.config.public_base_url = "https://Bus.Lan"

    reply = await gateway.console(
        "POST", "/register", host="BUS.lan", body=b"csrf=1",
        headers=(("origin", "https://Bus.Lan"), ("content-type", FORM)),
    )

    assert reply.status == 200


@pytest.mark.parametrize(
    "types",
    [
        (),
        ("application/json",),
        ("multipart/form-data",),
        (FORM, FORM),
        (f"{FORM}; charset=latin-1",),
    ],
)
async def test_a_form_post_must_declare_exactly_one_form_content_type(
    gateway: Gateway, types: tuple[str, ...],
) -> None:
    reply = await gateway.console(
        "POST", "/register", messages=[],
        headers=(("origin", ORIGIN), *(("content-type", value) for value in types)),
    )

    assert reply.refusal == (415, "operator form content type required")
    assert not gateway.handler.reached


@pytest.mark.parametrize("content_type", [FORM.upper(), f"{FORM}; Charset=UTF-8", f"{FORM} ;charset=utf-8"])
async def test_form_content_type_ignores_case_and_spacing(
    gateway: Gateway, content_type: str,
) -> None:
    reply = await gateway.console(
        "POST", "/register", body=b"csrf=1",
        headers=(("origin", ORIGIN), ("content-type", content_type)),
    )

    assert reply.status == 200


async def test_a_form_larger_than_the_operator_cap_is_refused(gateway: Gateway) -> None:
    declared = await gateway.form("/register", messages=[], headers=(("content-length", "17"),))
    streamed = await gateway.form("/register", body=b"x" * 17)

    assert declared.refusal == (413, "request body too large")
    assert streamed.refusal == (413, "request body too large")
    assert not gateway.handler.reached


async def test_a_form_that_never_arrives_times_out(gateway: Gateway) -> None:
    gateway.config.operator_form_timeout_seconds = 0.05

    reply = await gateway.form(
        "/register", messages=[{"type": "http.request", "body": b"csrf=", "more_body": True}],
    )

    assert reply.refusal == (408, "operator form timed out")
    assert not gateway.handler.reached


async def test_a_client_that_disconnects_mid_form_gets_no_response(gateway: Gateway) -> None:
    reply = await gateway.form(
        "/register",
        messages=[
            {"type": "http.request", "body": b"csrf=", "more_body": True},
            {"type": "http.disconnect"},
        ],
    )

    assert reply.sent == []
    assert not gateway.handler.reached


# -- the console stylesheet -------------------------------------------------


async def test_the_stylesheet_needs_no_session_but_is_source_limited(gateway: Gateway) -> None:
    gateway.state.operator_auth = None

    served = await gateway.call("GET", DASHBOARD_STYLESHEET_PATH)
    gateway.world.limited.add(f"source:{CLIENT}")
    limited = await gateway.call("GET", DASHBOARD_STYLESHEET_PATH)

    assert served.status == 200
    assert limited.refusal == (429, "request rate limit exceeded")
    assert limited.headers["retry-after"] == "7"
    assert gateway.world.steps("session") == []
