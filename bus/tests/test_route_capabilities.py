from __future__ import annotations

import pytest
from fastapi import APIRouter, FastAPI

from strugglebus import capabilities
from strugglebus.api import create_api_router
from strugglebus.capabilities import (
    ROUTE_CAPABILITIES,
    assert_routes_declared,
    build_resolver,
    is_governed,
)
from strugglebus.errors import ConfigurationError


def _governed_routes() -> set[tuple[str, str]]:
    declared: set[tuple[str, str]] = set()
    for route in create_api_router().routes:
        path = getattr(route, "path", "")
        if not is_governed(path):
            continue
        for method in getattr(route, "methods", set()) or set():
            if method not in {"HEAD", "OPTIONS"}:
                declared.add((method, path))
    return declared


def test_every_governed_route_declares_exactly_one_known_capability() -> None:
    served = _governed_routes()
    undeclared = served - set(ROUTE_CAPABILITIES)
    assert not undeclared, f"routes without a declared capability: {sorted(undeclared)}"
    stale = set(ROUTE_CAPABILITIES) - served
    assert not stale, f"declared capabilities for absent routes: {sorted(stale)}"
    for route, capability in ROUTE_CAPABILITIES.items():
        assert capability in capabilities.CAPABILITIES, route


def test_adding_a_governed_route_without_a_declaration_fails_startup() -> None:
    # The whole point of capability gating is that it fails closed. A route
    # that declares nothing must be refused, not silently permitted.
    router = APIRouter()

    @router.get("/api/undeclared-surface")
    async def undeclared() -> dict[str, str]:  # pragma: no cover - never served
        return {}

    application = FastAPI()
    application.include_router(router)
    with pytest.raises(ConfigurationError, match="declare no capability"):
        assert_routes_declared(application.routes)


def test_ungoverned_paths_are_not_required_to_declare_capabilities() -> None:
    router = APIRouter()

    @router.get("/console-only")
    async def console() -> dict[str, str]:  # pragma: no cover - never served
        return {}

    application = FastAPI()
    application.include_router(router)
    assert_routes_declared(application.routes)
    assert not is_governed("/console-only")
    assert is_governed("/healthz")
    assert is_governed("/api/whoami")


def test_resolver_matches_parameterized_routes_without_crossing_separators() -> None:
    resolver = build_resolver()
    assert (
        resolver.resolve("GET", "/api/channels/status/messages")
        == capabilities.AGENT_OPERATIONAL
    )
    assert resolver.resolve("GET", "/api/whoami") == capabilities.AGENT_BOOTSTRAP
    assert resolver.resolve("POST", "/api/agents") == capabilities.ADMIN
    assert resolver.resolve("GET", "/api/agents") == capabilities.AGENT_OPERATIONAL
    assert (
        resolver.resolve("POST", "/api/enrollments/redeem")
        == capabilities.ENROLLMENT
    )
    # A parameter must not swallow a separator and match a deeper route.
    assert resolver.resolve("PUT", "/api/subscriptions/one/two") is None
    # Unknown routes and wrong methods resolve to nothing, which the middleware
    # treats as a denial.
    assert resolver.resolve("GET", "/api/does-not-exist") is None
    assert resolver.resolve("DELETE", "/api/whoami") is None


def test_literal_routes_win_over_parameterized_siblings() -> None:
    resolver = build_resolver()
    # /api/admin/roe/global/revisions and
    # /api/admin/roe/agents/{agent_name}/revisions must not be confused.
    assert (
        resolver.resolve("POST", "/api/admin/roe/global/revisions")
        == capabilities.ADMIN
    )
    assert (
        resolver.resolve("POST", "/api/admin/roe/agents/some-agent/revisions")
        == capabilities.ADMIN
    )


def test_unknown_capability_names_are_rejected() -> None:
    with pytest.raises(ConfigurationError, match="unknown capability"):
        build_resolver({("GET", "/api/example"): "not-a-capability"})


def test_bootstrap_capability_stays_minimal_and_intentional() -> None:
    # Bootstrap routes are reachable before identity proof and before a
    # rules-of-engagement receipt, so widening this set is a security change
    # and should require editing this assertion deliberately.
    bootstrap = {
        route
        for route, capability in ROUTE_CAPABILITIES.items()
        if capability == capabilities.AGENT_BOOTSTRAP
    }
    assert bootstrap == {
        ("GET", "/api/whoami"),
        ("GET", "/api/orientation"),
        ("GET", "/api/server-info"),
        ("GET", "/api/integration-guide"),
        ("GET", "/api/roe/effective"),
        ("POST", "/api/roe/acknowledgements"),
        ("POST", "/api/credentials/prove"),
    }


def test_admin_and_credential_surfaces_are_never_agent_operational() -> None:
    for (method, path), capability in ROUTE_CAPABILITIES.items():
        if path.startswith("/api/admin/"):
            assert capability == capabilities.ADMIN, (method, path)
    assert ROUTE_CAPABILITIES[("POST", "/api/agents")] == capabilities.ADMIN
    assert (
        ROUTE_CAPABILITIES[("POST", "/api/enrollments/redeem")]
        == capabilities.ENROLLMENT
    )
    assert (
        ROUTE_CAPABILITIES[("POST", "/api/reconnect/redeem")]
        == capabilities.RECONNECT
    )
    assert (
        ROUTE_CAPABILITIES[("POST", "/api/spn/onboarding-packages")]
        == capabilities.SPN_ONBOARDING
    )
