"""Declared per-route capabilities for the authenticated API surface.

The middleware used to decide which gates applied by comparing the request path
against a hardcoded set. That set lived far from the routes it governed, and a
new route inherited the strictest gate silently, which is safe but invisible.

Capabilities are declared here per route instead, and enforcement is
**default-deny**: a governed route that declares no capability fails startup and
is refused at request time. Capability gating that fails open would be strictly
worse than a path list while looking safer, so the absence of a declaration is
always an error rather than a permission.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from strugglebus.errors import ConfigurationError

#: Reachable without any credential.
PUBLIC = "public"
#: Requires the root admin token.
ADMIN = "admin"
#: Authenticated by a single-use enrollment token, never an API credential.
ENROLLMENT = "enrollment"
#: Authenticated by a reconnect grant, never an API credential.
RECONNECT = "reconnect"
#: Reachable by a pending credential that has not yet proved identity or
#: acknowledged its rules of engagement. Deliberately small.
AGENT_BOOTSTRAP = "agent-bootstrap"
#: Requires a proved credential and a current rules-of-engagement receipt.
AGENT_OPERATIONAL = "agent-operational"
#: Authenticated by a single-use mobile enrollment token, never a credential.
MOBILE_ENROLLMENT = "mobile-enrollment"
#: A mobile monitor's minimal liveness surface. It exposes state alone: a
#: monitor that cannot tell "frozen" from "unreachable" reports an outage
#: during a deliberate safety action.
MOBILE_STATUS = "mobile-status"
#: A mobile monitor's read surface. It keeps answering while frozen, because a
#: freeze stops the agent plane and a monitor is how the owner watches the
#: incident it was declared for.
MOBILE_READ = "mobile-read"
#: A monitor's write surface. Every write here needs the device credential
#: *and* the device's write grant, so possession of the running app is not by
#: itself a write capability. Containment actions also need a confirmation
#: bound to the exact action and target; a #humans post targets nothing.
MOBILE_WRITE = "mobile-write"
#: Dedicated service-principal routes: package issuance, retiring the
#: identities it created, and rotating its own credential. It is neither an
#: agent nor an administrator.
SPN_ONBOARDING = "spn-onboarding"
#: Authenticated by a single-use host enrollment code, never a credential.
#: A worker host holds nothing else before it has joined. LAN only: it is not
#: among the routes a satellite site may reach.
HOST_ENROLLMENT = "host-enrollment"
#: Authenticated by the verified satellite site certificate alone, and only on
#: the satellite path. No agent key is involved: these routes renew the site's
#: own certificate and describe the release the satellite should run.
SATELLITE = "satellite"

CAPABILITIES = frozenset(
    {
        PUBLIC,
        ADMIN,
        ENROLLMENT,
        RECONNECT,
        AGENT_BOOTSTRAP,
        AGENT_OPERATIONAL,
        MOBILE_STATUS,
        MOBILE_READ,
        MOBILE_WRITE,
        MOBILE_ENROLLMENT,
        HOST_ENROLLMENT,
        SPN_ONBOARDING,
        SATELLITE,
    }
)

#: Capabilities authenticated by a mobile monitor credential rather than an
#: agent credential. The two can never satisfy each other.
MOBILE_CAPABILITIES = frozenset({MOBILE_STATUS, MOBILE_READ, MOBILE_WRITE})

#: All a satellite site may reach: the agent plane and its own routes. Admin,
#: mobile and service-principal routes stay LAN-only.
SITE_CAPABILITIES = frozenset(
    {ENROLLMENT, RECONNECT, AGENT_BOOTSTRAP, AGENT_OPERATIONAL, SATELLITE}
)

#: Only these paths are capability-governed. The human console is authenticated
#: by an operator session in a separate branch and is not covered here.
GOVERNED_PREFIXES = ("/api/",)
GOVERNED_EXACT = frozenset({"/healthz"})

ROUTE_CAPABILITIES: dict[tuple[str, str], str] = {
    ("GET", "/healthz"): PUBLIC,
    # Credential issuance outside the ordinary agent credential path.
    ("POST", "/api/agents"): ADMIN,
    ("GET", "/api/admin/identity-provenance"): ADMIN,
    ("POST", "/api/enrollments/redeem"): ENROLLMENT,
    ("POST", "/api/reconnect/redeem"): RECONNECT,
    ("GET", "/api/admin/agents/{agent_name}/credentials"): ADMIN,
    ("POST", "/api/admin/agents/{agent_name}/credentials"): ADMIN,
    ("POST", "/api/admin/agents/{agent_name}/credentials/recover"): ADMIN,
    (
        "POST",
        "/api/admin/agents/{agent_name}/credentials/{credential_id}/revoke",
    ): ADMIN,
    ("POST", "/api/admin/agents/{agent_name}/revoke"): ADMIN,
    ("POST", "/api/admin/roe/agents/{agent_name}/revisions"): ADMIN,
    ("POST", "/api/admin/roe/global/revisions"): ADMIN,
    ("GET", "/api/admin/roe/revisions"): ADMIN,
    # The bootstrap set: identity inspection, the guidance needed to bootstrap,
    # proof itself, and the rules-of-engagement exchange. Anything added here
    # is reachable before proof, so additions deserve the same scrutiny as a
    # new unauthenticated route.
    ("GET", "/api/whoami"): AGENT_BOOTSTRAP,
    ("GET", "/api/orientation"): AGENT_BOOTSTRAP,
    ("GET", "/api/server-info"): AGENT_BOOTSTRAP,
    ("GET", "/api/integration-guide"): AGENT_BOOTSTRAP,
    ("GET", "/api/roe/effective"): AGENT_BOOTSTRAP,
    ("POST", "/api/roe/acknowledgements"): AGENT_BOOTSTRAP,
    ("POST", "/api/credentials/prove"): AGENT_BOOTSTRAP,
    # Everything else requires a proved credential and a current receipt.
    ("GET", "/api/agents"): AGENT_OPERATIONAL,
    ("GET", "/api/catch-up"): AGENT_OPERATIONAL,
    ("GET", "/api/channels"): AGENT_OPERATIONAL,
    ("POST", "/api/channels"): AGENT_OPERATIONAL,
    ("GET", "/api/channels/{name}/messages"): AGENT_OPERATIONAL,
    ("POST", "/api/channels/{name}/messages"): AGENT_OPERATIONAL,
    ("POST", "/api/credentials/rotate"): AGENT_OPERATIONAL,
    ("POST", "/api/credentials/{credential_id}/retire"): AGENT_OPERATIONAL,
    ("GET", "/api/messages/{message_seq}/replies"): AGENT_OPERATIONAL,
    ("POST", "/api/messages/{message_seq}/claim"): AGENT_OPERATIONAL,
    ("GET", "/api/messages/{message_seq}/claim"): AGENT_OPERATIONAL,
    ("DELETE", "/api/messages/{message_seq}/claim"): AGENT_OPERATIONAL,
    ("GET", "/api/search"): AGENT_OPERATIONAL,
    ("GET", "/api/site-documents/{name}"): AGENT_OPERATIONAL,
    ("GET", "/api/stream"): AGENT_OPERATIONAL,
    ("GET", "/api/subscriptions"): AGENT_OPERATIONAL,
    ("PUT", "/api/subscriptions/{channel}"): AGENT_OPERATIONAL,
    ("DELETE", "/api/subscriptions/{channel}"): AGENT_OPERATIONAL,
    # Mobile monitor surface. Reads keep answering while frozen; status
    # reports state=frozen so a frozen board can never be mistaken for an
    # empty one.
    ("GET", "/api/mobile/status"): MOBILE_STATUS,
    ("GET", "/api/mobile/snapshot"): MOBILE_READ,
    ("GET", "/api/mobile/search"): MOBILE_READ,
    ("GET", "/api/mobile/channels"): MOBILE_READ,
    ("GET", "/api/mobile/channels/activity"): MOBILE_READ,
    ("GET", "/api/mobile/agents"): MOBILE_READ,
    ("GET", "/api/mobile/stream"): MOBILE_READ,
    ("POST", "/api/mobile/enrollments/redeem"): MOBILE_ENROLLMENT,
    # Containment surface. Establishing a grant proves the operator password
    # and creates authority, so it is refused while frozen. Confirmations and
    # actions are not refused: the actions they can name are containment
    # actions the owner may need *during* an incident, and a freeze that
    # blocked its own response would be the control defeating its purpose.
    ("POST", "/api/mobile/grants"): MOBILE_WRITE,
    ("POST", "/api/mobile/confirmations"): MOBILE_WRITE,
    ("POST", "/api/mobile/actions"): MOBILE_WRITE,
    ("POST", "/api/mobile/humans/messages"): MOBILE_WRITE,
    ("POST", "/api/mobile/enrollments/agents"): MOBILE_WRITE,
    ("POST", "/api/mobile/enrollments/service-principals"): MOBILE_WRITE,
    ("POST", "/api/mobile/enrollments/devices"): MOBILE_WRITE,
    ("POST", "/api/mobile/enrollments/hosts"): MOBILE_WRITE,
    ("POST", "/api/mobile/hosts/commands"): MOBILE_WRITE,
    ("POST", "/api/hosts/enrollments/redeem"): HOST_ENROLLMENT,
    ("POST", "/api/hosts/status"): AGENT_OPERATIONAL,
    ("POST", "/api/hosts/events"): AGENT_OPERATIONAL,
    ("POST", "/api/mobile/admin/logs/full"): MOBILE_WRITE,
    ("GET", "/api/mobile/hosts/status"): MOBILE_READ,
    ("GET", "/api/mobile/hosts/{agent_id}/status/history"): MOBILE_READ,
    ("POST", "/api/mobile/admin/hosts/status"): MOBILE_WRITE,
    ("POST", "/api/mobile/admin/agents/{agent_id}/host"): MOBILE_WRITE,
    # Operator management from a device. The lists are operator-class reads.
    # The control routes restore or mint authority as well as narrowing it;
    # the owner allowed that, and the write grant is their authorisation.
    ("GET", "/api/mobile/admin/agents"): MOBILE_READ,
    ("GET", "/api/mobile/admin/devices"): MOBILE_READ,
    ("GET", "/api/mobile/admin/service-principals"): MOBILE_READ,
    ("GET", "/api/mobile/admin/logs"): MOBILE_READ,
    ("GET", "/api/mobile/site-documents/{name}"): MOBILE_READ,
    ("POST", "/api/mobile/site-documents/{name}"): MOBILE_WRITE,
    ("POST", "/api/mobile/admin/agents/{agent_id}/control"): MOBILE_WRITE,
    (
        "POST",
        "/api/mobile/admin/service-principals/{spn_id}/control",
    ): MOBILE_WRITE,
    ("POST", "/api/spn/onboarding-packages"): SPN_ONBOARDING,
    ("POST", "/api/spn/agents/{agent_name}/retire"): SPN_ONBOARDING,
    ("POST", "/api/spn/credentials/rotate"): SPN_ONBOARDING,
    ("POST", "/api/satellite/renew"): SATELLITE,
    ("GET", "/api/satellite/release"): SATELLITE,
    ("GET", "/api/satellite/release/wheel"): SATELLITE,
    ("GET", "/api/satellite/release/requirements-lock"): SATELLITE,
}


def is_governed(path: str) -> bool:
    return path in GOVERNED_EXACT or path.startswith(GOVERNED_PREFIXES)


@dataclass(frozen=True, slots=True)
class _Entry:
    methods: frozenset[str]
    pattern: re.Pattern[str]
    capability: str
    template: str


class CapabilityResolver:
    """Resolve a request to its declared capability, or to nothing at all."""

    __slots__ = ("_entries",)

    def __init__(self, entries: tuple[_Entry, ...]) -> None:
        self._entries = entries

    def resolve(self, method: str, path: str) -> str | None:
        entry = self._match(method, path)
        return None if entry is None else entry.capability

    def template(self, method: str, path: str) -> str | None:
        """The declared route template, so logs never carry the raw path."""

        entry = self._match(method, path)
        return None if entry is None else entry.template

    def _match(self, method: str, path: str) -> _Entry | None:
        for entry in self._entries:
            if method in entry.methods and entry.pattern.fullmatch(path):
                return entry
        return None


def _pattern_for(template: str) -> re.Pattern[str]:
    # Path parameters never span a separator, matching Starlette's default
    # converter, so one segment cannot be smuggled into another route.
    literal = re.sub(r"\{[^{}]+\}", "\x00", template)
    escaped = re.escape(literal).replace("\x00", "[^/]+")
    return re.compile(escaped)


def build_resolver(
    declared: dict[tuple[str, str], str] | None = None,
) -> CapabilityResolver:
    source = ROUTE_CAPABILITIES if declared is None else declared
    entries: list[_Entry] = []
    for (method, template), capability in source.items():
        if capability not in CAPABILITIES:
            raise ConfigurationError(
                f"route {method} {template} declares unknown capability "
                f"{capability!r}"
            )
        entries.append(
            _Entry(
                methods=frozenset({method}),
                pattern=_pattern_for(template),
                capability=capability,
                template=template,
            )
        )
    # Longer templates first so a literal segment wins over a parameter that
    # would otherwise also match it.
    entries.sort(key=lambda entry: len(entry.pattern.pattern), reverse=True)
    return CapabilityResolver(tuple(entries))


def _walk(routes: Iterable[object]) -> Iterable[object]:
    """Yield routes, descending into included sub-routers.

    Some FastAPI versions keep an included router as one wrapper entry whose
    own path is ``None`` rather than flattening its routes into the parent.
    Iterating only the top level would inspect nothing while appearing to
    succeed, which is precisely the failure this module exists to prevent.
    """

    for route in routes:
        nested = getattr(route, "routes", None)
        if nested is None:
            # FastAPI's _IncludedRouter exposes the router it wrapped rather
            # than a routes collection of its own.
            inner = getattr(route, "original_router", None)
            nested = getattr(inner, "routes", None) if inner is not None else None
        if nested:
            yield from _walk(nested)
        if isinstance(getattr(route, "path", None), str):
            yield route


def assert_routes_declared(routes: Iterable[object]) -> None:
    """Fail startup when a governed route declares no capability.

    Enforcement lives here rather than at request time alone so that adding a
    route without declaring its capability cannot reach production at all.
    """

    undeclared: list[str] = []
    for route in _walk(routes):
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not isinstance(path, str) or not methods or not is_governed(path):
            continue
        for method in sorted(methods):
            if method in {"HEAD", "OPTIONS"}:
                continue
            if (method, path) not in ROUTE_CAPABILITIES:
                undeclared.append(f"{method} {path}")
    if undeclared:
        raise ConfigurationError(
            "governed routes declare no capability: " + ", ".join(sorted(undeclared))
        )
