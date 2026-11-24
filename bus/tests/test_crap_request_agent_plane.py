"""The request gateway's agent plane: MCP and every REST capability.

Uses the scripted gateway from ``test_crap_request_gateway.py``. Each test
names the gate it exercises; where the order of gates matters, the recorded
sequence of collaborator calls is asserted as well.
"""

from __future__ import annotations

from collections.abc import Iterator
import json
import logging
from types import SimpleNamespace
from typing import Any

import pytest

from strugglebus import audit_feed
from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    CredentialNotFoundError,
    RoeAcknowledgementRequiredError,
    StorageError,
)
from strugglebus.models import ServicePrincipalIdentity
from strugglebus.operator_auth import OperatorCapacityError
from test_crap_request_gateway import CLIENT, PROXY, SITE, Gateway

AGENT_KEY = "agent-key"
ENROLLMENT = "sbe1_" + "A" * 22 + "_" + "A" * 43
SPN_ENROLLMENT = "sbse1_" + "A" * 22 + "_" + "A" * 43
MOBILE_ENROLLMENT = "sbme1_" + "A" * 22 + "_" + "A" * 43
RECONNECT = "sbr1_" + "A" * 22 + "_" + "A" * 43
JSON = ("content-type", "application/json")
SOURCE_LIMIT = f"limit source:{CLIENT} 30"
RECEIPT_REQUIRED = (428, "current rules of engagement receipt required")


def _identity(status: str = "active") -> Any:
    return SimpleNamespace(
        agent=SimpleNamespace(id="agent-1"),
        credential=SimpleNamespace(id="cred-1", kind="sb1", status=status),
    )


@pytest.fixture
def gateway() -> Gateway:
    """A gateway that knows one proved agent holding a current receipt."""

    gateway = Gateway()
    gateway.world.agents[AGENT_KEY] = _identity()
    gateway.world.receipts.add(("agent-1", "cred-1"))
    return gateway


# -- default deny and credential parsing -----------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/api/not-a-route"), ("DELETE", "/api/channels"), ("GET", "/api/")],
)
async def test_an_api_route_that_declares_no_capability_is_refused(
    gateway: Gateway, method: str, path: str,
) -> None:
    reply = await gateway.call(method, path, token=AGENT_KEY)

    assert reply.refusal == (403, "route declares no capability")
    # Refused before any limiter or credential check could fail open.
    assert gateway.world.calls == []


@pytest.mark.parametrize(
    "authorizations",
    [
        (),
        ("Basic agent-key",),
        ("Bearer",),
        ("Bearer ",),
        ("agent-key",),
        (f"Bearer {AGENT_KEY}", f"Bearer {AGENT_KEY}"),
    ],
)
async def test_anything_but_one_bearer_credential_is_no_credential(
    gateway: Gateway, authorizations: tuple[str, ...],
) -> None:
    reply = await gateway.call(
        "GET", "/api/channels",
        headers=tuple(("authorization", value) for value in authorizations),
    )

    assert reply.refusal == (401, "agent authentication required")
    assert reply.headers["www-authenticate"] == "Bearer"
    assert gateway.world.calls == [SOURCE_LIMIT]


async def test_the_bearer_scheme_is_case_insensitive(gateway: Gateway) -> None:
    reply = await gateway.call(
        "GET", "/api/channels", headers=(("Authorization", f"bEARER {AGENT_KEY}"),),
    )

    assert reply.status == 200


# -- agents -------------------------------------------------------------------


async def test_an_operational_request_holds_its_receipt_for_the_whole_call(
    gateway: Gateway,
) -> None:
    reply = await gateway.call("GET", "/api/channels", token=AGENT_KEY)

    assert reply.status == 200
    identity = gateway.world.agents[AGENT_KEY]
    assert gateway.handler.state == {
        "authenticated_agent": identity.agent,
        "authenticated_identity": identity,
        "credential_kind": "sb1",
        "credential_id": "cred-1",
    }
    assert gateway.world.calls == [
        "authorize",
        "limit credential:cred-1 600",
        "receipt",
        "begin-operational agent-1 cred-1",
        "handler",
        # Re-checked at the moment the response starts.
        "receipt",
        "end-operational operational-lease",
    ]


@pytest.mark.parametrize("path", ["/api/channels", "/api/whoami", "/mcp", "/mcp/"])
async def test_an_unknown_agent_credential_is_refused_and_counted_against_its_source(
    gateway: Gateway, path: str,
) -> None:
    reply = await gateway.call("GET", path, token="wrong-key")

    assert reply.refusal == (401, "invalid agent credential")
    assert reply.headers["www-authenticate"] == "Bearer"
    assert gateway.world.calls == ["authorize", SOURCE_LIMIT]


@pytest.mark.parametrize("token", [None, "wrong-key"])
async def test_a_source_over_its_limit_is_told_so_instead_of_being_challenged(
    gateway: Gateway, token: str | None,
) -> None:
    gateway.world.limited.add(f"source:{CLIENT}")

    reply = await gateway.call("GET", "/api/channels", token=token)

    assert reply.refusal == (429, "request rate limit exceeded")
    assert reply.headers["retry-after"] == "7"
    assert "www-authenticate" not in reply.headers


@pytest.mark.parametrize(
    ("error", "refusal"),
    [
        (AgentAccessFrozenError("frozen"), (503, "agent access is frozen")),
        (StorageError("disk"), (503, "agent access is unavailable")),
    ],
)
async def test_agent_authentication_fails_closed(
    gateway: Gateway, error: Exception, refusal: tuple[int, str],
) -> None:
    gateway.world.fail("authorize", error)

    reply = await gateway.call("GET", "/api/channels", token=AGENT_KEY)

    assert reply.refusal == refusal
    assert gateway.world.calls == ["authorize"]


async def test_each_credential_has_its_own_request_limit(gateway: Gateway) -> None:
    gateway.world.limited.add("credential:cred-1")

    reply = await gateway.call("GET", "/api/channels", token=AGENT_KEY)

    assert reply.refusal == (429, "request rate limit exceeded")
    assert gateway.world.calls == ["authorize", "limit credential:cred-1 600"]
    assert gateway.scope.get("state") is None


async def test_a_pending_credential_reaches_only_the_bootstrap_routes(gateway: Gateway) -> None:
    gateway.world.agents[AGENT_KEY] = _identity("pending")
    gateway.world.receipts.clear()

    operational = await gateway.call("GET", "/api/channels", token=AGENT_KEY)
    before_bootstrap = len(gateway.world.calls)
    bootstrap = await gateway.call("GET", "/api/whoami", token=AGENT_KEY)

    assert operational.refusal == (403, "credential identity proof required")
    # Proof is demanded before the receipt is even looked at.
    assert "receipt" not in gateway.world.calls
    assert bootstrap.status == 200
    assert gateway.world.calls[before_bootstrap:] == [
        "authorize",
        "limit credential:cred-1 600",
        "begin-bootstrap agent-1 cred-1",
        "handler",
        "live agent-1 cred-1",
        "end-operational None",
        "end-bootstrap bootstrap-lease",
    ]


async def test_a_proved_credential_without_a_current_receipt_is_refused(
    gateway: Gateway,
) -> None:
    gateway.world.receipts.clear()

    reply = await gateway.call("GET", "/api/channels", token=AGENT_KEY)

    assert reply.refusal == RECEIPT_REQUIRED
    assert gateway.world.steps("begin", "handler", "end") == []


def _withdraw_receipt(gateway: Gateway) -> Any:
    return lambda scope: gateway.world.receipts.clear()


async def test_a_response_is_withheld_when_the_receipt_went_stale_during_the_call(
    gateway: Gateway,
) -> None:
    gateway.handler.before_response = _withdraw_receipt(gateway)

    reply = await gateway.call("GET", "/api/channels", token=AGENT_KEY)

    assert reply.refusal == RECEIPT_REQUIRED
    assert b"handled" not in reply.body
    assert gateway.world.calls[-1] == "end-operational operational-lease"


@pytest.mark.parametrize(
    ("error", "refusal"),
    [
        (AgentNotFoundError("gone"), (401, "agent credential is unavailable")),
        (CredentialNotFoundError("gone"), (401, "agent credential is unavailable")),
        (AgentAccessFrozenError("frozen"), (503, "agent access is unavailable")),
        (StorageError("disk"), (503, "agent access is unavailable")),
    ],
)
@pytest.mark.parametrize(("path", "step"), [
    ("/api/channels", "receipt"), ("/api/whoami", "live agent-1 cred-1"),
])
async def test_a_response_is_withheld_when_the_credential_was_withdrawn_during_the_call(
    gateway: Gateway, path: str, step: str, error: Exception, refusal: tuple[int, str],
) -> None:
    # The admission check passes; the re-check at response start does not.
    gateway.world.fail(step, error, call=2 if step == "receipt" else 1)

    reply = await gateway.call("GET", path, token=AGENT_KEY)

    assert reply.refusal == refusal
    assert b"handled" not in reply.body
    assert gateway.handler.reached


@pytest.mark.parametrize(
    ("error", "refusal"),
    [
        (RoeAcknowledgementRequiredError("stale"), RECEIPT_REQUIRED),
        (AgentNotFoundError("gone"), (401, "agent access is unavailable")),
        (CredentialNotFoundError("gone"), (401, "agent access is unavailable")),
        (AgentAccessFrozenError("frozen"), (503, "agent access is unavailable")),
    ],
)
@pytest.mark.parametrize("path", ["/api/channels", "/api/whoami"])
async def test_a_handler_that_finds_the_agent_withdrawn_is_answered_with_a_refusal(
    gateway: Gateway, path: str, error: Exception, refusal: tuple[int, str],
) -> None:
    gateway.handler.error = error

    reply = await gateway.call("GET", path, token=AGENT_KEY)

    assert reply.refusal == refusal
    # The lease taken for the call is always released.
    assert gateway.world.steps("end-") != []


@pytest.mark.parametrize(
    "error", [RoeAcknowledgementRequiredError("stale"), AgentAccessFrozenError("frozen")],
)
async def test_an_agent_failure_after_the_response_started_is_not_disguised(
    gateway: Gateway, error: Exception,
) -> None:
    gateway.handler.error_after_start = error

    with pytest.raises(type(error)):
        await gateway.call("GET", "/api/channels", token=AGENT_KEY)

    assert gateway.world.calls[-1] == "end-operational operational-lease"


async def test_a_storage_failure_inside_a_handler_is_left_to_the_application(
    gateway: Gateway,
) -> None:
    gateway.handler.error = StorageError("disk")

    with pytest.raises(StorageError):
        await gateway.call("GET", "/api/channels", token=AGENT_KEY)

    assert gateway.world.calls[-1] == "end-operational operational-lease"


async def test_mcp_authenticates_the_agent_and_leaves_the_body_to_the_mcp_server(
    gateway: Gateway,
) -> None:
    gateway.world.receipts.clear()
    gateway.world.agents[AGENT_KEY] = _identity("pending")
    oversized = b"x" * 100

    reply = await gateway.call("POST", "/mcp", token=AGENT_KEY, body=oversized)

    assert reply.status == 200
    assert gateway.handler.body == oversized
    assert gateway.handler.state["credential_id"] == "cred-1"
    # Proof and receipt are enforced per tool inside the MCP server.
    assert gateway.world.calls == [
        "authorize", "limit credential:cred-1 600", "handler", "end-operational None",
    ]


# -- request bodies -----------------------------------------------------------


async def test_a_rest_body_is_buffered_whole_and_replayed_once(gateway: Gateway) -> None:
    gateway.handler.reads = 2

    reply = await gateway.call(
        "POST", "/api/channels", token=AGENT_KEY, headers=(("content-length", "6"),),
        messages=[
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"def"},
        ],
    )

    assert reply.status == 200
    assert gateway.handler.received == [
        {"type": "http.request", "body": b"abcdef", "more_body": False},
        {"type": "http.disconnect"},
    ]


async def test_reads_are_not_buffered(gateway: Gateway) -> None:
    first = {"type": "http.request", "body": b"x" * 100, "more_body": True}

    reply = await gateway.call(
        "GET", "/api/channels", token=AGENT_KEY, messages=[first],
        headers=(("content-length", "nonsense"),),
    )

    assert reply.status == 200
    assert gateway.handler.received == [first]


@pytest.mark.parametrize(
    "lengths",
    [
        ("3", "3"),
        ("three",),
        ("+3",),
        ("-3",),
        ("3.0",),
        (" 3",),
        ("",),
        ("4",),
        ("2",),
        # Longer than Python will parse as an integer.
        ("9" * 5000,),
    ],
)
async def test_a_content_length_that_is_not_one_honest_decimal_is_refused(
    gateway: Gateway, lengths: tuple[str, ...],
) -> None:
    reply = await gateway.call(
        "POST", "/api/channels", token=AGENT_KEY, body=b"abc",
        headers=tuple(("content-length", value) for value in lengths),
    )

    assert reply.refusal == (400, "invalid content length")
    assert not gateway.handler.reached
    # The credential was accepted first; a caller without one learns nothing.
    assert gateway.world.calls[0] == "authorize"


async def test_a_declared_oversize_body_is_refused_without_being_read(gateway: Gateway) -> None:
    reply = await gateway.call(
        "POST", "/api/channels", token=AGENT_KEY, messages=[],
        headers=(("content-length", "33"),),
    )

    assert reply.refusal == (413, "request body too large")
    assert reply.headers["cache-control"] == "no-store"


async def test_an_undeclared_oversize_body_is_cut_off_at_the_cap(gateway: Gateway) -> None:
    reply = await gateway.call(
        "POST", "/api/channels", token=AGENT_KEY,
        messages=[
            {"type": "http.request", "body": b"x" * 32, "more_body": True},
            {"type": "http.request", "body": b"x", "more_body": True},
        ],
    )

    assert reply.refusal == (413, "request body too large")
    assert not gateway.handler.reached


async def test_a_body_exactly_at_the_cap_is_accepted(gateway: Gateway) -> None:
    reply = await gateway.call(
        "POST", "/api/channels", token=AGENT_KEY, body=b"x" * 32,
        headers=(("Content-Length", "32"),),
    )

    assert reply.status == 200
    assert gateway.handler.body == b"x" * 32


async def test_a_client_that_disconnects_mid_body_gets_no_response(gateway: Gateway) -> None:
    reply = await gateway.call(
        "POST", "/api/channels", token=AGENT_KEY,
        messages=[
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.disconnect"},
        ],
    )

    assert reply.sent == []
    assert not gateway.handler.reached
    # Nothing was dispatched, so no lease was taken.
    assert gateway.world.steps("begin", "end") == []


# -- admin --------------------------------------------------------------------


async def test_an_admin_request_is_verified_limited_and_refused_while_frozen_in_that_order(
    gateway: Gateway,
) -> None:
    reply = await gateway.call("POST", "/api/agents", token="admin-secret", body=b"{}")

    assert reply.status == 200
    assert gateway.handler.state == {
        "admin_authenticated": True,
        "admin_credential_kind": "admin-token",
        "admin_credential_id": "admin-credential-1",
    }
    assert gateway.handler.body == b"{}"
    assert gateway.world.calls == [
        "admin-verify", f"limit admin:{CLIENT} 600", "freeze", "handler",
        "end-operational None",
    ]


async def test_admin_without_a_credential_is_challenged(gateway: Gateway) -> None:
    reply = await gateway.call("POST", "/api/agents")

    assert reply.refusal == (401, "admin authentication required")
    assert reply.headers["www-authenticate"] == "Bearer"
    assert gateway.world.calls == [SOURCE_LIMIT]


@pytest.mark.parametrize("verifier_loaded", [True, False])
async def test_a_wrong_admin_credential_is_rejected_without_a_challenge(
    gateway: Gateway, verifier_loaded: bool,
) -> None:
    if not verifier_loaded:
        gateway.state.admin_verifier = None

    # An agent key is not an admin credential.
    reply = await gateway.call("POST", "/api/agents", token=AGENT_KEY)

    assert reply.refusal == (403, "admin credential rejected")
    assert "www-authenticate" not in reply.headers
    assert gateway.world.steps("limit", "authorize", "freeze") == [SOURCE_LIMIT]


@pytest.mark.parametrize("token", [None, "wrong"])
async def test_admin_guessing_is_rate_limited_by_source(gateway: Gateway, token: str | None) -> None:
    gateway.world.limited.add(f"source:{CLIENT}")

    reply = await gateway.call("POST", "/api/agents", token=token)

    assert reply.refusal == (429, "request rate limit exceeded")


async def test_a_valid_admin_has_its_own_limit(gateway: Gateway) -> None:
    gateway.world.limited.add(f"admin:{CLIENT}")

    reply = await gateway.call("POST", "/api/agents", token="admin-secret")

    assert reply.refusal == (429, "request rate limit exceeded")
    assert "freeze" not in gateway.world.calls


@pytest.mark.parametrize("cause", ["frozen", "unreadable"])
async def test_admin_is_refused_while_access_is_frozen_or_unknown(
    gateway: Gateway, cause: str,
) -> None:
    if cause == "frozen":
        gateway.world.frozen = True
    else:
        gateway.world.fail("freeze", StorageError("disk"))

    reply = await gateway.call("POST", "/api/agents", token="admin-secret", messages=[])

    # Deliberately the same answer either way.
    assert reply.refusal == (503, "service is unavailable")
    assert gateway.scope.get("state") is None


# -- enrollment ---------------------------------------------------------------


@pytest.mark.parametrize("token", [ENROLLMENT, SPN_ENROLLMENT])
async def test_enrollment_checks_shape_and_freeze_before_reading_a_body(
    gateway: Gateway, token: str,
) -> None:
    reply = await gateway.call("POST", "/api/enrollments/redeem", token=token, body=b"{}")

    assert reply.status == 200
    assert gateway.handler.state == {"enrollment_token": token}
    assert gateway.world.calls == [SOURCE_LIMIT, "freeze", "handler", "end-operational None"]


async def test_enrollment_is_source_limited_before_anything_is_examined(gateway: Gateway) -> None:
    gateway.world.limited.add(f"source:{CLIENT}")

    reply = await gateway.call("POST", "/api/enrollments/redeem", token=ENROLLMENT)

    assert reply.refusal == (429, "request rate limit exceeded")


async def test_enrollment_without_a_token_is_challenged(gateway: Gateway) -> None:
    reply = await gateway.call("POST", "/api/enrollments/redeem")

    assert reply.refusal == (401, "enrollment authentication required")
    assert reply.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("token", [AGENT_KEY, MOBILE_ENROLLMENT, RECONNECT, ENROLLMENT + "A"])
async def test_a_token_of_the_wrong_shape_never_reaches_enrollment_storage(
    gateway: Gateway, token: str,
) -> None:
    reply = await gateway.call("POST", "/api/enrollments/redeem", token=token)

    assert reply.refusal == (401, "enrollment token is not valid")
    assert "www-authenticate" not in reply.headers
    assert gateway.world.calls == [SOURCE_LIMIT]


@pytest.mark.parametrize(
    ("path", "token"),
    [("/api/enrollments/redeem", ENROLLMENT), ("/api/mobile/enrollments/redeem", MOBILE_ENROLLMENT)],
)
@pytest.mark.parametrize(
    ("cause", "detail"),
    [("frozen", "agent access is frozen"), ("unreadable", "service is unavailable")],
)
async def test_nothing_enrolls_while_access_is_frozen_or_unknown(
    gateway: Gateway, path: str, token: str, cause: str, detail: str,
) -> None:
    if cause == "frozen":
        gateway.world.frozen = True
    else:
        gateway.world.fail("freeze", StorageError("disk"))

    reply = await gateway.call("POST", path, token=token, messages=[])

    assert reply.refusal == (503, detail)
    assert gateway.scope.get("state") is None


async def test_mobile_enrollment_accepts_only_a_mobile_allowance(gateway: Gateway) -> None:
    accepted = await gateway.call(
        "POST", "/api/mobile/enrollments/redeem", token=MOBILE_ENROLLMENT, body=b"{}",
    )
    accepted_calls = list(gateway.world.calls)
    state = gateway.handler.state
    refusals = [
        await gateway.call("POST", "/api/mobile/enrollments/redeem", token=token)
        for token in (None, ENROLLMENT, AGENT_KEY)
    ]

    assert accepted.status == 200
    assert state == {"mobile_enrollment_token": MOBILE_ENROLLMENT}
    assert accepted_calls == [SOURCE_LIMIT, "freeze", "handler", "end-operational None"]
    for reply in refusals:
        assert reply.refusal == (401, "enrollment authentication required")
        assert reply.headers["www-authenticate"] == "Bearer"


async def test_mobile_enrollment_is_source_limited_first(gateway: Gateway) -> None:
    gateway.world.limited.add(f"source:{CLIENT}")

    reply = await gateway.call("POST", "/api/mobile/enrollments/redeem", token=MOBILE_ENROLLMENT)

    assert reply.refusal == (429, "request rate limit exceeded")
    assert "freeze" not in gateway.world.calls


async def test_enrollment_bodies_are_bounded(gateway: Gateway) -> None:
    reply = await gateway.call(
        "POST", "/api/enrollments/redeem", token=ENROLLMENT, body=b"x" * 33,
    )

    assert reply.refusal == (413, "request body too large")


# -- reconnect ----------------------------------------------------------------


@pytest.fixture
def reconnecting(gateway: Gateway) -> Gateway:
    gateway.world.reconnect_grants.add(RECONNECT)
    return gateway


async def _redeem(gateway: Gateway, **kwargs: Any) -> Any:
    kwargs.setdefault("token", RECONNECT)
    kwargs.setdefault("headers", (JSON,))
    if "messages" not in kwargs:
        kwargs.setdefault("body", b"{}")
    return await gateway.call("POST", "/api/reconnect/redeem", **kwargs)


async def test_a_reconnect_is_admitted_checked_for_freeze_then_verified(
    reconnecting: Gateway,
) -> None:
    reply = await _redeem(reconnecting)

    assert reply.status == 200
    assert reconnecting.handler.state == {"reconnect_token": RECONNECT}
    assert reconnecting.handler.body == b"{}"
    assert reconnecting.world.calls == [
        f"admit reconnect-redeem {CLIENT}", "freeze", "reconnect-verify", "handler",
    ]


async def test_reconnect_over_capacity_is_refused_first(reconnecting: Gateway) -> None:
    reconnecting.world.fail(
        f"admit reconnect-redeem {CLIENT}", OperatorCapacityError("busy"),
    )

    reply = await _redeem(reconnecting)

    assert reply.refusal == (429, "reconnect request limit reached")
    assert reconnecting.world.steps("freeze", "reconnect-verify") == []


@pytest.mark.parametrize("cause", ["frozen", "freeze-unreadable", "grant-unreadable"])
async def test_reconnect_is_unavailable_while_frozen_or_storage_fails(
    reconnecting: Gateway, cause: str,
) -> None:
    if cause == "frozen":
        reconnecting.world.frozen = True
    elif cause == "freeze-unreadable":
        reconnecting.world.fail("freeze", StorageError("disk"))
    else:
        reconnecting.world.fail("reconnect-verify", StorageError("disk"))

    reply = await _redeem(reconnecting)

    assert reply.refusal == (503, "agent access is unavailable")
    assert not reconnecting.handler.reached
    if cause == "frozen":
        # A frozen bus does not even look the grant up.
        assert "reconnect-verify" not in reconnecting.world.calls


@pytest.mark.parametrize("token", [None, AGENT_KEY, RECONNECT[:-1] + "B"])
async def test_reconnect_without_a_live_grant_is_refused(
    reconnecting: Gateway, token: str | None,
) -> None:
    kwargs = {"headers": (JSON,), "messages": []}
    reply = await reconnecting.call("POST", "/api/reconnect/redeem", token=token, **kwargs)

    assert reply.refusal == (401, "reconnect grant is unavailable")
    assert "www-authenticate" not in reply.headers
    # A missing token is never passed to the verifier.
    assert ("reconnect-verify" in reconnecting.world.calls) == (token is not None)


@pytest.mark.parametrize(
    "types",
    [(), ("text/plain",), ("application/json", "application/json"), ("application/json; charset=ascii",)],
)
async def test_reconnect_requires_json_after_the_grant_is_proved(
    reconnecting: Gateway, types: tuple[str, ...],
) -> None:
    reply = await _redeem(
        reconnecting, messages=[], headers=tuple(("content-type", value) for value in types),
    )

    assert reply.refusal == (415, "reconnect JSON content type required")
    assert reconnecting.scope.get("state") is None


async def test_reconnect_accepts_utf8_json_in_any_spelling(reconnecting: Gateway) -> None:
    reply = await _redeem(
        reconnecting, headers=(("content-type", "Application/JSON; charset=UTF-8"),),
    )

    assert reply.status == 200


async def test_a_reconnect_body_is_small_and_bounded_by_the_operator_form_cap(
    reconnecting: Gateway,
) -> None:
    at_cap = await _redeem(reconnecting, body=b"x" * 16)
    over_cap = await _redeem(reconnecting, body=b"x" * 17)
    reconnecting.config.operator_form_bytes = 1_000_000
    hard_cap = await _redeem(reconnecting, body=b"x" * 2048)
    over_hard_cap = await _redeem(reconnecting, body=b"x" * 2049)

    assert (at_cap.status, hard_cap.status) == (200, 200)
    assert over_cap.refusal == (413, "request body too large")
    assert over_hard_cap.refusal == (413, "request body too large")


async def test_a_reconnect_body_that_never_arrives_times_out(reconnecting: Gateway) -> None:
    reconnecting.config.operator_form_timeout_seconds = 0.05

    reply = await _redeem(reconnecting, messages=[])

    assert reply.refusal == (408, "reconnect request timed out")
    assert not reconnecting.handler.reached


def _issue_credential(scope: dict[str, Any]) -> None:
    scope["state"]["reconnect_identity"] = ("agent-1", "cred-2")


async def test_a_reissued_credential_is_confirmed_live_before_it_is_sent(
    reconnecting: Gateway,
) -> None:
    reconnecting.handler.before_response = _issue_credential

    reply = await _redeem(reconnecting)

    assert reply.status == 200
    assert reply.body == b"handled"
    assert reconnecting.world.calls[-2:] == ["handler", "live agent-1 cred-2"]


@pytest.mark.parametrize(
    ("error", "refusal"),
    [
        (AgentNotFoundError("gone"), (401, "reconnect credential is unavailable")),
        (CredentialNotFoundError("gone"), (401, "reconnect credential is unavailable")),
        (AgentAccessFrozenError("frozen"), (503, "agent access is unavailable")),
        (StorageError("disk"), (503, "agent access is unavailable")),
    ],
)
async def test_a_reissued_credential_revoked_meanwhile_is_never_sent(
    reconnecting: Gateway, error: Exception, refusal: tuple[int, str],
) -> None:
    reconnecting.handler.before_response = _issue_credential
    reconnecting.world.fail("live agent-1 cred-2", error)

    reply = await _redeem(reconnecting)

    assert reply.refusal == refusal
    assert b"handled" not in reply.body
    assert len(reply.sent) == 2


# -- service principals -------------------------------------------------------

SPN_KEY = "spn-key"
SPN_UNAVAILABLE = (503, "service principal access is unavailable")


@pytest.fixture
def principal(gateway: Gateway) -> Gateway:
    gateway.world.principals[SPN_KEY] = ServicePrincipalIdentity(
        spn_id="spn-1", spn_name="deployer", agent_name_prefix="fleet",
        credential_id="spn-cred-1", credential_kind="sbsp1",
    )
    gateway.world.active_principals.add("spn-cred-1")
    return gateway


async def _onboard(gateway: Gateway, **kwargs: Any) -> Any:
    kwargs.setdefault("token", SPN_KEY)
    kwargs.setdefault("headers", (JSON,))
    if "messages" not in kwargs:
        kwargs.setdefault("body", b"{}")
    return await gateway.call("POST", "/api/spn/onboarding-packages", **kwargs)


async def test_a_service_principal_is_authenticated_limited_and_freeze_checked(
    principal: Gateway,
) -> None:
    reply = await _onboard(principal)

    assert reply.status == 200
    assert principal.handler.state == {"spn_identity": principal.world.principals[SPN_KEY]}
    assert principal.world.calls[:4] == [
        "spn-authorize", "limit spn:spn-1 6", "freeze", "handler",
    ]
    # Both are re-checked, together, when the response starts.
    assert sorted(principal.world.calls[4:]) == ["freeze", "spn-active"]


@pytest.mark.parametrize(
    ("token", "detail"),
    [
        (None, "service principal authentication required"),
        ("wrong", "invalid service principal credential"),
        # An agent key is not a service principal credential.
        (AGENT_KEY, "invalid service principal credential"),
    ],
)
async def test_an_unauthenticated_service_principal_is_challenged_and_source_limited(
    principal: Gateway, token: str | None, detail: str,
) -> None:
    reply = await _onboard(principal, token=token, messages=[])
    principal.world.limited.add(f"source:{CLIENT}")
    limited = await _onboard(principal, token=token, messages=[])

    assert reply.refusal == (401, detail)
    assert reply.headers["www-authenticate"] == "Bearer"
    assert limited.refusal == (429, "request rate limit exceeded")
    assert principal.world.steps("authorize", "freeze", "handler") == []


async def test_service_principal_authentication_fails_closed(principal: Gateway) -> None:
    principal.world.fail("spn-authorize", StorageError("disk"))

    reply = await _onboard(principal, messages=[])

    assert reply.refusal == SPN_UNAVAILABLE
    assert principal.world.calls == ["spn-authorize"]


async def test_each_service_principal_has_its_own_issue_limit(principal: Gateway) -> None:
    principal.world.limited.add("spn:spn-1")

    reply = await _onboard(principal, messages=[])

    assert reply.refusal == (429, "request rate limit exceeded")
    assert "freeze" not in principal.world.calls


@pytest.mark.parametrize(
    ("cause", "refusal"),
    [("frozen", (503, "agent access is frozen")), ("unreadable", SPN_UNAVAILABLE)],
)
async def test_a_service_principal_issues_nothing_while_frozen(
    principal: Gateway, cause: str, refusal: tuple[int, str],
) -> None:
    if cause == "frozen":
        principal.world.frozen = True
    else:
        principal.world.fail("freeze", StorageError("disk"))

    reply = await _onboard(principal, messages=[])

    assert reply.refusal == refusal
    assert principal.scope.get("state") is None


async def test_service_principal_requests_must_be_small_json(principal: Gateway) -> None:
    not_json = await _onboard(principal, headers=(("content-type", "text/plain"),), messages=[])
    state_after_refusal = principal.scope.get("state")
    at_cap = await _onboard(principal, body=b"x" * 4096)
    too_large = await _onboard(principal, body=b"x" * 4097)

    assert not_json.refusal == (415, "SPN onboarding JSON content type required")
    assert state_after_refusal is None
    assert at_cap.status == 200
    assert too_large.refusal == (413, "request body too large")


@pytest.mark.parametrize(
    ("cause", "refusal"),
    [
        ("revoked", (401, "service principal credential is unavailable")),
        ("frozen", (503, "agent access is frozen")),
        ("unreadable", SPN_UNAVAILABLE),
    ],
)
async def test_a_package_is_withheld_when_the_principal_lost_authority_meanwhile(
    principal: Gateway, cause: str, refusal: tuple[int, str],
) -> None:
    def lose_authority(scope: dict[str, Any]) -> None:
        if cause == "revoked":
            principal.world.active_principals.clear()
        elif cause == "frozen":
            principal.world.frozen = True
        else:
            principal.world.fail("spn-active", StorageError("disk"))

    principal.handler.before_response = lose_authority

    reply = await _onboard(principal)

    assert reply.refusal == refusal
    assert b"handled" not in reply.body
    assert len(reply.sent) == 2


async def test_a_self_rotation_is_guarded_by_the_successor_credential(principal: Gateway) -> None:
    def rotate(scope: dict[str, Any]) -> None:
        # Rotation revokes the credential that authorized the request.
        principal.world.active_principals.clear()
        principal.world.active_principals.add("spn-cred-2")
        scope["state"]["spn_rotated_to"] = "spn-cred-2"

    principal.handler.before_response = rotate

    reply = await principal.call(
        "POST", "/api/spn/credentials/rotate", token=SPN_KEY, headers=(JSON,), body=b"{}",
    )

    assert reply.status == 200
    checked = principal.principals.checked[-1]
    assert (checked.spn_id, checked.credential_id) == ("spn-1", "spn-cred-2")


# -- mobile monitors ------------------------------------------------------------

DEVICE_KEY = "device-key"
MOBILE_UNAVAILABLE = (503, "mobile access is unavailable")


@pytest.fixture
def device(gateway: Gateway) -> Gateway:
    gateway.world.devices[DEVICE_KEY] = SimpleNamespace(credential_id="device-1")
    return gateway


@pytest.mark.parametrize("frozen", [False, True])
async def test_a_monitor_keeps_reading_while_frozen_and_is_told_the_state(
    device: Gateway, frozen: bool,
) -> None:
    device.world.frozen = frozen

    reply = await device.call("GET", "/api/mobile/status", token=DEVICE_KEY)

    assert reply.status == 200
    assert device.handler.state == {
        "mobile_identity": device.world.devices[DEVICE_KEY], "mobile_frozen": frozen,
    }
    # No agent proof, no receipt: a monitor holds no coordination authority.
    assert device.world.calls == [
        "mobile-authorize", "limit mobile:device-1 600", "freeze", "handler",
    ]


async def test_containment_writes_reach_their_route_while_frozen(device: Gateway) -> None:
    device.world.frozen = True
    body = b"x" * 100

    reply = await device.call("POST", "/api/mobile/actions", token=DEVICE_KEY, body=body)

    assert reply.status == 200
    assert device.handler.state["mobile_frozen"] is True
    # The route applies its own bound; the gateway does not buffer this body.
    assert device.handler.body == body


@pytest.mark.parametrize(
    ("token", "detail"),
    [
        (None, "mobile authentication required"),
        ("wrong", "invalid mobile credential"),
        # An agent key cannot stand in for a device credential.
        (AGENT_KEY, "invalid mobile credential"),
    ],
)
async def test_an_unauthenticated_monitor_is_challenged_and_source_limited(
    device: Gateway, token: str | None, detail: str,
) -> None:
    reply = await device.call("GET", "/api/mobile/snapshot", token=token)
    device.world.limited.add(f"source:{CLIENT}")
    limited = await device.call("GET", "/api/mobile/snapshot", token=token)

    assert reply.refusal == (401, detail)
    assert reply.headers["www-authenticate"] == "Bearer"
    assert limited.refusal == (429, "request rate limit exceeded")
    assert device.world.steps("authorize", "freeze", "handler") == []


@pytest.mark.parametrize("cause", ["no-service", "authorize", "freeze"])
async def test_mobile_access_fails_closed(device: Gateway, cause: str) -> None:
    if cause == "no-service":
        del device.state.mobile_service
    elif cause == "authorize":
        device.world.fail("mobile-authorize", StorageError("disk"))
    else:
        device.world.fail("freeze", StorageError("disk"))

    reply = await device.call("GET", "/api/mobile/status", token=DEVICE_KEY)

    assert reply.refusal == MOBILE_UNAVAILABLE
    assert not device.handler.reached
    assert device.scope.get("state") is None


async def test_each_device_has_its_own_request_limit(device: Gateway) -> None:
    device.world.limited.add("mobile:device-1")

    reply = await device.call("GET", "/api/mobile/status", token=DEVICE_KEY)

    assert reply.refusal == (429, "request rate limit exceeded")
    assert "freeze" not in device.world.calls


# -- satellite sites on the agent plane ---------------------------------------


async def test_an_admitted_site_uses_the_agent_plane_like_any_agent(gateway: Gateway) -> None:
    rest = await gateway.site_call("GET", "/api/channels", token=AGENT_KEY)
    mcp = await gateway.site_call("POST", "/mcp", token=AGENT_KEY)

    assert (rest.status, mcp.status) == (200, 200)


@pytest.mark.parametrize(
    ("method", "path", "token"),
    [
        ("POST", "/api/agents", "admin-secret"),
        ("GET", "/api/mobile/status", "device-key"),
        ("POST", "/api/mobile/enrollments/redeem", MOBILE_ENROLLMENT),
        ("POST", "/api/spn/onboarding-packages", "spn-key"),
    ],
)
async def test_a_site_cannot_reach_admin_mobile_or_service_principal_routes(
    gateway: Gateway, method: str, path: str, token: str,
) -> None:
    gateway.world.devices["device-key"] = SimpleNamespace(credential_id="device-1")

    reply = await gateway.site_call(method, path, token=token, headers=(JSON,))

    assert reply.refusal == (403, "satellite sites reach agent routes only")
    # The credential it presented was never examined.
    assert gateway.world.calls == [f"site-admits {SITE}"]


async def test_satellite_routes_exist_only_on_the_satellite_path(gateway: Gateway) -> None:
    reply = await gateway.call("GET", "/api/satellite/release", token=AGENT_KEY)

    assert reply.refusal == (403, "satellite path required")
    assert gateway.world.calls == []


async def test_the_admitted_site_is_the_whole_authority_on_satellite_routes(
    gateway: Gateway,
) -> None:
    reply = await gateway.site_call("POST", "/api/satellite/renew", body=b"csr")

    assert reply.status == 200
    assert gateway.handler.state == {"satellite_site": SITE}
    assert gateway.handler.body == b"csr"
    assert gateway.world.calls == [f"site-admits {SITE}", f"limit site:{SITE} 600", "handler"]


async def test_satellite_routes_are_limited_per_site_and_bounded(gateway: Gateway) -> None:
    at_cap = await gateway.site_call("POST", "/api/satellite/renew", body=b"x" * 8192)
    too_large = await gateway.site_call("POST", "/api/satellite/renew", body=b"x" * 8193)
    gateway.world.limited.add(f"site:{SITE}")
    limited = await gateway.site_call("POST", "/api/satellite/renew", body=b"csr")

    assert at_cap.status == 200
    assert too_large.refusal == (413, "request body too large")
    assert limited.refusal == (429, "request rate limit exceeded")
    assert limited.headers["retry-after"] == "7"


# -- the audit feed -------------------------------------------------------------


@pytest.fixture
def audit() -> Iterator[list[dict[str, Any]]]:
    """Every line the gateway hands to the SIEM feed, parsed."""

    lines: list[dict[str, Any]] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(json.loads(record.getMessage().removeprefix(audit_feed.PREFIX)))

    logger = audit_feed.LOGGER
    capture, level = Capture(), logger.level
    logger.addHandler(capture)
    logger.setLevel(logging.INFO)
    try:
        yield lines
    finally:
        logger.removeHandler(capture)
        logger.setLevel(level)


async def test_ordinary_successful_requests_are_not_audited(
    gateway: Gateway, audit: list[dict[str, Any]],
) -> None:
    await gateway.call("GET", "/api/channels", token=AGENT_KEY)
    await gateway.call("GET", "/healthz")
    await gateway.console("GET", "/activity")

    assert audit == []


@pytest.mark.parametrize(
    ("method", "path", "event", "status"),
    [
        ("GET", "/api/channels", "GET /api/channels", 401),
        ("GET", "/api/channels/secret-project/messages", "GET /api/channels/{name}/messages", 401),
        ("POST", "/mcp", "POST /mcp", 401),
        ("POST", "/mcp/anything", "POST /mcp", 401),
        ("GET", "/api/undeclared", "GET other", 403),
        ("POST", "/register", "POST other", 401),
    ],
)
async def test_every_refused_request_is_audited_by_route_template_not_raw_path(
    gateway: Gateway, audit: list[dict[str, Any]],
    method: str, path: str, event: str, status: int,
) -> None:
    await gateway.call(
        method, path, client=(PROXY, 1), headers=(("x-forwarded-for", "203.0.113.9"),),
    )

    [line] = audit
    assert (line["table"], line["event"], line["status"], line["outcome"]) == (
        "request", event, status, "refused",
    )
    assert line["remote_address"] == "203.0.113.9"
    assert line["spn_id"] is None


async def test_rate_limit_refusals_are_audited(
    gateway: Gateway, audit: list[dict[str, Any]],
) -> None:
    gateway.world.limited.add("credential:cred-1")

    await gateway.call("GET", "/api/channels", token=AGENT_KEY)

    [line] = audit
    assert (line["event"], line["status"]) == ("GET /api/channels", 429)


@pytest.mark.parametrize(
    ("method", "path", "token", "event"),
    [
        ("POST", "/api/agents", "admin-secret", "POST /api/agents"),
        ("POST", "/api/enrollments/redeem", ENROLLMENT, "POST /api/enrollments/redeem"),
        ("POST", "/api/mobile/enrollments/redeem", MOBILE_ENROLLMENT,
         "POST /api/mobile/enrollments/redeem"),
        ("POST", "/api/credentials/prove", AGENT_KEY, "POST /api/credentials/prove"),
        ("POST", "/api/credentials/rotate", AGENT_KEY, "POST /api/credentials/rotate"),
        ("POST", "/api/credentials/cred-9/retire", AGENT_KEY,
         "POST /api/credentials/{credential_id}/retire"),
    ],
)
async def test_lifecycle_requests_are_audited_even_when_they_succeed(
    gateway: Gateway, audit: list[dict[str, Any]],
    method: str, path: str, token: str, event: str,
) -> None:
    reply = await gateway.call(method, path, token=token, body=b"{}")

    assert reply.status == 200
    [line] = audit
    assert (line["event"], line["status"], line["outcome"]) == (event, 200, "ok")
    assert line["remote_address"] == CLIENT


async def test_a_service_principal_request_is_audited_with_its_principal(
    principal: Gateway, audit: list[dict[str, Any]],
) -> None:
    await _onboard(principal)

    [line] = audit
    assert (line["event"], line["status"], line["spn_id"]) == (
        "POST /api/spn/onboarding-packages", 200, "spn-1",
    )


async def test_a_reconnect_is_audited_and_a_request_with_no_response_is_not(
    reconnecting: Gateway, audit: list[dict[str, Any]],
) -> None:
    await _redeem(reconnecting, messages=[{"type": "http.disconnect"}])
    assert audit == []

    await _redeem(reconnecting)

    [line] = audit
    assert (line["event"], line["status"]) == ("POST /api/reconnect/redeem", 200)


async def test_a_request_is_audited_even_when_its_handler_raises(
    gateway: Gateway, audit: list[dict[str, Any]],
) -> None:
    gateway.handler.error_after_start = StorageError("disk")

    with pytest.raises(StorageError):
        await gateway.call("POST", "/api/agents", token="admin-secret", body=b"{}")

    [line] = audit
    assert (line["event"], line["status"]) == ("POST /api/agents", 200)
