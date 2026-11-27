"""Host enrolment codes: how a worker host joins the bus as its own service principal.

The redeem call is the one route here that takes no credential beyond the code
itself, so most of these tests are about what it refuses and what it gives away.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from strugglebus.auth import (
    HOST_ENROLLMENT_PREFIX,
    mint_host_enrollment_token,
    parse_credential,
    parse_host_enrollment_token,
    parse_spn_credential,
)
from strugglebus.errors import ConfigurationError
from strugglebus.host_enrollment import (
    HostEnrollmentService,
    confirmation_code,
    validate_host_prefix,
)
from strugglebus.migrations import LATEST_SCHEMA_VERSION
from strugglebus.store._host_enrollment import MAX_PENDING_HOST_ENROLLMENTS
from test_mobile_write_path import _auth, _grant, surface  # noqa: F401

REDEEM = "/api/hosts/enrollments/redeem"
MINT = "/api/mobile/enrollments/hosts"


def _stamp(ago: timedelta) -> str:
    return (datetime.now(UTC) - ago).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _mint(client, secret, grant, prefix="host-office1", request_id=None):
    return client.post(
        MINT,
        json={
            "request_id": request_id or str(uuid.uuid4()), "host_prefix": prefix,
            "reason": "new worker host", "grant_secret": grant,
        },
        headers=_auth(secret),
    )


def _redeem(client, code, request_id=None):
    return client.post(
        REDEEM, json={"request_id": request_id or str(uuid.uuid4())}, headers=_auth(code),
    )


def _code(client, secret, grant, prefix="host-office1") -> str:
    minted = _mint(client, secret, grant, prefix)
    assert minted.status_code == 201, minted.text
    return minted.json()["code"]


def test_schema_twenty_four_adds_the_worker_host_tables(surface) -> None:
    _client, _secret, _agents, store = surface
    assert LATEST_SCHEMA_VERSION == 25
    with sqlite3.connect(store.database_path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"host_enrollments", "site_documents", "site_document_audit"} <= tables


def test_a_host_code_is_its_own_kind_of_token() -> None:
    enrollment_id, verifier, code = mint_host_enrollment_token()
    assert code.startswith(HOST_ENROLLMENT_PREFIX) and enrollment_id.startswith("hen_")
    assert parse_host_enrollment_token(code) == (enrollment_id, verifier)
    assert parse_credential(code) is None and parse_spn_credential(code) is None
    for other in ("", "sbhe1_short", code + "x", code.replace("sbhe1_", "sbe1_"), None, 7):
        assert parse_host_enrollment_token(other) is None


@pytest.mark.parametrize("typed,stored", [
    ("host-office1", "host-office1"), ("  Host-Office1 ", "host-office1"), ("ab", "ab"),
    ("host-" + "a" * 26, "host-" + "a" * 26),
])
def test_host_names_the_bus_accepts(typed, stored) -> None:
    assert validate_host_prefix(typed) == stored


@pytest.mark.parametrize("typed", [
    "", "a", "host-", "-host", "host--one", "host_one", "host one", "host.one",
    "host-" + "a" * 27, None, 7,
])
def test_host_names_the_bus_refuses(typed) -> None:
    with pytest.raises(ConfigurationError):
        validate_host_prefix(typed)


def test_the_confirmation_code_is_eight_hex_of_agent_id_then_request_id() -> None:
    import hashlib

    agent_id, request_id = "3b283d99-7521-4216-aceb-d39e6b5d5402", "11111111-2222-4333-8444-555555555555"
    expected = hashlib.sha256(f"{agent_id}\n{request_id}".encode()).hexdigest()[:8]
    assert confirmation_code(agent_id, request_id) == expected == "6be98e36"
    assert confirmation_code(agent_id, request_id) != confirmation_code(request_id, agent_id)


def test_a_host_joins_with_its_code_and_becomes_a_service_principal(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    minted = _mint(client, secret, grant, " Host-Office1 ")
    assert minted.status_code == 201, minted.text
    body = minted.json()
    assert (body["host_prefix"], body["code_issued"]) == ("host-office1", True)
    assert minted.headers["cache-control"] == "no-store"
    assert body["code"] not in store.database_path.read_bytes().decode("latin-1")

    request_id = str(uuid.uuid4())
    redeemed = _redeem(client, body["code"], request_id)
    assert redeemed.status_code == 201, redeemed.text
    assert redeemed.headers["cache-control"] == "no-store"
    answer = redeemed.json()
    assert (answer["name"], answer["request_id"]) == ("host-office1", request_id)
    assert parse_spn_credential(answer["credential"]) is not None

    # It is an ordinary service principal now: listed, and the operator can see
    # which request and address redeemed the code.
    listed = client.get("/api/mobile/admin/service-principals", headers=_auth(secret)).json()
    host = next(item for item in listed if item["name"] == "host-office1")
    assert (host["agent_name_prefix"], host["status"]) == ("host-office1", "enabled")
    assert host["host_redeem_request_id"] == request_id
    assert host["host_redeemed_from"] and host["host_redeemed_at"]
    assert client.app.state.spn_service.authorize(answer["credential"]) is not None


def test_the_same_request_again_replaces_the_credential_and_any_other_is_refused(surface) -> None:
    client, secret, _agents, _store = surface
    code = _code(client, secret, _grant(client, secret))
    request_id = str(uuid.uuid4())
    first = _redeem(client, code, request_id).json()["credential"]

    again = _redeem(client, code, request_id)
    assert again.status_code == 200, again.text
    second = again.json()["credential"]
    assert second != first and again.json()["name"] == "host-office1"
    spn = client.app.state.spn_service
    assert spn.authorize(first) is None
    assert spn.authorize(second) is not None

    stranger = _redeem(client, code)
    assert (stranger.status_code, stranger.json()) == (404, {"detail": "unknown-or-used-code"})
    assert spn.authorize(second) is not None


def test_nothing_is_learned_without_the_right_code(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    code = _code(client, secret, grant)
    _id, _verifier, unknown = mint_host_enrollment_token()
    # The right code id with the wrong secret.
    # A code is "sbhe1_", a 22-character id, "_" and a 43-character secret.
    forged = code[:29] + unknown[29:]
    assert forged != code and parse_host_enrollment_token(forged)[0] == parse_host_enrollment_token(code)[0]

    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP TRIGGER host_enrollments_identity_immutable")
        connection.execute(
            "UPDATE host_enrollments SET created_at = ?, expires_at = ?",
            (_stamp(timedelta(minutes=20)), _stamp(timedelta(seconds=1))),
        )
    for wrong in (unknown, forged):
        refused = _redeem(client, wrong)
        assert (refused.status_code, refused.json()) == (404, {"detail": "unknown-or-used-code"})
    # Only the holder of the real code is told it has expired.
    expired = _redeem(client, code)
    assert (expired.status_code, expired.json()) == (410, {"detail": "expired"})

    for headers in ({}, _auth("not-a-code"), _auth(secret)):
        missing = client.post(REDEEM, json={"request_id": str(uuid.uuid4())}, headers=headers)
        assert missing.status_code == 401
    assert _redeem(client, code, "not-a-uuid").status_code == 422


def test_a_redeemed_code_cannot_be_replayed_after_it_expires(surface) -> None:
    client, secret, _agents, store = surface
    code = _code(client, secret, _grant(client, secret))
    request_id = str(uuid.uuid4())
    assert _redeem(client, code, request_id).status_code == 201
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP TRIGGER host_enrollments_identity_immutable")
        connection.execute(
            "UPDATE host_enrollments SET created_at = ?, expires_at = ?",
            (_stamp(timedelta(minutes=20)), _stamp(timedelta(seconds=1))),
        )
    late = _redeem(client, code, request_id)
    assert (late.status_code, late.json()) == (404, {"detail": "unknown-or-used-code"})


def test_a_blocked_host_cannot_get_a_new_credential_by_asking_again(surface) -> None:
    client, secret, _agents, store = surface
    code = _code(client, secret, _grant(client, secret))
    request_id = str(uuid.uuid4())
    credential = _redeem(client, code, request_id).json()["credential"]
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE spn_principals SET status = 'blocked', blocked_at = created_at WHERE name = 'host-office1'",
        )
    assert _redeem(client, code, request_id).status_code == 404
    assert client.app.state.spn_service.authorize(credential) is None


def test_minting_again_replaces_the_earlier_code_and_a_taken_name_is_refused(surface) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)
    first = _code(client, secret, grant)
    second = _code(client, secret, grant)

    assert _redeem(client, first).status_code == 404
    assert _redeem(client, second).status_code == 201

    taken = _mint(client, secret, grant)
    assert taken.status_code == 409 and "already registered" in taken.json()["detail"]
    # A service principal made by hand takes the name too.
    made = client.post(
        "/api/mobile/enrollments/service-principals",
        json={
            "request_id": str(uuid.uuid4()), "name": "host-lab2", "agent_name_prefix": "host-lab2",
            "reason": "by hand", "grant_secret": grant,
        },
        headers=_auth(secret),
    )
    assert made.status_code == 201, made.text
    assert _mint(client, secret, grant, "host-lab2").status_code == 409


def test_a_name_taken_between_minting_and_redeeming_is_said_only_to_the_code_holder(surface) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)
    code = _code(client, secret, grant, "host-lab3")
    made = client.post(
        "/api/mobile/enrollments/service-principals",
        json={
            "request_id": str(uuid.uuid4()), "name": "host-lab3", "agent_name_prefix": "host-lab3",
            "reason": "raced", "grant_secret": grant,
        },
        headers=_auth(secret),
    )
    assert made.status_code == 201, made.text
    refused = _redeem(client, code)
    assert (refused.status_code, refused.json()) == (409, {"detail": "name-taken"})


def test_minting_needs_the_device_the_grant_and_a_valid_name_and_is_shown_once(surface) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)

    assert _mint(client, secret, "wrong-grant").status_code == 401
    assert client.post(MINT, json={}, headers=_auth("nope")).status_code in {401, 403}
    for bad in ("x", "host_one", "host-", "host-" + "a" * 40):
        assert _mint(client, secret, grant, bad).status_code == 422

    request_id = str(uuid.uuid4())
    first = _mint(client, secret, grant, request_id=request_id)
    replay = _mint(client, secret, grant, request_id=request_id)
    assert first.json()["code"] and replay.status_code == 201
    assert (replay.json()["code_issued"], replay.json()["code"]) == (False, None)
    other = _mint(client, secret, grant, "host-other", request_id=request_id)
    assert other.status_code == 409


def test_codes_are_refused_while_agent_access_is_frozen(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    code = _code(client, secret, grant)
    store.set_access_freeze(frozen=True, reason="test freeze", changed_at=datetime.now(UTC))

    assert _mint(client, secret, grant, "host-later").status_code == 503
    frozen = _redeem(client, code)
    assert frozen.status_code == 503 and frozen.json() == {"detail": "unavailable"}

    store.set_access_freeze(frozen=False, reason="test thaw", changed_at=datetime.now(UTC))
    assert _redeem(client, code).status_code == 201


def test_only_so_many_codes_can_be_waiting_at_once(surface) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)
    for index in range(MAX_PENDING_HOST_ENROLLMENTS):
        assert _mint(client, secret, grant, f"host-n{index}").status_code == 201
    full = _mint(client, secret, grant, "host-one-more")
    assert full.status_code == 409 and "waiting" in full.json()["detail"]


def test_the_redeem_route_is_rate_limited_by_source(surface) -> None:
    client, _secret, _agents, _store = surface
    _id, _verifier, unknown = mint_host_enrollment_token()
    limit = client.app.state.config.unauthenticated_requests_per_minute
    statuses = [_redeem(client, unknown).status_code for _ in range(limit + 2)]
    assert statuses[0] == 404 and statuses[-1] == 429


def test_the_service_refuses_a_lifetime_longer_than_fifteen_minutes(surface) -> None:
    _client, _secret, _agents, store = surface
    for seconds in (59, 901, "900", True):
        with pytest.raises(ConfigurationError):
            HostEnrollmentService(store, code_seconds=seconds)
    assert HostEnrollmentService(store, code_seconds=60).code_seconds == 60


def test_a_request_id_that_is_not_canonical_is_a_bad_request(surface) -> None:
    client, secret, _agents, _store = surface
    code = _code(client, secret, _grant(client, secret))
    shouted = _redeem(client, code, str(uuid.uuid4()).upper())
    assert (shouted.status_code, shouted.json()) == (400, {"detail": "bad-request"})
    # The code was not burned by the bad request.
    assert _redeem(client, code).status_code == 201
