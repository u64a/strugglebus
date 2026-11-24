"""The site document store: the bus keeps signed bytes and returns them unchanged.

It never verifies or reads a document, so these tests are about three things:
the bytes come back exactly, a serial cannot go backwards, and only an operator
device holding its write grant can publish.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime

import pytest

from strugglebus.errors import ConfigurationError
from strugglebus.site_documents import (
    MAX_DOCUMENT_BYTES,
    decode_document,
    validate_document_name,
)
from test_mobile_write_path import _auth, _grant, surface  # noqa: F401

FLEET = "/api/mobile/site-documents/fleet"
SIGNATURE = (
    "-----BEGIN SSH SIGNATURE-----\n"
    "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg\n"
    "AAAAEXN0cnVnZ2xlYnVzLWZsZWV0AAAAAAAAAAZzaGE1MTI=\n"
    "-----END SSH SIGNATURE-----\n"
)
FINGERPRINT = "SHA256:" + "A" * 43
# Bytes a careless store would damage: CRLF, a trailing space, non-ASCII, no final newline.
BODY = "serial = 1\r\nowner = \"café\" \r\n[[host]]\nname = \"host-office1-host\"".encode("utf-8")


def _agent_key(agents, name: str) -> str:
    """A proved agent's key: what a worker host's own agent holds."""

    created = agents.create_agent(name)
    identity = agents.authorize(created.api_key)
    agents.prove(
        identity,
        request_id=str(uuid.uuid4()),
        expected_agent_id=identity.agent.id,
        expected_agent_name=identity.agent.name,
        expected_credential_epoch=identity.agent.credential_epoch,
        expected_credential_version=identity.credential.version,
    )
    return created.api_key


def _publish(client, secret, grant, *, serial=1, body=BODY, signature=SIGNATURE, **extra):
    return client.post(
        FLEET,
        json={
            "serial": serial, "body": base64.b64encode(body).decode("ascii"),
            "signature": signature, "signer_fingerprint": FINGERPRINT,
            "reason": "add a host", "grant_secret": grant, **extra,
        },
        headers=_auth(secret),
    )


def test_a_published_document_comes_back_byte_for_byte(surface) -> None:
    client, secret, agents, store = surface
    grant = _grant(client, secret)
    assert client.get(FLEET, headers=_auth(secret)).status_code == 404

    published = _publish(client, secret, grant)
    assert published.status_code == 201, published.text
    stored = published.json()
    assert (stored["name"], stored["serial"], stored["signer_fingerprint"]) == ("fleet", 1, FINGERPRINT)
    assert base64.b64decode(stored["body"]) == BODY
    assert stored["signature"] == SIGNATURE

    # The operator's device and an enrolled agent read the same thing.
    assert client.get(FLEET, headers=_auth(secret)).json() == stored
    agent_key = _agent_key(agents, "host-office1-host")
    read = client.get("/api/site-documents/fleet", headers=_auth(agent_key))
    assert read.status_code == 200, read.text
    assert read.json() == stored

    with sqlite3.connect(store.database_path) as connection:
        audit = connection.execute(
            "SELECT name, serial, body_sha256, signer_fingerprint, actor_id, reason FROM site_document_audit",
        ).fetchall()
    assert audit == [("fleet", 1, hashlib.sha256(BODY).hexdigest(), FINGERPRINT, "device:phone-one", "add a host")]


def test_a_serial_must_rise(surface) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)
    assert _publish(client, secret, grant, serial=5).status_code == 201

    for stale in (5, 4, 1):
        refused = _publish(client, secret, grant, serial=stale, body=b"older")
        assert refused.status_code == 409 and "serial 5" in refused.json()["detail"]
    assert base64.b64decode(client.get(FLEET, headers=_auth(secret)).json()["body"]) == BODY

    assert _publish(client, secret, grant, serial=6, body=b"newer").status_code == 201
    current = client.get(FLEET, headers=_auth(secret)).json()
    assert (current["serial"], base64.b64decode(current["body"])) == (6, b"newer")


def test_the_database_itself_refuses_a_serial_that_does_not_rise_or_a_delete(surface) -> None:
    client, secret, _agents, store = surface
    assert _publish(client, secret, _grant(client, secret), serial=3).status_code == 201
    with sqlite3.connect(store.database_path) as connection:
        for statement in (
            "UPDATE site_documents SET serial = 3",
            "UPDATE site_documents SET serial = 2",
            "DELETE FROM site_documents",
            "DELETE FROM site_document_audit",
            "UPDATE site_document_audit SET reason = 'rewritten'",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)


def test_publishing_needs_the_device_and_its_write_grant(surface) -> None:
    client, secret, agents, _store = surface
    grant = _grant(client, secret)
    agent_key = _agent_key(agents, "curious-agent")

    assert _publish(client, secret, "wrong-grant").status_code == 401
    assert _publish(client, agent_key, grant).status_code in {401, 403}
    assert client.post(FLEET, json={}).status_code == 401
    assert client.get(FLEET).status_code == 401
    assert client.get("/api/site-documents/fleet").status_code == 401
    # An agent cannot use the device's read route, nor a device the agent's.
    assert client.get(FLEET, headers=_auth(agent_key)).status_code in {401, 403}
    assert client.get("/api/site-documents/fleet", headers=_auth(secret)).status_code in {401, 403}
    assert client.get(FLEET, headers=_auth(secret)).status_code == 404


@pytest.mark.parametrize("change", [
    {"signature": "not a signature"},
    {"signature": SIGNATURE.replace("BEGIN SSH SIGNATURE", "BEGIN PGP SIGNATURE")},
    {"signature": SIGNATURE + "trailing"},
    {"signer_fingerprint": "MD5:00:11"},
    {"body": "not base64 !!"},
    {"serial": 0},
    {"serial": 2**60},
    {"reason": " padded "},
])
def test_what_is_not_a_document_is_refused(surface, change) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)
    body = {
        "serial": 1, "body": base64.b64encode(BODY).decode("ascii"), "signature": SIGNATURE,
        "signer_fingerprint": FINGERPRINT, "reason": "add a host", "grant_secret": grant, **change,
    }
    assert client.post(FLEET, json=body, headers=_auth(secret)).status_code == 422
    assert client.get(FLEET, headers=_auth(secret)).status_code == 404


def test_only_the_fleet_document_exists_and_it_has_a_size_limit(surface) -> None:
    client, secret, agents, _store = surface
    grant = _grant(client, secret)
    other = "/api/mobile/site-documents/secrets"
    payload = {
        "serial": 1, "body": base64.b64encode(BODY).decode("ascii"), "signature": SIGNATURE,
        "signer_fingerprint": "", "reason": "x", "grant_secret": grant,
    }
    assert client.post(other, json=payload, headers=_auth(secret)).status_code == 422
    assert client.get(other, headers=_auth(secret)).status_code == 404
    agent_key = _agent_key(agents, "host-lab2-host")
    assert client.get("/api/site-documents/secrets", headers=_auth(agent_key)).status_code == 404
    assert client.get("/api/site-documents/fleet", headers=_auth(agent_key)).status_code == 404

    assert _publish(client, secret, grant, body=b"x" * MAX_DOCUMENT_BYTES, signer_fingerprint="").status_code == 201
    too_big = _publish(client, secret, grant, serial=2, body=b"x" * (MAX_DOCUMENT_BYTES + 1))
    assert too_big.status_code == 422


def test_a_signature_with_windows_line_endings_is_stored_with_unix_ones(surface) -> None:
    client, secret, _agents, _store = surface
    published = _publish(client, secret, _grant(client, secret), signature=SIGNATURE.replace("\n", "\r\n"))
    assert published.status_code == 201, published.text
    assert published.json()["signature"] == SIGNATURE


def test_a_fleet_can_be_published_and_read_by_the_operator_while_frozen(surface) -> None:
    client, secret, agents, store = surface
    grant = _grant(client, secret)
    agent_key = _agent_key(agents, "host-office1-host")
    store.set_access_freeze(frozen=True, reason="incident", changed_at=datetime.now(UTC))

    assert _publish(client, secret, grant, serial=9).status_code == 201
    assert client.get(FLEET, headers=_auth(secret)).json()["serial"] == 9
    # The agent plane is frozen, so a host keeps the last copy it accepted.
    assert client.get("/api/site-documents/fleet", headers=_auth(agent_key)).status_code in {401, 403, 503}


def test_the_validators_stand_alone() -> None:
    assert validate_document_name("fleet") == "fleet"
    for name in ("", "Fleet", "fleet2", "../fleet"):
        with pytest.raises(ConfigurationError):
            validate_document_name(name)
    assert decode_document(base64.b64encode(b"\x00\xff").decode()) == b"\x00\xff"
    for bad in ("", "====", base64.b64encode(b"").decode()):
        with pytest.raises(ConfigurationError):
            decode_document(bad)


def test_the_operators_log_names_the_host_and_the_document(surface) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)
    minted = client.post(
        "/api/mobile/enrollments/hosts",
        json={
            "request_id": str(uuid.uuid4()), "host_prefix": "host-office1",
            "reason": "new worker host", "grant_secret": grant,
        },
        headers=_auth(secret),
    )
    assert minted.status_code == 201, minted.text
    assert _publish(client, secret, grant, serial=7).status_code == 201

    entries = client.get("/api/mobile/admin/logs", headers=_auth(secret)).json()["entries"]
    by_event = {entry["event"]: entry for entry in entries}
    assert by_event["host-code-minted"]["subject"] == "host-office1"
    assert by_event["host-code-minted"]["detail"] == "host enrollments"
    assert by_event["site-document-stored"]["subject"] == "fleet serial 7"
    assert minted.json()["code"] not in json.dumps(entries)
