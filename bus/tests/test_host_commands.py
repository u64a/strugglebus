"""Carrying a signed host command: the one operator post allowed outside #humans.

The bus does not read or verify a command, so these tests pin what it will
carry, and that the exception to "the operator posts only in #humans" is
exactly this one message shape and nothing wider.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import uuid

import pytest

from strugglebus.service import HOST_COMMAND_BODY, MAX_HOST_COMMAND_BYTES
from strugglebus.store import HUMAN_OPERATOR_AGENT_ID
from test_mobile_write_path import _auth, _grant, surface  # noqa: F401
from test_site_documents import SIGNATURE, _agent_key

COMMANDS = "/api/mobile/hosts/commands"
DOCUMENT = json.dumps({
    "v": 1, "type": "sb-host-command", "host": "host-office1-host", "verb": "pause",
    "nonce": "00112233445566778899aabbccddeeff", "issued_at": "2026-11-24T14:02:11Z",
    "expires_at": "2026-11-24T14:07:11Z",
}, separators=(",", ":")).encode()


@pytest.fixture
def hosts_channel(surface):
    client, secret, agents, store = surface
    key = _agent_key(agents, "host-office1-host")
    made = client.post(
        "/api/channels", json={"name": "worker-hosts", "purpose": "Worker hosts"}, headers=_auth(key),
    )
    assert made.status_code in {200, 201}, made.text
    return client, secret, key, store


def _send(client, secret, grant, *, channel="worker-hosts", document=DOCUMENT, signature=SIGNATURE, request_id=None):
    return client.post(
        COMMANDS,
        json={
            "request_id": request_id or str(uuid.uuid4()), "channel": channel,
            "document": base64.b64encode(document).decode("ascii"), "signature": signature,
            "grant_secret": grant,
        },
        headers=_auth(secret),
    )


def test_a_signed_command_is_carried_to_the_hosts_channel_unchanged(hosts_channel) -> None:
    client, secret, key, _store = hosts_channel
    sent = _send(client, secret, _grant(client, secret))
    assert sent.status_code == 201, sent.text
    message = sent.json()
    assert (message["channel"], message["agent_name"], message["kind"], message["body"]) == (
        "worker-hosts", "human:operator", "question", HOST_COMMAND_BODY,
    )
    carried = message["metadata"]["sb_host_command"]
    assert base64.b64decode(carried["doc"]) == DOCUMENT and carried["sig"] == SIGNATURE

    # The host reads it from its channel with its own agent credential.
    read = client.get("/api/channels/worker-hosts/messages", headers=_auth(key)).json()
    assert read[-1]["metadata"] == message["metadata"]


def test_the_same_request_is_carried_once(hosts_channel) -> None:
    client, secret, _key, _store = hosts_channel
    grant = _grant(client, secret)
    request_id = str(uuid.uuid4())
    first = _send(client, secret, grant, request_id=request_id)
    again = _send(client, secret, grant, request_id=request_id)
    assert first.status_code == 201 and again.status_code == 201
    assert again.json()["seq"] == first.json()["seq"]
    different = _send(client, secret, grant, request_id=request_id, document=b"{}")
    assert different.status_code == 409


def test_the_bus_does_not_read_what_it_carries(hosts_channel) -> None:
    client, secret, _key, _store = hosts_channel
    nonsense = _send(client, secret, _grant(client, secret), document=b"\x00\xffnot json at all")
    assert nonsense.status_code == 201, nonsense.text


@pytest.mark.parametrize("change", [
    {"document": b""},
    {"document": b"x" * (MAX_HOST_COMMAND_BYTES + 1)},
    {"signature": "trust me"},
    {"signature": SIGNATURE + "extra"},
    {"channel": "Not A Channel!"},
])
def test_what_is_not_a_command_is_refused(hosts_channel, change) -> None:
    client, secret, _key, _store = hosts_channel
    refused = _send(client, secret, _grant(client, secret), **change)
    # An empty document never reaches the service: the request shape refuses it.
    assert refused.status_code in {400, 422}, refused.text
    assert refused.status_code == (422 if change.get("document") == b"" else 400)


def test_base64_must_be_valid_and_the_channel_must_exist(hosts_channel) -> None:
    client, secret, _key, _store = hosts_channel
    grant = _grant(client, secret)
    body = {
        "request_id": str(uuid.uuid4()), "channel": "worker-hosts", "document": "not base64 !!",
        "signature": SIGNATURE, "grant_secret": grant,
    }
    assert client.post(COMMANDS, json=body, headers=_auth(secret)).status_code == 400
    assert _send(client, secret, grant, channel="no-such-channel").status_code == 404


def test_sending_needs_the_device_and_its_write_grant(hosts_channel) -> None:
    client, secret, key, _store = hosts_channel
    grant = _grant(client, secret)
    assert _send(client, secret, "wrong-grant").status_code == 401
    assert _send(client, key, grant).status_code in {401, 403}
    assert client.post(COMMANDS, json={}).status_code == 401


def test_the_operator_still_cannot_post_anything_else_outside_humans(hosts_channel) -> None:
    """The exception is one exact shape. Every near miss is still refused by the database."""

    client, secret, _key, store = hosts_channel
    assert _send(client, secret, _grant(client, secret)).status_code == 201
    meta = json.dumps({"sb_host_command": {"doc": "eA==", "sig": SIGNATURE}})
    near_misses = [
        ("chat", HOST_COMMAND_BODY, meta, None),                       # wrong kind
        ("question", "please pause, thanks", meta, None),              # free text body
        ("question", HOST_COMMAND_BODY, "{}", None),                   # no command
        ("question", HOST_COMMAND_BODY, '{"sb_host_command":"x"}', None),  # not an object
        ("question", HOST_COMMAND_BODY, meta, 1),                      # a reply
    ]
    with sqlite3.connect(store.database_path) as connection:
        channel = connection.execute("SELECT id FROM channels WHERE name = 'worker-hosts'").fetchone()[0]
        for kind, body, metadata, reply_to in near_misses:
            with pytest.raises(sqlite3.IntegrityError, match="only in #humans"):
                connection.execute(
                    "INSERT INTO messages (id, channel_id, agent_id, body, kind, reply_to, meta, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, '2026-11-24T00:00:00.000000Z')",
                    (str(uuid.uuid4()), channel, HUMAN_OPERATOR_AGENT_ID, body, kind, reply_to, metadata),
                )


def test_an_ordinary_operator_post_still_goes_only_to_humans(hosts_channel) -> None:
    client, secret, _key, _store = hosts_channel
    grant = _grant(client, secret)
    posted = client.post(
        "/api/mobile/humans/messages",
        json={"request_id": str(uuid.uuid4()), "body": "hello", "kind": "chat", "grant_secret": grant},
        headers=_auth(secret),
    )
    assert posted.status_code == 201 and posted.json()["channel"] == "humans"
    assert posted.json()["metadata"] == {}


def test_carrying_a_command_writes_an_audit_line_that_says_nothing_about_its_content(hosts_channel) -> None:
    import logging

    from strugglebus import audit_feed

    client, secret, _key, _store = hosts_channel
    lines: list[dict] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(json.loads(record.getMessage().removeprefix(audit_feed.PREFIX)))

    handler = Capture()
    audit_feed.LOGGER.addHandler(handler)
    previous = audit_feed.LOGGER.level
    audit_feed.LOGGER.setLevel(logging.INFO)
    try:
        assert _send(client, secret, _grant(client, secret)).status_code == 201
        assert _send(client, secret, "wrong-grant").status_code == 401
    finally:
        audit_feed.LOGGER.removeHandler(handler)
        audit_feed.LOGGER.setLevel(previous)

    carried = [line for line in lines if line["event"] == "POST /api/mobile/hosts/commands"]
    assert [(line["status"], line["outcome"]) for line in carried] == [(201, "ok"), (401, "refused")]
    assert all(line["remote_address"] for line in carried)
    assert "pause" not in json.dumps(lines) and "host-office1-host" not in json.dumps(lines)
