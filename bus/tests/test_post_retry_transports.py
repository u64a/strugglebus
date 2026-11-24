from __future__ import annotations

import json
import re
import uuid
from dataclasses import replace
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from mcp import ClientSession
from mcp.types import LATEST_PROTOCOL_VERSION

from strugglebus.app import create_app
from test_agent_lifecycle import transition
from test_mcp_integration import (
    RunningServer,
    _activate,
    _mcp_session,
    running_server,
)
from test_rest_api import _agent_addendum, _receipt_payload


CONFLICT = "post request_id conflicts with previously accepted input"
CANONICAL_REQUEST_ID = "abcdef01-2345-6789-abcd-0123456789ab"
MESSAGE_FIELDS = {
    "seq", "id", "channel", "agent_id", "agent_name", "body", "kind",
    "reply_to", "metadata", "created_at",
}
INVALID_KEYS = [
    None, True, False, 1, 1.0, [], {}, [CANONICAL_REQUEST_ID],
    "", " ", CANONICAL_REQUEST_ID.upper(), CANONICAL_REQUEST_ID.replace("-", ""),
    "{" + CANONICAL_REQUEST_ID + "}", "urn:uuid:" + CANONICAL_REQUEST_ID,
    " " + CANONICAL_REQUEST_ID, CANONICAL_REQUEST_ID + " ", CANONICAL_REQUEST_ID + "\n",
    CANONICAL_REQUEST_ID[:-1], CANONICAL_REQUEST_ID + "0", "g" + CANONICAL_REQUEST_ID[1:],
    "-" * 36, "a" * 36, CANONICAL_REQUEST_ID.replace("-", "\u2010"),
    "\uff41" + CANONICAL_REQUEST_ID[1:], CANONICAL_REQUEST_ID[:-1] + "\x00",
]


def _headers(api_key: str) -> dict[str, str]:
    return {"Authorization": "Bearer " + api_key}


def _endpoint(channel: str = "status") -> str:
    return f"/api/channels/{quote(channel, safe='')}/messages"


def _tool_text(result: Any) -> str:
    return " ".join(getattr(item, "text", "") for item in result.content)


async def _post(
    rest: httpx.AsyncClient,
    session: ClientSession,
    transport: str,
    payload: dict[str, Any],
    *,
    channel: str = "status",
) -> dict[str, Any]:
    if transport == "rest":
        response = await rest.post(_endpoint(channel), json=payload)
        assert response.status_code == 201, response.text
        message = response.json()
    else:
        result = await session.call_tool("post", {"channel": channel, **payload})
        assert result.is_error is False, _tool_text(result)
        message = result.structured_content
    assert set(message) == MESSAGE_FIELDS
    return message


def _rpc_post(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "post",
            "arguments": {"channel": "status", **payload},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }


def _rpc_message(response: httpx.Response) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        events = [
            json.loads(line.removeprefix("data: "))
            for line in response.text.splitlines()
            if line.startswith("data: ")
        ]
        assert len(events) == 1
        envelope = events[0]
    else:
        envelope = response.json()
    assert "error" not in envelope
    result = envelope["result"]
    assert not result.get("isError", False), result
    message = result["structuredContent"]
    assert set(message) == MESSAGE_FIELDS
    return message


def _rpc_headers(api_key: str) -> dict[str, str]:
    return {
        **_headers(api_key),
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": LATEST_PROTOCOL_VERSION,
        "Mcp-Method": "tools/call",
        "Mcp-Name": "post",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("first_transport", ["rest", "mcp"])
async def test_keyed_post_replays_full_message_across_transports(
    running_server: RunningServer, first_transport: str,
) -> None:
    async with httpx.AsyncClient(
        base_url=running_server.base_url, headers=_headers(running_server.api_key),
    ) as rest, _mcp_session(running_server, running_server.api_key) as session:
        created = await rest.post("/api/channels", json={"name": "team-updates"})
        assert created.status_code == 201
        root = await _post(rest, session, "rest", {"body": "reply target"},
                           channel="team-updates")
        payload = {
            "request_id": CANONICAL_REQUEST_ID,
            "body": "exact \u00e9\nintent",
            "kind": "answer",
            "reply_to": root["seq"],
            "metadata": {"z": [1, 2], "a": {"y": "\u00e9", "x": True}},
        }
        first = await _post(
            rest, session, first_transport, payload, channel="#Team_Updates",
        )
        equivalent = {
            **payload, "metadata": {"a": {"x": True, "y": "\u00e9"}, "z": [1, 2]},
        }
        other_transport = "mcp" if first_transport == "rest" else "rest"
        replay = await _post(
            rest, session, other_transport, equivalent, channel="team-updates",
        )
        repeated = await _post(
            rest, session, first_transport, payload, channel="team-updates",
        )
        assert first == replay == repeated
        assert first["agent_id"] == running_server.agent_id
        assert first["channel"] == "team-updates"
        after = await _post(rest, session, "rest", {"body": "next"},
                            channel="team-updates")
        assert after["seq"] == first["seq"] + 1
        listing = await rest.get(_endpoint("team-updates"))
        assert listing.json() == [root, first, after]


@pytest.mark.asyncio
async def test_defaults_json_escaping_and_legacy_repeat_compatibility(
    running_server: RunningServer,
) -> None:
    async with httpx.AsyncClient(
        base_url=running_server.base_url, headers=_headers(running_server.api_key),
    ) as rest, _mcp_session(running_server, running_server.api_key) as session:
        payload = {"request_id": CANONICAL_REQUEST_ID, "body": "\u00e9\nintent"}
        response = await rest.post(
            _endpoint(), content=json.dumps(payload, ensure_ascii=True),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 201
        first = response.json()
        replay = await _post(rest, session, "mcp", {
            **payload, "kind": "chat", "reply_to": None, "metadata": {},
        })
        assert first == replay
        legacy = {"body": "intent", "metadata": {"request_id": CANONICAL_REQUEST_ID}}
        messages = [first]
        for transport in ("rest", "rest", "mcp", "mcp"):
            messages.append(await _post(rest, session, transport, legacy))
        for transport in ("rest", "mcp"):
            messages.append(await _post(rest, session, transport, {
                **payload, "request_id": str(uuid.uuid4()),
            }))
        assert len({message["id"] for message in messages}) == len(messages)
        assert [message["seq"] for message in messages] == list(
            range(first["seq"], first["seq"] + len(messages))
        )
        assert (await rest.get(_endpoint())).json() == messages


@pytest.mark.asyncio
async def test_conflicting_valid_intent_is_fixed_safe_error_on_both_transports(
    running_server: RunningServer,
) -> None:
    async with httpx.AsyncClient(
        base_url=running_server.base_url, headers=_headers(running_server.api_key),
    ) as rest, _mcp_session(running_server, running_server.api_key) as session:
        root = await _post(rest, session, "rest", {"body": "reply target"})
        payload = {
            "request_id": CANONICAL_REQUEST_ID, "body": "\u00e9\nintent",
            "metadata": {"array": [1, 2], "value": 1},
        }
        first = await _post(rest, session, "mcp", payload)
        changes = [
            {"body": "\u00e9\nintent "},
            {"body": "\u00e9\r\nintent"},
            {"body": "e\u0301\nintent"},
            {"kind": "question"},
            {"reply_to": root["seq"]},
            {"metadata": {"array": [2, 1], "value": 1}},
            {"metadata": {"array": [1, 2], "value": 1.0}},
            {"metadata": {"array": [1, 2], "value": True}},
            {"metadata": {"array": [1, 2], "value": "1"}},
            {"metadata": {}},
        ]
        for channel, changed in [
            *(("status", change) for change in changes), ("help", {}),
        ]:
            attempted = {**payload, **changed}
            response = await rest.post(_endpoint(channel), json=attempted)
            assert response.status_code == 409, response.text
            assert response.json() == {"detail": CONFLICT}
            result = await session.call_tool(
                "post", {"channel": channel, **attempted},
            )
            assert result.is_error is True
            assert _tool_text(result) == f"Error executing tool post: {CONFLICT}"
            assert result.structured_content is None
        assert await _post(rest, session, "rest", payload) == first
        after = await _post(rest, session, "mcp", {"body": "next"})
        assert after["seq"] == first["seq"] + 1
        assert (await rest.get(_endpoint())).json() == [root, first, after]
        assert (await rest.get(_endpoint("help"))).json() == []


@pytest.mark.asyncio
async def test_request_key_is_scoped_to_stable_agent_not_global_bus(
    running_server: RunningServer,
) -> None:
    other = _activate(
        running_server.agent_service,
        running_server.agent_service.create_agent("independent-retry-agent"),
    )
    payload = {"request_id": CANONICAL_REQUEST_ID, "body": "same intent"}
    async with httpx.AsyncClient(
        base_url=running_server.base_url, headers=_headers(running_server.api_key),
    ) as rest, _mcp_session(running_server, running_server.api_key) as first_session:
        first = await _post(rest, first_session, "rest", payload)
        async with _mcp_session(running_server, other.api_key) as other_session:
            second = await _post(rest, other_session, "mcp", payload)
            assert await _post(rest, other_session, "mcp", payload) == second
        assert await _post(rest, first_session, "mcp", payload) == first
        assert first["agent_id"] != second["agent_id"] == other.agent.id
        assert first["id"] != second["id"]
        assert second["seq"] == first["seq"] + 1


@pytest.mark.asyncio
async def test_replay_does_not_resolve_a_now_revoked_mentioned_recipient(
    running_server: RunningServer,
) -> None:
    recipient = _activate(
        running_server.agent_service,
        running_server.agent_service.create_agent("retry-recipient"),
    )
    payload = {"request_id": CANONICAL_REQUEST_ID, "body": "For @retry-recipient"}
    async with httpx.AsyncClient(
        base_url=running_server.base_url, headers=_headers(running_server.api_key),
    ) as rest, _mcp_session(running_server, running_server.api_key) as session:
        first = await _post(rest, session, "mcp", payload)
        running_server.agent_service.revoke_agent(recipient.agent.id)
        assert await _post(rest, session, "rest", payload) == first
        assert await _post(rest, session, "mcp", payload) == first
        fresh = {**payload, "request_id": str(uuid.uuid4())}
        denied = await rest.post(_endpoint(), json=fresh)
        assert denied.status_code == 400, denied.text
        result = await session.call_tool("post", {"channel": "status", **fresh})
        assert result.is_error is True
        assert "mention" in _tool_text(result)
        assert (await rest.get(_endpoint())).json() == [first]


def _assert_key_schema(schema: dict[str, Any]) -> None:
    assert "request_id" not in schema.get("required", [])
    field = schema["properties"]["request_id"]
    assert field["type"] == "string"
    assert field["minLength"] == field["maxLength"] == 36
    assert "default" not in field
    assert "anyOf" not in field and "oneOf" not in field
    assert re.fullmatch(field["pattern"], CANONICAL_REQUEST_ID)
    for invalid in INVALID_KEYS:
        if isinstance(invalid, str):
            assert re.fullmatch(field["pattern"], invalid) is None, repr(invalid)


@pytest.mark.asyncio
async def test_generated_schemas_and_invalid_key_matrix_match_runtime(
    running_server: RunningServer,
) -> None:
    async with httpx.AsyncClient(
        base_url=running_server.base_url, headers=_headers(running_server.api_key),
    ) as rest, _mcp_session(running_server, running_server.api_key) as session:
        catalog = await session.list_tools()
        post = next(tool for tool in catalog.tools if tool.name == "post")
        _assert_key_schema(post.input_schema)
        assert set(post.output_schema["properties"]) == MESSAGE_FIELDS
        openapi = running_server.application.openapi()
        _assert_key_schema(openapi["components"]["schemas"]["MessageCreate"])
        assert set(openapi["components"]["schemas"]["MessageResponse"]["properties"]) == (
            MESSAGE_FIELDS
        )
        for key in INVALID_KEYS:
            payload = {"request_id": key, "body": "must not be accepted"}
            response = await rest.post(_endpoint(), json=payload)
            assert response.status_code == 422, (repr(key), response.text)
            result = await session.call_tool("post", {"channel": "status", **payload})
            assert result.is_error is True, repr(key)
            assert running_server.api_key not in _tool_text(result)
            assert "sqlite" not in _tool_text(result).lower()
        assert (await rest.get(_endpoint())).json() == []
        accepted = await _post(rest, session, "rest", {
            "request_id": CANONICAL_REQUEST_ID, "body": "canonical accepted",
        })
        assert accepted["seq"] == 1


@pytest.mark.asyncio
async def test_static_input_limits_apply_on_hit_and_miss(
    running_server: RunningServer,
) -> None:
    async with httpx.AsyncClient(
        base_url=running_server.base_url, headers=_headers(running_server.api_key),
    ) as rest, _mcp_session(running_server, running_server.api_key) as session:
        payload = {
            "request_id": CANONICAL_REQUEST_ID, "body": "\u00e9" * 32,
            "metadata": {"x": "v" * 56},
        }
        first = await _post(rest, session, "rest", payload)
        assert await _post(rest, session, "mcp", payload) == first
        nested: dict[str, Any] = {}
        for _ in range(9):
            nested = {"x": nested}
        for key in (CANONICAL_REQUEST_ID, str(uuid.uuid4())):
            for change, expected_status in [
                ({"body": "\u00e9" * 33}, 413),
                ({"body": ""}, 422),
                ({"kind": "invalid"}, 422),
                ({"reply_to": True}, 422),
                ({"metadata": None}, 422),
                ({"metadata": {"x": "v" * 57}}, 400),
                ({"metadata": nested}, 400),
            ]:
                invalid = {**payload, "request_id": key, **change}
                response = await rest.post(_endpoint(), json=invalid)
                assert response.status_code == expected_status, response.text
                result = await session.call_tool("post", {"channel": "status", **invalid})
                assert result.is_error is True
                assert CONFLICT not in _tool_text(result)
        assert (await rest.get(_endpoint())).json() == [first]


@pytest.mark.asyncio
async def test_missing_invalid_and_admin_credentials_cannot_lookup_retry_keys(
    running_server: RunningServer,
) -> None:
    payload = {"request_id": CANONICAL_REQUEST_ID, "body": "private accepted intent"}
    async with httpx.AsyncClient(base_url=running_server.base_url) as client:
        accepted = await client.post(
            _endpoint(), json=payload, headers=_headers(running_server.api_key),
        )
        assert accepted.status_code == 201
        for key in (CANONICAL_REQUEST_ID, str(uuid.uuid4())):
            attempted = {**payload, "request_id": key}
            for credential in (None, "invalid", "test-only-admin-secret"):
                headers = {} if credential is None else _headers(credential)
                rest_denied = await client.post(
                    _endpoint(), json=attempted, headers=headers,
                )
                mcp_denied = await client.post(
                    "/mcp", json=_rpc_post(attempted),
                    headers={
                        "Accept": "application/json, text/event-stream", **headers,
                    },
                )
                for response in (rest_denied, mcp_denied):
                    assert response.status_code == 401, response.text
                    assert accepted.json()["id"] not in response.text
                    assert CONFLICT not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("denial", ["freeze", "blocked", "revoked"])
async def test_current_authority_denies_hit_and_miss_before_key_lookup(
    running_server: RunningServer, denial: str,
) -> None:
    async with httpx.AsyncClient(
        base_url=running_server.base_url, headers=_headers(running_server.api_key),
    ) as rest, _mcp_session(running_server, running_server.api_key) as session:
        payload = {"request_id": CANONICAL_REQUEST_ID, "body": "retained acceptance"}
        first = await _post(rest, session, "rest", payload)
        if denial == "freeze":
            running_server.application.state.access_freeze_service.freeze(
                "post retry containment test",
            )
            expected_status = 503
        elif denial == "blocked":
            transition(running_server.agent_service, running_server.agent_id, "block")
            expected_status = 401
        else:
            running_server.agent_service.revoke_agent(running_server.agent_id)
            expected_status = 401
        errors: dict[str, list[str]] = {"rest": [], "mcp": []}
        for key in (CANONICAL_REQUEST_ID, str(uuid.uuid4())):
            for body in (payload["body"], "different otherwise valid intent"):
                attempted = {"request_id": key, "body": body}
                denied = await rest.post(_endpoint(), json=attempted)
                mcp_denied = await rest.post(
                    "/mcp", json=_rpc_post(attempted),
                    headers=_rpc_headers(running_server.api_key),
                )
                for transport, response in (("rest", denied), ("mcp", mcp_denied)):
                    assert response.status_code == expected_status, response.text
                    assert first["id"] not in response.text
                    assert payload["body"] not in response.text
                    assert CONFLICT not in response.text
                    errors[transport].append(response.text)
        assert all(len(set(responses)) == 1 for responses in errors.values())
        if denial == "freeze":
            assert (await rest.get("/healthz")).status_code == 200
            running_server.application.state.access_freeze_service.unfreeze(
                "post retry containment reviewed",
            )
            assert await _post(rest, session, "mcp", payload) == first
            assert (await rest.get(_endpoint())).json() == [first]


@pytest.mark.asyncio
async def test_pending_and_retired_credentials_cannot_replay_but_successor_can(
    running_server: RunningServer,
) -> None:
    agents = running_server.agent_service
    async with httpx.AsyncClient(
        base_url=running_server.base_url, headers=_headers(running_server.api_key),
    ) as rest, _mcp_session(running_server, running_server.api_key) as session:
        payload = {"request_id": CANONICAL_REQUEST_ID, "body": "survives credential rotation"}
        first = await _post(rest, session, "rest", payload)
        predecessor = agents.authenticate(running_server.api_key)
        assert predecessor is not None
        successor = agents.rotate(
            predecessor, request_id=str(uuid.uuid4()),
            expected_agent_id=predecessor.agent.id,
            expected_credential_id=predecessor.credential.id,
            expected_credential_epoch=predecessor.agent.credential_epoch,
        )
        assert successor.secret is not None
        async with _mcp_session(running_server, successor.secret) as pending_session:
            for key in (CANONICAL_REQUEST_ID, str(uuid.uuid4())):
                attempted = {**payload, "request_id": key}
                denied = await rest.post(
                    _endpoint(), json=attempted, headers=_headers(successor.secret),
                )
                assert denied.status_code == 403
                result = await pending_session.call_tool(
                    "post", {"channel": "status", **attempted},
                )
                assert result.is_error is True
                assert CONFLICT not in _tool_text(result)
                assert first["id"] not in _tool_text(result)
        pending = agents.verify_credential(successor.secret)
        assert pending is not None
        agents.prove(
            pending, request_id=str(uuid.uuid4()),
            expected_agent_id=pending.agent.id,
            expected_agent_name=pending.agent.name,
            expected_credential_epoch=pending.agent.credential_epoch,
            expected_credential_version=pending.credential.version,
        )
        current = agents.authenticate(successor.secret)
        assert current is not None
        agents.retire_predecessor(
            current, credential_id=predecessor.credential.id,
            request_id=str(uuid.uuid4()),
            expected_credential_epoch=current.agent.credential_epoch,
            expected_credential_version=predecessor.credential.version,
        )
        for key in (CANONICAL_REQUEST_ID, str(uuid.uuid4())):
            attempted = {**payload, "request_id": key}
            assert (await rest.post(_endpoint(), json=attempted)).status_code == 401
            assert (await rest.post(
                "/mcp", json=_rpc_post(attempted),
                headers=_rpc_headers(running_server.api_key),
            )).status_code == 401
        rest.headers.update(_headers(successor.secret))
        async with _mcp_session(running_server, successor.secret) as current_session:
            assert await _post(rest, current_session, "mcp", payload) == first
            assert await _post(rest, current_session, "rest", payload) == first
        assert (await rest.get(_endpoint())).json() == [first]


@pytest.mark.asyncio
async def test_enforced_missing_and_stale_roe_deny_retries_until_current_receipt(
    app_config, agent_service, uvicorn_server,
) -> None:
    created = _activate(agent_service, agent_service.create_agent("retry-roe"))
    config = replace(app_config, roe_enforcement_mode="enforce")
    application = create_app(config=config, agent_service=agent_service)
    with uvicorn_server(application) as base_url:
        server = RunningServer(
            base_url, created.api_key, created.agent.id, agent_service,
            application.state.board_service, application.state.roe_service, application,
        )
        async with httpx.AsyncClient(
            base_url=base_url, headers=_headers(created.api_key),
        ) as rest, _mcp_session(server, created.api_key) as session:
            payload = {"request_id": CANONICAL_REQUEST_ID, "body": "receipt-bound authority"}
            effective = (await rest.get("/api/roe/effective")).json()
            receipt = await rest.post(
                "/api/roe/acknowledgements", json=_receipt_payload(effective),
            )
            assert receipt.status_code == 201
            first = await _post(rest, session, "rest", payload)
        predecessor = agent_service.authenticate(created.api_key)
        assert predecessor is not None
        successor = agent_service.rotate(
            predecessor, request_id=str(uuid.uuid4()),
            expected_agent_id=predecessor.agent.id,
            expected_credential_id=predecessor.credential.id,
            expected_credential_epoch=predecessor.agent.credential_epoch,
        )
        assert successor.secret is not None
        pending = agent_service.verify_credential(successor.secret)
        assert pending is not None
        agent_service.prove(
            pending, request_id=str(uuid.uuid4()),
            expected_agent_id=pending.agent.id,
            expected_agent_name=pending.agent.name,
            expected_credential_epoch=pending.agent.credential_epoch,
            expected_credential_version=pending.credential.version,
        )
        async with httpx.AsyncClient(
            base_url=base_url, headers=_headers(successor.secret),
        ) as rest, _mcp_session(server, successor.secret) as session:
            for phase in ("missing", "stale"):
                for key in (CANONICAL_REQUEST_ID, str(uuid.uuid4())):
                    attempted = {**payload, "request_id": key}
                    denied = await rest.post(_endpoint(), json=attempted)
                    assert denied.status_code == 428, denied.text
                    result = await session.call_tool(
                        "post", {"channel": "status", **attempted},
                    )
                    assert result.is_error is True
                    assert "receipt required" in _tool_text(result)
                    assert CONFLICT not in _tool_text(result)
                effective = (await rest.get("/api/roe/effective")).json()
                assert effective["receipt_status"] == phase
                receipt = await rest.post(
                    "/api/roe/acknowledgements", json=_receipt_payload(effective),
                )
                assert receipt.status_code == 201, receipt.text
                if phase == "missing":
                    assert await _post(rest, session, "rest", payload) == first
                    application.state.roe_service.publish_agent(
                        agent_id=created.agent.id, revision_id=str(uuid.uuid4()),
                        expected_current_revision_id=None,
                        author_label="Retry test administrator",
                        policy=_agent_addendum(),
                        publisher_kind="remote-admin", publisher_id="test-admin",
                    )
                else:
                    assert await _post(rest, session, "mcp", payload) == first
            assert (await rest.get(_endpoint())).json() == [first]


@pytest.mark.asyncio
async def test_full_envelope_boundaries_apply_to_keyed_replay_and_new_key(
    app_config, agent_service, uvicorn_server,
) -> None:
    created = _activate(agent_service, agent_service.create_agent("retry-envelope"))
    config = replace(
        app_config, max_message_bytes=64, max_metadata_bytes=64,
        max_rest_request_body_bytes=10 * 1024, max_request_body_bytes=4096,
    )
    application = create_app(config=config, agent_service=agent_service)
    with uvicorn_server(application) as base_url:
        async with httpx.AsyncClient(
            base_url=base_url, headers=_headers(created.api_key),
        ) as rest:
            payload = {"request_id": CANONICAL_REQUEST_ID, "body": "bounded intent"}
            first = await rest.post(_endpoint(), json=payload)
            assert first.status_code == 201
            for transport, limit in (
                ("rest", config.max_rest_request_body_bytes),
                ("mcp", config.max_request_body_bytes),
            ):
                for key in (CANONICAL_REQUEST_ID, str(uuid.uuid4())):
                    attempted = {**payload, "request_id": key}
                    envelope = attempted if transport == "rest" else _rpc_post(attempted)
                    encoded = json.dumps(envelope).encode("ascii")
                    exact = encoded + b" " * (limit - len(encoded))
                    path = _endpoint() if transport == "rest" else "/mcp"
                    headers = _rpc_headers(created.api_key)
                    too_large = await rest.post(path, content=exact + b" ", headers=headers)
                    assert too_large.status_code == 413, too_large.text
                    unauthenticated = await rest.post(
                        path, content=exact + b" ",
                        headers={**headers, "Authorization": "Bearer invalid"},
                    )
                    assert unauthenticated.status_code == 401
                    allowed = await rest.post(path, content=exact, headers=headers)
                    if transport == "rest":
                        assert allowed.status_code == 201, allowed.text
                        message = allowed.json()
                    else:
                        message = _rpc_message(allowed)
                    if key == CANONICAL_REQUEST_ID:
                        assert message == first.json()
            assert len((await rest.get(_endpoint())).json()) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("reduced_limit", ["body", "metadata"])
async def test_reduced_current_limits_deny_even_identical_saved_intent(
    app_config, agent_service, uvicorn_server, reduced_limit: str,
) -> None:
    created = _activate(agent_service, agent_service.create_agent("retry-reduced-limit"))
    payload = {
        "request_id": CANONICAL_REQUEST_ID, "body": "\u00e9" * 33,
        "metadata": {"x": "v" * 57},
    }
    original = create_app(config=app_config, agent_service=agent_service)
    with uvicorn_server(original) as base_url:
        async with httpx.AsyncClient(
            base_url=base_url, headers=_headers(created.api_key),
        ) as rest:
            response = await rest.post(_endpoint(), json=payload)
            assert response.status_code == 201
            first = response.json()
    config = replace(
        app_config,
        **({"max_message_bytes": 64} if reduced_limit == "body"
           else {"max_metadata_bytes": 64}),
    )
    reduced = create_app(config=config, agent_service=agent_service)
    with uvicorn_server(reduced) as base_url:
        server = RunningServer(
            base_url, created.api_key, created.agent.id, agent_service,
            reduced.state.board_service, reduced.state.roe_service, reduced,
        )
        async with httpx.AsyncClient(
            base_url=base_url, headers=_headers(created.api_key),
        ) as rest, _mcp_session(server, created.api_key) as session:
            denied = await rest.post(_endpoint(), json=payload)
            assert denied.status_code == (413 if reduced_limit == "body" else 400)
            result = await session.call_tool("post", {"channel": "status", **payload})
            assert result.is_error is True
            assert CONFLICT not in _tool_text(result)
            assert (await rest.get(_endpoint())).json() == [first]


@pytest.mark.asyncio
async def test_replays_consume_shared_rest_mcp_rate_admission(
    app_config, agent_service, uvicorn_server,
) -> None:
    created = _activate(agent_service, agent_service.create_agent("retry-rate"))
    config = replace(app_config, authenticated_requests_per_minute=3)
    application = create_app(config=config, agent_service=agent_service)
    with uvicorn_server(application) as base_url:
        async with httpx.AsyncClient(
            base_url=base_url, headers=_headers(created.api_key),
        ) as rest:
            payload = {"request_id": CANONICAL_REQUEST_ID, "body": "rate-bound intent"}
            first = await rest.post(_endpoint(), json=payload)
            assert first.status_code == 201
            replay = await rest.post(
                "/mcp", json=_rpc_post(payload), headers=_rpc_headers(created.api_key),
            )
            assert _rpc_message(replay) == first.json()
            last_allowed = await rest.post(_endpoint(), json=payload)
            assert last_allowed.status_code == 201
            assert last_allowed.json() == first.json()
            for key in (CANONICAL_REQUEST_ID, str(uuid.uuid4())):
                attempted = {**payload, "request_id": key}
                for path, envelope in (
                    (_endpoint(), attempted), ("/mcp", _rpc_post(attempted)),
                ):
                    denied = await rest.post(
                        path, json=envelope, headers=_rpc_headers(created.api_key),
                    )
                    assert denied.status_code == 429, denied.text
                    assert int(denied.headers["retry-after"]) > 0
                    assert CONFLICT not in denied.text
    messages = application.state.board_service.list_messages("status", limit=10)
    assert [message.id for message in messages] == [first.json()["id"]]
