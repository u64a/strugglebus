from __future__ import annotations

import asyncio
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import AbstractContextManager, asynccontextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, AsyncIterator, Callable

import httpx
import pytest
from fastapi.testclient import TestClient
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.types import LATEST_PROTOCOL_VERSION

from strugglebus.app import (
    APIKeyTokenVerifier,
    DEFAULT_MAX_MCP_REQUEST_BODY_SIZE,
    create_app,
)
from strugglebus.auth import AgentService
from strugglebus.config import AppConfig
from strugglebus.service import BoardService


DEPLOYMENT_VARIABLES = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "inventory"
    / "example"
    / "group_vars"
    / "all.yml"
)


def _deployment_scalar(name: str) -> str:
    matches = []
    for line in DEPLOYMENT_VARIABLES.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == name:
            matches.append(value.split("#", 1)[0].strip().strip("'\""))
    if len(matches) != 1 or not matches[0] or matches[0] == "CHANGE_ME":
        raise AssertionError(f"deployment variable {name!r} is not a usable scalar")
    return matches[0]


DEPLOYMENT_DOMAIN = _deployment_scalar("strugglebus_domain")
EXTERNAL_DEPLOYMENT_DOMAIN = _deployment_scalar("strugglebus_external_domain")


@dataclass(frozen=True)
class RunningServer:
    base_url: str
    api_key: str
    agent_id: str
    agent_service: AgentService
    board_service: BoardService
    roe_service: Any
    application: Any = None


def _activate(service: AgentService, created):
    identity = service.authorize(created.api_key)
    assert identity is not None
    service.prove(
        identity,
        request_id=str(uuid.uuid4()),
        expected_agent_id=identity.agent.id,
        expected_agent_name=identity.agent.name,
        expected_credential_epoch=identity.agent.credential_epoch,
        expected_credential_version=identity.credential.version,
    )
    return created


@pytest.fixture
def running_server(
    app_config: AppConfig,
    agent_service: AgentService,
    uvicorn_server: Callable[[Any], AbstractContextManager[str]],
) -> Iterator[RunningServer]:
    created = _activate(
        agent_service,
        agent_service.create_agent("integration-test"),
    )
    limited_config = AppConfig(
        database_path=app_config.database_path,
        data_dir=app_config.data_dir,
        runtime_dir=app_config.runtime_dir,
        backup_dir=app_config.backup_dir,
        admin_credential_path=None,
        admin_secret=b"test-only-admin-secret",
        max_message_bytes=64,
        max_request_body_bytes=4096,
        max_metadata_bytes=64,
        public_base_url=f"https://{EXTERNAL_DEPLOYMENT_DOMAIN}",
        allowed_hosts=(
            DEPLOYMENT_DOMAIN,
            f"{DEPLOYMENT_DOMAIN}:*",
            EXTERNAL_DEPLOYMENT_DOMAIN,
            f"{EXTERNAL_DEPLOYMENT_DOMAIN}:*",
            "127.0.0.1:*",
            "localhost:*",
            "[::1]:*",
        ),
        allowed_origins=(
            f"https://{DEPLOYMENT_DOMAIN}",
            f"https://{EXTERNAL_DEPLOYMENT_DOMAIN}",
        ),
    )
    application = create_app(
        agent_service=agent_service,
        config=limited_config,
    )
    with uvicorn_server(application) as base_url:
        yield RunningServer(
            base_url=base_url,
            api_key=created.api_key,
            agent_id=created.agent.id,
            agent_service=agent_service,
            board_service=application.state.board_service,
            roe_service=application.state.roe_service,
            application=application,
        )


@pytest.mark.asyncio
async def test_official_client_carries_persistent_identity_to_tool(
    running_server: RunningServer,
) -> None:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {running_server.api_key}"}
    ) as http_client:
        async with streamable_http_client(
            f"{running_server.base_url}/mcp",
            http_client=http_client,
        ) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool("whoami")

    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["agent"]["id"] == running_server.agent_id
    assert result.structured_content["agent"]["name"] == "integration-test"
    assert result.structured_content["subscriptions"] == []
    assert "api_key" not in result.structured_content["agent"]
    assert "key_hash" not in result.structured_content["agent"]


@pytest.mark.asyncio
async def test_official_client_accepts_deployment_host_and_origin(
    running_server: RunningServer,
) -> None:
    edge_headers = {
        "Host": DEPLOYMENT_DOMAIN,
        "Origin": f"https://{DEPLOYMENT_DOMAIN}",
    }
    async with _mcp_session(
        running_server,
        running_server.api_key,
        request_headers=edge_headers,
    ) as session:
        identity = await session.call_tool("whoami")

    assert identity.structured_content["agent"]["id"] == running_server.agent_id

    with pytest.RaisesGroup(MCPError, flatten_subgroups=True):
        async with _mcp_session(
            running_server,
            running_server.api_key,
            request_headers={
                "Host": "unapproved.invalid",
                "Origin": f"https://{DEPLOYMENT_DOMAIN}",
            },
        ):
            pass


def test_mcp_rejects_missing_and_invalid_bearer_keys(
    running_server: RunningServer,
) -> None:
    endpoint = f"{running_server.base_url}/mcp"
    headers = {"Accept": "application/json, text/event-stream"}

    missing = httpx.post(endpoint, headers=headers)
    invalid = httpx.post(
        endpoint,
        content=b"x" * 1025,
        headers={**headers, "Authorization": "Bearer invalid"},
    )

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert running_server.api_key not in missing.text
    assert running_server.api_key not in invalid.text


@pytest.mark.asyncio
async def test_persistent_verifier_rejects_revoked_key(
    running_server: RunningServer,
) -> None:
    verifier = APIKeyTokenVerifier(running_server.agent_service)
    running_server.agent_service.revoke_agent(running_server.agent_id)

    assert await verifier.verify_token(running_server.api_key) is None


def test_mcp_enforces_configured_request_limit_after_authentication(
    running_server: RunningServer,
) -> None:
    response = httpx.post(
        f"{running_server.base_url}/mcp",
        content=b"x" * 4097,
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {running_server.api_key}",
            "Content-Type": "application/json",
        },
    )

    assert DEFAULT_MAX_MCP_REQUEST_BODY_SIZE == 1024 * 1024
    assert response.status_code == 413


def test_stateless_transport_accepts_caddy_forwarded_host_without_session(
    running_server: RunningServer,
) -> None:
    response = httpx.post(
        f"{running_server.base_url}/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "proxy-test", "version": "1"},
            },
        },
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {running_server.api_key}",
            "Host": "bus.lan",
            "X-Forwarded-Proto": "https",
        },
    )

    assert response.status_code == 200
    assert "Mcp-Session-Id" not in response.headers


def test_canonical_transport_accepts_external_caddy_host(
    running_server: RunningServer,
) -> None:
    response = httpx.post(
        f"{running_server.base_url}/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "canonical-test", "version": "1"},
            },
        },
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {running_server.api_key}",
            "Host": EXTERNAL_DEPLOYMENT_DOMAIN,
            "X-Forwarded-Proto": "https",
        },
    )

    assert response.status_code == 200
    assert "Mcp-Session-Id" not in response.headers


def test_transport_rejects_unapproved_forwarded_host(
    running_server: RunningServer,
) -> None:
    response = httpx.post(
        f"{running_server.base_url}/mcp",
        content=b"{}",
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {running_server.api_key}",
            "Content-Type": "application/json",
            "Host": "public.example",
        },
    )

    assert response.status_code == 421


def test_mcp_uses_shared_authenticated_agent_rate_limit(
    app_config: AppConfig,
    agent_service: AgentService,
) -> None:
    created = _activate(
        agent_service,
        agent_service.create_agent("mcp-rate-test"),
    )
    limited_config = replace(
        app_config,
        authenticated_requests_per_minute=1,
    )
    application = create_app(
        agent_service=agent_service,
        config=limited_config,
    )
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "rate-test", "version": "1"},
        },
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {created.api_key}",
        "Host": "bus.lan",
    }

    with TestClient(application) as client:
        first = client.post("/mcp", json=payload, headers=headers)
        second = client.post("/mcp", json=payload, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"]


def test_fastapi_health_route_is_available_alongside_mcp(
    running_server: RunningServer,
) -> None:
    response = httpx.get(f"{running_server.base_url}/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@asynccontextmanager
async def _mcp_session(
    server: RunningServer,
    api_key: str | None,
    *,
    request_headers: dict[str, str] | None = None,
) -> AsyncIterator[ClientSession]:
    headers = dict(request_headers or {})
    if api_key is not None:
        headers["Authorization"] = f"Bearer {api_key}"
    async with httpx.AsyncClient(headers=headers) as http_client:
        async with streamable_http_client(
            f"{server.base_url}/mcp",
            http_client=http_client,
        ) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session


@pytest.mark.asyncio
async def test_tool_catalog_has_typed_bounded_mcp_21_contracts(
    running_server: RunningServer,
) -> None:
    async with _mcp_session(running_server, running_server.api_key) as session:
        catalog = await session.list_tools()

    tools = {tool.name: tool for tool in catalog.tools}
    assert set(tools) == {
        "whoami",
        "orientation",
        "server_info",
        "integration_guide",
        "get_effective_roe",
        "acknowledge_roe",
        "prove_credential",
        "retire_predecessor_credential",
        "post",
        "read",
        "read_replies",
        "list_channels",
        "list_subscriptions",
        "create_channel",
        "subscribe",
        "unsubscribe",
        "list_agents",
        "catch_up",
        "search",
    }
    assert all(tool.output_schema is not None for tool in tools.values())
    assert all(tool.output_schema["type"] == "object" for tool in tools.values())
    assert all(
        "agent_id" not in tool.input_schema.get("properties", {})
        for name, tool in tools.items()
        if name != "prove_credential"
    )
    assert tools["read"].input_schema["properties"]["since"]["minimum"] == 0
    assert tools["read"].input_schema["properties"]["limit"]["maximum"] == 200
    assert tools["read_replies"].input_schema["properties"]["message_seq"][
        "minimum"
    ] == 1
    assert tools["read_replies"].input_schema["properties"]["since"]["minimum"] == 0
    assert tools["read_replies"].input_schema["properties"]["limit"]["maximum"] == 200
    assert tools["catch_up"].input_schema["properties"]["limit"]["maximum"] == 200
    assert "Persist each page before processing" in tools["catch_up"].description
    assert "recover history" in tools["catch_up"].description
    assert "never waits for a response" in tools["post"].description
    assert "verify pinned identity" in tools["whoami"].description
    assert "optional additive agent" in tools["get_effective_roe"].description
    assert "before asking in help" in tools["search"].description
    assert tools["search"].input_schema["properties"]["query"]["maxLength"] == 256
    assert tools["post"].input_schema["properties"]["kind"]["enum"] == [
        "announce",
        "question",
        "answer",
        "status",
        "chat",
        "task",
    ]
    assert tools["create_channel"].input_schema["properties"]["name"][
        "maxLength"
    ] == 64
    assert tools["integration_guide"].input_schema["properties"] == {}
    assert tools["get_effective_roe"].input_schema["properties"] == {}
    assert tools["acknowledge_roe"].input_schema["properties"][
        "global_content_sha256"
    ]["pattern"] == "^[0-9a-f]{64}$"
    assert tools["server_info"].input_schema["properties"] == {}
    assert set(tools["server_info"].output_schema["properties"]) == {
        "application_version",
        "release_id",
        "integration_guide_version",
        "coordination_protocol_version",
    }


@pytest.mark.asyncio
async def test_integration_guide_has_rest_mcp_parity(
    running_server: RunningServer,
) -> None:
    headers = {"Authorization": f"Bearer {running_server.api_key}"}
    async with _mcp_session(running_server, running_server.api_key) as session:
        mcp_result = await session.call_tool("integration_guide")
        mcp_info = await session.call_tool("server_info")
    rest_result = httpx.get(
        f"{running_server.base_url}/api/integration-guide",
        headers=headers,
    )
    rest_info = httpx.get(
        f"{running_server.base_url}/api/server-info",
        headers=headers,
    )

    assert mcp_result.is_error is False
    assert rest_result.status_code == 200
    assert mcp_result.structured_content == rest_result.json()
    assert rest_result.json()["guide_version"] == "1.19.0"
    assert mcp_info.is_error is False
    assert mcp_info.structured_content == rest_info.json() == {
        "application_version": "0.2.71",
        "release_id": "development",
        "integration_guide_version": "1.19.0",
        "coordination_protocol_version": 1,
    }


@pytest.mark.asyncio
async def test_effective_roe_and_receipt_have_rest_mcp_parity(
    running_server: RunningServer,
) -> None:
    headers = {"Authorization": f"Bearer {running_server.api_key}"}
    async with _mcp_session(running_server, running_server.api_key) as session:
        mcp_effective = await session.call_tool("get_effective_roe")
        effective = mcp_effective.structured_content
        assert effective is not None
        acknowledgement = await session.call_tool(
            "acknowledge_roe",
            {
                "global_revision_id": effective["global_revision"]["id"],
                "global_content_sha256": effective["global_revision"][
                    "content_sha256"
                ],
                "effective_sha256": effective["effective_sha256"],
            },
        )

    rest_effective = httpx.get(
        f"{running_server.base_url}/api/roe/effective",
        headers=headers,
    )
    rest_retry = httpx.post(
        f"{running_server.base_url}/api/roe/acknowledgements",
        headers=headers,
        json={
            "global_revision_id": effective["global_revision"]["id"],
            "global_content_sha256": effective["global_revision"][
                "content_sha256"
            ],
            "agent_revision_id": None,
            "agent_content_sha256": None,
            "effective_sha256": effective["effective_sha256"],
        },
    )

    assert mcp_effective.is_error is False
    assert effective["receipt_status"] == "missing"
    assert {
        "author_label",
        "publisher_type",
        "publisher_identity",
    }.isdisjoint(effective["global_revision"])
    assert acknowledgement.is_error is False
    assert rest_effective.status_code == 200
    assert rest_effective.json()["receipt_status"] == "current"
    assert rest_retry.status_code == 200
    assert rest_retry.json() == acknowledgement.structured_content


@pytest.mark.asyncio
async def test_enforced_mcp_preserves_bootstrap_until_exact_receipt(
    app_config: AppConfig,
    agent_service: AgentService,
    uvicorn_server: Callable[[Any], AbstractContextManager[str]],
) -> None:
    created = _activate(
        agent_service,
        agent_service.create_agent("mcp-enforced-agent"),
    )
    enforced_config = replace(
        app_config,
        roe_enforcement_mode="enforce",
    )
    application = create_app(
        agent_service=agent_service,
        config=enforced_config,
    )
    with uvicorn_server(application) as base_url:
        server = RunningServer(
            base_url=base_url,
            api_key=created.api_key,
            agent_id=created.agent.id,
            agent_service=agent_service,
            board_service=application.state.board_service,
            roe_service=application.state.roe_service,
        )
        async with _mcp_session(server, server.api_key) as session:
            identity = await session.call_tool("whoami")
            effective_result = await session.call_tool("get_effective_roe")
            denied = await session.call_tool("list_channels")
            effective = effective_result.structured_content
            assert effective is not None
            receipt = await session.call_tool(
                "acknowledge_roe",
                {
                    "global_revision_id": effective["global_revision"]["id"],
                    "global_content_sha256": effective["global_revision"][
                        "content_sha256"
                    ],
                    "effective_sha256": effective["effective_sha256"],
                },
            )
            allowed = await session.call_tool("list_channels")

    assert identity.is_error is False
    assert effective_result.is_error is False
    assert denied.is_error is True
    assert "receipt required" in denied.content[0].text
    assert receipt.is_error is False
    assert allowed.is_error is False


@pytest.mark.asyncio
async def test_enforced_rest_handles_more_requests_than_executor_workers(
    app_config: AppConfig,
    agent_service: AgentService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _activate(
        agent_service,
        agent_service.create_agent("rest-concurrency-agent"),
    )
    application = create_app(
        agent_service=agent_service,
        config=replace(app_config, roe_enforcement_mode="enforce"),
    )
    original = application.state.board_service.list_channels
    entered_count = 0
    entered_lock = threading.Lock()
    concurrent = threading.Event()
    release = threading.Event()

    def slow_list_channels():
        nonlocal entered_count
        with entered_lock:
            entered_count += 1
            if entered_count >= 2:
                concurrent.set()
        assert release.wait(timeout=5)
        return original()

    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            timeout=5,
        ) as client:
            headers = {"Authorization": f"Bearer {created.api_key}"}
            effective = (
                await client.get("/api/roe/effective", headers=headers)
            ).json()
            receipt = await client.post(
                "/api/roe/acknowledgements",
                headers=headers,
                json={
                    "global_revision_id": effective["global_revision"]["id"],
                    "global_content_sha256": effective["global_revision"][
                        "content_sha256"
                    ],
                    "agent_revision_id": None,
                    "agent_content_sha256": None,
                    "effective_sha256": effective["effective_sha256"],
                },
            )
            assert receipt.status_code == 201
            monkeypatch.setattr(
                application.state.board_service,
                "list_channels",
                slow_list_channels,
            )
            requests = [
                asyncio.create_task(client.get("/api/channels", headers=headers))
                for _ in range(40)
            ]
            try:
                deadline = asyncio.get_running_loop().time() + 2
                while not concurrent.is_set():
                    assert asyncio.get_running_loop().time() < deadline
                    await asyncio.sleep(0.01)
            finally:
                release.set()
            responses = await asyncio.gather(*requests)

    assert entered_count > 1
    assert all(response.status_code == 200 for response in responses)


@pytest.mark.asyncio
async def test_cancelled_enforced_rest_request_cannot_orphan_publication(
    app_config: AppConfig,
    agent_service: AgentService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _activate(
        agent_service,
        agent_service.create_agent("rest-cancellation-agent"),
    )
    application = create_app(
        agent_service=agent_service,
        config=replace(app_config, roe_enforcement_mode="enforce"),
    )
    original = application.state.board_service.list_channels
    first_entered = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()
    release_second = threading.Event()
    call_count = 0
    call_lock = threading.Lock()

    def slow_list_channels():
        nonlocal call_count
        with call_lock:
            call_count += 1
            current = call_count
        if current == 1:
            first_entered.set()
            assert release_first.wait(timeout=5)
        else:
            second_entered.set()
            assert release_second.wait(timeout=5)
        return original()

    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            timeout=5,
        ) as client:
            headers = {"Authorization": f"Bearer {created.api_key}"}
            effective = (
                await client.get("/api/roe/effective", headers=headers)
            ).json()
            receipt = await client.post(
                "/api/roe/acknowledgements",
                headers=headers,
                json={
                    "global_revision_id": effective["global_revision"]["id"],
                    "global_content_sha256": effective["global_revision"][
                        "content_sha256"
                    ],
                    "agent_revision_id": None,
                    "agent_content_sha256": None,
                    "effective_sha256": effective["effective_sha256"],
                },
            )
            assert receipt.status_code == 201
            monkeypatch.setattr(
                application.state.board_service,
                "list_channels",
                slow_list_channels,
            )
            first = asyncio.create_task(
                client.get("/api/channels", headers=headers)
            )
            deadline = asyncio.get_running_loop().time() + 2
            while not first_entered.is_set():
                assert asyncio.get_running_loop().time() < deadline
                await asyncio.sleep(0.01)
            second = asyncio.create_task(
                client.get("/api/channels", headers=headers)
            )
            while not second_entered.is_set():
                assert asyncio.get_running_loop().time() < deadline
                await asyncio.sleep(0.01)
            second.cancel()
            with pytest.raises(asyncio.CancelledError):
                await second

            revision = await asyncio.wait_for(
                asyncio.to_thread(
                    application.state.roe_service.publish_agent,
                    agent_id=created.agent.id,
                    revision_id=str(uuid.uuid4()),
                    expected_current_revision_id=None,
                    author_label="Test administrator",
                    policy={
                        "schema_version": 1,
                        "policy_kind": "agent-addendum",
                        "title": "Cancellation-safe update",
                        "coordination_boundaries": [
                            {
                                "id": "requests-remain-proposals",
                                "message_kinds": ["chat"],
                                "authority_effect": "none",
                                "statement": "Requests remain proposals.",
                            }
                        ],
                    },
                    publisher_kind="api-key-sha256-v1",
                    publisher_id="sha256:" + "a" * 64,
                ),
                timeout=2,
            )
            assert revision[1] is True
            release_first.set()
            release_second.set()
            assert (await first).status_code == 428


@pytest.mark.asyncio
async def test_rest_and_mcp_share_operations_state_order_and_conflicts(
    running_server: RunningServer,
) -> None:
    rest_headers = {"Authorization": f"Bearer {running_server.api_key}"}
    async with httpx.AsyncClient(
        base_url=running_server.base_url,
        headers=rest_headers,
    ) as rest:
        rest_channels = (await rest.get("/api/channels")).json()
        rest_agents = (await rest.get("/api/agents")).json()

        async with _mcp_session(
            running_server,
            running_server.api_key,
        ) as session:
            channels = await session.call_tool("list_channels")
            agents = await session.call_tool("list_agents")
            created = await session.call_tool(
                "create_channel",
                {"name": "#Parity_Channel", "purpose": "Cross-facade checks"},
            )
            duplicate_mcp = await session.call_tool(
                "create_channel",
                {"name": "parity-channel"},
            )
            first = await session.call_tool(
                "post",
                {
                    "channel": "parity-channel",
                    "body": "<b>stored, not rendered</b>",
                    "kind": "question",
                    "metadata": {"source": "mcp", "ticket": 7},
                },
            )

            assert channels.structured_content == {"channels": rest_channels}
            assert [
                (agent["id"], agent["name"])
                for agent in agents.structured_content["agents"]
            ] == [
                (agent["id"], agent["name"]) for agent in rest_agents
            ]
            assert created.is_error is False
            assert created.structured_content["name"] == "parity-channel"
            assert created.structured_content["created_by"] == running_server.agent_id
            assert duplicate_mcp.is_error is True

            duplicate_rest = await rest.post(
                "/api/channels",
                json={"name": "Parity Channel"},
            )
            second = await rest.post(
                "/api/channels/parity-channel/messages",
                json={
                    "body": "REST reply",
                    "kind": "answer",
                    "reply_to": first.structured_content["seq"],
                    "metadata": {"source": "rest"},
                },
            )
            assert duplicate_rest.status_code == 409
            assert second.status_code == 201

            read = await session.call_tool(
                "read",
                {"channel": "parity-channel", "limit": 2},
            )
            focused = await session.call_tool(
                "read_replies",
                {"message_seq": first.structured_content["seq"]},
            )
            rest_focused = (
                await rest.get(
                    f"/api/messages/{first.structured_content['seq']}/replies"
                )
            ).json()
            subscribed = await session.call_tool(
                "subscribe",
                {"channel": "#Parity_Channel"},
            )
            subscribed_again = await session.call_tool(
                "subscribe",
                {"channel": "parity-channel"},
            )
            identity = await session.call_tool("whoami")
            orientation_before = await session.call_tool("orientation")
            catch_up = await session.call_tool("catch_up", {"limit": 10})
            orientation_after = await session.call_tool("orientation")
            search = await session.call_tool(
                "search",
                {"query": "stored rendered", "limit": 10},
            )

            assert [
                message["seq"]
                for message in read.structured_content["messages"]
            ] == [
                first.structured_content["seq"],
                second.json()["seq"],
            ]
            assert read.structured_content["messages"][1]["reply_to"] == (
                first.structured_content["seq"]
            )
            assert focused.structured_content["messages"] == rest_focused
            assert [
                message["seq"]
                for message in focused.structured_content["messages"]
            ] == [second.json()["seq"]]
            assert subscribed.structured_content["subscribed"] is True
            assert subscribed_again.structured_content == subscribed.structured_content
            # Orientation works over MCP and is advisory: catch_up clears the
            # outstanding work it reported, and it never advances a cursor itself.
            assert orientation_before.structured_content["unread"] >= 1
            assert orientation_after.structured_content["unread"] == 0
            assert orientation_before.structured_content["guidance"]
            assert "catch_up" in [
                action["action"]
                for action in orientation_before.structured_content[
                    "required_actions"
                ]
            ]
            assert [
                channel["name"]
                for channel in identity.structured_content["subscriptions"]
            ] == ["parity-channel"]
            assert [
                message["seq"]
                for message in catch_up.structured_content["messages"]
            ] == [
                first.structured_content["seq"],
                second.json()["seq"],
            ]
            rest_catch_up = (
                await rest.get("/api/catch-up", params={"limit": 10})
            ).json()
            rest_search = (
                await rest.get(
                    "/api/search",
                    params={"query": "stored rendered", "limit": 10},
                )
            ).json()
            assert [
                message["seq"] for message in rest_catch_up
            ] == [
                message["seq"]
                for message in catch_up.structured_content["messages"]
            ]
            assert rest_search == search.structured_content["messages"]

            third = await session.call_tool(
                "post",
                {
                    "channel": "parity-channel",
                    "body": "Visible to REST immediately",
                },
            )
            unsubscribed = await session.call_tool(
                "unsubscribe",
                {"channel": "parity-channel"},
            )
            unsubscribed_again = await session.call_tool(
                "unsubscribe",
                {"channel": "parity-channel"},
            )
            identity = await session.call_tool("whoami")

        rest_messages = (
            await rest.get(
                "/api/channels/parity-channel/messages",
                params={"limit": 10},
            )
        ).json()

    assert [message["seq"] for message in rest_messages] == [
        first.structured_content["seq"],
        second.json()["seq"],
        third.structured_content["seq"],
    ]
    assert rest_messages[0]["metadata"] == {"source": "mcp", "ticket": 7}
    assert unsubscribed.structured_content["subscribed"] is False
    assert unsubscribed_again.structured_content == unsubscribed.structured_content
    assert identity.structured_content["subscriptions"] == []


@pytest.mark.asyncio
async def test_tools_reject_bad_inputs_with_safe_useful_errors(
    running_server: RunningServer,
) -> None:
    async with _mcp_session(running_server, running_server.api_key) as session:
        reply_target = await session.call_tool(
            "post",
            {"channel": "status", "body": "reply target"},
        )
        nested_metadata: dict[str, Any] = {}
        for _ in range(9):
            nested_metadata = {"nested": nested_metadata}
        cases: list[tuple[str, dict[str, Any], str]] = [
            ("read", {"channel": "help", "since": -1}, "greater than or equal"),
            ("read", {"channel": "help", "since": True}, "valid integer"),
            ("read", {"channel": "help", "limit": 201}, "less than or equal"),
            (
                "read_replies",
                {"message_seq": True},
                "valid integer",
            ),
            (
                "read_replies",
                {"message_seq": 2**63},
                "less than or equal",
            ),
            (
                "read_replies",
                {"message_seq": 999_999},
                "reply target",
            ),
            (
                "read_replies",
                {
                    "message_seq": reply_target.structured_content["seq"],
                    "since": -1,
                },
                "greater than or equal",
            ),
            (
                "read_replies",
                {
                    "message_seq": reply_target.structured_content["seq"],
                    "limit": 201,
                },
                "less than or equal",
            ),
            ("catch_up", {"limit": 201}, "less than or equal"),
            ("catch_up", {"include_stale": 1}, "valid boolean"),
            ("search", {"query": "\"\"\""}, "searchable term"),
            ("search", {"query": "x" * 257}, "at most 256 characters"),
            ("create_channel", {"name": "bad/name"}, "lowercase kebab-case"),
            (
                "create_channel",
                {"name": "valid", "purpose": "x" * 1025},
                "at most 1024 characters",
            ),
            ("subscribe", {"channel": "missing"}, "was not found"),
            (
                "post",
                {"channel": "help", "body": "", "kind": "chat"},
                "at least 1 character",
            ),
            (
                "post",
                {"channel": "help", "body": "ok", "kind": "invalid"},
                "announce",
            ),
            (
                "post",
                {"channel": "help", "body": "é" * 33},
                "configured limit",
            ),
            (
                "post",
                {
                    "channel": "help",
                    "body": "ok",
                    "metadata": {"value": "x" * 65},
                },
                "metadata must not exceed",
            ),
            (
                "post",
                {"channel": "help", "body": "ok", "metadata": None},
                "valid dictionary",
            ),
            (
                "post",
                {
                    "channel": "help",
                    "body": "ok",
                    "metadata": nested_metadata,
                },
                "metadata nesting exceeds",
            ),
            (
                "post",
                {"channel": "help", "body": "reply", "reply_to": True},
                "valid integer",
            ),
            (
                "post",
                {"channel": "help", "body": "reply", "reply_to": 999_999},
                "reply target",
            ),
            (
                "post",
                {
                    "channel": "help",
                    "body": "wrong channel",
                    "reply_to": reply_target.structured_content["seq"],
                },
                "reply target",
            ),
        ]
        for tool, arguments, expected in cases:
            result = await session.call_tool(tool, arguments)
            assert result.is_error is True
            text = " ".join(
                getattr(content, "text", "") for content in result.content
            )
            assert expected in text
            assert running_server.api_key not in text
            assert "sqlite" not in text.lower()


@pytest.mark.asyncio
async def test_official_client_rejects_missing_invalid_and_revoked_credentials(
    running_server: RunningServer,
) -> None:
    for api_key in (None, "invalid-agent-key"):
        with pytest.RaisesGroup(MCPError, flatten_subgroups=True):
            async with _mcp_session(running_server, api_key):
                pass

    async with _mcp_session(
        running_server,
        running_server.api_key,
    ) as session:
        assert (await session.call_tool("whoami")).is_error is False

    running_server.agent_service.revoke_agent(running_server.agent_id)
    with pytest.RaisesGroup(MCPError, flatten_subgroups=True):
        async with _mcp_session(running_server, running_server.api_key):
            pass


@pytest.mark.asyncio
async def test_concurrent_stateless_clients_share_order_and_subscriptions(
    running_server: RunningServer,
) -> None:
    async def call(tool: str, arguments: dict[str, Any]) -> Any:
        async with _mcp_session(
            running_server,
            running_server.api_key,
        ) as session:
            return await session.call_tool(tool, arguments)

    posts = await asyncio.gather(
        *(
            call(
                "post",
                {
                    "channel": "status",
                    "body": f"concurrent {index}",
                    "kind": "status",
                },
            )
            for index in range(16)
        )
    )
    sequences = [result.structured_content["seq"] for result in posts]
    assert all(result.is_error is False for result in posts)
    assert len(set(sequences)) == 16

    subscriptions = await asyncio.gather(
        *(call("subscribe", {"channel": "status"}) for _ in range(8))
    )
    assert all(result.is_error is False for result in subscriptions)

    catches = await asyncio.gather(
        *(call("catch_up", {"limit": 50}) for _ in range(2))
    )
    assert all(
        [message["seq"] for message in result.structured_content["messages"]]
        == sorted(sequences)
        for result in catches
    )

    async with _mcp_session(
        running_server,
        running_server.api_key,
    ) as fresh_session:
        read = await fresh_session.call_tool(
            "read",
            {"channel": "status", "limit": 50},
        )
        identity = await fresh_session.call_tool("whoami")

    returned = [
        message["seq"] for message in read.structured_content["messages"]
    ]
    assert returned == sorted(sequences)
    assert identity.structured_content["subscriptions"][0]["name"] == "status"


@pytest.mark.asyncio
async def test_official_clients_share_transactional_mention_identity(
    running_server: RunningServer,
) -> None:
    mentioned = _activate(
        running_server.agent_service,
        running_server.agent_service.create_agent("mentioned-copilot"),
    )

    async with _mcp_session(
        running_server,
        running_server.api_key,
    ) as writer_session:
        posted = await writer_session.call_tool(
            "post",
            {
                "channel": "help",
                "body": "Please review @mentioned-copilot",
            },
        )
        rejected = await writer_session.call_tool(
            "post",
            {
                "channel": "help",
                "body": "This must roll back @unknown-copilot",
            },
        )

    async with _mcp_session(
        running_server,
        mentioned.api_key,
    ) as mentioned_session:
        caught = await mentioned_session.call_tool("catch_up", {"limit": 10})

    assert rejected.is_error is True
    assert [
        message["seq"] for message in caught.structured_content["messages"]
    ] == [posted.structured_content["seq"]]
    messages = running_server.board_service.list_messages("help", limit=10)
    assert [message.seq for message in messages] == [
        posted.structured_content["seq"]
    ]


@pytest.mark.asyncio
async def test_real_http_sse_disconnect_cleans_up_and_service_remains_responsive(
    running_server: RunningServer,
) -> None:
    posted = running_server.board_service.create_message(
        "status",
        agent_id=running_server.agent_id,
        body="stream then disconnect",
        kind="status",
        reply_to=None,
        metadata={},
    )
    headers = {"Authorization": f"Bearer {running_server.api_key}"}

    async with httpx.AsyncClient(
        base_url=running_server.base_url,
        headers=headers,
    ) as client:
        async with client.stream("GET", "/api/stream", params={"since": 0}) as response:
            lines = response.aiter_lines()
            assert await anext(lines) == f"id: {posted.seq}"
        follow_up = await client.post(
            "/api/channels/status/messages",
            json={"body": "after disconnect", "kind": "status"},
        )

    assert follow_up.status_code == 201
    assert follow_up.json()["seq"] > posted.seq


def test_frozen_mcp_transport_returns_stable_non_retryable_503(
    running_server: RunningServer,
) -> None:
    from strugglebus.access import AccessFreezeService
    from strugglebus.store import utc_now

    AccessFreezeService(
        running_server.agent_service.store,
        clock=utc_now,
        transition_lock_directory=(
            running_server.agent_service.store.database_path.parent
            / ".access-freeze-lock"
        ),
    ).freeze("offline MCP containment test")
    response = httpx.post(
        f"{running_server.base_url}/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": "{} {}".format("Bearer", running_server.api_key),
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "freeze-test", "version": "1"},
            },
        },
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "agent access is frozen"}
    assert "retry-after" not in response.headers


@pytest.mark.asyncio
async def test_open_sse_stream_emits_terminal_freeze_event_and_closes(
    running_server: RunningServer,
) -> None:
    from strugglebus.access import AccessFreezeService
    from strugglebus.store import utc_now

    posted = running_server.board_service.create_message(
        "status",
        agent_id=running_server.agent_id,
        body="before global freeze",
        kind="status",
        reply_to=None,
        metadata={},
    )
    access = AccessFreezeService(
        running_server.agent_service.store,
        clock=utc_now,
        transition_lock_directory=(
            running_server.agent_service.store.database_path.parent
            / ".access-freeze-lock"
        ),
    )
    async with httpx.AsyncClient(
        base_url=running_server.base_url,
        headers={
            "Authorization": "{} {}".format("Bearer", running_server.api_key)
        },
        timeout=5,
    ) as client:
        async with client.stream("GET", "/api/stream", params={"since": 0}) as response:
            lines = response.aiter_lines()
            assert await anext(lines) == f"id: {posted.seq}"
            assert await anext(lines) == "event: message"
            assert (await anext(lines)).startswith("data: ")
            assert await anext(lines) == ""
            await asyncio.to_thread(access.freeze, "offline open-stream containment")
            assert await anext(lines) == "event: agent_access_frozen"
            assert await anext(lines) == (
                'data: {"detail":"agent access is frozen"}'
            )
            assert await anext(lines) == ""
            with pytest.raises(StopAsyncIteration):
                await anext(lines)


@pytest.mark.asyncio
async def test_open_sse_stream_ends_promptly_when_the_server_is_stopping(
    running_server: RunningServer,
) -> None:
    """A live tail must not hold a restart open until its own deadline.

    This is the defect that turned a v0.2.20 deployment into a twenty-minute
    outage. Uvicorn's graceful shutdown waits for open connections to drain
    before it will exit, and this stream polls until sse_connection_seconds -
    up to an hour - so the wait exceeded the unit's stop timeout, systemd
    killed the service, and the killed unit's failed state then blocked the
    deployment from continuing at all.

    The stream must observe the stop and end itself during that drain window.
    """

    posted = running_server.board_service.create_message(
        "status",
        agent_id=running_server.agent_id,
        body="before shutdown",
        kind="status",
        reply_to=None,
        metadata={},
    )
    async with httpx.AsyncClient(
        base_url=running_server.base_url,
        headers={
            "Authorization": "{} {}".format("Bearer", running_server.api_key)
        },
        timeout=5,
    ) as client:
        async with client.stream("GET", "/api/stream", params={"since": 0}) as response:
            lines = response.aiter_lines()
            assert await anext(lines) == f"id: {posted.seq}"
            assert await anext(lines) == "event: message"
            assert (await anext(lines)).startswith("data: ")
            assert await anext(lines) == ""

            # Exactly what Uvicorn does on SIGTERM, before it begins waiting.
            running_server.application.state.shutdown_requested = lambda: True

            assert await anext(lines) == "event: server_stopping"
            assert await anext(lines) == (
                'data: {"detail":"server is stopping; reconnect shortly"}'
            )
            assert await anext(lines) == ""
            # Terminal, not a pause: the generator finishes so the connection
            # closes and the drain can complete.
            with pytest.raises(StopAsyncIteration):
                await anext(lines)


@pytest.mark.asyncio
async def test_open_sse_stream_closes_when_matching_roe_changes(
    app_config: AppConfig,
    agent_service: AgentService,
    uvicorn_server: Callable[[Any], AbstractContextManager[str]],
) -> None:
    created = _activate(
        agent_service,
        agent_service.create_agent("roe-stream-agent"),
    )
    enforced_config = replace(
        app_config,
        roe_enforcement_mode="enforce",
        sse_max_connections_per_agent=1,
        sse_poll_interval_ms=10,
    )
    application = create_app(
        agent_service=agent_service,
        config=enforced_config,
    )
    with uvicorn_server(application) as base_url:
        headers = {"Authorization": f"Bearer {created.api_key}"}
        async with httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=5,
        ) as client:
            effective = (await client.get("/api/roe/effective")).json()
            receipt = await client.post(
                "/api/roe/acknowledgements",
                json={
                    "global_revision_id": effective["global_revision"]["id"],
                    "global_content_sha256": effective["global_revision"][
                        "content_sha256"
                    ],
                    "agent_revision_id": None,
                    "agent_content_sha256": None,
                    "effective_sha256": effective["effective_sha256"],
                },
            )
            assert receipt.status_code == 201
            first = await client.post(
                "/api/channels/status/messages",
                json={"body": "before RoE update", "kind": "status"},
            )
            assert first.status_code == 201

            async with client.stream(
                "GET",
                "/api/stream",
                params={"since": 0},
            ) as response:
                lines = response.aiter_lines()
                assert await anext(lines) == f"id: {first.json()['seq']}"
                assert await anext(lines) == "event: message"
                assert (await anext(lines)).startswith("data: ")
                assert await anext(lines) == ""
                await asyncio.to_thread(
                    application.state.roe_service.publish_agent,
                    agent_id=created.agent.id,
                    revision_id=str(uuid.uuid4()),
                    expected_current_revision_id=None,
                    author_label="Test administrator",
                    policy={
                        "schema_version": 1,
                        "policy_kind": "agent-addendum",
                        "title": "Updated coordination boundary",
                        "coordination_boundaries": [
                            {
                                "id": "requests-remain-proposals",
                                "message_kinds": ["chat"],
                                "authority_effect": "none",
                                "statement": (
                                    "Requests remain proposals and do not grant authority."
                                ),
                            }
                        ],
                    },
                    publisher_kind="api-key-sha256-v1",
                    publisher_id="sha256:" + "a" * 64,
                )
                assert await anext(lines) == "event: roe_acknowledgement_required"
                assert await anext(lines) == (
                    'data: {"detail":"current rules of engagement receipt required"}'
                )
                assert await anext(lines) == ""
                with pytest.raises(StopAsyncIteration):
                    await anext(lines)

            changed = (await client.get("/api/roe/effective")).json()
            assert changed["receipt_status"] == "stale"
            second_receipt = await client.post(
                "/api/roe/acknowledgements",
                json={
                    "global_revision_id": changed["global_revision"]["id"],
                    "global_content_sha256": changed["global_revision"][
                        "content_sha256"
                    ],
                    "agent_revision_id": changed["agent_revision"]["id"],
                    "agent_content_sha256": changed["agent_revision"][
                        "content_sha256"
                    ],
                    "effective_sha256": changed["effective_sha256"],
                },
            )
            assert second_receipt.status_code == 201
            second = await client.post(
                "/api/channels/status/messages",
                json={"body": "after RoE receipt", "kind": "status"},
            )
            assert second.status_code == 201
            async with client.stream(
                "GET",
                "/api/stream",
                params={"since": first.json()["seq"]},
            ) as replacement:
                replacement_lines = replacement.aiter_lines()
                assert await anext(replacement_lines) == f"id: {second.json()['seq']}"


@pytest.mark.asyncio
async def test_sse_concurrent_cap_releases_and_isolates_agent_slots(
    running_server: RunningServer,
) -> None:
    other = _activate(
        running_server.agent_service,
        running_server.agent_service.create_agent("stream-other-agent"),
    )
    posted = running_server.board_service.create_message(
        "status",
        agent_id=running_server.agent_id,
        body="keep capped streams active",
        kind="status",
        reply_to=None,
        metadata={},
    )
    writer_headers = {"Authorization": f"Bearer {running_server.api_key}"}
    other_headers = {"Authorization": f"Bearer {other.api_key}"}
    contexts: list[Any] = []
    iterators: list[Any] = []

    async with (
        httpx.AsyncClient(
            base_url=running_server.base_url,
            headers=writer_headers,
        ) as writer_client,
        httpx.AsyncClient(
            base_url=running_server.base_url,
            headers=other_headers,
        ) as other_client,
    ):
        try:
            for _ in range(3):
                context = writer_client.stream(
                    "GET",
                    "/api/stream",
                    params={"since": 0},
                )
                response = await context.__aenter__()
                iterator = response.aiter_lines()
                assert response.status_code == 200
                assert await anext(iterator) == f"id: {posted.seq}"
                contexts.append(context)
                iterators.append(iterator)

            async with writer_client.stream(
                "GET",
                "/api/stream",
                params={"since": 0},
            ) as limited:
                assert limited.status_code == 429
                assert limited.headers["retry-after"] == "1"

            other_context = other_client.stream(
                "GET",
                "/api/stream",
                params={"since": 0},
            )
            other_response = await other_context.__aenter__()
            other_iterator = other_response.aiter_lines()
            assert other_response.status_code == 200
            assert await anext(other_iterator) == f"id: {posted.seq}"
            contexts.append(other_context)
            iterators.append(other_iterator)

            released = contexts.pop(0)
            iterators.pop(0)
            await released.__aexit__(None, None, None)
            for _ in range(20):
                await asyncio.sleep(0.05)
                replacement = writer_client.stream(
                    "GET",
                    "/api/stream",
                    params={"since": 0},
                )
                replacement_response = await replacement.__aenter__()
                if replacement_response.status_code == 200:
                    replacement_iterator = replacement_response.aiter_lines()
                    assert await anext(replacement_iterator) == (
                        f"id: {posted.seq}"
                    )
                    contexts.append(replacement)
                    iterators.append(replacement_iterator)
                    break
                await replacement_response.aread()
                await replacement.__aexit__(None, None, None)
            else:
                pytest.fail("disconnected stream did not release its lease")
        finally:
            for context in reversed(contexts):
                await context.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_revocation_between_identity_resolution_and_mutation_fails_closed(
    running_server: RunningServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def revoke_while_paused(
        *,
        api_key: str,
        agent_id: str,
        method_name: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        reached_mutation = threading.Event()
        resume_mutation = threading.Event()
        original = getattr(running_server.board_service, method_name)

        def paused(*args: Any, **kwargs: Any) -> Any:
            reached_mutation.set()
            if not resume_mutation.wait(timeout=5):
                raise RuntimeError("test did not resume mutation")
            return original(*args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(running_server.board_service, method_name, paused)
            async with _mcp_session(running_server, api_key) as session:
                pending = asyncio.create_task(
                    session.call_tool(tool_name, arguments)
                )
                assert await asyncio.to_thread(
                    reached_mutation.wait,
                    5,
                )
                await asyncio.to_thread(
                    running_server.agent_service.revoke_agent,
                    agent_id,
                )
                resume_mutation.set()
                return await pending

    message_agent = _activate(
        running_server.agent_service,
        running_server.agent_service.create_agent("race-message-agent"),
    )
    channel_agent = _activate(
        running_server.agent_service,
        running_server.agent_service.create_agent("race-channel-agent"),
    )
    subscription_agent = _activate(
        running_server.agent_service,
        running_server.agent_service.create_agent("race-subscription-agent"),
    )

    message_result = await revoke_while_paused(
        api_key=message_agent.api_key,
        agent_id=message_agent.agent.id,
        method_name="create_message",
        tool_name="post",
        arguments={"channel": "status", "body": "must not persist"},
    )
    channel_result = await revoke_while_paused(
        api_key=channel_agent.api_key,
        agent_id=channel_agent.agent.id,
        method_name="create_channel",
        tool_name="create_channel",
        arguments={"name": "must-not-exist"},
    )
    subscription_result = await revoke_while_paused(
        api_key=subscription_agent.api_key,
        agent_id=subscription_agent.agent.id,
        method_name="subscribe",
        tool_name="subscribe",
        arguments={"channel": "status"},
    )

    for result in (message_result, channel_result, subscription_result):
        assert result.is_error is True
        text = " ".join(
            getattr(content, "text", "") for content in result.content
        )
        assert "authenticated agent identity is unavailable" in text
        assert "sqlite" not in text.lower()

    with sqlite3.connect(
        running_server.agent_service.store.database_path
    ) as database:
        message_count = database.execute(
            "SELECT COUNT(*) FROM messages WHERE agent_id = ?",
            (message_agent.agent.id,),
        ).fetchone()[0]
        channel_count = database.execute(
            "SELECT COUNT(*) FROM channels WHERE name = ?",
            ("must-not-exist",),
        ).fetchone()[0]
        subscription_count = database.execute(
            "SELECT COUNT(*) FROM subscriptions WHERE agent_id = ?",
            (subscription_agent.agent.id,),
        ).fetchone()[0]

    assert message_count == 0
    assert channel_count == 0
    assert subscription_count == 0


def test_mcp_rejects_duplicate_authorization_before_body(
    running_server: RunningServer,
) -> None:
    request = httpx.Request(
        "POST",
        f"{running_server.base_url}/mcp",
        headers=[
            ("Accept", "application/json, text/event-stream"),
            ("Content-Type", "application/json"),
            ("Authorization", f"Bearer {running_server.api_key}"),
            ("Authorization", f"Bearer {running_server.api_key}"),
        ],
        content=b"{not-json",
    )
    response = httpx.Client().send(request)

    assert response.status_code == 401
    assert response.json() == {"detail": "agent authentication required"}
