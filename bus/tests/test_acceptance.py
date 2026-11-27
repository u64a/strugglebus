from __future__ import annotations

import asyncio
import io
import json
import os
import sqlite3
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractContextManager, asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

from strugglebus.app import create_app
from strugglebus.cli import EXIT_OK, main as cli_main
from strugglebus.migrations import LATEST_SCHEMA_VERSION


ADMIN_TOKEN = "acceptance-only-admin-token"


@asynccontextmanager
async def _mcp_session(base_url: str, api_key: str) -> AsyncIterator[ClientSession]:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=5,
    ) as http_client:
        async with streamable_http_client(
            f"{base_url}/mcp",
            http_client=http_client,
        ) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session


async def _register_agent(
    client: httpx.AsyncClient,
    name: str,
) -> dict[str, Any]:
    response = await client.post(
        "/api/agents",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={
            "request_id": str(uuid.uuid4()),
            "name": name,
            "description": f"{name} acceptance identity",
            "host": "acceptance.lan",
        },
    )
    assert response.status_code == 201, response.text
    value = response.json()
    agent = value["agent"]
    credential = value["credential"]
    api_key = value["credential_secret"]
    proof = await client.post(
        "/api/credentials/prove",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "request_id": str(uuid.uuid4()),
            "expected_agent_id": agent["id"],
            "expected_agent_name": agent["name"],
            "expected_credential_epoch": agent["credential_epoch"],
            "expected_credential_version": credential["version"],
        },
    )
    assert proof.status_code == 200, proof.text
    return {**agent, "api_key": api_key, "credential": proof.json()}


async def _enroll_agent(
    client: httpx.AsyncClient,
    application: Any,
    name: str,
    *,
    prefix: str,
) -> dict[str, Any]:
    """Self-register over the real server using a single-use enrollment token."""

    issued = application.state.agent_service.create_enrollment(
        name_prefix=prefix,
        reason="acceptance enrollment",
    )
    token_headers = {"Authorization": f"Bearer {issued.token}"}
    response = await client.post(
        "/api/enrollments/redeem",
        headers=token_headers,
        json={
            "request_id": str(uuid.uuid4()),
            "name": name,
            "host": "acceptance.lan",
        },
    )
    assert response.status_code == 201, response.text
    value = response.json()
    agent = value["agent"]
    credential = value["credential"]
    api_key = value["credential_secret"]
    assert agent["name"] == name
    assert credential["status"] == "pending"

    replay = await client.post(
        "/api/enrollments/redeem",
        headers=token_headers,
        json={
            "request_id": str(uuid.uuid4()),
            "name": f"{prefix}-replay-attempt",
            "host": "acceptance.lan",
        },
    )
    assert replay.status_code == 401, replay.text

    proof = await client.post(
        "/api/credentials/prove",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "request_id": str(uuid.uuid4()),
            "expected_agent_id": agent["id"],
            "expected_agent_name": agent["name"],
            "expected_credential_epoch": agent["credential_epoch"],
            "expected_credential_version": credential["version"],
        },
    )
    assert proof.status_code == 200, proof.text
    return {**agent, "api_key": api_key, "credential": proof.json()}


async def _next_sse_message(
    lines: AsyncIterator[str],
    expected_seq: int,
) -> dict[str, Any]:
    fields: dict[str, list[str]] = {}
    async with asyncio.timeout(5):
        async for line in lines:
            if line.startswith(":"):
                continue
            if line:
                name, separator, value = line.partition(":")
                if separator and value.startswith(" "):
                    value = value[1:]
                fields.setdefault(name, []).append(value)
                continue
            if fields.get("event") == ["message"]:
                event_id = fields.get("id")
                if event_id != [str(expected_seq)]:
                    raise AssertionError(f"unexpected resumed SSE id: {event_id!r}")
                payload = json.loads("\n".join(fields.get("data", [])))
                if not isinstance(payload, dict) or payload.get("seq") != expected_seq:
                    raise AssertionError(
                        "resumed SSE payload has an unexpected sequence"
                    )
                return payload
            fields.clear()
    raise AssertionError("resumed SSE message was not received")


@pytest.mark.asyncio
async def test_v01_end_to_end_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    uvicorn_server: Callable[[Any], AbstractContextManager[str]],
) -> None:
    data_dir = tmp_path / "data"
    runtime_dir = tmp_path / "run"
    backup_dir = tmp_path / "backups"
    credential_dir = tmp_path / "credentials"
    for directory in (data_dir, runtime_dir, backup_dir, credential_dir):
        directory.mkdir()
    credential_dir.chmod(0o700)
    credential = credential_dir / "admin-token"
    credential.write_text(ADMIN_TOKEN, encoding="utf-8")
    credential.chmod(0o600)
    database_path = data_dir / "strugglebus.db"

    environment = {
        "CREDENTIALS_DIRECTORY": str(credential_dir),
        "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": str(credential),
        "STRUGGLEBUS_BACKUP_DIR": str(backup_dir),
        "STRUGGLEBUS_DATA_DIR": str(data_dir),
        "STRUGGLEBUS_DATABASE_PATH": str(database_path),
        "STRUGGLEBUS_PUBLIC_BASE_URL": "http://127.0.0.1",
        "STRUGGLEBUS_RUNTIME_DIR": str(runtime_dir),
        "STRUGGLEBUS_SSE_CONNECTION_SECONDS": "2",
        "STRUGGLEBUS_SSE_HEARTBEAT_SECONDS": "1",
        "STRUGGLEBUS_SSE_POLL_INTERVAL_MS": "10",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    application = create_app()
    assert not database_path.exists()

    with uvicorn_server(application) as base_url:
        async with httpx.AsyncClient(base_url=base_url, timeout=5) as public:
            health = await public.get("/healthz")
            assert health.status_code == 200
            assert health.json() == {"status": "ok"}

            writer = await _register_agent(public, "acceptance-writer")
            reader = await _enroll_agent(
                public,
                application,
                "acceptance-reader",
                prefix="acceptance",
            )
            writer_headers = {
                "Authorization": f"Bearer {writer['api_key']}"
            }
            reader_headers = {
                "Authorization": f"Bearer {reader['api_key']}"
            }

            defaults = await public.get("/api/channels", headers=writer_headers)
            assert [channel["name"] for channel in defaults.json()] == [
                "announce",
                "help",
                "humans",
                "status",
                "strugglebus-improvements",
            ]

            async with (
                _mcp_session(base_url, writer["api_key"]) as writer_mcp,
                _mcp_session(base_url, reader["api_key"]) as reader_mcp,
            ):
                writer_identity = await writer_mcp.call_tool("whoami")
                reader_identity = await reader_mcp.call_tool("whoami")
                server_info = await writer_mcp.call_tool("server_info")
                assert writer_identity.structured_content["agent"]["id"] == writer["id"]
                assert reader_identity.structured_content["agent"]["id"] == reader["id"]
                rest_server_info = await public.get(
                    "/api/server-info",
                    headers=writer_headers,
                )
                assert server_info.structured_content == rest_server_info.json()
                assert server_info.structured_content["application_version"] == "0.2.74"
                assert (
                    server_info.structured_content["integration_guide_version"]
                    == "1.19.0"
                )

                channel = await writer_mcp.call_tool(
                    "create_channel",
                    {
                        "name": "Acceptance Room",
                        "purpose": "v0.1 release acceptance",
                    },
                )
                assert channel.is_error is False
                subscribed = await reader_mcp.call_tool(
                    "subscribe",
                    {"channel": "acceptance-room"},
                )
                assert subscribed.structured_content["subscribed"] is True

                question = await writer_mcp.call_tool(
                    "post",
                    {
                        "channel": "acceptance-room",
                        "body": "<script>release needle</script>",
                        "kind": "question",
                        "metadata": {"facade": "mcp"},
                    },
                )
                question_seq = question.structured_content["seq"]
                rest_read = await public.get(
                    "/api/channels/acceptance-room/messages",
                    headers=reader_headers,
                )
                assert [message["seq"] for message in rest_read.json()] == [
                    question_seq
                ]

                answer = await public.post(
                    "/api/channels/acceptance-room/messages",
                    headers=reader_headers,
                    json={
                        "body": "bounded searchable answer",
                        "kind": "answer",
                        "reply_to": question_seq,
                        "metadata": {"facade": "rest"},
                    },
                )
                assert answer.status_code == 201
                answer_seq = answer.json()["seq"]
                mcp_read = await writer_mcp.call_tool(
                    "read",
                    {"channel": "acceptance-room", "limit": 10},
                )
                assert [
                    message["seq"]
                    for message in mcp_read.structured_content["messages"]
                ] == [question_seq, answer_seq]
                assert (
                    mcp_read.structured_content["messages"][1]["reply_to"]
                    == question_seq
                )
                focused = await writer_mcp.call_tool(
                    "read_replies",
                    {"message_seq": question_seq},
                )
                rest_focused = await public.get(
                    f"/api/messages/{question_seq}/replies",
                    headers=writer_headers,
                )
                assert focused.structured_content["messages"] == rest_focused.json()
                assert [
                    message["seq"]
                    for message in focused.structured_content["messages"]
                ] == [answer_seq]

                mention = await writer_mcp.call_tool(
                    "post",
                    {
                        "channel": "help",
                        "body": "@acceptance-reader inspect the release needle",
                    },
                )
                mention_seq = mention.structured_content["seq"]
                catch_up = await reader_mcp.call_tool(
                    "catch_up",
                    {"limit": 10},
                )
                assert [
                    message["seq"]
                    for message in catch_up.structured_content["messages"]
                ] == [question_seq, answer_seq, mention_seq]

                mcp_search = await reader_mcp.call_tool(
                    "search",
                    {"query": "bounded searchable", "limit": 10},
                )
                assert [
                    message["seq"]
                    for message in mcp_search.structured_content["messages"]
                ] == [answer_seq]
                rest_search = await public.get(
                    "/api/search",
                    headers=writer_headers,
                    params={"query": "release needle", "limit": 10},
                )
                assert [
                    message["seq"] for message in rest_search.json()
                ] == [mention_seq, question_seq]

                async with public.stream(
                    "GET",
                    "/api/stream",
                    headers={
                        **reader_headers,
                        "Last-Event-ID": str(question_seq),
                    },
                ) as stream:
                    assert stream.status_code == 200
                    resumed = await _next_sse_message(
                        stream.aiter_lines(),
                        answer_seq,
                    )
                    assert resumed["reply_to"] == question_seq

            page = await public.get("/")
            assert page.status_code == 503
            assert "<script>release needle</script>" not in page.text
            assert "release needle" not in page.text
            assert "metadata" not in page.text

            cli_stdout = io.StringIO()
            cli_stderr = io.StringIO()
            exit_code = await asyncio.to_thread(
                cli_main,
                ["agent", "revoke", "acceptance-reader"],
                stdout=cli_stdout,
                stderr=cli_stderr,
            )
            assert exit_code == EXIT_OK
            assert reader["api_key"] not in cli_stdout.getvalue()
            assert reader["api_key"] not in cli_stderr.getvalue()

            denied = await public.get("/api/channels", headers=reader_headers)
            assert denied.status_code == 401
            assert reader["api_key"] not in denied.text
            with pytest.RaisesGroup(MCPError, flatten_subgroups=True):
                async with _mcp_session(base_url, reader["api_key"]):
                    pass

        assert application.state.configuration_initialized is True
        with sqlite3.connect(database_path) as database:
            assert database.execute("PRAGMA user_version").fetchone() == (
                LATEST_SCHEMA_VERSION,
            )
            assert database.execute(
                "SELECT COUNT(*) FROM agents "
                "WHERE revoked_at IS NULL AND name NOT IN "
                "('system:strugglebus-maintenance', 'human:operator')"
            ).fetchone() == (1,)

    assert application.state.configuration_initialized is False
    assert os.environ["STRUGGLEBUS_DATABASE_PATH"] == str(database_path)
