from __future__ import annotations

from datetime import datetime

import httpx
import pytest

from test_mcp_integration import _mcp_session, running_server


@pytest.mark.asyncio
async def test_large_drain_tokens_cross_rest_mcp_with_identical_pages(running_server):
    board = running_server.board_service
    agent_id = running_server.agent_id
    expected = []
    for index in range(505):
        message = board.create_message(
            "status", agent_id=agent_id, body=str(index),
            kind="chat", reply_to=None, metadata={},
        )
        expected.append(message.seq)
    async with httpx.AsyncClient(
        base_url=running_server.base_url,
        headers={"Authorization": "Bearer " + running_server.api_key},
    ) as rest:
        async with _mcp_session(running_server, running_server.api_key) as session:
            subscribed = await rest.put("/api/subscriptions/status")
            assert subscribed.status_code == 200
            listing = await session.call_tool("list_subscriptions")
            assert listing.structured_content["channels"] == (
                await rest.get("/api/subscriptions")
            ).json()
            first = await rest.get("/api/catch-up", params={
                "start_drain": True, "limit": 50,
            })
            assert first.status_code == 200
            received = [message["seq"] for message in first.json()]
            token = first.headers["Catch-Up-Continuation"]
            snapshot_seq = int(first.headers["Catch-Up-Snapshot-Seq"])
            while True:
                args = {"limit": 50, "continuation": token}
                mcp = await session.call_tool("catch_up", args)
                assert not mcp.is_error
                page = mcp.structured_content
                replay = await rest.get("/api/catch-up", params=args)
                assert replay.status_code == 200
                assert replay.json() == page["messages"]
                assert page["mode"] == "drain"
                assert page["snapshot_seq"] == snapshot_seq
                assert replay.headers["Catch-Up-Complete"] == str(page["complete"]).lower()
                assert replay.headers.get("Catch-Up-Continuation") == page["continuation"]
                assert datetime.fromisoformat(
                    replay.headers["Catch-Up-Expires-At"]
                ) == datetime.fromisoformat(page["expires_at"])
                received.extend(message["seq"] for message in page["messages"])
                if page["complete"]:
                    break
                token = page["continuation"]
            assert received == expected
            legacy = await session.call_tool("catch_up", {"limit": 50})
            assert legacy.structured_content["mode"] == "legacy"
            assert legacy.structured_content["complete"] is None
            invalid = await session.call_tool("catch_up", {
                "continuation": "not-a-token",
            })
            assert invalid.is_error
            removed = await session.call_tool("unsubscribe", {"channel": "status"})
            assert removed.structured_content == (await rest.delete(
                "/api/subscriptions/status"
            )).json()
