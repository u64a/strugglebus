from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from operator_test_support import operator_client
from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.config import AppConfig
from strugglebus.dashboard import (
    ACTIVITY_REFRESH_SECONDS,
    DASHBOARD_STYLESHEET,
    DASHBOARD_STYLESHEET_PATH,
)
from strugglebus.errors import StorageError
from strugglebus.service import BoardService
from strugglebus.store import SQLiteStore


def _services(
    config: AppConfig,
    *,
    now: datetime | None = None,
) -> tuple[AgentService, BoardService]:
    store = SQLiteStore(
        config.database_path,
        backup_dir=config.backup_dir,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
    )
    clock = None if now is None else lambda: now
    agents = AgentService(store, **({} if clock is None else {"clock": clock}))
    board = BoardService(
        store,
        max_message_bytes=config.max_message_bytes,
        max_metadata_bytes=config.max_metadata_bytes,
        max_channels=config.max_channels,
        **({} if clock is None else {"clock": clock}),
    )
    board.initialize()
    return agents, board


def _post(
    board: BoardService,
    *,
    agent_id: str,
    body: str,
    channel: str = "status",
    kind: str = "chat",
    reply_to: int | None = None,
    metadata: dict[str, object] | None = None,
):
    return board.create_message(
        channel,
        agent_id=agent_id,
        body=body,
        kind=kind,
        reply_to=reply_to,
        metadata={} if metadata is None else metadata,
    )


def _client(
    config: AppConfig,
    agents: AgentService,
    board: BoardService,
):
    return operator_client(
        create_app(
            config=config,
            agent_service=agents,
            board_service=board,
        )
    )


_EXPECTED_STRICT_CSP = {
    "default-src": ("'none'",),
    "style-src": ("'self'",),
    "script-src": ("'none'",),
    "connect-src": ("'none'",),
    "img-src": ("'none'",),
    "font-src": ("'none'",),
    "object-src": ("'none'",),
    "base-uri": ("'none'",),
    "form-action": ("'self'",),
    "frame-ancestors": ("'none'",),
}


def _csp_directives(policy: str) -> dict[str, tuple[str, ...]]:
    directives: dict[str, tuple[str, ...]] = {}
    for item in policy.split(";"):
        parts = item.strip().split()
        if not parts:
            continue
        if parts[0] in directives:
            raise AssertionError(f"duplicate CSP directive: {parts[0]}")
        directives[parts[0]] = tuple(parts[1:])
    return directives


def _csp_sources(policy: str, directive: str) -> tuple[str, ...]:
    directives = _csp_directives(policy)
    return directives.get(directive, directives.get("default-src", ()))


def _allows_same_origin_stylesheet(policy: str, path: str) -> bool:
    return (
        path.startswith("/")
        and not path.startswith("//")
        and "'self'" in _csp_sources(policy, "style-src")
    )


def _allows_inline_styles(policy: str) -> bool:
    return "'unsafe-inline'" in _csp_sources(policy, "style-src")


def _production_caddy_csp() -> str:
    template = (
        Path(__file__).resolve().parents[1]
        / "deploy/roles/caddy/templates/Caddyfile.j2"
    ).read_text(encoding="utf-8")
    match = re.search(r'Content-Security-Policy "([^"]+)"', template)
    assert match is not None
    return match.group(1)


def test_overview_empty_state_landmarks_versions_and_security_headers(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)

    with _client(app_config, agents, board) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "<header" in response.text
    assert '<main class="shell" id="main-content" tabindex="-1">' in response.text
    assert '<details><summary>Versions</summary>' in response.text
    assert 'aria-labelledby="summary-heading">' in response.text
    assert re.search(r'aria-current="page">.*?<span>Overview</span></a>', response.text)
    assert "No recent activity" in response.text
    assert "Application 0.2.71" in response.text
    assert "Release development" in response.text
    assert "Protocol 1" in response.text
    assert "Enabled agents</span><span class=\"summary-value\">0" in response.text
    assert "Channels</span><span class=\"summary-value\">5" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "script-src 'none'" in response.headers["content-security-policy"]
    assert "form-action 'self'" in response.headers["content-security-policy"]
    assert response.headers["permissions-policy"]


def test_all_console_pages_use_only_content_addressed_same_origin_css(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    paths = ("/", "/activity", "/channels", "/agents", "/system")

    with _client(app_config, agents, board) as client:
        responses = [client.get(path) for path in paths]

    production_csp = _production_caddy_csp()
    with pytest.raises(AssertionError, match="duplicate CSP directive"):
        _csp_directives("style-src *; style-src 'self'")
    assert _csp_directives(production_csp) == _EXPECTED_STRICT_CSP
    assert _allows_same_origin_stylesheet(
        production_csp, DASHBOARD_STYLESHEET_PATH
    )
    assert not _allows_inline_styles(production_csp)
    for response in responses:
        assert response.status_code == 200
        assert response.headers["referrer-policy"] == "same-origin"
        assert "<style" not in response.text.lower()
        assert re.search(r"\sstyle\s*=", response.text, re.IGNORECASE) is None
        assert re.findall(
            r'<link rel="stylesheet" href="([^"]+)">',
            response.text,
        ) == [DASHBOARD_STYLESHEET_PATH]
        application_csp = response.headers["content-security-policy"]
        assert _csp_directives(application_csp) == _EXPECTED_STRICT_CSP
        assert _allows_same_origin_stylesheet(
            application_csp, DASHBOARD_STYLESHEET_PATH
        )
        assert not _allows_inline_styles(application_csp)


def test_dashboard_stylesheet_is_safe_cacheable_first_party_css(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)

    with _client(app_config, agents, board) as client:
        response = client.get(DASHBOARD_STYLESHEET_PATH)
        bad_host = client.get(
            DASHBOARD_STYLESHEET_PATH,
            headers={"Host": "public.example"},
        )

    assert response.status_code == 200
    assert response.text == DASHBOARD_STYLESHEET
    assert response.headers["content-type"] == "text/css; charset=utf-8"
    assert response.headers["cache-control"] == (
        "public, max-age=31536000, immutable"
    )
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "color-scheme: dark" in response.text
    assert "@media (max-width: 36rem)" in response.text
    assert "@media (prefers-reduced-motion: reduce)" in response.text
    assert ":focus-visible" in response.text
    assert re.search(
        r"api[_-]?key|authorization|admin token|access freeze",
        response.text,
        re.IGNORECASE,
    ) is None
    assert bad_host.status_code == 421


def test_primary_nav_marks_active_section_on_every_page(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)

    with _client(app_config, agents, board) as client:
        pages = {
            "/": "Overview",
            "/activity": "Activity",
            "/channels": "Channels",
            "/agents": "Agents",
            "/system": "Administration",
            "/register": "Administration",
            "/devices": "Administration",
        }
        for path, label in pages.items():
            response = client.get(path)
            assert response.status_code == 200
            assert re.findall(
                r'aria-current="page"><svg.*?</svg><span>([^<]+)</span></a>',
                response.text,
            ) == [label, label]
            assert '<nav aria-label="Console sections">' in response.text
            assert 'class="primary-nav"' not in response.text
            assert '<aside class="rail"' in response.text
            assert '<header class="mobile-top">' in response.text


def test_activity_page_links_from_overview_teaser(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    posted = _post(board, agent_id=writer.id, body="teaser message")

    with _client(app_config, agents, board) as client:
        overview = client.get("/")
        activity = client.get("/activity")

    assert posted.body in overview.text
    assert '<a class="button button-secondary" href="/activity">' in overview.text
    assert 'aria-labelledby="activity-heading"' in activity.text
    assert '<form method="get" action="/activity">' in activity.text


def test_dashboard_escapes_untrusted_values_and_omits_sensitive_fields(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    created = agents.create_agent(
        "writer-copilot",
        description="PRIVATE-DESCRIPTION",
        host="PRIVATE-HOST",
    )
    board.subscribe("status", agent_id=created.agent.id)
    _post(
        board,
        agent_id=created.agent.id,
        body='<script>alert("x")</script><img src=x onerror=alert(1)>',
        metadata={"PRIVATE-METADATA": "<b>unsafe</b>"},
    )

    with _client(app_config, agents, board) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "<script>" not in response.text
    assert "<img" not in response.text
    assert "&lt;script&gt;" in response.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in response.text
    assert "PRIVATE-DESCRIPTION" not in response.text
    assert "PRIVATE-HOST" not in response.text
    assert "PRIVATE-METADATA" not in response.text
    assert created.agent.id not in response.text
    assert "Subscriptions</span><span class=\"summary-value\">1" in response.text


def test_dashboard_filters_and_keyset_pagination_are_bounded(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    first_agent = agents.create_agent("first-copilot").agent
    second_agent = agents.create_agent("second-copilot").agent
    first = _post(board, agent_id=first_agent.id, body="first matching")
    _post(
        board,
        agent_id=second_agent.id,
        body="different agent",
        channel="help",
    )
    latest = _post(board, agent_id=first_agent.id, body="latest matching")

    with _client(app_config, agents, board) as client:
        page = client.get(
            "/activity",
            params={
                "channel": "status",
                "agent": "first-copilot",
                "limit": 1,
            },
        )
        older = client.get(
            "/activity",
            params={
                "channel": "status",
                "agent": "first-copilot",
                "limit": 1,
                "before": latest.seq,
            },
        )
        no_results = client.get("/activity", params={"channel": "unused-channel"})
        invalid = client.get("/activity?limit=101")
        unknown = client.get("/activity?other=value")
        duplicate = client.get("/activity?limit=10&limit=25")
        noncanonical = client.get("/activity?channel=Status")

    assert latest.body in page.text
    assert first.body not in page.text
    assert f"before={latest.seq}" in page.text.replace("&amp;", "&")
    assert first.body in older.text
    assert latest.body not in older.text
    assert "No matching activity" in no_results.text
    assert invalid.status_code == 422
    assert unknown.status_code == 422
    assert duplicate.status_code == 422
    assert noncanonical.status_code == 422


def test_dashboard_renders_only_direct_reply_context(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    parent = _post(board, agent_id=writer.id, body="bounded parent context")
    reply = _post(
        board,
        agent_id=writer.id,
        body="direct reply",
        reply_to=parent.seq,
    )
    nested = _post(
        board,
        agent_id=writer.id,
        body="reply to reply",
        reply_to=reply.seq,
    )

    with _client(app_config, agents, board) as client:
        context_page = client.get("/activity", params={"limit": 1})
        linked_page = client.get("/activity", params={"limit": 2})

    assert nested.body in context_page.text
    assert f"Direct reply to message #{reply.seq}" in context_page.text
    assert parent.body not in context_page.text
    assert f'href="#message-{reply.seq}"' in linked_page.text
    assert "reply to reply" in linked_page.text
    assert "direct reply" in linked_page.text


def test_dashboard_shows_only_strict_validated_visible_status_progression(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    request_id = UUID("51e9bf56-f625-4f5f-a4e8-355d925db01e")

    def status_body(state: str, detail: str, *, sender: str = writer.name) -> str:
        return json.dumps(
            {
                "protocol_version": 1,
                "message_type": "test_status",
                "request_id": str(request_id),
                "test_session_id": "a9ce378b-e7c3-4811-a70d-a44025443f0f",
                "parent_request_id": None,
                "sender_agent": sender,
                "state": state,
                "detail": detail,
                "observed_at": "2026-08-30T00:00:00Z",
                "artifacts": [],
            }
        )

    _post(
        board,
        agent_id=writer.id,
        body=status_body("running", "Tests are running."),
        kind="status",
    )
    _post(
        board,
        agent_id=writer.id,
        body=status_body("succeeded", "Tests passed."),
        kind="status",
    )
    invalid = status_body("running", "Untrusted mismatch.", sender="other-copilot")
    _post(board, agent_id=writer.id, body=invalid, kind="status")

    with _client(app_config, agents, board) as client:
        response = client.get("/activity")

    assert "Tests are running." in response.text
    assert "Tests passed." in response.text
    assert "Visible updates for request" in response.text
    assert "Running at" in response.text
    assert "Succeeded at" in response.text
    assert "Untrusted mismatch." in response.text
    assert "Untrusted mismatch.</p>" not in response.text
    assert response.text.count("Visible updates for request") == 1


def test_dashboard_marks_old_status_messages_stale(
    app_config: AppConfig,
) -> None:
    old = datetime.now(UTC) - timedelta(days=8)
    agents, board = _services(app_config, now=old)
    writer = agents.create_agent("writer-copilot").agent
    _post(
        board,
        agent_id=writer.id,
        body="old status",
        kind="status",
    )

    with _client(app_config, agents, board) as client:
        response = client.get("/activity")

    assert "old status" in response.text
    assert "Stale status" in response.text
    assert re.search(r"<time datetime=\"[^\"]+\">[^<]+UTC</time>", response.text)


def test_dashboard_returns_generic_html_error_for_storage_failure(
    app_config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agents, board = _services(app_config)

    def fail(**_kwargs):
        raise StorageError("PRIVATE DATABASE PATH")

    monkeypatch.setattr(board, "dashboard_snapshot", fail)
    with _client(app_config, agents, board) as client:
        overview = client.get("/")
        activity = client.get("/activity")

    for response in (overview, activity):
        assert response.status_code == 503
        assert response.headers["content-type"].startswith("text/html")
        assert "Dashboard unavailable" in response.text
        assert "PRIVATE DATABASE PATH" not in response.text


def test_channels_and_agents_pages_return_generic_html_error_for_storage_failure(
    app_config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agents, board = _services(app_config)

    def fail(**_kwargs):
        raise StorageError("PRIVATE DATABASE PATH")

    monkeypatch.setattr(board, "channel_activity", fail)
    monkeypatch.setattr(agents, "list_managed_agents", fail)
    with _client(app_config, agents, board) as client:
        channels = client.get("/channels")
        agents_page = client.get("/agents")

    for response in (channels, agents_page):
        assert response.status_code == 503
        assert response.headers["content-type"].startswith("text/html")
        assert "unavailable" in response.text
        assert "PRIVATE DATABASE PATH" not in response.text


def test_dashboard_limit_respects_lower_configured_cap(
    app_config: AppConfig,
) -> None:
    config = replace(app_config, human_activity_limit=5)
    agents, board = _services(config)

    with _client(config, agents, board) as client:
        default_page = client.get("/activity")
        over_limit = client.get("/activity", params={"limit": 6})

    assert '<option value="5" selected>5</option>' in default_page.text
    assert over_limit.status_code == 422


def test_dashboard_preserves_valid_custom_limit(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)

    with _client(app_config, agents, board) as client:
        response = client.get("/activity", params={"limit": 17})

    assert '<option value="17" selected>17</option>' in response.text


def test_activity_auto_refresh_toggle_is_opt_in_bounded_and_scriptless(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    _post(board, agent_id=writer.id, body="watched message")

    with _client(app_config, agents, board) as client:
        default_page = client.get("/activity")
        refreshing = client.get("/activity", params={"refresh": "1"})
        disabled = client.get("/activity", params={"refresh": "0"})
        invalid = client.get("/activity", params={"refresh": "yes"})
        duplicated = client.get("/activity?refresh=1&refresh=1")

    assert '<meta http-equiv="refresh"' not in default_page.text
    assert "Auto-refresh every 2 minutes" in default_page.text
    assert (
        f'<meta http-equiv="refresh" content="{ACTIVITY_REFRESH_SECONDS}">'
        in refreshing.text
    )
    assert "Stop auto-refresh" in refreshing.text
    assert '<input type="hidden" name="refresh" value="1">' in refreshing.text
    assert "refresh=1" in refreshing.text.replace("&amp;", "&")
    assert '<meta http-equiv="refresh"' not in disabled.text
    assert invalid.status_code == 422
    assert duplicated.status_code == 422
    # The toggle must not reintroduce script into a script-free console.
    assert "<script" not in refreshing.text.lower()


def test_dashboard_treats_deep_status_json_as_ordinary_text(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    deeply_nested = "[" * 2_000 + "0" + "]" * 2_000
    _post(
        board,
        agent_id=writer.id,
        body=deeply_nested,
        kind="status",
    )

    with _client(app_config, agents, board) as client:
        response = client.get("/activity")

    assert response.status_code == 200
    assert deeply_nested in response.text
    assert "Visible updates for request" not in response.text


def test_dashboard_can_filter_visible_history_from_revoked_agent(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("former-copilot").agent
    _post(board, agent_id=writer.id, body="historical message")
    agents.revoke_agent(writer.id)

    with _client(app_config, agents, board) as client:
        response = client.get("/activity", params={"agent": writer.name})

    assert response.status_code == 200
    assert "historical message" in response.text
    with _client(app_config, agents, board) as client:
        overview = client.get("/")
    assert "Enabled agents</span><span class=\"summary-value\">0" in overview.text


def test_channels_page_lists_bounded_fields_and_excludes_creator_id(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    board.create_channel(
        "roadmap",
        purpose='<script>alert(1)</script>PRIVATE-PURPOSE-DETAIL',
        created_by=writer.id,
    )
    board.subscribe("roadmap", agent_id=writer.id)
    _post(board, agent_id=writer.id, body="roadmap update", channel="roadmap")

    with _client(app_config, agents, board) as client:
        response = client.get("/channels")

    assert response.status_code == 200
    assert 'aria-labelledby="channels-heading"' in response.text
    assert "#roadmap" in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;PRIVATE-PURPOSE-DETAIL" in (
        response.text
    )
    assert "<script>alert(1)</script>" not in response.text
    assert "Messages: <strong>1</strong>" in response.text
    assert "Subscribers: <strong>1</strong>" in response.text
    assert writer.id not in response.text
    # Default channels with no messages/subscribers still render bounded zero
    # values instead of omitting the row.
    assert "None yet" in response.text


def test_channels_page_keyset_pagination_and_empty_and_invalid_cursor(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)

    with _client(app_config, agents, board) as client:
        first_page = client.get("/channels", params={"limit": 2})
        invalid_limit = client.get("/channels?limit=101")
        noncanonical = client.get("/channels?after=Status")
        duplicate = client.get("/channels?after=status&after=help")

    assert first_page.status_code == 200
    assert "channels on this page" in first_page.text
    assert 'href="/channels?limit=2&amp;after=' in first_page.text
    assert invalid_limit.status_code == 422
    assert noncanonical.status_code == 422
    assert duplicate.status_code == 422

    with _client(app_config, agents, board) as client:
        exhausted = client.get("/channels", params={"after": "zzz-not-a-channel"})
    assert exhausted.status_code == 200
    assert "No channels to show" in exhausted.text
    assert "the end of the channel list" in exhausted.text


def test_agents_page_lists_bounded_fields_and_excludes_private_data(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    created = agents.create_agent(
        "writer-copilot",
        description="PRIVATE-DESCRIPTION",
        host="PRIVATE-HOST",
    )

    with _client(app_config, agents, board) as client:
        response = client.get("/agents")

    assert response.status_code == 200
    assert 'aria-labelledby="agents-heading"' in response.text
    assert '<h2 id="agents-heading">Agents on this bus</h2>' in response.text
    assert "writer-copilot" in response.text
    assert "Never" in response.text
    assert "PRIVATE-DESCRIPTION" not in response.text
    assert "PRIVATE-HOST" not in response.text
    assert created.agent.id in response.text
    assert created.api_key not in response.text
    assert "Enabled" in response.text


def test_agents_page_excludes_revoked_agents_and_shows_empty_state(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("former-copilot").agent
    agents.revoke_agent(writer.id)

    with _client(app_config, agents, board) as client:
        response = client.get("/agents")

    assert response.status_code == 200
    assert "former-copilot" not in response.text
    assert "No agents to show." in response.text
    assert ">Retired</option>" in response.text


def test_system_page_shows_versions_and_separate_operator_authority(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)

    with _client(app_config, agents, board) as client:
        response = client.get("/system")

    assert response.status_code == 200
    assert 'aria-labelledby="system-heading"' in response.text
    assert "Application 0.2.71" in response.text
    assert "Release development" in response.text
    assert "Coordination protocol" in response.text
    assert "You sign in here with the operator password" in response.text
    assert "one-time package for one exact agent name" in response.text
    assert "keeps its name and its messages" in response.text
    assert "currently open to" not in response.text
    assert "Signing in here never overrides a freeze" in response.text
