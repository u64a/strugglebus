"""Input validation and guidance that requests rely on once admitted.

Covers the refusal paths of the board service's validators, the stream
resume position, the orientation guidance text, and the MCP identity
middleware's handling of a missing or withdrawn identity.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from mcp.server.mcpserver.exceptions import ToolError

from strugglebus.app import IdentityInitializeMiddleware
from strugglebus.config import AppConfig
from strugglebus.errors import (
    AgentAccessFrozenError,
    ChannelNotFoundError,
    CredentialNotFoundError,
    DomainValidationError,
    StorageError,
)
from strugglebus.models import AgentOrientation
from strugglebus.orientation import RequiredAction, guidance, required_actions
from strugglebus.routes.streams import _resume_position, _stream_channel_filter
from strugglebus.service import (
    MAX_MESSAGE_LIMIT,
    MAX_SEARCH_QUERY_LENGTH,
    MAX_SEARCH_TERM_LENGTH,
    MAX_SEARCH_TERMS,
    MAX_SEQUENCE,
    BoardService,
    _search_expression,
    _serialize_message_metadata,
    normalize_name,
)
from strugglebus.store import SQLiteStore

# -- names --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("#Status", "status"),
        ("  release notes  ", "release-notes"),
        ("build__and--ship", "build-and-ship"),
        ("a" * 64, "a" * 64),
    ],
)
def test_channel_names_are_normalized_to_kebab_case(raw: str, normalized: str) -> None:
    assert normalize_name(raw) == normalized


@pytest.mark.parametrize("raw", ["", "   ", "#", "a" * 65, "-leading", "trailing-", "café", "a/b"])
def test_a_channel_name_that_cannot_be_kebab_case_is_refused(raw: str) -> None:
    with pytest.raises(DomainValidationError) as refused:
        normalize_name(raw)

    assert str(refused.value) == "channel name must be lowercase kebab-case"


@pytest.mark.parametrize("raw", [None, 7, b"status", ["status"]])
@pytest.mark.parametrize("agent", [False, True])
def test_a_name_that_is_not_text_is_refused(raw: Any, agent: bool) -> None:
    with pytest.raises(DomainValidationError) as refused:
        normalize_name(raw, agent=agent)

    assert str(refused.value) == "name must be text"


def test_an_agent_name_keeps_its_hash_and_needs_a_project_and_a_platform() -> None:
    assert normalize_name("StruggleBus Copilot", agent=True) == "strugglebus-copilot"
    assert normalize_name("a" * 126 + "-b", agent=True) == "a" * 126 + "-b"

    for raw in ("copilot", "#strugglebus-copilot", "a" * 127 + "-b", ""):
        with pytest.raises(DomainValidationError) as refused:
            normalize_name(raw, agent=True)
        assert str(refused.value) == (
            "agent name must be lowercase kebab-case with project and platform"
        )


# -- message metadata ---------------------------------------------------------


def test_metadata_is_serialized_canonically() -> None:
    serialized = _serialize_message_metadata(
        {"b": [1, 2.5, None, True, "x"], "a": {"nested": {"deep": []}}}, 1024,
    )

    assert serialized == '{"a":{"nested":{"deep":[]}},"b":[1,2.5,null,true,"x"]}'


@pytest.mark.parametrize(
    ("metadata", "detail"),
    [
        (["not", "an", "object"], "metadata must be a JSON object"),
        ({"when": datetime(2026, 1, 1, tzinfo=UTC)}, "metadata must contain only JSON values"),
        ({"items": (1, 2)}, "metadata must contain only JSON values"),
        ({"nested": {1: "integer key"}}, "metadata must contain only JSON values"),
        ({"nested": {"nul\x00key": 1}}, "metadata must contain only JSON values"),
        ({"ratio": float("nan")}, "metadata numbers must be finite"),
        ({"ratio": [float("inf")]}, "metadata numbers must be finite"),
        ({"ratio": {"low": float("-inf")}}, "metadata numbers must be finite"),
        ({"text": "x" * 64}, "metadata must not exceed 32 bytes"),
    ],
)
def test_metadata_that_is_not_bounded_finite_json_is_refused(
    metadata: Any, detail: str,
) -> None:
    with pytest.raises(DomainValidationError) as refused:
        _serialize_message_metadata(metadata, 32)

    assert str(refused.value) == detail


def test_metadata_nesting_is_bounded() -> None:
    def nested(levels: int) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for _ in range(levels):
            value = {"n": value}
        return value

    assert _serialize_message_metadata(nested(8), 1024).count("{") == 9
    with pytest.raises(DomainValidationError) as refused:
        _serialize_message_metadata(nested(9), 1024)

    assert str(refused.value) == "metadata nesting exceeds 8 levels"


# -- search -------------------------------------------------------------------


def test_a_search_becomes_a_conjunction_of_quoted_terms() -> None:
    # Operators and punctuation are dropped, so a query cannot inject syntax.
    assert _search_expression('deploy* OR "don\'t" re-run') == (
        '"deploy" AND "OR" AND "don\'t" AND "re-run"'
    )


@pytest.mark.parametrize(
    ("query", "detail"),
    [
        (None, "query must be text"),
        (17, "query must be text"),
        ("deploy\x00", "query must not contain NUL"),
        ("x" * (MAX_SEARCH_QUERY_LENGTH + 1),
         f"query must not exceed {MAX_SEARCH_QUERY_LENGTH} characters"),
        ("", "query must contain a searchable term"),
        ('"*" -- ()', "query must contain a searchable term"),
        (" ".join(["term"] * (MAX_SEARCH_TERMS + 1)),
         f"query must contain at most {MAX_SEARCH_TERMS} terms"),
        ("x" * (MAX_SEARCH_TERM_LENGTH + 1),
         f"query terms must not exceed {MAX_SEARCH_TERM_LENGTH} characters"),
    ],
)
def test_a_search_that_cannot_be_run_safely_is_refused(query: Any, detail: str) -> None:
    with pytest.raises(DomainValidationError) as refused:
        _search_expression(query)

    assert str(refused.value) == detail


def test_a_search_at_every_limit_is_accepted() -> None:
    terms = ["x" * MAX_SEARCH_TERM_LENGTH] + ["y"] * (MAX_SEARCH_TERMS - 1)

    assert _search_expression(" ".join(terms)).count(" AND ") == MAX_SEARCH_TERMS - 1


# -- board reads --------------------------------------------------------------


@pytest.fixture
def board(app_config: AppConfig) -> BoardService:
    # Every refusal below happens before storage is touched, so the store is
    # deliberately left uninitialized: reaching it would fail the test.
    store = SQLiteStore(
        app_config.database_path,
        backup_dir=app_config.backup_dir,
        busy_timeout_ms=app_config.sqlite_busy_timeout_ms,
    )
    return BoardService(
        store,
        max_message_bytes=app_config.max_message_bytes,
        max_metadata_bytes=app_config.max_metadata_bytes,
        max_channels=app_config.max_channels,
    )


SINCE_REFUSED = f"since must be between 0 and {MAX_SEQUENCE}"
LIMIT_REFUSED = f"limit must be between 1 and {MAX_MESSAGE_LIMIT}"


@pytest.mark.parametrize("since", [-1, MAX_SEQUENCE + 1, True, "0", 1.0, None])
def test_reading_from_an_impossible_position_is_refused(board: BoardService, since: Any) -> None:
    with pytest.raises(DomainValidationError) as listed:
        board.list_messages("status", since=since)
    with pytest.raises(DomainValidationError) as streamed:
        board.stream_messages(since=since)

    assert str(listed.value) == SINCE_REFUSED
    assert str(streamed.value) == SINCE_REFUSED


@pytest.mark.parametrize("limit", [0, -1, MAX_MESSAGE_LIMIT + 1, True])
def test_reading_an_impossible_number_of_messages_is_refused(
    board: BoardService, limit: Any,
) -> None:
    refusals = []
    for read in (
        lambda: board.list_messages("status", limit=limit),
        lambda: board.stream_messages(since=0, limit=limit),
        lambda: board.recent_activity(limit=limit),
        lambda: board.catch_up_page(agent_id="agent-1", limit=limit),
        lambda: board.dashboard_snapshot(
            channel_name=None, agent_name=None, before=None, limit=limit,
        ),
    ):
        with pytest.raises(DomainValidationError) as refused:
            read()
        refusals.append(str(refused.value))

    assert refusals == [LIMIT_REFUSED] * 5


def test_a_read_validates_its_channel_before_its_position(board: BoardService) -> None:
    with pytest.raises(DomainValidationError) as refused:
        board.list_messages("not a channel!", since=-1)

    assert str(refused.value) == "channel name must be lowercase kebab-case"


@pytest.mark.parametrize("before", [0, -5, MAX_SEQUENCE + 1, True, "9"])
def test_the_activity_page_refuses_an_impossible_page_position(
    board: BoardService, before: Any,
) -> None:
    with pytest.raises(DomainValidationError) as refused:
        board.dashboard_snapshot(channel_name=None, agent_name=None, before=before, limit=10)

    assert str(refused.value) == f"before must be between 1 and {MAX_SEQUENCE}"


def test_the_activity_page_refuses_malformed_filters(board: BoardService) -> None:
    with pytest.raises(DomainValidationError) as channel:
        board.dashboard_snapshot(channel_name="!!", agent_name=None, before=None, limit=10)
    with pytest.raises(DomainValidationError) as agent:
        board.dashboard_snapshot(channel_name=None, agent_name="copilot", before=None, limit=10)

    assert str(channel.value) == "channel name must be lowercase kebab-case"
    assert str(agent.value) == (
        "agent name must be lowercase kebab-case with project and platform"
    )


@pytest.mark.parametrize(
    "flags",
    [{"include_stale": 1}, {"start_drain": "yes"}, {"include_stale": None}],
)
def test_catch_up_flags_must_be_booleans(board: BoardService, flags: dict[str, Any]) -> None:
    with pytest.raises(DomainValidationError) as refused:
        board.catch_up_page(agent_id="agent-1", **flags)

    assert str(refused.value) == "catch-up flags must be true or false"


def test_a_drain_cannot_be_started_and_continued_at_once(board: BoardService) -> None:
    with pytest.raises(DomainValidationError):
        board.catch_up_page(agent_id="agent-1", start_drain=True, continuation="token")


# -- stream resume ------------------------------------------------------------


@pytest.mark.parametrize(
    ("since", "last_event_id", "expected"),
    [
        (5, None, 5),
        (5, "9", 9),
        # A reconnecting client never moves backwards.
        (9, "5", 9),
        (0, "0", 0),
        (0, str(MAX_SEQUENCE), MAX_SEQUENCE),
        (0, " 12 ", 12),
    ],
)
def test_a_stream_resumes_from_the_later_of_since_and_last_event_id(
    since: int, last_event_id: str | None, expected: int,
) -> None:
    assert _resume_position(since, last_event_id) == expected


@pytest.mark.parametrize(
    ("last_event_id", "detail"),
    [
        ("abc", "Last-Event-ID must be zero or greater"),
        ("", "Last-Event-ID must be zero or greater"),
        ("1.5", "Last-Event-ID must be zero or greater"),
        ("-1", f"Last-Event-ID must be between 0 and {MAX_SEQUENCE}"),
        (str(MAX_SEQUENCE + 1), f"Last-Event-ID must be between 0 and {MAX_SEQUENCE}"),
    ],
)
def test_a_malformed_last_event_id_is_refused_at_connect(
    last_event_id: str, detail: str,
) -> None:
    with pytest.raises(HTTPException) as refused:
        _resume_position(3, last_event_id)

    assert (refused.value.status_code, refused.value.detail) == (422, detail)


class _Channels:
    def __init__(self, known: set[str]) -> None:
        self.known = known

    def require_channel(self, name: str) -> None:
        if name not in self.known:
            raise ChannelNotFoundError(f"channel {name} does not exist")


def _stream_request(known: set[str]) -> Any:
    state = SimpleNamespace(board_service=_Channels(known))
    return SimpleNamespace(app=SimpleNamespace(state=state))


async def test_a_stream_filter_is_normalized_and_must_name_a_real_channel() -> None:
    request = _stream_request({"status"})

    assert await _stream_channel_filter(request, None) is None
    assert await _stream_channel_filter(request, "#Status") == "status"

    with pytest.raises(HTTPException) as unknown:
        await _stream_channel_filter(request, "statsu")
    with pytest.raises(HTTPException) as malformed:
        await _stream_channel_filter(request, "not a channel!")

    # A typo is a 404 at connect, never a silently quiet stream.
    assert (unknown.value.status_code, unknown.value.detail) == (
        404, "channel statsu does not exist",
    )
    assert (malformed.value.status_code, malformed.value.detail) == (
        422, "channel name must be lowercase kebab-case",
    )


# -- orientation guidance ------------------------------------------------------


def _orientation(**overrides: Any) -> AgentOrientation:
    values: dict[str, Any] = dict(
        latest_seq=10, unread=0, unread_capped=False, pending_mentions=0,
        pending_mentions_capped=False, last_caught_up_at=None, channels=(),
        new_channels=(), subscription_count=2,
    )
    values.update(overrides)
    return AgentOrientation(**values)


def _roe(status: str) -> Any:
    return SimpleNamespace(acknowledgement_status=status)


def _actions(credential: str = "active", roe: str = "current", **overrides: Any) -> list[str]:
    return [
        action.action
        for action in required_actions(
            credential_status=credential, roe=_roe(roe), orientation=_orientation(**overrides),
        )
    ]


def test_a_settled_agent_has_nothing_required_of_it() -> None:
    assert _actions() == []


def test_required_actions_come_in_bootstrap_order() -> None:
    assert _actions("pending", "missing", subscription_count=0, unread=3) == [
        "prove_credential", "acknowledge_roe", "choose_subscriptions", "catch_up",
    ]


def test_a_missing_and_a_stale_receipt_are_explained_differently() -> None:
    [missing] = required_actions(
        credential_status="active", roe=_roe("missing"), orientation=_orientation(),
    )
    [stale] = required_actions(
        credential_status="active", roe=_roe("stale"), orientation=_orientation(),
    )

    assert missing.action == stale.action == "acknowledge_roe"
    assert "has not recorded receipt" in missing.reason
    assert "changed since your last receipt" in stale.reason


@pytest.mark.parametrize(
    ("observed", "detail"),
    [
        ({"unread": 1}, "The observed scope has 1 message."),
        ({"unread": 4}, "The observed scope has 4 messages."),
        ({"unread": 1, "unread_capped": True}, "The observed scope has at least 1 messages."),
        ({"unread": 4, "pending_mentions": 1},
         "The observed scope has 4 messages, including 1 mention addressed to you."),
        ({"unread": 4, "pending_mentions": 2, "pending_mentions_capped": True},
         "The observed scope has 4 messages, including at least 2 mentions addressed to you."),
        # Nothing was counted, but the count cannot rule unread messages out.
        ({"counts_complete": False}, "The observed scope has 0 messages."),
        ({"pending_mentions_capped": True}, "The observed scope has 0 messages."),
    ],
)
def test_catch_up_is_required_whenever_unread_messages_cannot_be_ruled_out(
    observed: dict[str, Any], detail: str,
) -> None:
    [action] = required_actions(
        credential_status="active", roe=_roe("current"), orientation=_orientation(**observed),
    )

    assert action.action == "catch_up"
    assert action.reason.startswith(detail + " Start catch_up(start_drain=true)")


NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
ADVISORY = (
    "Orientation is advisory: it changes no subscriptions, credential proof, "
    "rules-of-engagement receipt, or cursor."
)


def test_guidance_for_a_settled_agent_says_only_what_was_observed() -> None:
    text = guidance(actions=(), orientation=_orientation(), now=NOW)

    assert text == (
        "No unread messages were observed in your subscribed channels "
        "or direct mentions at this snapshot. "
        "No recorded cursor update is available. " + ADVISORY
    )


def test_guidance_lists_the_next_steps_in_order() -> None:
    actions = (
        RequiredAction("prove_credential", ""),
        RequiredAction("choose_subscriptions", ""),
        RequiredAction("catch_up", ""),
    )

    text = guidance(actions=actions, orientation=_orientation(), now=NOW)

    assert text.startswith(
        "Next, call prove_credential then review channels and choose subscriptions "
        "(optional; mention-only use is valid) then call catch_up(start_drain=true), "
        "in that order. "
        "Follow returned continuations with the same limit and include_stale "
        "until complete=true, even after empty or short pages. "
    )
    assert text.endswith(ADVISORY)


def test_guidance_states_every_limit_of_what_was_surveyed() -> None:
    caught_up = datetime(2026, 2, 28, 9, 30, tzinfo=UTC)

    text = guidance(
        actions=(),
        orientation=_orientation(
            subscription_count=0, counts_complete=False, last_caught_up_at=caught_up,
            new_channels=("a", "b", "c", "d", "e", "f"),
            subscribed_channels_truncated=True, new_channels_truncated=True,
        ),
        now=NOW,
    )

    assert text == " ".join([
        "No unread messages were observed in your subscribed channels "
        "or direct mentions at this snapshot.",
        "With no subscriptions, only direct mentions are eligible; "
        "broader channel history has not been surveyed.",
        "Counts are incomplete lower bounds; even zero does not establish "
        "that the eligible scope is exhausted.",
        "The last recorded cursor update was 2026-02-28T09:30:00+00:00 across "
        "cursor scopes; this is not evidence of completed delivery or processing.",
        "Channels created since that recorded cursor update: #a, #b, #c, #d, #e and others.",
        "The subscribed-channel list is truncated.",
        "New-channel discovery is truncated.",
        ADVISORY,
    ])


@pytest.mark.parametrize(
    ("new_channels", "truncated", "listed"),
    [
        (("a",), False, "#a."),
        (("a", "b", "c", "d", "e"), False, "#a, #b, #c, #d, #e."),
        # Fewer than six are shown, but discovery itself stopped early.
        (("a", "b"), True, "#a, #b and others."),
    ],
)
def test_guidance_says_and_others_only_when_channels_were_left_out(
    new_channels: tuple[str, ...], truncated: bool, listed: str,
) -> None:
    text = guidance(
        actions=(),
        orientation=_orientation(new_channels=new_channels, new_channels_truncated=truncated),
        now=NOW,
    )

    assert f"Channels created since that recorded cursor update: {listed} " in text


# -- the MCP identity middleware ----------------------------------------------


class _Liveness:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.failures: list[BaseException | None] = []

    def begin_bootstrap(self, agent_id: str, credential_id: str) -> str:
        self.calls.append(f"begin {agent_id} {credential_id}")
        return "lease"

    def end_bootstrap(self, lease: str) -> None:
        self.calls.append(f"end {lease}")

    def require_live_identity(self, agent_id: str, credential_id: str) -> None:
        self.calls.append("live")
        failure = self.failures.pop(0) if self.failures else None
        if failure is not None:
            raise failure


def _token(**overrides: Any) -> Any:
    claims = {
        "agent_id": "agent-1", "agent_name": "strugglebus-copilot",
        "credential_id": "cred-1", "credential_kind": "sb1",
        "credential_status": "active", "credential_epoch": 3,
    }
    values: dict[str, Any] = dict(subject="agent-1", client_id="agent-1", claims=claims)
    values.update(overrides)
    return SimpleNamespace(**values)


async def _run_mcp(
    token: Any, *, method: str = "tools/call", result: Any = "tool result",
    liveness: _Liveness | None = None,
) -> tuple[Any, _Liveness]:
    liveness = liveness or _Liveness()
    middleware = IdentityInitializeMiddleware(liveness)  # type: ignore[arg-type]

    async def call_next(ctx: Any) -> Any:
        liveness.calls.append("handler")
        return result

    with patch("strugglebus.app.get_access_token", return_value=token):
        return await middleware(SimpleNamespace(method=method), call_next), liveness


async def test_an_mcp_call_is_bracketed_by_liveness_checks_under_a_bootstrap_lease() -> None:
    result, liveness = await _run_mcp(_token())

    assert result == "tool result"
    assert liveness.calls == ["begin agent-1 cred-1", "live", "handler", "live", "end lease"]


@pytest.mark.parametrize(
    "token",
    [
        None,
        _token(subject=None),
        # A token minted for another client is not this agent's identity.
        _token(client_id="agent-2"),
        _token(claims={"agent_id": "agent-1"}),
        _token(claims={"credential_id": 7}),
    ],
)
async def test_an_mcp_call_without_a_coherent_identity_is_refused_before_any_lease(
    token: Any,
) -> None:
    liveness = _Liveness()

    with pytest.raises(ToolError) as refused:
        await _run_mcp(token, liveness=liveness)

    assert str(refused.value) == "authenticated agent identity is unavailable"
    assert liveness.calls == []


@pytest.mark.parametrize(
    ("error", "detail"),
    [
        (AgentAccessFrozenError("frozen"), "agent access is frozen"),
        (CredentialNotFoundError("gone"), "authenticated agent identity is unavailable"),
        (StorageError("disk"), "authenticated agent identity is unavailable"),
    ],
)
@pytest.mark.parametrize("when", ["before", "after"])
async def test_a_withdrawn_identity_turns_a_tool_call_into_a_tool_error_result(
    error: Exception, detail: str, when: str,
) -> None:
    liveness = _Liveness()
    liveness.failures = [error] if when == "before" else [None, error]

    result, _ = await _run_mcp(_token(), liveness=liveness)

    # The tool's own result is discarded, even when the tool already ran.
    assert result.model_dump(by_alias=True)["isError"] is True
    assert [content.text for content in result.content] == [detail]
    assert ("handler" in liveness.calls) == (when == "after")
    assert liveness.calls[-1] == "end lease"


@pytest.mark.parametrize("method", ["initialize", "tools/list", "resources/read"])
async def test_a_withdrawn_identity_fails_any_other_mcp_method(method: str) -> None:
    liveness = _Liveness()
    liveness.failures = [AgentAccessFrozenError("frozen")]

    with pytest.raises(ToolError) as refused:
        await _run_mcp(_token(), method=method, liveness=liveness)

    assert str(refused.value) == "agent access is frozen"
    assert liveness.calls == ["begin agent-1 cred-1", "live", "end lease"]


async def test_initialize_tells_the_agent_who_the_server_believes_it_is() -> None:
    result, _ = await _run_mcp(
        _token(), method="initialize",
        result={"instructions": "Be kind.", "_meta": {"other": 1}, "serverInfo": {"name": "bus"}},
    )

    assert result["serverInfo"] == {"name": "bus"}
    assert result["_meta"] == {
        "other": 1,
        "strugglebus.identity": {
            "agent_id": "agent-1", "agent_name": "strugglebus-copilot",
            "credential_id": "cred-1", "credential_kind": "sb1",
            "credential_status": "active", "credential_epoch": 3,
        },
    }
    assert result["instructions"] == (
        "Be kind.\n\nCompare both stable agent ID and name with locally pinned expected "
        "values and abort before coordination on any mismatch."
    )


async def test_initialize_without_instructions_or_meta_still_carries_the_identity() -> None:
    result, _ = await _run_mcp(
        _token(), method="initialize", result={"_meta": "not a mapping"},
    )

    assert set(result["_meta"]) == {"strugglebus.identity"}
    assert result["instructions"].startswith("Compare both stable agent ID and name")


@pytest.mark.parametrize(
    ("method", "result"),
    [("tools/list", {"tools": []}), ("initialize", ["not", "a", "mapping"])],
)
async def test_only_a_mapping_initialize_result_is_annotated(method: str, result: Any) -> None:
    returned, _ = await _run_mcp(_token(), method=method, result=result)

    assert returned is result


async def test_initialize_is_left_alone_if_the_token_vanished_meanwhile() -> None:
    liveness = _Liveness()
    middleware = IdentityInitializeMiddleware(liveness)  # type: ignore[arg-type]
    original = {"instructions": "Be kind."}

    async def call_next(ctx: Any) -> Any:
        return original

    with patch("strugglebus.app.get_access_token", side_effect=[_token(), None]):
        result = await middleware(SimpleNamespace(method="initialize"), call_next)

    assert result is original
