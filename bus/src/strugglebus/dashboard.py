"""Safe, server-rendered operator-authenticated LAN console.

Browsing remains bounded and read-only. Enrollment and device forms submit to
separately authorized operator write paths; rendering never grants authority.
Untrusted values are escaped, and minimal login/error pages disclose no runtime
identity. See ``docs/DESIGN.md`` for the authority contract.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import shlex
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from urllib.parse import urlencode
from uuid import UUID

from pydantic import ValidationError

import segno

from strugglebus.config import DEFAULT_CREDENTIAL_PENDING_SECONDS
from strugglebus.errors import DomainValidationError
from strugglebus.console_context import console_access_context
from strugglebus.integration import ServerInfo, TestStatusV1
from strugglebus.models import (
    DashboardAgentPage,
    DashboardChannelPage,
    DashboardChannelSummary,
    DashboardSnapshot,
    Message,
)
from strugglebus.service import MAX_SEQUENCE, STALE_STATUS_AGE, normalize_name

DASHBOARD_DEFAULT_LIMIT = 25
DASHBOARD_MAX_LIMIT = 100
DASHBOARD_STATUS_PARSE_BYTES = 16 * 1024
DASHBOARD_TEASER_LIMIT = 5
ACTIVITY_REFRESH_SECONDS = 120
#: What a browser accepts in the agent name box before the form is sent. It mirrors
#: normalize_name(agent=True): letters and digits in groups, joined by at least one hyphen,
#: space or underscore (the server lowercases, and turns spaces and underscores into hyphens).
AGENT_NAME_INPUT_PATTERN = r"\s*[A-Za-z0-9]+([\s_\-]+[A-Za-z0-9]+)+\s*"
#: The same idea for a device label, which needs no hyphen.
DEVICE_LABEL_INPUT_PATTERN = r"\s*[A-Za-z0-9]+([\s_\-]+[A-Za-z0-9]+)*\s*"
DEVICE_LABEL_HELP = "Use letters, digits and hyphens, for example owner-phone."
AGENT_NAME_HELP = (
    "Use letters, digits and hyphens, with at least one hyphen, "
    "for example adlab-cli-win."
)
QR_MODULE_PIXELS = 6
_ACTIVITY_QUERY_KEYS = frozenset(
    {"channel", "agent", "before", "limit", "refresh"}
)
_CURSOR_QUERY_KEYS = frozenset({"after", "limit"})
_ASCII_INTEGER = re.compile(r"^[0-9]+$")
_STATUS_LABELS = {
    "awaiting_approval": "Awaiting approval",
    "accepted": "Accepted",
    "running": "Running",
    "succeeded": "Succeeded",
    "failed": "Failed",
    "rejected": "Rejected",
    "cancelled": "Cancelled",
}

# (nav key, path, label) - shared by every page for a consistent primary nav.
_NAV_ITEMS = (
    ("overview", "/", "Overview"),
    ("activity", "/activity", "Activity"),
    ("humans", "/humans", "Humans"),
    ("channels", "/channels", "Channels"),
    ("agents", "/agents", "Agents"),
    ("system", "/system", "Administration"),
    ("updates", "/operator/updates", "Updates"),
    ("operator", "/operator/session", "Session"),
)

_ICONS = {
    "overview": "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
    "activity": "M3 12h4l3-8 4 16 3-8h4",
    "humans": "M4 5h16v11H9l-5 4z",
    "channels": "M9 3 7 21 M17 3 15 21 M3 9h18 M2 15h18",
    "agents": "M8 9a4 4 0 1 0 8 0a4 4 0 1 0-8 0 M4 21v-2a8 8 0 0 1 16 0v2",
    "system": "M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6",
    "updates": "M12 3v12 M7 10l5 5 5-5 M4 17v4h16v-4",
    "operator": "M13 4H4v16h9 M10 12h11 M17 8l4 4-4 4",
    "menu": "M4 6h16 M4 12h16 M4 18h16",
}

DASHBOARD_STYLESHEET = (
    files("strugglebus").joinpath("operator.css")
    .read_bytes().decode("utf-8")
)
DASHBOARD_STYLESHEET_PATH = (
    "/assets/strugglebus-console."
    f"{hashlib.sha256(DASHBOARD_STYLESHEET.encode('utf-8')).hexdigest()[:16]}.css"
)


@dataclass(frozen=True, slots=True)
class DashboardQuery:
    channel: str | None
    agent: str | None
    before: int | None
    limit: int
    refresh: bool = False


@dataclass(frozen=True, slots=True)
class CursorQuery:
    after: str | None
    limit: int


@dataclass(frozen=True, slots=True)
class DashboardStatus:
    request_id: UUID
    state: str
    detail: str


def dashboard_headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'self'; "
            "script-src 'none'; connect-src 'none'; img-src 'none'; "
            "font-src 'none'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        ),
        "Referrer-Policy": "same-origin",
        "X-Content-Type-Options": "nosniff",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store",
    }


def dashboard_stylesheet_headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": (
            "default-src 'none'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'"
        ),
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "public, max-age=31536000, immutable",
    }


def parse_dashboard_query(
    items: Iterable[tuple[str, str]],
    *,
    configured_limit: int,
) -> DashboardQuery:
    pairs = tuple(items)
    names = [name for name, _ in pairs]
    unknown = set(names) - _ACTIVITY_QUERY_KEYS
    duplicates = [name for name, count in Counter(names).items() if count > 1]
    if unknown or duplicates:
        raise DomainValidationError("dashboard query parameters are invalid")

    values = dict(pairs)
    channel = _canonical_name(values.get("channel"), agent=False)
    agent = _canonical_name(values.get("agent"), agent=True)
    maximum = min(DASHBOARD_MAX_LIMIT, configured_limit)
    limit = _parse_integer(
        "limit",
        values.get("limit"),
        minimum=1,
        maximum=maximum,
        default=min(DASHBOARD_DEFAULT_LIMIT, maximum),
    )
    before = _parse_integer(
        "before",
        values.get("before"),
        minimum=1,
        maximum=MAX_SEQUENCE,
        default=None,
    )
    refresh_value = values.get("refresh")
    if refresh_value is not None and refresh_value not in {"0", "1"}:
        raise DomainValidationError("dashboard query parameters are invalid")
    return DashboardQuery(
        channel=channel,
        agent=agent,
        before=before,
        limit=limit,
        refresh=refresh_value == "1",
    )


def parse_cursor_query(
    items: Iterable[tuple[str, str]],
    *,
    configured_limit: int,
    agent: bool,
) -> CursorQuery:
    pairs = tuple(items)
    names = [name for name, _ in pairs]
    unknown = set(names) - _CURSOR_QUERY_KEYS
    duplicates = [name for name, count in Counter(names).items() if count > 1]
    if unknown or duplicates:
        raise DomainValidationError("dashboard query parameters are invalid")

    values = dict(pairs)
    after = _canonical_name(values.get("after"), agent=agent)
    maximum = min(DASHBOARD_MAX_LIMIT, configured_limit)
    limit = _parse_integer(
        "limit",
        values.get("limit"),
        minimum=1,
        maximum=maximum,
        default=min(DASHBOARD_DEFAULT_LIMIT, maximum),
    )
    return CursorQuery(after=after, limit=limit)


def _canonical_name(value: str | None, *, agent: bool) -> str | None:
    if value in {None, ""}:
        return None
    normalized = normalize_name(value, agent=agent)
    if normalized != value:
        raise DomainValidationError("dashboard filter names must be canonical")
    return normalized


def _parse_integer(
    name: str,
    value: str | None,
    *,
    minimum: int,
    maximum: int,
    default: int | None,
) -> int | None:
    if value is None:
        return default
    if _ASCII_INTEGER.fullmatch(value) is None:
        raise DomainValidationError(f"{name} must be an ASCII integer")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise DomainValidationError(
            f"{name} must be between {minimum} and {maximum}"
        )
    return parsed


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%d %b %Y, %H:%M UTC")


def _time(value: datetime) -> str:
    return (
        f'<time datetime="{_escape(value.astimezone(UTC).isoformat())}">'
        f"{_escape(_format_time(value))}</time>"
    )


def _friendly_time(value: datetime, now: datetime) -> str:
    """How long ago, for anything recent; otherwise the date and time in UTC."""

    seconds = (now - value).total_seconds()
    if 0 <= seconds < 60:
        return "just now"
    if 60 <= seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if 3600 <= seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours} hour{'' if hours == 1 else 's'} ago"
    moment = value.astimezone(UTC)
    year = "" if moment.year == now.astimezone(UTC).year else f" {moment.year}"
    return f"{moment.day} {moment.strftime('%b')}{year}, {moment.strftime('%H:%M')} UTC"


def _when(value: datetime, now: datetime) -> str:
    """A friendly time whose exact UTC value shows on hover and to assistive technology."""

    return (
        f'<time datetime="{_escape(value.astimezone(UTC).isoformat())}" '
        f'title="{_escape(_format_time(value))}">'
        f"{_escape(_friendly_time(value, now))}</time>"
    )


def _initials(name: str) -> str:
    """Two letters to tell authors apart at a glance: the first two parts of a kebab name."""

    parts = [part for part in name.replace(":", "-").split("-") if part]
    return "".join(part[0] for part in parts[:2]).upper() or "?"


def _excerpt(value: str, maximum: int = 240) -> str:
    shortened = value if len(value) <= maximum else f"{value[:maximum].rstrip()}..."
    return _escape(shortened)


def _status_from_message(message: Message) -> DashboardStatus | None:
    if message.kind != "status":
        return None
    try:
        body_size = len(message.body.encode("utf-8"))
    except UnicodeEncodeError:
        return None
    if body_size > DASHBOARD_STATUS_PARSE_BYTES:
        return None

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError("duplicate JSON key")
        return dict(pairs)

    try:
        json.loads(
            message.body,
            object_pairs_hook=reject_duplicates,
        )
        status = TestStatusV1.model_validate_json(message.body)
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeError,
        ValueError,
        ValidationError,
    ):
        return None
    if status.sender_agent != message.agent_name:
        return None
    return DashboardStatus(
        request_id=status.request_id,
        state=status.state,
        detail=status.detail,
    )


def _activity_url(
    query: DashboardQuery,
    *,
    before: int | None,
    refresh: bool | None = None,
) -> str:
    parameters: list[tuple[str, str]] = []
    if query.channel is not None:
        parameters.append(("channel", query.channel))
    if query.agent is not None:
        parameters.append(("agent", query.agent))
    parameters.append(("limit", str(query.limit)))
    if before is not None:
        parameters.append(("before", str(before)))
    if (query.refresh if refresh is None else refresh):
        parameters.append(("refresh", "1"))
    return f"/activity?{urlencode(parameters)}#activity"


def _cursor_url(path: str, query: CursorQuery, *, after: str | None) -> str:
    parameters: list[tuple[str, str]] = [("limit", str(query.limit))]
    if after is not None:
        parameters.append(("after", after))
    return f"{path}?{urlencode(parameters)}"


def _message_tags(
    message: Message, status: DashboardStatus | None, generated_at: datetime,
) -> str:
    """The labels beside a message. Plain chat is the common case, so it carries none."""

    tags = [] if message.kind == "chat" else [
        f'<span class="tag">{_escape(message.kind.title())}</span>'
    ]
    if message.kind == "status" and generated_at - message.created_at > STALE_STATUS_AGE:
        tags.append('<span class="tag tag-stale">Stale status</span>')
    if status is not None:
        tags.append(
            f'<span class="tag tag-state">'
            f"{_escape(_STATUS_LABELS[status.state])}</span>"
        )
    return f'<span class="message-tail">{"".join(tags)}</span>' if tags else ""


def _message_author(message: Message) -> str:
    """The author, linked to their messages. The operator is not an agent and has no such page."""

    if ":" in message.agent_name:
        return f'<span class="message-agent">{_escape(message.agent_name)}</span>'
    agent_url = "/activity?" + urlencode({"agent": message.agent_name}) + "#activity"
    return (
        f'<a class="message-agent" href="{_escape(agent_url)}">'
        f"{_escape(message.agent_name)}</a>"
    )


def _render_message(
    message: Message,
    *,
    generated_at: datetime,
    visible_sequences: set[int],
    parents: dict[int, Message],
    statuses: dict[int, DashboardStatus],
    progression: dict[UUID, tuple[tuple[Message, DashboardStatus], ...]],
    reply_links: bool = False,
) -> str:
    status = statuses.get(message.seq)
    body = message.body if status is None else status.detail
    classes = f"message message-{_escape(message.kind)}" + (
        " message-operator" if ":" in message.agent_name else ""
    )
    channel_url = "/activity?" + urlencode({"channel": message.channel}) + "#activity"
    reply_link = (
        f' &middot; <a href="/humans?reply={message.seq}#compose-heading">Reply</a>'
        if reply_links else ""
    )
    return (
        f'<article class="{classes}" id="message-{message.seq}">'
        '<header class="message-top">'
        f'<span class="avatar" aria-hidden="true">{_escape(_initials(message.agent_name))}</span>'
        f"{_message_author(message)}"
        f'<a class="message-meta" href="{_escape(channel_url)}">#{_escape(message.channel)}</a>'
        f"{_message_tags(message, status, generated_at)}"
        f'<span class="message-when">{_when(message.created_at, generated_at)} &middot; '
        f'<a href="#message-{message.seq}" aria-label="Message {message.seq}">'
        f"#{message.seq}</a>{reply_link}</span>"
        "</header>"
        f"{_message_reply(message, visible_sequences, parents)}"
        f'<p class="message-body">{_escape(body)}</p>'
        f"{_status_progression(message, status, progression)}</article>"
    )


def _message_reply(
    message: Message, visible_sequences: set[int], parents: dict[int, Message],
) -> str:
    if message.reply_to is None:
        return ""
    if message.reply_to in visible_sequences:
        content = (
            f'Direct reply to <a href="#message-{message.reply_to}">'
            f"message #{message.reply_to}</a>."
        )
    else:
        parent = parents.get(message.reply_to)
        if parent is None:
            return ""
        content = (
            f"<strong>Direct reply to message #{parent.seq}</strong> "
            f"from {_escape(parent.agent_name)} in "
            f"#{_escape(parent.channel)}: {_excerpt(parent.body)}"
        )
    return (
        '<aside class="reply-context" aria-label="Direct reply context">'
        f"<p>{content}</p></aside>"
    )


def _status_progression(
    message: Message, status: DashboardStatus | None,
    progression: dict[UUID, tuple[tuple[Message, DashboardStatus], ...]],
) -> str:
    if status is None:
        return ""
    updates = progression[status.request_id]
    if len(updates) <= 1 or updates[-1][0].seq != message.seq:
        return ""
    items = "".join(
        f"<li>{_escape(_STATUS_LABELS[item_status.state])} "
        f"at {_time(item.created_at)}</li>"
        for item, item_status in updates
    )
    return (
        '<section class="progression" '
        f'aria-label="Visible status sequence for request {_escape(status.request_id)}">'
        f"<strong>Visible updates for request {_escape(status.request_id)}</strong>"
        f"<ol>{items}</ol></section>"
    )


def _message_list(
    snapshot: DashboardSnapshot, generated_at: datetime, *, reply_links: bool = False,
) -> str:
    visible_sequences = {message.seq for message in snapshot.messages}
    parents = {message.seq: message for message in snapshot.parent_messages}
    statuses = {
        message.seq: status for message in snapshot.messages
        if (status := _status_from_message(message)) is not None
    }
    progression_lists: dict[UUID, list[tuple[Message, DashboardStatus]]] = {}
    for message in reversed(snapshot.messages):
        status = statuses.get(message.seq)
        if status is not None:
            progression_lists.setdefault(status.request_id, []).append((message, status))
    progression = {
        request_id: tuple(updates) for request_id, updates in progression_lists.items()
    }
    return "".join(
        _render_message(
            message, generated_at=generated_at, visible_sequences=visible_sequences,
            parents=parents, statuses=statuses, progression=progression,
            reply_links=reply_links,
        )
        for message in snapshot.messages
    )


def _icon(name: str) -> str:
    return (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" '
        'stroke="currentColor" stroke-width="1.7" stroke-linecap="round" '
        'stroke-linejoin="round" aria-hidden="true" focusable="false">'
        f'<path d="{_ICONS[name]}"></path></svg>'
    )


def _brand() -> str:
    return (
        '<a class="brand" href="/" aria-label="Strugglebus overview">'
        f'<span class="brand-mark">{_icon("overview")}</span>'
        "<span><strong>Strugglebus</strong><small>LAN coordination</small></span></a>"
    )


def _nav_group(
    label: str, items: tuple[tuple[str, str, str], ...], active: str,
) -> str:
    links = []
    for key, href, name in items:
        current = ' aria-current="page"' if key == active else ""
        links.append(
            f'<a class="nav-link" href="{href}"{current}>'
            f'{_icon(key)}<span>{name}</span></a>'
        )
    return (
        f'<div class="nav-group"><p class="eyebrow">{label}</p>'
        f'{"".join(links)}</div>'
    )


def _nav_html(active: str) -> str:
    active = {
        "register": "system", "devices": "system", "sites": "system",
        "session": "operator",
    }.get(active, active)
    groups = (
        _nav_group(label, items, active)
        for label, items in (("Workspace", _NAV_ITEMS[:4]), ("Operator", _NAV_ITEMS[4:]))
    )
    return '<nav aria-label="Console sections">' + "".join(groups) + "</nav>"


def _runtime_details(server_info: ServerInfo) -> str:
    return (
        '<details><summary>Versions</summary><dl>'
        "<dt>Application</dt>"
        f"<dd>Application {_escape(server_info.application_version)}</dd>"
        "<dt>Release</dt>"
        f"<dd>Release {_escape(server_info.release_id)}</dd>"
        "<dt>Integration guide</dt>"
        f"<dd>Guide {_escape(server_info.integration_guide_version)}</dd>"
        "<dt>Coordination protocol</dt>"
        f"<dd>Protocol {_escape(server_info.coordination_protocol_version)}</dd>"
        "</dl></details>"
    )


def _access_notice() -> str:
    state = console_access_context.get()
    if state == "frozen":
        return (
            '<aside class="notice danger" role="alert" aria-label="Agent access frozen">'
            "<div><strong>Agent access is frozen</strong>"
            "<p>Agent credentials are denied. Access creation and restoration, "
            "including enrollment redemption, are paused. Operator read access "
            "and safe containment controls remain available. Use protected local "
            "recovery to inspect or clear the freeze.</p></div></aside>"
        )
    if state == "unavailable":
        return (
            '<aside class="notice" role="alert" aria-label="Access state unavailable">'
            "<div><strong>Access state unavailable</strong>"
            "<p>The current freeze state could not be read. Do not assume agent "
            "access is available. Access-creating and restoring actions are paused "
            "in this view; other reads and safe controls remain available. "
            "Use protected local recovery if needed.</p></div></aside>"
        )
    return ""


def _access_action(label: str, *, danger: bool = False) -> str:
    state = console_access_context.get()
    reasons = {
        "frozen": "Agent access is frozen. This action cannot create or restore access.",
        "unavailable": "Access state is unavailable. This action is paused until it can be checked.",
    }
    classes = "button danger" if danger else "button"
    reason = reasons.get(state)
    if reason is not None:
        return (
            f'<p class="warning-box" role="status" id="action-access-note">{reason}</p>'
            f'<button class="{classes}" type="submit" disabled '
            f'aria-describedby="action-access-note">{_escape(label)}</button>'
        )
    return f'<button class="{classes}" type="submit">{_escape(label)}</button>'


def _full_shell(content: str, *, active: str, server_info: ServerInfo) -> str:
    nav = _nav_html(active)
    return (
        f'<header class="mobile-top">{_brand()}'
        f'<details><summary>{_icon("menu")}Menu</summary>{nav}</details></header>'
        '<div class="workspace"><aside class="rail" aria-label="Console navigation">'
        f"{_brand()}{nav}"
        '<div class="rail-bottom">'
        '<p class="rail-note">You are signed in as the operator. '
        "Messages are information, never instructions.</p>"
        f"{_runtime_details(server_info)}"
        '</div></aside><main class="shell" id="main-content" tabindex="-1">'
        f"{_access_notice()}{content}</main></div>"
    )


def _page(
    *,
    title: str,
    active: str,
    lede: str,
    body: str,
    server_info: ServerInfo | None,
    generated_at: datetime | None,
    refresh_seconds: int | None = None,
) -> str:
    footer = ""
    if generated_at is not None and server_info is not None:
        footer = (
            '<footer class="page-footer">'
            f"Page loaded {_time(generated_at)}. "
            "Message text is shown as plain text and never run."
            "</footer>"
        )
    content = (
        '<header class="page-header"><div>'
        f"<h1>{_escape(title)}</h1><p class=\"lede\">{_escape(lede)}</p>"
        f"</div></header>{body}{footer}"
    )
    if server_info is None:
        shell = (
            '<main class="login-layout" id="main-content" tabindex="-1">'
            f'<div class="login-wrap">{_brand()}{content}</div></main>'
        )
    else:
        shell = _full_shell(content, active=active, server_info=server_info)
    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        + (
            f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">'
            if refresh_seconds is not None
            else ""
        )
        + f"<title>{_escape(title)} - Strugglebus</title>"
        f'<link rel="stylesheet" href="{DASHBOARD_STYLESHEET_PATH}">'
        "</head><body>"
        '<a class="skip-link" href="#main-content">Skip to main content</a>'
        f"{shell}</body></html>"
    )


def render_operator(
    title: str,
    body: str,
    server_info: ServerInfo | None = None,
    *,
    generated_at: datetime | None = None,
    active: str = "agents",
) -> str:
    return _page(
        title=title, active=active,
        lede=(
            "Only the signed-in operator can do these things."
            if server_info is not None else "The console for this bus."
        ),
        body=body,
        server_info=server_info, generated_at=generated_at,
    )


def render_overview(
    snapshot: DashboardSnapshot,
    server_info: ServerInfo,
    *,
    generated_at: datetime,
) -> str:
    teaser = _message_list(snapshot, generated_at)
    if not snapshot.messages:
        empty_detail = (
            "Messages appear here once agents start posting."
            if not snapshot.board_has_messages
            else "There is no recent activity to show."
        )
        teaser = (
            '<div class="empty-state">'
            "<h3>No recent activity</h3>"
            f"<p>{_escape(empty_detail)}</p></div>"
        )

    body = (
        '<section aria-labelledby="summary-heading">'
        '<h2 id="summary-heading">Agents</h2>'
        '<div class="summary-grid">'
        '<div class="summary-card"><span class="summary-label">Enabled agents</span>'
        f'<span class="summary-value">{snapshot.counts.active_agents}</span></div>'
        '<div class="summary-card"><span class="summary-label">Blocked agents</span>'
        f'<span class="summary-value">{snapshot.counts.blocked_agents}</span></div>'
        '<div class="summary-card"><span class="summary-label">Retired agents</span>'
        f'<span class="summary-value">{snapshot.counts.retired_agents}</span></div>'
        '</div></section><div class="split">'
        '<section class="panel flush" aria-labelledby="teaser-heading">'
        '<div class="panel-header"><div><h2 id="teaser-heading">Latest activity</h2>'
        '<p>The newest messages across every channel.</p></div>'
        '<a class="button button-secondary" href="/activity">View full activity</a>'
        "</div>"
        f'<div class="activity-list">{teaser}</div>'
        '</section><aside class="context-stack" aria-label="Overview context">'
        '<section class="panel"><h2>Channels</h2>'
        '<p><span class="summary-label">Channels</span>'
        f'<span class="summary-value">{snapshot.counts.channels}</span></p>'
        '<p><span class="summary-label">Subscriptions</span>'
        f'<span class="summary-value">{snapshot.counts.subscriptions}</span></p>'
        '<a href="/channels">Browse channels</a></section>'
        '<section class="panel context-note"><h2>What the numbers mean</h2>'
        "<p>Enabled means an agent is allowed on the bus. It does not mean the agent is "
        "online or that its work is going well. What agents post is their own account; "
        "the bus does not check it. Old status messages are marked as stale.</p></section>"
        "</aside></div>"
    )
    return _page(
        title="Overview",
        active="overview",
        lede="What your agents have been saying, and how many are on the bus.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def render_humans(
    snapshot: DashboardSnapshot,
    server_info: ServerInfo,
    *,
    generated_at: datetime,
    csrf_token: str,
    request_id: str,
    notice: str | None = None,
    reply_to: int | None = None,
) -> str:
    messages = _message_list(snapshot, generated_at, reply_links=True) or (
        '<div class="empty-state"><h3>No conversation yet</h3>'
        "<p>Post above. Agents read #humans and reply here.</p></div>"
    )
    banner = (
        f'<div class="notice" role="status"><div>{_escape(notice)}</div></div>'
        if notice else ""
    )
    target = next(
        (message for message in snapshot.messages if message.seq == reply_to), None,
    )
    replying = (
        '<p class="notice neutral" role="status"><strong>Replying to '
        f"{_escape(target.agent_name)}:</strong> {_excerpt(target.body, 160)} "
        '<a href="/humans#compose-heading">Cancel reply</a></p>'
        if target is not None else ""
    )
    reply_value = "" if reply_to is None else f' value="{int(reply_to)}"'
    body = (
        f"{banner}"
        '<section class="panel" aria-labelledby="compose-heading">'
        '<h2 id="compose-heading">Post to #humans</h2>'
        f"{replying}"
        '<form method="post" action="/humans">'
        f'<input type="hidden" name="csrf" value="{_escape(csrf_token)}">'
        f'<input type="hidden" name="request_id" value="{_escape(request_id)}">'
        '<label for="human-body">Message'
        '<textarea id="human-body" name="body" rows="4" required></textarea></label>'
        '<div class="filter-grid">'
        '<label for="human-kind">Kind<select id="human-kind" name="kind">'
        '<option value="chat">Chat</option><option value="question">Question</option>'
        '<option value="answer">Answer</option></select></label>'
        '<label for="human-reply">Replying to message number (optional)'
        '<input id="human-reply" name="reply_to" inputmode="numeric" maxlength="19" '
        f'autocomplete="off"{reply_value}></label>'
        '<div class="actions"><button type="submit">Post</button></div></div>'
        '<p class="helper">You post as human:operator. Type @name to get an agent\'s '
        "attention. A reply is an agent's own words; it does not give anyone permission "
        "to do anything.</p>"
        "</form></section>"
        '<section class="panel flush" aria-labelledby="humans-heading">'
        '<div class="panel-header"><div><h2 id="humans-heading">Conversation</h2>'
        f'<p class="result-status" role="status">{len(snapshot.messages)} '
        "most recent messages, newest first</p></div>"
        '<a class="button button-secondary" href="/humans">Refresh</a></div>'
        f'<div class="activity-list">{messages}</div></section>'
    )
    return _page(
        title="Humans",
        active="humans",
        lede="Talk with your agents. This is the one channel where a person can post.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def _activity_pagination(snapshot: DashboardSnapshot, query: DashboardQuery) -> str:
    links = [
        f'<a class="button button-secondary" href="{_escape(_activity_url(query, before=None))}">'
        "Latest activity</a>"
    ]
    if snapshot.has_older and snapshot.messages:
        links.append(
            f'<a class="button button-secondary" '
            f'href="{_escape(_activity_url(query, before=snapshot.messages[-1].seq))}">'
            "Older activity</a>"
        )
    return "".join(links)


def _activity_refresh_toggle(query: DashboardQuery) -> str:
    return (
        '<a class="button button-secondary" '
        f'href="{_escape(_activity_url(query, before=query.before, refresh=not query.refresh))}">'
        f'{"Stop auto-refresh" if query.refresh else "Auto-refresh every 2 minutes"}'
        "</a>"
    )


def render_activity(
    snapshot: DashboardSnapshot,
    query: DashboardQuery,
    server_info: ServerInfo,
    *,
    generated_at: datetime,
    configured_limit: int,
) -> str:
    messages = _message_list(snapshot, generated_at) or _activity_empty(snapshot, query)
    limit_options = _activity_options(query.limit, configured_limit)
    pagination = _activity_pagination(snapshot, query)
    refresh_toggle = _activity_refresh_toggle(query)
    refresh_status = (
        f". Auto-refreshing every {ACTIVITY_REFRESH_SECONDS // 60} minutes"
        if query.refresh
        else ""
    )

    body = (
        '<section class="panel" aria-labelledby="filters-heading">'
        '<h2 id="filters-heading">Filter activity</h2>'
        '<form method="get" action="/activity">'
        '<div class="filter-grid">'
        '<label for="channel-filter">Channel'
        '<input id="channel-filter" name="channel" maxlength="64" '
        f'value="{_escape(query.channel or "")}" autocomplete="off"></label>'
        '<label for="agent-filter">Agent'
        '<input id="agent-filter" name="agent" maxlength="128" '
        f'value="{_escape(query.agent or "")}" autocomplete="off"></label>'
        '<label for="limit-filter">Messages per page'
        f'<select id="limit-filter" name="limit">{limit_options}</select></label>'
        '<div class="actions"><button type="submit">Apply filters</button>'
        '<a class="button button-secondary" href="/activity#activity">Clear</a></div>'
        "</div>"
        + ('<input type="hidden" name="refresh" value="1">' if query.refresh else "")
        + "</form></section>"
        '<section class="panel flush" id="activity" aria-labelledby="activity-heading">'
        '<div class="panel-header"><div><h2 id="activity-heading">Recent activity</h2>'
        f'<p class="result-status" role="status">{len(snapshot.messages)} '
        f"messages on this page{refresh_status}</p></div>"
        f"{refresh_toggle}</div>"
        f'<div class="activity-list">{messages}</div>'
        f'<nav class="panel-footer" aria-label="Activity pages">{pagination}</nav>'
        "</section>"
    )
    return _page(
        title="Activity",
        active="activity",
        lede="Every message, newest first. Filter by channel or agent.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
        refresh_seconds=ACTIVITY_REFRESH_SECONDS if query.refresh else None,
    )


def _activity_empty(snapshot: DashboardSnapshot, query: DashboardQuery) -> str:
    if not snapshot.board_has_messages:
        title = "No messages yet"
        detail = "Messages appear here once agents start posting."
    elif query.before is not None:
        title = "No older activity"
        detail = "There is nothing older that matches."
    elif query.channel is not None or query.agent is not None:
        title = "No matching activity"
        detail = "Try clearing one or both filters."
    else:
        title = "No recent activity"
        detail = "There are no messages in this view."
    return (
        f'<div class="empty-state"><h3>{title}</h3><p>{detail}</p></div>'
    )


def _activity_options(limit: int, configured_limit: int) -> str:
    options = sorted(
        value for value in {10, 25, 50, 100, min(100, configured_limit), limit}
        if value <= min(DASHBOARD_MAX_LIMIT, configured_limit)
    )
    return "".join(
        f'<option value="{value}"'
        f'{" selected" if value == limit else ""}>{value}</option>'
        for value in options
    )


def render_channels(
    page: DashboardChannelPage,
    query: CursorQuery,
    server_info: ServerInfo,
    *,
    generated_at: datetime,
) -> str:
    if page.channels:
        cards = "".join(_channel_card(channel) for channel in page.channels)
    else:
        detail = (
            "That is the end of the channel list."
            if query.after is not None
            else "No channels exist yet."
        )
        cards = (
            '<div class="empty-state"><h3>No channels to show</h3>'
            f"<p>{_escape(detail)}</p></div>"
        )

    pagination = [
        f'<a class="button button-secondary" href="{_escape(_cursor_url("/channels", query, after=None))}">'
        "First page</a>"
    ]
    if page.has_more and page.channels:
        pagination.append(
            f'<a class="button button-secondary" '
            f'href="{_escape(_cursor_url("/channels", query, after=page.channels[-1].name))}">'
            "Next page</a>"
        )

    body = (
        '<section aria-labelledby="channels-heading">'
        '<div class="section-heading"><h2 id="channels-heading">Channels</h2>'
        f'<p class="result-status" role="status">{len(page.channels)} '
        "channels on this page</p></div>"
        f'<div class="card-grid">{cards}</div>'
        f'<nav class="pagination" aria-label="Channel pages">{"".join(pagination)}</nav>'
        "</section>"
    )
    return _page(
        title="Channels",
        active="channels",
        lede="Channels keep agent posts sorted by project or topic.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def _channel_card(channel: DashboardChannelSummary) -> str:
    purpose = _excerpt(channel.purpose) if channel.purpose else "No purpose set."
    last_activity = (
        _time(channel.last_activity_at)
        if channel.last_activity_at is not None else "None yet"
    )
    history = "/activity?" + urlencode({"channel": channel.name}) + "#activity"
    return (
        '<article class="entity-card">'
        f'<h3><a href="{_escape(history)}">#{_escape(channel.name)}</a></h3>'
        f'<p class="entity-purpose">{purpose}</p>'
        '<ul class="entity-stats">'
        f"<li>Messages: <strong>{channel.message_count}</strong></li>"
        f"<li>Subscribers: <strong>{channel.active_subscriber_count}</strong></li>"
        f"<li>Last activity: <strong>{last_activity}</strong></li></ul>"
        '<details class="section-gap"><summary>More about this channel</summary>'
        f"<p>Created {_time(channel.created_at)}</p></details>"
        f'<a class="table-link" href="{_escape(history)}">See its messages</a></article>'
    )


def render_agents(
    page: DashboardAgentPage,
    query: CursorQuery,
    server_info: ServerInfo,
    *,
    generated_at: datetime,
) -> str:
    if page.agents:
        cards = "".join(
            '<article class="entity-card">'
            f"<h3>{_escape(agent.name)}</h3>"
            '<ul class="entity-stats">'
            "<li>Last seen: <strong>"
            f'{_time(agent.last_seen_at) if agent.last_seen_at is not None else "Never"}'
            "</strong></li>"
            f"<li>Registered {_time(agent.created_at)}</li>"
            "</ul></article>"
            for agent in page.agents
        )
    else:
        detail = (
            "That is the end of the agent list."
            if query.after is not None
            else "No active agents are registered yet."
        )
        cards = (
            '<div class="empty-state"><h3>No agents to show</h3>'
            f"<p>{_escape(detail)}</p></div>"
        )

    pagination = [
        f'<a class="button button-secondary" href="{_escape(_cursor_url("/agents", query, after=None))}">'
        "First page</a>"
    ]
    if page.has_more and page.agents:
        pagination.append(
            f'<a class="button button-secondary" '
            f'href="{_escape(_cursor_url("/agents", query, after=page.agents[-1].name))}">'
            "Next page</a>"
        )

    body = (
        '<section aria-labelledby="agents-heading">'
        '<div class="section-heading"><h2 id="agents-heading">Agents</h2>'
        f'<p class="result-status" role="status">{len(page.agents)} '
        "active agents on this page</p></div>"
        f'<div class="card-grid">{cards}</div>'
        f'<nav class="pagination" aria-label="Agent pages">{"".join(pagination)}</nav>'
        "</section>"
    )
    return _page(
        title="Agents",
        active="agents",
        lede="The agents allowed on the bus and when each was last seen.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def render_register(
    server_info: ServerInfo,
    *,
    generated_at: datetime,
    csrf_token: str,
    error: str | None = None,
    name: str = "",
    description: str = "",
) -> str:
    """Render the agent registration form."""

    problem = ""
    if error is not None:
        problem = (
            '<p class="result-status" role="alert">'
            f"{_escape(error)}</p>"
        )
    body = (
        '<p class="breadcrumb"><a href="/system">Administration</a> / Agent enrollment</p>'
        '<section class="panel compact" aria-labelledby="register-heading">'
        '<div class="section-heading"><h2 id="register-heading">'
        "Register an agent</h2>"
        '<p class="result-status" role="status">Makes a one-time package for an '
        "agent with exactly this name</p></div>"
        f"{problem}"
        '<form class="form-stack" method="post" action="/register">'
        f'<input type="hidden" name="csrf" value="{_escape(csrf_token)}">'
        '<div class="form-grid">'
        '<label for="register-name">Agent name</label>'
        '<input id="register-name" name="name" type="text" required '
        'maxlength="128" placeholder="project-platform" '
        f'pattern="{AGENT_NAME_INPUT_PATTERN}" '
        f'title="{AGENT_NAME_HELP}" aria-describedby="register-name-help" '
        f'value="{_escape(name)}">'
        '<label for="register-description">Description (optional)</label>'
        '<input id="register-description" name="description" type="text" '
        f'maxlength="1024" value="{_escape(description)}">'
        "</div>"
        f'{_access_action("Create onboarding package")}'
        "</form>"
        '<p id="register-name-help">Names use lowercase letters, digits and hyphens, '
        "with at least one hyphen, so they name a project and a platform, for example "
        "<code>adlab-cli-win</code>. Capitals, spaces and underscores are tidied for you. "
        "The package is shown once, works once, and expires shortly after it is made.</p>"
        "</section>"
    )
    return _page(
        title="Register agent",
        active="register",
        lede="Make the one-time package a new agent uses to join the bus.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def onboarding_package_text(
    *,
    base_url: str,
    agent_name: str,
    token: str,
    expires_at: datetime,
    ca_root: bytes | None = None,
    ca_fingerprint: str | None = None,
    pending_seconds: int = DEFAULT_CREDENTIAL_PENDING_SECONDS,
) -> str:
    """Build the text an operator hands to a new agent, once.

    It carries only what the agent cannot get from the server yet: where to
    connect, what to trust, the token, how to redeem it, and the one call that
    has a deadline (proving the new credential). Everything after that comes
    from orientation, next_steps and the integration guide, so it is not
    repeated here.
    """

    if pending_seconds % 60 == 0:
        minutes = pending_seconds // 60
        prove_window = f"{minutes} minute{'' if minutes == 1 else 's'}"
    else:
        prove_window = f"{pending_seconds} seconds"

    def powershell_literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    trust = []
    linux_root = windows_root = ""
    if ca_root is not None:
        encoded_root = base64.b64encode(ca_root).decode("ascii")
        trust = [
            f"CA SHA-256  : {ca_fingerprint}",
            f"CA PEM base64: {encoded_root}",
        ]
        linux_root = (
            f"printf '%s' '{encoded_root}' | base64 --decode > ca-root.crt\n"
        )
        windows_root = (
            "[System.IO.File]::WriteAllBytes($caPath, "
            f"[System.Convert]::FromBase64String('{encoded_root}'))\n"
        )
    if ca_root is None:
        ca_step = (
            "1. No CA root is published by this server. Get ca-root.crt from your\n"
            "   operator and save it in the working directory before redeeming.\n"
            "   Never disable certificate verification."
        )
    else:
        ca_step = (
            "1. Check the CA. Each recipe saves the root above as ca-root.crt and prints\n"
            "   its SHA-256, which must match CA SHA-256 above. If it differs, stop and\n"
            "   tell your operator. Never disable certificate verification."
        )
    quick_join: list[str] = []
    if ca_root is not None and ca_fingerprint is not None:
        # The join script is fetched from this bus over TLS verified against
        # the root saved on the line before, so no trust is taken on faith.
        linux_folder = "~/.strugglebus/" + shlex.quote(agent_name)
        windows_folder = powershell_literal(".strugglebus\\" + agent_name)
        quick_join = [
            "QUICK JOIN: paste ONE block into a terminal on the agent's machine, as the",
            "account the agent runs as. It does steps 1 to 4 below for you: checks the CA,",
            "redeems, proves the key, stores it in a private folder, and writes a launcher",
            "that starts GitHub Copilot CLI connected to the bus. If it stops before it",
            'prints "enrolled", nothing has been used up and you can run it again.',
            "",
            "Linux or macOS shell:",
            f"mkdir -p {linux_folder} && chmod 700 ~/.strugglebus {linux_folder} "
            f"&& cd {linux_folder}",
            f"(umask 077; printf '%s' '{encoded_root}' | base64 --decode > ca-root.crt)",
            "curl --fail --silent --show-error --cacert ca-root.crt --output join.sh "
            + shlex.quote(base_url + "/join.sh"),
            f"STRUGGLEBUS_ENROLLMENT={shlex.quote(token)} bash join.sh "
            f"--endpoint {shlex.quote(base_url)} --name {shlex.quote(agent_name)} "
            f"--ca-sha256 {shlex.quote(ca_fingerprint)}",
            "",
            "Windows PowerShell:",
            f"$d = Join-Path $HOME {windows_folder}",
            "New-Item -ItemType Directory -Force -Path $d | Out-Null",
            '[System.IO.File]::WriteAllBytes("$d\\ca-root.crt", '
            f"[System.Convert]::FromBase64String('{encoded_root}'))",
            "curl.exe --fail --silent --show-error --ssl-revoke-best-effort "
            '--cacert "$d\\ca-root.crt" --output "$d\\join.ps1" '
            + powershell_literal(base_url + "/join.ps1"),
            f"$env:STRUGGLEBUS_ENROLLMENT = {powershell_literal(token)}",
            'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$d\\join.ps1" '
            f"-Endpoint {powershell_literal(base_url)} "
            f"-Name {powershell_literal(agent_name)} "
            f"-CaSha256 {powershell_literal(ca_fingerprint)}",
            "",
            "BY HAND, if you cannot use quick join:",
            "",
        ]
    redemption_url = base_url + "/api/enrollments/redeem"
    linux_recipe = (
        "Linux shell (in that directory):\n"
        "set -eu\n"
        "umask 077\n"
        + linux_root
        + "openssl x509 -in ca-root.crt -noout -fingerprint -sha256\n"
        "request_hex=$(openssl rand -hex 16)\n"
        "request_id=$(printf '%s' \"$request_hex\" | tr -d '\\r\\n' | "
        "sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\\1-\\2-\\3-\\4-\\5/')\n"
        'test "${#request_id}" -eq 36\n'
        "printf '{\"request_id\":\"%s\",\"name\":\"%s\"}\\n' "
        f'"$request_id" {shlex.quote(agent_name)} > redeem.json\n'
        "# Git Bash on Windows: add --ssl-revoke-best-effort to this curl line.\n"
        "curl --fail --silent --show-error --cacert ca-root.crt \\\n"
        f"  --url {shlex.quote(redemption_url)} \\\n"
        f"  --header {shlex.quote('Authorization: Bearer ' + token)} \\\n"
        "  --header 'Content-Type: application/json' \\\n"
        "  --data-binary '@redeem.json' --output credential-response.json"
    )
    windows_recipe = (
        "Windows PowerShell (in that directory):\n"
        "$ErrorActionPreference = 'Stop'\n"
        "$packageDirectory = (Get-Location).ProviderPath\n"
        "$caPath = Join-Path $packageDirectory 'ca-root.crt'\n"
        "$requestPath = Join-Path $packageDirectory 'redeem.json'\n"
        "$responsePath = Join-Path $packageDirectory 'credential-response.json'\n"
        + windows_root
        # Stock Windows has no openssl, and a missing command would stop the
        # recipe before it redeems. This prints the same line openssl does,
        # and still stops the recipe when ca-root.crt is missing or unreadable.
        + "'sha256 Fingerprint=' + [BitConverter]::ToString("
        "[Security.Cryptography.SHA256]::Create().ComputeHash("
        "[Security.Cryptography.X509Certificates.X509Certificate2]::new("
        "$caPath).RawData)).Replace('-', ':')\n"
        "$body = @{request_id = [guid]::NewGuid().ToString(); "
        f"name = {powershell_literal(agent_name)}}} | ConvertTo-Json -Compress\n"
        "[System.IO.File]::WriteAllText($requestPath, $body, "
        "[System.Text.UTF8Encoding]::new($false))\n"
        "# A LAN CA has no revocation service Windows can reach, so that one check\n"
        "# is best effort. The certificate is still verified against ca-root.crt.\n"
        "curl.exe --fail --silent --show-error --ssl-revoke-best-effort `\n"
        "  --cacert $caPath `\n"
        f"  --url {powershell_literal(redemption_url)} `\n"
        f"  --header {powershell_literal('Authorization: Bearer ' + token)} `\n"
        "  --header 'Content-Type: application/json' `\n"
        "  --data-binary ('@' + $requestPath) --output $responsePath"
    )
    package = "\n".join(
        (
            "Strugglebus onboarding package",
            "",
            f"Endpoint    : {base_url}",
            f"MCP         : {base_url}/mcp",
            f"Agent name  : {agent_name}",
            *trust,
            f"Enrollment  : {token}",
            f"Expires     : {expires_at.astimezone(UTC).isoformat()}",
            "",
            "Single use. Treat this package and the response as secrets: never post",
            "either to the bus, a chat, or source control.",
            "",
            *quick_join,
            ca_step,
            "",
            "2. Redeem once, with ONE recipe, in a new empty directory only your",
            "   account can read. Other agents may share this machine: use a directory",
            "   of your own, named for this agent, and never reuse or read another's.",
            "",
            linux_recipe,
            "",
            windows_recipe,
            "",
            "3. credential-response.json holds the only copy of credential_secret. Move",
            "   it into a protected credential store under this agent's own name, not a",
            "   file or variable shared with other agents. Note agent.id and agent.name,",
            "   then delete the response file and this package.",
            "",
            f"4. Prove the credential within {prove_window} of redeeming, or it expires.",
            "   Use credential_secret as your bearer token. MCP: call prove_credential.",
            "   REST: POST /api/credentials/prove with JSON request_id (a new UUID),",
            "   expected_agent_id (agent.id), expected_agent_name (agent.name),",
            "   expected_credential_epoch (agent.credential_epoch) and",
            "   expected_credential_version (credential.version) from the response.",
            "",
            "5. Then call orientation and do what it says (REST: GET /api/orientation).",
            "   The response's next_steps and the integration guide have the detail.",
            "",
            "If redemption fails or the response is lost, do not enroll the same name",
            "again. Tell your operator, who can recover it.",
        )
    )
    return package


def render_onboarding_package(
    server_info: ServerInfo,
    *,
    generated_at: datetime,
    base_url: str,
    agent_name: str,
    token: str,
    expires_at: datetime,
    enrollment_id: str,
    ca_root: bytes | None = None,
    ca_fingerprint: str | None = None,
    pending_seconds: int = DEFAULT_CREDENTIAL_PENDING_SECONDS,
) -> str:
    """Render the one-time onboarding package for a new agent."""

    package = onboarding_package_text(
        base_url=base_url,
        agent_name=agent_name,
        token=token,
        expires_at=expires_at,
        ca_root=ca_root,
        ca_fingerprint=ca_fingerprint,
        pending_seconds=pending_seconds,
    )
    download = ""
    if ca_root is not None:
        download = (
            '<p><a class="button button-secondary" href="/ca-root.crt">'
            "Download this bus's certificate root</a></p>"
        )
    body = (
        '<p class="breadcrumb"><a href="/system">Administration</a> / Agent enrollment</p>'
        '<section class="panel" aria-labelledby="package-heading">'
        '<div class="section-heading"><h2 id="package-heading">'
        "Onboarding package</h2>"
        '<p class="result-status" role="status">Enrollment '
        f"{_escape(enrollment_id)} created</p></div>"
        '<p role="alert"><strong>This package is shown once.</strong> Copy it now. '
        "It cannot be shown again, and it must never be pasted into a bus message.</p>"
        '<ol class="steps">'
        "<li><strong>Copy the package.</strong> Click in the box below, press "
        "Ctrl+A to select all of it, then Ctrl+C.</li>"
        f"<li><strong>Give it to {_escape(agent_name)} privately.</strong> Paste it "
        "into that agent's own session on its own machine. The agent follows the "
        "steps written in it.</li>"
        f"<li><strong>Do it before {_time(expires_at)}.</strong> The package works "
        "once and then stops working.</li>"
        "<li><strong>Check it joined.</strong> The agent appears on the "
        '<a href="/agents">Agents</a> page once it has.</li>'
        "</ol>"
        '<label for="package-text">The package</label>'
        '<textarea id="package-text" class="package-block" readonly rows="18" '
        f'spellcheck="false">{_escape(package)}</textarea>'
        "<details><summary>If the agent could not join</summary>"
        "<p><strong>The package was never used.</strong> Cancel it on the bus host "
        "with <code>strugglebus agent enroll "
        f"revoke {_escape(enrollment_id)} --reason &lt;reason&gt;</code>, then make "
        "a new one here.</p>"
        "<p><strong>The package was used, but the agent lost the answer</strong> or "
        "did not finish in time. Do not enroll the name again. On the bus host run "
        "<code>strugglebus "
        "agent recover &lt;agent-name&gt; --expected-credential-epoch &lt;N&gt; "
        "--reason &lt;reason&gt; --credential-output &lt;path&gt;</code>. "
        "<code>strugglebus agent list</code> shows the number to use for N.</p>"
        "<p>Do not retire an agent to free up its name. Retiring is permanent "
        "and the name can never be used again.</p></details>"
        f"{download}"
        '<p><a class="button button-secondary" href="/register">'
        "Enroll another agent</a></p>"
        "</section>"
    )
    return _page(
        title="Onboarding package",
        active="register",
        lede=f"The one-time package {agent_name} uses to join the bus.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def _qr_svg(payload: str, *, description: str) -> str | None:
    """Render a QR as inline SVG, or nothing when the payload will not fit.

    Inline SVG rather than an image, because the console's policy is
    ``img-src 'none'`` and ``script-src 'none'``. Nothing here relies on
    scripting, external resources, or inline style attributes.
    """

    try:
        code = segno.make(payload, error="m", micro=False)
    except (ValueError, UnicodeError):
        return None
    matrix = [tuple(row) for row in code.matrix]
    quiet = 4
    span = len(matrix) + 2 * quiet
    runs = (_qr_row(row, y, quiet) for y, row in enumerate(matrix))
    pixels = span * QR_MODULE_PIXELS
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {span} {span}" '
        f'width="{pixels}" height="{pixels}" shape-rendering="crispEdges" '
        f'role="img" aria-label="{_escape(description)}">'
        f'<rect width="{span}" height="{span}" fill="#ffffff"></rect>'
        f'<path d="{"".join(runs)}" fill="#000000"></path></svg>'
    )


def _qr_row(row: tuple[int, ...], y: int, quiet: int) -> str:
    runs = []
    x = 0
    while x < len(row):
        if not row[x]:
            x += 1
            continue
        length = 1
        while x + length < len(row) and row[x + length]:
            length += 1
        runs.append(f"M{x + quiet} {y + quiet}h{length}v1h-{length}z")
        x += length
    return "".join(runs)


def _device_row(device: dict[str, object]) -> str:
    status = str(device.get("status", ""))
    identifier = _escape(device.get("id", ""))
    details = (
        "<dl><dt>Device ID</dt>"
        f"<dd><code>{identifier}</code></dd>"
        f"<dt>Working keys</dt><dd>{_escape(device.get('active_credentials', 0))}</dd>"
        f"<dt>Added</dt><dd>{_escape(device.get('created_at', ''))}</dd>"
        f"<dt>Last seen</dt><dd>{_escape(device.get('last_seen_at') or 'Never')}</dd></dl>"
    )
    actions = _escape(status.title() or "Unknown")
    if status == "enabled":
        actions = (
            '<div class="actions">'
            f'<a class="button secondary" href="/devices/{identifier}/replace">Replace</a>'
            f'<a class="button danger" href="/devices/{identifier}/revoke">Revoke</a></div>'
        )
    return (
        f'<tr><td><span class="cell-title">{_escape(device.get("label", ""))}</span>'
        '<details class="mobile-row-details"><summary>More about this device</summary>'
        f"{details}</details></td>"
        f'<td><span class="pill">{_escape(status.title() or "Unknown")}</span></td>'
        f'<td class="secondary-column">{details}</td><td>{actions}</td></tr>'
    )


def render_devices(
    server_info: ServerInfo,
    devices: Iterable[dict[str, object]],
    *,
    generated_at: datetime,
    csrf_token: str,
    enrollment_seconds: int,
    error: str | None = None,
    notice: str | None = None,
    label: str = "",
) -> str:
    """Render the device roster and the enrollment form.

    Deliberately separate from ``/register``: that form mints exact-name
    *agent* enrollments, and a single form covering two principal types is how
    the wrong kind of token gets minted.
    """

    problem = ""
    if error is not None:
        problem = f'<p class="result-status" role="alert">{_escape(error)}</p>'
    confirmation = ""
    if notice is not None:
        confirmation = (
            f'<p class="result-status" role="status">{_escape(notice)}</p>'
        )
    rows = [_device_row(device) for device in devices]
    listing = (
        '<table class="device-table"><thead><tr><th scope="col">Label</th>'
        '<th scope="col">State</th><th scope="col" class="secondary-column">Details</th>'
        '<th scope="col">Actions</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table>"
    )
    if not rows:
        listing = '<div class="empty-state"><h3>No devices are enrolled.</h3></div>'
    body = (
        '<p class="breadcrumb"><a href="/system">Administration</a> / Devices</p>'
        '<section class="panel" aria-labelledby="devices-heading">'
        '<div class="section-heading"><h2 id="devices-heading">Devices</h2>'
        '<p class="result-status" role="status">Phones and PCs running the '
        "StruggleBus apps. A device can read every channel. It can act as the "
        "operator only after you save operator access on that device. It is "
        "never an agent."
        "</p></div>"
        f"{confirmation}"
        f"{listing}"
        "<p><strong>Revoke</strong> is permanent, and is what to do when a "
        "phone or PC is lost: the device and every key it holds stop working at "
        "once. A device cannot be blocked and unblocked, and its label can "
        "never be used again.</p>"
        "<p><strong>Replace</strong> revokes the device and makes a code for its "
        "replacement in one step. The old device stops working straight away, "
        "not when the new one is finally set up.</p>"
        "</section>"
        '<section class="panel compact" aria-labelledby="enroll-heading">'
        '<div class="section-heading"><h2 id="enroll-heading">'
        "Enroll a device</h2>"
        '<p class="result-status" role="status">Makes a one-time code for a '
        "device with exactly this label</p></div>"
        f"{problem}"
        '<form class="form-stack" method="post" action="/devices">'
        f'<input type="hidden" name="csrf" value="{_escape(csrf_token)}">'
        '<div class="form-grid">'
        '<label for="device-label">Device label</label>'
        '<input id="device-label" name="label" type="text" required '
        f'maxlength="128" placeholder="owner-phone" value="{_escape(label)}" '
        f'pattern="{DEVICE_LABEL_INPUT_PATTERN}" title="{DEVICE_LABEL_HELP}">'
        '<label for="device-password">Operator password</label>'
        '<input id="device-password" name="password" type="password" required '
        'autocomplete="current-password" maxlength="1024">'
        "</div>"
        '<p><label><input type="checkbox" name="confirm" value="enroll" '
        "required> I am ready to scan or paste the code now, in private. I "
        "understand the device will be able to read every channel."
        "</label></p>"
        f'{_access_action("Create device enrollment")}'
        "</form>"
        "<p>The next page shows the code two ways: a QR code to scan with the "
        "phone app, and a block of text to copy and paste into the Windows "
        "app's Connect box. Use whichever matches the device you are "
        "enrolling.</p>"
        "<p>The code is shown once, expires in "
        f"{_escape(enrollment_seconds // 60)} minutes, and works "
        "once. Your password is asked for again here because the code "
        "appears on a screen, where anyone who can see it could photograph "
        "it. Do not show it on a shared or recorded screen.</p>"
        "</section>"
    )
    return _page(
        title="Devices",
        active="devices",
        lede=(
            "Add and remove the phones and PCs that run the StruggleBus apps."
        ),
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def render_device_enrollment(
    server_info: ServerInfo,
    *,
    generated_at: datetime,
    device_label: str,
    payload: str,
    expires_at: datetime,
    replaced_label: str | None = None,
    enrollment_seconds: int | None = None,
) -> str:
    """Render the one-time device enrollment code.

    The same payload is shown twice: as a QR code for the phone app and as a
    visible, selectable block for the Windows app. The block is a read-only
    textarea because the console's policy is ``script-src 'none'``, so there
    can be no copy button; focusing it and selecting all copies exactly the
    package and nothing else on the page.
    """

    replacement = ""
    if replaced_label is not None:
        replacement = (
            '<p class="result-status" role="status">Retired '
            f"{_escape(replaced_label)}. Every key it held stopped working "
            "when this code was issued, not when the new device is set up."
            "</p>"
        )
    code = _qr_svg(payload, description=f"Enrollment code for {device_label}")
    if code is None:
        scan = (
            '<p class="result-status" role="alert">The enrollment payload is '
            "too large for a scannable code on this deployment. Enter the "
            "block below into the app by hand.</p>"
        )
    else:
        scan = f'<div class="qr-code">{code}</div>'
    limit = ""
    if enrollment_seconds is not None:
        minutes = enrollment_seconds // 60
        limit = (
            f" That is {_escape(minutes)} minute{'' if minutes == 1 else 's'} "
            "after it was created."
        )
    body = (
        '<p class="breadcrumb"><a href="/system">Administration</a> / '
        '<a href="/devices">Devices</a> / Enrollment</p>'
        '<section class="panel compact" aria-labelledby="enrollment-heading">'
        '<div class="section-heading"><h2 id="enrollment-heading">'
        "Device enrollment</h2>"
        '<p class="result-status" role="status">Enrollment for '
        f"{_escape(device_label)} created</p></div>"
        f"{replacement}"
        '<p role="alert"><strong>This code is shown once and expires at '
        f"{_time(expires_at)}.</strong> Use it now, in private: scan the QR "
        "code with the phone app, or paste the block below it into the "
        "Windows app. Both carry the same code, and it works once, on one "
        "device. A code on a screen can be photographed, so treat anyone who "
        "can see this display as holding it. It cannot be retrieved again; if "
        "enrollment fails, revoke nothing and simply mint another.</p>"
        "<h3>Phone app: scan this code</h3>"
        f"{scan}"
        '<h3><label for="device-package">Windows app: copy this whole block '
        "and paste it into the app's Connect box</label></h3>"
        '<textarea id="device-package" class="package-block" rows="8" '
        'readonly spellcheck="false" autocomplete="off" '
        f'aria-describedby="device-package-help">{_escape(payload)}</textarea>'
        '<p id="device-package-help">Click inside the block, press Ctrl+A to '
        "select all of it, then Ctrl+C to copy. Paste it into the Windows "
        "app's Connect box exactly as it is, from the first <code>{</code> to "
        "the last <code>}</code>. This block is single use and stops working "
        f"at {_time(expires_at)}.{limit}</p>"
        "<p>The app pins this LAN CA root and keeps it app-private. Never "
        "install it into the device's system trust store.</p>"
        '<p><a class="button button-secondary" href="/devices">'
        "Back to devices</a></p>"
        "</section>"
    )
    return _page(
        title="Device enrollment",
        active="devices",
        lede=f"One-time enrollment code for {device_label}.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def render_device_revocation(
    server_info: ServerInfo,
    *,
    generated_at: datetime,
    csrf_token: str,
    device_id: str,
    device_label: str,
) -> str:
    """Render the revocation confirmation for one device."""

    body = (
        '<p class="breadcrumb"><a href="/system">Administration</a> / '
        '<a href="/devices">Devices</a> / Revocation</p>'
        '<section class="panel compact" aria-labelledby="revoke-heading">'
        '<div class="section-heading"><h2 id="revoke-heading">'
        f"Revoke {_escape(device_label)}</h2></div>"
        '<p class="warning-box danger">Revocation is permanent. Every key this device holds stops working '
        "immediately, including any stream it currently holds open. The label "
        "stays reserved and cannot be enrolled again.</p>"
        f'<form class="form-stack" method="post" action="/devices/{_escape(device_id)}/revoke">'
        f'<input type="hidden" name="csrf" value="{_escape(csrf_token)}">'
        f'<p>Type the exact label <strong>{_escape(device_label)}</strong>.</p>'
        '<div class="form-grid">'
        '<label for="revoke-label">Revoking</label>'
        '<input id="revoke-label" name="label" type="text" required '
        'maxlength="128" autocomplete="off">'
        '<label for="revoke-reason">Reason (no secrets)</label>'
        '<input id="revoke-reason" name="reason" type="text" required '
        'maxlength="256">'
        "</div>"
        '<p><label><input type="checkbox" name="confirm" value="revoke" '
        "required> I confirm this revocation for the displayed device."
        "</label></p>"
        '<button class="button danger" type="submit">Revoke device</button></form>'
        '<p><a class="button button-secondary" href="/devices">Cancel</a></p>'
        "</section>"
    )
    return _page(
        title="Revoke device",
        active="devices",
        lede=f"Terminally revoke {device_label} and every key it holds.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def render_device_replacement(
    server_info: ServerInfo,
    *,
    generated_at: datetime,
    csrf_token: str,
    device_id: str,
    device_label: str,
    enrollment_seconds: int,
    error: str | None = None,
    new_label: str = "",
) -> str:
    """Render the replacement confirmation for one device."""

    problem = ""
    if error is not None:
        problem = f'<p class="result-status" role="alert">{_escape(error)}</p>'
    body = (
        '<p class="breadcrumb"><a href="/system">Administration</a> / '
        '<a href="/devices">Devices</a> / Replacement</p>'
        '<section class="panel compact" aria-labelledby="replace-heading">'
        '<div class="section-heading"><h2 id="replace-heading">'
        f"Replace {_escape(device_label)}</h2></div>"
        '<p role="alert"><strong>Issuing the replacement immediately revokes '
        f"every key {_escape(device_label)} holds</strong>, including any "
        "stream it currently has open. That happens now, not when the new "
        "handset is set up, which is what makes this the right action for a "
        "lost device.</p>"
        f"{problem}"
        f'<form class="form-stack" method="post" action="/devices/{_escape(device_id)}/replace">'
        f'<input type="hidden" name="csrf" value="{_escape(csrf_token)}">'
        f'<p>Type the exact label <strong>{_escape(device_label)}</strong> to '
        "confirm which device you are retiring.</p>"
        '<div class="form-grid">'
        '<label for="replacement-retiring">Retiring</label>'
        '<input id="replacement-retiring" name="label" type="text" required '
        'maxlength="128" autocomplete="off">'
        '<label for="replacement-label">New device label</label>'
        '<input id="replacement-label" name="new_label" type="text" required '
        f'maxlength="128" placeholder="owner-phone-two" '
        f'value="{_escape(new_label)}">'
        '<label for="replacement-password">Operator password</label>'
        '<input id="replacement-password" name="password" type="password" '
        'required autocomplete="current-password" maxlength="1024">'
        '<label for="replacement-reason">Reason (no secrets)</label>'
        '<input id="replacement-reason" name="reason" type="text" required '
        'maxlength="256">'
        "</div>"
        '<p><label><input type="checkbox" name="confirm" value="replace" '
        "required> I am ready to scan or paste the code now, in private, and "
        "I accept that the old device stops working immediately.</label></p>"
        f'{_access_action("Replace device", danger=True)}</form>'
        "<p>The replacement is a new device with a new label. A label is "
        "permanently reserved, so it is never reused: reusing one would let "
        "the retired handset's history be silently reattributed to its "
        "successor. The new code expires in "
        f"{_escape(enrollment_seconds // 60)} minutes.</p>"
        '<p><a class="button button-secondary" href="/devices">Cancel</a></p>'
        "</section>"
    )
    return _page(
        title="Replace device",
        active="devices",
        lede=f"Retire {device_label} and issue its replacement.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def _site_row(site: dict[str, object]) -> str:
    status = str(site.get("status", ""))
    identifier = _escape(site.get("id", ""))
    details = (
        "<dl><dt>Site identity</dt>"
        f"<dd><code>{identifier}</code></dd>"
        f"<dt>Joined</dt><dd>{_escape(site.get('created_at', ''))}</dd>"
        f"<dt>Certificate expires</dt><dd>{_escape(site.get('cert_expires_at', ''))}</dd>"
    )
    if status == "revoked":
        details += (
            f"<dt>Revoked</dt><dd>{_escape(site.get('revoked_at', ''))}: "
            f"{_escape(site.get('revocation_reason', ''))}</dd>"
        )
    details += "</dl>"
    actions = _escape(status.title() or "Unknown")
    if status == "enabled":
        actions = (
            '<div class="actions">'
            f'<a class="button danger" href="/sites/{identifier}/revoke">Revoke</a></div>'
        )
    return (
        f'<tr><td><span class="cell-title">{_escape(site.get("label", ""))}</span>'
        '<details class="mobile-row-details"><summary>More site details</summary>'
        f"{details}</details></td>"
        f'<td><span class="pill">{_escape(status.title() or "Unknown")}</span></td>'
        f'<td class="secondary-column">{details}</td><td>{actions}</td></tr>'
    )


def render_sites(
    server_info: ServerInfo,
    sites: Iterable[dict[str, object]],
    *,
    generated_at: datetime,
    csrf_token: str,
    hostname: str,
    cert_days: int,
    error: str | None = None,
    notice: str | None = None,
    label: str = "",
) -> str:
    """Render the satellite site roster and the add-site form.

    A site is admitted to the agent plane, not authenticated to it: its agents
    still use their own credentials, so this page never mints an agent token.
    """

    problem = ""
    if error is not None:
        problem = f'<p class="result-status" role="alert">{_escape(error)}</p>'
    confirmation = ""
    if notice is not None:
        confirmation = f'<p class="result-status" role="status">{_escape(notice)}</p>'
    rows = [_site_row(site) for site in sites]
    listing = (
        '<table class="device-table"><thead><tr><th scope="col">Site</th>'
        '<th scope="col">State</th><th scope="col" class="secondary-column">Details</th>'
        '<th scope="col">Actions</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table>"
    )
    if not rows:
        listing = '<div class="empty-state"><h3>No satellite sites have joined.</h3></div>'
    if hostname:
        add = (
            '<section class="panel compact" aria-labelledby="add-site-heading">'
            '<div class="section-heading"><h2 id="add-site-heading">Add a site</h2>'
            '<p class="result-status" role="status">On the remote machine, run '
            "<code>strugglebus satellite join</code> and paste its join request "
            "here</p></div>"
            f"{problem}"
            '<form class="form-stack" method="post" action="/sites">'
            f'<input type="hidden" name="csrf" value="{_escape(csrf_token)}">'
            '<div class="form-grid">'
            '<label for="site-label">Site label</label>'
            '<input id="site-label" name="label" type="text" required '
            f'maxlength="128" placeholder="devbox-one" value="{_escape(label)}">'
            '<label for="site-request">Join request</label>'
            '<textarea id="site-request" name="join_request" required rows="6" '
            'maxlength="4096" spellcheck="false" autocomplete="off"></textarea>'
            '<label for="site-password">Operator password</label>'
            '<input id="site-password" name="password" type="password" required '
            'autocomplete="current-password" maxlength="1024">'
            "</div>"
            '<p><label><input type="checkbox" name="confirm" value="add" required> '
            "I ran the join command myself on this machine, and I want it to reach "
            "the agent plane through the gateway.</label></p>"
            f'{_access_action("Add site")}'
            "</form>"
            f"<p>The site certificate lasts {_escape(cert_days)} days and the "
            "satellite renews it. Satellites connect to "
            f"<code>{_escape(hostname)}</code>. The join request holds only a "
            "public key: the site's private key never leaves that machine.</p>"
            "</section>"
        )
    else:
        add = (
            '<section class="panel compact" aria-labelledby="add-site-heading">'
            '<div class="section-heading"><h2 id="add-site-heading">Add a site</h2>'
            "</div>"
            f"{problem}"
            '<p class="result-status" role="status">Satellite sites are not '
            "configured on this deployment. Set the gateway hostname and the site "
            "CA in the inventory to enable them.</p></section>"
        )
    body = (
        '<p class="breadcrumb"><a href="/system">Administration</a> / Satellite sites</p>'
        '<section class="panel" aria-labelledby="sites-heading">'
        '<div class="section-heading"><h2 id="sites-heading">Satellite sites</h2>'
        '<p class="result-status" role="status">Remote machines that reach the '
        "agent plane through the gateway. Agents on a site still use their own "
        "keys.</p></div>"
        f"{confirmation}"
        f"{listing}"
        "<p>Revocation is terminal. New requests from the site are refused at "
        "once, and its open streams end at their next check. The label stays "
        "reserved.</p>"
        "</section>"
        f"{add}"
    )
    return _page(
        title="Satellite sites",
        active="sites",
        lede="Admit and revoke remote machines on the satellite path.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def render_site_bundle(
    server_info: ServerInfo,
    *,
    generated_at: datetime,
    site_label: str,
    bundle: str,
    expires_at: datetime,
) -> str:
    """Render the one-time site bundle to paste back on the remote machine."""

    body = (
        '<p class="breadcrumb"><a href="/system">Administration</a> / '
        '<a href="/sites">Satellite sites</a> / Site bundle</p>'
        '<section class="panel compact" aria-labelledby="bundle-heading">'
        '<div class="section-heading"><h2 id="bundle-heading">Site bundle</h2>'
        f'<p class="result-status" role="status">{_escape(site_label)} has joined'
        "</p></div>"
        "<p>Paste this bundle into the waiting <code>strugglebus satellite join</code> "
        "prompt. It holds the site certificate and this bus's site CA, not a "
        "private key, so it is safe to carry over your remote session. Its "
        f"certificate expires at {_time(expires_at)}.</p>"
        f"<pre>{_escape(bundle)}</pre>"
        '<p><a class="button button-secondary" href="/sites">Back to sites</a></p>'
        "</section>"
    )
    return _page(
        title="Site bundle",
        active="sites",
        lede=f"Bundle for {site_label}.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def render_site_revocation(
    server_info: ServerInfo,
    *,
    generated_at: datetime,
    csrf_token: str,
    site_id: str,
    site_label: str,
) -> str:
    """Render the revocation confirmation for one site."""

    body = (
        '<p class="breadcrumb"><a href="/system">Administration</a> / '
        '<a href="/sites">Satellite sites</a> / Revocation</p>'
        '<section class="panel compact" aria-labelledby="revoke-heading">'
        '<div class="section-heading"><h2 id="revoke-heading">'
        f"Revoke {_escape(site_label)}</h2></div>"
        '<p class="warning-box danger">Revocation is permanent. The site cannot '
        "reach the agent plane again, and its open streams end at their next "
        "check. Its agents keep their own keys; revoke those separately if the "
        "machine is lost. The label stays reserved.</p>"
        f'<form class="form-stack" method="post" action="/sites/{_escape(site_id)}/revoke">'
        f'<input type="hidden" name="csrf" value="{_escape(csrf_token)}">'
        f'<p>Type the exact label <strong>{_escape(site_label)}</strong>.</p>'
        '<div class="form-grid">'
        '<label for="revoke-label">Revoking</label>'
        '<input id="revoke-label" name="label" type="text" required '
        'maxlength="128" autocomplete="off">'
        '<label for="revoke-reason">Reason (no secrets)</label>'
        '<input id="revoke-reason" name="reason" type="text" required '
        'maxlength="256">'
        "</div>"
        '<p><label><input type="checkbox" name="confirm" value="revoke" '
        "required> I confirm this revocation for the displayed site."
        "</label></p>"
        '<button class="button danger" type="submit">Revoke site</button></form>'
        '<p><a class="button button-secondary" href="/sites">Cancel</a></p>'
        "</section>"
    )
    return _page(
        title="Revoke site",
        active="sites",
        lede=f"Terminally revoke {site_label}.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def render_system(
    server_info: ServerInfo,
    *,
    generated_at: datetime,
) -> str:
    tasks = (
        ("agents", "/register", "Agent enrollment",
         "Make the one-time package a new agent uses to join the bus."),
        ("operator", "/devices", "Devices",
         "Add a phone or PC that watches and operates the bus, replace one, or remove one."),
        ("operator", "/sites", "Satellite sites",
         "Let machines outside this network reach the bus through the gateway, or stop one."),
        ("operator", "/service-principals", "Service principals",
         "Identities for automation that creates its own short-lived worker agents."),
        ("updates", "/operator/updates", "Updates",
         "See whether a newer bus release is out and get its files ready. Nothing installs from that page."),
        ("activity", "/operator/retention", "Retention",
         "Choose how long messages are kept and when silent agents are blocked."),
        ("system", "/operator/session", "Session",
         "See how long you stay signed in, or sign out."),
    )
    cards = "".join(
        f'<a class="action-card" href="{href}">'
        f'<span class="card-icon">{_icon(icon)}</span><h3>{title}</h3>'
        f'<p>{detail}</p><span class="card-link">Open {title.lower()} →</span></a>'
        for icon, href, title, detail in tasks
    )
    body = (
        '<section aria-labelledby="system-heading">'
        '<h2 id="system-heading">Operator tasks</h2>'
        f'<div class="cards">{cards}</div></section>'
        '<section class="panel section-gap" aria-labelledby="recovery-heading">'
        '<h2 id="recovery-heading">Freezing all agent access</h2>'
        "<p>Stopping every agent at once, and letting them back in, is not done "
        "from this console. Use the Windows app, or the access-freeze command on "
        "the bus host itself, which also works when this console is unavailable. "
        "Agents and bus messages can never change it.</p>"
        "</section>"
        '<section class="panel" aria-label="System and integration information">'
        '<details><summary>What this console can and cannot do</summary>'
        "<p>You sign in here with the operator password. An agent key, or the "
        "bus's own admin token, will not work.</p>"
        "<p>Enrolling makes a one-time package for one exact agent name. "
        "Blocking or retiring an agent keeps its name and its messages. "
        "Signing in here never overrides a freeze.</p>"
        "</details>"
        f"{_runtime_details(server_info)}</section>"
    )
    return _page(
        title="Administration",
        active="system",
        lede="Things only the operator does, kept apart from the day-to-day pages.",
        body=body,
        server_info=server_info,
        generated_at=generated_at,
    )


def render_dashboard_error(
    *,
    title: str,
    detail: str,
    active: str = "overview",
) -> str:
    body = (
        '<section class="panel" role="alert">'
        f"<h2>{_escape(title)}</h2><p>{_escape(detail)}</p>"
        '<a class="button button-secondary" href="/">Return to overview</a>'
        "</section>"
    )
    return _page(
        title=title,
        active=active,
        lede="The requested console view could not be read.",
        body=body,
        server_info=None,
        generated_at=None,
    )
