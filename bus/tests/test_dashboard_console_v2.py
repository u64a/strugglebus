"""Shared v2 shell and dashboard-owned workflow rendering contracts."""

from __future__ import annotations

import hashlib
import html
import re
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from importlib.resources import files

import pytest

from strugglebus import dashboard as ui
from strugglebus.console_context import console_access_context
from strugglebus.integration import build_server_info
from strugglebus.models import (
    DashboardAgentPage,
    DashboardAgentSummary,
    DashboardChannelPage,
    DashboardChannelSummary,
    DashboardCounts,
    DashboardSnapshot,
    Message,
)

NOW = datetime(2026, 9, 17, 11, 0, tzinfo=UTC)
HOSTILE = '"><script>untrusted & value</script>'


class Document(HTMLParser):
    def __init__(self, source: str):
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def attributes(self, tag: str):
        return [attrs for name, attrs in self.elements if name == tag]


@contextmanager
def contexts(state="unobserved"):
    access_token = console_access_context.set(state)
    try:
        yield
    finally:
        console_access_context.reset(access_token)


@pytest.fixture
def info(app_config):
    return build_server_info(app_config)


def message(*, seq=1, kind="chat", body="A report", reply_to=None):
    return Message(
        seq=seq, id=f"message-{seq}", channel="status", agent_id="private-id",
        agent_name="atlas-worker", body=body, kind=kind, reply_to=reply_to,
        metadata={"not-exposed": HOSTILE}, created_at=NOW,
    )


def snapshot(*messages, parents=(), board_has_messages=True):
    return DashboardSnapshot(
        counts=DashboardCounts(3, 4, 5, blocked_agents=2, retired_agents=1),
        messages=messages, parent_messages=parents, has_older=False,
        board_has_messages=board_has_messages,
    )


def test_stylesheet_path_is_bound_to_the_packaged_css_bytes():
    css = files("strugglebus").joinpath("operator.css").read_bytes()
    assert css.decode() == ui.DASHBOARD_STYLESHEET
    assert hashlib.sha256(css).hexdigest()[:16] in ui.DASHBOARD_STYLESHEET_PATH


@pytest.mark.parametrize("state", ["unobserved", "available", "frozen", "unavailable"])
def test_shared_shell_labels_state_without_inferring_health(info, state):
    with contexts(state):
        source = ui.render_operator("A view", "<p>Readable content</p>", info, generated_at=NOW)
    document = Document(source)
    assert len(document.attributes("h1")) == 1
    assert len(document.attributes("main")) == 1
    assert document.attributes("main")[0]["tabindex"] == "-1"
    assert '<a class="skip-link" href="#main-content">' in source
    assert source.count('aria-label="Console sections"') == 2
    assert "Workspace" in source and "Operator" in source
    assert "Readable content" in source
    assert "Page loaded" in source
    expected = {
        "frozen": "Agent access is frozen",
        "unavailable": "Access state unavailable",
    }.get(state)
    if expected:
        assert expected in source
        assert 'role="alert"' in source
    else:
        assert 'role="alert"' not in source
        assert "Available" not in source
    assert "status-ok" not in source
    assert "primary-nav" not in source


def test_minimal_documents_hide_context_and_runtime_even_when_supplied_timestamp():
    with contexts("frozen"):
        source = ui.render_operator(HOSTILE, "<p>A minimal response</p>", generated_at=NOW)
    assert html.escape(HOSTILE) in source
    assert "<script>" not in source
    assert 'class="login-layout"' in source
    assert 'class="rail"' not in source
    assert "Console sections" not in source
    assert "<summary>Versions" not in source
    assert "Page loaded" not in source
    assert "frozen" not in source
    assert Document(source).attributes("link") == [
        {"rel": "stylesheet", "href": ui.DASHBOARD_STYLESHEET_PATH}
    ]


@pytest.mark.parametrize("active", ["operator", "session"])
def test_session_navigation_accepts_existing_and_semantic_active_keys(info, active):
    source = ui.render_operator("Session", "<p>Session details</p>", info, active=active)
    assert source.count('href="/operator/session" aria-current="page"') == 2
    assert source.count("<span>Session</span>") == 2


@pytest.mark.parametrize("state", ["unobserved", "available", "frozen", "unavailable"])
def test_access_creating_forms_explain_denial_beside_submit_without_disabling_containment(info, state):
    with contexts(state):
        forms = [
            ui.render_register(info, generated_at=NOW, csrf_token=HOSTILE, name=HOSTILE),
            ui.render_devices(info, (), generated_at=NOW, csrf_token=HOSTILE, enrollment_seconds=180),
            ui.render_device_replacement(
                info, generated_at=NOW, csrf_token=HOSTILE, device_id="device-one",
                device_label=HOSTILE, enrollment_seconds=180, new_label=HOSTILE,
            ),
        ]
        revoke = ui.render_device_revocation(
            info, generated_at=NOW, csrf_token=HOSTILE,
            device_id="device-one", device_label=HOSTILE,
        )
    for source in forms:
        submit = Document(source).attributes("button")[0]
        assert ("disabled" in submit) == (state in {"frozen", "unavailable"})
        assert 'class="form-stack"' in source
        assert html.escape(HOSTILE) in source
        assert "<script>" not in source
        if "disabled" in submit:
            assert submit["aria-describedby"] == "action-access-note"
            assert 'id="action-access-note"' in source.split("<form", 1)[1]
    assert "disabled" not in Document(revoke).attributes("button")[0]
    assert Document(revoke).attributes("button")[0]["class"] == "button danger"
    assert 'href="/devices"' in revoke
    assert "Revocation is permanent" in revoke


def test_dashboard_owned_workflows_keep_every_field_bound(info):
    register = ui.render_register(info, generated_at=NOW, csrf_token="csrf")
    inputs = {item["name"]: item for item in Document(register).attributes("input")}
    assert inputs["name"]["maxlength"] == "128"
    assert inputs["description"]["maxlength"] == "1024"
    assert inputs["csrf"]["value"] == "csrf"
    replacement = ui.render_device_replacement(
        info, generated_at=NOW, csrf_token="csrf", device_id="device-one",
        device_label="owner-phone", enrollment_seconds=180,
    )
    inputs = {item["name"]: item for item in Document(replacement).attributes("input")}
    assert set(inputs) == {"csrf", "label", "new_label", "password", "reason", "confirm"}
    assert inputs["password"]["maxlength"] == "1024"
    assert inputs["password"]["autocomplete"] == "current-password"
    assert "value" not in inputs["password"]
    assert inputs["reason"]["maxlength"] == "256"
    assert inputs["confirm"]["value"] == "replace"
    assert inputs["label"]["maxlength"] == inputs["new_label"]["maxlength"] == "128"
    assert "immediately revokes" in replacement
    assert "3 minutes" in replacement


def test_device_roster_preserves_details_mobile_disclosures_and_unknown_state(info):
    devices = (
        {
            "id": "device-one", "label": HOSTILE, "status": "enabled",
            "active_credentials": 2, "created_at": NOW, "last_seen_at": NOW,
        },
        {"id": "device-two", "label": "old-phone", "status": "revoked"},
        {},
    )
    source = ui.render_devices(
        info, devices, generated_at=NOW, csrf_token="csrf", enrollment_seconds=180,
        error=HOSTILE, notice=HOSTILE, label=HOSTILE,
    )
    assert "More about this device" in source
    for field in ("Device ID", "Working keys", "Added", "Last seen"):
        assert field in source
    assert "Unknown" in source and "Never" in source and "Revoked" in source
    assert "/devices/device-one/revoke" in source
    assert "/devices/device-two/revoke" not in source
    assert html.escape(HOSTILE) in source and "<script>" not in source
    assert "never an agent" in source and "save operator access on that device" in source
    assert "Phones and PCs running the StruggleBus apps" in source
    assert "paste into the Windows app's Connect box" in html.unescape(source)
    assert "mobile monitors" not in source


@pytest.mark.parametrize("payload", ['{"device":"owner-phone"}', "x" * 10000])
def test_device_enrollment_supports_scan_and_manual_failure_without_hiding_payload(info, payload):
    source = ui.render_device_enrollment(
        info, generated_at=NOW, device_label=HOSTILE,
        payload=payload, expires_at=NOW + timedelta(minutes=3), replaced_label=HOSTILE,
        enrollment_seconds=180,
    )
    assert html.escape(payload) in source
    # A Windows desktop user has no camera to scan with, so the package they
    # paste must be on the page in full, never behind a disclosure.
    section = source.split('id="enrollment-heading"', 1)[1].split("</section>", 1)[0]
    assert "<details" not in section
    block = source.split('<textarea id="device-package"', 1)[1]
    attributes, block = block.split(">", 1)
    assert "readonly" in attributes
    assert block.split("</textarea>", 1)[0] == html.escape(payload)
    assert (
        "Windows app: copy this whole block and paste it into the app's "
        "Connect box"
    ) in html.unescape(source)
    assert "Phone app: scan this code" in source
    help_text = source.split('id="device-package-help"', 1)[1].split("</p>", 1)[0]
    assert "stops working at <time" in help_text
    assert "That is 3 minutes after it was created." in help_text
    assert html.escape(HOSTILE) in source
    assert "Every key it held stopped working" in source
    assert "shown once" in source and "app-private" in source
    assert "<script>" not in source
    assert ("too large for a scannable code" in source) == (len(payload) > 1000)
    assert ('class="qr-code"' in source) == (len(payload) < 1000)


def test_qr_invalid_unicode_and_runs_are_bounded():
    assert ui._qr_svg("\ud800", description="Invalid") is None
    assert ui._qr_row((0, 1, 1, 0, 1), 2, 4) == "M5 6h2v1h-2zM8 6h1v1h-1z"
    assert ui._qr_row((0, 0), 0, 4) == ""


@pytest.mark.parametrize("ca_root", [None, b"PUBLIC-CA-ROOT"])
def test_onboarding_packages_retain_trust_platform_recipes_and_recovery(info, ca_root):
    source = ui.render_onboarding_package(
        info, generated_at=NOW, base_url="https://bus.lan",
        agent_name="atlas-worker", token="synthetic-token",
        expires_at=NOW + timedelta(minutes=3), enrollment_id=HOSTILE,
        ca_root=ca_root, ca_fingerprint="f" * 64,
    )
    for required in (
        "shown once", "Linux shell", "Windows PowerShell",
        "credential-response.json", "call orientation", "agent recover",
        "--expected-credential-epoch", "Never disable certificate",
        "X509Certificates.X509Certificate2", "sha256 Fingerprint=",
    ):
        assert required in source
    # Stock Windows has no openssl; under ErrorActionPreference Stop a missing
    # command would abort the recipe before the single-use token is redeemed.
    windows = html.unescape(source).split("Windows PowerShell (", 1)[1]
    assert "openssl" not in windows.split("\n\n3.", 1)[0]
    assert html.escape(HOSTILE) in source and "<script>" not in source
    if ca_root is None:
        assert "No CA root is published" in source
        assert 'href="/ca-root.crt"' not in source
    else:
        assert "UFVCTElDLUNBLVJPT1Q=" in source
        assert 'href="/ca-root.crt"' in source
        assert "must match CA SHA-256" in source
        assert "as ca-root.crt and prints" in source
        assert "Get ca-root.crt from your" not in source


@pytest.mark.parametrize("value", ["-1", " 5", "５", ""])
def test_page_limits_reject_non_ascii_or_noncanonical_integers(value):
    from strugglebus.errors import DomainValidationError

    with pytest.raises(DomainValidationError, match="ASCII integer"):
        ui.parse_dashboard_query([("limit", value)], configured_limit=100)


def test_overview_uses_real_lifecycle_counts_and_preserves_long_escaped_body(info):
    body = HOSTILE + "x" * 4096
    source = ui.render_overview(snapshot(message(body=body)), info, generated_at=NOW)
    assert html.escape(body) in source
    assert "not-exposed" not in source
    assert "private-id" not in source
    for label, count in (("Enabled agents", 3), ("Blocked agents", 2), ("Retired agents", 1)):
        assert f'{label}</span><span class="summary-value">{count}</span>' in source
    assert "Availability" not in source and "Sections</span>" not in source
    assert 'class="split"' in source and "Overview context" in source
    assert "does not mean the agent is online" in source
    assert 'href="/activity?channel=status#activity">' in source
    assert 'href="/activity?agent=atlas-worker#activity">' in source


@pytest.mark.parametrize(
    ("board_has_messages", "query", "expected"),
    [
        (False, ui.DashboardQuery(None, None, None, 5), "No messages yet"),
        (True, ui.DashboardQuery(None, None, 9, 5), "No older activity"),
        (True, ui.DashboardQuery("empty-channel", None, None, 5), "No matching activity"),
        (True, ui.DashboardQuery(None, "empty-agent", None, 5), "No matching activity"),
        (True, ui.DashboardQuery(None, None, None, 5), "No recent activity"),
    ],
)
def test_activity_empty_states_keep_limits_filters_and_cursor(info, board_has_messages, query, expected):
    source = ui.render_activity(
        snapshot(board_has_messages=board_has_messages), query, info,
        generated_at=NOW, configured_limit=5,
    )
    assert expected in source
    assert 'value="5" selected' in source
    assert 'value="10"' not in source
    assert "Older activity</a>" not in source
    assert "Apply filters" in source and "Auto-refresh every 2 minutes" in source
    assert re.search(r'id="message-\d+"', source) is None


def test_overview_empty_retained_board_is_not_an_initial_empty_board(info):
    source = ui.render_overview(snapshot(), info, generated_at=NOW)
    assert "There is no recent activity to show" in source
    assert "Messages appear here once agents start posting" not in source


def test_reply_without_retained_parent_and_bounded_parent_excerpt(info):
    orphan = message(seq=9, reply_to=8)
    source = ui.render_overview(snapshot(orphan), info, generated_at=NOW)
    assert "Direct reply" not in source
    parent = message(seq=8, body=HOSTILE + "x" * 500)
    source = ui.render_overview(snapshot(orphan, parents=(parent,)), info, generated_at=NOW)
    assert "Direct reply to message #8" in source
    assert html.escape(parent.body[:240].rstrip()) + "..." in source
    assert parent.body[-300:] not in source


@pytest.mark.parametrize("body", ["\ud800", "x" * 17000, '{"state":"running","state":"failed"}'])
def test_status_parser_rejects_oversized_unicode_and_duplicate_fields(body):
    assert ui._status_from_message(message(kind="status", body=body)) is None


@pytest.mark.parametrize("populated", [False, True])
def test_channel_directory_preserves_empty_and_long_details(info, populated):
    channel = DashboardChannelSummary(
        name="x" * 64, purpose=HOSTILE + "y" * 400,
        created_at=NOW, message_count=4, last_activity_at=NOW, active_subscriber_count=2,
    )
    page = DashboardChannelPage((channel,) if populated else (), has_more=populated)
    source = ui.render_channels(page, ui.CursorQuery(None, 1), info, generated_at=NOW)
    if populated:
        assert "Messages: <strong>4</strong>" in source
        assert "More about this channel" in source and "Created <time" in source
        assert '<a class="table-link" href="/activity?channel=' in source
        assert html.escape(channel.purpose[:240]) + "..." in source
        assert "Next page" in source
    else:
        assert "No channels exist yet" in source
        assert "Next page" not in source
    assert "<script>" not in source


@pytest.mark.parametrize("last_seen", [None, NOW])
def test_legacy_agent_renderer_retains_bounded_navigation(info, last_seen):
    agent = DashboardAgentSummary("x" * 128, NOW, last_seen)
    source = ui.render_agents(
        DashboardAgentPage((agent,), True), ui.CursorQuery(None, 1), info,
        generated_at=NOW,
    )
    assert agent.name in source and "Next page" in source
    assert ("Never" in source) == (last_seen is None)


@pytest.mark.parametrize("after", [None, "last-agent"])
def test_legacy_agent_renderer_empty_distinctions(info, after):
    source = ui.render_agents(
        DashboardAgentPage((), False), ui.CursorQuery(after, 5), info,
        generated_at=NOW,
    )
    expected = "No active agents are registered yet" if after is None else "the end of the agent list"
    assert expected in source
    assert "Next page" not in source


def test_admin_landing_keeps_tasks_recovery_and_complete_runtime_in_disclosures(info):
    source = ui.render_system(info, generated_at=NOW)
    for path in ("/register", "/devices", "/operator/session"):
        assert f'class="action-card" href="{path}"' in source
    assert "<h1>Administration</h1>" in source
    assert "<summary>What this console can and cannot do</summary>" in source
    assert "Versions</summary>" in source
    assert "Integration guide" in source and "Coordination protocol" in source
    assert "access-freeze command on the bus host" in source
    assert "Agents and bus messages can never change it" in source
    assert "<form" not in source


def test_error_document_is_minimal_escaped_and_not_a_success_snapshot():
    source = ui.render_dashboard_error(title=HOSTILE, detail=HOSTILE, active="channels")
    assert "<script>" not in source and html.escape(HOSTILE) in source
    assert 'role="alert"' in source
    assert "Page loaded" not in source
    assert "Enabled agents" not in source and "Console sections" not in source
    assert "could not be read" in source


def test_stylesheet_keeps_compact_actions_touch_login_focus_and_reflow_contracts():
    css = ui.DASHBOARD_STYLESHEET
    for color in ("#060b1e", "#101324", "#ffcead", "#af907f", "#7d82d9"):
        assert color in css
    assert "min-height: 36px" in css
    assert "@media (max-width: 860px), (pointer: coarse)" in css
    assert "button, .button { min-height: 44px; }" in css
    assert ".form-stack > button, .form-stack > .button { justify-self: start; }" in css
    assert '.login-wrap button[type="submit"] { width: 100%; min-height: 44px; }' in css
    assert ".login-wrap .button" not in css
    assert ".button.danger, button.danger, .button-danger" in css
    assert "background: transparent; color: var(--red); border-color: #8a3a44" in css
    assert ":focus-visible { outline: 3px solid var(--accent)" in css
    assert ".skip-link:focus" in css
    assert ".rail { display: none; }" in css
    assert ".mobile-top { display: block;" in css
    assert "overflow-wrap: anywhere" in css
    assert ".mobile-row-details { display: block;" in css
    for component in (".message-top", ".avatar", ".message-agent", ".message-bottom"):
        assert component in css
    assert ".workspace:not(:has(> .rail)) { display: block; }" in css
    assert "prefers-reduced-motion: reduce" in css
    assert not re.search(r"@import|url\s*\(|javascript|expression\s*\(", css, re.I)


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (timedelta(seconds=20), "just now"),
        (timedelta(minutes=5, seconds=30), "5 min ago"),
        (timedelta(hours=1, minutes=10), "1 hour ago"),
        (timedelta(hours=23), "23 hours ago"),
        (timedelta(days=3), "14 Sep, 11:00 UTC"),
        (timedelta(days=400), "13 Aug 2025, 11:00 UTC"),
        (timedelta(seconds=-30), "17 Sep, 11:00 UTC"),
    ],
)
def test_message_times_say_how_long_ago_and_keep_the_exact_time(info, age, expected):
    posted = replace(message(), created_at=NOW - age)
    source = ui.render_overview(snapshot(posted), info, generated_at=NOW)
    exact = (NOW - age).strftime("%d %b %Y, %H:%M UTC")
    assert f'title="{exact}">{expected}</time>' in source


def test_a_message_is_one_compact_row_led_by_its_author(info):
    source = ui.render_overview(
        snapshot(message(seq=7), message(seq=8, kind="question")), info, generated_at=NOW,
    )
    assert "Message #7" not in source
    assert '<span class="avatar" aria-hidden="true">AW</span>' in source
    assert '<a class="message-agent" href="/activity?agent=atlas-worker#activity">atlas-worker</a>' in source
    assert '<a href="#message-7" aria-label="Message 7">#7</a>' in source
    # Plain chat carries no label; any other kind is named.
    assert source.count('<span class="tag">') == 1
    assert '<span class="tag">Question</span>' in source
    assert "Reply</a>" not in source


@pytest.mark.parametrize(
    ("name", "expected"),
    [("atlas-worker", "AW"), ("human:operator", "HO"), ("solo", "S"), ("a-b-c", "AB"), ("-", "?")],
)
def test_initials_come_from_the_first_two_parts_of_a_name(name, expected):
    assert ui._initials(name) == expected


def test_humans_offers_a_reply_link_and_prefills_the_reply(info):
    asked = replace(message(seq=6, kind="question", body="May I delete " + HOSTILE), channel="humans")
    plain = ui.render_humans(
        snapshot(asked), info, generated_at=NOW, csrf_token="csrf", request_id="request",
    )
    assert '<a href="/humans?reply=6#compose-heading">Reply</a>' in plain
    assert "Replying to atlas-worker" not in plain
    assert 'autocomplete="off"></label>' in plain

    replying = ui.render_humans(
        snapshot(asked), info, generated_at=NOW, csrf_token="csrf", request_id="request",
        reply_to=6,
    )
    assert "<strong>Replying to atlas-worker:</strong> May I delete " in replying
    assert "<script>" not in replying
    assert 'autocomplete="off" value="6"></label>' in replying
    assert '<a href="/humans#compose-heading">Cancel reply</a>' in replying

    # A number that is not on the page is still filled in; the server checks it when posting.
    elsewhere = ui.render_humans(
        snapshot(asked), info, generated_at=NOW, csrf_token="csrf", request_id="request",
        reply_to=99,
    )
    assert 'value="99"' in elsewhere and "Replying to" not in elsewhere.replace("Replying to message number", "")


@pytest.mark.parametrize(
    ("typed", "accepted"),
    [
        ("adlab-cli-win", True), ("Build Agent", True), ("build_agent__2", True), (" a-b ", True),
        ("buildagent", False), ("build.agent", False), ("-build-agent", False), ("a-", False),
    ],
)
def test_the_name_box_refuses_what_the_server_would_refuse(info, typed, accepted):
    from strugglebus.errors import DomainValidationError
    from strugglebus.service import normalize_name

    try:
        normalize_name(typed, agent=True)
        server = True
    except DomainValidationError:
        server = False
    assert server is accepted
    assert (re.fullmatch(ui.AGENT_NAME_INPUT_PATTERN, typed) is not None) is accepted
    page = ui.render_register(info, generated_at=NOW, csrf_token="csrf")
    assert f'pattern="{ui.AGENT_NAME_INPUT_PATTERN}"' in page
    assert f'title="{ui.AGENT_NAME_HELP}"' in page
    assert "kebab" not in page


@pytest.mark.parametrize(
    ("typed", "accepted"),
    [
        ("owner-phone", True), ("Owner Phone", True), ("laptop", True), ("spare_pc_2", True),
        ("owner.phone", False), ("-phone", False), ("phone-", False), ("", False),
    ],
)
def test_the_device_label_box_refuses_what_the_server_would_refuse(info, typed, accepted):
    from strugglebus.errors import DomainValidationError
    from strugglebus.service import normalize_name

    try:
        normalize_name(typed)
        server = True
    except DomainValidationError:
        server = False
    assert server is accepted
    assert (re.fullmatch(ui.DEVICE_LABEL_INPUT_PATTERN, typed) is not None) is accepted
    page = ui.render_devices(info, (), generated_at=NOW, csrf_token="csrf", enrollment_seconds=180)
    assert f'pattern="{ui.DEVICE_LABEL_INPUT_PATTERN}"' in page
    assert f'title="{ui.DEVICE_LABEL_HELP}"' in page
    assert "can act as the operator only after you save operator access" in page
