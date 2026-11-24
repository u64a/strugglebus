"""Renderer contract coverage independent of credential and lifecycle authority."""

from dataclasses import replace
from datetime import timedelta, UTC, datetime
from html import escape
from html.parser import HTMLParser

import pytest

from strugglebus import operator_lifecycle_rendering as ui
from strugglebus.console_context import console_access_context
from strugglebus.errors import (
    AgentAccessFrozenError, AgentNotFoundError, ConfigurationError,
    CredentialConflictError, CredentialLimitError, DomainValidationError,
    StorageError, TrustAnchorError,
)
from strugglebus.models import Agent, AgentLifecycleEvent, AgentLifecycleResult
from strugglebus.operator_auth import OperatorContext
from strugglebus.operator_web import _failure

WHEN = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
UNTRUSTED = '<script>alert("unsafe")</script>&'


class Elements(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.items = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.items.append((tag, dict(attrs)))

    def tags(self, tag):
        return [attrs for name, attrs in self.items if name == tag]


@pytest.fixture
def agent():
    return Agent(
        id=UNTRUSTED, name=UNTRUSTED, description=UNTRUSTED, host=UNTRUSTED,
        created_at=WHEN, last_seen_at=WHEN, revoked_at=None, credential_epoch=7,
    )


@pytest.fixture
def event():
    return AgentLifecycleEvent(
        seq=41, id=UNTRUSTED, request_id=UNTRUSTED, intent_sha256=UNTRUSTED,
        agent_id=UNTRUSTED, action=UNTRUSTED, previous_state=UNTRUSTED,
        resulting_state=UNTRUSTED, previous_epoch=7, resulting_epoch=8,
        actor_type=UNTRUSTED, actor_id=UNTRUSTED, occurred_at=WHEN,
        reason=UNTRUSTED, grant_id=UNTRUSTED,
    )


def test_components_escape_all_plaintext_and_keep_trusted_markup():
    markup = ui.panel(
        UNTRUSTED, "<p>Trusted body</p>", description=UNTRUSTED, heading_id=UNTRUSTED,
    )
    markup += ui.disclosure(UNTRUSTED, ui.facts({UNTRUSTED: UNTRUSTED}))
    markup += ui.hidden(UNTRUSTED, UNTRUSTED)
    assert "<script>" not in markup
    assert escape(UNTRUSTED) in markup
    assert "<p>Trusted body</p>" in markup
    assert Elements(markup).tags("section")[0]["aria-labelledby"] == UNTRUSTED
    assert Elements(markup).tags("h2")[0]["id"] == UNTRUSTED
    assert Elements(markup).tags("input") == [
        {"type": "hidden", "name": UNTRUSTED, "value": UNTRUSTED},
    ]
    assert ui.lifecycle_badge(UNTRUSTED) == f'<span class="pill ">{escape(UNTRUSTED.title())}</span>'
    assert ui.timestamp(None) == "Never"
    assert ui.timestamp(WHEN) == WHEN.strftime("%d %b %Y, %H:%M:%S UTC")


@pytest.mark.parametrize("state", ["unobserved", "available", "frozen", "unavailable"])
@pytest.mark.parametrize("action", ["block", "unblock", "retire", "reconnect"])
def test_confirmation_discloses_exact_identity_consequence_and_local_denial(agent, state, action):
    token = console_access_context.set(state)
    try:
        markup = ui.confirmation(agent, action, UNTRUSTED, UNTRUSTED)
        link = ui._identity_action(agent, action)
    finally:
        console_access_context.reset(token)
    elements = Elements(markup)
    assert len(elements.tags("form")) == 1
    assert elements.tags("form")[0]["method"] == "post"
    assert all(item.get("type") != "password" for item in elements.tags("input"))
    assert escape(ui.ACTION_WARNINGS[action]) in markup
    assert "Agent ID" in markup and "Key generation" in markup
    assert "Request ID" in markup and "the bus checks again" in markup
    values = {item["name"]: item.get("value") for item in elements.tags("input")}
    assert values["csrf"] == UNTRUSTED and values["request_id"] == UNTRUSTED
    assert values["action"] == action and values["epoch"] == "7"
    assert values["confirm"] == action
    if action == "retire":
        assert values["name"] is None
        assert "Type the exact name" in markup
    else:
        assert values["name"] == UNTRUSTED
    denied = state in {"frozen", "unavailable"} and action in {"unblock", "reconnect"}
    assert ("disabled" in elements.tags("button")[0]) == denied
    if denied:
        assert "Creating or restoring access is paused." in markup
        assert "disabled" in Elements(link).tags("button")[0]
        assert not Elements(link).tags("a")
    else:
        assert len(Elements(link).tags("a")) == 1
    assert "<script>" not in markup + link


@pytest.mark.parametrize("state,actions", [
    ("enabled", ("block", "retire", "reconnect")),
    ("blocked", ("unblock", "retire")),
    ("retired", ()),
])
def test_identity_preserves_states_fields_and_history_without_credential_claim(agent, state, actions):
    agent = replace(
        agent, blocked_at=WHEN if state == "blocked" else None,
        revoked_at=WHEN if state == "retired" else None,
    )
    assert ui.available_actions(agent) == actions
    markup = ui.identity(agent, (), 2)
    assert "<script>" not in markup
    assert "Technical details" in markup and "Nothing on this page." in markup
    for label in ("Host", "Last seen", "Joined", "Blocked", "Retired", "Description"):
        assert f"<dt>{label}</dt>" in markup
    for action in actions:
        assert f"action={action}" in markup
    if state == "retired":
        assert "can never be used again" in markup
        assert "/control?" not in markup
    else:
        assert "asks you to confirm on the next page" in markup
    empty = ui._identity_facts(replace(agent, description="", host="", last_seen_at=None))
    assert "No description." in empty and "Not recorded" in empty and "Never" in empty


def test_roster_pagination_and_mobile_disclosures_preserve_every_secondary_field(agent):
    markup = ui.roster((agent,), state="enabled", after=UNTRUSTED, limit=1, maximum=20)
    assert "<script>" not in markup
    assert 'aria-labelledby="agents-heading"' in markup
    assert '<h2 id="agents-heading">Agents on this bus</h2>' in markup
    assert "Next agents" in markup
    assert 'value="enabled" selected' in markup
    assert 'name="limit" type="number" min="1" max="20" value="1"' in markup
    fields = Elements(markup).tags("input")
    assert fields[0] == {"type": "hidden", "name": "after", "value": UNTRUSTED}
    mobile = markup.split('<details class="mobile-row-details">', 1)[1].split("</details>", 1)[0]
    for label in ("Last seen", "Joined"):
        assert f"<dt>{label}</dt>" in mobile
    assert "its key still works" in markup
    empty = ui.roster((), state="managed", after="", limit=2, maximum=20)
    assert "No agents to show." in empty and "Next agents" not in empty
    assert 'name="after"' not in empty


def test_history_preserves_complete_audit_and_mobile_secondary_data(event):
    markup = ui.history(UNTRUSTED, (event,), 1)
    assert "Next history" in markup and "?after=41&amp;limit=1" in markup
    assert "<script>" not in markup
    for label in (
        "Sequence", "Event ID", "Agent ID", "Request ID", "Intent SHA-256",
        "Done by (type)", "Done by", "Key generation", "Grant ID",
    ):
        assert f"<dt>{label}</dt>" in markup
    assert "7 to 8" in markup
    mobile = markup.split('<details class="mobile-row-details">', 1)[1].split("</details>", 1)[0]
    for label in ("When", "Reason", "Done by"):
        assert f"<dt>{label}</dt>" in mobile
    assert escape(UNTRUSTED) in mobile
    assert "<dd>None</dd>" in ui.event_details(replace(event, grant_id=None))
    empty = ui.history("identity", (), 1)
    assert "Nothing on this page." in empty and "Next history" not in empty


@pytest.mark.parametrize("changed,label", [(True, "Applied"), (False, "Already recorded")])
def test_lifecycle_result_is_exact_escaped_record_not_an_inferred_new_action(event, changed, label):
    markup = ui.lifecycle_result(AgentLifecycleResult(event, changed))
    assert label in markup and "Request ID" in markup and "Key generation after" in markup
    assert "Reloading this page does not repeat the action" in markup
    assert "<script>" not in markup
    assert not Elements(markup).tags("form")


def test_login_and_session_never_disclose_session_tokens():
    markup = ui.login_form(UNTRUSTED)
    elements = Elements(markup)
    assert elements.tags("form")[0]["action"] == "/login"
    password = next(item for item in elements.tags("input") if item["name"] == "password")
    assert password == {
        "id": "password", "name": "password", "type": "password", "required": None,
        "autocomplete": "current-password", "maxlength": "1024",
    }
    assert "An agent key or a device code will not work here." in markup
    context = OperatorContext(UNTRUSTED, 123456.7, "private-session-id", UNTRUSTED)
    page = ui.session(context, lifetime=3600, idle=600)
    assert "1 hour" in page and "10 minutes" in page
    assert "private-session-id" not in page and "123456.7" not in page
    assert "<script>" not in markup + page
    assert Elements(page).tags("form")[0]["action"] == "/logout"
    assert Elements(page).tags("form")[0]["method"] == "post"


@pytest.mark.parametrize("error,code", [
    (CredentialConflictError, 409), (CredentialLimitError, 409),
    (AgentNotFoundError, 404), (ConfigurationError, 422),
    (DomainValidationError, 422), (StorageError, 503),
    (TrustAnchorError, 503), (AgentAccessFrozenError, 503),
])
def test_operator_failures_are_explicit_and_never_leak_exception_details(error, code):
    response = _failure(error(UNTRUSTED))
    assert response.status_code == code
    text = response.body.decode()
    assert UNTRUSTED not in text and escape(UNTRUSTED) not in text
    assert 'role="alert"' in text
    assert "it may still have gone through" in text
    assert "No agents to show" not in text


def test_unexpected_operator_failures_are_not_hidden():
    with pytest.raises(RuntimeError, match="synthetic"):
        _failure(RuntimeError("synthetic"))


def test_times_are_written_for_people(agent):
    now = WHEN + timedelta(hours=30)
    assert ui.day(None) == "Never" and ui.day(WHEN) == WHEN.strftime("%d %b %Y")
    assert ui.ago(None, now) == "Never"
    assert ui.ago(now - timedelta(seconds=10), now) == "Just now"
    assert ui.ago(now - timedelta(minutes=7), now) == "7 min ago"
    assert ui.ago(now - timedelta(hours=1), now) == "1 hour ago"
    assert ui.ago(now - timedelta(hours=5), now) == "5 hours ago"
    assert ui.ago(WHEN, now) == ui.day(WHEN)
    assert ui.ago(now + timedelta(minutes=5), now) == ui.day(now + timedelta(minutes=5))
    assert [ui.duration(value) for value in (28800, 3600, 1800, 60, 90, 1)] == [
        "8 hours", "1 hour", "30 minutes", "1 minute", "90 seconds", "1 second",
    ]


def test_the_agent_list_shows_when_each_was_seen_and_how_to_manage_it(agent):
    seen = replace(agent, last_seen_at=WHEN - timedelta(minutes=3), description="Builds things")
    markup = ui.roster((seen,), state="managed", after="", limit=5, maximum=20, now=WHEN)
    # The list keeps to bounded fields: a description is only on the agent's own page.
    assert "3 min ago" in markup and "Builds things" not in markup
    assert f'<a class="table-link" href="/agents/{escape(seen.id, quote=True)}">Manage</a>' in markup
    assert "Stable identity" not in markup and "Credential epoch" not in markup
    assert "Choose Manage to block, unblock, reconnect or retire an agent." in markup
    assert "Never" in ui.roster((replace(agent, last_seen_at=None),), state="managed", after="", limit=5, maximum=20)
