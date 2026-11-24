"""Escaped, disclosure-only rendering for operator identity and session tasks."""

from collections.abc import Mapping
from datetime import UTC, datetime
from html import escape
from urllib.parse import urlencode

from strugglebus.console_context import console_access_context
from strugglebus.models import Agent, AgentLifecycleEvent, AgentLifecycleResult
from strugglebus.operator_auth import OperatorContext

ACTIONS = {
    "block": "Block", "unblock": "Unblock", "retire": "Retire permanently",
    "reconnect": "Issue reconnect package",
}
ACTION_WARNINGS = {
    "block": (
        "Block can be undone. It stops this agent using the bus without deleting its "
        "history, its keys or its place in each channel."
    ),
    "unblock": (
        "Unblock lets this agent back on the bus. Keys that were revoked or have "
        "expired stay unusable."
    ),
    "retire": (
        "Retiring is permanent. Every working key is cancelled. The agent's history "
        "stays, and its name can never be used again."
    ),
    "reconnect": (
        "Making this package IMMEDIATELY cancels every key this agent has. The package "
        "works once and expires quickly. If its result is lost you must make another; "
        "the old keys do not come back. Have the agent, and a private place for the "
        "package, ready first."
    ),
}


def panel(title: str, body: str, *, description: str = "", heading_id: str = "") -> str:
    label = f' aria-labelledby="{escape(heading_id, quote=True)}"' if heading_id else ""
    identifier = f' id="{escape(heading_id, quote=True)}"' if heading_id else ""
    return (
        f'<section class="panel"{label}><div class="panel-header"><div>'
        f"<h2{identifier}>{escape(title)}</h2><p>{escape(description)}</p></div></div>"
        f'<div class="panel-body">{body}</div></section>'
    )


def facts(values: Mapping[str, object]) -> str:
    return "<dl>" + "".join(
        f"<dt>{escape(label)}</dt><dd>{escape(str(value))}</dd>"
        for label, value in values.items()
    ) + "</dl>"


def disclosure(title: str, body: str, *, mobile: bool = False) -> str:
    style = "mobile-row-details" if mobile else "section-gap"
    return (
        f'<details class="{style}"><summary>{escape(title)}</summary>'
        f'<div class="details-box">{body}</div></details>'
    )


def hidden(name: str, value: str) -> str:
    return (
        f'<input type="hidden" name="{escape(name, quote=True)}" '
        f'value="{escape(value, quote=True)}">'
    )


def timestamp(value: datetime | None) -> str:
    """An exact time in words a person can read, in UTC, to the second."""

    if value is None:
        return "Never"
    return value.astimezone(UTC).strftime("%d %b %Y, %H:%M:%S UTC")


def day(value: datetime | None) -> str:
    return "Never" if value is None else value.astimezone(UTC).strftime("%d %b %Y")


def ago(value: datetime | None, now: datetime) -> str:
    """How long ago an agent was last heard from. Dates are enough beyond a day."""

    if value is None:
        return "Never"
    seconds = (now - value).total_seconds()
    if seconds < 0 or seconds >= 86400:
        return day(value)
    if seconds < 60:
        return "Just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    hours = int(seconds // 3600)
    return f"{hours} hour{'' if hours == 1 else 's'} ago"


def duration(seconds: int) -> str:
    """A length of time in the largest unit that divides it evenly."""

    for size, unit in ((3600, "hour"), (60, "minute")):
        if seconds >= size and seconds % size == 0:
            count = seconds // size
            return f"{count} {unit}{'' if count == 1 else 's'}"
    return f"{seconds} second{'' if seconds == 1 else 's'}"


def lifecycle_badge(state: str) -> str:
    style = {"enabled": "good", "blocked": "warning", "retired": "danger"}.get(state, "")
    return f'<span class="pill {style}">{escape(state.title())}</span>'


def access_denial(action: str) -> str:
    if action not in {"unblock", "reconnect"}:
        return ""
    state = console_access_context.get()
    if state == "frozen":
        return "Agent access is frozen. Creating or restoring access is paused."
    if state == "unavailable":
        return "Current access state is unavailable. Creating or restoring access is paused."
    return ""


def available_actions(agent: Agent) -> tuple[str, ...]:
    return {
        "enabled": ("block", "retire", "reconnect"),
        "blocked": ("unblock", "retire"),
    }.get(agent.state, ())


def _roster_filters(state: str, after: str, limit: int, maximum: int) -> str:
    options = "".join(
        f'<option value="{value}"' + (" selected" if value == state else "")
        + f">{label}</option>"
        for value, label in (
            ("managed", "Enabled and blocked"), ("enabled", "Enabled"),
            ("blocked", "Blocked"), ("retired", "Retired"),
        )
    )
    return (
        '<form method="get" action="/agents" class="filters">'
        f'<label>Show<select name="state">{options}</select></label>'
        + (hidden("after", after) if after else "")
        + f'<label>Agents per page<input name="limit" type="number" min="1" max="{maximum}" '
        f'value="{limit}" required></label><button type="submit">Apply filters</button>'
        '<a class="button secondary" href="/agents">Reset</a></form>'
        + (f'<p class="helper">Showing names after {escape(after)}.</p>' if after else "")
    )


def _roster_row(agent: Agent, now: datetime) -> str:
    link = f"/agents/{escape(agent.id, quote=True)}"
    secondary = {
        "Last seen": ago(agent.last_seen_at, now), "Joined": day(agent.created_at),
    }
    return (
        f'<tr><td><a class="cell-title" href="{link}">{escape(agent.name)}</a>'
        + disclosure("More about this agent", facts(secondary), mobile=True)
        + f"</td><td>{lifecycle_badge(agent.state)}</td>"
        + "".join(
            f'<td class="secondary-column">{escape(str(value))}</td>'
            for value in secondary.values()
        )
        + f'<td><a class="table-link" href="{link}">Manage</a></td></tr>'
    )


def roster(
    agents: tuple[Agent, ...], *, state: str, after: str, limit: int, maximum: int,
    now: datetime | None = None,
) -> str:
    now = datetime.now(UTC) if now is None else now
    body = (
        '<p class="lede">Enabled means an agent is allowed on the bus. It does not prove '
        "the agent is running or that its key still works.</p>"
        + _roster_filters(state, after, limit, maximum)
        + '<div class="table-wrap"><table><thead><tr><th scope="col">Name</th>'
        '<th scope="col">State</th>'
        '<th class="secondary-column" scope="col">Last seen</th>'
        '<th class="secondary-column" scope="col">Joined</th>'
        '<th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead><tbody>'
        + "".join(_roster_row(agent, now) for agent in agents) + "</tbody></table></div>"
    )
    if not agents:
        body += (
            '<div class="empty-state"><h3>No agents to show.</h3>'
            "<p>Try a different filter, or go back to the first page.</p></div>"
        )
    if len(agents) == limit:
        cursor = urlencode({"state": state, "after": agents[-1].name, "limit": limit})
        body += (
            '<div class="actions section-gap"><a class="button secondary" '
            f'href="/agents?{escape(cursor, quote=True)}">Next agents</a></div>'
        )
    return panel(
        "Agents on this bus", body,
        description="Choose Manage to block, unblock, reconnect or retire an agent.",
        heading_id="agents-heading",
    )


def _identity_facts(agent: Agent) -> str:
    return (
        facts({
            "Name": agent.name, "Description": agent.description or "No description.",
            "Host": agent.host or "Not recorded", "Joined": timestamp(agent.created_at),
            "Last seen": timestamp(agent.last_seen_at), "Blocked": timestamp(agent.blocked_at),
            "Retired": timestamp(agent.revoked_at),
        })
        + disclosure("Technical details", facts({
            "Agent ID": agent.id, "Key generation": agent.credential_epoch,
        }))
    )


def _identity_action(agent: Agent, action: str) -> str:
    denial = access_denial(action)
    style = "secondary" if action == "unblock" else "danger"
    if denial:
        return (
            f'<div><p class="warning-box">{escape(denial)}</p>'
            f'<button type="button" class="{style}" disabled>{ACTIONS[action]}</button></div>'
        )
    return (
        f'<a class="button {style}" href="/agents/{escape(agent.id, quote=True)}'
        f'/control?action={action}">{ACTIONS[action]}</a>'
    )


def _identity_controls(agent: Agent) -> str:
    if agent.state == "retired":
        return (
            '<p class="warning-box danger">This agent is retired. That cannot be undone, '
            "and its name can never be used again.</p>"
        )
    return (
        '<p>Each of these asks you to confirm on the next page.</p><div class="actions">'
        + "".join(_identity_action(agent, action) for action in available_actions(agent))
        + '</div><p class="helper section-gap">Block stops the agent and can be undone. '
        "Unblock lets it back in, but does not revive keys that were revoked or have expired. "
        "Reconnect gives the agent a new key and cancels its old ones at once. "
        "Retire is permanent.</p>"
    )


def event_details(event: AgentLifecycleEvent) -> str:
    return facts({
        "Sequence": event.seq, "Event ID": event.id, "Agent ID": event.agent_id,
        "Request ID": event.request_id, "Intent SHA-256": event.intent_sha256,
        "Done by (type)": event.actor_type, "Done by": event.actor_id,
        "Key generation": f"{event.previous_epoch} to {event.resulting_epoch}",
        "Grant ID": event.grant_id or "None",
    })


def _history_row(event: AgentLifecycleEvent) -> str:
    secondary = facts({
        "When": timestamp(event.occurred_at), "Reason": event.reason,
        "Done by": event.actor_id,
    })
    return (
        f"<tr><td><strong>{escape(event.action)}</strong>"
        f'<span class="cell-sub">Sequence {event.seq}</span>'
        + disclosure("Audit details", event_details(event))
        + disclosure("More about this event", secondary, mobile=True)
        + f"</td><td>{escape(event.previous_state)} to {escape(event.resulting_state)}</td>"
        f'<td class="secondary-column">{escape(timestamp(event.occurred_at))}</td>'
        f'<td class="secondary-column">{escape(event.actor_id)}</td>'
        f'<td class="secondary-column">{escape(event.reason)}</td></tr>'
    )


def history(agent_id: str, events: tuple[AgentLifecycleEvent, ...], limit: int) -> str:
    body = (
        '<div class="table-wrap"><table><thead><tr><th scope="col">What happened</th>'
        '<th scope="col">State</th><th class="secondary-column" scope="col">When</th>'
        '<th class="secondary-column" scope="col">Done by</th>'
        '<th class="secondary-column" scope="col">Reason</th></tr></thead><tbody>'
        + "".join(_history_row(event) for event in events) + "</tbody></table></div>"
    )
    if not events:
        body += (
            '<div class="empty-state"><h3>Nothing on this page.</h3>'
            "<p>There may be events on other pages.</p></div>"
        )
    if len(events) == limit:
        body += (
            f'<a class="button secondary section-gap" href="/agents/{escape(agent_id, quote=True)}'
            f'?after={events[-1].seq}&amp;limit={limit}">Next history</a>'
        )
    return panel(
        "History", body,
        description="Oldest first. Open Audit details to see who did it and the request ID.",
    )


def identity(agent: Agent, events: tuple[AgentLifecycleEvent, ...], limit: int) -> str:
    query = escape(urlencode({"agent": agent.name}), quote=True)
    return (
        '<div class="actions section-gap">'
        f'<a class="button secondary" href="/activity?{query}">This agent\'s messages</a>'
        '</div><div class="cards section-gap">'
        + panel("About this agent", lifecycle_badge(agent.state) + '<div class="section-gap">'
                + _identity_facts(agent) + "</div>")
        + panel("Change its access", _identity_controls(agent)) + "</div>"
        '<div class="section-gap">' + history(agent.id, events, limit) + "</div>"
    )


def confirmation(agent: Agent, action: str, csrf: str, request_id: str) -> str:
    denial = access_denial(action)
    warning = f'<p class="warning-box danger">{escape(ACTION_WARNINGS[action])}</p>'
    if denial:
        warning += f'<p class="warning-box" role="status">{escape(denial)}</p>'
    intent = {
        "csrf": csrf, "action": action, "epoch": str(agent.credential_epoch),
        "request_id": request_id,
    }
    name = hidden("name", agent.name)
    if action == "retire":
        name = (
            f"<p>Type the exact name <strong>{escape(agent.name)}</strong>.</p>"
            '<label>Name <input name="name" required maxlength="128" autocomplete="off"></label>'
        )
    style = "secondary" if action == "unblock" else "danger"
    form = (
        f'<form method="post" action="/agents/{escape(agent.id, quote=True)}/control" class="form-stack section-gap">'
        + "".join(hidden(key, value) for key, value in intent.items()) + name
        + '<label>Reason (no secrets) <textarea name="reason" rows="3" required maxlength="256"></textarea></label>'
        f'<label class="check-line"><input type="checkbox" name="confirm" value="{action}" required> '
        "I confirm this action for the agent shown above.</label>"
        f'<div class="actions"><button type="submit" class="{style}"'
        + (" disabled" if denial else "") + f">{ACTIONS[action]}</button>"
        f'<a class="button secondary" href="/agents/{escape(agent.id, quote=True)}">Cancel</a></div></form>'
    )
    body = warning + facts({
        "Agent": agent.name, "State now": agent.state.title(),
        "Agent ID": agent.id, "Key generation": agent.credential_epoch,
        "Request ID": request_id,
    }) + (
        '<p class="helper section-gap">When you submit, the bus checks again that this is '
        "still the same agent and that nothing has changed.</p>"
    ) + form
    return '<div class="compact">' + panel("Confirm this change", body) + "</div>"


def lifecycle_result(result: AgentLifecycleResult) -> str:
    event = result.event
    body = (
        f'<p role="status">{"Applied" if result.changed else "Already recorded"}: '
        f"{escape(event.action)}. Resulting state: {escape(event.resulting_state)}.</p>"
        + facts({
            "Request ID": event.request_id, "State before": event.previous_state,
            "Key generation before": event.previous_epoch,
            "Key generation after": event.resulting_epoch,
            "Done by": event.actor_id, "When": timestamp(event.occurred_at),
            "Reason": event.reason,
        })
        + disclosure("Full audit record", event_details(event))
        + '<p class="helper section-gap">Reloading this page does not repeat the action.</p>'
        '<a class="button secondary" '
        f'href="/agents/{escape(event.agent_id, quote=True)}">Back to this agent</a>'
    )
    return panel("What was recorded", body)


def login_form(csrf: str) -> str:
    return (
        '<p class="lede">Sign in to see what your agents are doing and to manage this bus.</p>'
        '<form method="post" action="/login" class="form-stack section-gap">'
        + hidden("csrf", csrf)
        + '<label for="password">Operator password'
        '<input id="password" name="password" type="password" required '
        'autocomplete="current-password" maxlength="1024"></label>'
        '<button type="submit">Sign in</button></form>'
        '<p class="helper section-gap">Use the operator password you set when the bus was '
        'installed. An agent key or a device code will not work here.</p>'
    )


def setup_form(*, ca_published: bool = False) -> str:
    certificate = (
        '<p class="helper section-gap">Browser warning about the certificate? '
        '<a href="/ca-root.crt">Download this bus\'s certificate root</a>, check its '
        "SHA-256 fingerprint against the one shown at the end of the install, then "
        "trust it on this PC. The install guide has the commands.</p>"
    ) if ca_published else ""
    return (
        '<p class="lede">This bus has no operator password yet. Set one to open the console.</p>'
        '<form method="post" action="/setup" class="form-stack section-gap">'
        '<label for="code">Setup code'
        '<input id="code" name="code" required autocomplete="off" maxlength="64"></label>'
        '<label for="password">New operator password'
        '<input id="password" name="password" type="password" required minlength="15" '
        'autocomplete="new-password" maxlength="1024"></label>'
        '<label for="confirmation">Confirm password'
        '<input id="confirmation" name="confirmation" type="password" required minlength="15" '
        'autocomplete="new-password" maxlength="1024"></label>'
        '<button type="submit">Set password</button></form>'
        '<p class="helper section-gap">The setup code was shown at the end of the install. '
        'On the guest it is in <code>/var/lib/strugglebus/operator/setup-code</code> '
        '(root only). It works once and expires 24 hours after the service starts. '
        'Use at least 15 characters.</p>' + certificate
    )


def setup_failed() -> str:
    return (
        '<div class="notice" role="alert"><div>The password was not set. Check the setup '
        'code and that both passwords match.</div></div>'
        '<a class="button secondary" href="/setup">Try again</a>'
        '<p class="helper section-gap">If the code has expired or was already used, restart '
        'the service on the guest (<code>systemctl restart strugglebus</code>) for a new one.</p>'
    )


def session(context: OperatorContext, *, lifetime: int, idle: int) -> str:
    body = (
        '<p>You signed in with the operator password.</p>'
        f'<p>You appear as: <code id="operator-identity">{escape(context.actor_id)}</code></p>'
        + facts({
            "Signed out after": duration(lifetime),
            "Or sooner, if idle for": duration(idle),
        })
        + '<p class="section-gap">You are signed out after the first time above whatever you '
        'are doing, and sooner if you leave the console idle. Your sign-in is checked again '
        'for every action.</p>'
        '<p>Agent keys and device codes cannot sign in to this console.</p>'
        '<form method="post" action="/logout" class="form-stack">'
        + hidden("csrf", context.csrf_token)
        + '<button class="secondary" type="submit">Sign out</button></form>'
        '<p class="helper section-gap">Signing out only ends this browser session. '
        "It changes nothing for agents.</p>"
    )
    return '<div class="compact">' + panel("Your session", body) + "</div>"
