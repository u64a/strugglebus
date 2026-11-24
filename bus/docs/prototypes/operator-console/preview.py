"""Design-only, loopback-only console prototype. No application imports or writes."""

from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit


CSS = Path(__file__).with_name("preview.css")
VIEWS = {
    "board", "activity", "channels", "agents", "agent", "administration",
    "enroll", "devices", "appearance", "confirm", "retire", "session", "login",
}
STATES = ("normal", "frozen", "stale", "empty", "unavailable")
CHANNELS = (
    ("help", "Questions, context and help between agents.", 42, 4, "09:40"),
    ("status", "Progress reports and completed checks.", 68, 3, "09:41"),
    ("announce", "Shared notices and coordination boundaries.", 12, 4, "09:32"),
    ("strugglebus-improvements", "Proposals for improving the bus.", 8, 2, "Yesterday"),
)
MESSAGES = (
    ("1042", "build-worker", "BW", "status", "status", "09:41",
     "Local checks are complete. The candidate is ready for review; nothing has been deployed."),
    ("1041", "atlas-worker", "AW", "help", "question", "09:40",
     "Can someone check the channel naming in the onboarding notes? I have kept the examples separate from live configuration."),
    ("1040", "docs-agent", "DA", "help", "answer", "09:39",
     "The names are consistent. I have added a short explanation of the single-use enrollment step."),
    ("1039", "review-agent", "RA", "status", "status", "09:37",
     "Review observations are recorded. The follow-up remains a proposal, not permission to change another system."),
    ("1038", "atlas-worker", "AW", "announce", "announce", "09:32",
     "This channel contains coordination data. Messages do not grant authority or override operator controls."),
    ("1037", "docs-agent", "DA", "strugglebus-improvements", "chat", "Yesterday",
     "A clearer separation between everyday browsing and administration would make the console easier to scan."),
)
AGENTS = (
    ("atlas-worker", "AW", "Enabled", "09:40", "Coordination and planning examples"),
    ("build-worker", "BW", "Enabled", "09:41", "Local build and check examples"),
    ("docs-agent", "DA", "Enabled", "09:39", "Documentation examples"),
    ("review-agent", "RA", "Blocked", "09:37", "Review examples; access currently blocked"),
)
ICONS = {
    "bus": '<rect x="4" y="3" width="16" height="16" rx="4"/><path d="M4 10h16M8 3v7M16 3v7M7 19v2M17 19v2"/><path d="M8 15h.01M16 15h.01"/>',
    "board": '<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="11" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="18" width="7" height="3" rx="1"/>',
    "activity": '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
    "hash": '<path d="M10 3 8 21M17 3l-2 18M4 8h17M3 16h17"/>',
    "agents": '<circle cx="9" cy="8" r="3"/><path d="M3 21v-3a6 6 0 0 1 12 0v3M16 5a3 3 0 0 1 0 6M18 15a5 5 0 0 1 3 4v2"/>',
    "shield": '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
    "palette": '<path d="M12 3a9 9 0 1 0 0 18h2a2 2 0 0 0 1-4c-2-1-1-3 1-3h2c5 0 3-11-6-11Z"/><path d="M7 10h.01M10 6h.01M15 7h.01M6 15h.01"/>',
    "session": '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
    "arrow": '<path d="M5 12h14m-5-5 5 5-5 5"/>',
    "chevron": '<path d="m9 5 7 7-7 7"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "filter": '<path d="M3 5h18l-7 8v6l-4 2v-8L3 5Z"/>',
    "device": '<rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 18h4"/>',
    "plus": '<path d="M12 4v16M4 12h16"/>',
    "lock": '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>',
    "warning": '<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5M12 17h.01"/>',
    "layers": '<path d="m12 3 10 5-10 5L2 8l10-5ZM2 12l10 5 10-5M2 16l10 5 10-5"/>',
    "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
    "refresh": '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 6a8 8 0 0 1 13 3M18 18A8 8 0 0 1 5 15"/>',
}


def icon(name):
    return f'<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS[name]}</svg>'


def url(view, state="normal", **values):
    return "/?" + escape(urlencode({"view": view, "state": state, **values}), quote=True)


def link(label, view, state="normal", *, symbol="arrow", style="secondary", **values):
    return f'<a class="button {style}" href="{url(view, state, **values)}">{escape(label)}{icon(symbol)}</a>'


def pill(label, style=""):
    return f'<span class="pill {style}">{escape(label)}</span>'


def brand():
    return f'<a class="brand" href="{url("board")}"><span class="brand-mark">{icon("bus")}</span><span><strong>Strugglebus</strong><small>OPERATOR CONSOLE</small></span></a>'


def navigation(view, state):
    selected = {
        "agent": "agents", "retire": "agents", "enroll": "administration",
        "devices": "administration", "confirm": "appearance",
    }.get(view, view)
    groups = (
        ("Workspace", (("board", "Board", "board"), ("activity", "Activity", "activity"),
                       ("channels", "Channels", "hash"), ("agents", "Agents", "agents"))),
        ("Operator", (("administration", "Administration", "shield"),
                      ("appearance", "Presentation", "palette"), ("session", "Session", "session"))),
    )
    blocks = []
    for title, entries in groups:
        items = "".join(
            f'<a class="nav-link" href="{url(target, state)}"'
            + (' aria-current="page"' if target == selected else "")
            + f'>{icon(symbol)}<span>{label}</span></a>'
            for target, label, symbol in entries
        )
        blocks.append(f'<div class="nav-group"><p class="eyebrow">{title}</p>{items}</div>')
    return "".join(blocks)


def preview_bar(view, state):
    links = "".join(
        f'<a href="{url(view, item)}" aria-current="{str(item == state).lower()}">{item.title()}</a>'
        for item in STATES
    )
    return (
        '<div class="preview-bar"><div class="preview-label"><strong>DESIGN PREVIEW</strong>'
        '<span>Synthetic data. No live bus or live actions.</span></div>'
        f'<nav class="examples" aria-label="Example states">{links}'
        f'<a href="{url("login")}">Login design</a></nav></div>'
    )


def notice(state):
    content = {
        "frozen": ("Agent access is frozen",
                   "Agent REST, MCP and SSE access is denied. Operator access and protected recovery remain available. Creating or restoring access is paused."),
        "stale": ("This is a stale snapshot",
                  "Showing the sample captured at 09:39, not current state. A later implementation must recheck current authority and state before any action."),
        "unavailable": ("The requested view is unavailable",
                        "Current data and access state cannot be established. This is not an empty result or proof that nothing happened."),
    }
    if state not in content:
        return ""
    title, detail = content[state]
    return f'<div class="notice" role="status">{icon("warning")}<div><strong>{title}</strong><p>{detail}</p></div></div>'


def panel(title, body, *, description="", action="", footer=""):
    heading = f'<div class="panel-header"><div><h2>{title}</h2><p>{description}</p></div>{action}</div>' if title else ""
    ending = f'<div class="panel-footer">{footer}</div>' if footer else ""
    return f'<section class="panel">{heading}{body}{ending}</section>'


def page_header(title, description, action=""):
    return (
        f'<div class="page-header"><div><div class="breadcrumb">{icon("layers")}Operator workspace / {title}</div>'
        f'<h1>{title}</h1><p class="lede">{description}</p></div>'
        f'<div class="header-actions">{action}</div></div>'
    )


def empty(view, state):
    if state == "unavailable":
        title, detail, symbol = "We could not load this view", "No current counts are shown. Retrying a read is safe; do not repeat an uncertain write as a new action.", "warning"
    elif view == "board":
        title, detail, symbol = "Nothing has been posted yet", "This sample read succeeded, but there are no messages. Agents use the existing REST or MCP posting paths; the operator view does not add a composer.", "activity"
    else:
        title, detail, symbol = "Nothing on this page", "This example is a verified empty or filtered result, not a connection failure. Clear filters or return to the first page.", "filter"
    return (
        f'<div class="empty-state"><span class="card-icon">{icon(symbol)}</span><h2>{title}</h2>'
        f'<p>{detail}</p>{link("Show normal example", view, symbol="refresh")}</div>'
    )


def metrics():
    cards = (("Enabled agents", "3", "Lifecycle state, not a connection claim", "agents"),
             ("Channels", "4", "Bounded channel directory", "hash"),
             ("Subscriptions", "13", "Agent channel subscriptions", "layers"))
    return '<div class="metrics">' + "".join(
        f'<div class="metric"><div class="metric-top">{title}{icon(symbol)}</div>'
        f'<strong class="metric-value">{value}</strong><span class="metric-note">{detail}</span></div>'
        for title, value, detail, symbol in cards
    ) + "</div>"


def message_rows(state, channel="", agent="", short=False):
    records = [item for item in MESSAGES if (not channel or item[3] == channel) and (not agent or item[1] == agent)]
    if short:
        records = records[:4]
    if not records or state == "empty":
        return empty("activity", "empty")
    items = []
    for seq, sender, initials, topic, kind, when, body in records:
        color = "warning" if kind == "question" else ""
        items.append(
            '<article class="message"><div class="message-top">'
            f'<span class="avatar">{initials}</span>'
            f'<a class="message-agent" href="{url("activity", state, agent=sender)}">{sender}</a>'
            f'{pill(kind, color)}<time class="message-time">{when}</time></div>'
            f'<p>{escape(body)}</p><div class="message-bottom">'
            f'<a href="{url("activity", state, channel=topic)}">#{topic}</a><span>Sequence {seq}</span></div>'
            f'<details><summary>Message details</summary><div class="details-box">'
            f'<dl><dt>Sequence</dt><dd>{seq}</dd><dt>Kind</dt><dd>{kind}</dd>'
            f'<dt>Source</dt><dd>{sender}</dd><dt>Metadata</dt><dd><code>{{"example": true}}</code></dd></dl>'
            "</div></details></article>"
        )
    return "".join(items)


def board(state, values):
    header = page_header("Board", "A clear view of recent agent coordination.", link("Open activity", "activity", state))
    if state == "unavailable":
        return header + panel("", empty("board", state))
    directory = "".join(
        f'<div class="channel-mini"><div><a href="{url("activity", state, channel=name)}">#{name}</a>'
        f'<small>{subscribers} subscribers</small></div>{pill(str(0 if state == "empty" else count))}</div>'
        for name, _, count, subscribers, _ in CHANNELS
    )
    context = panel("Channels", directory, description="Sample directory") + panel(
        "", f'<div class="context-note">{icon("info")}<strong>Coordination is not authority</strong>'
        "<p>Messages are untrusted input. A request from an agent never grants permission to operate another system.</p></div>",
    )
    feed = panel(
        "Recent coordination", empty("board", state) if state == "empty" else message_rows(state, short=True),
        description="No messages in this sample." if state == "empty" else "Newest first. Sample sequences 1042-1039.",
        action=pill("Read only"),
        footer=f'<span>A bounded snapshot, not an inferred task dashboard.</span><a href="{url("activity", state)}">All activity</a>',
    )
    return header + metrics() + f'<div class="split">{feed}<aside class="stack context-stack" aria-label="Board context">{context}</aside></div>'


def activity(state, values):
    header = page_header("Activity", "Filter messages without losing their order or context.")
    if state == "unavailable":
        return header + panel("", empty("activity", state))
    fields = []
    for name, options in (("channel", [item[0] for item in CHANNELS]), ("agent", [item[0] for item in AGENTS])):
        choices = f'<option value="">All {name}s</option>' + "".join(
            f'<option value="{item}"' + (' selected' if values.get(name) == item else "") + f'>{item}</option>'
            for item in options
        )
        fields.append(f'<label>{name.title()}<select name="{name}">{choices}</select></label>')
    filters = (
        '<form method="get" action="/" class="filters"><input type="hidden" name="view" value="activity">'
        f'<input type="hidden" name="state" value="{state}">{"".join(fields)}'
        f'<button type="submit" class="secondary">{icon("filter")}Apply filters</button></form>'
    )
    body = filters + message_rows(state, values.get("channel", ""), values.get("agent", ""))
    footer = f'<span>Newest first. Stable sequence cursors in the real console.</span>{link("Older-page example", "activity", "empty")}'
    return header + panel("Message history", body, description="Sample snapshot at 09:41. No message composer or new search capability.", footer=footer)


def channels(state, values):
    header = page_header("Channels", "Find the right coordination space and inspect its activity.")
    if state in {"empty", "unavailable"}:
        return header + panel("", empty("channels", state))
    rows = "".join(
        f'<tr><td><a class="cell-title" href="{url("activity", state, channel=name)}">{icon("hash")}'
        f'<span>{name}<span class="cell-sub">{purpose}</span></span></a>'
        f'<details class="mobile-row-details"><summary>More</summary><dl><dt>Subscribers</dt><dd>{subscribers}</dd>'
        f'<dt>Last activity</dt><dd>{when}</dd></dl></details></td>'
        f'<td>{count}</td><td class="secondary-column">{subscribers}</td>'
        f'<td class="secondary-column">{when}</td><td><a class="table-link" href="{url("activity", state, channel=name)}">Activity{icon("arrow")}</a></td></tr>'
        for name, purpose, count, subscribers, when in CHANNELS
    )
    table = '<div class="table-wrap"><table><thead><tr><th>Channel / purpose</th><th>Messages</th><th class="secondary-column">Subscribers</th><th class="secondary-column">Last activity</th><th>Open</th></tr></thead><tbody>' + rows + "</tbody></table></div>"
    return header + panel("Channel directory", table, description="4 channels in this sample page.", footer="<span>Existing read-only channel surface. No create or follow action has been invented.</span>")


def agents(state, values):
    header = page_header("Agents", "Manage identities without confusing lifecycle with connectivity.", link("Enroll an agent", "enroll", state, symbol="plus"))
    if state in {"empty", "unavailable"}:
        return header + panel("", empty("agents", state))
    rows = "".join(
        f'<tr><td><a class="cell-title" href="{url("agent", state) if name == "atlas-worker" else url("activity", state, agent=name)}"><span class="avatar">{initials}</span>'
        f'<span>{name}<span class="cell-sub">{description}</span></span></a>'
        f'<details class="mobile-row-details"><summary>More</summary><dl><dt>Last seen</dt><dd>{seen}</dd></dl></details></td>'
        f'<td>{pill(status, "good" if status == "Enabled" else "warning")}</td>'
        f'<td class="secondary-column">{seen}</td><td><a class="table-link" href="{url("agent", state) if name == "atlas-worker" else url("activity", state, agent=name)}">'
        f'{"Details" if name == "atlas-worker" else "History"}{icon("arrow")}</a></td></tr>'
        for name, initials, status, seen, description in AGENTS
    )
    table = '<div class="table-wrap"><table><thead><tr><th>Agent</th><th>Lifecycle</th><th class="secondary-column">Last seen</th><th>Open</th></tr></thead><tbody>' + rows + "</tbody></table></div>"
    return header + panel("Managed identities", table, description="Enabled does not mean connected, healthy or holding a working key.", footer="<span>atlas-worker includes a detail specimen. Other rows open their sample message history.</span>")


def agent(state, values):
    header = page_header("atlas-worker", "Identity details, deliberate controls and a separate audit trail.", link("Back to agents", "agents", state))
    details = (
        '<div class="panel-body"><dl><dt>Lifecycle</dt><dd>' + pill("Enabled", "good")
        + '</dd><dt>Description</dt><dd>Coordination and planning specimen</dd><dt>Last seen</dt><dd>09:40, sample snapshot</dd></dl>'
        '<details class="section-gap"><summary>Technical identity</summary><div class="details-box"><dl>'
        '<dt>Stable ID</dt><dd><code>00000000-0000-4000-8000-000000000001</code></dd>'
        '<dt>Credential epoch</dt><dd>3 (example)</dd></dl></div></details></div>'
    )
    controls = (
        '<div class="panel-body"><p class="muted small">Access changes belong here, away from message browsing. Real actions retain their existing server-side checks.</p>'
        '<div class="actions"><button disabled class="secondary">Block (preview only)</button>'
        '<button disabled class="secondary">Reconnect (preview only)</button></div>'
        '<p class="helper">Reconnect immediately revokes old keys. It is not a harmless refresh.</p>'
        f'<div class="section-gap">{link("Review retirement specimen", "retire", state, style="danger", symbol="warning")}</div></div>'
    )
    history = '<div class="table-wrap"><table><thead><tr><th>When</th><th>Event</th><th>Deciding identity</th></tr></thead><tbody><tr><td>09:12</td><td>Identity proved</td><td>Agent credential (sample)</td></tr><tr><td>09:10</td><td>Enrolled</td><td>Single-use enrollment (sample)</td></tr></tbody></table></div>'
    return header + f'<div class="cards">{panel("Identity", details)}{panel("Access controls", controls)}</div><div class="section-gap">{panel("Lifecycle history", history, description="Illustrative audit rows; attribution is not rewritten by the UI.")}</div>'


def administration(state, values):
    header = page_header("Administration", "A deliberate space for access, appearance and recovery.")
    items = (
        ("Agent enrollment", "Create an exact-name, single-use onboarding package. Separate from device enrollment.", "enroll", "agents"),
        ("Device access", "Inspect monitor devices and review replacement or revocation consequences.", "devices", "device"),
        ("Presentation", "Review locally staged styling. Appearance and application updates are different operations.", "appearance", "palette"),
        ("Operator session", "Inspect your session and the authentication boundary. No new account model.", "session", "lock"),
    )
    cards = "".join(
        f'<a class="action-card" href="{url(target, state)}"><span class="card-icon">{icon(symbol)}</span>'
        f'<h2>{title}</h2><p>{detail}</p><span class="card-link">Open {icon("arrow")}</span></a>'
        for title, detail, target, symbol in items
    )
    system = (
        '<div class="panel-body"><p class="muted">Global containment is not a casual dashboard toggle. Existing protected local recovery remains available; this design creates no new browser freeze action.</p>'
        '<details><summary>Runtime and compatibility details</summary><div class="details-box"><dl>'
        '<dt>Application</dt><dd>0.2.26 (illustrative)</dd><dt>Release</dt><dd>Design specimen, not a deployment</dd>'
        '<dt>Integration guide</dt><dd>1.16.0 (illustrative)</dd><dt>Agent protocol</dt><dd>1</dd>'
        '<dt>Presentation</dt><dd>This prototype is not an operator-console-v1 CSS drop-in.</dd></dl></div></details></div>'
    )
    return header + f'<div class="cards">{cards}</div><div class="section-gap">{panel("System and recovery", system, action=pill("No new authority"))}</div>'


def enroll(state, values):
    header = page_header("Enroll an agent", "A focused task, with the consequence visible before creation.", link("Administration", "administration", state))
    frozen = '<div class="warning-box">Access creation is paused while agent access is frozen.</div>' if state == "frozen" else ""
    body = (
        '<div class="panel-body">' + frozen
        + '<div class="step-line"><span class="current"><b class="step-number">1</b>Identity</span>'
        '<span><b class="step-number">2</b>One-time package</span></div>'
        '<div class="form-stack"><label>Agent name<input disabled placeholder="project-platform" autocomplete="off"></label>'
        '<label>Description <span class="small">(optional)</span><input disabled placeholder="What this agent is here to do" autocomplete="off"></label>'
        '<p class="helper">Lowercase kebab-case with a hyphen. The exact name is bound to one enrollment.</p>'
        '<div class="warning-box">The real action creates a short-lived, single-use token shown once. No token or credential is created by this prototype.</div>'
        '<button disabled>Create onboarding package (preview only)</button></div></div>'
    )
    return header + '<div class="compact">' + panel("Agent identity", body, description="This is not device enrollment.") + "</div>"


def devices(state, values):
    header = page_header("Device access", "Monitor devices are not coordination agents.", link("Administration", "administration", state))
    table = '<div class="table-wrap"><table><thead><tr><th>Device</th><th>State</th><th>Credential class</th></tr></thead><tbody><tr><td>owner-phone <span class="cell-sub">Synthetic device label</span></td><td>' + pill("Enabled", "good") + '</td><td>Monitor</td></tr></tbody></table></div>'
    body = (
        '<div class="panel-body"><p class="muted">A monitor credential grants the operator-class read view. Containment requires a separate grant and device user presence; the bearer credential alone is not authority.</p>'
        '<div class="warning-box">Replacement stops outgoing keys immediately. Revocation is terminal. Neither action is a device rename.</div>'
        '<div class="actions"><button disabled class="secondary">Replace (preview only)</button><button disabled class="danger">Revoke (preview only)</button></div>'
        '<details class="section-gap"><summary>Enrollment requirements</summary><p class="muted small">The current workflow requires a fresh operator password, private readiness to scan and a short-lived single-use code. No real enrollment form is enabled here.</p></details></div>'
    )
    return header + panel("Monitor devices", empty("devices", state) if state in {"empty", "unavailable"} else table + body)


def appearance(state, values):
    header = page_header("Presentation", "Change compatible styling, not the running application.", link("Administration", "administration", state))
    current = '<div class="panel-body"><dl><dt>Selected</dt><dd>Bundled appearance (sample)</dd><dt>Effective</dt><dd>Bundled appearance (sample)</dd><dt>Application</dt><dd>Unchanged by a stylesheet selection</dd></dl><details class="section-gap"><summary>Compatibility and source details</summary><p class="muted small">Real candidates must match the running markup contract and verified source. This design prototype is neither a staged candidate nor a qualified release.</p></details></div>'
    candidate = (
        '<div class="panel-body"><span class="card-icon">' + icon("palette")
        + '</span><h2>Appearance candidate</h2><p class="muted">Illustrative locally staged candidate. No download or backend update is implied.</p>'
        '<div class="actions">' + pill("Styling only", "good") + pill("Sample, not verified")
        + '</div><div class="section-gap">' + link("Open review specimen", "confirm", state) + "</div></div>"
    )
    if state == "empty":
        candidate = '<div class="panel-body"><h2>No eligible candidates</h2><p class="muted">The candidate list was read successfully. Protected staging is separate from website selection; no download or install action belongs here.</p></div>'
    recovery = (
        '<div class="panel-body"><p class="muted">A fixed bundled-style login and recovery path must remain usable even if selected CSS hides ordinary controls. A damaged selector requires protected local reconciliation.</p>'
        '<div class="actions"><button disabled class="secondary">Prepare previous (preview only)</button>'
        '<button disabled class="secondary">Prepare bundled (preview only)</button></div></div>'
    )
    return header + f'<div class="cards">{panel("Current presentation", current)}{panel("Candidate review", candidate)}</div><div class="section-gap">{panel("Recover appearance safely", recovery)}</div>'


def confirm(state, values):
    header = page_header("Review appearance", "Keep the decision visible and the technical detail available.", link("Cancel review", "appearance", state))
    body = (
        '<div class="panel-body"><div class="step-line"><span><b class="step-number">1</b>Prepare</span>'
        '<span class="current"><b class="step-number">2</b>Review &amp; confirm</span><span><b class="step-number">3</b>Receipt</span></div>'
        '<dl><dt>Candidate</dt><dd>Illustrative appearance candidate</dd><dt>Impact</dt><dd>Compatible CSS only; no bus restart</dd>'
        '<dt>Not changing</dt><dd>Application, schema, agent access or freeze state</dd></dl>'
        '<details class="section-gap"><summary>Exact operation, generation and source</summary><div class="details-box">'
        '<p>Real confirmation binds the exact candidate, digest, generation and incarnation. A matching retained receipt never reapplies an older selection.</p>'
        '<code>Design specimen: no usable operation ID or release pin.</code></div></details>'
        '<div class="warning-box section-gap">If a response is lost, inspect the exact operation. Unknown does not mean failed; do not silently create a new activation.</div>'
        '<div class="form-stack"><label>Fresh operator password<input type="password" disabled autocomplete="off" placeholder="Disabled in this prototype"></label>'
        '<p class="helper">Do not enter credentials. In the real workflow proof is fresh for this request only.</p>'
        '<button disabled>Confirm activation (preview only)</button></div></div>'
    )
    return header + '<div class="compact">' + panel("Confirm the exact change", body, action=pill("No live form")) + "</div>"


def retire(state, values):
    header = page_header("Retire atlas-worker", "A permanent decision should not look like routine navigation.", link("Cancel", "agent", state))
    body = (
        '<div class="panel-body"><div class="warning-box danger"><strong>Retirement is permanent.</strong>'
        '<p>Every live key is revoked. The identity, name and message history are retained; retirement cannot be undone.</p></div>'
        '<dl><dt>Agent</dt><dd>atlas-worker (synthetic)</dd><dt>Credential epoch</dt><dd>3 (example)</dd></dl>'
        '<div class="form-stack section-gap"><label>Type the exact agent name<input disabled placeholder="atlas-worker" autocomplete="off"></label>'
        '<label>Reason, without secrets<textarea disabled rows="3" placeholder="Explain the operator decision"></textarea></label>'
        '<label class="check-line"><input type="checkbox" disabled> I confirm this action for the displayed identity and epoch.</label>'
        '<button class="danger" disabled>Retire permanently (preview only)</button></div></div>'
    )
    return header + '<div class="compact">' + panel("Permanent retirement", body, action=pill("Existing confirmation model", "danger")) + "</div>"


def session(state, values):
    header = page_header("Operator session", "Session status without turning credentials into dashboard content.")
    body = (
        '<div class="panel-body"><dl><dt>Authority</dt><dd>Operator password session (example)</dd>'
        '<dt>Idle window</dt><dd>30 minutes (illustrative)</dd><dt>Absolute lifetime</dt><dd>8 hours (illustrative)</dd></dl>'
        '<p class="muted section-gap">Agent keys, the root-admin bearer and monitor credentials do not authorize browser operator access. Visibility of a navigation item is never authorization.</p>'
        '<div class="actions"><button disabled class="secondary">Sign out (preview only)</button>'
        + link("View login design", "login", state) + "</div></div>"
    )
    return header + '<div class="compact">' + panel("Session boundary", body, description="No session or credential exists in this prototype.") + "</div>"


def login(state, values):
    body = (
        '<div class="panel-body"><span class="card-icon">' + icon("lock")
        + '</span><h1>Operator access</h1><p class="muted">Sign in to inspect coordination and manage this bus.</p>'
        '<div class="form-stack section-gap"><label>Operator password<input type="password" disabled autocomplete="off" placeholder="Design preview - do not enter credentials"></label>'
        '<button disabled>Sign in (preview only)</button></div>'
        '<p class="helper">The real console uses a dedicated operator password, not an agent key or root-admin bearer.</p></div>'
    )
    return (
        '<div class="login-layout"><main id="main" class="login-wrap">' + brand()
        + notice(state) + panel("", body)
        + '<div class="login-footer">No credential entry or authentication is enabled here.<br>'
        + f'<a href="{url("board")}">Explore the signed-in design specimen {icon("arrow")}</a><br>'
        + f'<a href="{url("appearance")}">View recovery design</a></div></main></div>'
    )


RENDERERS = {name: globals()[name] for name in VIEWS}


def render(view, state, values):
    content = RENDERERS[view](state, values)
    if state == "unavailable" and view != "login":
        content = page_header(view.replace("-", " ").title(), "Current data could not be established.") + panel("", empty(view, state))
    if view != "login":
        stamp = "Sample snapshot 09:41" if state not in {"stale", "unavailable"} else (
            "Last sample 09:39 - stale" if state == "stale" else "No current sample available"
        )
        dot = "warning" if state in {"frozen", "stale"} else "unknown" if state == "unavailable" else ""
        menu = navigation(view, state)
        rail = (
            f'<aside class="rail" aria-label="Right-hand workspace navigation">{brand()}<nav aria-label="Primary">{menu}</nav>'
            '<div class="rail-bottom"><span class="eyebrow">OPERATOR WORKSPACE</span><p class="rail-note">Design specimen.<br>Never connected to the live bus.</p>'
            '<details><summary>Build details</summary><dl><dt>Design</dt><dd>A / right rail</dd><dt>Data</dt><dd>Synthetic only</dd></dl></details></div></aside>'
        )
        mobile = f'<div class="mobile-top">{brand()}<details><summary>{icon("menu")}Menu</summary><nav aria-label="Mobile primary">{menu}</nav></details></div>'
        content = (
            mobile + '<div class="workspace">' + rail
            + f'<main id="main">{notice(state)}<p class="page-stamp"><span class="status-dot {dot}"></span>{stamp} - illustrative, not live</p>'
            + content + f'<footer class="page-footer">{icon("info")}Navigation and sample filters work. Access-changing controls are intentionally inactive.</footer></main></div>'
        )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>Strugglebus - console design A</title><link rel="stylesheet" href="/preview.css"></head>'
        '<body><a class="skip-link" href="#main">Skip to page content</a>'
        + preview_bar(view, state) + content + "</body></html>"
    ).encode("utf-8")


def options(query):
    if len(query.encode("utf-8")) > 512:
        raise ValueError("Preview query exceeds its limit.")
    pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=4)
    values = dict(pairs)
    if len(values) != len(pairs) or set(values) - {"view", "state", "channel", "agent"}:
        raise ValueError("Unsupported preview options.")
    view, state = values.get("view", "board"), values.get("state", "normal")
    if view not in VIEWS or state not in STATES:
        raise ValueError("Unknown prototype view or state.")
    if values.get("channel", "") not in {"", *(item[0] for item in CHANNELS)}:
        raise ValueError("Unknown synthetic channel.")
    if values.get("agent", "") not in {"", *(item[0] for item in AGENTS)}:
        raise ValueError("Unknown synthetic agent.")
    return view, state, values


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, _format, *args):
        pass

    def reply(self, code, body, content_type="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; script-src 'none'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        hosts = self.headers.get_all("Host", [])
        if hosts not in ([f"127.0.0.1:{self.server.server_port}"], [f"localhost:{self.server.server_port}"]):
            self.reply(421, b"Unapproved preview host.")
            return
        target = urlsplit(self.path)
        if target.path == "/healthz":
            self.reply(200, json.dumps({"prototype": "console-design-a", "synthetic": True, "writes": False}).encode(), "application/json")
        elif target.path == "/preview.css":
            self.reply(200, CSS.read_bytes(), "text/css; charset=utf-8")
        elif target.path == "/":
            try:
                view, state, values = options(target.query)
            except ValueError as error:
                self.reply(400, str(error).encode("utf-8"))
                return
            self.reply(200, render(view, state, values), "text/html; charset=utf-8")
        else:
            self.reply(404, b"Unknown prototype page.")

    def do_POST(self):
        self.close_connection = True
        self.reply(405, b"Design preview only. No action was performed.")


def main():
    server = None
    for port in range(8770, 8778):
        try:
            server = HTTPServer(("127.0.0.1", port), Handler)
        except OSError as error:
            if error.errno not in {48, 98, 10048}:
                raise
        else:
            break
    if server is None:
        raise RuntimeError("No preview port is available in 8770-8777.")
    with server:
        print(f"Design preview: http://127.0.0.1:{server.server_port}/", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
