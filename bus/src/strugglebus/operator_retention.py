"""The operator's retention setting: how long messages and silent agents are kept."""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response

from strugglebus.dashboard import dashboard_headers
from strugglebus.errors import DomainValidationError
from strugglebus.operator_auth import OperatorFormError
from strugglebus.operator_lifecycle_rendering import facts, hidden, panel, timestamp
from strugglebus.operator_web import (
    _query, authority_for, context_for, operator_form, operator_operation, operator_page,
)
from strugglebus.retention import PREFIX
from strugglebus.store import utc_now
from strugglebus.store._retention import (
    MAXIMUM_DAYS, MINIMUM_DAYS, RetentionOverview, RetentionSettings,
)

ROOT = "/operator/retention"


def _days(value: int | None, *, never: str) -> str:
    return never if value is None else f"{value} days"


def _field(name: str, label: str, value: int | None, helper: str) -> str:
    current = "" if value is None else str(value)
    return (
        f'<div class="field"><label for="retention-{name}">{escape(label)}</label>'
        f'<input id="retention-{name}" name="{name}" type="number" '
        f'min="{MINIMUM_DAYS}" max="{MAXIMUM_DAYS}" value="{current}">'
        f'<p class="helper">{escape(helper)}</p></div>'
    )


def render(settings: RetentionSettings, overview: RetentionOverview, csrf: str) -> str:
    values: dict[str, object] = {
        "Messages are kept for": _days(settings.message_days, never="Forever"),
        "Silent agents are blocked after": _days(settings.idle_agent_days, never="Never"),
        "Messages stored now": overview.stored_messages,
        "Oldest message": timestamp(overview.oldest_message_at),
        "Enabled agents": overview.enabled_agents,
        "Last clean-up": timestamp(settings.last_run_at),
    }
    if settings.last_run_at is not None:
        values["Last clean-up removed"] = (
            f"{settings.last_removed_messages} messages, "
            f"blocked {settings.last_blocked_agents} agents"
        )
        values["Removed and blocked in total"] = (
            f"{settings.total_removed_messages} messages, "
            f"{settings.total_blocked_agents} agents"
        )
    explanation = (
        "<p>Once an hour the bus removes messages older than the first period and "
        "blocks agents that have not connected for the second. Removing a message "
        "is permanent: it remains only in backups taken before it was removed.</p>"
        "<p>A blocked agent keeps its identity and history. Open it under Agents "
        "and unblock it to let it back in.</p>"
        "<p>Nothing is removed or blocked while agent access is frozen. Each "
        f"clean-up that changes something writes a <code>{escape(PREFIX.strip())}</code> "
        "line to the service log.</p>"
    )
    if settings.message_days is None and settings.idle_agent_days is None:
        explanation = (
            '<p role="status">Retention is off on this bus: nothing is removed and '
            "no agent is blocked for being silent. Enter a period below to turn it on."
            "</p>" + explanation
        )
    form = (
        f'<form method="post" action="{ROOT}" class="form-stack">{hidden("csrf", csrf)}'
        + _field(
            "message_days", "Keep messages for (days)", settings.message_days,
            f"{MINIMUM_DAYS} to {MAXIMUM_DAYS}. Leave empty to keep messages forever.",
        )
        + _field(
            "idle_agent_days", "Block silent agents after (days)", settings.idle_agent_days,
            f"{MINIMUM_DAYS} to {MAXIMUM_DAYS}. Leave empty to never block a silent agent.",
        )
        + '<div class="field"><label for="retention-password">Operator password</label>'
        '<input id="retention-password" name="password" type="password" '
        'autocomplete="current-password" maxlength="1024" required></div>'
        '<div class="form-actions"><button type="submit">Save retention</button></div></form>'
    )
    return panel(
        "Retention", facts(values) + explanation + form,
        description="How long this bus keeps messages and silent agents.",
    )


def _page(request: Request, body: str, *, code: int = 200) -> Response:
    return operator_page("Retention", body, code=code, request=request, active="system")


def _period(text: str) -> int | None:
    text = text.strip()
    if not text:
        return None
    if not text.isascii() or not text.isdigit() or len(text) > 5:
        raise OperatorFormError("A retention period must be a whole number of days.")
    return int(text)


async def retention_view(request: Request) -> Response:
    _query(request, set())
    context = context_for(request)
    store = request.app.state.agent_service.store
    settings = await operator_operation(request, store.get_retention)
    overview = await operator_operation(request, store.retention_overview)
    return _page(request, render(settings, overview, context.csrf_token))


async def retention_submit(request: Request) -> Response:
    _query(request, set())
    fields = await operator_form(
        request, fields={"message_days", "idle_agent_days", "password"},
        required={"password"},
    )
    message_days = _period(fields.get("message_days", ""))
    idle_agent_days = _period(fields.get("idle_agent_days", ""))
    context = context_for(request)
    await authority_for(request).reauthenticate(
        context, fields["password"], source=request.state.operator_source,
        family="updater-confirm",
    )
    store = request.app.state.agent_service.store
    await operator_operation(
        request, store.set_retention, message_days=message_days,
        idle_agent_days=idle_agent_days, changed_by=context.actor_id, changed_at=utc_now(),
    )
    print(
        f"{PREFIX}setting changed by {context.actor_id}: messages "
        f"{_days(message_days, never='kept forever')}, silent agents "
        f"{_days(idle_agent_days, never='never blocked')}",
        flush=True,
    )
    return RedirectResponse(ROOT, status_code=303, headers=dashboard_headers())


def add_retention_routes(router: APIRouter) -> None:
    async def view(request: Request) -> Response:
        context_for(request)
        return await retention_view(request)

    async def submit(request: Request) -> Response:
        context_for(request)
        try:
            return await retention_submit(request)
        except (OperatorFormError, DomainValidationError) as error:
            body = panel(
                "Retention was not changed", f'<p role="alert">{escape(str(error))}</p>'
                f'<p><a class="button secondary" href="{ROOT}">Back to retention</a></p>',
            )
            return _page(request, body, code=400)

    router.add_api_route(ROOT, view, methods=["GET"], include_in_schema=False)
    router.add_api_route(ROOT, submit, methods=["POST"], include_in_schema=False)
