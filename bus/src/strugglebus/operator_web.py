"""No-JavaScript operator login, lifecycle controls and audited roster."""

from __future__ import annotations

import asyncio
import html
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TypeVar
from urllib.parse import urlencode
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from strugglebus.dashboard import dashboard_headers, render_humans, render_operator
from strugglebus.integration import build_server_info
from strugglebus.ca import load_trust_anchor
from strugglebus.errors import (
    AgentAccessFrozenError, AgentNotFoundError, ConfigurationError,
    CredentialConflictError, CredentialLimitError, DomainValidationError,
    PostRequestConflictError, ReplyNotFoundError,
    ServicePrincipalNotFoundError, StorageError, TrustAnchorError,
)
from strugglebus.store import HUMAN_CHANNEL
from strugglebus.models import LifecycleActor
from strugglebus.operator_auth import (
    CHALLENGE_COOKIE,
    SESSION_COOKIE,
    OperatorAuth,
    OperatorAuthError,
    OperatorCapacityError,
    OperatorContext,
    OperatorFormError,
    operator_cookie,
    parse_form,
)
from strugglebus.reconnect import encode_package
from strugglebus import operator_lifecycle_rendering as ui
from strugglebus.operator_lifecycle_rendering import (
    ACTIONS as _ACTIONS,
    hidden as _hidden,  # noqa: F401 - imported by operator submodules
)

T = TypeVar("T")


def operator_page(
    title: str, body: str, *, code: int = 200,
    request: Request | None = None, active: str = "agents",
) -> HTMLResponse:
    return HTMLResponse(
        render_operator(
            title, body, build_server_info(request.app.state.config) if request else None,
            generated_at=datetime.now(UTC), active=active,
        ),
        status_code=code, headers=dashboard_headers(),
    )


def _cookie(response: Response, name: str, value: str, seconds: int) -> None:
    response.set_cookie(
        name, value, max_age=seconds, secure=True, httponly=True,
        samesite="strict", path="/",
    )


def _clear_cookie(response: Response, name: str) -> None:
    response.delete_cookie(
        name, secure=True, httponly=True, samesite="strict", path="/",
    )


def authority_for(request: Request) -> OperatorAuth:
    authority = request.app.state.operator_auth
    if not isinstance(authority, OperatorAuth) or not authority.configured:
        raise OperatorAuthError("operator access is unavailable")
    return authority


def context_for(request: Request) -> OperatorContext:
    context = getattr(request.state, "operator_context", None)
    if not isinstance(context, OperatorContext):
        raise OperatorAuthError("operator authentication required")
    authority_for(request).require_active(context)
    return context


def actor_for(request: Request) -> LifecycleActor:
    context = context_for(request)
    authority = authority_for(request)
    return LifecycleActor(
        "remote-admin", context.actor_id, lambda: authority.require_active(context),
    )


async def operator_operation(
    request: Request, function: Callable[..., T], *args, **kwargs,
) -> T:
    actor = actor_for(request)
    store = request.app.state.agent_service.store

    def run() -> T:
        token = store.begin_operator_operation(actor)
        try:
            return function(*args, **kwargs)
        finally:
            store.end_operator_operation(token)

    return await asyncio.to_thread(run)


def _query(request: Request, allowed: set[str]) -> dict[str, str]:
    if len(request.scope.get("query_string", b"")) > 1024:
        raise DomainValidationError("operator query exceeds its limit")
    result = {}
    for key, value in request.query_params.multi_items():
        if key not in allowed or key in result:
            raise DomainValidationError("invalid operator query")
        result[key] = value
    return result


def _integer(value: str, *, maximum: int = 2**63 - 2, minimum: int = 0) -> int:
    if not value.isascii() or not value.isdecimal() or len(value) > 19:
        raise DomainValidationError("invalid operator sequence or limit")
    number = int(value)
    if not minimum <= number <= maximum:
        raise DomainValidationError("invalid operator sequence or limit")
    return number


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise DomainValidationError("invalid operator timestamp") from None
    if parsed.tzinfo is None:
        raise DomainValidationError("invalid operator timestamp")
    return parsed.astimezone(UTC)


def _identity(value: str) -> str:
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except ValueError:
        raise DomainValidationError("canonical agent identity required") from None
    return value


def _navigation(*, back: bool = True) -> str:
    return (
        '<div class="actions section-gap" aria-label="Agent tasks">'
        + ('<a class="button secondary" href="/agents">All agents</a>' if back else "")
        + '<a class="button secondary" href="/register">Enroll an agent</a></div>'
        '<p class="helper section-gap">Freezing all agent access at once is not done from '
        'this console. Use the Windows app, or the access-freeze command on the bus host '
        '(see the manual). Agents can never freeze or unfreeze anything.</p>'
    )


def _failure(error: Exception) -> HTMLResponse:
    if isinstance(error, (CredentialConflictError, CredentialLimitError)):
        code, message = 409, (
            "Something changed before your action arrived, or a limit was reached. "
            "Reload the page and try again."
        )
    elif isinstance(error, (AgentNotFoundError, ServicePrincipalNotFoundError)):
        code, message = 404, "That agent could not be found."
    elif isinstance(error, (ConfigurationError, DomainValidationError)):
        code, message = 422, "Something in that request was not valid."
    elif isinstance(error, (StorageError, TrustAnchorError, AgentAccessFrozenError)):
        code, message = 503, "That is unavailable just now. Try again shortly."
    else:
        raise error
    body = (
        f'<div class="notice" role="alert"><div>{message}</div></div>'
        "<p>If you were making a change, it may still have gone through. Check the "
        "agent's page and its history before trying again.</p>" + _navigation()
    )
    return operator_page("That did not work", body, code=code)


async def managed_agents_view(request: Request) -> HTMLResponse:
    try:
        query = _query(request, {"state", "after", "limit"})
        limit = _integer(
            query.get("limit", str(min(100, request.app.state.config.human_activity_limit))),
            minimum=1, maximum=min(200, request.app.state.config.human_activity_limit),
        )
        state = query.get("state", "managed")
        agents = await operator_operation(
            request, request.app.state.agent_service.list_managed_agents,
            state=state, after_name=query.get("after"), limit=limit,
            require_access=False,
        )
    except (DomainValidationError, StorageError, AgentAccessFrozenError) as error:
        return _failure(error)
    body = ui.roster(
        agents, state=state, after=query.get("after", ""), limit=limit,
        maximum=min(200, request.app.state.config.human_activity_limit),
    ) + _navigation(back=False)
    return operator_page("Agents", body, request=request)


async def operator_form(
    request: Request, *, fields: set[str], required: set[str],
) -> dict[str, str]:
    context = context_for(request)
    parsed = parse_form(
        await request.body(), allowed=fields | {"csrf"},
        required=required | {"csrf"},
        maximum=request.app.state.config.operator_form_bytes,
    )
    authority_for(request).require_csrf(context, parsed.pop("csrf"))
    return parsed


def _require_plain_login(request: Request) -> None:
    if request.scope.get("query_string", b""):
        raise OperatorFormError("invalid operator query")


async def _login_fields(request: Request) -> dict[str, str]:
    return parse_form(
        await request.body(), allowed={"csrf", "password"},
        required={"csrf", "password"},
        maximum=request.app.state.config.operator_form_bytes,
    )


def _login_failure(*, code: int) -> Response:
    response = operator_page(
        "Sign in unsuccessful",
        '<div class="notice" role="alert"><div>Sign in failed. No new session was created.</div></div>'
        '<a class="button secondary" href="/login">Try again</a>'
        '<p class="helper section-gap">Use the operator password. No password or token is displayed here.</p>',
        code=code,
    )
    _clear_cookie(response, CHALLENGE_COOKIE)
    return response


def add_operator_routes(router: APIRouter) -> None:
    from strugglebus.operator_updates import add_update_routes

    add_update_routes(router)
    from strugglebus.operator_retention import add_retention_routes

    add_retention_routes(router)

    async def humans_page(
        request: Request, *, notice: str | None = None, code: int = 200,
        reply_to: int | None = None,
    ) -> Response:
        try:
            snapshot = await operator_operation(
                request, request.app.state.board_service.dashboard_snapshot,
                channel_name=HUMAN_CHANNEL, agent_name=None, before=None,
                limit=min(100, request.app.state.config.human_activity_limit),
            )
        except (DomainValidationError, StorageError) as error:
            return _failure(error)
        return HTMLResponse(
            render_humans(
                snapshot, build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
                csrf_token=context_for(request).csrf_token,
                request_id=str(uuid4()), notice=notice, reply_to=reply_to,
            ),
            status_code=code, headers=dashboard_headers(),
        )

    @router.get("/humans", include_in_schema=False)
    async def humans_view(request: Request) -> Response:
        try:
            reply = _query(request, {"reply"}).get("reply")
            reply_to = None if reply is None else _integer(reply, minimum=1)
        except DomainValidationError as error:
            return _failure(error)
        return await humans_page(request, reply_to=reply_to)

    @router.post("/humans", include_in_schema=False)
    async def humans_post(request: Request) -> Response:
        fields = await operator_form(
            request, fields={"body", "kind", "reply_to", "request_id"},
            required={"body", "kind", "request_id"},
        )
        try:
            reply = fields.get("reply_to", "").strip()
            message = await operator_operation(
                request, request.app.state.board_service.create_human_message,
                body=fields["body"].replace("\r\n", "\n"), kind=fields["kind"],
                reply_to=_integer(reply, minimum=1) if reply else None,
                request_id=fields["request_id"],
            )
        except (DomainValidationError, ReplyNotFoundError, PostRequestConflictError) as error:
            detail = (
                "That reply target is not a #humans message." if isinstance(error, ReplyNotFoundError)
                else "This form was already used for a different post. Reload and try again."
                if isinstance(error, PostRequestConflictError)
                else "The post was not accepted: check its size, kind, mentions and reply number."
            )
            return await humans_page(request, notice=detail, code=422)
        except StorageError as error:
            return _failure(error)
        return RedirectResponse(f"/humans#message-{message.seq}", status_code=303)
    @router.get("/service-principals", include_in_schema=False)
    async def service_principals_view(request: Request) -> Response:
        principals = await operator_operation(
            request, request.app.state.spn_service.list,
        )
        csrf = html.escape(context_for(request).csrf_token, quote=True)
        rows = []
        for principal in principals:
            attributed_page = await operator_operation(
                request,
                request.app.state.agent_service.list_identity_creation_provenance,
                creator_type="spn",
                creator_id=principal.id,
                limit=1,
            )
            identifier = html.escape(principal.id, quote=True)
            name = html.escape(principal.name)
            prefix = html.escape(principal.agent_name_prefix)
            controls = []
            actions = (
                ("block", "Block") if principal.status == "enabled"
                else ("unblock", "Unblock") if principal.status == "blocked"
                else None
            )
            available = ([actions] if actions is not None else [])
            if principal.status != "revoked":
                available.extend([("rotate", "Rotate credential"), ("revoke", "Revoke")])
            for action, label in available:
                controls.append(
                    '<form method="post" action="/service-principals/'
                    f'{identifier}/control">'
                    f'<input type="hidden" name="csrf" value="{csrf}">'
                    f'<input type="hidden" name="action" value="{action}">'
                    f'<input type="hidden" name="expected_version" value="{principal.version}">'
                    f'<input type="hidden" name="request_id" value="{uuid4()}">'
                    '<label>Reason <input name="reason" required maxlength="256"></label>'
                    f'<button type="submit">{label}</button></form>'
                )
            rows.append(
                "<section class=\"panel compact\">"
                f"<h2>{name}</h2><p>ID: <code>{identifier}</code></p>"
                f"<p>Agent prefix: <code>{prefix}</code>; state: "
                f"<strong>{html.escape(principal.status)}</strong>; version "
                f"{principal.version}</p>"
                "<p>Attributed durable agents: "
                f"<strong>{attributed_page.total_count}</strong>"
                + (
                    "; <a href=\"/service-principals/"
                    f"{identifier}/agents\">view complete roster</a></p>"
                    if attributed_page.total_count else
                    "</p><p>No agent identity has been created by this SPN.</p>"
                )
                + f"{''.join(controls)}</section>"
            )
        body = (
            '<p class="breadcrumb"><a href="/system">Administration</a> / '
            "Service principals</p>"
            '<section class="panel compact"><h2>Create onboarding SPN</h2>'
            '<p>An SPN can only issue exact-name onboarding packages under its '
            "configured prefix. It cannot act as an agent or administrator.</p>"
            '<form class="form-stack" method="post" action="/service-principals">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="request_id" value="{uuid4()}">'
            '<label>Name <input name="name" required maxlength="64"></label>'
            '<label>Agent-name prefix <input name="agent_name_prefix" required '
            'maxlength="128"></label><button type="submit">Create SPN</button>'
            "</form></section>"
            + "".join(rows)
        )
        return operator_page(
            "Service principals", body, request=request, active="operator",
        )

    @router.get(
        "/service-principals/{spn_id}/agents", include_in_schema=False,
    )
    async def service_principal_agents(
        request: Request, spn_id: str,
    ) -> Response:
        try:
            _identity(spn_id)
            principal = next(
                (
                    item for item in await operator_operation(
                        request, request.app.state.spn_service.list,
                    )
                    if item.id == spn_id
                ),
                None,
            )
            if principal is None:
                raise ServicePrincipalNotFoundError(
                    "service principal does not exist"
                )
            query = _query(
                request, {"after_created_at", "after_agent_id", "limit"},
            )
            after_created_at = (
                _timestamp(query["after_created_at"])
                if "after_created_at" in query else None
            )
            after_agent_id = query.get("after_agent_id")
            limit = _integer(
                query.get("limit", "100"), minimum=1, maximum=200,
            )
            page = await operator_operation(
                request,
                request.app.state.agent_service.list_identity_creation_provenance,
                creator_type="spn",
                creator_id=spn_id,
                after_created_at=after_created_at,
                after_agent_id=after_agent_id,
                limit=limit,
            )
        except (
            DomainValidationError, ServicePrincipalNotFoundError, StorageError,
        ) as error:
            return _failure(error)
        rows = "".join(
            "<tr>"
            f'<td><a href="/agents/{html.escape(item.agent.id, quote=True)}">'
            f"{html.escape(item.agent.name)}</a></td>"
            f"<td>{html.escape(item.agent.state)}</td>"
            f"<td><code>{html.escape(item.originating_request_id)}</code></td>"
            f"<td>{html.escape(item.created_at.isoformat())}</td>"
            "</tr>"
            for item in page.items
        )
        next_link = ""
        if (
            page.has_more
            and page.next_created_at is not None
            and page.next_agent_id is not None
        ):
            query_string = urlencode({
                "after_created_at": page.next_created_at.isoformat(),
                "after_agent_id": page.next_agent_id,
                "limit": limit,
            })
            next_link = (
                '<p><a class="button secondary" href="/service-principals/'
                f'{html.escape(spn_id, quote=True)}/agents?{html.escape(query_string, quote=True)}">'
                "Next page</a></p>"
            )
        body = (
            '<p class="breadcrumb"><a href="/service-principals">Service principals</a> / '
            f"{html.escape(principal.name)} attributed agents</p>"
            f"<p>Showing {len(page.items)} of {page.total_count} attributed "
            f"agents. More remain: {'yes' if page.has_more else 'no'}.</p>"
            "<table><thead><tr><th>Agent</th><th>State</th>"
            "<th>Creation request</th><th>Created</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>{next_link}"
        )
        return operator_page(
            "Attributed agents", body, request=request, active="operator",
        )

    @router.post("/service-principals", include_in_schema=False)
    async def service_principal_create(request: Request) -> Response:
        try:
            fields = await operator_form(
                request,
                fields={"name", "agent_name_prefix", "request_id"},
                required={"name", "agent_name_prefix", "request_id"},
            )
            issued = await operator_operation(
                request,
                request.app.state.spn_service.create,
                name=fields["name"],
                agent_name_prefix=fields["agent_name_prefix"],
                request_id=fields["request_id"],
                actor=actor_for(request),
            )
        except (
            AgentAccessFrozenError, ConfigurationError, CredentialConflictError,
            DomainValidationError, StorageError,
        ) as error:
            return _failure(error)
        if not issued.secret_issued or issued.secret is None:
            detail = (
                "<p>This request already committed. The credential secret is "
                "not recoverable; rotate explicitly if a replacement is needed.</p>"
            )
        else:
            detail = (
                "<p>Copy this credential now. It will never be displayed again.</p>"
                f"<pre>{html.escape(issued.secret)}</pre>"
            )
        return operator_page(
            "Service principal created",
            detail
            + '<p><a href="/service-principals">Return to service principals</a></p>',
            request=request,
            active="operator",
        )

    @router.post("/service-principals/{spn_id}/control", include_in_schema=False)
    async def service_principal_control(request: Request, spn_id: str) -> Response:
        try:
            _identity(spn_id)
            fields = await operator_form(
                request,
                fields={"action", "expected_version", "request_id", "reason"},
                required={"action", "expected_version", "request_id", "reason"},
            )
            action = fields["action"]
            if action not in {"block", "unblock", "rotate", "revoke"}:
                raise DomainValidationError("invalid SPN action")
            expected_version = _integer(fields["expected_version"])
            if action == "rotate":
                issued = await operator_operation(
                    request,
                    request.app.state.spn_service.rotate,
                    spn_id,
                    expected_version=expected_version,
                    request_id=fields["request_id"],
                    reason=fields["reason"],
                    actor=actor_for(request),
                )
                detail = (
                    "<p>This rotation already committed. The credential secret "
                    "is not recoverable.</p>"
                    if not issued.secret_issued or issued.secret is None
                    else "<p>Copy this replacement credential now. It will never "
                    f"be displayed again.</p><pre>{html.escape(issued.secret)}</pre>"
                )
            else:
                principal = await operator_operation(
                    request,
                    request.app.state.spn_service.transition,
                    spn_id,
                    action=action,
                    expected_version=expected_version,
                    request_id=fields["request_id"],
                    reason=fields["reason"],
                    actor=actor_for(request),
                )
                detail = (
                    f"<p>Service principal is now "
                    f"<strong>{html.escape(principal.status)}</strong>.</p>"
                )
        except (
            AgentAccessFrozenError, ConfigurationError, CredentialConflictError,
            CredentialLimitError, DomainValidationError,
            ServicePrincipalNotFoundError, StorageError,
        ) as error:
            return _failure(error)
        return operator_page(
            "Service principal updated",
            detail
            + '<p><a href="/service-principals">Return to service principals</a></p>',
            request=request,
            active="operator",
        )

    @router.get("/agents/{agent_id}", include_in_schema=False)
    async def agent_view(request: Request, agent_id: str) -> Response:
        try:
            _identity(agent_id)
            query = _query(request, {"after", "limit"})
            after = _integer(query.get("after", "0"))
            limit = _integer(
                query.get("limit", str(min(100, request.app.state.config.human_activity_limit))),
                minimum=1, maximum=min(200, request.app.state.config.human_activity_limit),
            )
            service = request.app.state.agent_service
            agent = await operator_operation(
                request, service.get_managed_agent, agent_id, require_access=False,
            )
            events = await operator_operation(
                request, service.store.list_agent_lifecycle_events,
                agent_id, after_seq=after, limit=limit, require_access=False,
            )
        except (
            AgentNotFoundError, DomainValidationError, StorageError, AgentAccessFrozenError,
        ) as error:
            return _failure(error)
        body = ui.identity(agent, events, limit) + _navigation()
        return operator_page(agent.name, body, request=request)

    @router.get("/agents/{agent_id}/control", include_in_schema=False)
    async def control_view(request: Request, agent_id: str) -> Response:
        try:
            _identity(agent_id)
            query = _query(request, {"action"})
            action = query.get("action", "")
            agent = await operator_operation(
                request, request.app.state.agent_service.get_managed_agent, agent_id,
                require_access=False,
            )
            allowed = ui.available_actions(agent)
            if action not in allowed:
                raise CredentialConflictError("action is unavailable")
        except (
            AgentNotFoundError, DomainValidationError, CredentialConflictError,
            StorageError, AgentAccessFrozenError,
        ) as error:
            return _failure(error)
        body = ui.confirmation(
            agent, action, context_for(request).csrf_token, str(uuid4()),
        )
        return operator_page(f"{_ACTIONS[action]}: {agent.name}", body, request=request)

    @router.post("/agents/{agent_id}/control", include_in_schema=False)
    async def control_submit(request: Request, agent_id: str) -> Response:
        try:
            _identity(agent_id)
            fields = await operator_form(
                request, fields={"action", "epoch", "request_id", "reason", "confirm", "name"},
                required={"action", "epoch", "request_id", "reason", "confirm", "name"},
            )
            action = fields["action"]
            if action not in _ACTIONS or fields["confirm"] != action:
                raise DomainValidationError("explicit confirmation required")
            epoch = _integer(fields["epoch"])
            service = request.app.state.agent_service
            agent = await operator_operation(
                request, service.get_managed_agent, agent_id, require_access=False,
            )
            if fields["name"] != agent.name:
                raise DomainValidationError("exact identity confirmation required")
            actor = actor_for(request)
            if action == "reconnect":
                authority_for(request).admit("reconnect-issue", context_for(request).session_id)
                config = request.app.state.config

                def issue():
                    anchor = load_trust_anchor(config.ca_bundle_path, config.ca_root_sha256)
                    if anchor is None or config.ca_root_sha256 is None:
                        raise TrustAnchorError("configured verified trust publication is required")
                    prepared = service.prepare_reconnect_grant()
                    package = encode_package(
                        agent_id=agent.id, agent_name=agent.name, base_url=config.public_base_url,
                        ca_root=anchor, ca_sha256=config.ca_root_sha256,
                        expires_at=prepared.expires_at, grant=prepared.token,
                    )
                    issued = service.issue_reconnect(
                        agent.id, expected_agent_name=fields["name"],
                        expected_credential_epoch=epoch, request_id=fields["request_id"],
                        reason=fields["reason"], actor=actor, prepared=prepared,
                    )
                    return issued, package

                issued, package = await operator_operation(request, issue)
                if issued.token is not None:
                    return Response(
                        package, status_code=201, media_type="application/json",
                        headers={
                            **dashboard_headers(), "Cache-Control": "no-store",
                            "Referrer-Policy": "no-referrer",
                            "Content-Disposition": f'attachment; filename="reconnect-{agent.id}.json"',
                        },
                    )
                return operator_page(
                    "Reconnect already issued",
                    ui.panel("That package can no longer be shown",
                        "<p>This request already went through, and a package is only ever shown "
                        "once. Check the history, and make a new package if you still need one.</p>"
                        + ui.facts({"Request ID": fields["request_id"], "Agent ID": agent.id})
                        + f'<a class="button secondary" href="/agents/{agent.id}">Back to this agent</a>'),
                    request=request,
                )
            result = await operator_operation(
                request, service.transition_agent, agent_id, action=action,
                expected_credential_epoch=epoch, request_id=fields["request_id"],
                reason=fields["reason"], actor=actor,
            )
            return operator_page(
                "Change recorded", ui.lifecycle_result(result),
                request=request,
            )
        except (
            AgentNotFoundError, ConfigurationError, DomainValidationError,
            CredentialConflictError, CredentialLimitError, StorageError,
            TrustAnchorError, AgentAccessFrozenError,
        ) as error:
            return _failure(error)

    @router.get("/login", include_in_schema=False)
    async def login_view(request: Request) -> Response:
        _require_plain_login(request)
        authority = authority_for(request)
        if getattr(request.state, "operator_context", None) is not None:
            return RedirectResponse("/", status_code=303, headers=dashboard_headers())
        token, csrf = authority.challenge(request.state.operator_source)
        response = operator_page("Sign in", ui.login_form(csrf))
        _cookie(response, CHALLENGE_COOKIE, token, 300)
        return response

    @router.post("/login", include_in_schema=False)
    async def login_submit(request: Request) -> Response:
        _require_plain_login(request)
        authority = authority_for(request)
        try:
            fields = await _login_fields(request)
        except OperatorFormError:
            return _login_failure(code=403)

        # Deliberately no freeze guard. The operator must be able to sign in
        # while frozen: containment happens through this console, and locking
        # the owner out of it meant the freeze prevented the very revocation it
        # exists to enable. Signing in grants no agent access.
        def unfrozen() -> None:
            return None

        try:
            token, _context = await authority.login(
                source=request.state.operator_source,
                challenge=operator_cookie(request.scope["headers"], CHALLENGE_COOKIE),
                csrf=fields["csrf"], password=fields["password"], guard=unfrozen,
            )
        except OperatorCapacityError:
            raise
        except OperatorAuthError:
            return _login_failure(code=401)
        response = RedirectResponse("/", status_code=303, headers=dashboard_headers())
        _cookie(response, SESSION_COOKIE, token, authority.config.operator_session_seconds)
        _clear_cookie(response, CHALLENGE_COOKIE)
        return response

    def setup_authority(request: Request) -> OperatorAuth | None:
        _require_plain_login(request)
        authority = request.app.state.operator_auth
        if isinstance(authority, OperatorAuth) and authority.setup_pending:
            return authority
        return None

    @router.get("/setup", include_in_schema=False)
    async def setup_view(request: Request) -> Response:
        if setup_authority(request) is None:
            return RedirectResponse("/login", status_code=303, headers=dashboard_headers())
        return operator_page(
            "Set the operator password",
            ui.setup_form(ca_published=bool(request.app.state.config.ca_bundle_path)),
        )

    @router.post("/setup", include_in_schema=False)
    async def setup_submit(request: Request) -> Response:
        authority = setup_authority(request)
        if authority is None:
            return RedirectResponse("/login", status_code=303, headers=dashboard_headers())
        try:
            fields = parse_form(
                await request.body(), allowed={"code", "password", "confirmation"},
                required={"code", "password", "confirmation"},
                maximum=request.app.state.config.operator_form_bytes,
            )
            await authority.complete_setup(
                source=request.state.operator_source, code=fields["code"],
                password=fields["password"], confirmation=fields["confirmation"],
            )
        except OperatorCapacityError:
            raise
        except (OperatorAuthError, ConfigurationError):
            return operator_page("Setup unsuccessful", ui.setup_failed(), code=401)
        return RedirectResponse("/login", status_code=303, headers=dashboard_headers())

    @router.get("/operator/session", include_in_schema=False)
    async def session_view(request: Request) -> Response:
        context = context_for(request)
        return operator_page(
            "Your session",
            ui.session(
                context, lifetime=request.app.state.config.operator_session_seconds,
                idle=request.app.state.config.operator_session_idle_seconds,
            ),
            request=request, active="operator",
        )

    @router.post("/logout", include_in_schema=False)
    async def logout_submit(request: Request) -> Response:
        await operator_form(request, fields=set(), required=set())
        authority_for(request).logout(context_for(request))
        response = RedirectResponse("/login", status_code=303, headers=dashboard_headers())
        _clear_cookie(response, SESSION_COOKIE)
        return response
