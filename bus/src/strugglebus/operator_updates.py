"""Human-only discovery and preparation of verified, non-executed release files."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response

from strugglebus import __version__
from strugglebus.config import AppConfig
from strugglebus.dashboard import dashboard_headers
from strugglebus.errors import DomainValidationError
from strugglebus.maintenance_client import MaintenanceClient
from strugglebus.maintenance_types import MaintenanceError
from strugglebus.operator_auth import OperatorCapacityError, OperatorContext, OperatorFormError
from strugglebus.operator_web import (
    _query, authority_for, context_for, operator_form, operator_page,
)
from strugglebus.update_client import UpdateClient
from strugglebus.update_types import UpdateCandidate, UpdateError, UpdateObservation, UpdateStatus
from strugglebus import selfhost_updates
from strugglebus import update_rendering as ui

ROOT = "/operator/updates"


def _identifier(value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise OperatorFormError("Invalid update identifier.")
    return value


@dataclass(frozen=True, slots=True)
class UpdateReview:
    review_id: str
    operation_id: str
    session_id: str = field(repr=False)
    actor_id: str
    expires_at: float
    worker_version: str
    policy_id: str
    observation: UpdateObservation
    candidate: UpdateCandidate


class UpdateConsole:
    def __init__(
        self, config: AppConfig, *, clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.client = UpdateClient(config.updater_socket_path) if config.updater_socket_path else None
        self.maintenance = (
            MaintenanceClient(config.maintenance_socket_path)
            if config.maintenance_socket_path else None
        )
        self._clock = clock
        self._wall_clock = wall_clock
        self._reviews: dict[str, UpdateReview] = {}
        self.selfhost = selfhost_updates.SelfHostUpdates.for_install(config.data_dir)

    def clear(self) -> None:
        self._reviews.clear()

    def require_client(self) -> UpdateClient:
        if self.client is None:
            raise OperatorFormError("Update discovery and preparation are not configured.")
        return self.client

    def require_maintenance(self) -> MaintenanceClient:
        if self.maintenance is None:
            raise OperatorFormError("Automatic and manual installation are not configured.")
        return self.maintenance

    def _observation(self, status: UpdateStatus) -> tuple[UpdateObservation, UpdateCandidate]:
        observation = status.observation
        if observation is None or observation.discovery.candidate is None:
            raise OperatorFormError("There is no observed candidate to review. Check releases first.")
        if status.state in {"checking", "preparing", "unavailable", "interrupted"}:
            raise OperatorFormError("The worker is not ready for a new review. Refresh its status.")
        if (
            observation.application_version != __version__
            or observation.application_release_id != self.config.release_id
            or observation.expires_at <= self._wall_clock()
        ):
            raise OperatorFormError("The observation is stale or incompatible. Check releases again.")
        return observation, observation.discovery.candidate

    def issue(self, context: OperatorContext, status: UpdateStatus) -> UpdateReview:
        observation, candidate = self._observation(status)
        self._prune()
        for review in self._reviews.values():
            if (
                review.session_id == context.session_id and review.actor_id == context.actor_id
                and review.observation == observation and review.worker_version == status.worker_version
                and review.policy_id == status.policy_id
            ):
                return review
        if len(self._reviews) >= self.config.updater_review_tickets:
            raise OperatorCapacityError("Update review capacity reached. Wait for an earlier review to expire.")
        review = UpdateReview(
            uuid4().hex, uuid4().hex, context.session_id, context.actor_id,
            self._clock() + self.config.updater_review_seconds,
            status.worker_version, status.policy_id, observation, candidate,
        )
        self._reviews[review.review_id] = review
        return review

    def require_review(self, review_id: str, context: OperatorContext) -> UpdateReview:
        self._prune()
        review = self._reviews.get(_identifier(review_id))
        if (
            review is None or review.session_id != context.session_id
            or review.actor_id != context.actor_id
            or review.observation.expires_at <= self._wall_clock()
        ):
            raise OperatorFormError("Update review is unavailable or expired. Review the current observation again.")
        return review

    def _prune(self) -> None:
        now = self._clock()
        self._reviews = {key: value for key, value in self._reviews.items() if value.expires_at > now}


def _console(request: Request) -> UpdateConsole:
    _query(request, set())
    context_for(request)
    console = request.app.state.updater
    if not isinstance(console, UpdateConsole):
        raise OperatorFormError("The update console is unavailable.")
    return console


def _page(request: Request, title: str, body: str, *, code: int = 200) -> Response:
    context_for(request)
    return operator_page(
        title, body + ui.navigation(), code=code, request=request, active="updates",
    )


def _status_path(operation_id: str) -> str:
    return ROOT + "/operations/" + _identifier(operation_id)


def _failure(request: Request, error: UpdateError, operation_id: str | None = None) -> Response:
    code = {
        "busy": 409, "conflict": 409, "history_unavailable": 409,
        "observation_expired": 409, "observation_mismatch": 409, "policy_mismatch": 409,
        "no_candidate": 409, "publication_changed": 409, "cleanup_pending": 409,
        "cooldown": 429, "rate_limited": 429, "invalid_request": 400, "forbidden": 403,
    }.get(error.code, 503)
    path = _status_path(operation_id) if operation_id is not None else None
    return _page(request, "Update operation unavailable", ui.worker_failure(error.code, path), code=code)


def _maintenance_failure(request: Request, error: MaintenanceError) -> Response:
    code = {
        "busy": 409, "conflict": 409, "paused": 409, "outside_window": 409,
        "no_candidate": 409, "invalid_request": 400, "forbidden": 403,
    }.get(error.code, 503)
    return _page(
        request,
        "Maintenance operation unavailable",
        ui.maintenance_failure(error.code),
        code=code,
    )


def _acknowledged(status: UpdateStatus, operation_id: str, action: str, actor_id: str) -> None:
    operation = status.operation
    if (
        operation is None or operation.operation_id != operation_id
        or operation.action != action or operation.actor_id != actor_id
    ):
        raise UpdateError("unknown_outcome")


def _require_review_status(review: UpdateReview, status: UpdateStatus) -> None:
    if (
        status.worker_version != review.worker_version or status.policy_id != review.policy_id
        or status.observation != review.observation
    ):
        raise OperatorFormError("The worker or observation changed. Inspect the operation receipt and review again.")


async def updates_view(request: Request) -> Response:
    console = _console(request)
    body = ""
    if await asyncio.to_thread(console.selfhost.available):
        # A self-hosted install has one control: its updater's on/off switch.
        body = await asyncio.to_thread(
            selfhost_updates.render, console.selfhost, context_for(request).csrf_token,
        )
        return _page(request, "Updates", body)
    if console.client is None:
        body += ui.disabled()
        status = None
    else:
        try:
            status = await console.client.status()
        except UpdateError as error:
            return _failure(request, error)
        body += ui.status(status) + ui.refresh(ROOT) + ui.controls(
            status, context_for(request).csrf_token,
        )
    context = context_for(request)
    if console.maintenance is None:
        body += ui.maintenance_disabled()
    else:
        try:
            maintenance = await console.maintenance.status()
        except MaintenanceError as error:
            body += ui.maintenance_failure(error.code)
        else:
            body += ui.maintenance_status(maintenance)
            body += ui.maintenance_controls(maintenance, context.csrf_token)
    return _page(request, "Updates", body)


async def automatic_toggle_submit(request: Request) -> Response:
    console = _console(request)
    fields = await operator_form(request, fields={"enabled"}, required={"enabled"})
    if fields["enabled"] not in {"true", "false"}:
        raise OperatorFormError("Invalid automatic-update setting.")
    if not await asyncio.to_thread(console.selfhost.available):
        raise OperatorFormError("This install has no automatic updater.")
    authority_for(request).require_active(context_for(request))
    try:
        await asyncio.to_thread(console.selfhost.set_enabled, fields["enabled"] == "true")
    except OSError:
        raise OperatorFormError("The setting could not be saved on the bus machine.") from None
    return RedirectResponse(ROOT, status_code=303, headers=dashboard_headers())


async def maintenance_toggle_submit(request: Request) -> Response:
    console = _console(request)
    fields = await operator_form(
        request, fields={"enabled", "password"}, required={"enabled", "password"},
    )
    if fields["enabled"] not in {"true", "false"}:
        raise OperatorFormError("Invalid automatic-update setting.")
    context = context_for(request)
    await authority_for(request).reauthenticate(
        context, fields["password"], source=request.state.operator_source,
        family="updater-confirm",
    )
    client = console.require_maintenance()
    operation_id = uuid4().hex
    try:
        current = await client.status()
        authority_for(request).require_active(context)
        await client.configure(
            operation_id,
            context.actor_id,
            enabled=fields["enabled"] == "true",
            hour=current.policy.hour,
            minute=current.policy.minute,
        )
    except MaintenanceError as error:
        return _maintenance_failure(request, error)
    return RedirectResponse(ROOT, status_code=303, headers=dashboard_headers())


async def maintenance_schedule_submit(request: Request) -> Response:
    console = _console(request)
    fields = await operator_form(
        request, fields={"hour", "minute", "password"},
        required={"hour", "minute", "password"},
    )
    try:
        hour = int(fields["hour"])
        minute = int(fields["minute"])
    except ValueError:
        raise OperatorFormError("The maintenance time is invalid.") from None
    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise OperatorFormError("The maintenance time is invalid.")
    context = context_for(request)
    await authority_for(request).reauthenticate(
        context, fields["password"], source=request.state.operator_source,
        family="updater-confirm",
    )
    client = console.require_maintenance()
    operation_id = uuid4().hex
    try:
        current = await client.status()
        authority_for(request).require_active(context)
        await client.configure(
            operation_id,
            context.actor_id,
            enabled=current.policy.enabled,
            hour=hour,
            minute=minute,
        )
    except MaintenanceError as error:
        return _maintenance_failure(request, error)
    return RedirectResponse(ROOT, status_code=303, headers=dashboard_headers())


async def maintenance_install_submit(request: Request) -> Response:
    console = _console(request)
    fields = await operator_form(
        request, fields={"password"}, required={"password"},
    )
    context = context_for(request)
    await authority_for(request).reauthenticate(
        context, fields["password"], source=request.state.operator_source,
        family="updater-confirm",
    )
    operation_id = uuid4().hex
    try:
        authority_for(request).require_active(context)
        result = await console.require_maintenance().install(
            operation_id, context.actor_id,
        )
        attempt = result.attempt
        if (
            attempt is None
            or attempt.operation_id != operation_id
            or attempt.actor_id != context.actor_id
        ):
            raise MaintenanceError("unknown_outcome")
    except MaintenanceError as error:
        return _maintenance_failure(request, error)
    return RedirectResponse(ROOT, status_code=303, headers=dashboard_headers())


async def check_submit(request: Request) -> Response:
    console = _console(request)
    await operator_form(request, fields=set(), required=set())
    client = console.require_client()
    context = context_for(request)
    operation_id = uuid4().hex
    authority_for(request).require_active(context)
    try:
        status = await client.check(operation_id, context.actor_id, __version__, console.config.release_id)
        _acknowledged(status, operation_id, "check", context.actor_id)
    except UpdateError as error:
        return _failure(request, error, operation_id)
    return RedirectResponse(_status_path(operation_id), status_code=303, headers=dashboard_headers())


async def review_view(request: Request) -> Response:
    console = _console(request)
    observation_id = _identifier(request.path_params["observation_id"])
    try:
        status = await console.require_client().status()
    except UpdateError as error:
        return _failure(request, error)
    if status.observation is None or status.observation.observation_id != observation_id:
        raise OperatorFormError("The observed release changed. Refresh and review the current observation.")
    context = context_for(request)
    review = console.issue(context, status)
    return _page(
        request, "Review release preparation",
        ui.review(review, context.csrf_token, console.config.updater_review_seconds),
    )


async def prepare_submit(request: Request) -> Response:
    console = _console(request)
    fields = await operator_form(
        request, fields={"review_id", "password"}, required={"review_id", "password"},
    )
    client = console.require_client()
    context = context_for(request)
    console.require_review(fields["review_id"], context)
    await authority_for(request).reauthenticate(
        context, fields["password"], source=request.state.operator_source, family="updater-confirm",
    )
    review = console.require_review(fields["review_id"], context)
    try:
        current = await client.status()
        review = console.require_review(fields["review_id"], context)
        _require_review_status(review, current)
        authority_for(request).require_active(context)
        status = await client.prepare(
            review.operation_id, context.actor_id, __version__, console.config.release_id,
            review.observation.observation_id, review.candidate.digest,
        )
        _acknowledged(status, review.operation_id, "prepare", context.actor_id)
    except UpdateError as error:
        return _failure(request, error, review.operation_id)
    return RedirectResponse(_status_path(review.operation_id), status_code=303, headers=dashboard_headers())


async def operation_view(request: Request) -> Response:
    console = _console(request)
    operation_id = _identifier(request.path_params["operation_id"])
    try:
        status = await console.require_client().status(operation_id)
        if status.history_available and (
            status.operation is None or status.operation.operation_id != operation_id
        ):
            raise UpdateError("unknown_outcome")
    except UpdateError as error:
        return _failure(request, error, operation_id)
    return _page(
        request, "Update operation status",
        ui.status(status) + ui.refresh(_status_path(operation_id))
        + ui.controls(status, context_for(request).csrf_token),
    )


def add_update_routes(router: APIRouter) -> None:
    for path, endpoint, methods in (
        ("", updates_view, ["GET"]),
        ("/check", check_submit, ["POST"]),
        ("/review/{observation_id}", review_view, ["GET"]),
        ("/prepare", prepare_submit, ["POST"]),
        ("/operations/{operation_id}", operation_view, ["GET"]),
        ("/automatic", automatic_toggle_submit, ["POST"]),
        ("/maintenance/toggle", maintenance_toggle_submit, ["POST"]),
        ("/maintenance/schedule", maintenance_schedule_submit, ["POST"]),
        ("/maintenance/install", maintenance_install_submit, ["POST"]),
    ):
        router.add_api_route(ROOT + path, _handled(endpoint), methods=methods, include_in_schema=False)


def _handled(function: Callable[[Request], Awaitable[Response]]) -> Callable[[Request], Awaitable[Response]]:
    async def endpoint(request: Request) -> Response:
        context_for(request)
        try:
            return await function(request)
        except (OperatorFormError, DomainValidationError) as error:
            return _page(request, "Update request refused", ui.failure(str(error), None), code=400)

    return endpoint
