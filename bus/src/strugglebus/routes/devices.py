from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse

from strugglebus.ca import der_base64, load_trust_anchor
from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    CredentialConflictError,
    DomainValidationError,
    DuplicateAgentNameError,
    StorageError,
    TrustAnchorError,
)
from strugglebus.dashboard import (
    dashboard_headers,
    render_device_enrollment,
    render_device_replacement,
    render_device_revocation,
    render_devices,
)
from strugglebus.integration import build_server_info
from strugglebus.operator_auth import (
    OperatorAuthError, OperatorCapacityError,
)
from strugglebus.operator_web import (
    authority_for,
    context_for,
    operator_form,
)
from strugglebus.service import normalize_name


def add_device_routes(router: APIRouter) -> None:
    @router.get("/devices", response_class=HTMLResponse, include_in_schema=False)
    async def devices_view(request: Request) -> HTMLResponse:
        config = request.app.state.config
        try:
            devices = await asyncio.to_thread(
                request.app.state.mobile_service.list_devices
            )
        except StorageError:
            # Never render an empty roster on failure. An operator cannot tell
            # "no devices" from "the roster could not be read", and that is the
            # same silent-failure shape the freeze contract exists to prevent.
            return await _devices_problem(
                request, "The device roster is unavailable. No device list is "
                "implied; this is not an empty roster.", 503,
            )
        return HTMLResponse(
            render_devices(
                build_server_info(config),
                devices,
                generated_at=datetime.now(UTC),
                csrf_token=context_for(request).csrf_token,
                enrollment_seconds=config.mobile_enrollment_seconds,
            ),
            headers=dashboard_headers(),
        )

    async def _devices_problem(
        request: Request,
        detail: str,
        code: int,
        *,
        label: str = "",
        notice: str | None = None,
    ) -> HTMLResponse:
        config = request.app.state.config
        try:
            devices = await asyncio.to_thread(
                request.app.state.mobile_service.list_devices
            )
        except StorageError:
            devices = ()
        return HTMLResponse(
            render_devices(
                build_server_info(config),
                devices,
                generated_at=datetime.now(UTC),
                csrf_token=context_for(request).csrf_token,
                enrollment_seconds=config.mobile_enrollment_seconds,
                error=detail if notice is None else None,
                notice=notice,
                label=label,
            ),
            status_code=code,
            headers=dashboard_headers(),
        )

    async def _device_anchor(request: Request) -> str:
        config = request.app.state.config
        anchor = await asyncio.to_thread(
            load_trust_anchor, config.ca_bundle_path, config.ca_root_sha256
        )
        if anchor is None or not config.ca_root_sha256:
            raise TrustAnchorError(
                "A published LAN CA root is required before a device can "
                "trust this service."
            )
        return der_base64(anchor)

    def _device_payload(
        request: Request, *, label: str, token: str, expires_at: datetime, ca_der: str,
    ) -> str:
        config = request.app.state.config
        return json.dumps(
            {
                "version": 1,
                "base_url": config.public_base_url,
                "ca_der": ca_der,
                "ca_sha256": config.ca_root_sha256,
                "device_label": label,
                "enrollment": token,
                "expires_at": expires_at.astimezone(UTC).isoformat(),
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )

    def _enrollment_response(
        request: Request,
        *,
        label: str,
        payload: str,
        expires_at: datetime,
        replaced_label: str | None = None,
    ) -> HTMLResponse:
        return HTMLResponse(
            render_device_enrollment(
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
                device_label=label,
                payload=payload,
                expires_at=expires_at,
                replaced_label=replaced_label,
                enrollment_seconds=(
                    request.app.state.config.mobile_enrollment_seconds
                ),
            ),
            status_code=status.HTTP_201_CREATED,
            headers={
                **dashboard_headers(), "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
            },
        )

    @router.post("/devices", response_class=HTMLResponse, include_in_schema=False)
    async def devices_enroll(request: Request) -> HTMLResponse:
        config = request.app.state.config
        fields = await operator_form(
            request,
            fields={"label", "password", "confirm"},
            required={"label", "password", "confirm"},
        )
        label = fields.get("label", "").strip()
        if fields.get("confirm") != "enroll":
            return await _devices_problem(
                request, "Explicit confirmation is required.", 422, label=label,
            )
        try:
            canonical = normalize_name(label)
        except DomainValidationError:
            return await _devices_problem(
                request,
                "Device labels are lowercase kebab-case, for example "
                "owner-phone.",
                422,
                label=label,
            )
        # The password is proved in this request, immediately before the code
        # is rendered. Nothing is remembered, so there is no window in which a
        # later request counts as recently reauthenticated.
        try:
            await authority_for(request).reauthenticate(
                context_for(request),
                fields["password"],
                source=request.state.operator_source,
            )
        except OperatorCapacityError:
            return await _devices_problem(
                request, "Too many enrollment attempts. Wait, then retry.",
                429, label=label,
            )
        except OperatorAuthError:
            return await _devices_problem(
                request, "Reauthentication failed. No enrollment was created.",
                401, label=label,
            )
        try:
            ca_der = await _device_anchor(request)
        except TrustAnchorError as error:
            return await _devices_problem(request, str(error), 503, label=canonical)
        try:
            token, expires_at = await asyncio.to_thread(
                request.app.state.mobile_service.mint_enrollment,
                device_label=canonical,
                ttl_seconds=config.mobile_enrollment_seconds,
                actor_id=context_for(request).actor_id,
            )
        except DuplicateAgentNameError:
            return await _devices_problem(
                request,
                "That label is already registered. Labels stay reserved even "
                "after revocation.",
                409,
                label=canonical,
            )
        except DomainValidationError as error:
            return await _devices_problem(request, str(error), 422, label=canonical)
        except AgentAccessFrozenError:
            return await _devices_problem(
                request, "Agent access is frozen.", 503, label=canonical,
            )
        except StorageError:
            return await _devices_problem(
                request, "The service could not create an enrollment.", 503,
                label=canonical,
            )
        return _enrollment_response(
            request,
            label=canonical,
            payload=_device_payload(
                request, label=canonical, token=token,
                expires_at=expires_at, ca_der=ca_der,
            ),
            expires_at=expires_at,
        )

    async def _enabled_device(request: Request, device_id: str) -> dict[str, object]:
        try:
            if str(UUID(device_id)) != device_id:
                raise ValueError
        except ValueError:
            raise DomainValidationError("canonical device identity required") from None
        devices = await asyncio.to_thread(
            request.app.state.mobile_service.list_devices
        )
        for device in devices:
            if device.get("id") == device_id and device.get("status") == "enabled":
                return device
        raise AgentNotFoundError("device is unavailable")

    @router.get(
        "/devices/{device_id}/revoke",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def device_revoke_view(request: Request, device_id: str) -> HTMLResponse:
        try:
            device = await _enabled_device(request, device_id)
        except DomainValidationError:
            return await _devices_problem(request, "Invalid device identity.", 422)
        except AgentNotFoundError:
            return await _devices_problem(
                request, "That device is unavailable or already revoked.", 404,
            )
        except StorageError:
            return await _devices_problem(
                request, "The device roster is unavailable.", 503,
            )
        return HTMLResponse(
            render_device_revocation(
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
                csrf_token=context_for(request).csrf_token,
                device_id=device_id,
                device_label=str(device.get("label", "")),
            ),
            headers=dashboard_headers(),
        )

    @router.post(
        "/devices/{device_id}/revoke",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def device_revoke_submit(request: Request, device_id: str) -> HTMLResponse:
        fields = await operator_form(
            request,
            fields={"label", "reason", "confirm"},
            required={"label", "reason", "confirm"},
        )
        try:
            device = await _enabled_device(request, device_id)
        except DomainValidationError:
            return await _devices_problem(request, "Invalid device identity.", 422)
        except AgentNotFoundError:
            return await _devices_problem(
                request, "That device is unavailable or already revoked.", 404,
            )
        except StorageError:
            return await _devices_problem(
                request, "The device roster is unavailable.", 503,
            )
        if fields.get("confirm") != "revoke" or fields.get("label") != device.get(
            "label"
        ):
            return await _devices_problem(
                request,
                "Exact label confirmation is required. Nothing was revoked.",
                422,
            )
        reason = fields.get("reason", "").strip()
        if not reason or len(reason) > 256:
            return await _devices_problem(
                request, "A bounded, non-secret reason is required.", 422,
            )
        try:
            revoked = await asyncio.to_thread(
                request.app.state.mobile_service.revoke_device,
                device_id,
                reason=reason,
                actor_id=context_for(request).actor_id,
            )
        except StorageError:
            return await _devices_problem(
                request, "The revocation is unavailable. No action is implied.",
                503,
            )
        if not revoked:
            return await _devices_problem(
                request, "That device changed state. Reload before retrying.", 409,
            )
        return await _devices_problem(
            request,
            "",
            200,
            notice=(
                f"Revoked {device.get('label', '')}. Every key it held is now "
                "unusable, including any open stream."
            ),
        )

    @router.get(
        "/devices/{device_id}/replace",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def device_replace_view(request: Request, device_id: str) -> HTMLResponse:
        try:
            device = await _enabled_device(request, device_id)
        except DomainValidationError:
            return await _devices_problem(request, "Invalid device identity.", 422)
        except AgentNotFoundError:
            return await _devices_problem(
                request, "That device is unavailable or already revoked.", 404,
            )
        except StorageError:
            return await _devices_problem(
                request, "The device roster is unavailable.", 503,
            )
        return HTMLResponse(
            render_device_replacement(
                build_server_info(request.app.state.config),
                generated_at=datetime.now(UTC),
                csrf_token=context_for(request).csrf_token,
                device_id=device_id,
                device_label=str(device.get("label", "")),
                enrollment_seconds=(
                    request.app.state.config.mobile_enrollment_seconds
                ),
            ),
            headers=dashboard_headers(),
        )

    @router.post(
        "/devices/{device_id}/replace",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def device_replace_submit(request: Request, device_id: str) -> HTMLResponse:
        config = request.app.state.config
        fields = await operator_form(
            request,
            fields={"label", "new_label", "password", "reason", "confirm"},
            required={"label", "new_label", "password", "reason", "confirm"},
        )
        try:
            device = await _enabled_device(request, device_id)
        except DomainValidationError:
            return await _devices_problem(request, "Invalid device identity.", 422)
        except AgentNotFoundError:
            return await _devices_problem(
                request, "That device is unavailable or already revoked.", 404,
            )
        except StorageError:
            return await _devices_problem(
                request, "The device roster is unavailable.", 503,
            )
        label = str(device.get("label", ""))

        def problem(detail: str, code: int, *, new_label: str = "") -> HTMLResponse:
            return HTMLResponse(
                render_device_replacement(
                    build_server_info(config),
                    generated_at=datetime.now(UTC),
                    csrf_token=context_for(request).csrf_token,
                    device_id=device_id,
                    device_label=label,
                    enrollment_seconds=config.mobile_enrollment_seconds,
                    error=detail,
                    new_label=new_label,
                ),
                status_code=code,
                headers=dashboard_headers(),
            )

        requested = fields.get("new_label", "").strip()
        if fields.get("confirm") != "replace" or fields.get("label") != label:
            return problem(
                "Exact label confirmation is required. Nothing was changed.",
                422,
                new_label=requested,
            )
        reason = fields.get("reason", "").strip()
        if not reason or len(reason) > 256:
            return problem(
                "A bounded, non-secret reason is required.", 422, new_label=requested,
            )
        try:
            canonical = normalize_name(requested)
        except DomainValidationError:
            return problem(
                "Device labels are lowercase kebab-case, for example "
                "owner-phone-two.",
                422,
                new_label=requested,
            )
        if canonical == label:
            return problem(
                "A label is permanently reserved, so a replacement needs a new "
                "one. Reusing it would reattribute the retired device's "
                "history.",
                409,
                new_label=requested,
            )
        try:
            await authority_for(request).reauthenticate(
                context_for(request),
                fields["password"],
                source=request.state.operator_source,
            )
        except OperatorCapacityError:
            return problem(
                "Too many enrollment attempts. Wait, then retry.",
                429,
                new_label=canonical,
            )
        except OperatorAuthError:
            return problem(
                "Reauthentication failed. Nothing was revoked or created.",
                401,
                new_label=canonical,
            )
        # The anchor is resolved before the write, so a deployment without one
        # cannot revoke a working device and then fail to issue its successor.
        try:
            ca_der = await _device_anchor(request)
        except TrustAnchorError as error:
            return problem(str(error), 503, new_label=canonical)
        try:
            token, expires_at, replaced = await asyncio.to_thread(
                request.app.state.mobile_service.replace_device,
                device_id,
                new_label=canonical,
                ttl_seconds=config.mobile_enrollment_seconds,
                actor_id=context_for(request).actor_id,
                reason=reason,
            )
        except DuplicateAgentNameError:
            return problem(
                "That label is already registered. Labels stay reserved even "
                "after revocation.",
                409,
                new_label=canonical,
            )
        except CredentialConflictError:
            return problem(
                "That device changed state. Reload before retrying.",
                409,
                new_label=canonical,
            )
        except DomainValidationError as error:
            return problem(str(error), 422, new_label=canonical)
        except AgentAccessFrozenError:
            return problem("Agent access is frozen.", 503, new_label=canonical)
        except StorageError:
            return problem(
                "The replacement is unavailable. No action is implied.",
                503,
                new_label=canonical,
            )
        return _enrollment_response(
            request,
            label=canonical,
            payload=_device_payload(
                request, label=canonical, token=token,
                expires_at=expires_at, ca_der=ca_der,
            ),
            expires_at=expires_at,
            replaced_label=replaced,
        )
