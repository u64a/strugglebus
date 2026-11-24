"""Disposable HTTPS contract mock for the StruggleApp research POC.

This is not a StruggleBus implementation. It models only the proposed mobile
wire contract and uses synthetic, in-memory state. Control routes bind to the
same loopback-only listener and exist solely for deterministic POC testing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def secret(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"


def verifier(value: str) -> str:
    return hashlib.sha256(("struggleapp-mock-v1\0" + value).encode()).hexdigest()


@dataclass
class MockState:
    lock: threading.RLock = field(default_factory=threading.RLock)
    frozen: bool = False
    revoked: bool = False
    terminal_event: str | None = None
    freeze_after_sequence: int | None = None
    active_streams: int = 0
    authentication_writes: int = 0
    last_used_at: str | None = None
    last_auth_write_monotonic: float | None = None
    enrollment_token: str = field(default_factory=lambda: secret("sbme1"))
    enrollment_expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=5)
    )
    enrollment_consumed: bool = False
    credential_verifier: str | None = None
    grant_verifier: str | None = None
    device: dict | None = None
    redemptions: dict[str, dict] = field(default_factory=dict)
    confirmations: dict[str, dict] = field(default_factory=dict)
    blocked_agents: set[str] = field(default_factory=set)
    managed_agents: dict[str, dict] = field(default_factory=lambda: {
        "agent-example": {"name": "example-agent", "host": "mock-host", "state": "enabled", "epoch": 1},
        "agent-maintainer": {"name": "maintainer-agent", "host": "mock-host", "state": "blocked", "epoch": 4},
        "agent-old": {"name": "old-runner", "host": "retired-host", "state": "retired", "epoch": 7},
    })
    managed_spns: dict[str, dict] = field(default_factory=lambda: {
        "spn-nightly": {"name": "nightly-audit", "prefix": "audit-worker", "status": "enabled", "version": 1},
    })
    messages: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.messages:
            self.messages.extend(
                [
                    {
                        "seq": 1,
                        "id": str(uuid4()),
                        "channel": "announce",
                        "agent_id": "agent-example",
                        "agent_name": "example-agent",
                        "body": "Synthetic mock activity",
                        "kind": "status",
                        "reply_to": None,
                        "created_at": utc_now(),
                    },
                    {
                        "seq": 2,
                        "id": str(uuid4()),
                        "channel": "status",
                        "agent_id": "agent-maintainer",
                        "agent_name": "maintainer-agent",
                        "body": "Synthetic service heartbeat",
                        "kind": "status",
                        "reply_to": None,
                        "created_at": utc_now(),
                    },
                ]
            )


class MobileMockHandler(BaseHTTPRequestHandler):
    server_version = "StruggleAppContractMock/1"
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> MockState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:
        # Deliberately omit headers and bodies so test credentials cannot leak.
        print(f"{self.address_string()} - {format % args}")

    def _json_body(self) -> dict:
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            # .NET's JsonContent streams without a Content-Length.
            raw = b""
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                raw += self.rfile.read(size)
                self.rfile.readline()
                if len(raw) > 16_384:
                    raise ValueError("request body too large")
        else:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16_384:
                raise ValueError("request body too large")
            raw = self.rfile.read(length)
        return json.loads(raw) if raw else {}

    def _send_json(
        self,
        status: int,
        payload: object,
        *,
        no_store: bool = False,
        headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if no_store or status >= 400:
            self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _bearer(self) -> str | None:
        value = self.headers.get("Authorization", "")
        return value[7:] if value.startswith("Bearer ") else None

    def _mobile_authenticated(self) -> bool:
        token = self._bearer()
        with self.state.lock:
            authenticated = bool(
                token
                and self.state.credential_verifier
                and not self.state.revoked
                and secrets.compare_digest(verifier(token), self.state.credential_verifier)
            )
            if authenticated:
                now = time.monotonic()
                if (
                    self.state.last_auth_write_monotonic is None
                    or now - self.state.last_auth_write_monotonic >= 60
                ):
                    self.state.authentication_writes += 1
                    self.state.last_used_at = utc_now()
                    self.state.last_auth_write_monotonic = now
            return authenticated

    def _require_mobile(self) -> bool:
        if self._mobile_authenticated():
            return True
        self._send_json(
            HTTPStatus.UNAUTHORIZED,
            {"detail": "invalid or inactive credential"},
            headers={"WWW-Authenticate": "Bearer"},
        )
        return False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
        elif parsed.path == "/__control/enrollment":
            self._get_control_enrollment()
        elif parsed.path == "/__control/diagnostics":
            self._get_control_diagnostics()
        elif parsed.path == "/api/mobile/status":
            self._get_status()
        elif parsed.path == "/api/mobile/snapshot":
            self._get_snapshot(parse_qs(parsed.query))
        elif parsed.path == "/api/mobile/channels":
            self._get_channels()
        elif parsed.path == "/api/mobile/agents":
            self._get_agents()
        elif parsed.path == "/api/mobile/admin/agents":
            self._get_admin_agents(parse_qs(parsed.query))
        elif parsed.path == "/api/mobile/admin/devices":
            self._get_admin_devices()
        elif parsed.path == "/api/mobile/admin/service-principals":
            self._get_admin_spns()
        elif parsed.path == "/api/mobile/admin/logs":
            self._get_admin_logs(parse_qs(parsed.query))
        elif parsed.path == "/api/mobile/stream":
            self._get_stream(parse_qs(parsed.query))
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"detail": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            body = self._json_body()
        except (ValueError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "malformed request"})
            return
        if parsed.path == "/api/mobile/enrollments/redeem":
            self._redeem(body)
        elif parsed.path == "/api/mobile/grants":
            self._establish_grant(body)
        elif parsed.path == "/api/mobile/confirmations":
            self._request_confirmation(body)
        elif parsed.path == "/api/mobile/actions":
            self._perform_action(body)
        elif parsed.path.startswith("/api/mobile/admin/agents/") and parsed.path.endswith("/control"):
            self._admin_control(body, parsed.path.split("/")[5], agents=True)
        elif parsed.path.startswith("/api/mobile/admin/service-principals/") and parsed.path.endswith("/control"):
            self._admin_control(body, parsed.path.split("/")[5], agents=False)
        elif parsed.path == "/__control/state":
            self._set_control_state(body)
        elif parsed.path == "/__control/messages":
            self._add_control_message(body)
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"detail": "not found"})

    def _get_control_diagnostics(self) -> None:
        with self.state.lock:
            payload = {
                "active_streams": self.state.active_streams,
                "authentication_writes": self.state.authentication_writes,
            }
        self._send_json(HTTPStatus.OK, payload, no_store=True)

    def _get_control_enrollment(self) -> None:
        with self.state.lock:
            payload = {
                "version": 1,
                "base_url": self.server.public_endpoint,  # type: ignore[attr-defined]
                "ca_der": self.server.ca_der_b64,  # type: ignore[attr-defined]
                "ca_sha256": self.server.ca_sha256,  # type: ignore[attr-defined]
                "device_label": "Test phone",
                "enrollment": self.state.enrollment_token,
                "expires_at": self.state.enrollment_expires_at.isoformat().replace("+00:00", "Z"),
            }
        self._send_json(HTTPStatus.OK, payload, no_store=True)

    def _redeem(self, body: dict) -> None:
        token = self._bearer()
        required = {"request_id"}
        if set(body) != required or not all(isinstance(body.get(key), str) for key in required):
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "malformed request"})
            return
        with self.state.lock:
            # Deliberately NOT idempotent. The deployed server verifies the token and its
            # remaining-use count before any request-id lookup, and stores only a one-way
            # hash of the issued secret, so a redeemed enrollment can never be replayed.
            valid = (
                token
                and not self.state.enrollment_consumed
                and datetime.now(timezone.utc) < self.state.enrollment_expires_at
                and secrets.compare_digest(token, self.state.enrollment_token)
            )
            if not valid:
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"detail": "enrollment token is no longer available"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
                return
            mobile_credential = secret("sbm1")
            device = {
                "id": str(uuid4()),
                "label": "Test phone",
                "status": "active",
                "created_at": utc_now(),
            }
            self.state.enrollment_consumed = True
            self.state.credential_verifier = verifier(mobile_credential)
            self.state.device = device
            self.state.redemptions[body["request_id"]] = device
        self._send_json(
            HTTPStatus.CREATED,
            {
                "device_id": device["id"],
                "device_label": device["label"],
                "credential_id": "mobile-credential-1",
                "credential_secret": mobile_credential,
                "guidance": "Store this credential securely; it is returned once.",
            },
            no_store=True,
        )

    def _establish_grant(self, body: dict) -> None:
        if not self._require_mobile():
            return
        if set(body) != {"request_id", "operator_password", "reason"} or not all(
            isinstance(value, str) and value.strip() for value in body.values()
        ):
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid grant request"})
            return
        with self.state.lock:
            if self.state.frozen:
                self._send_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"detail": "agent access is frozen"},
                )
                return
            if not secrets.compare_digest(body["operator_password"], "correct horse battery staple"):
                self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "operator password is not valid"})
                return
            grant = secret("sbmg1")
            self.state.grant_verifier = verifier(grant)
            device_id = self.state.device["id"] if self.state.device else ""
        self._send_json(
            HTTPStatus.CREATED,
            {
                "device_id": device_id,
                "grant_secret": grant,
                "guidance": "Store this grant behind user-presence protected device storage.",
            },
            no_store=True,
        )

    def _request_confirmation(self, body: dict) -> None:
        if not self._require_mobile():
            return
        if set(body) != {"request_id", "action", "target_id"} or not all(
            isinstance(value, str) and value.strip() for value in body.values()
        ):
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid confirmation request"})
            return
        action = body["action"]
        target_id = body["target_id"]
        allowed = {"revoke-device", "block-agent", "activate-freeze", "clear-freeze"}
        if action not in allowed:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "action is not available to a device"})
            return
        with self.state.lock:
            if action in {"activate-freeze", "clear-freeze"}:
                if target_id != "global":
                    self._send_json(HTTPStatus.NOT_FOUND, {"detail": "target not found"})
                    return
                target_kind, target_label = "system", "agent access"
                actionable = (action == "activate-freeze" and not self.state.frozen) or (
                    action == "clear-freeze" and self.state.frozen
                )
            elif action == "block-agent":
                agents = {agent["id"]: agent for agent in self._agents()}
                target = agents.get(target_id)
                if target is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"detail": "target not found"})
                    return
                target_kind, target_label = "agent", target["name"]
                actionable = target_id not in self.state.blocked_agents
            else:
                target = self.state.device
                if target is None or target_id != target["id"]:
                    self._send_json(HTTPStatus.NOT_FOUND, {"detail": "target not found"})
                    return
                target_kind, target_label = "device", target["label"]
                actionable = not self.state.revoked
            if not actionable:
                self._send_json(HTTPStatus.CONFLICT, {"detail": "target is not in an actionable state"})
                return
            confirmation_id = secret("sbmc1")
            expires = datetime.now(timezone.utc) + timedelta(seconds=60)
            effect = {
                "activate-freeze": "Freeze all agent access while monitor and operator controls remain available.",
                "clear-freeze": "Restore agent access after the active global freeze.",
                "block-agent": f"Block agent {target_label} from coordinating until a console operator unblocks it.",
                "revoke-device": f"Revoke monitor device {target_label} and its write grant immediately.",
            }[action]
            confirmation = {
                "confirmation_id": confirmation_id,
                "action": action,
                "target_kind": target_kind,
                "target_id": target_id,
                "target_label": target_label,
                "expires_at": expires.isoformat().replace("+00:00", "Z"),
                "effect": effect,
                "expires": expires,
            }
            self.state.confirmations[confirmation_id] = confirmation
        self._send_json(
            HTTPStatus.CREATED,
            {key: value for key, value in confirmation.items() if key != "expires"},
            no_store=True,
        )

    def _perform_action(self, body: dict) -> None:
        if not self._require_mobile():
            return
        required = {
            "request_id", "confirmation_id", "action", "target_id", "grant_secret", "reason"
        }
        if set(body) != required or not all(
            isinstance(value, str) and value.strip() for value in body.values()
        ):
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid action request"})
            return
        with self.state.lock:
            grant_valid = bool(
                self.state.grant_verifier
                and secrets.compare_digest(verifier(body["grant_secret"]), self.state.grant_verifier)
            )
            if not grant_valid:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "write grant is not valid"})
                return
            confirmation = self.state.confirmations.pop(body["confirmation_id"], None)
            if (
                confirmation is None
                or datetime.now(timezone.utc) >= confirmation["expires"]
                or confirmation["action"] != body["action"]
                or confirmation["target_id"] != body["target_id"]
            ):
                self._send_json(HTTPStatus.CONFLICT, {"detail": "confirmation does not match this action"})
                return
            action = body["action"]
            target_id = body["target_id"]
            if action == "activate-freeze":
                self.state.frozen = True
            elif action == "clear-freeze":
                self.state.frozen = False
            elif action == "block-agent":
                self.state.blocked_agents.add(target_id)
            elif action == "revoke-device":
                self.state.revoked = True
                self.state.grant_verifier = None
            detail = f"{action} applied to {confirmation['target_label']}"
        self._send_json(
            HTTPStatus.OK,
            {
                "action": action,
                "target_id": target_id,
                "target_label": confirmation["target_label"],
                "applied": True,
                "detail": detail,
            },
            no_store=True,
        )

    def _get_status(self) -> None:
        if not self._require_mobile():
            return
        with self.state.lock:
            state = "frozen" if self.state.frozen else "available"
        self._send_json(
            HTTPStatus.OK,
            {"api_version": 1, "server_time": utc_now(), "state": state},
        )

    def _get_snapshot(self, query: dict[str, list[str]]) -> None:
        if not self._require_mobile():
            return
        try:
            limit = int(query.get("limit", ["100"])[0])
        except ValueError:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid limit"})
            return
        if not 1 <= limit <= 200:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid limit"})
            return
        with self.state.lock:
            payload = self.state.messages[-limit:]
        self._send_json(HTTPStatus.OK, payload)

    def _get_channels(self) -> None:
        if not self._require_mobile():
            return
        self._send_json(HTTPStatus.OK, self._channels())

    def _get_agents(self) -> None:
        if not self._require_mobile():
            return
        self._send_json(HTTPStatus.OK, self._agents())

    # ---- Operator management (StruggleBus 0.2.64) ---------------------------------------------

    _AGENT_ACTIONS = {"enabled": ("block", "retire"), "blocked": ("unblock", "retire")}
    _SPN_ACTIONS = {"enabled": ("block", "rotate", "revoke"), "blocked": ("unblock", "revoke")}
    _AGENT_RESULT = {"block": "blocked", "unblock": "enabled", "retire": "retired"}
    _SPN_RESULT = {"block": "blocked", "unblock": "enabled", "revoke": "revoked", "rotate": None}

    @staticmethod
    def _options(actions: tuple[str, ...]) -> list[dict]:
        return [{"action": action, "effect": f"Mock effect of {action}."} for action in actions]

    def _get_admin_agents(self, query: dict[str, list[str]]) -> None:
        if not self._require_mobile():
            return
        wanted = query.get("state", ["managed"])[0]
        if wanted not in {"managed", "enabled", "blocked", "retired", "all"}:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid managed roster query"})
            return
        after = query.get("after", [""])[0]
        with self.state.lock:
            rows = [
                {
                    "id": agent_id,
                    "name": agent["name"],
                    "description": "Synthetic test agent",
                    "host": agent["host"],
                    "state": agent["state"],
                    "credential_epoch": agent["epoch"],
                    "created_at": utc_now(),
                    "last_seen_at": None if agent["state"] == "retired" else utc_now(),
                    "blocked_at": utc_now() if agent["state"] == "blocked" else None,
                    "retired_at": utc_now() if agent["state"] == "retired" else None,
                    "actions": self._options(self._AGENT_ACTIONS.get(agent["state"], ())),
                }
                for agent_id, agent in self.state.managed_agents.items()
                if agent["name"] > after
                and (
                    wanted == "all"
                    or agent["state"] == wanted
                    or (wanted == "managed" and agent["state"] != "retired")
                )
            ]
        self._send_json(HTTPStatus.OK, sorted(rows, key=lambda row: row["name"]))

    def _get_admin_devices(self) -> None:
        if not self._require_mobile():
            return
        with self.state.lock:
            device = self.state.device or {}
            rows = [
                {
                    "id": device.get("id", "device-mock"),
                    "label": device.get("label", "test-phone"),
                    "status": "enabled",
                    "created_at": utc_now(),
                    "last_seen_at": utc_now(),
                    "revoked_at": None,
                    "has_write_grant": self.state.grant_verifier is not None,
                    "this_device": True,
                    "actions": self._options(("revoke-device",)),
                },
                {
                    "id": "device-lost",
                    "label": "lost-tablet",
                    "status": "revoked",
                    "created_at": utc_now(),
                    "last_seen_at": None,
                    "revoked_at": utc_now(),
                    "has_write_grant": False,
                    "this_device": False,
                    "actions": [],
                },
            ]
        self._send_json(HTTPStatus.OK, rows)

    def _get_admin_spns(self) -> None:
        if not self._require_mobile():
            return
        with self.state.lock:
            rows = [
                {
                    "id": spn_id,
                    "name": spn["name"],
                    "agent_name_prefix": spn["prefix"],
                    "status": spn["status"],
                    "version": spn["version"],
                    "created_at": utc_now(),
                    "blocked_at": utc_now() if spn["status"] == "blocked" else None,
                    "revoked_at": utc_now() if spn["status"] == "revoked" else None,
                    "actions": self._options(self._SPN_ACTIONS.get(spn["status"], ())),
                }
                for spn_id, spn in self.state.managed_spns.items()
            ]
        self._send_json(HTTPStatus.OK, rows)

    def _get_admin_logs(self, query: dict[str, list[str]]) -> None:
        """Operator log view (StruggleBus 0.2.65): audit, request and server lines, newest first."""
        if not self._require_mobile():
            return
        try:
            limit = int(query.get("limit", ["200"])[0])
        except ValueError:
            limit = 0
        if not 1 <= limit <= 500:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid limit"})
            return
        now = utc_now()

        def entry(source, level, event, detail, **extra):
            return {
                "ts": now, "source": source, "level": level, "event": event,
                "subject": None, "actor": None, "status": None, "remote_address": None,
                "detail": detail, **extra,
            }

        entries = [
            entry("request", "warning", "POST /api/mobile/grants", "refused", status=401, remote_address="192.0.2.7"),
            entry("audit", "info", "blocked", "agent lifecycle", subject="maintainer-agent", actor="remote-admin:device:test-phone"),
            entry("server", "error", "uvicorn.error", "Exception in ASGI application (StorageError: database is locked)"),
            entry("server", "info", "uvicorn.error", "Application startup complete."),
        ]
        self._send_json(
            HTTPStatus.OK,
            {"version": "0.2.65", "started_at": self.server.started_at, "entries": entries[:limit]},  # type: ignore[attr-defined]
        )

    def _admin_control(self, body: dict, target_id: str, *, agents: bool) -> None:
        if not self._require_mobile():
            return
        version_key = "expected_credential_epoch" if agents else "expected_version"
        required = {"request_id", "action", "expected_name", version_key, "reason", "grant_secret"}
        if (
            set(body) != required
            or type(body[version_key]) is not int
            or not all(isinstance(body[key], str) and body[key].strip() for key in required - {version_key})
        ):
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid control request"})
            return
        with self.state.lock:
            if not (
                self.state.grant_verifier
                and secrets.compare_digest(verifier(body["grant_secret"]), self.state.grant_verifier)
            ):
                self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "write grant is not valid for this device"})
                return
            targets = self.state.managed_agents if agents else self.state.managed_spns
            state_key, current_key = ("state", "epoch") if agents else ("status", "version")
            allowed = self._AGENT_ACTIONS if agents else self._SPN_ACTIONS
            results = self._AGENT_RESULT if agents else self._SPN_RESULT
            target = targets.get(target_id)
            if target is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"detail": "target not found"})
                return
            action = body["action"]
            if action not in results:
                self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid action"})
                return
            if (
                target["name"] != body["expected_name"]
                or target[current_key] != body[version_key]
                or action not in allowed.get(target[state_key], ())
            ):
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"detail": "The target changed or a limit was reached. Reload the list before trying again."},
                )
                return
            if action in {"unblock"} and self.state.frozen:
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"detail": "agent access is frozen"})
                return
            target[current_key] += 1
            if results[action] is not None:
                target[state_key] = results[action]
            minted = secret("sbs1") if action == "rotate" else None
            payload = {
                "action": action,
                "target_id": target_id,
                "target_label": target["name"],
                "applied": True,
                "state": target[state_key],
                "detail": f"Mock: now {target[state_key]}.",
                "secret": minted,
                "secret_kind": "service-principal-credential" if minted else None,
            }
        self._send_json(HTTPStatus.OK, payload, no_store=True)

    def _get_stream(self, query: dict[str, list[str]]) -> None:
        if not self._require_mobile():
            return
        try:
            since = int(query.get("since", ["0"])[0])
            last_event_id = int(self.headers.get("Last-Event-ID", "0"))
            cursor = max(0, since, last_event_id)
        except ValueError:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "invalid cursor"})
            return
        channel = query.get("channel", [None])[0]
        with self.state.lock:
            if self.state.active_streams >= 3:
                self._send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"detail": "concurrent stream limit exceeded"},
                    headers={"Retry-After": "1"},
                )
                return
            self.state.active_streams += 1
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            deadline = time.monotonic() + self.server.stream_seconds  # type: ignore[attr-defined]
            sent = cursor
            while time.monotonic() < deadline:
                with self.state.lock:
                    revoked = self.state.revoked
                    terminal_event = self.state.terminal_event
                    pending = [
                        message for message in self.state.messages
                        if message["seq"] > sent and (channel is None or message["channel"] == channel)
                    ]
                if revoked:
                    self._write_event("credential_inactive", {"detail": "mobile credential is inactive"})
                    return
                if terminal_event:
                    self._write_event(terminal_event, {"detail": terminal_event.replace("_", " ")})
                    return
                for message in pending:
                    # Re-check credential and availability before each serialized message.
                    with self.state.lock:
                        revoked = self.state.revoked
                        terminal_event = self.state.terminal_event
                    if revoked:
                        self._write_event("credential_inactive", {"detail": "mobile credential is inactive"})
                        return
                    if terminal_event:
                        self._write_event(terminal_event, {"detail": terminal_event.replace("_", " ")})
                        return
                    self._write_event("message", message, event_id=message["seq"])
                    sent = max(sent, message["seq"])
                    with self.state.lock:
                        if self.state.freeze_after_sequence == sent:
                            self.state.frozen = True
                self.wfile.write(b": heartbeat\n\n")
                self.wfile.flush()
                time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            with self.state.lock:
                self.state.active_streams -= 1

    def _write_event(self, event: str, payload: dict, event_id: int | None = None) -> None:
        if event_id is not None:
            self.wfile.write(f"id: {event_id}\n".encode())
        self.wfile.write(f"event: {event}\n".encode())
        data = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
        self.wfile.write(("data: " + data + "\n\n").encode())
        self.wfile.flush()

    def _set_control_state(self, body: dict) -> None:
        allowed = {"frozen", "revoked", "terminal_event", "freeze_after_sequence"}
        terminal_events = {
            None,
            "agent_access_frozen",
            "credential_inactive",
            "roe_acknowledgement_required",
            "agent_access_unavailable",
            "server_stopping",
        }
        if not set(body).issubset(allowed):
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "malformed request"})
            return
        if any(key in body and not isinstance(body[key], bool) for key in ("frozen", "revoked")):
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "malformed request"})
            return
        if body.get("terminal_event") not in terminal_events:
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "malformed request"})
            return
        freeze_after = body.get("freeze_after_sequence")
        if freeze_after is not None and (not isinstance(freeze_after, int) or freeze_after < 0):
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "malformed request"})
            return
        with self.state.lock:
            if "frozen" in body:
                self.state.frozen = body["frozen"]
            if "revoked" in body:
                self.state.revoked = body["revoked"]
            if "terminal_event" in body:
                self.state.terminal_event = body["terminal_event"]
            if "freeze_after_sequence" in body:
                self.state.freeze_after_sequence = freeze_after
        self._send_json(
            HTTPStatus.OK,
            {
                "frozen": self.state.frozen,
                "revoked": self.state.revoked,
                "terminal_event": self.state.terminal_event,
            },
        )

    def _add_control_message(self, body: dict) -> None:
        if set(body) != {"channel", "body"} or not all(isinstance(value, str) for value in body.values()):
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "malformed request"})
            return
        with self.state.lock:
            seq = self.state.messages[-1]["seq"] + 1 if self.state.messages else 1
            message = {
                "seq": seq,
                "id": str(uuid4()),
                "channel": body["channel"],
                "agent_id": "agent-control",
                "agent_name": "control-fixture",
                "body": body["body"],
                "kind": "chat",
                "reply_to": None,
                "created_at": utc_now(),
            }
            self.state.messages.append(message)
        self._send_json(HTTPStatus.CREATED, message)

    @staticmethod
    def _channels() -> list[dict]:
        created_at = utc_now()
        return [
            {
                "id": "channel-announce",
                "name": "announce",
                "purpose": "Announcements",
                "created_at": created_at,
                "created_by": None,
            },
            {
                "id": "channel-status",
                "name": "status",
                "purpose": "Agent status",
                "created_at": created_at,
                "created_by": None,
            },
        ]

    @staticmethod
    def _agents() -> list[dict]:
        return [
            {
                "id": "agent-example",
                "name": "example-agent",
                "description": "Synthetic test agent",
                "host": "mock-host",
                "created_at": utc_now(),
                "last_seen_at": utc_now(),
                "credential_epoch": 1,
            }
        ]


class MobileMockServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        public_endpoint: str,
        ca_sha256: str,
        ca_der_b64: str = "",
        stream_seconds: float = 3.0,
    ) -> None:
        super().__init__(address, MobileMockHandler)
        self.state = MockState()
        self.public_endpoint = public_endpoint
        self.ca_sha256 = ca_sha256
        self.ca_der_b64 = ca_der_b64
        self.stream_seconds = stream_seconds
        self.started_at = utc_now()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca-sha256", required=True)
    parser.add_argument("--ca-der-b64", required=True)
    parser.add_argument("--public-endpoint", default="https://10.0.2.2:8443")
    parser.add_argument("--stream-seconds", type=float, default=3.0)
    args = parser.parse_args()

    server = MobileMockServer(
        (args.host, args.port),
        public_endpoint=args.public_endpoint,
        ca_sha256=args.ca_sha256.lower(),
        ca_der_b64=args.ca_der_b64,
        stream_seconds=args.stream_seconds,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"StruggleApp contract mock listening on https://{args.host}:{args.port}")
    print("Use GET /__control/enrollment to obtain the current synthetic enrollment package.")
    server.serve_forever()


if __name__ == "__main__":
    main()
