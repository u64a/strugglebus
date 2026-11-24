"""Strict contracts for the root-owned self-update maintenance supervisor."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from strugglebus.update_types import (
    JsonObject,
    JsonValue,
    MAX_TIMESTAMP,
    require_bool,
    require_error,
    require_hex,
    require_int,
    require_object,
    require_safe_text,
    require_version,
)

MAINTENANCE_PROTOCOL_VERSION = 1
MAINTENANCE_REQUEST_BYTES = 4096
MAINTENANCE_RESPONSE_BYTES = 16384
MAINTENANCE_ERROR_CODES = frozenset(
    {
        "invalid_request",
        "unavailable",
        "forbidden",
        "busy",
        "conflict",
        "paused",
        "outside_window",
        "no_candidate",
        "updater_unavailable",
        "preparation_failed",
        "installation_failed",
        "state_corrupt",
        "unknown_outcome",
        "internal_error",
    }
)
MAINTENANCE_PHASES = frozenset({"accepted", "running", "succeeded", "failed"})
MAINTENANCE_MODES = frozenset({"automatic", "manual"})
MAINTENANCE_ACTIONS = frozenset({"status", "configure", "install"})
DEFAULT_TIMEZONE = "Australia/Brisbane"
DEFAULT_WINDOW_MINUTES = 30
DEFAULT_NOTICE_SECONDS = 300


class MaintenanceError(Exception):
    """Sanitized supervisor failure."""

    def __init__(self, code: str):
        self.code = code if code in MAINTENANCE_ERROR_CODES else "internal_error"
        super().__init__(self.code)


def _maintenance_error(value: JsonValue) -> str | None:
    if value is None:
        return None
    text = require_safe_text(value)
    if text not in MAINTENANCE_ERROR_CODES:
        raise MaintenanceError("invalid_request")
    return text


def _timezone(value: JsonValue) -> str:
    name = require_safe_text(value, 64)
    if name != DEFAULT_TIMEZONE:
        raise MaintenanceError("invalid_request")
    return name


def _zone(name: str) -> timezone:
    _timezone(name)
    # Queensland does not observe daylight saving time.
    return timezone(timedelta(hours=10), name)


@dataclass(frozen=True, slots=True)
class MaintenancePolicy:
    enabled: bool = True
    hour: int = 1
    minute: int = 0
    timezone: str = DEFAULT_TIMEZONE
    window_minutes: int = DEFAULT_WINDOW_MINUTES
    notice_seconds: int = DEFAULT_NOTICE_SECONDS

    def __post_init__(self) -> None:
        require_bool(self.enabled)
        require_int(self.hour, 23)
        require_int(self.minute, 59)
        _timezone(self.timezone)
        if self.window_minutes != DEFAULT_WINDOW_MINUTES:
            raise MaintenanceError("invalid_request")
        if self.notice_seconds != DEFAULT_NOTICE_SECONDS:
            raise MaintenanceError("invalid_request")

    def window(self, now: datetime) -> tuple[datetime, datetime, str]:
        zone = _zone(self.timezone)
        local = now.astimezone(zone)
        start = local.replace(
            hour=self.hour, minute=self.minute, second=0, microsecond=0,
        )
        end = start + timedelta(minutes=self.window_minutes)
        return start, end, start.date().isoformat()

    def due(self, now: datetime, last_window: str | None) -> bool:
        if not self.enabled:
            return False
        start, end, identity = self.window(now)
        local = now.astimezone(_zone(self.timezone))
        return start <= local < end and last_window != identity

    def next_window(self, now: datetime) -> int:
        start, end, _ = self.window(now)
        local = now.astimezone(_zone(self.timezone))
        if local >= end:
            start += timedelta(days=1)
        return int(start.timestamp())


@dataclass(frozen=True, slots=True)
class MaintenanceAttempt:
    operation_id: str
    mode: str
    actor_id: str
    phase: str
    started_at: int
    finished_at: int | None = None
    candidate_version: str | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        require_hex(self.operation_id, 32)
        if self.mode not in MAINTENANCE_MODES or self.phase not in MAINTENANCE_PHASES:
            raise MaintenanceError("invalid_request")
        require_safe_text(self.actor_id, 256)
        require_int(self.started_at, MAX_TIMESTAMP)
        if self.finished_at is not None:
            require_int(self.finished_at, MAX_TIMESTAMP)
            if self.finished_at < self.started_at:
                raise MaintenanceError("invalid_request")
        if self.candidate_version is not None:
            require_version(self.candidate_version)
        _maintenance_error(self.error)
        self._require_coherent_outcome()

    def _require_coherent_outcome(self) -> None:
        """Only a finished attempt has an end time, and only a failed one an error."""
        if (self.phase in {"accepted", "running"}) != (self.finished_at is None):
            raise MaintenanceError("invalid_request")
        if self.phase == "succeeded" and self.error is not None:
            raise MaintenanceError("invalid_request")
        if self.phase == "failed" and self.error is None:
            raise MaintenanceError("invalid_request")


@dataclass(frozen=True, slots=True)
class MaintenanceStatus:
    policy: MaintenancePolicy
    current_version: str
    last_window: str | None
    next_window: int
    attempt: MaintenanceAttempt | None

    def __post_init__(self) -> None:
        require_version(self.current_version)
        if self.last_window is not None:
            require_safe_text(self.last_window, 10)
        require_int(self.next_window, MAX_TIMESTAMP)


@dataclass(frozen=True, slots=True)
class MaintenanceRequest:
    action: str
    operation_id: str | None = None
    actor_id: str | None = None
    enabled: bool | None = None
    hour: int | None = None
    minute: int | None = None

    def __post_init__(self) -> None:
        if self.action not in MAINTENANCE_ACTIONS:
            raise MaintenanceError("invalid_request")
        if self.action == "status":
            if any(value is not None for value in (
                self.operation_id, self.actor_id, self.enabled, self.hour, self.minute,
            )):
                raise MaintenanceError("invalid_request")
            return
        require_hex(self.operation_id, 32)
        require_safe_text(self.actor_id, 256)
        if self.action == "install":
            if any(value is not None for value in (self.enabled, self.hour, self.minute)):
                raise MaintenanceError("invalid_request")
            return
        require_bool(self.enabled)
        require_int(self.hour, 23)
        require_int(self.minute, 59)


def policy_to_json(value: MaintenancePolicy) -> JsonObject:
    return {
        "enabled": value.enabled,
        "hour": value.hour,
        "minute": value.minute,
        "timezone": value.timezone,
        "window_minutes": value.window_minutes,
        "notice_seconds": value.notice_seconds,
    }


def policy_from_json(value: JsonValue) -> MaintenancePolicy:
    obj = require_object(
        value,
        {"enabled", "hour", "minute", "timezone", "window_minutes", "notice_seconds"},
    )
    return MaintenancePolicy(
        require_bool(obj["enabled"]),
        require_int(obj["hour"], 23),
        require_int(obj["minute"], 59),
        _timezone(obj["timezone"]),
        require_int(obj["window_minutes"], DEFAULT_WINDOW_MINUTES, DEFAULT_WINDOW_MINUTES),
        require_int(obj["notice_seconds"], DEFAULT_NOTICE_SECONDS, DEFAULT_NOTICE_SECONDS),
    )


def attempt_to_json(value: MaintenanceAttempt) -> JsonObject:
    return {
        "operation_id": value.operation_id,
        "mode": value.mode,
        "actor_id": value.actor_id,
        "phase": value.phase,
        "started_at": value.started_at,
        "finished_at": value.finished_at,
        "candidate_version": value.candidate_version,
        "error": value.error,
    }


def attempt_from_json(value: JsonValue) -> MaintenanceAttempt:
    obj = require_object(
        value,
        {
            "operation_id", "mode", "actor_id", "phase", "started_at",
            "finished_at", "candidate_version", "error",
        },
    )
    return MaintenanceAttempt(
        require_hex(obj["operation_id"], 32),
        require_safe_text(obj["mode"]),
        require_safe_text(obj["actor_id"], 256),
        require_safe_text(obj["phase"]),
        require_int(obj["started_at"], MAX_TIMESTAMP),
        None if obj["finished_at"] is None else require_int(obj["finished_at"], MAX_TIMESTAMP),
        None if obj["candidate_version"] is None else require_version(obj["candidate_version"]),
        _maintenance_error(obj["error"]),
    )


def status_to_json(value: MaintenanceStatus) -> JsonObject:
    return {
        "policy": policy_to_json(value.policy),
        "current_version": value.current_version,
        "last_window": value.last_window,
        "next_window": value.next_window,
        "attempt": None if value.attempt is None else attempt_to_json(value.attempt),
    }


def status_from_json(value: JsonValue) -> MaintenanceStatus:
    obj = require_object(
        value, {"policy", "current_version", "last_window", "next_window", "attempt"},
    )
    return MaintenanceStatus(
        policy_from_json(obj["policy"]),
        require_version(obj["current_version"]),
        None if obj["last_window"] is None else require_safe_text(obj["last_window"], 10),
        require_int(obj["next_window"], MAX_TIMESTAMP),
        None if obj["attempt"] is None else attempt_from_json(obj["attempt"]),
    )


def request_to_json(value: MaintenanceRequest) -> JsonObject:
    return {
        "version": MAINTENANCE_PROTOCOL_VERSION,
        "action": value.action,
        "operation_id": value.operation_id,
        "actor_id": value.actor_id,
        "enabled": value.enabled,
        "hour": value.hour,
        "minute": value.minute,
    }


def request_from_json(value: JsonValue) -> MaintenanceRequest:
    obj = require_object(
        value,
        {"version", "action", "operation_id", "actor_id", "enabled", "hour", "minute"},
    )
    require_int(obj["version"], MAINTENANCE_PROTOCOL_VERSION, MAINTENANCE_PROTOCOL_VERSION)
    return MaintenanceRequest(
        require_safe_text(obj["action"]),
        None if obj["operation_id"] is None else require_hex(obj["operation_id"], 32),
        None if obj["actor_id"] is None else require_safe_text(obj["actor_id"], 256),
        None if obj["enabled"] is None else require_bool(obj["enabled"]),
        None if obj["hour"] is None else require_int(obj["hour"], 23),
        None if obj["minute"] is None else require_int(obj["minute"], 59),
    )


def response_to_json(
    status: MaintenanceStatus | None, error: str | None = None,
) -> JsonObject:
    return {
        "version": MAINTENANCE_PROTOCOL_VERSION,
        "ok": error is None,
        "error": error,
        "status": None if status is None else status_to_json(status),
    }


def response_from_json(value: JsonValue) -> MaintenanceStatus:
    obj = require_object(value, {"version", "ok", "error", "status"})
    require_int(obj["version"], MAINTENANCE_PROTOCOL_VERSION, MAINTENANCE_PROTOCOL_VERSION)
    ok = require_bool(obj["ok"])
    error = _maintenance_error(obj["error"])
    if not ok:
        if error is None or obj["status"] is not None:
            raise MaintenanceError("invalid_request")
        raise MaintenanceError(error)
    if error is not None or obj["status"] is None:
        raise MaintenanceError("invalid_request")
    return status_from_json(obj["status"])
