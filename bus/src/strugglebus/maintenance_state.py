"""Durable policy and operation state for self-updating maintenance."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import secrets
import stat

from strugglebus.maintenance_types import (
    MaintenanceAttempt,
    MaintenanceError,
    MaintenancePolicy,
    MaintenanceStatus,
    attempt_from_json,
    attempt_to_json,
    policy_from_json,
    policy_to_json,
)
from strugglebus.update_types import JsonValue
from strugglebus.update_types import UpdateError

STATE_BYTES = 16384


@dataclass(frozen=True, slots=True)
class MaintenanceJournal:
    policy: MaintenancePolicy = field(default_factory=MaintenancePolicy)
    last_window: str | None = None
    attempt: MaintenanceAttempt | None = None


def journal_to_json(value: MaintenanceJournal) -> dict[str, JsonValue]:
    return {
        "version": 1,
        "policy": policy_to_json(value.policy),
        "last_window": value.last_window,
        "attempt": None if value.attempt is None else attempt_to_json(value.attempt),
    }


def _last_window(value: JsonValue) -> str | None:
    """Accept an absent window or one shaped like an ISO calendar date."""
    if value is not None and (
        not isinstance(value, str)
        or len(value) != 10
        or value[4] != "-"
        or value[7] != "-"
    ):
        raise MaintenanceError("state_corrupt")
    return value


def journal_from_json(value: JsonValue) -> MaintenanceJournal:
    if not isinstance(value, dict) or set(value) != {
        "version", "policy", "last_window", "attempt",
    }:
        raise MaintenanceError("state_corrupt")
    if value["version"] != 1:
        raise MaintenanceError("state_corrupt")
    try:
        policy = policy_from_json(value["policy"])
        last_window = _last_window(value["last_window"])
        attempt = None if value["attempt"] is None else attempt_from_json(value["attempt"])
        return MaintenanceJournal(policy, last_window, attempt)
    except (MaintenanceError, UpdateError):
        raise MaintenanceError("state_corrupt") from None


class MaintenanceState:
    def __init__(self, path: Path, current_version: str):
        self.path = path
        self.current_version = current_version
        self.journal = self._load()

    def _load(self) -> MaintenanceJournal:
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            journal = MaintenanceJournal()
            self._save(journal)
            return journal
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (
                os.name == "posix"
                and (
                    stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_uid != os.geteuid()
                )
            )
            or metadata.st_size > STATE_BYTES
        ):
            raise MaintenanceError("state_corrupt")
        try:
            content = self.path.read_bytes()
            value = json.loads(content.decode("ascii"))
            return journal_from_json(value)
        except (OSError, UnicodeError, ValueError, RecursionError):
            raise MaintenanceError("state_corrupt") from None

    def _save(self, journal: MaintenanceJournal) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or (
                os.name == "posix"
                and (
                    stat.S_IMODE(parent.st_mode) != 0o700
                    or parent.st_uid != os.geteuid()
                )
            )
        ):
            raise MaintenanceError("state_corrupt")
        raw = (
            json.dumps(
                journal_to_json(journal),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")
        if len(raw) > STATE_BYTES:
            raise MaintenanceError("state_corrupt")
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(8)}")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self.path)
            if os.name == "posix":
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except OSError:
            raise MaintenanceError("state_corrupt") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
        self.journal = journal

    def status(self, now: datetime | None = None) -> MaintenanceStatus:
        instant = datetime.now(UTC) if now is None else now
        return MaintenanceStatus(
            self.journal.policy,
            self.current_version,
            self.journal.last_window,
            self.journal.policy.next_window(instant),
            self.journal.attempt,
        )

    def configure(self, *, enabled: bool, hour: int, minute: int) -> None:
        policy = replace(
            self.journal.policy, enabled=enabled, hour=hour, minute=minute,
        )
        self._save(replace(self.journal, policy=policy))

    def accept(
        self, operation_id: str, mode: str, actor_id: str, *, now: int,
        window: str | None = None,
    ) -> MaintenanceAttempt:
        attempt = self.journal.attempt
        if attempt is not None:
            if attempt.operation_id == operation_id:
                return attempt
            if attempt.phase in {"accepted", "running"}:
                raise MaintenanceError("busy")
        accepted = MaintenanceAttempt(operation_id, mode, actor_id, "accepted", now)
        self._save(replace(
            self.journal,
            last_window=window if mode == "automatic" else self.journal.last_window,
            attempt=accepted,
        ))
        return accepted

    def start(self, operation_id: str) -> MaintenanceAttempt:
        attempt = self._attempt(operation_id)
        running = replace(attempt, phase="running")
        self._save(replace(self.journal, attempt=running))
        return running

    def bind_candidate(self, operation_id: str, version: str) -> MaintenanceAttempt:
        attempt = self._attempt(operation_id)
        bound = replace(attempt, candidate_version=version)
        self._save(replace(self.journal, attempt=bound))
        return bound

    def finish(self, operation_id: str, *, now: int, error: str | None = None) -> None:
        attempt = self._attempt(operation_id)
        finished = replace(
            attempt,
            phase="succeeded" if error is None else "failed",
            finished_at=max(now, attempt.started_at),
            error=error,
        )
        self._save(replace(self.journal, attempt=finished))

    def _attempt(self, operation_id: str) -> MaintenanceAttempt:
        attempt = self.journal.attempt
        if attempt is None or attempt.operation_id != operation_id:
            raise MaintenanceError("conflict")
        if attempt.phase not in {"accepted", "running"}:
            return attempt
        return attempt

    @staticmethod
    def new_operation_id() -> str:
        return secrets.token_hex(16)
