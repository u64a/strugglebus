"""Policy controller and orchestration for automatic self-updating maintenance."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import sys
import time
from typing import Protocol

from strugglebus.maintenance_state import MaintenanceState
from strugglebus.maintenance_types import (
    MaintenanceError,
    MaintenanceRequest,
    MaintenanceStatus,
)


@dataclass(frozen=True, slots=True)
class PreparedRelease:
    version: str
    directory: Path


class ReleaseGateway(Protocol):
    def prepare_latest(self, *, actor_id: str) -> PreparedRelease | None:
        raise NotImplementedError


class ReleaseInstaller(Protocol):
    def install(self, release: PreparedRelease, *, operation_id: str) -> None:
        raise NotImplementedError


class MaintenanceAnnouncer(Protocol):
    def announce(
        self, release: PreparedRelease, *, operation_id: str,
        scheduled_at: int, automatic: bool,
    ) -> None:
        raise NotImplementedError


class MaintenanceController:
    def __init__(
        self,
        state: MaintenanceState,
        *,
        trigger: Callable[[], None],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.state = state
        self.trigger = trigger
        self.clock = clock

    def dispatch(self, request: MaintenanceRequest) -> MaintenanceStatus:
        now = self.clock()
        if request.action == "status":
            return self.state.status(now)
        if request.operation_id is None or request.actor_id is None:
            raise MaintenanceError("invalid_request")
        if request.action == "configure":
            if request.enabled is None or request.hour is None or request.minute is None:
                raise MaintenanceError("invalid_request")
            self.state.configure(
                enabled=request.enabled, hour=request.hour, minute=request.minute,
            )
            return self.state.status(now)
        attempt = self.state.accept(
            request.operation_id, "manual", request.actor_id,
            now=int(now.timestamp()),
        )
        if attempt.phase == "accepted":
            self.trigger()
        return self.state.status(now)


class MaintenanceRunner:
    def __init__(
        self,
        state: MaintenanceState,
        gateway: ReleaseGateway,
        installer: ReleaseInstaller,
        announcer: MaintenanceAnnouncer,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.state = state
        self.gateway = gateway
        self.installer = installer
        self.announcer = announcer
        self.clock = clock
        self.sleep = sleep

    def accept_automatic_if_due(self) -> str | None:
        now = self.clock()
        policy = self.state.journal.policy
        if not policy.due(now, self.state.journal.last_window):
            return None
        _, _, window = policy.window(now)
        operation_id = self.state.new_operation_id()
        self.state.accept(
            operation_id,
            "automatic",
            "system:auto-maintenance",
            now=int(now.timestamp()),
            window=window,
        )
        return operation_id

    def pending_operation(self) -> str | None:
        attempt = self.state.journal.attempt
        if attempt is None:
            return self.accept_automatic_if_due()
        if attempt.phase == "running":
            self.state.finish(
                attempt.operation_id,
                now=int(self.clock().timestamp()),
                error="unknown_outcome",
            )
            return None
        if attempt.phase != "accepted":
            return self.accept_automatic_if_due()
        return attempt.operation_id

    def run_pending(self) -> bool:
        operation_id = self.pending_operation()
        if operation_id is None:
            return False
        attempt = self.state.start(operation_id)
        try:
            release = self.gateway.prepare_latest(actor_id=attempt.actor_id)
            if release is None:
                self.state.finish(
                    operation_id, now=int(self.clock().timestamp()),
                )
                return True
            self.state.bind_candidate(operation_id, release.version)
            scheduled_at = int(self.clock().timestamp()) + self.state.journal.policy.notice_seconds
            try:
                self.announcer.announce(
                    release,
                    operation_id=operation_id,
                    scheduled_at=scheduled_at,
                    automatic=attempt.mode == "automatic",
                )
            except MaintenanceError:
                # The board notice is informational; it must not block updates.
                print("maintenance_notice_skipped", file=sys.stderr, flush=True)
            self.sleep(self.state.journal.policy.notice_seconds)
            self.installer.install(release, operation_id=operation_id)
            self.state.finish(operation_id, now=int(self.clock().timestamp()))
            return True
        except MaintenanceError as error:
            self.state.finish(
                operation_id,
                now=int(self.clock().timestamp()),
                error=error.code,
            )
            raise
        except Exception:
            self.state.finish(
                operation_id,
                now=int(self.clock().timestamp()),
                error="installation_failed",
            )
            raise MaintenanceError("installation_failed") from None
