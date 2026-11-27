"""The background clean-up that applies the operator's retention setting.

Once an hour it removes messages older than the configured period and blocks
agents that have been silent for the configured period. Every run that changes
something prints one ``strugglebus-retention`` line, so the service log shows
what was removed and who was blocked; blocks are also in the lifecycle audit.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from strugglebus.host_status import HISTORY
from strugglebus.store._common import utc_now

if TYPE_CHECKING:
    from strugglebus.store import SQLiteStore

FIRST_RUN_SECONDS = 120.0
INTERVAL_SECONDS = 3600.0
#: Bounds one run, so a first clean-up of a large history yields the single
#: SQLite writer between batches and finishes over a few runs if need be.
MAXIMUM_BATCHES = 100
PREFIX = "strugglebus-retention: "


@dataclass(frozen=True, slots=True)
class RetentionRun:
    removed_messages: int
    blocked_agents: tuple[str, ...]


def _say(line: str) -> None:
    print(PREFIX + line, flush=True)


class RetentionSweeper:
    def __init__(
        self, store: SQLiteStore, *, clock: Callable[[], datetime] = utc_now,
        emit: Callable[[str], None] = _say, batch_size: int = 500,
    ) -> None:
        self.store = store
        self.clock = clock
        self.emit = emit
        self.batch_size = batch_size

    def run_once(self) -> RetentionRun:
        now = self.clock()
        settings = self.store.get_retention()
        removed = 0
        for _ in range(MAXIMUM_BATCHES):
            count = self.store.remove_expired_messages(now=now, batch_size=self.batch_size)
            removed += count
            if count < self.batch_size:
                break
        # A host that reports trims its own history as it goes. This catches the ones that stopped.
        for _ in range(MAXIMUM_BATCHES):
            if self.store.remove_expired_host_status_samples(
                now=now, keep=HISTORY, batch_size=self.batch_size,
            ) < self.batch_size:
                break
        blocked = self.store.block_idle_agents(now=now)
        self.store.record_retention_run(
            now=now, removed_messages=removed, blocked_agents=len(blocked),
        )
        if removed:
            self.emit(f"removed {removed} messages older than {settings.message_days} days")
        if blocked:
            self.emit(
                f"blocked {len(blocked)} agents with no activity for "
                f"{settings.idle_agent_days} days: {', '.join(blocked)}"
            )
        return RetentionRun(removed, blocked)

    async def run(self) -> None:
        await asyncio.sleep(FIRST_RUN_SECONDS)
        while True:
            try:
                await asyncio.to_thread(self.run_once)
            except Exception as error:
                print(
                    f"{PREFIX}clean-up failed ({type(error).__name__}); "
                    "it will be tried again in an hour",
                    file=sys.stderr, flush=True,
                )
            await asyncio.sleep(INTERVAL_SECONDS)
