"""Bounded process-local catch-up snapshots and integrity-protected positions."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from strugglebus.errors import (
    CatchUpCapacityError,
    CatchUpUnavailableError,
    DomainValidationError,
)
from strugglebus.models import Message

MAX_CONTINUATION_LENGTH = 256
_TOKEN = re.compile(r"^1\.([0-9a-f]{32})\.([0-9]{1,19})\.([0-9a-f]{64})$")
_UNAVAILABLE = "catch-up continuation expired or unavailable; start a new drain"


@dataclass(frozen=True, slots=True)
class CatchUpSnapshot:
    agent_id: str
    subscriptions: tuple[tuple[str, int], ...]
    mention_cursor: int
    upper_seq: int
    overlap_since: datetime
    stale_before: datetime
    include_stale: bool
    limit: int


@dataclass(frozen=True, slots=True)
class CatchUpPage:
    messages: tuple[Message, ...]
    mode: Literal["legacy", "drain"] = "legacy"
    continuation: str | None = None
    complete: bool | None = None
    snapshot_seq: int | None = None
    expires_at: datetime | None = None


PageBuilder = Callable[
    [CatchUpSnapshot, tuple[Message, ...], int, bool], CatchUpPage
]
DrainOperation = Callable[[CatchUpSnapshot | None, int, PageBuilder], CatchUpPage]


def _token_fields(continuation: object) -> tuple[str, str, str]:
    """Split a well-formed continuation into identifier, position and signature."""
    match = None
    if (
        isinstance(continuation, str)
        and len(continuation) <= MAX_CONTINUATION_LENGTH
    ):
        match = _TOKEN.fullmatch(continuation)
    if match is None:
        raise DomainValidationError("invalid catch-up continuation")
    identifier, raw_position, signature = match.groups()
    return identifier, raw_position, signature


@dataclass(slots=True)
class _Entry:
    agent_id: str
    deadline: float
    expires_at: datetime
    snapshot: CatchUpSnapshot | None = None


class DrainRegistry:
    def __init__(
        self,
        *,
        maximum: int,
        per_agent: int,
        ttl_seconds: int,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._maximum = maximum
        self._per_agent = per_agent
        self._ttl_seconds = ttl_seconds
        self._monotonic = monotonic
        self._key = secrets.token_bytes(32)
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.RLock()

    def _signature(
        self, prefix: str, agent_id: str, snapshot: CatchUpSnapshot
    ) -> str:
        material = (
            f"{prefix}|{agent_id}|{snapshot.limit}|{int(snapshot.include_stale)}"
        )
        return hmac.new(
            self._key, material.encode("ascii"), hashlib.sha256
        ).hexdigest()

    def _expire(self, moment: float) -> None:
        expired = [
            key for key, value in self._entries.items()
            if value.deadline <= moment
        ]
        for key in expired:
            del self._entries[key]

    def _reserve(
        self, agent_id: str, moment: float, now: datetime
    ) -> tuple[str, _Entry]:
        held = sum(
            value.agent_id == agent_id for value in self._entries.values()
        )
        if len(self._entries) >= self._maximum or held >= self._per_agent:
            raise CatchUpCapacityError(
                "catch-up drain capacity reached; retry after snapshots expire"
            )
        identifier = secrets.token_hex(16)
        entry = _Entry(
            agent_id=agent_id,
            deadline=moment + self._ttl_seconds,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
        )
        self._entries[identifier] = entry
        return identifier, entry

    def _resume(
        self,
        continuation: object,
        *,
        agent_id: str,
        limit: int,
        include_stale: bool,
    ) -> tuple[str, _Entry, int]:
        identifier, raw_position, signature = _token_fields(continuation)
        entry = self._entries.get(identifier)
        if entry is None or entry.snapshot is None:
            raise CatchUpUnavailableError(_UNAVAILABLE)
        snapshot = entry.snapshot
        prefix = f"1.{identifier}.{raw_position}"
        if (
            entry.agent_id != agent_id
            or snapshot.limit != limit
            or snapshot.include_stale != include_stale
            or not hmac.compare_digest(
                signature, self._signature(prefix, agent_id, snapshot)
            )
        ):
            raise DomainValidationError("invalid catch-up continuation")
        after_seq = int(raw_position)
        if after_seq > snapshot.upper_seq:
            raise DomainValidationError("invalid catch-up continuation")
        return identifier, entry, after_seq

    def _page_builder(
        self, identifier: str, entry: _Entry, agent_id: str, starting: bool
    ) -> PageBuilder:
        def build_page(
            snapshot: CatchUpSnapshot,
            messages: tuple[Message, ...],
            position: int,
            complete: bool,
        ) -> CatchUpPage:
            if self._monotonic() >= entry.deadline:
                raise CatchUpUnavailableError(_UNAVAILABLE)
            entry.snapshot = snapshot
            token = None
            if not complete:
                prefix = f"1.{identifier}.{position}"
                token = prefix + "." + self._signature(
                    prefix, agent_id, snapshot
                )
            return CatchUpPage(
                messages=messages,
                mode="drain",
                continuation=token,
                complete=complete,
                snapshot_seq=snapshot.upper_seq,
                expires_at=(
                    None if starting and complete else entry.expires_at
                ),
            )

        return build_page

    def run(
        self,
        *,
        agent_id: str,
        limit: int,
        include_stale: bool,
        continuation: str | None,
        now: datetime,
        operation: DrainOperation,
    ) -> CatchUpPage:
        # Hold admission through selection/commit: reservations cannot race, and
        # failed transactions cannot publish a usable, partially built snapshot.
        with self._lock:
            moment = self._monotonic()
            self._expire(moment)
            starting = continuation is None
            if starting:
                identifier, entry = self._reserve(agent_id, moment, now)
                after_seq = 0
            else:
                identifier, entry, after_seq = self._resume(
                    continuation,
                    agent_id=agent_id,
                    limit=limit,
                    include_stale=include_stale,
                )
            build_page = self._page_builder(identifier, entry, agent_id, starting)
            try:
                page = operation(entry.snapshot, after_seq, build_page)
            except BaseException:
                if starting:
                    del self._entries[identifier]
                raise
            if starting and page.complete:
                del self._entries[identifier]
            return page
