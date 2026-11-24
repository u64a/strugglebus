"""Concurrency-safe, injectable one-process request limiting."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class SlidingWindowRateLimiter:
    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        window_seconds: float = 60.0,
    ) -> None:
        self._clock = clock
        self._window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = 0.0

    def allow(self, key: str, limit: int) -> tuple[bool, int]:
        now = self._clock()
        cutoff = now - self._window_seconds
        with self._lock:
            if now - self._last_sweep >= self._window_seconds:
                for existing_key, existing_events in tuple(
                    self._events.items()
                ):
                    while existing_events and existing_events[0] <= cutoff:
                        existing_events.popleft()
                    if not existing_events:
                        del self._events[existing_key]
                self._last_sweep = now
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(events[0] + self._window_seconds - now) + 1)
                return False, retry_after
            events.append(now)
            return True, 0


class ConcurrentConnectionLimiter:
    """Process-local per-identity leases for long-lived connections."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def acquire(self, key: str, limit: int) -> bool:
        with self._lock:
            current = self._counts.get(key, 0)
            if current >= limit:
                return False
            self._counts[key] = current + 1
            return True

    def release(self, key: str) -> None:
        with self._lock:
            current = self._counts.get(key)
            if current is None:
                raise RuntimeError("connection lease was not acquired")
            if current == 1:
                del self._counts[key]
            else:
                self._counts[key] = current - 1
