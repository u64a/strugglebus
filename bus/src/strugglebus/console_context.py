"""Request-local access-state disclosure; never an authorization decision."""

import asyncio
from contextvars import ContextVar
from typing import Any, Literal

from strugglebus.errors import StorageError

ConsoleAccessState = Literal["unobserved", "available", "frozen", "unavailable"]

console_access_context: ContextVar[ConsoleAccessState] = ContextVar(
    "console_access_context", default="unobserved",
)


async def _console_access(scope: dict[str, Any]) -> ConsoleAccessState:
    if scope["state"].get("operator_context") is None:
        return "unobserved"
    try:
        state = await asyncio.to_thread(scope["app"].state.access_freeze_service.status)
    except StorageError:
        return "unavailable"
    return "frozen" if state.frozen else "available"


class ConsoleAccessMiddleware:
    """Expose the freeze state to console rendering for admitted operator requests."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or "operator_context" not in scope.get("state", {}):
            await self.app(scope, receive, send)
            return
        token = console_access_context.set(await _console_access(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            console_access_context.reset(token)
