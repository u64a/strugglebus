"""Recent server log lines, kept in memory for the operator's device.

`strugglebus serve` attaches one handler that remembers the last
``MAX_ENTRIES`` lines: server start and stop, warnings and errors from any
logger, and the request lines the audit feed sends to the SIEM (refusals,
failed logins, lifecycle calls). It holds what the journal already holds,
nothing more, and is lost on restart; committed audit rows are read from
their tables instead, so those survive one.
"""

from __future__ import annotations

import json
import logging
from collections import deque
from datetime import UTC, datetime

from strugglebus.audit_feed import LOGGER as AUDIT_LOGGER, PREFIX as AUDIT_PREFIX

MAX_ENTRIES = 1000
MAX_DETAIL = 500


class RecentLog(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.entries: deque[dict[str, object]] = deque(maxlen=MAX_ENTRIES)
        self.started_at = datetime.now(UTC)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = (
                _request_entry(record.getMessage())
                if record.name == AUDIT_LOGGER.name
                else _server_entry(record)
            )
        except Exception:
            # A log line that cannot be kept must never break the caller.
            return
        if entry is not None:
            self.entries.append(entry)

    def recent(self, limit: int) -> list[dict[str, object]]:
        return list(self.entries)[-limit:]


def _server_entry(record: logging.LogRecord) -> dict[str, object]:
    detail = record.getMessage()
    if record.exc_info and record.exc_info[1] is not None:
        error = record.exc_info[1]
        detail = f"{detail} ({type(error).__name__}: {error})"
    level = (
        "error" if record.levelno >= logging.ERROR
        else "warning" if record.levelno >= logging.WARNING
        else "info"
    )
    return {
        "ts": datetime.fromtimestamp(record.created, UTC),
        "source": "server",
        "level": level,
        "event": record.name,
        "subject": None,
        "actor": None,
        "status": None,
        "remote_address": None,
        "detail": detail[:MAX_DETAIL],
    }


def _request_entry(line: str) -> dict[str, object] | None:
    # Committed table rows also pass through the audit logger; they are read
    # from the tables instead, so only gateway request lines are kept here.
    if not line.startswith(AUDIT_PREFIX):
        return None
    record = json.loads(line[len(AUDIT_PREFIX):])
    if record.get("table") != "request":
        return None
    status = record.get("status")
    refused = isinstance(status, int) and status >= 400
    return {
        "ts": datetime.fromisoformat(str(record["ts"])),
        "source": "request",
        "level": "warning" if refused else "info",
        "event": str(record.get("event", "")),
        "subject": record.get("spn_id"),
        "actor": None,
        "status": status if isinstance(status, int) else None,
        "remote_address": record.get("remote_address"),
        "detail": "refused" if refused else "ok",
    }


#: One per process, like the log it mirrors. Empty until ``install`` runs.
RECENT = RecentLog()


def install() -> None:
    """Attach the handler. Call after uvicorn has configured its loggers."""

    RECENT.started_at = datetime.now(UTC)
    for logger in (logging.getLogger(), logging.getLogger("uvicorn"), AUDIT_LOGGER):
        if RECENT not in logger.handlers:
            logger.addHandler(RECENT)
