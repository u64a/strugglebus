"""Copy committed lifecycle audit rows to stdout (journald) for the SIEM.

The SQLite audit tables stay the source of truth. Each new row becomes one
line: ``strugglebus-audit `` followed by a compact JSON object holding only
the allow-listed identifying fields below - never reasons, details, secrets
or hashes. The feed starts at the tables' current end; history is not replayed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from strugglebus.store import SQLiteStore

PREFIX = "strugglebus-audit "
#: Only `strugglebus serve` attaches a handler (stdout, so journald), so tools
#: that run the app in-process keep their own stdout clean.
LOGGER = logging.getLogger("strugglebus.audit")
LOGGER.propagate = False


def install_stdout_handler() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)


def emit(line: str) -> None:
    LOGGER.info(line)
POLL_SECONDS = 5.0
MAX_BACKOFF_SECONDS = 60.0

# One literal query per table, so no SQL is ever assembled at run time. Each
# returns the same columns; absent ones are NULL. agent_name and the identity
# expiry come from the agent the row is about.
_QUERIES: dict[str, str] = {
    "agent_credential_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.event_type AS event,
               t.agent_id AS agent_id, t.credential_id AS credential_id,
               NULL AS spn_id, t.request_id AS request_id, a.name AS agent_name,
               a.expires_at AS identity_expires_at, t.actor_type, t.actor_id
        FROM agent_credential_audit t LEFT JOIN agents a ON a.id = t.agent_id
        WHERE t.rowid > ? ORDER BY t.rowid LIMIT 500
    """,
    "agent_lifecycle_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.action AS event,
               t.agent_id AS agent_id, NULL AS credential_id, NULL AS spn_id,
               t.request_id AS request_id, a.name AS agent_name,
               a.expires_at AS identity_expires_at, t.actor_type, t.actor_id
        FROM agent_lifecycle_audit t LEFT JOIN agents a ON a.id = t.agent_id
        WHERE t.rowid > ? ORDER BY t.rowid LIMIT 500
    """,
    "agent_access_audit": """
        SELECT t.rowid AS row_id, t.changed_at AS ts, t.transition AS event,
               NULL AS agent_id, NULL AS credential_id, NULL AS spn_id,
               NULL AS request_id, NULL AS agent_name, NULL AS identity_expires_at,
               t.actor_type, t.actor_id
        FROM agent_access_audit t
        WHERE t.rowid > ? ORDER BY t.rowid LIMIT 500
    """,
    "spn_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.event_type AS event,
               NULL AS agent_id, t.credential_id AS credential_id,
               t.spn_id AS spn_id, t.request_id AS request_id, NULL AS agent_name,
               json_extract(t.details_json, '$.identity_expires_at')
                   AS identity_expires_at,
               t.actor_type, t.actor_id
        FROM spn_audit t
        WHERE t.rowid > ? ORDER BY t.rowid LIMIT 500
    """,
    "roe_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.event_type AS event,
               t.agent_id AS agent_id, NULL AS credential_id, NULL AS spn_id,
               NULL AS request_id, a.name AS agent_name,
               a.expires_at AS identity_expires_at, t.actor_type, t.actor_id
        FROM roe_audit t LEFT JOIN agents a ON a.id = t.agent_id
        WHERE t.rowid > ? ORDER BY t.rowid LIMIT 500
    """,
    "mobile_device_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.event_type AS event,
               NULL AS agent_id, t.credential_id AS credential_id, NULL AS spn_id,
               t.request_id AS request_id, NULL AS agent_name,
               NULL AS identity_expires_at, t.actor_type, t.actor_id
        FROM mobile_device_audit t
        WHERE t.rowid > ? ORDER BY t.rowid LIMIT 500
    """,
    "host_enrollments": """
        SELECT t.rowid AS row_id, t.created_at AS ts, 'host-code-minted' AS event,
               NULL AS agent_id, NULL AS credential_id, NULL AS spn_id,
               t.mint_request_id AS request_id, NULL AS agent_name,
               NULL AS identity_expires_at, t.actor_type, t.actor_id,
               t.host_prefix AS host_prefix
        FROM host_enrollments t
        WHERE t.rowid > ? ORDER BY t.rowid LIMIT 500
    """,
    "site_document_audit": """
        SELECT t.seq AS row_id, t.occurred_at AS ts, 'site-document-stored' AS event,
               NULL AS agent_id, NULL AS credential_id, NULL AS spn_id,
               NULL AS request_id, NULL AS agent_name, NULL AS identity_expires_at,
               t.actor_type, t.actor_id, t.name AS document, t.serial AS serial,
               t.signer_fingerprint AS signer_fingerprint
        FROM site_document_audit t
        WHERE t.seq > ? ORDER BY t.seq LIMIT 500
    """,
    "host_agent_audit": """
        SELECT t.seq AS row_id, t.occurred_at AS ts, 'host-' || t.action AS event,
               t.agent_id AS agent_id, NULL AS credential_id, NULL AS spn_id,
               t.request_id AS request_id, t.agent_name AS agent_name,
               NULL AS identity_expires_at, t.actor_type, t.actor_id
        FROM host_agent_audit t
        WHERE t.seq > ? ORDER BY t.seq LIMIT 500
    """,
}
_END_QUERIES: dict[str, str] = {
    "agent_credential_audit": "SELECT COALESCE(MAX(rowid), 0) FROM agent_credential_audit",
    "agent_lifecycle_audit": "SELECT COALESCE(MAX(rowid), 0) FROM agent_lifecycle_audit",
    "agent_access_audit": "SELECT COALESCE(MAX(rowid), 0) FROM agent_access_audit",
    "spn_audit": "SELECT COALESCE(MAX(rowid), 0) FROM spn_audit",
    "roe_audit": "SELECT COALESCE(MAX(rowid), 0) FROM roe_audit",
    "mobile_device_audit": "SELECT COALESCE(MAX(rowid), 0) FROM mobile_device_audit",
    "host_enrollments": "SELECT COALESCE(MAX(rowid), 0) FROM host_enrollments",
    "site_document_audit": "SELECT COALESCE(MAX(seq), 0) FROM site_document_audit",
    "host_agent_audit": "SELECT COALESCE(MAX(seq), 0) FROM host_agent_audit",
}
#: The same selects, newest first, for the operator's log view. Written out
#: rather than derived, so these too are never assembled at run time.
_RECENT_QUERIES: dict[str, str] = {
    "agent_credential_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.event_type AS event,
               t.agent_id AS agent_id, t.credential_id AS credential_id,
               NULL AS spn_id, t.request_id AS request_id, a.name AS agent_name,
               a.expires_at AS identity_expires_at, t.actor_type, t.actor_id
        FROM agent_credential_audit t LEFT JOIN agents a ON a.id = t.agent_id
        ORDER BY t.rowid DESC LIMIT ?
    """,
    "agent_lifecycle_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.action AS event,
               t.agent_id AS agent_id, NULL AS credential_id, NULL AS spn_id,
               t.request_id AS request_id, a.name AS agent_name,
               a.expires_at AS identity_expires_at, t.actor_type, t.actor_id
        FROM agent_lifecycle_audit t LEFT JOIN agents a ON a.id = t.agent_id
        ORDER BY t.rowid DESC LIMIT ?
    """,
    "agent_access_audit": """
        SELECT t.rowid AS row_id, t.changed_at AS ts, t.transition AS event,
               NULL AS agent_id, NULL AS credential_id, NULL AS spn_id,
               NULL AS request_id, NULL AS agent_name, NULL AS identity_expires_at,
               t.actor_type, t.actor_id
        FROM agent_access_audit t
        ORDER BY t.rowid DESC LIMIT ?
    """,
    "spn_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.event_type AS event,
               NULL AS agent_id, t.credential_id AS credential_id,
               t.spn_id AS spn_id, t.request_id AS request_id, NULL AS agent_name,
               json_extract(t.details_json, '$.identity_expires_at')
                   AS identity_expires_at,
               t.actor_type, t.actor_id
        FROM spn_audit t
        ORDER BY t.rowid DESC LIMIT ?
    """,
    "roe_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.event_type AS event,
               t.agent_id AS agent_id, NULL AS credential_id, NULL AS spn_id,
               NULL AS request_id, a.name AS agent_name,
               a.expires_at AS identity_expires_at, t.actor_type, t.actor_id
        FROM roe_audit t LEFT JOIN agents a ON a.id = t.agent_id
        ORDER BY t.rowid DESC LIMIT ?
    """,
    "mobile_device_audit": """
        SELECT t.rowid AS row_id, t.occurred_at AS ts, t.event_type AS event,
               NULL AS agent_id, t.credential_id AS credential_id, NULL AS spn_id,
               t.request_id AS request_id, NULL AS agent_name,
               NULL AS identity_expires_at, t.actor_type, t.actor_id
        FROM mobile_device_audit t
        ORDER BY t.rowid DESC LIMIT ?
    """,
    "host_enrollments": """
        SELECT t.rowid AS row_id, t.created_at AS ts, 'host-code-minted' AS event,
               NULL AS agent_id, NULL AS credential_id, NULL AS spn_id,
               t.mint_request_id AS request_id, NULL AS agent_name,
               NULL AS identity_expires_at, t.actor_type, t.actor_id,
               t.host_prefix AS host_prefix
        FROM host_enrollments t
        ORDER BY t.rowid DESC LIMIT ?
    """,
    "site_document_audit": """
        SELECT t.seq AS row_id, t.occurred_at AS ts, 'site-document-stored' AS event,
               NULL AS agent_id, NULL AS credential_id, NULL AS spn_id,
               NULL AS request_id, NULL AS agent_name, NULL AS identity_expires_at,
               t.actor_type, t.actor_id, t.name AS document, t.serial AS serial,
               t.signer_fingerprint AS signer_fingerprint
        FROM site_document_audit t
        ORDER BY t.seq DESC LIMIT ?
    """,
    "host_agent_audit": """
        SELECT t.seq AS row_id, t.occurred_at AS ts, 'host-' || t.action AS event,
               t.agent_id AS agent_id, NULL AS credential_id, NULL AS spn_id,
               t.request_id AS request_id, t.agent_name AS agent_name,
               NULL AS identity_expires_at, t.actor_type, t.actor_id
        FROM host_agent_audit t
        ORDER BY t.seq DESC LIMIT ?
    """,
}
_FIELDS = (
    "ts", "event", "agent_id", "agent_name", "credential_id", "spn_id",
    "actor_type", "actor_id", "request_id", "identity_expires_at",
)
#: Worker host events add these. Every other line carries them as null, so the
#: key set is the same on every line. ``signer_fingerprint`` is what the
#: publishing device stated: the bus does not check it against the signature.
_HOST_FIELDS = ("host_prefix", "document", "serial", "signer_fingerprint")


def _fields(row) -> dict[str, object]:
    """The allow-listed values of one audit row; a column a table lacks is null."""

    present = set(row.keys())
    return {
        **{name: row[name] for name in _FIELDS},
        **{name: row[name] if name in present else None for name in _HOST_FIELDS},
    }
#: Request lines carry these too; table rows have them as null and "ok".
#: ``request_bytes`` is the size the caller declared, on a worker host's reports.
_REQUEST_FIELDS = ("remote_address", "outcome", "status", "request_bytes")


def _line(record: dict[str, object]) -> str:
    return PREFIX + json.dumps(
        record, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
    )


def request_line(
    *, ts: str, event: str, status: int, remote_address: str,
    spn_id: str | None = None, agent_id: str | None = None, agent_name: str | None = None,
    request_bytes: int | None = None,
) -> str:
    """One lifecycle or refused request, from the ASGI gateway.

    The tables record only what committed; this is how refusals, failed
    logins and the caller's address reach the SIEM.
    """

    record: dict[str, object] = {name: None for name in _FIELDS + _HOST_FIELDS}
    record.update(
        table="request", ts=ts, event=event, spn_id=spn_id,
        agent_id=agent_id, agent_name=agent_name,
        remote_address=remote_address, status=status, request_bytes=request_bytes,
        outcome="ok" if status < 400 else "refused",
    )
    return _line(record)


def recent(store: SQLiteStore, limit: int) -> list[dict[str, object]]:
    """The newest committed audit rows across every table, newest first.

    The same allow-listed fields the feed emits, so the operator's device sees
    exactly what the SIEM was sent and nothing the feed withholds.
    """

    rows: list[dict[str, object]] = []
    with store._read_transaction() as connection:
        for table, query in _RECENT_QUERIES.items():
            for row in connection.execute(query, (limit,)):
                rows.append({"table": table, **_fields(row)})
    rows.sort(key=lambda row: str(row["ts"]), reverse=True)
    return rows[:limit]


class AuditFeed:
    def __init__(self, store: SQLiteStore, emit: Callable[[str], None] | None = None) -> None:
        self.store = store
        self.emit = emit if emit is not None else LOGGER.info
        self.last: dict[str, int] | None = None

    def start_at_end(self) -> None:
        with self.store._read_transaction() as connection:
            self.last = {
                table: int(connection.execute(query).fetchone()[0])
                for table, query in _END_QUERIES.items()
            }

    def poll_once(self) -> None:
        if self.last is None:
            self.start_at_end()
            return
        lines: list[tuple[str, int, str]] = []
        with self.store._read_transaction() as connection:
            for table, query in _QUERIES.items():
                for row in connection.execute(query, (self.last[table],)):
                    record: dict[str, object] = {
                        "table": table, **_fields(row),
                        "remote_address": None, "outcome": "ok", "status": None,
                        "request_bytes": None,
                    }
                    lines.append((table, int(row["row_id"]), _line(record)))
        for table, row_id, line in lines:
            self.emit(line)
            self.last[table] = row_id

    async def run(self) -> None:
        delay = POLL_SECONDS
        while True:
            try:
                await asyncio.to_thread(self.poll_once)
                delay = POLL_SECONDS
            except Exception:
                print("strugglebus audit feed: storage read failed; retrying", file=sys.stderr, flush=True)
                delay = min(delay * 2, MAX_BACKOFF_SECONDS)
            await asyncio.sleep(delay)
