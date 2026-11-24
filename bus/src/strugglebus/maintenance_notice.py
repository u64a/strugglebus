"""Publish one fixed, idempotent board notice before a maintenance outage."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import sqlite3
import uuid

from strugglebus.service import _serialize_message_metadata, _validate_message_body
from strugglebus.store import SQLiteStore

VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})")
OPERATION = re.compile(r"[0-9a-f]{32}")


def _require_valid_notice(
    database: Path,
    backup_dir: Path,
    operation_id: str,
    version: str,
    scheduled_at: int,
    automatic: bool,
) -> None:
    if (
        not database.is_absolute()
        or not backup_dir.is_absolute()
        or OPERATION.fullmatch(operation_id) is None
        or VERSION.fullmatch(version) is None
        or type(scheduled_at) is not int
        or not 0 <= scheduled_at <= 253402300799
        or type(automatic) is not bool
    ):
        raise ValueError("invalid maintenance notice")


def publish_notice(
    *,
    database: Path,
    backup_dir: Path,
    operation_id: str,
    version: str,
    scheduled_at: int,
    automatic: bool,
    now: datetime | None = None,
) -> int:
    _require_valid_notice(
        database, backup_dir, operation_id, version, scheduled_at, automatic,
    )
    instant = datetime.now(UTC) if now is None else now.astimezone(UTC)
    scheduled = datetime.fromtimestamp(scheduled_at, UTC)
    mode = "automatic" if automatic else "operator-triggered"
    body = (
        f"Strugglebus maintenance: release {version} is scheduled for installation "
        f"at {scheduled.isoformat()}. The bus will disconnect briefly and agents "
        "should reconnect and start a fresh catch-up after service returns."
    )
    metadata = {
        "maintenance": {
            "automatic": automatic,
            "mode": mode,
            "operation_id": operation_id,
            "scheduled_at": scheduled_at,
            "version": version,
        }
    }
    _validate_message_body(body, 4096)
    metadata_json = _serialize_message_metadata(metadata, 4096)
    store = SQLiteStore(database, backup_dir=backup_dir, busy_timeout_ms=30_000)
    message = store.create_maintenance_announcement(
        message_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"strugglebus-maintenance:{operation_id}")),
        body=body,
        metadata_json=metadata_json,
        created_at=instant,
        request_id=str(uuid.UUID(hex=operation_id)),
    )
    return message.seq


def _failure_code(error: Exception) -> str:
    current: BaseException | None = error
    for _ in range(8):
        if isinstance(current, sqlite3.Error):
            name = getattr(current, "sqlite_errorname", None)
            if isinstance(name, str) and re.fullmatch(r"SQLITE_[A-Z0-9_]{1,56}", name):
                return name
            return "SQLITE_ERROR"
        current = current.__cause__ or current.__context__
        if current is None:
            break
    return "NON_SQLITE_ERROR"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--backup-dir", required=True, type=Path)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--scheduled-at", required=True, type=int)
    parser.add_argument("--automatic", action="store_true")
    args = parser.parse_args(argv)
    try:
        sequence = publish_notice(
            database=args.database,
            backup_dir=args.backup_dir,
            operation_id=args.operation_id,
            version=args.version,
            scheduled_at=args.scheduled_at,
            automatic=args.automatic,
        )
    except Exception as error:
        print(json.dumps({
            "ok": False,
            "error": "maintenance_notice_failed",
            "cause": _failure_code(error),
        }, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "sequence": sequence}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
