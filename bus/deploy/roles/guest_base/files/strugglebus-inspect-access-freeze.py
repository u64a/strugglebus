#!/usr/bin/python3.13
"""Read only the persisted access-freeze decision for release safety gates."""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from urllib.parse import quote

FREEZE_SCHEMA_VERSION = 6
MAX_SUPPORTED_SCHEMA_VERSION = 25
MAX_REASON_CHARACTERS = 256
MAX_REASON_BYTES = 1024
# Fixed, reviewed sqlite_schema fingerprints, not candidate release metadata.
# Schema 12 additionally binds reversible containment and reconnect history.
# Schema 13 adds the mobile monitor principal tables. That migration does not
# touch agent_access_state, so freeze semantics are unchanged and this
# inspector remains freeze-capable against it; the fingerprint is widened
# deliberately rather than the gate being relaxed.
# Schema 14 adds device write grants and action confirmations. Schema 15 adds
# deciding-identity columns to the freeze audit without changing
# agent_access_state. The freeze state this inspector reads is unchanged.
# Schema 16 adds message retry bindings and immutable keyed-message guards,
# without changing agent_access_state or the deciding-identity audit.
# Schema 17 adds isolated onboarding service-principal state and does not
# change agent_access_state or its audit contract.
# Schema 20 adds task message claims and does not change agent_access_state
# or its audit contract.
# Schema 18 adds the credentialless maintenance announcement author and does
# not change agent_access_state or its audit contract.
# Schema 19 adds the credentialless #humans operator author and does not
# change agent_access_state or its audit contract.
# Schema 20 adds task message claims and does not change agent_access_state
# or its audit contract.
# Schema 21 adds satellite site admission records and does not change
# agent_access_state or its audit contract.
# Schema 22 adds SPN identity expiry and does not change agent_access_state
# or its audit contract.
# Schema 23 adds the retention setting and does not change agent_access_state
# or its audit contract.
# Schema 24 adds worker host enrolment codes and the site document store, and
# lets the operator author post one fixed-shape signed host command outside
# #humans. It does not change agent_access_state or its audit contract.
# Schema 25 adds the host marks, host status and the stored event log. It does
# not change agent_access_state or its audit contract.
# Widened on the same terms: a reviewed fingerprint, never a relaxed gate. An
# unrecognised schema must keep failing closed - that refusal is what stops an
# unreviewed layout being declared freeze-capable.
# Tests rebuild these layouts from packaged SQL and the attributed 0011 fixture.
SCHEMA_FINGERPRINTS = {
    10: "7448d0a93e969a310ed2bf9ecad981870df91e0361ed5f2759ca760bd80d72bb",
    11: "9b910a6422103680afb36f9d14d0a901f5f8ccd18d59190a652f0a1ae460e12b",
    12: "dab8e8a79a31a84f215e34037e1e08fec23f875d61bd67ffedba91c6bdbc46cc",
    13: "08c3f59569b0dd2412e8212342713f2da5a47e76702311dcc5e7d54a511bcc04",
    14: "6725feda6c7b6c2c8e6b2f21a2c6313a477b9a68f4d0a102a7f33d6aa167551a",
    15: "68af63f61219a10647c436f7cbc4dd774ca4dd78aa9c5c3b33fa8524554f4482",
    16: "dfaa2ef82a7e95c25816a887b47a3628d99d92284cf42c99692782f7c50d218f",
    17: "cfa4d54fb0816cf64e82b1a08a77635ee445743d3be8460a44bcda01ae378cd9",
    18: "5918173749552fb177b8ac9e49fe1545ecc570b75fc9727d5afad3f11ca45773",
    19: "86bddb53526657c51b10f4aa6d0c0ed35fd2f55c2233eb9d2951c7b8868bc0b5",
    20: "7203078e8afeb93c994887032d56e439d4ee686d3574a694a0a1d79e2b9ac292",
    21: "1f08c7751a2df9a8df25b995fc3fe7fef7bb35c642c81c1fda6de6f335b05c16",
    22: "4090cf543120b58881014f63ebebf4df26a8ec94dc383009c67fceffec51c941",
    23: "40480404f87bf7945a038c156598b0aaa9054b488d5a9d2b32e9ad0dc1b3f6ff",
    24: "7f998570da1b8eb0ab8ea732c9c9263e5240624e2f6c4be529fbb30b8f25b1eb",
    25: "125331e20446c99b9b8141eb87634ad4629ff98bd6ba9ce1bff8171ef115fa70",
}
_SQL_TOKENS = re.compile(
    r"""'(?:[^']|'')*'|"(?:[^"]|"")*"|`(?:[^`]|``)*`|\[[^\]]*\]|\S"""
)


class FreezeInspectionError(RuntimeError):
    pass


def _require_regular(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FreezeInspectionError("database is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise FreezeInspectionError("database is not a protected regular file")


def _valid_utc(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _schema_fingerprint(database: sqlite3.Connection) -> str:
    rows = database.execute(
        """
        SELECT type, name, tbl_name, sql FROM sqlite_schema
        WHERE name NOT GLOB 'sqlite_*'
        ORDER BY type, name
        LIMIT 193
        """
    ).fetchall()
    if len(rows) > 192 or sum(len(row[3] or "") for row in rows) > 131072:
        raise FreezeInspectionError("database schema is unrecognized")
    # Ignore formatting outside quoted SQL, but preserve literals, constraints,
    # columns, indexes and trigger bodies. Root pages and ANALYZE data vary.
    layout = [
        (kind, name, table, "".join(_SQL_TOKENS.findall(sql or "")))
        for kind, name, table, sql in rows
    ]
    return hashlib.sha256(
        json.dumps(layout, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def inspect_access_freeze(path: Path) -> dict[str, bool]:
    if not path.is_absolute():
        raise FreezeInspectionError("database path must be absolute")
    _require_regular(path)
    uri = f"file:{quote(os.fspath(path), safe='/')}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as database:
            database.execute("PRAGMA query_only = ON")
            database.execute("BEGIN")
            version = int(database.execute("PRAGMA user_version").fetchone()[0])
            if version < 0:
                raise FreezeInspectionError("database schema is unrecognized")
            if version < FREEZE_SCHEMA_VERSION:
                return {"schema_supported": False, "frozen": False}
            if version > MAX_SUPPORTED_SCHEMA_VERSION:
                raise FreezeInspectionError("database schema is newer than the safety gate")
            if (
                version >= 10
                and _schema_fingerprint(database) != SCHEMA_FINGERPRINTS[version]
            ):
                raise FreezeInspectionError("database schema is unrecognized")
            rows = database.execute(
                """
                SELECT singleton, frozen, transition, changed_at, reason
                FROM agent_access_state
                LIMIT 2
                """
            ).fetchall()
    except sqlite3.Error as error:
        raise FreezeInspectionError("database freeze state is unreadable") from error
    if len(rows) != 1 or rows[0][0] != 1:
        raise FreezeInspectionError("database freeze state is missing")
    _, frozen, transition, changed_at, reason = rows[0]
    if transition == "initialized":
        valid = frozen == 0 and changed_at is None and reason is None
    else:
        valid = (
            transition in {"freeze", "unfreeze"}
            and frozen == int(transition == "freeze")
            and _valid_utc(changed_at)
            and isinstance(reason, str)
            and reason == reason.strip()
            and bool(reason)
            and "\x00" not in reason
            and len(reason) <= MAX_REASON_CHARACTERS
            and len(reason.encode("utf-8")) <= MAX_REASON_BYTES
        )
    if not valid:
        raise FreezeInspectionError("database freeze state is invalid")
    return {"schema_supported": True, "frozen": bool(frozen)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    try:
        result = inspect_access_freeze(args.database)
    except FreezeInspectionError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
