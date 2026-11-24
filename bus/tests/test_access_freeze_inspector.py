from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from strugglebus.migrations import apply_migrations, load_packaged_migrations


REPOSITORY = Path(__file__).resolve().parents[1]
HELPER = (
    REPOSITORY
    / "deploy/roles/guest_base/files/strugglebus-inspect-access-freeze.py"
)
SPEC = importlib.util.spec_from_file_location("access_freeze_inspector", HELPER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the access-freeze inspector")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
FreezeInspectionError = MODULE.FreezeInspectionError
inspect_access_freeze = MODULE.inspect_access_freeze
MAX_SUPPORTED_SCHEMA_VERSION = MODULE.MAX_SUPPORTED_SCHEMA_VERSION
SCHEMA_11_SQL = (
    REPOSITORY / "deploy/tests/inspector_schema_11.sql"
).read_text(encoding="utf-8")


def _packaged_database(path: Path, version: int) -> sqlite3.Connection:
    database = sqlite3.connect(path)
    apply_migrations(database, load_packaged_migrations()[:10])
    if version == 11:
        database.executescript(SCHEMA_11_SQL)
        database.execute("PRAGMA user_version = 11")
    elif version >= 12:
        # Apply exactly the requested version's migrations. Applying every
        # packaged migration happened to match while 12 was the newest, and
        # would otherwise stamp an older version onto a newer layout.
        apply_migrations(
            database, load_packaged_migrations()[:version],
            database_path=path, backup_dir=path.parent / "schema-backups",
        )
    return database


def _database(path: Path, version: int) -> sqlite3.Connection:
    database = sqlite3.connect(path)
    database.execute(f"PRAGMA user_version = {version}")
    return database


def _create_state_table(database: sqlite3.Connection) -> None:
    database.execute(
        """
        CREATE TABLE agent_access_state (
            singleton INTEGER,
            frozen INTEGER,
            transition TEXT,
            changed_at TEXT,
            reason TEXT
        )
        """
    )


@pytest.mark.parametrize("version", range(6))
def test_legacy_schema_is_reported_as_freeze_unaware(
    tmp_path: Path, version: int
) -> None:
    path = tmp_path / "legacy.db"
    with _database(path, version):
        pass

    assert inspect_access_freeze(path) == {
        "schema_supported": False,
        "frozen": False,
    }


@pytest.mark.parametrize("version", [6, 7, 8, 9])
@pytest.mark.parametrize(
    ("row", "expected_frozen"),
    [
        ((1, 0, "initialized", None, None), False),
        ((1, 1, "freeze", "2026-01-02T03:04:05Z", "incident"), True),
        ((1, 0, "unfreeze", "2026-01-02T04:05:06+00:00", "recovered"), False),
    ],
)
def test_supported_schema_returns_only_the_safety_decision(
    tmp_path: Path,
    version: int,
    row: tuple[object, ...],
    expected_frozen: bool,
) -> None:
    path = tmp_path / "supported.db"
    with _database(path, version) as database:
        _create_state_table(database)
        database.execute(
            "INSERT INTO agent_access_state VALUES (?, ?, ?, ?, ?)",
            row,
        )

    assert inspect_access_freeze(path) == {
        "schema_supported": True,
        "frozen": expected_frozen,
    }


@pytest.mark.parametrize("version", [6, 7, 8, 9])
@pytest.mark.parametrize(
    "rows",
    [
        [],
        [(2, 1, "freeze", "2026-01-02T03:04:05Z", "incident")],
        [
            (1, 1, "freeze", "2026-01-02T03:04:05Z", "incident"),
            (2, 0, "initialized", None, None),
        ],
        [(1, 0, "freeze", "2026-01-02T03:04:05Z", "incident")],
        [(1, 1, "freeze", "not-a-time", "incident")],
        [(1, 1, "freeze", "2026-01-02T03:04:05Z", " padded ")],
    ],
)
def test_supported_schema_rejects_missing_duplicate_or_malformed_state(
    tmp_path: Path,
    version: int,
    rows: list[tuple[object, ...]],
) -> None:
    path = tmp_path / "malformed.db"
    with _database(path, version) as database:
        _create_state_table(database)
        database.executemany(
            "INSERT INTO agent_access_state VALUES (?, ?, ?, ?, ?)",
            rows,
        )

    with pytest.raises(FreezeInspectionError):
        inspect_access_freeze(path)


@pytest.mark.parametrize("version", [25, 99, 2147483647])
def test_future_schema_and_missing_database_fail_closed(
    tmp_path: Path, version: int
) -> None:
    future = tmp_path / "future.db"
    assert MAX_SUPPORTED_SCHEMA_VERSION == 24
    with _packaged_database(future, 11) as database:
        database.execute(f"PRAGMA user_version = {version}")

    with pytest.raises(FreezeInspectionError, match="newer"):
        inspect_access_freeze(future)
    with pytest.raises(FreezeInspectionError, match="unavailable"):
        inspect_access_freeze(tmp_path / "missing.db")


def test_a_forged_supported_version_is_caught_by_the_fingerprint(
    tmp_path: Path,
) -> None:
    """Raising the gate must not let a mislabelled layout through.

    Stamping an older layout with a now-supported version passes the version
    check, so the fingerprint is the only thing left standing between an
    unreviewed schema and a freeze-capability claim. It must refuse.
    """

    forged = tmp_path / "forged.db"
    with _packaged_database(forged, 11) as database:
        database.execute(f"PRAGMA user_version = {MAX_SUPPORTED_SCHEMA_VERSION}")

    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(forged)


@pytest.mark.parametrize("version", [10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
@pytest.mark.parametrize("transition", ["initialized", "freeze", "unfreeze"])
def test_real_packaged_schema_and_exact_cli_result(
    tmp_path: Path, version: int, transition: str
) -> None:
    path = tmp_path / "actual.db"
    with _packaged_database(path, version) as database:
        if transition != "initialized":
            database.execute(
                """
                UPDATE agent_access_state SET frozen = ?, transition = ?,
                    changed_at = '2026-01-02T03:04:05Z', reason = 'local decision'
                """,
                (int(transition == "freeze"), transition),
            )
        assert MODULE._schema_fingerprint(database) == MODULE.SCHEMA_FINGERPRINTS[version]
    before = path.read_bytes()
    expected = {"schema_supported": True, "frozen": transition == "freeze"}

    assert inspect_access_freeze(path) == expected
    result = subprocess.run(
        [sys.executable, "-I", str(HELPER), str(path)],
        capture_output=True, timeout=10, check=False,
    )
    assert result.returncode == 0
    assert result.stderr == b""
    assert result.stdout.decode().strip() == json.dumps(
        expected, sort_keys=True, separators=(",", ":")
    )
    assert path.read_bytes() == before


@pytest.mark.parametrize("version", [10, 11, 12, 13, 14, 15, 16])
def test_version_number_and_freeze_table_alone_are_not_a_recognized_schema(
    tmp_path: Path, version: int
) -> None:
    path = tmp_path / "counterfeit.db"
    with _database(path, version) as database:
        _create_state_table(database)
        database.execute(
            "INSERT INTO agent_access_state VALUES (1, 0, 'initialized', NULL, NULL)"
        )
    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(path)


@pytest.mark.parametrize("version", [10, 11, 12, 13, 14, 15, 16])
@pytest.mark.parametrize(
    "mutation",
    [
        "DROP TABLE agent_enrollment_redemptions",
        "DROP TRIGGER agent_enrollments_immutable_identity",
        "DROP INDEX idx_agent_enrollments_status_expiry",
        "DROP TABLE agent_access_audit",
        "DROP TRIGGER roe_acknowledgements_no_update",
        "ALTER TABLE messages ADD COLUMN unexpected TEXT",
        "CREATE TABLE unexpected (id INTEGER)",
        """
        DROP TABLE agent_access_state;
        CREATE VIEW agent_access_state AS
        SELECT 1 AS singleton, 0 AS frozen, 'initialized' AS transition,
            NULL AS changed_at, NULL AS reason;
        """,
    ],
)
def test_changed_real_schema_fails_closed(
    tmp_path: Path, version: int, mutation: str
) -> None:
    path = tmp_path / "changed.db"
    with _packaged_database(path, version) as database:
        database.executescript(mutation)
    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(path)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("DEFAULT 'prefix'", "DEFAULT 'exact'"),
        ("name_match TEXT NOT NULL", "name_match TEXT"),
        ("CHECK (name_match IN ('prefix', 'exact'))", "CHECK (1)"),
        ("new.name_match <> old.name_match", "0"),
        ("'enrollment name matching is immutable'", "'enrollmentnamematchingisimmutable'"),
    ],
)
def test_schema_11_requires_exact_constraint_and_immutable_trigger(
    tmp_path: Path, old: str, new: str
) -> None:
    path = tmp_path / "changed11.db"
    with _packaged_database(path, 10) as database:
        assert old in SCHEMA_11_SQL
        database.executescript(SCHEMA_11_SQL.replace(old, new))
        database.execute("PRAGMA user_version = 11")
    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(path)


@pytest.mark.parametrize(
    "sql",
    [
        "PRAGMA user_version = 11",
        """
        ALTER TABLE agent_enrollments
        ADD COLUMN name_match TEXT NOT NULL DEFAULT 'prefix'
            CHECK (name_match IN ('prefix', 'exact'));
        PRAGMA user_version = 11;
        """,
    ],
)
def test_incomplete_schema_11_migration_fails_closed(tmp_path: Path, sql: str) -> None:
    path = tmp_path / "incomplete.db"
    with _packaged_database(path, 10) as database:
        database.executescript(sql)
    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(path)


def test_schema_11_cannot_masquerade_as_schema_10(tmp_path: Path) -> None:
    path = tmp_path / "wrong-version.db"
    with _packaged_database(path, 11) as database:
        database.execute("PRAGMA user_version = 10")
    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(path)


@pytest.mark.parametrize("mutation", [
    "DROP TRIGGER agents_valid_lifecycle",
    "DROP TRIGGER agents_no_delete",
    "DROP TRIGGER agents_reconnect_epoch_guard",
    "DROP TRIGGER agent_reconnect_valid_update",
    "DROP TRIGGER agent_reconnect_no_delete",
    "DROP TABLE agent_lifecycle_audit",
    "DROP INDEX idx_agent_reconnect_pending_agent",
    "PRAGMA user_version = 11",
])
def test_schema_12_requires_exact_containment_and_grant_guards(tmp_path, mutation):
    path = tmp_path / "changed12.db"
    with _packaged_database(path, 12) as database:
        database.executescript(mutation)
    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(path)


def test_schema_11_cannot_claim_operator_lifecycle_support(tmp_path):
    path = tmp_path / "incomplete12.db"
    with _packaged_database(path, 11) as database:
        database.execute("PRAGMA user_version = 12")
    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(path)


@pytest.mark.parametrize("mutation", [
    "DROP INDEX idx_messages_post_request",
    "DROP TRIGGER messages_post_request_immutable",
    "DROP TRIGGER messages_keyed_immutable",
    "DROP TRIGGER messages_keyed_no_delete",
    "PRAGMA user_version = 15",
])
def test_schema_16_requires_exact_retry_guards(tmp_path, mutation):
    path = tmp_path / "changed16.db"
    with _packaged_database(path, 16) as database:
        database.executescript(mutation)
    before = path.read_bytes()
    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("version", [10, 11, 12, 13, 14, 15, 16])
@pytest.mark.parametrize(
    ("changed_at", "reason"),
    [
        ("not-a-time", "incident"),
        ("2026-01-02T03:04:05", "incident"),
        ("2026-01-02T03:04:05Z", ""),
        ("2026-01-02T03:04:05Z", " padded "),
        ("2026-01-02T03:04:05Z", "a" * 257),
        ("2026-01-02T03:04:05Z", "a\x00b"),
    ],
)
def test_actual_schema_rejects_invalid_freeze_state(
    tmp_path: Path, version: int, changed_at: str, reason: str
) -> None:
    path = tmp_path / "bad-state.db"
    with _packaged_database(path, version) as database:
        database.execute(
            """
            UPDATE agent_access_state
            SET frozen = 1, transition = 'freeze', changed_at = ?, reason = ?
            """,
            (changed_at, reason),
        )
    with pytest.raises(FreezeInspectionError, match="invalid"):
        inspect_access_freeze(path)


@pytest.mark.parametrize("version", [10, 11, 12, 13, 14, 15, 16])
def test_actual_schema_missing_freeze_state_fails_closed(
    tmp_path: Path, version: int
) -> None:
    path = tmp_path / "missing-state.db"
    with _packaged_database(path, version) as database:
        database.execute("DELETE FROM agent_access_state")
    with pytest.raises(FreezeInspectionError, match="missing"):
        inspect_access_freeze(path)


@pytest.mark.parametrize("version", [10, 11, 12, 13, 14, 15, 16])
def test_schema_fingerprint_survives_analyze_and_vacuum(
    tmp_path: Path, version: int
) -> None:
    path = tmp_path / "maintained.db"
    with _packaged_database(path, version) as database:
        database.execute("ANALYZE")
    with sqlite3.connect(path) as database:
        database.execute("VACUUM")
    assert inspect_access_freeze(path) == {"schema_supported": True, "frozen": False}


def test_schema_11_fixture_matches_packaged_migration_when_integrated() -> None:
    migrations = load_packaged_migrations()
    if len(migrations) >= 11:
        def statements(sql: str) -> str:
            return "\n".join(
                line for line in sql.splitlines() if not line.startswith("--")
            ).strip()
        assert statements(migrations[10].sql) == statements(SCHEMA_11_SQL)


def test_negative_version_and_corrupt_database_fail_without_stdout(tmp_path: Path) -> None:
    path = tmp_path / "invalid.db"
    with _database(path, -1):
        pass
    with pytest.raises(FreezeInspectionError, match="unrecognized"):
        inspect_access_freeze(path)
    path.write_bytes(b"not a SQLite database")
    result = subprocess.run(
        [sys.executable, "-I", str(HELPER), str(path)],
        capture_output=True, timeout=10, check=False,
    )
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr.decode().strip() == "database freeze state is unreadable"
