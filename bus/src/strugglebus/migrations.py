"""Ordered, transactional SQLite schema migrations."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from functools import lru_cache
from pathlib import Path

from strugglebus.backup import create_verified_backup
from strugglebus.errors import (
    BackupError,
    DatabaseVersionError,
    MigrationError,
    MissingMigrationError,
)

MIGRATION_FILES = (
    "0001_initial.sql",
    "0002_unique_agent_key_hash.sql",
    "0003_catch_up_search_indexes.sql",
    "0004_cursor_scopes.sql",
    "0005_reply_lookup_index.sql",
    "0006_agent_access_freeze.sql",
    "0007_dashboard_activity_index.sql",
    "0008_agent_rules_of_engagement.sql",
    "0009_agent_credentials.sql",
    "0010_agent_enrollments.sql",
    "0011_enrollment_name_match.sql",
    "0012_agent_operator_lifecycle.sql",
    "0013_mobile_monitor_principal.sql",
    "0014_mobile_write_grants.sql",
    "0015_access_freeze_actor.sql",
    "0016_message_post_retry.sql",
    "0017_spn_onboarding.sql",
    "0018_maintenance_announcements.sql",
    "0019_human_channel.sql",
    "0020_message_claims.sql",
    "0021_satellite_sites.sql",
    "0022_spn_identity_expiry.sql",
    "0023_retention.sql",
    "0024_worker_hosts.sql",
    "0025_hosts_and_events.sql",
)
LATEST_SCHEMA_VERSION = len(MIGRATION_FILES)
_MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{4})_[a-z0-9_]+\.sql$")
_FORBIDDEN_STATEMENT = re.compile(
    r"^(?:BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b|"
    r"^PRAGMA\s+user_version\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    sql: str


def load_packaged_migrations() -> tuple[Migration, ...]:
    migration_root = files("strugglebus").joinpath("migrations")
    migrations: list[Migration] = []
    for expected_version, filename in enumerate(MIGRATION_FILES, start=1):
        match = _MIGRATION_NAME.fullmatch(filename)
        if match is None or int(match.group("version")) != expected_version:
            raise MissingMigrationError(
                f"migration {expected_version} has an invalid filename"
            )
        try:
            sql = migration_root.joinpath(filename).read_text(encoding="utf-8")
        except (FileNotFoundError, ModuleNotFoundError) as error:
            raise MissingMigrationError(
                f"migration {expected_version} is missing"
            ) from error
        if not sql.strip():
            raise MissingMigrationError(f"migration {expected_version} is empty")
        migrations.append(Migration(expected_version, filename, sql))
    return tuple(migrations)


def _significant_sql(statement: str) -> str:
    """Drop blank and comment-only lines so the statement keyword comes first."""
    significant_lines = (
        line
        for line in statement.splitlines()
        if line.strip() and not line.lstrip().startswith("--")
    )
    return "\n".join(significant_lines).lstrip()


def _validate_migrations(migrations: tuple[Migration, ...]) -> None:
    expected_versions = tuple(range(1, len(migrations) + 1))
    actual_versions = tuple(migration.version for migration in migrations)
    if actual_versions != expected_versions:
        raise MissingMigrationError(
            "migrations must contain every ordered version starting at 1"
        )
    for migration in migrations:
        for statement in _split_sql_script(migration.sql):
            if _FORBIDDEN_STATEMENT.search(_significant_sql(statement)):
                raise MigrationError(
                    f"migration {migration.version} contains transaction control"
                )


def _split_sql_script(script: str) -> tuple[str, ...]:
    statements: list[str] = []
    pending: list[str] = []
    for line in script.splitlines(keepends=True):
        pending.append(line)
        candidate = "".join(pending)
        if sqlite3.complete_statement(candidate):
            statements.append(candidate)
            pending.clear()
    if "".join(pending).strip():
        raise MigrationError("migration contains an incomplete SQL statement")
    return tuple(statements)


def _user_object_count(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        """
        SELECT COUNT(*)
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        """
    ).fetchone()
    return int(row[0])


@lru_cache(maxsize=1)
def _pinned_schema_layout() -> tuple[tuple[str, str], ...]:
    """Pin the exact schema, not merely the claimed user_version.

    This previously pinned only the objects introduced by the newest
    migration, which meant every new migration silently retired the previous
    one's guards from the check: adding the mobile principal tables stopped
    schema 12's lifecycle triggers from being validated at all. Every object
    here is created by a migration, so replaying them yields an exact
    reference and pinning all of it costs nothing while keeping older safety
    guards covered forever.
    """

    with sqlite3.connect(":memory:") as reference:
        for migration in load_packaged_migrations():
            for statement in _split_sql_script(migration.sql):
                reference.execute(statement)
        return tuple(
            (name, " ".join(sql.split()))
            for name, sql in reference.execute(
                "SELECT name, sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name"
            )
        )


def validate_pinned_schema(connection: sqlite3.Connection) -> None:
    for name, expected in _pinned_schema_layout():
        row = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE name = ?", (name,),
        ).fetchone()
        if row is None or row[0] is None or " ".join(row[0].split()) != expected:
            raise MigrationError("schema is incomplete or invalid")


def _create_verified_backup(
    *,
    database_path: Path,
    backup_dir: Path,
    current_version: int,
) -> Path:
    prefix = f"{database_path.name}.v{current_version}."
    try:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        created = create_verified_backup(
            database_path,
            backup_dir,
            destination_name=f"{prefix}{timestamp}.backup",
        )
    except BackupError as error:
        raise MigrationError("could not create verified pre-migration backup") from error
    _prune_pre_migration_backups(backup_dir, prefix, keep=created)
    return created


PRE_MIGRATION_BACKUP_RETENTION = 3


def _pre_migration_copies(backup_dir: Path, prefix: str) -> list[Path]:
    """Return one schema version's copies; the timestamp in the name sorts oldest first."""
    return sorted(
        path for path in backup_dir.iterdir()
        if path.name.startswith(prefix) and path.name.endswith(".backup")
        and path.is_file() and not path.is_symlink()
    )


def _prune_pre_migration_backups(backup_dir: Path, prefix: str, *, keep: Path) -> None:
    """Keep the newest few pre-migration copies taken from one schema version.

    A migration that fails is retried every time the service restarts, and each
    attempt copies the whole database first. Without a bound, a restart loop
    fills the disk with identical copies. The copy just made is never removed.
    """

    try:
        copies = _pre_migration_copies(backup_dir, prefix)
    except OSError:
        return
    for path in copies[:-PRE_MIGRATION_BACKUP_RETENTION]:
        if path != keep:
            try:
                path.unlink()
            except OSError:
                pass


def _begin_and_read_version(connection: sqlite3.Connection, latest_version: int) -> int:
    connection.execute("BEGIN IMMEDIATE")
    current_version = int(
        connection.execute("PRAGMA user_version").fetchone()[0]
    )
    if current_version > latest_version:
        raise DatabaseVersionError(
            f"database version {current_version} is newer than supported "
            f"version {latest_version}"
        )
    return current_version


def _validate_packaged_schema(connection: sqlite3.Connection, latest_version: int) -> None:
    """Pin the layout only when the packaged migration set was applied."""
    if latest_version == LATEST_SCHEMA_VERSION:
        validate_pinned_schema(connection)


def _prepare_pending_migration(
    connection: sqlite3.Connection,
    current_version: int,
    *,
    database_path: Path | None,
    backup_dir: Path | None,
) -> None:
    """Refuse unrecognized databases and back up existing ones before changes."""
    if current_version == 0 and _user_object_count(connection):
        raise DatabaseVersionError(
            "database has objects but no recognized schema version"
        )
    if current_version > 0:
        if database_path is None or backup_dir is None:
            raise MigrationError(
                "existing databases require a verified pre-migration backup"
            )
        _create_verified_backup(
            database_path=database_path,
            backup_dir=backup_dir,
            current_version=current_version,
        )


def _execute_migrations(
    connection: sqlite3.Connection,
    pending: tuple[Migration, ...],
) -> None:
    for migration in pending:
        for statement in _split_sql_script(migration.sql):
            connection.execute(statement)
        connection.execute(f"PRAGMA user_version = {migration.version}")


def apply_migrations(
    connection: sqlite3.Connection,
    migrations: tuple[Migration, ...],
    *,
    database_path: Path | None = None,
    backup_dir: Path | None = None,
) -> int:
    """Apply all pending migrations atomically and return the resulting version."""

    _validate_migrations(migrations)
    latest_version = len(migrations)
    current_version = 0
    pending = migrations
    try:
        current_version = _begin_and_read_version(connection, latest_version)
        if current_version == latest_version:
            _validate_packaged_schema(connection, latest_version)
            connection.execute("COMMIT")
            return current_version
        _prepare_pending_migration(
            connection,
            current_version,
            database_path=database_path,
            backup_dir=backup_dir,
        )
        pending = migrations[current_version:]
        _execute_migrations(connection, pending)
        _validate_packaged_schema(connection, latest_version)
        connection.execute("COMMIT")
    except (sqlite3.Error, MigrationError) as error:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        if isinstance(error, MigrationError):
            raise
        failed_version = pending[0].version if pending else current_version
        raise MigrationError(
            f"migration starting at version {failed_version} failed"
        ) from error
    return latest_version


def migrate_database(
    connection: sqlite3.Connection,
    *,
    database_path: Path,
    backup_dir: Path,
) -> int:
    return apply_migrations(
        connection,
        load_packaged_migrations(),
        database_path=database_path,
        backup_dir=backup_dir,
    )
