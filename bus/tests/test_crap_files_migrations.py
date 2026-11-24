"""Failure paths of schema migration, its backups and the trust-anchor loader."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

import strugglebus.ca as ca
import strugglebus.migrations as migrations
from strugglebus.errors import (
    DatabaseVersionError,
    MigrationError,
    MissingMigrationError,
    TrustAnchorError,
)
from strugglebus.migrations import Migration, apply_migrations

FIRST = Migration(1, "0001_first.sql", "CREATE TABLE first (id INTEGER PRIMARY KEY);\n")
SECOND = Migration(2, "0002_second.sql", "CREATE TABLE second (id INTEGER PRIMARY KEY);\n")
BROKEN = Migration(2, "0002_broken.sql", "CREATE TABLE first (id INTEGER PRIMARY KEY);\n")


def _connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, isolation_level=None)


def _tables(connection: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        )
    ]


def _version(connection: sqlite3.Connection) -> int:
    return connection.execute("PRAGMA user_version").fetchone()[0]


# --- Pre-migration backup retention --------------------------------------------


def _copy(directory: Path, name: str) -> Path:
    path = directory / name
    path.write_bytes(b"copy")
    return path


def test_pruning_keeps_the_newest_three_copies_of_one_schema_version(tmp_path):
    prefix = "bus.db.v4."
    copies = [_copy(tmp_path, f"{prefix}2026010{day}T000000Z.backup") for day in range(1, 7)]
    other_version = _copy(tmp_path, "bus.db.v3.20250101T000000Z.backup")
    not_a_backup = _copy(tmp_path, f"{prefix}20250101T000000Z.partial")
    folder = tmp_path / f"{prefix}20240101T000000Z.backup"
    folder.mkdir()

    migrations._prune_pre_migration_backups(tmp_path, prefix, keep=copies[-1])

    assert [path.exists() for path in copies] == [False, False, False, True, True, True]
    assert other_version.exists()
    assert not_a_backup.exists()
    assert folder.is_dir()


def test_pruning_never_removes_the_copy_just_made(tmp_path):
    prefix = "bus.db.v4."
    copies = [_copy(tmp_path, f"{prefix}2026010{day}T000000Z.backup") for day in range(1, 6)]

    # A clock that stepped backwards can sort the new copy before older ones.
    migrations._prune_pre_migration_backups(tmp_path, prefix, keep=copies[0])

    assert [path.exists() for path in copies] == [True, False, True, True, True]


def test_pruning_ignores_symbolic_links(tmp_path):
    prefix = "bus.db.v4."
    target = _copy(tmp_path, "elsewhere")
    link = tmp_path / f"{prefix}20200101T000000Z.backup"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable")
    copies = [_copy(tmp_path, f"{prefix}2026010{day}T000000Z.backup") for day in range(1, 4)]

    migrations._prune_pre_migration_backups(tmp_path, prefix, keep=copies[-1])

    assert link.is_symlink()
    assert target.exists()
    assert all(path.exists() for path in copies)


def test_pruning_tolerates_an_unreadable_directory(tmp_path):
    migrations._prune_pre_migration_backups(
        tmp_path / "absent", "bus.db.v4.", keep=tmp_path / "absent" / "kept",
    )


class _FakeCopy:
    def __init__(self, name: str, *, removable: bool = True) -> None:
        self.name = name
        self.removable = removable
        self.removed = False

    def __lt__(self, other: _FakeCopy) -> bool:
        return self.name < other.name

    def is_file(self) -> bool:
        return True

    def is_symlink(self) -> bool:
        return False

    def unlink(self) -> None:
        if not self.removable:
            raise PermissionError("synthetic denial")
        self.removed = True


class _FakeDirectory:
    def __init__(self, entries: list[_FakeCopy]) -> None:
        self._entries = entries

    def iterdir(self):
        return iter(self._entries)


def test_pruning_continues_past_a_copy_that_cannot_be_removed():
    prefix = "bus.db.v4."
    entries = [
        _FakeCopy(f"{prefix}1.backup", removable=False),
        _FakeCopy(f"{prefix}2.backup"),
        _FakeCopy(f"{prefix}3.backup"),
        _FakeCopy(f"{prefix}4.backup"),
        _FakeCopy(f"{prefix}5.backup"),
    ]

    migrations._prune_pre_migration_backups(
        _FakeDirectory(list(reversed(entries))), prefix, keep=entries[-1],
    )

    assert [entry.removed for entry in entries] == [False, True, False, False, False]


# --- Applying migrations ------------------------------------------------------


def test_custom_migration_sets_apply_in_order_and_are_idempotent(tmp_path):
    with closing(_connect(tmp_path / "bus.db")) as connection:
        assert apply_migrations(connection, (FIRST, SECOND)) == 2
        assert _tables(connection) == ["first", "second"]
        assert _version(connection) == 2
        assert not connection.in_transaction

        assert apply_migrations(connection, (FIRST, SECOND)) == 2
        assert not connection.in_transaction


def test_existing_database_is_not_migrated_without_backup_locations(tmp_path):
    database = tmp_path / "bus.db"
    with closing(_connect(database)) as connection:
        apply_migrations(connection, (FIRST,))

        for options in (
            {},
            {"database_path": database},
            {"backup_dir": tmp_path / "backups"},
        ):
            with pytest.raises(MigrationError, match="require a verified pre-migration backup"):
                apply_migrations(connection, (FIRST, SECOND), **options)
            assert not connection.in_transaction
        assert _tables(connection) == ["first"]
        assert _version(connection) == 1
    assert not (tmp_path / "backups").exists()


def test_upgrade_backs_up_the_old_schema_version_first(tmp_path):
    database = (tmp_path / "bus.db").resolve()
    backups = tmp_path.resolve() / "backups"
    with closing(_connect(database)) as connection:
        apply_migrations(connection, (FIRST,))

        assert apply_migrations(
            connection, (FIRST, SECOND), database_path=database, backup_dir=backups,
        ) == 2
        assert _tables(connection) == ["first", "second"]

    (copy,) = [path for path in backups.iterdir() if path.name.endswith(".backup")]
    assert copy.name.startswith("bus.db.v1.")
    with closing(sqlite3.connect(copy)) as backup:
        assert _tables(backup) == ["first"]
        assert _version(backup) == 1


def test_upgrade_is_abandoned_when_the_backup_cannot_be_made(tmp_path):
    database = (tmp_path / "bus.db").resolve()
    with closing(_connect(database)) as connection:
        apply_migrations(connection, (FIRST,))

        with pytest.raises(MigrationError, match="could not create verified pre-migration backup"):
            apply_migrations(
                connection,
                (FIRST, SECOND),
                database_path=tmp_path.resolve() / "absent.db",
                backup_dir=tmp_path.resolve() / "backups",
            )
        assert not connection.in_transaction
        assert _tables(connection) == ["first"]
        assert _version(connection) == 1


def test_failed_statement_names_the_first_pending_version_and_rolls_back(tmp_path):
    database = (tmp_path / "bus.db").resolve()
    with closing(_connect(database)) as connection:
        apply_migrations(connection, (FIRST,))

        with pytest.raises(MigrationError, match="migration starting at version 2 failed") as raised:
            apply_migrations(
                connection,
                (FIRST, BROKEN),
                database_path=database,
                backup_dir=tmp_path.resolve() / "backups",
            )
        assert isinstance(raised.value.__cause__, sqlite3.Error)
        assert not connection.in_transaction
        assert _version(connection) == 1


def test_failure_before_the_version_is_known_names_the_first_migration(tmp_path):
    with closing(_connect(tmp_path / "bus.db")) as connection:
        connection.execute("BEGIN")

        with pytest.raises(MigrationError, match="migration starting at version 1 failed"):
            apply_migrations(connection, (FIRST,))
        assert not connection.in_transaction
        assert _tables(connection) == []


def test_newer_and_unversioned_databases_are_refused_and_released(tmp_path):
    with closing(_connect(tmp_path / "newer.db")) as connection:
        connection.execute("PRAGMA user_version = 3")
        with pytest.raises(DatabaseVersionError, match="version 3 is newer than supported version 2"):
            apply_migrations(connection, (FIRST, SECOND))
        assert not connection.in_transaction

    with closing(_connect(tmp_path / "foreign.db")) as connection:
        connection.execute("CREATE TABLE unrelated (id INTEGER)")
        with pytest.raises(DatabaseVersionError, match="objects but no recognized schema version"):
            apply_migrations(connection, (FIRST,))
        assert not connection.in_transaction
        assert _tables(connection) == ["unrelated"]


def test_packaged_schema_drift_is_detected_at_the_current_version(tmp_path):
    with closing(_connect(tmp_path / "bus.db")) as connection:
        packaged = migrations.load_packaged_migrations()
        assert apply_migrations(connection, packaged) == migrations.LATEST_SCHEMA_VERSION
        index = connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'index' AND sql IS NOT NULL LIMIT 1"
        ).fetchone()[0]
        connection.execute(f'DROP INDEX "{index}"')

        with pytest.raises(MigrationError, match="schema is incomplete or invalid"):
            apply_migrations(connection, packaged)
        assert not connection.in_transaction


# --- Validating the migration set ---------------------------------------------


@pytest.mark.parametrize(
    "versions",
    [(2,), (1, 3), (2, 1), (1, 1)],
    ids=["missing-first", "gap", "out-of-order", "duplicate"],
)
def test_migration_versions_must_be_contiguous_from_one(versions):
    candidates = tuple(
        Migration(version, f"{version:04d}_x.sql", "SELECT 1;\n") for version in versions
    )

    with pytest.raises(MissingMigrationError, match="every ordered version starting at 1"):
        migrations._validate_migrations(candidates)


@pytest.mark.parametrize(
    "statement",
    [
        "COMMIT;",
        "begin immediate;",
        "ROLLBACK;",
        "SAVEPOINT before;",
        "RELEASE before;",
        "PRAGMA user_version = 9;",
        "-- leading note\n\n   Commit;",
    ],
)
def test_migrations_must_not_control_their_own_transaction(statement):
    candidate = Migration(1, "0001_x.sql", f"CREATE TABLE t (id INTEGER);\n{statement}\n")

    with pytest.raises(MigrationError, match="migration 1 contains transaction control"):
        migrations._validate_migrations((candidate,))


def test_transaction_words_inside_comments_and_triggers_are_allowed():
    sql = (
        "-- BEGIN the schema\n"
        "CREATE TABLE t (id INTEGER);\n"
        "CREATE TRIGGER guard BEFORE DELETE ON t\n"
        "BEGIN\n"
        "    SELECT RAISE(ABORT, 'rows are permanent');\n"
        "END;\n"
        "PRAGMA foreign_keys = ON;\n"
    )

    migrations._validate_migrations((Migration(1, "0001_x.sql", sql),))

    assert len(migrations._split_sql_script(sql)) == 3


def test_incomplete_statement_is_refused_before_anything_runs(tmp_path):
    candidate = Migration(1, "0001_x.sql", "CREATE TABLE t (id INTEGER);\nCREATE TABLE u (")
    with closing(_connect(tmp_path / "bus.db")) as connection:
        with pytest.raises(MigrationError, match="incomplete SQL statement"):
            apply_migrations(connection, (candidate,))
        assert not connection.in_transaction
        assert _tables(connection) == []


def test_packaged_migration_names_must_carry_their_position(monkeypatch):
    for names in (("0002_second.sql",), ("second.sql",), ("0001-First.sql",)):
        monkeypatch.setattr(migrations, "MIGRATION_FILES", names)
        with pytest.raises(MissingMigrationError, match="has an invalid filename"):
            migrations.load_packaged_migrations()


def test_packaged_migrations_must_exist_and_have_content(monkeypatch, tmp_path):
    package = tmp_path / "package"
    (package / "migrations").mkdir(parents=True)
    (package / "migrations" / "0001_first.sql").write_text(FIRST.sql, encoding="utf-8")
    (package / "migrations" / "0002_blank.sql").write_text("  \n\n", encoding="utf-8")
    monkeypatch.setattr(migrations, "files", lambda name: package)

    monkeypatch.setattr(migrations, "MIGRATION_FILES", ("0001_first.sql",))
    assert migrations.load_packaged_migrations() == (FIRST,)

    monkeypatch.setattr(migrations, "MIGRATION_FILES", ("0001_first.sql", "0002_absent.sql"))
    with pytest.raises(MissingMigrationError, match="migration 2 is missing"):
        migrations.load_packaged_migrations()

    monkeypatch.setattr(migrations, "MIGRATION_FILES", ("0001_first.sql", "0002_blank.sql"))
    with pytest.raises(MissingMigrationError, match="migration 2 is empty"):
        migrations.load_packaged_migrations()


# --- Trust anchor loading -----------------------------------------------------

UNAVAILABLE = "Configured LAN CA publication is unavailable"
DIGEST = "a" * 64


def test_manual_trust_is_only_an_entirely_empty_configuration():
    assert ca.load_trust_anchor("", "") is None


@pytest.mark.parametrize(
    "digest",
    ["", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 63 + " "],
    ids=["empty", "short", "long", "uppercase", "not-hex", "whitespace"],
)
def test_trust_anchor_digest_must_be_lowercase_sha256(tmp_path, digest):
    bundle = tmp_path.resolve() / "ca.pem"
    bundle.write_bytes(b"irrelevant")

    with pytest.raises(TrustAnchorError, match=UNAVAILABLE):
        ca.load_trust_anchor(str(bundle), digest)


def test_trust_anchor_path_must_be_absolute_and_present(tmp_path):
    with pytest.raises(TrustAnchorError, match=UNAVAILABLE):
        ca.load_trust_anchor("", DIGEST)
    with pytest.raises(TrustAnchorError, match=UNAVAILABLE):
        ca.load_trust_anchor("relative/ca.pem", DIGEST)
    with pytest.raises(TrustAnchorError, match=UNAVAILABLE):
        ca.load_trust_anchor(str(tmp_path.resolve() / "absent.pem"), DIGEST)
    with pytest.raises(TrustAnchorError, match=UNAVAILABLE):
        ca.load_trust_anchor(str(tmp_path.resolve()), DIGEST)


def test_trust_anchor_read_failures_are_sanitized(monkeypatch, tmp_path):
    bundle = tmp_path.resolve() / "ca.pem"
    bundle.write_bytes(b"irrelevant")

    def refuse(self, *arguments, **options):
        raise PermissionError(f"synthetic denial for {self}")

    monkeypatch.setattr(Path, "open", refuse)

    with pytest.raises(TrustAnchorError, match=UNAVAILABLE) as raised:
        ca.load_trust_anchor(str(bundle), DIGEST)
    assert raised.value.__cause__ is None
    assert str(bundle) not in str(raised.value)


def test_trust_anchor_bundle_read_is_bounded_and_handed_to_validation(
    monkeypatch, tmp_path,
):
    bundle = tmp_path.resolve() / "ca.pem"
    bundle.write_bytes(b"x" * (ca.MAX_BUNDLE_BYTES + 100))
    seen = []

    def validate(pem, expected):
        seen.append((len(pem), expected))
        return b"validated"

    monkeypatch.setattr(ca, "validate_trust_anchor", validate)

    assert ca.load_trust_anchor(str(bundle), DIGEST) == b"validated"
    assert seen == [(ca.MAX_BUNDLE_BYTES + 1, DIGEST)]


def test_in_memory_validation_rejects_oversized_bundles_and_bad_digests():
    with pytest.raises(TrustAnchorError, match=UNAVAILABLE):
        ca.validate_trust_anchor(b"x" * (ca.MAX_BUNDLE_BYTES + 1), DIGEST)
    with pytest.raises(TrustAnchorError, match=UNAVAILABLE):
        ca.validate_trust_anchor(b"", "A" * 64)
    with pytest.raises(TrustAnchorError, match=UNAVAILABLE):
        ca.validate_trust_anchor(b"no certificates here", DIGEST)


def test_der_export_requires_exactly_one_certificate():
    one = b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"

    assert ca.der_base64(one) == "QUJD"
    for anchor in (b"", one + one, b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"):
        with pytest.raises(TrustAnchorError, match=UNAVAILABLE):
            ca.der_base64(anchor)
