from datetime import UTC, datetime
from pathlib import Path
import sqlite3

import pytest

from strugglebus.access import AccessFreezeService
from strugglebus.auth import AgentService, mint_credential, mint_enrollment_token
from strugglebus.errors import AgentAccessFrozenError, MigrationError
from strugglebus.migrations import LATEST_SCHEMA_VERSION, Migration, apply_migrations, load_packaged_migrations
from strugglebus.store import SQLiteStore


@pytest.fixture
def schema_ten(tmp_path: Path):
    path = tmp_path / "schema-ten.db"
    store = SQLiteStore(path, backup_dir=tmp_path / "backups")
    migrations = load_packaged_migrations()
    with sqlite3.connect(path, isolation_level=None) as database:
        assert apply_migrations(database, migrations[:10]) == 10
    agent_id = "historical-agent-id"
    credential_id, credential_hash, _ = mint_credential()
    token_id, digest, token = mint_enrollment_token()
    timestamp = "2026-01-01T00:00:00.000000Z"
    with sqlite3.connect(path) as database:
        database.execute(
            "INSERT INTO agents (id, name, created_at, credential_epoch) "
            "VALUES (?, 'historical-agent', ?, 1)", (agent_id, timestamp),
        )
        database.execute(
            "INSERT INTO agent_credentials (id, agent_id, kind, secret_hash, status, "
            "creation_method, creation_reason, issuance_request_id, created_at, pending_expires_at) "
            "VALUES (?, ?, 'sb1', ?, 'pending', 'registration', 'historical agent', "
            "'historical-request', ?, '2099-01-01T00:00:00.000000Z')",
            (credential_id, agent_id, credential_hash, timestamp),
        )
        database.executemany(
            """
            INSERT INTO agent_enrollments (
                id, secret_hash, name_prefix, description, status, uses_allowed,
                uses_remaining, created_at, expires_at, last_redeemed_at,
                exhausted_at, revoked_at, revocation_reason, actor_type, actor_id,
                creation_reason
            ) VALUES (?, ?, 'review-reader', 'historical allowance', ?, ?, ?, ?,
                      '2099-01-01T00:00:00.000000Z', ?, ?, ?, ?, 'local-admin',
                      'dashboard', 'historical dashboard registration')
            """,
            [
                (token_id, digest, "pending", 2, 2, timestamp, None, None, None, None),
                ("spent", "a" * 64, "exhausted", 1, 0, timestamp,
                 timestamp, timestamp, None, None),
                ("revoked", "b" * 64, "revoked", 1, 1, timestamp,
                 None, None, timestamp, "operator revoked"),
            ],
        )
        database.execute(
            """
            INSERT INTO agent_enrollment_redemptions (
                enrollment_id, agent_id, credential_id, claimed_name, request_id,
                redeemed_at
            ) VALUES ('spent', ?, ?, 'historical-agent', 'old-redemption', ?)
            """,
            (agent_id, credential_id, timestamp),
        )
        database.execute(
            "INSERT INTO channels VALUES ('channel', 'history', '', ?, ?)",
            (timestamp, agent_id),
        )
        database.execute(
            """
            INSERT INTO messages (id, channel_id, agent_id, body, kind, created_at)
            VALUES ('message', 'channel', ?, 'preserve history', 'chat', ?)
            """,
            (agent_id, timestamp),
        )
        database.execute(
            "INSERT INTO subscriptions VALUES (?, 'channel', ?)",
            (agent_id, timestamp),
        )
        database.execute(
            """
            INSERT INTO cursors (agent_id, channel_id, include_stale, last_seq, updated_at)
            VALUES (?, 'channel', 0, 1, ?)
            """,
            (agent_id, timestamp),
        )
        database.execute(
            """
            INSERT INTO mention_cursors (agent_id, include_stale, last_seq, updated_at)
            VALUES (?, 0, 1, ?)
            """,
            (agent_id, timestamp),
        )
        database.execute("INSERT INTO mentions VALUES (1, ?)", (agent_id,))
    changed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(path) as database:
        database.execute(
            "UPDATE agent_access_state SET frozen = 1, transition = 'freeze', "
            "changed_at = ?, reason = 'preserve schema ten freeze'",
            (changed_at,),
        )
        database.execute(
            "INSERT INTO agent_access_audit (transition, changed_at, reason) "
            "VALUES ('freeze', ?, 'preserve schema ten freeze')",
            (changed_at,),
        )
    tables = (
        "agents", "agent_credentials", "agent_credential_requests",
        "agent_credential_audit", "agent_access_state", "agent_access_audit",
        "agent_enrollment_redemptions", "channels", "messages", "cursors",
        "mention_cursors", "subscriptions", "mentions",
    )
    with sqlite3.connect(path) as database:
        snapshot = {
            table: database.execute(f"SELECT * FROM {table}").fetchall()
            for table in tables
        }
        old_allowances = database.execute(
            "SELECT * FROM agent_enrollments ORDER BY id"
        ).fetchall()
    return store, token, snapshot, old_allowances


def test_schema_ten_preserves_all_old_allowances_and_frozen_history(schema_ten) -> None:
    store, token, snapshot, old_allowances = schema_ten
    assert store.initialize() == LATEST_SCHEMA_VERSION
    with sqlite3.connect(store.database_path) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (LATEST_SCHEMA_VERSION,)
        for table, rows in snapshot.items():
            current = database.execute(f"SELECT * FROM {table}").fetchall()
            if table == "agents":
                current = [
                    row for row in current
                    if row[1] not in {"system:strugglebus-maintenance", "human:operator"}
                ]
                # Later schemas add blocked_at and the schema-22 expiry.
                current = [row[:-2] for row in current]
            elif table == "agent_access_audit":
                current = [row[:-2] for row in current]
            elif table == "messages":
                assert database.execute(
                    "SELECT post_request_id FROM messages"
                ).fetchall() == [(None,)] * len(rows)
                current = [row[:-1] for row in current]
            assert current == rows
        migrated = database.execute(
            "SELECT * FROM agent_enrollments ORDER BY id"
        ).fetchall()
        assert [row[:-3] for row in migrated] == old_allowances
        assert {row[-3] for row in migrated} == {"prefix"}
        assert {row[-1] for row in migrated} == {None}
    backups = list(store.backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as database:
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert database.execute("PRAGMA user_version").fetchone() == (10,)
        assert database.execute(
            "SELECT * FROM agent_enrollments ORDER BY id"
        ).fetchall() == old_allowances
        assert database.execute("SELECT frozen FROM agent_access_state").fetchone() == (1,)
    service = AgentService(store)
    with pytest.raises(AgentAccessFrozenError):
        service.redeem_enrollment(token, claimed_name="review-reader-extra")
    AccessFreezeService(
        store, clock=lambda: datetime.now(UTC),
        transition_lock_directory=store.database_path.parent / "freeze-lock",
    ).unfreeze("reviewed migration fixture")
    # Even historical dashboard tokens retain their original suffix allowance.
    assert service.redeem_enrollment(
        token, claimed_name="review-reader-extra"
    ).agent.name == "review-reader-extra"


@pytest.mark.parametrize("failure", ["migration", "backup"])
def test_schema_eleven_failure_is_atomic_with_frozen_existing_data(
    schema_ten, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    store, _, snapshot, old_allowances = schema_ten
    migrations = load_packaged_migrations()
    if failure == "migration":
        last = migrations[10]
        migrations = (*migrations[:10], Migration(
            11, last.name, last.sql + "\nTHIS IS NOT SQL;\n"
        ))
    else:
        def fail_backup(**kwargs):
            raise MigrationError("verified backup unavailable")

        monkeypatch.setattr("strugglebus.migrations._create_verified_backup", fail_backup)
    with sqlite3.connect(store.database_path, isolation_level=None) as database:
        with pytest.raises(MigrationError):
            apply_migrations(
                database, migrations,
                database_path=store.database_path, backup_dir=store.backup_dir,
            )
        assert database.execute("PRAGMA user_version").fetchone() == (10,)
        assert database.execute(
            "SELECT * FROM agent_enrollments ORDER BY id"
        ).fetchall() == old_allowances
        for table, rows in snapshot.items():
            assert database.execute(f"SELECT * FROM {table}").fetchall() == rows
        assert database.execute(
            "SELECT 1 FROM sqlite_master WHERE name='agent_enrollments_immutable_name_match'"
        ).fetchone() is None
