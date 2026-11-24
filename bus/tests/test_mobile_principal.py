from __future__ import annotations

import sqlite3

import pytest

from strugglebus.auth import (
    LEGACY_CREDENTIAL_KIND,
    MOBILE_CREDENTIAL_KIND,
    mint_credential,
    mint_enrollment_token,
    mint_mobile_credential,
    mint_mobile_enrollment_token,
    mint_reconnect_token,
    parse_credential,
    parse_enrollment_token,
    parse_mobile_credential,
    parse_mobile_enrollment_token,
    parse_reconnect_token,
)
from strugglebus.migrations import LATEST_SCHEMA_VERSION, load_packaged_migrations


def _migrated() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys=ON")
    for migration in load_packaged_migrations():
        connection.executescript(migration.sql)
    return connection


def test_schema_thirteen_adds_only_mobile_tables() -> None:
    assert LATEST_SCHEMA_VERSION == 24
    connection = _migrated()
    names = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {
        "mobile_devices",
        "mobile_device_credentials",
        "mobile_enrollments",
        "mobile_enrollment_redemptions",
        "mobile_device_audit",
    } <= names
    # The agent credential surface must be untouched, so an agent credential
    # can never be issued with a mobile kind.
    agent_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE name='agent_credentials'"
    ).fetchone()[0]
    assert "'legacy-sha256-v1', 'sb1'" in agent_sql
    assert "sbm1" not in agent_sql


def test_mobile_credential_kind_is_constrained() -> None:
    connection = _migrated()
    connection.execute(
        "INSERT INTO mobile_devices (id, label, status, created_at) "
        "VALUES ('dev-1', 'phone-one', 'enabled', '2026-01-01T00:00:00Z')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO mobile_device_credentials "
            "(id, device_id, kind, secret_hash, status, creation_method, "
            " creation_reason, issuance_request_id, created_at) "
            "VALUES ('mob-1', 'dev-1', 'sb1', ?, 'active', 'enrollment', "
            "'test', 'req-1', '2026-01-01T00:00:00Z')",
            ("a" * 64,),
        )


def test_mobile_device_labels_are_immutable_and_unique() -> None:
    connection = _migrated()
    connection.execute(
        "INSERT INTO mobile_devices (id, label, status, created_at) "
        "VALUES ('dev-1', 'phone-one', 'enabled', '2026-01-01T00:00:00Z')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO mobile_devices (id, label, status, created_at) "
            "VALUES ('dev-2', 'phone-one', 'enabled', '2026-01-01T00:00:00Z')"
        )
    # A revoked handset's label stays reserved, so history cannot be silently
    # reattributed by reusing it.
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute(
            "UPDATE mobile_devices SET label = 'phone-two' WHERE id = 'dev-1'"
        )


def test_mobile_audit_and_redemptions_are_append_only() -> None:
    connection = _migrated()
    connection.execute(
        "INSERT INTO mobile_device_audit "
        "(id, event_type, actor_type, actor_id, reason, occurred_at) "
        "VALUES ('a1', 'issued', 'local-admin', 'owner', 'test', "
        "'2026-01-01T00:00:00Z')"
    )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("UPDATE mobile_device_audit SET reason = 'changed'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("DELETE FROM mobile_device_audit")


def test_mobile_credentials_never_parse_as_any_other_principal() -> None:
    _, _, mobile = mint_mobile_credential()
    _, _, mobile_enrollment = mint_mobile_enrollment_token()
    _, _, agent = mint_credential()
    _, _, enrollment = mint_enrollment_token()
    _, _, reconnect = mint_reconnect_token()

    # A mobile secret must never authenticate as an agent, an enrollment or a
    # reconnect grant. Falling through to the legacy hash would be the
    # dangerous outcome, so assert the parser refuses rather than reclassifies.
    assert parse_credential(mobile) is None
    assert parse_enrollment_token(mobile) is None
    assert parse_reconnect_token(mobile) is None
    assert parse_mobile_enrollment_token(mobile) is None

    assert parse_credential(mobile_enrollment) is None
    assert parse_mobile_credential(mobile_enrollment) is None
    assert parse_enrollment_token(mobile_enrollment) is None

    # And the converse: no other principal's secret may parse as mobile.
    for foreign in (agent, enrollment, reconnect):
        assert parse_mobile_credential(foreign) is None
        assert parse_mobile_enrollment_token(foreign) is None


def test_mobile_identifier_and_hash_domains_are_distinct() -> None:
    mobile_id, mobile_verifier, mobile = mint_mobile_credential()
    enrollment_id, enrollment_verifier, _ = mint_mobile_enrollment_token()
    assert mobile_id.startswith("mob_")
    assert enrollment_id.startswith("mnr_")
    # Identifier spaces must not collide with agent credentials or grants.
    assert not mobile_id.startswith(("cred_", "enr_", "rcg_"))
    assert mobile_verifier != enrollment_verifier
    # Re-parsing is stable, and the verifier is a hash rather than the secret.
    assert parse_mobile_credential(mobile) == (mobile_id, mobile_verifier)
    assert mobile not in mobile_verifier
    assert len(mobile_verifier) == 64


def test_reserved_prefixes_are_refused_rather_than_hashed_as_legacy() -> None:
    # A malformed value carrying a reserved prefix must be refused outright.
    # Treating it as a legacy credential would evaluate one principal class
    # under another's verifier.
    for prefix in ("sb1_", "sbe1_", "sbr1_", "sbm1_", "sbme1_"):
        assert parse_credential(prefix + "short") is None
    # Something with no reserved prefix still parses as legacy, unchanged.
    parsed = parse_credential("legacy-style-token")
    assert parsed is not None
    assert parsed[0] == LEGACY_CREDENTIAL_KIND


def test_mobile_credential_kind_constant_matches_schema() -> None:
    connection = _migrated()
    credential_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE name='mobile_device_credentials'"
    ).fetchone()[0]
    assert f"'{MOBILE_CREDENTIAL_KIND}'" in credential_sql
