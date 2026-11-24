from __future__ import annotations

import base64
import io
import json
import sqlite3
import uuid
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from operator_test_support import operator_client
import strugglebus.cli as cli
from strugglebus.app import create_app
from strugglebus.auth import (
    mint_spn_credential,
    mint_spn_enrollment_token,
    parse_credential,
    parse_enrollment_token,
    parse_mobile_credential,
    parse_reconnect_token,
    parse_spn_credential,
    parse_spn_enrollment_token,
)
from strugglebus.errors import CredentialConflictError
from strugglebus.migrations import LATEST_SCHEMA_VERSION, apply_migrations, load_packaged_migrations
from strugglebus.models import LifecycleActor
from strugglebus.store import SQLiteStore

_ROOT_DER = b"synthetic-spn-root-certificate" * 12
_ROOT_PEM = (
    b"-----BEGIN CERTIFICATE-----\n"
    + base64.b64encode(_ROOT_DER)
    + b"\n-----END CERTIFICATE-----\n"
)
_ROOT_SHA256 = "c" * 64


def _actor() -> LifecycleActor:
    return LifecycleActor("local-admin", "test-operator")


@pytest.fixture
def spn_client(app_config, tmp_path, monkeypatch):
    bundle = tmp_path / "lan-root.pem"
    bundle.write_bytes(_ROOT_PEM)
    config = replace(
        app_config,
        ca_bundle_path=str(bundle),
        ca_root_sha256=_ROOT_SHA256,
        spn_package_ttl_seconds=300,
        spn_max_outstanding_packages=2,
        spn_issues_per_minute=10,
    )
    monkeypatch.setattr(
        "strugglebus.routes.agents.load_trust_anchor", lambda path, digest: _ROOT_PEM,
    )
    monkeypatch.setattr(
        "strugglebus.spn.validate_trust_anchor",
        lambda anchor, digest: anchor,
    )
    with TestClient(create_app(config=config)) as client:
        yield client


def _create_spn(client: TestClient, *, prefix: str = "build") -> tuple[object, str]:
    issued = client.app.state.spn_service.create(
        name="build-onboarder",
        agent_name_prefix=prefix,
        request_id=str(uuid.uuid4()),
        actor=_actor(),
    )
    assert issued.secret is not None
    return issued.principal, issued.secret


def _issue(
    client: TestClient,
    secret: str,
    *,
    request_id: str | None = None,
    agent_name: str = "build-cli-win",
):
    return client.post(
        "/api/spn/onboarding-packages",
        json={
            "request_id": request_id or str(uuid.uuid4()),
            "agent_name": agent_name,
            "description": "automated worker",
        },
        headers={"Authorization": f"Bearer {secret}"},
    )


def test_spn_prefixes_are_disjoint_and_reserved() -> None:
    _, _, credential = mint_spn_credential()
    _, _, enrollment = mint_spn_enrollment_token()
    assert parse_spn_credential(credential) is not None
    assert parse_spn_enrollment_token(enrollment) is not None
    for value in (credential, enrollment, "sbsp1_malformed", "sbse1_malformed"):
        assert parse_credential(value) is None
        assert parse_enrollment_token(value) is None
        assert parse_mobile_credential(value) is None
        assert parse_reconnect_token(value) is None


def test_spn_issues_exact_one_time_package_and_existing_redemption_flow(
    spn_client: TestClient,
) -> None:
    principal, secret = _create_spn(spn_client)
    response = _issue(spn_client, secret)
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    body = response.json()
    assert body["status"] == "new"
    assert body["secret_issued"] is True
    package = body["package"]
    assert package["agent_name"] == "build-cli-win"
    assert package["base_url"] == "https://bus.lan"
    assert package["ca_root"] == _ROOT_PEM.decode("ascii")
    assert package["ca_sha256"] == _ROOT_SHA256
    assert package["redeem_path"] == "/api/enrollments/redeem"
    assert package["enrollment_token"].startswith("sbse1_")

    redeemed = spn_client.post(
        package["redeem_path"],
        json={"request_id": str(uuid.uuid4()), "name": package["agent_name"]},
        headers={"Authorization": f"Bearer {package['enrollment_token']}"},
    )
    assert redeemed.status_code == 201
    assert redeemed.json()["credential"]["status"] == "pending"
    assert redeemed.json()["agent"]["name"] == "build-cli-win"
    assert spn_client.app.state.spn_service.list()[0] == principal


def test_spn_issuance_is_idempotent_without_secret_replay(
    spn_client: TestClient,
) -> None:
    _, secret = _create_spn(spn_client)
    request_id = str(uuid.uuid4())
    first = _issue(spn_client, secret, request_id=request_id)
    replay = _issue(spn_client, secret, request_id=request_id)
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json() == {
        "status": "already-committed",
        "secret_issued": False,
        "request_id": request_id,
        "enrollment_id": first.json()["enrollment_id"],
        "agent_name": "build-cli-win",
        "expires_at": first.json()["expires_at"],
        "identity_expires_at": None,
        "package": None,
    }
    conflict = _issue(
        spn_client, secret, request_id=request_id, agent_name="build-cli-linux",
    )
    assert conflict.status_code == 409
    with sqlite3.connect(spn_client.app.state.config.database_path) as database:
        assert database.execute(
            "SELECT COUNT(*) FROM spn_onboarding_issuances"
        ).fetchone() == (1,)


def test_spn_provenance_is_immutable_queryable_and_survives_containment(
    spn_client: TestClient,
) -> None:
    principal, secret = _create_spn(spn_client)
    issuance_request_id = str(uuid.uuid4())
    issued = _issue(
        spn_client, secret, request_id=issuance_request_id,
    ).json()
    redemption_request_id = str(uuid.uuid4())
    redeemed = spn_client.post(
        issued["package"]["redeem_path"],
        json={
            "request_id": redemption_request_id,
            "name": issued["package"]["agent_name"],
        },
        headers={
            "Authorization": f"Bearer {issued['package']['enrollment_token']}"
        },
    )
    assert redeemed.status_code == 201
    agent_id = redeemed.json()["agent"]["id"]

    assert spn_client.get("/api/admin/identity-provenance").status_code == 401
    assert _issue(spn_client, secret).status_code in {201, 409}
    admin = spn_client.app.state.config.admin_secret.decode("ascii")
    roster = spn_client.get(
        "/api/admin/identity-provenance",
        params={"creator_type": "spn", "creator_id": principal.id},
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert roster.status_code == 200
    assert roster.json()["page_count"] == 1
    assert roster.json()["total_count"] == 1
    assert roster.json()["has_more"] is False
    assert roster.json()["next_cursor"] is None
    provenance = roster.json()["items"][0]
    assert provenance["agent"]["id"] == agent_id
    assert provenance["state"] == "enabled"
    assert provenance["creation_method"] == "spn-enrollment"
    assert provenance["creator_principal_type"] == "spn"
    assert provenance["creator_principal_id"] == principal.id
    assert provenance["originating_request_id"] == redemption_request_id
    assert provenance["originating_enrollment_id"] == issued["enrollment_id"]
    assert (
        provenance["originating_issuance_request_id"] == issuance_request_id
    )
    assert provenance["created_at"] == provenance["agent"]["created_at"]

    blocked = spn_client.app.state.spn_service.transition(
        principal.id,
        action="block",
        expected_version=principal.version,
        request_id=str(uuid.uuid4()),
        reason="contain creator",
        actor=_actor(),
    )
    revoked = spn_client.app.state.spn_service.transition(
        principal.id,
        action="revoke",
        expected_version=blocked.version,
        request_id=str(uuid.uuid4()),
        reason="retire creator",
        actor=_actor(),
    )
    assert revoked.status == "revoked"
    attributed = (
        spn_client.app.state.agent_service.list_identity_creation_provenance(
            creator_type="spn", creator_id=principal.id,
        )
    )
    assert [(item.agent.id, item.agent.state) for item in attributed.items] == [
        (agent_id, "enabled")
    ]

    with sqlite3.connect(spn_client.app.state.config.database_path) as database:
        assert database.execute(
            "SELECT revoked_at, blocked_at FROM agents WHERE id = ?", (agent_id,),
        ).fetchone() == (None, None)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            database.execute(
                """
                UPDATE agent_identity_provenance
                SET creator_principal_id = 'forged'
                WHERE agent_id = ?
                """,
                (agent_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            database.execute(
                "DELETE FROM agent_identity_provenance WHERE agent_id = ?",
                (agent_id,),
            )


def test_direct_admin_creation_records_authenticated_creator(
    spn_client: TestClient,
) -> None:
    admin = spn_client.app.state.config.admin_secret.decode("ascii")
    headers = {"Authorization": f"Bearer {admin}"}
    created = spn_client.post(
        "/api/agents",
        json={
            "request_id": str(uuid.uuid4()),
            "name": "direct-api-win",
            "description": "operator-created",
            "host": "",
        },
        headers=headers,
    )
    assert created.status_code == 201
    listed = spn_client.get(
        "/api/admin/identity-provenance",
        params={"creator_type": "remote-admin"},
        headers=headers,
    )
    assert listed.status_code == 200
    matching = [
        item for item in listed.json()["items"]
        if item["agent"]["id"] == created.json()["agent"]["id"]
    ]
    assert len(matching) == 1
    provenance = matching[0]
    assert provenance["creation_method"] == "direct-registration"
    assert provenance["creator_principal_id"] != "admin"
    assert provenance["originating_enrollment_id"] is None
    assert provenance["originating_issuance_request_id"] is None
    filtered = spn_client.get(
        "/api/admin/identity-provenance",
        params={
            "creator_type": "remote-admin",
            "creator_id": provenance["creator_principal_id"],
        },
        headers=headers,
    )
    assert [item["agent"]["id"] for item in filtered.json()["items"]] == [
        created.json()["agent"]["id"]
    ]


@pytest.mark.parametrize("action", ["block", "unblock", "revoke"])
def test_spn_transition_replay_returns_committed_result_and_rejects_new_intent(
    spn_client: TestClient, action: str,
) -> None:
    principal, _ = _create_spn(spn_client)
    if action == "unblock":
        principal = spn_client.app.state.spn_service.transition(
            principal.id,
            action="block",
            expected_version=principal.version,
            request_id=str(uuid.uuid4()),
            reason="prepare unblock replay",
            actor=_actor(),
        )
    expected_version = principal.version
    request_id = str(uuid.uuid4())
    result = spn_client.app.state.spn_service.transition(
        principal.id,
        action=action,
        expected_version=expected_version,
        request_id=request_id,
        reason=f"{action} replay test",
        actor=_actor(),
    )
    replay = spn_client.app.state.spn_service.transition(
        principal.id,
        action=action,
        expected_version=expected_version,
        request_id=request_id,
        reason=f"{action} replay test",
        actor=_actor(),
    )
    assert replay == result
    with pytest.raises(
        CredentialConflictError, match="request id is already in use",
    ):
        spn_client.app.state.spn_service.transition(
            principal.id,
            action=action,
            expected_version=expected_version,
            request_id=request_id,
            reason=f"different {action} intent",
            actor=_actor(),
        )
    with sqlite3.connect(spn_client.app.state.config.database_path) as database:
        assert database.execute(
            """
            SELECT COUNT(*) FROM spn_transition_requests
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone() == (1,)
        assert database.execute(
            "SELECT COUNT(*) FROM spn_audit WHERE request_id = ?",
            (request_id,),
        ).fetchone() == (1,)
        if action == "block":
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                database.execute(
                    """
                    UPDATE spn_transition_requests
                    SET result_status = 'enabled'
                    WHERE request_id = ?
                    """,
                    (request_id,),
                )
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                database.execute(
                    "DELETE FROM spn_transition_requests WHERE request_id = ?",
                    (request_id,),
                )


def test_spn_transition_replay_returns_original_snapshot_after_later_change(
    spn_client: TestClient,
) -> None:
    principal, _ = _create_spn(spn_client)
    block_request_id = str(uuid.uuid4())
    blocked = spn_client.app.state.spn_service.transition(
        principal.id,
        action="block",
        expected_version=principal.version,
        request_id=block_request_id,
        reason="ambiguous block",
        actor=_actor(),
    )
    current = spn_client.app.state.spn_service.transition(
        principal.id,
        action="unblock",
        expected_version=blocked.version,
        request_id=str(uuid.uuid4()),
        reason="later unblock",
        actor=_actor(),
    )
    assert current.status == "enabled"
    replay = spn_client.app.state.spn_service.transition(
        principal.id,
        action="block",
        expected_version=principal.version,
        request_id=block_request_id,
        reason="ambiguous block",
        actor=_actor(),
    )
    assert replay == blocked
    assert spn_client.app.state.spn_service.list()[0] == current


def test_prefix_auth_freeze_and_outstanding_limits_are_enforced(
    spn_client: TestClient,
) -> None:
    _, secret = _create_spn(spn_client)
    assert _issue(spn_client, secret, agent_name="other-cli-win").status_code == 422
    assert _issue(spn_client, "not-an-spn").status_code == 401
    agent_secret = spn_client.app.state.agent_service.create_agent(
        "other-agent"
    ).api_key
    assert _issue(spn_client, agent_secret).status_code == 401
    assert _issue(
        spn_client, spn_client.app.state.config.admin_secret.decode("ascii"),
    ).status_code == 401
    assert spn_client.get(
        "/api/agents", headers={"Authorization": f"Bearer {secret}"},
    ).status_code == 401

    assert _issue(spn_client, secret, agent_name="build-one").status_code == 201
    assert _issue(spn_client, secret, agent_name="build-two").status_code == 201
    assert _issue(spn_client, secret, agent_name="build-three").status_code == 409

    spn_client.app.state.access_freeze_service.freeze("SPN freeze test")
    assert _issue(spn_client, secret, agent_name="build-four").status_code == 503


def test_block_revokes_packages_unblock_does_not_restore_and_rotate_is_one_time(
    spn_client: TestClient,
) -> None:
    principal, secret = _create_spn(spn_client)
    issued = _issue(spn_client, secret)
    token = issued.json()["package"]["enrollment_token"]
    blocked = spn_client.app.state.spn_service.transition(
        principal.id,
        action="block",
        expected_version=principal.version,
        request_id=str(uuid.uuid4()),
        reason="contain automation",
        actor=_actor(),
    )
    assert _issue(spn_client, secret).status_code == 401
    rejected = spn_client.post(
        "/api/enrollments/redeem",
        json={"request_id": str(uuid.uuid4()), "name": "build-cli-win"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert rejected.status_code == 401

    unblocked = spn_client.app.state.spn_service.transition(
        principal.id,
        action="unblock",
        expected_version=blocked.version,
        request_id=str(uuid.uuid4()),
        reason="incident resolved",
        actor=_actor(),
    )
    assert _issue(spn_client, secret, agent_name="build-cli-two").status_code == 201

    rotate_id = str(uuid.uuid4())
    rotated = spn_client.app.state.spn_service.rotate(
        principal.id,
        expected_version=unblocked.version,
        request_id=rotate_id,
        reason="scheduled rotation",
        actor=_actor(),
    )
    assert rotated.secret is not None
    replay = spn_client.app.state.spn_service.rotate(
        principal.id,
        expected_version=unblocked.version,
        request_id=rotate_id,
        reason="scheduled rotation",
        actor=_actor(),
    )
    assert replay.secret_issued is False
    assert replay.secret is None
    assert _issue(spn_client, secret, agent_name="build-old").status_code == 401
    assert _issue(
        spn_client, rotated.secret, agent_name="build-new",
    ).status_code == 201

    with pytest.raises(CredentialConflictError):
        spn_client.app.state.spn_service.transition(
            principal.id,
            action="revoke",
            expected_version=unblocked.version,
            request_id=str(uuid.uuid4()),
            reason="stale version",
            actor=_actor(),
        )
    revoked = spn_client.app.state.spn_service.transition(
        principal.id,
        action="revoke",
        expected_version=rotated.principal.version,
        request_id=str(uuid.uuid4()),
        reason="retire automation",
        actor=_actor(),
    )
    assert revoked.status == "revoked"
    assert _issue(spn_client, rotated.secret, agent_name="build-after").status_code == 401
    with sqlite3.connect(spn_client.app.state.config.database_path) as database:
        events = [
            row[0] for row in database.execute(
                "SELECT event_type FROM spn_audit ORDER BY seq"
            )
        ]
        assert events == [
            "created", "package-issued", "blocked", "unblocked",
            "package-issued", "rotated", "package-issued", "revoked",
        ]
        assert secret.encode("ascii") not in spn_client.app.state.config.database_path.read_bytes()
        assert rotated.secret.encode("ascii") not in (
            spn_client.app.state.config.database_path.read_bytes()
        )


def test_schema_sixteen_upgrades_with_backup_and_preserves_existing_data(
    tmp_path,
) -> None:
    path = tmp_path / "schema16.db"
    backups = tmp_path / "backups"
    migrations = load_packaged_migrations()
    with sqlite3.connect(path, isolation_level=None) as database:
        assert apply_migrations(database, migrations[:16]) == 16
        database.execute(
            "INSERT INTO agents (id, name, created_at) VALUES (?, ?, ?)",
            ("legacy-agent", "legacy-agent", datetime.now(UTC).isoformat()),
        )
    store = SQLiteStore(path, backup_dir=backups)
    assert store.initialize() == LATEST_SCHEMA_VERSION == 24
    with sqlite3.connect(path) as database:
        assert database.execute(
            "SELECT name FROM agents WHERE id = 'legacy-agent'"
        ).fetchone() == ("legacy-agent",)
        assert {
            "spn_principals",
            "spn_credentials",
            "spn_requests",
            "spn_transition_requests",
            "spn_onboarding_issuances",
            "spn_audit",
            "agent_identity_provenance",
        } <= {
            row[0] for row in database.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []
        assert database.execute(
            """
            SELECT creator_principal_type, creator_principal_id,
                   creation_method
            FROM agent_identity_provenance
            WHERE agent_id = 'legacy-agent'
            """
        ).fetchone() == (
            "system", "system:schema-17-backfill", "schema-17-backfill",
        )
    backup = next(backups.glob("*.backup"))
    with sqlite3.connect(backup) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (16,)


def test_operator_console_exposes_complete_spn_lifecycle(
    app_config, tmp_path, monkeypatch,
) -> None:
    bundle = tmp_path / "operator-root.pem"
    bundle.write_bytes(_ROOT_PEM)
    config = replace(
        app_config, ca_bundle_path=str(bundle), ca_root_sha256=_ROOT_SHA256,
    )
    monkeypatch.setattr(
        "strugglebus.routes.agents.load_trust_anchor", lambda path, digest: _ROOT_PEM,
    )
    monkeypatch.setattr(
        "strugglebus.spn.validate_trust_anchor",
        lambda anchor, digest: anchor,
    )
    with operator_client(create_app(config=config)) as browser:
        listing = browser.get("/service-principals")
        assert listing.status_code == 200
        assert "Attributed durable agents" not in listing.text
        created = browser.post(
            "/service-principals",
            data={
                "csrf": browser.operator_csrf,
                "request_id": str(uuid.uuid4()),
                "name": "console-onboarder",
                "agent_name_prefix": "console",
            },
            headers={"Origin": "https://bus.lan"},
        )
        assert created.status_code == 200
        assert "sbsp1_" in created.text
        principal = browser.app.state.spn_service.list()[0]
        secret = created.text.split("<pre>", 1)[1].split("</pre>", 1)[0]
        issued = _issue(
            browser, secret, agent_name="console-cli-win",
        ).json()["package"]
        redeemed = browser.post(
            issued["redeem_path"],
            json={
                "request_id": str(uuid.uuid4()),
                "name": issued["agent_name"],
            },
            headers={"Authorization": f"Bearer {issued['enrollment_token']}"},
        )
        assert redeemed.status_code == 201
        listing = browser.get("/service-principals")
        assert "Attributed durable agents" in listing.text
        assert "<strong>1</strong>" in listing.text
        roster = browser.get(
            f"/service-principals/{principal.id}/agents",
        )
        assert roster.status_code == 200
        assert "Showing 1 of 1 attributed agents" in roster.text
        assert "console-cli-win" in roster.text
        assert "enabled" in roster.text

        for action, resulting in (
            ("block", "blocked"),
            ("unblock", "enabled"),
            ("rotate", "enabled"),
            ("revoke", "revoked"),
        ):
            response = browser.post(
                f"/service-principals/{principal.id}/control",
                data={
                    "csrf": browser.operator_csrf,
                    "action": action,
                    "expected_version": str(principal.version),
                    "request_id": str(uuid.uuid4()),
                    "reason": f"{action} test",
                },
                headers={"Origin": "https://bus.lan"},
            )
            assert response.status_code == 200, response.text
            if action == "rotate":
                assert "sbsp1_" in response.text
            principal = browser.app.state.spn_service.list()[0]
            assert principal.status == resulting


def test_spn_api_rate_and_body_limits_apply_before_route(
    app_config, tmp_path, monkeypatch,
) -> None:
    bundle = tmp_path / "limited-root.pem"
    bundle.write_bytes(_ROOT_PEM)
    config = replace(
        app_config,
        ca_bundle_path=str(bundle),
        ca_root_sha256=_ROOT_SHA256,
        spn_issues_per_minute=1,
    )
    monkeypatch.setattr(
        "strugglebus.routes.agents.load_trust_anchor", lambda path, digest: _ROOT_PEM,
    )
    monkeypatch.setattr(
        "strugglebus.spn.validate_trust_anchor",
        lambda anchor, digest: anchor,
    )
    with TestClient(create_app(config=config)) as client:
        _, secret = _create_spn(client)
        assert _issue(client, secret, agent_name="build-first").status_code == 201
        assert _issue(client, secret, agent_name="build-second").status_code == 429

    config = replace(config, spn_issues_per_minute=10)
    with TestClient(create_app(config=config)) as client:
        secret = client.app.state.spn_service.rotate(
            client.app.state.spn_service.list()[0].id,
            expected_version=0,
            request_id=str(uuid.uuid4()),
            reason="body-limit credential",
            actor=_actor(),
        ).secret
        assert secret is not None
        oversized = client.post(
            "/api/spn/onboarding-packages",
            content=b"{" + b"x" * 4096 + b"}",
            headers={
                "Authorization": f"Bearer {secret}",
                "Content-Type": "application/json",
            },
        )
        assert oversized.status_code == 413


def test_protected_local_cli_exposes_complete_spn_lifecycle(
    tmp_path, monkeypatch,
) -> None:
    admin = tmp_path / "admin-token"
    admin.write_text("test-admin-token", encoding="ascii")
    admin.chmod(0o600)
    for name, value in {
        "STRUGGLEBUS_DATA_DIR": str(tmp_path),
        "STRUGGLEBUS_RUNTIME_DIR": str(tmp_path / "run"),
        "STRUGGLEBUS_BACKUP_DIR": str(tmp_path / "backups"),
        "STRUGGLEBUS_DATABASE_PATH": str(tmp_path / "strugglebus.db"),
        "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": str(admin),
        "CREDENTIALS_DIRECTORY": str(tmp_path),
    }.items():
        monkeypatch.setenv(name, value)

    credential = tmp_path / "spn.credential"
    assert cli.main([
        "operator", "spn", "create", "cli-onboarder", "cli",
        "--request-id", str(uuid.uuid4()),
        "--credential-output", str(credential),
    ]) == cli.EXIT_OK
    secret = credential.read_text(encoding="ascii").strip()
    assert parse_spn_credential(secret) is not None

    output = io.StringIO()
    assert cli.main(["operator", "spn", "list"], stdout=output) == cli.EXIT_OK
    principal = json.loads(output.getvalue())[0]
    for action in ("block", "unblock"):
        assert cli.main([
            "operator", "spn", action, principal["id"],
            "--expected-version", str(principal["version"]),
            "--request-id", str(uuid.uuid4()),
            "--reason", f"{action} test",
        ]) == cli.EXIT_OK
        output = io.StringIO()
        assert cli.main(["operator", "spn", "list"], stdout=output) == cli.EXIT_OK
        principal = json.loads(output.getvalue())[0]

    replacement = tmp_path / "spn-rotated.credential"
    assert cli.main([
        "operator", "spn", "rotate", principal["id"],
        "--expected-version", str(principal["version"]),
        "--request-id", str(uuid.uuid4()),
        "--reason", "rotation test",
        "--credential-output", str(replacement),
    ]) == cli.EXIT_OK
    assert parse_spn_credential(
        replacement.read_text(encoding="ascii").strip()
    ) is not None
    output = io.StringIO()
    assert cli.main(["operator", "spn", "list"], stdout=output) == cli.EXIT_OK
    principal = json.loads(output.getvalue())[0]
    assert cli.main([
        "operator", "spn", "revoke", principal["id"],
        "--expected-version", str(principal["version"]),
        "--request-id", str(uuid.uuid4()),
        "--reason", "retirement test",
    ]) == cli.EXIT_OK


def test_provenance_api_and_operator_roster_paginate_beyond_two_hundred(
    app_config,
) -> None:
    with operator_client(create_app(config=app_config)) as browser:
        principal = browser.app.state.spn_service.create(
            name="large-roster",
            agent_name_prefix="large",
            request_id=str(uuid.uuid4()),
            actor=_actor(),
        ).principal
        created_at = "2026-09-28T00:00:00.000000Z"
        expires_at = "2026-09-28T01:00:00.000000Z"
        with sqlite3.connect(browser.app.state.config.database_path) as database:
            for index in range(205):
                agent_id = f"agent-page-{index:03d}"
                agent_name = f"large-page-{index:03d}"
                enrollment_id = f"sen_page_{index:03d}"
                issuance_id = f"issue-page-{index:03d}"
                database.execute(
                    """
                    INSERT INTO agent_enrollments (
                        id, secret_hash, name_prefix, name_match, description,
                        status, uses_allowed, uses_remaining, created_at,
                        expires_at, last_redeemed_at, exhausted_at, actor_type,
                        actor_id, creation_reason, version, spn_id
                    )
                    VALUES (?, ?, ?, 'exact', '', 'exhausted', 1, 0, ?, ?, ?,
                            ?, 'system', ?, 'pagination fixture', 1, ?)
                    """,
                    (
                        enrollment_id, f"{index:064x}", agent_name, created_at,
                        expires_at, created_at, created_at,
                        f"spn:{principal.id}", principal.id,
                    ),
                )
                database.execute(
                    """
                    INSERT INTO spn_onboarding_issuances (
                        request_id, spn_id, intent_sha256, enrollment_id,
                        agent_name, created_at, expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        issuance_id, principal.id, f"{index + 1000:064x}",
                        enrollment_id, agent_name, created_at, expires_at,
                    ),
                )
                database.execute(
                    """
                    INSERT INTO agents (
                        id, name, description, host, created_at, credential_epoch
                    )
                    VALUES (?, ?, '', '', ?, 1)
                    """,
                    (agent_id, agent_name, created_at),
                )
                database.execute(
                    """
                    INSERT INTO agent_identity_provenance (
                        agent_id, creation_method, creator_principal_type,
                        creator_principal_id, originating_request_id,
                        originating_enrollment_id,
                        originating_issuance_request_id, created_at
                    )
                    VALUES (?, 'spn-enrollment', 'spn', ?, ?, ?, ?, ?)
                    """,
                    (
                        agent_id, principal.id, f"redeem-page-{index:03d}",
                        enrollment_id, issuance_id, created_at,
                    ),
                )
            database.commit()

        admin = browser.app.state.config.admin_secret.decode("ascii")
        headers = {"Authorization": f"Bearer {admin}"}
        invalid_cursor = browser.get(
            "/api/admin/identity-provenance",
            params={"after_agent_id": "agent-page-000"},
            headers=headers,
        )
        assert invalid_cursor.status_code == 422
        params: dict[str, object] = {
            "creator_type": "spn",
            "creator_id": principal.id,
            "limit": 75,
        }
        seen: list[str] = []
        page_counts = []
        cursors = []
        while True:
            response = browser.get(
                "/api/admin/identity-provenance",
                params=params,
                headers=headers,
            )
            assert response.status_code == 200
            page = response.json()
            assert page["total_count"] == 205
            assert page["page_count"] == len(page["items"])
            page_counts.append(page["page_count"])
            seen.extend(item["agent"]["id"] for item in page["items"])
            if not page["has_more"]:
                assert page["next_cursor"] is None
                break
            assert page["next_cursor"] is not None
            cursors.append(page["next_cursor"])
            params["after_created_at"] = page["next_cursor"]["created_at"]
            params["after_agent_id"] = page["next_cursor"]["agent_id"]
        assert page_counts == [75, 75, 55]
        assert seen == [f"agent-page-{index:03d}" for index in range(205)]
        assert len(set(seen)) == 205

        overview = browser.get("/service-principals")
        assert "<strong>205</strong>" in overview.text
        assert "view complete roster" in overview.text
        first = browser.get(f"/service-principals/{principal.id}/agents")
        assert "Showing 100 of 205 attributed agents. More remain: yes." in first.text
        second = browser.get(
            f"/service-principals/{principal.id}/agents",
            params={
                "after_created_at": cursors[0]["created_at"],
                "after_agent_id": "agent-page-099",
                "limit": 100,
            },
        )
        assert "Showing 100 of 205 attributed agents. More remain: yes." in second.text
        third = browser.get(
            f"/service-principals/{principal.id}/agents",
            params={
                "after_created_at": cursors[0]["created_at"],
                "after_agent_id": "agent-page-199",
                "limit": 100,
            },
        )
        assert "Showing 5 of 205 attributed agents. More remain: no." in third.text
        assert "large-page-204" in third.text
