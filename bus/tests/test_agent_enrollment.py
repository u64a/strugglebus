from __future__ import annotations

import sqlite3
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from strugglebus.app import create_app
from strugglebus.auth import (
    AgentService,
    mint_enrollment_token,
    parse_credential,
    parse_enrollment_token,
)
from strugglebus.config import AppConfig
from strugglebus.errors import (
    ConfigurationError,
    DuplicateAgentNameError,
    EnrollmentInvalidError,
    EnrollmentNotFoundError,
)
from strugglebus.store import SQLiteStore


def _service(config: AppConfig, **kwargs: object) -> AgentService:
    service = AgentService(
        SQLiteStore(
            config.database_path,
            backup_dir=config.backup_dir,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
        ),
        **kwargs,
    )
    service.initialize()
    return service


def _application(config: AppConfig, **kwargs: object):
    service = AgentService(
        SQLiteStore(
            config.database_path,
            backup_dir=config.backup_dir,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
        ),
        **kwargs,
    )
    return create_app(config=config, agent_service=service)


@pytest.fixture
def enrollment_client(app_config: AppConfig):
    with TestClient(_application(app_config, max_enrollment_uses=4)) as client:
        yield client


def _redeem(
    client: TestClient,
    token: str,
    name: str,
    **extra: object,
):
    payload: dict[str, object] = {"request_id": str(uuid.uuid4()), "name": name}
    payload.update(extra)
    return client.post(
        "/api/enrollments/redeem",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )


def _mint(client: TestClient, prefix: str = "adlab", **kwargs: object) -> str:
    issued = client.app.state.agent_service.create_enrollment(
        name_prefix=prefix, **kwargs
    )
    assert issued.token is not None
    return issued.token


def test_enrollment_token_is_never_a_credential() -> None:
    _, _, token = mint_enrollment_token()
    assert token.startswith("sbe1_")
    # A token must never be accepted as, or silently hashed as, an API key.
    assert parse_credential(token) is None
    assert parse_enrollment_token(token) is not None


def test_credential_is_never_an_enrollment_token(app_config: AppConfig) -> None:
    service = _service(app_config)
    created = service.create_agent("adlab-cli-win")
    assert parse_enrollment_token(created.api_key) is None


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "sbe1_",
        "sbe1_short_secret",
        "sbe1_" + "a" * 22 + "_" + "b" * 42,
        "sbe1_" + "a" * 22 + "_" + "b" * 44,
        "sbe1_" + "!" * 22 + "_" + "b" * 43,
        "x" * 400,
    ],
)
def test_malformed_tokens_are_rejected(candidate: str) -> None:
    assert parse_enrollment_token(candidate) is None


def test_redeem_creates_a_pending_credential(
    enrollment_client: TestClient,
) -> None:
    token = _mint(enrollment_client)
    response = _redeem(enrollment_client, token, "adlab-cli-win", host="ws1")
    assert response.status_code == 201
    body = response.json()
    assert body["agent"]["name"] == "adlab-cli-win"
    assert body["credential"]["status"] == "pending"
    assert body["credential_secret"].startswith("sb1_")
    assert body["next_steps"]
    assert response.headers["Cache-Control"] == "no-store"


def test_redemption_steps_explicitly_start_and_finish_a_bounded_drain(
    enrollment_client: TestClient,
) -> None:
    token = _mint(enrollment_client)
    response = _redeem(enrollment_client, token, "adlab-cli-win")
    assert response.status_code == 201
    body = response.json()
    steps = body["next_steps"]
    assert "prove_credential" in steps[3]
    assert "acknowledge_roe" in steps[4]
    assert "list_channels" in steps[5]
    assert "list_subscriptions" in steps[5]
    assert "subscriptions are optional" in steps[5]
    assert "mention-only use is valid" in steps[5]
    assert "catch_up(start_drain=true)" in steps[6]
    assert "continuation with the same limit and include_stale" in steps[6]
    assert "complete=true, including empty or short pages" in steps[6]
    assert "Deduplicate by global seq" in steps[6]
    assert all("Call catch_up and" not in step for step in steps)
    assert body["credential"]["status"] == "pending"
    assert enrollment_client.app.state.board_service.list_subscriptions(
        body["agent"]["id"]
    ) == ()
    with sqlite3.connect(enrollment_client.app.state.config.database_path) as connection:
        for table in ("cursors", "mention_cursors", "roe_acknowledgements"):
            assert connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE agent_id = ?",
                (body["agent"]["id"],),
            ).fetchone()[0] == 0


def test_redeemed_credential_can_prove_and_operate(
    enrollment_client: TestClient,
) -> None:
    token = _mint(enrollment_client)
    body = _redeem(enrollment_client, token, "adlab-cli-win").json()
    headers = {"Authorization": f"Bearer {body['credential_secret']}"}

    whoami = enrollment_client.get("/api/whoami", headers=headers)
    assert whoami.status_code == 200
    assert whoami.json()["agent"]["id"] == body["agent"]["id"]

    # A pending credential must not be able to coordinate before proving.
    assert enrollment_client.get("/api/channels", headers=headers).status_code == 403

    proved = enrollment_client.post(
        "/api/credentials/prove",
        json={
            "request_id": str(uuid.uuid4()),
            "expected_agent_id": body["agent"]["id"],
            "expected_agent_name": body["agent"]["name"],
            "expected_credential_epoch": body["agent"]["credential_epoch"],
            "expected_credential_version": body["credential"]["version"],
        },
        headers=headers,
    )
    assert proved.status_code == 200


def test_replay_is_rejected(enrollment_client: TestClient) -> None:
    token = _mint(enrollment_client)
    assert _redeem(enrollment_client, token, "adlab-cli-win").status_code == 201
    replay = _redeem(enrollment_client, token, "adlab-cli-two")
    assert replay.status_code == 401
    agents = enrollment_client.app.state.agent_service.store.list_agents()
    assert [agent.name for agent in agents] == ["adlab-cli-win"]


def test_claimed_name_must_match_the_allowance(
    enrollment_client: TestClient,
) -> None:
    token = _mint(enrollment_client, prefix="adlab", uses=2)
    outside = _redeem(enrollment_client, token, "other-project-cli")
    assert outside.status_code == 401
    # A rejected claim must not consume the allowance.
    enrollment = enrollment_client.app.state.agent_service.list_enrollments()[0]
    assert enrollment.uses_remaining == 2
    assert _redeem(enrollment_client, token, "adlab-cli-win").status_code == 201


def test_prefix_is_matched_on_a_segment_boundary(
    enrollment_client: TestClient,
) -> None:
    token = _mint(enrollment_client, prefix="adlab", uses=2)
    # "adlabextra-cli" must not pass as being under the "adlab" allowance.
    assert _redeem(enrollment_client, token, "adlabextra-cli").status_code == 401
    assert _redeem(enrollment_client, token, "adlab-cli-win").status_code == 201


def test_generic_prefix_accepts_the_prefix_itself_and_a_suffix(enrollment_client):
    token = _mint(enrollment_client, prefix="review-reader", uses=2)
    assert _redeem(enrollment_client, token, "review-reader").status_code == 201
    assert _redeem(enrollment_client, token, "review-reader-extra").status_code == 201


def test_existing_agent_name_is_never_adopted(
    enrollment_client: TestClient,
) -> None:
    service = enrollment_client.app.state.agent_service
    service.create_agent("adlab-cli-win")
    token = _mint(enrollment_client, prefix="adlab", uses=2)
    conflict = _redeem(enrollment_client, token, "adlab-cli-win")
    assert conflict.status_code == 409
    assert service.list_enrollments()[0].uses_remaining == 2


def test_revoked_agent_name_is_never_resurrected(
    enrollment_client: TestClient,
) -> None:
    service = enrollment_client.app.state.agent_service
    service.create_agent("adlab-cli-win")
    service.revoke_agent_by_name("adlab-cli-win")
    token = _mint(enrollment_client, prefix="adlab", uses=2)
    assert _redeem(enrollment_client, token, "adlab-cli-win").status_code == 409


def test_expired_token_is_rejected(app_config: AppConfig) -> None:
    service = _service(app_config)
    issued = service.create_enrollment(name_prefix="adlab", ttl_seconds=60)
    later = _service(
        app_config,
        clock=lambda: datetime.now(UTC) + timedelta(seconds=120),
    )
    with pytest.raises(EnrollmentInvalidError, match="expired"):
        later.redeem_enrollment(issued.token, claimed_name="adlab-cli-win")


def test_revoked_enrollment_is_rejected(app_config: AppConfig) -> None:
    service = _service(app_config)
    issued = service.create_enrollment(name_prefix="adlab")
    service.revoke_enrollment(issued.enrollment.id, reason="operator test")
    with pytest.raises(EnrollmentInvalidError):
        service.redeem_enrollment(issued.token, claimed_name="adlab-cli-win")
    with pytest.raises(EnrollmentInvalidError):
        service.revoke_enrollment(issued.enrollment.id, reason="again")


def test_revoking_an_unknown_enrollment_fails(app_config: AppConfig) -> None:
    service = _service(app_config)
    with pytest.raises(EnrollmentNotFoundError):
        service.revoke_enrollment("enr_unknown", reason="operator test")


def test_allowance_is_bounded_and_exhausts(app_config: AppConfig) -> None:
    service = _service(app_config, max_enrollment_uses=2)
    with pytest.raises(ConfigurationError, match="uses must not exceed"):
        service.create_enrollment(name_prefix="adlab", uses=3)
    issued = service.create_enrollment(name_prefix="adlab", uses=2)
    service.redeem_enrollment(issued.token, claimed_name="adlab-cli-one")
    service.redeem_enrollment(issued.token, claimed_name="adlab-cli-two")
    enrollment = service.list_enrollments()[0]
    assert (enrollment.status, enrollment.uses_remaining) == ("exhausted", 0)
    with pytest.raises(EnrollmentInvalidError):
        service.redeem_enrollment(issued.token, claimed_name="adlab-cli-three")


def test_ttl_cannot_exceed_the_configured_ceiling(app_config: AppConfig) -> None:
    service = _service(app_config, enrollment_ttl_seconds=300)
    with pytest.raises(ConfigurationError, match="ttl_seconds must not exceed"):
        service.create_enrollment(name_prefix="adlab", ttl_seconds=301)


@pytest.mark.parametrize(
    "prefix",
    ["", "-adlab", "adlab-", "ad lab", "ad_lab", "a" * 129],
)
def test_invalid_name_prefixes_are_rejected(
    app_config: AppConfig, prefix: str
) -> None:
    service = _service(app_config)
    with pytest.raises(ConfigurationError):
        service.create_enrollment(name_prefix=prefix)


def test_name_prefix_is_normalized_like_an_agent_name(
    app_config: AppConfig,
) -> None:
    service = _service(app_config)
    issued = service.create_enrollment(name_prefix="  AdLab  ")
    assert issued.enrollment.name_prefix == "adlab"
    redeemed = service.redeem_enrollment(
        issued.token, claimed_name="ADLAB-CLI-WIN"
    )
    assert redeemed.agent.name == "adlab-cli-win"


def test_missing_or_malformed_token_is_rejected(
    enrollment_client: TestClient,
) -> None:
    anonymous = enrollment_client.post(
        "/api/enrollments/redeem",
        json={"request_id": str(uuid.uuid4()), "name": "adlab-cli-win"},
    )
    assert anonymous.status_code == 401
    malformed = _redeem(enrollment_client, "not-a-token", "adlab-cli-win")
    assert malformed.status_code == 401
    # An agent API key must not be usable as an enrollment token.
    created = enrollment_client.app.state.agent_service.create_agent("adlab-cli-x")
    assert _redeem(enrollment_client, created.api_key, "adlab-cli-win").status_code == 401


def test_unknown_token_does_not_reach_storage(
    enrollment_client: TestClient,
) -> None:
    _, _, token = mint_enrollment_token()
    response = _redeem(enrollment_client, token, "adlab-cli-win")
    assert response.status_code == 401
    assert not enrollment_client.app.state.agent_service.store.list_agents()


def test_redemption_is_denied_while_frozen(
    enrollment_client: TestClient,
) -> None:
    token = _mint(enrollment_client)
    enrollment_client.app.state.access_freeze_service.freeze("incident drill")
    response = _redeem(enrollment_client, token, "adlab-cli-win")
    assert response.status_code == 503
    assert response.json()["detail"] == "agent access is frozen"
    enrollment_client.app.state.access_freeze_service.unfreeze("drill complete")
    assert _redeem(enrollment_client, token, "adlab-cli-win").status_code == 201


def test_redemption_is_rate_limited_per_source(app_config: AppConfig) -> None:
    limited = replace(app_config, unauthenticated_requests_per_minute=1)
    with TestClient(_application(limited)) as client:
        token = _mint(client)
        first = _redeem(client, token, "adlab-cli-one")
        second = _redeem(client, token, "adlab-cli-two")
        assert first.status_code == 201
        assert second.status_code == 429


def test_token_is_not_persisted_in_plaintext(
    app_config: AppConfig,
) -> None:
    service = _service(app_config)
    issued = service.create_enrollment(name_prefix="adlab")
    service.redeem_enrollment(issued.token, claimed_name="adlab-cli-win")
    with sqlite3.connect(app_config.database_path) as database:
        rows = database.execute(
            "SELECT secret_hash FROM agent_enrollments"
        ).fetchall()
        assert rows and all(len(row[0]) == 64 for row in rows)
    contents = Path(app_config.database_path).read_bytes()
    assert issued.token.encode("ascii") not in contents


def test_redemption_records_immutable_provenance(
    app_config: AppConfig,
) -> None:
    service = _service(app_config)
    issued = service.create_enrollment(name_prefix="adlab")
    redeemed = service.redeem_enrollment(
        issued.token, claimed_name="adlab-cli-win"
    )
    with sqlite3.connect(app_config.database_path) as database:
        row = database.execute(
            """
            SELECT enrollment_id, agent_id, credential_id, claimed_name
            FROM agent_enrollment_redemptions
            """
        ).fetchone()
        assert row == (
            issued.enrollment.id,
            redeemed.agent.id,
            redeemed.issued_credential.credential.id,
            "adlab-cli-win",
        )
        with pytest.raises(sqlite3.IntegrityError):
            database.execute(
                "UPDATE agent_enrollment_redemptions SET claimed_name = 'x'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            database.execute("DELETE FROM agent_enrollments")
        with pytest.raises(sqlite3.IntegrityError):
            database.execute(
                "UPDATE agent_enrollments SET uses_remaining = uses_remaining + 1"
            )


def test_enrollment_listing_never_exposes_a_token(
    app_config: AppConfig,
) -> None:
    service = _service(app_config)
    issued = service.create_enrollment(name_prefix="adlab")
    listed = service.list_enrollments()
    assert [enrollment.id for enrollment in listed] == [issued.enrollment.id]
    assert not hasattr(listed[0], "token")
    assert issued.token not in repr(listed[0])
    assert issued.token not in repr(issued)


def test_name_match_is_validated_and_immutable(app_config: AppConfig) -> None:
    service = _service(app_config)
    with pytest.raises(ConfigurationError, match="name_match"):
        service.create_enrollment(name_prefix="review-reader", name_match="unknown")
    with pytest.raises(ConfigurationError, match="complete agent name"):
        service.create_enrollment(name_prefix="review", name_match="exact")
    from strugglebus.operator_auth import OperatorContext

    exact = service.create_dashboard_enrollment(
        name="review-reader",
        operator=OperatorContext(f"operator:owner:{uuid.uuid4()}", 1000.0, "fixture", "fixture"),
        authorize=lambda: None,
    )
    with sqlite3.connect(app_config.database_path) as database:
        for mode in ("prefix", "unknown", None):
            with pytest.raises(sqlite3.IntegrityError):
                database.execute(
                    "UPDATE agent_enrollments SET name_match=?, version=version+1 WHERE id=?",
                    (mode, exact.enrollment.id),
                )
        # Invalid mode must be rejected on INSERT too, independently of triggers.
        columns = [
            row[1] for row in database.execute("PRAGMA table_info(agent_enrollments)")
        ]
        values = list(database.execute("SELECT * FROM agent_enrollments").fetchone())
        values[columns.index("id")] = "invalid-mode"
        values[columns.index("secret_hash")] = "f" * 64
        values[columns.index("name_match")] = "unknown"
        with pytest.raises(sqlite3.IntegrityError):
            database.execute(
                "INSERT INTO agent_enrollments VALUES (" + ",".join("?" for _ in values) + ")",
                values,
            )
