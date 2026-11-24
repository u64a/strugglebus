from __future__ import annotations

import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

import strugglebus.store._credentials as store_credentials
from strugglebus.auth import AgentService, mint_credential
from strugglebus.errors import (
    AgentNotFoundError,
    CredentialConflictError,
    CredentialLimitError,
)
from strugglebus.store import SQLiteStore


def _request_id() -> str:
    return str(uuid.uuid4())


def _activate(service: AgentService, secret: str):
    pending = service.verify_credential(secret)
    assert pending is not None
    activated = service.prove(
        pending,
        request_id=_request_id(),
        expected_agent_id=pending.agent.id,
        expected_agent_name=pending.agent.name,
        expected_credential_epoch=pending.agent.credential_epoch,
        expected_credential_version=pending.credential.version,
    )
    assert activated.status == "active"
    identity = service.authenticate(secret)
    assert identity is not None
    return identity


def test_rotation_overlaps_proves_and_explicitly_retires_predecessor(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("rotation-copilot")
    predecessor = _activate(agent_service, created.api_key)
    request_id = _request_id()

    successor = agent_service.rotate(
        predecessor,
        request_id=request_id,
        expected_agent_id=predecessor.agent.id,
        expected_credential_id=predecessor.credential.id,
        expected_credential_epoch=predecessor.agent.credential_epoch,
    )

    assert successor.secret_issued is True
    assert successor.secret is not None
    assert successor.credential.status == "pending"
    assert agent_service.authenticate(created.api_key) is not None
    replay = agent_service.rotate(
        predecessor,
        request_id=request_id,
        expected_agent_id=predecessor.agent.id,
        expected_credential_id=predecessor.credential.id,
        expected_credential_epoch=predecessor.agent.credential_epoch,
    )
    assert replay.credential.id == successor.credential.id
    assert replay.secret_issued is False
    assert replay.secret is None

    successor_identity = agent_service.verify_credential(successor.secret)
    assert successor_identity is not None
    with pytest.raises(CredentialConflictError, match="expected identity"):
        agent_service.prove(
            successor_identity,
            request_id=_request_id(),
            expected_agent_id=successor_identity.agent.id,
            expected_agent_name="wrong-agent",
            expected_credential_epoch=successor_identity.agent.credential_epoch,
            expected_credential_version=successor_identity.credential.version,
        )
    successor_identity = _activate(agent_service, successor.secret)
    retired = agent_service.retire_predecessor(
        successor_identity,
        credential_id=predecessor.credential.id,
        request_id=_request_id(),
        expected_credential_epoch=successor_identity.agent.credential_epoch,
        expected_credential_version=predecessor.credential.version,
    )

    assert retired.status == "retired"
    assert agent_service.authenticate(created.api_key) is None
    assert agent_service.authenticate(successor.secret) is not None


def test_recovery_revokes_every_live_credential_and_cannot_reactivate_agent(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("recovery-copilot")
    original = _activate(agent_service, created.api_key)
    rotated = agent_service.rotate(
        original,
        request_id=_request_id(),
        expected_agent_id=original.agent.id,
        expected_credential_id=original.credential.id,
        expected_credential_epoch=original.agent.credential_epoch,
    )
    assert rotated.secret is not None
    pending = agent_service.verify_credential(rotated.secret)
    assert pending is not None
    request_id = _request_id()

    recovered = agent_service.recover_agent(
        original.agent.name,
        request_id=request_id,
        expected_credential_epoch=pending.agent.credential_epoch,
        reason="compromised host",
    )

    assert recovered.secret_issued is True
    assert recovered.secret is not None
    assert agent_service.authenticate(created.api_key) is None
    assert agent_service.authenticate(rotated.secret) is None
    replay = agent_service.recover_agent(
        original.agent.name,
        request_id=request_id,
        expected_credential_epoch=pending.agent.credential_epoch,
        reason="compromised host",
    )
    assert replay.credential.id == recovered.credential.id
    assert replay.secret is None
    assert replay.secret_issued is False

    recovered_identity = _activate(agent_service, recovered.secret)
    agent_service.revoke_agent(recovered_identity.agent.id)
    with pytest.raises(AgentNotFoundError):
        agent_service.recover_agent(
            recovered_identity.agent.name,
            request_id=_request_id(),
            expected_credential_epoch=recovered_identity.agent.credential_epoch + 1,
            reason="must remain terminal",
        )


def test_pending_expiry_is_persisted_terminal_and_audited(app_config) -> None:
    now = datetime(2026, 9, 1, tzinfo=UTC)
    moment = [now]
    service = AgentService(
        SQLiteStore(
            app_config.database_path,
            backup_dir=app_config.backup_dir,
        ),
        clock=lambda: moment[0],
        pending_seconds=10,
    )
    service.initialize()
    created = service.create_agent("expiry-copilot")
    moment[0] += timedelta(seconds=11)

    assert service.verify_credential(created.api_key) is None
    with sqlite3.connect(app_config.database_path) as database:
        status, expired_at, version = database.execute(
            """
            SELECT status, expired_at, version
            FROM agent_credentials
            WHERE id = ?
            """,
            (created.issued_credential.credential.id,),
        ).fetchone()
        audits = database.execute(
            """
            SELECT event_type, credential_id
            FROM agent_credential_audit
            WHERE event_type = 'expire'
            """
        ).fetchall()
    assert status == "expired"
    assert expired_at is not None
    assert version == 1
    assert audits == [("expire", created.issued_credential.credential.id)]


def test_authentication_telemetry_does_not_change_lifecycle_version(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("telemetry-copilot")
    active = _activate(agent_service, created.api_key)
    version = active.credential.version

    for _ in range(3):
        assert agent_service.authenticate(created.api_key) is not None

    credential = agent_service.list_credentials(active.agent.name)[0]
    assert credential.version == version
    assert credential.last_used_at is not None


def test_unknown_new_lookup_uses_dummy_constant_time_comparison(
    agent_service: AgentService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, unknown_secret = mint_credential()
    compared: list[tuple[str, str]] = []
    original = store_credentials.hmac.compare_digest

    def recording_compare(candidate: str, stored: str) -> bool:
        compared.append((candidate, stored))
        return original(candidate, stored)

    monkeypatch.setattr(store_credentials.hmac, "compare_digest", recording_compare)

    assert agent_service.authenticate(unknown_secret) is None
    assert len(compared) == 1
    assert len(compared[0][0]) == len(compared[0][1]) == 64


def test_pending_capacity_and_request_id_conflicts_are_bounded(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("bounded-copilot")
    active = _activate(agent_service, created.api_key)
    request_id = _request_id()
    first = agent_service.rotate(
        active,
        request_id=request_id,
        expected_agent_id=active.agent.id,
        expected_credential_id=active.credential.id,
        expected_credential_epoch=active.agent.credential_epoch,
    )

    with pytest.raises(CredentialConflictError, match="already in use"):
        agent_service.rotate(
            active,
            request_id=request_id,
            expected_agent_id=active.agent.id,
            expected_credential_id=active.credential.id,
            expected_credential_epoch=active.agent.credential_epoch,
            reason="different reason",
        )
    refreshed = agent_service.authenticate(created.api_key)
    assert refreshed is not None
    with pytest.raises(CredentialLimitError, match="capacity"):
        agent_service.rotate(
            refreshed,
            request_id=_request_id(),
            expected_agent_id=refreshed.agent.id,
            expected_credential_id=refreshed.credential.id,
            expected_credential_epoch=refreshed.agent.credential_epoch,
        )
    assert first.secret is not None


def test_concurrent_rotation_idempotency_issues_secret_once(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("concurrent-copilot")
    active = _activate(agent_service, created.api_key)
    request_id = _request_id()

    def rotate_once(_index: int):
        return agent_service.rotate(
            active,
            request_id=request_id,
            expected_agent_id=active.agent.id,
            expected_credential_id=active.credential.id,
            expected_credential_epoch=active.agent.credential_epoch,
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(rotate_once, range(4)))

    assert len({result.credential.id for result in results}) == 1
    assert sum(result.secret_issued for result in results) == 1
    assert sum(result.secret is not None for result in results) == 1
