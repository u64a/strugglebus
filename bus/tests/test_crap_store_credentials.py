"""Credential lifecycle guards in the store: capacity, staleness and replay."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import timedelta

import pytest

from strugglebus.auth import AgentService, mint_credential
from strugglebus.errors import (
    AgentNotFoundError,
    CredentialConflictError,
    CredentialLimitError,
)
from strugglebus.store import utc_now
from strugglebus.store._credentials import _require_active_predecessor


def _request_id() -> str:
    return str(uuid.uuid4())


def _activate(service: AgentService, secret: str):
    pending = service.verify_credential(secret)
    assert pending is not None
    service.prove(
        pending,
        request_id=_request_id(),
        expected_agent_id=pending.agent.id,
        expected_agent_name=pending.agent.name,
        expected_credential_epoch=pending.agent.credential_epoch,
        expected_credential_version=pending.credential.version,
    )
    identity = service.authenticate(secret)
    assert identity is not None
    return identity


def _epoch(service: AgentService, agent_id: str) -> int:
    return service.get_active_agent(agent_id).credential_epoch


def _statuses(service: AgentService, name: str) -> list[str]:
    return [credential.status for credential in service.list_credentials(name)]


def _audit_count(service: AgentService) -> int:
    with sqlite3.connect(service.store.database_path) as database:
        return database.execute(
            "SELECT COUNT(*) FROM agent_credential_audit"
        ).fetchone()[0]


def _issue_directly(service: AgentService, agent_id: str, *, expected_epoch: int):
    credential_id, verifier, _ = mint_credential()
    now = utc_now()
    return service.store.issue_credential(
        agent_id=agent_id,
        credential_id=credential_id,
        secret_hash=verifier,
        request_id=_request_id(),
        expected_credential_epoch=expected_epoch,
        reason="operator issue",
        actor_type="local-admin",
        actor_id="tester",
        created_at=now,
        pending_expires_at=now + timedelta(minutes=5),
        max_active=2,
        max_pending=2,
    )


def test_issue_refuses_unknown_or_retired_agents_and_stale_epochs(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("issue-copilot")
    retired = agent_service.create_agent("retired-copilot")
    agent_service.revoke_agent(retired.agent.id, request_id=_request_id())
    audit_before = _audit_count(agent_service)

    with pytest.raises(AgentNotFoundError, match="authenticated agent is unavailable"):
        _issue_directly(agent_service, str(uuid.uuid4()), expected_epoch=1)
    with pytest.raises(AgentNotFoundError, match="authenticated agent is unavailable"):
        _issue_directly(
            agent_service, retired.agent.id,
            expected_epoch=agent_service.get_managed_agent(retired.agent.id).credential_epoch,
        )
    with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
        _issue_directly(
            agent_service, created.agent.id,
            expected_epoch=created.agent.credential_epoch + 1,
        )

    assert _statuses(agent_service, "issue-copilot") == ["pending"]
    assert _audit_count(agent_service) == audit_before

    issued, was_created = _issue_directly(
        agent_service, created.agent.id, expected_epoch=created.agent.credential_epoch,
    )
    assert was_created is True
    assert issued.status == "pending"
    assert issued.creation_method == "issue"
    assert _epoch(agent_service, created.agent.id) == created.agent.credential_epoch + 1


def test_self_rotation_is_limited_per_window(agent_service: AgentService) -> None:
    limited = AgentService(
        agent_service.store,
        max_active_credentials=3,
        max_pending_credentials=3,
        rotations_per_window=1,
    )
    created = limited.create_agent("rotating-copilot")
    identity = _activate(limited, created.api_key)

    first = limited.rotate(
        identity,
        request_id=_request_id(),
        expected_agent_id=identity.agent.id,
        expected_credential_id=identity.credential.id,
        expected_credential_epoch=_epoch(limited, identity.agent.id),
    )
    epoch_after_first = _epoch(limited, identity.agent.id)
    with pytest.raises(CredentialLimitError, match="credential rotation limit reached"):
        limited.rotate(
            identity,
            request_id=_request_id(),
            expected_agent_id=identity.agent.id,
            expected_credential_id=identity.credential.id,
            expected_credential_epoch=epoch_after_first,
        )

    assert first.credential.predecessor_id == identity.credential.id
    assert _statuses(limited, "rotating-copilot") == ["active", "pending"]
    assert _epoch(limited, identity.agent.id) == epoch_after_first


def test_rotation_requires_the_presented_identity_to_be_the_expected_active_one(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("mismatch-copilot")
    pending = agent_service.verify_credential(created.api_key)
    assert pending is not None

    with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
        agent_service.rotate(
            pending,
            request_id=_request_id(),
            expected_agent_id=pending.agent.id,
            expected_credential_id=pending.credential.id,
            expected_credential_epoch=pending.agent.credential_epoch,
        )
    identity = _activate(agent_service, created.api_key)
    for expected_agent_id, expected_credential_id in (
        (str(uuid.uuid4()), identity.credential.id),
        (identity.agent.id, "cred_someone-elses"),
    ):
        with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
            agent_service.rotate(
                identity,
                request_id=_request_id(),
                expected_agent_id=expected_agent_id,
                expected_credential_id=expected_credential_id,
                expected_credential_epoch=_epoch(agent_service, identity.agent.id),
            )

    assert _statuses(agent_service, "mismatch-copilot") == ["active"]


def test_rotation_predecessor_must_still_be_active(agent_service: AgentService) -> None:
    created = agent_service.create_agent("predecessor-copilot")
    pending = agent_service.verify_credential(created.api_key)
    assert pending is not None

    with agent_service.store._transaction() as connection:
        # An issue has no predecessor, so there is nothing to check.
        _require_active_predecessor(connection, pending.agent.id, None)
        with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
            _require_active_predecessor(connection, pending.agent.id, "cred_missing")
        with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
            _require_active_predecessor(
                connection, pending.agent.id, pending.credential.id,
            )

    identity = _activate(agent_service, created.api_key)
    with agent_service.store._transaction() as connection:
        _require_active_predecessor(connection, identity.agent.id, identity.credential.id)
        with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
            _require_active_predecessor(
                connection, str(uuid.uuid4()), identity.credential.id,
            )


def test_proof_is_refused_once_active_capacity_is_full(
    agent_service: AgentService,
) -> None:
    roomy = AgentService(agent_service.store, max_active_credentials=2)
    strict = AgentService(agent_service.store, max_active_credentials=1)
    created = roomy.create_agent("capacity-copilot")
    _activate(roomy, created.api_key)
    second = roomy.issue_for_agent(
        "capacity-copilot",
        request_id=_request_id(),
        expected_credential_epoch=_epoch(roomy, created.agent.id),
        reason="second credential",
    )
    assert second.secret is not None
    pending = strict.verify_credential(second.secret)
    assert pending is not None

    with pytest.raises(CredentialLimitError, match="active credential capacity reached"):
        strict.prove(
            pending,
            request_id=_request_id(),
            expected_agent_id=pending.agent.id,
            expected_agent_name=pending.agent.name,
            expected_credential_epoch=pending.agent.credential_epoch,
            expected_credential_version=pending.credential.version,
        )

    assert _statuses(roomy, "capacity-copilot") == ["active", "pending"]


def test_proof_needs_current_expectations_and_replays_its_result(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("proof-copilot")
    pending = agent_service.verify_credential(created.api_key)
    assert pending is not None
    expectations = {
        "expected_agent_id": pending.agent.id,
        "expected_agent_name": pending.agent.name,
        "expected_credential_epoch": pending.agent.credential_epoch,
        "expected_credential_version": pending.credential.version,
    }

    for stale in (
        {"expected_credential_version": pending.credential.version + 1},
        {"expected_credential_epoch": pending.agent.credential_epoch + 1},
    ):
        with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
            agent_service.prove(pending, request_id=_request_id(), **(expectations | stale))
    assert _statuses(agent_service, "proof-copilot") == ["pending"]

    request_id = _request_id()
    proved = agent_service.prove(pending, request_id=request_id, **expectations)
    audit_after_proof = _audit_count(agent_service)
    replayed = agent_service.prove(pending, request_id=request_id, **expectations)

    assert proved.status == "active"
    assert replayed == proved
    assert _audit_count(agent_service) == audit_after_proof
    # The same request id cannot be reused for a different expectation.
    with pytest.raises(CredentialConflictError, match="request id is already in use"):
        agent_service.prove(
            pending, request_id=request_id,
            **(expectations | {"expected_credential_version": 99}),
        )
    # A fresh request finds the credential already active, not pending.
    with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
        agent_service.prove(pending, request_id=_request_id(), **expectations)


def test_only_the_active_predecessor_can_be_retired_and_retirement_replays(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("retire-copilot")
    predecessor = _activate(agent_service, created.api_key)
    rotated = agent_service.rotate(
        predecessor,
        request_id=_request_id(),
        expected_agent_id=predecessor.agent.id,
        expected_credential_id=predecessor.credential.id,
        expected_credential_epoch=_epoch(agent_service, predecessor.agent.id),
    )
    assert rotated.secret is not None
    successor = _activate(agent_service, rotated.secret)
    epoch = _epoch(agent_service, successor.agent.id)
    predecessor_version = agent_service.get_credential(
        "retire-copilot", predecessor.credential.id,
    ).version

    refused = (
        # Its own credential, a stranger, a stale version, a stale epoch.
        (successor.credential.id, successor.credential.version, epoch),
        ("cred_unrelated", predecessor_version, epoch),
        (predecessor.credential.id, predecessor_version + 1, epoch),
        (predecessor.credential.id, predecessor_version, epoch + 1),
    )
    for credential_id, version, expected_epoch in refused:
        with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
            agent_service.retire_predecessor(
                successor,
                credential_id=credential_id,
                request_id=_request_id(),
                expected_credential_epoch=expected_epoch,
                expected_credential_version=version,
            )
    assert _statuses(agent_service, "retire-copilot") == ["active", "active"]

    request_id = _request_id()
    retired = agent_service.retire_predecessor(
        successor,
        credential_id=predecessor.credential.id,
        request_id=request_id,
        expected_credential_epoch=epoch,
        expected_credential_version=predecessor_version,
    )
    audit_after_retire = _audit_count(agent_service)
    replayed = agent_service.retire_predecessor(
        successor,
        credential_id=predecessor.credential.id,
        request_id=request_id,
        expected_credential_epoch=epoch,
        expected_credential_version=predecessor_version,
    )

    assert retired.status == "retired"
    assert replayed == retired
    assert _audit_count(agent_service) == audit_after_retire
    assert agent_service.authenticate(created.api_key) is None


def test_targeted_revocation_checks_state_and_replays_its_result(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("revoke-copilot")
    identity = _activate(agent_service, created.api_key)
    epoch = _epoch(agent_service, identity.agent.id)
    version = agent_service.get_credential("revoke-copilot", identity.credential.id).version

    for stale_epoch, stale_version, credential_id in (
        (epoch + 1, version, identity.credential.id),
        (epoch, version + 1, identity.credential.id),
        (epoch, version, "cred_unknown"),
    ):
        with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
            agent_service.revoke_credential(
                "revoke-copilot",
                credential_id,
                request_id=_request_id(),
                expected_credential_epoch=stale_epoch,
                expected_credential_version=stale_version,
                reason="suspected leak",
            )
    assert agent_service.authenticate(created.api_key) is not None

    request_id = _request_id()
    revoked = agent_service.revoke_credential(
        "revoke-copilot",
        identity.credential.id,
        request_id=request_id,
        expected_credential_epoch=epoch,
        expected_credential_version=version,
        reason="suspected leak",
    )
    audit_after_revoke = _audit_count(agent_service)
    replayed = agent_service.revoke_credential(
        "revoke-copilot",
        identity.credential.id,
        request_id=request_id,
        expected_credential_epoch=epoch,
        expected_credential_version=version,
        reason="suspected leak",
    )

    assert revoked.status == "revoked"
    assert replayed == revoked
    assert _audit_count(agent_service) == audit_after_revoke
    assert agent_service.authenticate(created.api_key) is None
    # Already revoked: a new request sees the changed state.
    with pytest.raises(CredentialConflictError, match="lifecycle state changed"):
        agent_service.revoke_credential(
            "revoke-copilot",
            identity.credential.id,
            request_id=_request_id(),
            expected_credential_epoch=_epoch(agent_service, identity.agent.id),
            expected_credential_version=revoked.version,
            reason="suspected leak",
        )


def test_live_credential_lookup_needs_exactly_one_live_credential(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("lookup-copilot")
    identity = _activate(agent_service, created.api_key)
    store = agent_service.store

    assert store.get_live_credential_id(identity.agent.id) == identity.credential.id

    agent_service.rotate(
        identity,
        request_id=_request_id(),
        expected_agent_id=identity.agent.id,
        expected_credential_id=identity.credential.id,
        expected_credential_epoch=_epoch(agent_service, identity.agent.id),
    )
    with pytest.raises(CredentialConflictError, match="exact credential context"):
        store.get_live_credential_id(identity.agent.id)

    agent_service.revoke_agent(identity.agent.id, request_id=_request_id())
    with pytest.raises(CredentialConflictError, match="exact credential context"):
        store.get_live_credential_id(identity.agent.id)


def test_credential_reads_report_unknown_agents_and_credentials(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("reader-copilot")
    store = agent_service.store

    with pytest.raises(AgentNotFoundError, match="agent is unavailable"):
        store.list_credentials(str(uuid.uuid4()))
    with pytest.raises(CredentialConflictError, match="exact credential was not found"):
        store.get_credential(created.agent.id, "cred_unknown")
    with pytest.raises(CredentialConflictError, match="exact credential was not found"):
        store.get_credential(str(uuid.uuid4()), created.issued_credential.credential.id)

    found = store.get_credential(created.agent.id, created.issued_credential.credential.id)
    assert found == created.issued_credential.credential


def test_retiring_an_already_retired_agent_is_a_no_op(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("gone-copilot")
    first = agent_service.revoke_agent(created.agent.id, request_id=_request_id())
    audit_after_first = _audit_count(agent_service)

    second = agent_service.revoke_agent(created.agent.id, request_id=_request_id())

    assert first.revoked_at is not None
    assert second == first
    assert _audit_count(agent_service) == audit_after_first
