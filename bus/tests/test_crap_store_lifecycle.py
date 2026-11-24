"""Reconnect grants and lifecycle history, exercised directly against the store."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from strugglebus.auth import AgentService, mint_credential, mint_reconnect_token
from strugglebus.config import AppConfig
from strugglebus.errors import (
    AgentNotFoundError,
    CredentialConflictError,
    CredentialLimitError,
    CredentialNotFoundError,
    DomainValidationError,
)
from strugglebus.models import LifecycleActor
from strugglebus.store import SQLiteStore

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _rid() -> str:
    return str(uuid.uuid4())


def _operator() -> LifecycleActor:
    return LifecycleActor("remote-admin", f"operator:owner:{_rid()}", lambda: None)


@pytest.fixture
def agents(app_config: AppConfig) -> AgentService:
    service = AgentService(
        SQLiteStore(app_config.database_path, backup_dir=app_config.backup_dir),
        clock=lambda: _NOW,
    )
    service.initialize()
    return service


def _issue(agents: AgentService, agent, **overrides):
    grant_id, verifier, _ = mint_reconnect_token()
    arguments = dict(
        agent_id=agent.id,
        expected_agent_name=agent.name,
        expected_credential_epoch=agents.get_active_agent(agent.id).credential_epoch,
        request_id=_rid(),
        reason="move to replacement computer",
        actor=_operator(),
        grant_id=grant_id,
        secret_hash=verifier,
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=10),
        checked_at=_NOW,
    )
    grant, created = agents.store.issue_reconnect_grant(**(arguments | overrides))
    return grant, created, verifier


def _redeem(agents: AgentService, agent, grant, verifier: str, **overrides):
    credential_id, secret_hash, _ = mint_credential()
    arguments = dict(
        grant_id=grant.id,
        candidate_digest=verifier,
        expected_agent_id=agent.id,
        expected_agent_name=agent.name,
        request_id=_rid(),
        credential_id=credential_id,
        secret_hash=secret_hash,
        redeemed_at=_NOW + timedelta(minutes=1),
        pending_expires_at=_NOW + timedelta(minutes=6),
    )
    return agents.store.redeem_reconnect_grant(**(arguments | overrides))


def _grant_statuses(agents: AgentService) -> list[str]:
    with sqlite3.connect(agents.store.database_path) as database:
        return [
            row[0]
            for row in database.execute(
                "SELECT status FROM agent_reconnect_grants ORDER BY created_at, id"
            )
        ]


@pytest.mark.parametrize(
    "overrides",
    [
        {"grant_id": "rcg_too-short"},
        {"grant_id": "grant_" + "a" * 22},
        {"secret_hash": "A" * 64},
        {"secret_hash": "a" * 63},
        {"expires_at": _NOW},
        {"expires_at": _NOW + timedelta(seconds=901)},
        {"max_outstanding": 0},
        {"max_outstanding": 1025},
        {"max_outstanding": True},
    ],
    ids=[
        "short-grant-id", "wrong-grant-prefix", "uppercase-hash", "short-hash",
        "zero-lifetime", "lifetime-over-fifteen-minutes", "no-capacity",
        "capacity-over-bound", "boolean-capacity",
    ],
)
def test_reconnect_issuance_rejects_malformed_material_before_any_cutoff(
    agents: AgentService, overrides: dict[str, object],
) -> None:
    created = agents.create_agent("issue-copilot")

    with pytest.raises(DomainValidationError, match="invalid reconnect issuance"):
        _issue(agents, created.agent, **overrides)

    assert _grant_statuses(agents) == []
    assert agents.verify_credential(created.api_key) is not None


def test_reconnect_issuance_needs_the_expected_enabled_agent(agents: AgentService) -> None:
    created = agents.create_agent("target-copilot")
    ghost = type(created.agent)(
        id=_rid(), name="ghost-copilot", description="", host="",
        created_at=_NOW, last_seen_at=None, revoked_at=None, credential_epoch=1,
        blocked_at=None,
    )

    with pytest.raises(AgentNotFoundError, match="agent is unavailable"):
        _issue(agents, ghost, expected_credential_epoch=1)
    with pytest.raises(CredentialConflictError, match="agent lifecycle state changed"):
        _issue(agents, created.agent, expected_agent_name="renamed-copilot")
    with pytest.raises(CredentialConflictError, match="agent lifecycle state changed"):
        _issue(
            agents, created.agent,
            expected_credential_epoch=created.agent.credential_epoch + 1,
        )
    with pytest.raises(CredentialConflictError, match="prepared reconnect grant expired"):
        _issue(agents, created.agent, checked_at=_NOW + timedelta(minutes=10))
    agents.transition_agent(
        created.agent.id, action="block",
        expected_credential_epoch=created.agent.credential_epoch,
        request_id=_rid(), reason="containment",
        actor=LifecycleActor("local-admin", "tester"),
    )
    with pytest.raises(CredentialConflictError, match="agent lifecycle state changed"):
        _issue(agents, created.agent)

    assert _grant_statuses(agents) == []


def test_reconnect_capacity_counts_other_agents_pending_grants(agents: AgentService) -> None:
    first = agents.create_agent("first-copilot")
    second = agents.create_agent("second-copilot")
    _issue(agents, first.agent, max_outstanding=1)

    with pytest.raises(CredentialLimitError, match="reconnect grant capacity reached"):
        _issue(agents, second.agent, max_outstanding=1)
    # An agent's own outstanding grant does not count against it: reissuing
    # replaces that grant.
    reissued, created, _ = _issue(agents, first.agent, max_outstanding=1)

    assert created is True
    assert reissued.status == "pending"
    assert _grant_statuses(agents).count("pending") == 1
    assert agents.verify_credential(second.api_key) is not None


@pytest.mark.parametrize(
    "overrides",
    [
        {"credential_id": "cred_short"},
        {"credential_id": "key_" + "a" * 22},
        {"secret_hash": "g" * 64},
        {"pending_expires_at": _NOW + timedelta(minutes=1)},
    ],
    ids=["short-id", "wrong-prefix", "non-hex-hash", "no-pending-lifetime"],
)
def test_reconnect_redemption_rejects_a_malformed_replacement_credential(
    agents: AgentService, overrides: dict[str, object],
) -> None:
    created = agents.create_agent("redeem-copilot")
    grant, _, verifier = _issue(agents, created.agent)

    with pytest.raises(DomainValidationError, match="invalid reconnect credential"):
        _redeem(agents, created.agent, grant, verifier, **overrides)

    assert _grant_statuses(agents) == ["pending"]


def test_failed_redemption_leaves_the_grant_spendable_exactly_once(
    agents: AgentService,
) -> None:
    created = agents.create_agent("spend-copilot")
    issue_request = _rid()
    grant, _, verifier = _issue(agents, created.agent, request_id=issue_request)

    with pytest.raises(CredentialNotFoundError, match="reconnect grant is unavailable"):
        _redeem(agents, created.agent, grant, verifier, expected_agent_name="other-copilot")
    with pytest.raises(CredentialNotFoundError, match="reconnect grant is unavailable"):
        _redeem(agents, created.agent, grant, verifier, expected_agent_id=_rid())
    # A request id that already names a lifecycle event cannot be reused.
    with pytest.raises(CredentialNotFoundError, match="reconnect grant is unavailable"):
        _redeem(agents, created.agent, grant, verifier, request_id=issue_request)
    with pytest.raises(CredentialNotFoundError, match="reconnect grant is unavailable"):
        _redeem(agents, created.agent, grant, "0" * 64)
    assert _grant_statuses(agents) == ["pending"]
    assert [credential.status for credential in agents.list_credentials("spend-copilot")] == [
        "revoked",
    ]

    agent, credential, redeemed = _redeem(agents, created.agent, grant, verifier)

    assert agent.id == created.agent.id
    assert agent.credential_epoch == grant.bound_epoch + 1
    assert credential.status == "pending"
    assert credential.creation_method == "reconnect"
    assert credential.pending_expires_at == _NOW + timedelta(minutes=6)
    assert redeemed.status == "redeemed"
    assert redeemed.result_credential_id == credential.id
    with pytest.raises(CredentialNotFoundError, match="reconnect grant is unavailable"):
        _redeem(agents, created.agent, grant, verifier)
    assert len(agents.list_credentials("spend-copilot")) == 2


def test_reconnect_grant_lookup_is_scoped_to_its_agent(agents: AgentService) -> None:
    created = agents.create_agent("lookup-copilot")
    other = agents.create_agent("other-copilot")
    grant, _, _ = _issue(agents, created.agent)

    assert agents.store.get_reconnect_grant(created.agent.id, grant.id) == grant
    with pytest.raises(CredentialNotFoundError, match="reconnect grant is unavailable"):
        agents.store.get_reconnect_grant(other.agent.id, grant.id)
    with pytest.raises(CredentialNotFoundError, match="reconnect grant is unavailable"):
        agents.store.get_reconnect_grant(created.agent.id, "rcg_" + "z" * 22)


def test_lifecycle_history_is_ordered_paged_and_bounds_its_query(
    agents: AgentService,
) -> None:
    created = agents.create_agent("history-copilot")
    admin = LifecycleActor("local-admin", "tester")
    epoch = created.agent.credential_epoch
    for action in ("block", "unblock", "block"):
        agents.transition_agent(
            created.agent.id, action=action, expected_credential_epoch=epoch,
            request_id=_rid(), reason=f"{action} for test", actor=admin,
        )
        epoch += 1
    store = agents.store

    everything = store.list_agent_lifecycle_events(created.agent.id)
    first_page = store.list_agent_lifecycle_events(created.agent.id, limit=2)
    second_page = store.list_agent_lifecycle_events(
        created.agent.id, after_seq=first_page[-1].seq, limit=2,
    )

    assert [event.action for event in everything] == ["block", "unblock", "block"]
    assert [event.resulting_state for event in everything] == [
        "blocked", "enabled", "blocked",
    ]
    assert first_page + second_page == everything
    assert store.list_agent_lifecycle_events(_rid()) == ()
    for query in (
        {"after_seq": -1},
        {"after_seq": 2**63},
        {"after_seq": True},
        {"limit": 0},
        {"limit": 201},
        {"limit": "5"},
    ):
        with pytest.raises(DomainValidationError, match="invalid lifecycle history query"):
            store.list_agent_lifecycle_events(created.agent.id, **query)
