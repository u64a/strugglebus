"""Registration, enrollment authorisation and creation provenance in the store."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from strugglebus.auth import AgentService, mint_enrollment_token
from strugglebus.config import AppConfig
from strugglebus.errors import (
    AgentAccessFrozenError,
    CredentialConflictError,
    DomainValidationError,
    DuplicateAgentNameError,
    EnrollmentInvalidError,
)
from strugglebus.store import SQLiteStore


def _rid() -> str:
    return str(uuid.uuid4())


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


@pytest.fixture
def agents(app_config: AppConfig) -> AgentService:
    service = AgentService(
        SQLiteStore(app_config.database_path, backup_dir=app_config.backup_dir),
        clock=_Clock(),
    )
    service.initialize()
    return service


def _count(agents: AgentService, table: str) -> int:
    with sqlite3.connect(agents.store.database_path) as database:
        return database.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def _freeze(agents: AgentService) -> None:
    with sqlite3.connect(agents.store.database_path) as database:
        database.execute(
            "UPDATE agent_access_state SET frozen = 1, transition = 'freeze', "
            "changed_at = '2026-09-01T00:00:00.000000Z', reason = 'incident'"
        )


@pytest.mark.parametrize(
    ("creator_type", "creator_id", "message"),
    [
        ("spn", "local-service", "creator type"),
        ("system", "local-service", "creator type"),
        ("local-admin", "", "creator id"),
        ("remote-admin", "x" * 257, "creator id"),
        ("remote-admin", 7, "creator id"),
    ],
)
def test_direct_registration_validates_its_creator_before_writing(
    agents: AgentService, creator_type: str, creator_id: object, message: str,
) -> None:
    before = _count(agents, "agents")

    with pytest.raises(DomainValidationError, match=f"invalid direct-registration {message}"):
        agents.create_agent(
            "direct-copilot", creator_type=creator_type, creator_id=creator_id,  # type: ignore[arg-type]
        )

    assert _count(agents, "agents") == before


def test_direct_registration_replays_by_request_id_and_refuses_other_input(
    agents: AgentService,
) -> None:
    request_id = _rid()
    created = agents.create_agent(
        "direct-copilot", description="first", host="alpha", request_id=request_id,
        creator_type="remote-admin", creator_id="admin",
    )
    agent_count = _count(agents, "agents")

    replayed = agents.create_agent(
        "direct-copilot", description="first", host="alpha", request_id=request_id,
    )

    assert created.issued_credential.secret_issued is True
    assert replayed.agent == created.agent
    assert replayed.issued_credential.credential == created.issued_credential.credential
    assert replayed.issued_credential.secret is None
    assert replayed.issued_credential.secret_issued is False
    for changed in (
        {"name": "another-copilot", "description": "first", "host": "alpha"},
        {"name": "direct-copilot", "description": "second", "host": "alpha"},
        {"name": "direct-copilot", "description": "first", "host": "beta"},
    ):
        with pytest.raises(CredentialConflictError, match="request id is already in use"):
            agents.create_agent(
                changed["name"], description=changed["description"],
                host=changed["host"], request_id=request_id,
            )
    with pytest.raises(DuplicateAgentNameError, match="'direct-copilot' is already registered"):
        agents.create_agent("direct-copilot")
    assert _count(agents, "agents") == agent_count
    page = agents.list_identity_creation_provenance(creator_type="remote-admin")
    assert [(item.agent.name, item.creator_principal_id, item.creation_method) for item in page.items] == [
        ("direct-copilot", "admin", "direct-registration"),
    ]


def test_direct_registration_honours_the_access_freeze_only_when_asked(
    agents: AgentService,
) -> None:
    _freeze(agents)

    with pytest.raises(AgentAccessFrozenError):
        agents.create_agent("frozen-copilot", require_access=True)
    local = agents.create_agent("local-copilot")

    assert local.agent.name == "local-copilot"
    assert [agent.name for agent in agents.store.list_agents()] == ["local-copilot"]


def _store_enrollment(agents: AgentService, **overrides: object):
    enrollment_id, verifier, _ = mint_enrollment_token()
    now = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
    arguments: dict[str, object] = dict(
        enrollment_id=enrollment_id,
        secret_hash=verifier,
        name_prefix="team",
        name_match="prefix",
        description="",
        uses_allowed=1,
        created_at=now,
        expires_at=now + timedelta(hours=1),
        actor_type="local-admin",
        actor_id="tester",
        creation_reason="agent self-registration",
    )
    return agents.store.create_enrollment(**(arguments | overrides))


def test_enrollment_guard_must_be_callable_and_operators_must_bring_one(
    agents: AgentService,
) -> None:
    operator_id = f"operator:owner:{_rid()}"

    with pytest.raises(DomainValidationError, match="authorization guard must be callable"):
        _store_enrollment(agents, authorize="yes")
    with pytest.raises(DomainValidationError, match="operator authorization guard is required"):
        _store_enrollment(agents, actor_type="remote-admin", actor_id=operator_id)
    with pytest.raises(DomainValidationError, match="operator authorization guard is required"):
        _store_enrollment(
            agents, actor_type="local-admin", actor_id=operator_id, authorize=lambda: None,
        )

    assert agents.list_enrollments() == ()


def test_enrollment_guard_runs_inside_the_write_and_can_veto_it(
    agents: AgentService,
) -> None:
    calls: list[str] = []

    def allow() -> None:
        calls.append("allow")

    def deny() -> None:
        calls.append("deny")
        raise PermissionError("session ended")

    with pytest.raises(PermissionError, match="session ended"):
        _store_enrollment(agents, authorize=deny)
    assert agents.list_enrollments() == ()

    plain = _store_enrollment(agents, authorize=allow)
    operator = _store_enrollment(
        agents, actor_type="remote-admin", actor_id=f"operator:owner:{_rid()}",
        authorize=allow,
    )

    assert calls == ["deny", "allow", "allow"]
    assert (plain.status, plain.uses_remaining, plain.actor_id) == ("pending", 1, "tester")
    assert operator.actor_type == "remote-admin"
    assert {enrollment.id for enrollment in agents.list_enrollments()} == {plain.id, operator.id}


def test_operator_enrollment_is_denied_while_access_is_frozen(agents: AgentService) -> None:
    calls: list[str] = []
    _freeze(agents)

    with pytest.raises(AgentAccessFrozenError):
        _store_enrollment(
            agents, actor_type="remote-admin", actor_id=f"operator:owner:{_rid()}",
            authorize=lambda: calls.append("allow"),
        )
    with pytest.raises(AgentAccessFrozenError):
        _store_enrollment(agents, require_access=True)
    # The protected local path does not ask for agent access.
    local = _store_enrollment(agents)

    # The operator's session was revalidated before the freeze refused the write.
    assert calls == ["allow"]
    assert [enrollment.id for enrollment in agents.list_enrollments()] == [local.id]


def test_redemption_enforces_the_name_allowance_and_never_reuses_a_name(
    agents: AgentService,
) -> None:
    agents = AgentService(agents.store, clock=_Clock(), max_enrollment_uses=5)
    exact = agents.create_enrollment(name_prefix="solo-copilot", name_match="exact", uses=2)
    prefixed = agents.create_enrollment(name_prefix="team", uses=3)
    agents.create_agent("team-taken")

    with pytest.raises(EnrollmentInvalidError, match="outside the enrollment allowance"):
        agents.redeem_enrollment(exact.token, claimed_name="solo-copilot-two")
    with pytest.raises(EnrollmentInvalidError, match="outside the enrollment allowance"):
        agents.redeem_enrollment(prefixed.token, claimed_name="teammate-copilot")
    with pytest.raises(DuplicateAgentNameError, match="already registered"):
        agents.redeem_enrollment(prefixed.token, claimed_name="team-taken")
    assert [
        enrollment.uses_remaining
        for enrollment in sorted(agents.list_enrollments(), key=lambda item: item.uses_allowed)
    ] == [2, 3]

    solo = agents.redeem_enrollment(exact.token, claimed_name="solo-copilot")
    member = agents.redeem_enrollment(prefixed.token, claimed_name="team-copilot")

    assert (solo.agent.name, member.agent.name) == ("solo-copilot", "team-copilot")
    assert solo.issued_credential.credential.status == "pending"
    with pytest.raises(DuplicateAgentNameError, match="already registered"):
        agents.redeem_enrollment(exact.token, claimed_name="solo-copilot")
    page = agents.list_identity_creation_provenance(creator_id="operator")
    assert {(item.agent.name, item.creation_method, item.originating_enrollment_id) for item in page.items} == {
        ("solo-copilot", "enrollment", exact.enrollment.id),
        ("team-copilot", "enrollment", prefixed.enrollment.id),
    }
    assert all(item.originating_issuance_request_id is None for item in page.items)


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ({"creator_type": "agent"}, "invalid creator principal type"),
        ({"creator_id": ""}, "invalid creator principal id"),
        ({"creator_id": "x" * 257}, "invalid creator principal id"),
        ({"creator_id": 5}, "invalid creator principal id"),
        (
            {"after_created_at": datetime(2026, 9, 1, tzinfo=UTC)},
            "both provenance cursor fields must be supplied",
        ),
        ({"after_agent_id": "agent"}, "both provenance cursor fields must be supplied"),
        (
            {"after_created_at": datetime(2026, 9, 1), "after_agent_id": "agent"},
            "cursor timestamp must include a timezone",
        ),
        (
            {"after_created_at": datetime(2026, 9, 1, tzinfo=UTC), "after_agent_id": ""},
            "invalid provenance cursor agent id",
        ),
        (
            {"after_created_at": datetime(2026, 9, 1, tzinfo=UTC), "after_agent_id": "x" * 257},
            "invalid provenance cursor agent id",
        ),
        ({"limit": 0}, "invalid provenance result limit"),
        ({"limit": 201}, "invalid provenance result limit"),
        ({"limit": True}, "invalid provenance result limit"),
        ({"limit": "10"}, "invalid provenance result limit"),
    ],
)
def test_provenance_query_is_validated(
    agents: AgentService, query: dict[str, object], message: str,
) -> None:
    with pytest.raises(DomainValidationError, match=message):
        agents.store.list_identity_creation_provenance(**query)  # type: ignore[arg-type]


def test_provenance_pages_in_creation_order_with_a_resumable_cursor(
    agents: AgentService,
) -> None:
    names = ["alpha-copilot", "bravo-copilot", "charlie-copilot"]
    for name in names:
        agents.create_agent(name)
    agents.create_agent("remote-copilot", creator_type="remote-admin", creator_id="admin")

    first = agents.list_identity_creation_provenance(creator_type="local-admin", limit=2)
    second = agents.list_identity_creation_provenance(
        creator_type="local-admin",
        after_created_at=first.next_created_at,
        after_agent_id=first.next_agent_id,
        limit=2,
    )
    everything = agents.list_identity_creation_provenance(limit=200)

    assert [item.agent.name for item in first.items] == names[:2]
    assert (first.total_count, first.has_more) == (3, True)
    assert first.next_created_at == first.items[-1].created_at
    assert first.next_agent_id == first.items[-1].agent.id
    assert [item.agent.name for item in second.items] == names[2:]
    assert (second.total_count, second.has_more) == (3, False)
    assert (second.next_created_at, second.next_agent_id) == (None, None)
    assert [item.agent.name for item in everything.items] == [*names, "remote-copilot"]
    assert everything.total_count == 4
    assert agents.list_identity_creation_provenance(creator_id="nobody").items == ()
