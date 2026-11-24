from __future__ import annotations

import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

import strugglebus.store._common as store_common
import strugglebus.store._credentials as store_credentials
import strugglebus.store._lifecycle as store_lifecycle
import strugglebus.store._messages as store_messages
import strugglebus.store._roe as store_roe
import strugglebus.store._task_claims as store_task_claims
from strugglebus.auth import AgentService
from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    ConfigurationError,
    CredentialConflictError,
    CredentialNotFoundError,
    DomainValidationError,
    UnknownMentionError,
)
from strugglebus.models import LifecycleActor
from strugglebus.roe import RoeService
from strugglebus.service import BoardService
from strugglebus.store import SQLiteStore


def request_id() -> str:
    return str(uuid.uuid4())


def operator(check=lambda: None) -> LifecycleActor:
    return LifecycleActor("remote-admin", f"operator:owner:{request_id()}", check)


def activate(service, created):
    identity = service.verify_credential(created.api_key)
    service.prove(
        identity, request_id=request_id(), expected_agent_id=identity.id,
        expected_agent_name=identity.name,
        expected_credential_epoch=identity.agent.credential_epoch,
        expected_credential_version=identity.credential.version,
    )
    return service.authenticate(created.api_key)


def transition(service, agent_id, action, **kwargs):
    return service.transition_agent(
        agent_id, action=action,
        expected_credential_epoch=service.get_active_agent(agent_id).credential_epoch,
        request_id=request_id(), reason="owner containment decision",
        actor=kwargs.pop("actor", operator()), **kwargs,
    )


def board_for(service):
    board = BoardService(
        service.store, max_message_bytes=1024 * 1024,
        max_metadata_bytes=8192, max_channels=32,
    )
    board.initialize()
    return board


def rows(service, table):
    with sqlite3.connect(service.store.database_path) as connection:
        return connection.execute(f"SELECT * FROM {table}").fetchall()


def test_block_unblock_preserves_credentials_history_and_queued_mentions(agent_service):
    target = agent_service.create_agent("blocked-copilot")
    sender = agent_service.create_agent("sender-copilot")
    active = activate(agent_service, target)
    activate(agent_service, sender)
    board = board_for(agent_service)
    board.subscribe("status", agent_id=target.agent.id)
    board.create_message("status", agent_id=target.agent.id, body="existing",
                         kind="chat", reply_to=None, metadata={})
    board.catch_up(agent_id=target.agent.id)
    preserved = {
        table: rows(agent_service, table)
        for table in ("agent_credentials", "agent_credential_audit", "messages", "mentions",
                      "subscriptions", "cursors", "mention_cursors", "roe_acknowledgements")
    }
    actor = operator()
    result = transition(agent_service, target.agent.id, "block", actor=actor)
    assert result.event.previous_state == "enabled"
    assert result.event.resulting_state == "blocked"
    assert result.event.resulting_epoch == active.agent.credential_epoch + 1
    assert {table: rows(agent_service, table) for table in preserved} == preserved
    assert agent_service.authenticate(target.api_key) is None
    assert agent_service.verify_credential(target.api_key) is None
    assert not agent_service.store.credential_is_active(target.agent.id, active.credential.id)
    assert target.agent.id in {a.id for a in agent_service.store.list_agents()}
    assert target.agent.id not in {a.id for a in board.list_agents()}
    assert agent_service.store.list_managed_agents(state="blocked")[0].id == target.agent.id

    queued = board.create_message(
        "status", agent_id=sender.agent.id, body="@blocked-copilot queued",
        kind="chat", reply_to=None, metadata={},
    )
    cursor_before = rows(agent_service, "cursors"), rows(agent_service, "mention_cursors")
    for operation in (
        lambda: board.catch_up(agent_id=target.agent.id),
        lambda: board.orientation(agent_id=target.agent.id),
        lambda: board.subscribe("help", agent_id=target.agent.id),
        lambda: board.create_message("status", agent_id=target.agent.id, body="denied",
                                     kind="chat", reply_to=None, metadata={}),
    ):
        with pytest.raises(AgentNotFoundError):
            operation()
    assert (rows(agent_service, "cursors"), rows(agent_service, "mention_cursors")) == cursor_before
    transition(agent_service, target.agent.id, "unblock")
    assert agent_service.authenticate(target.api_key) is not None
    assert queued.seq in {m.seq for m in board.catch_up(agent_id=target.agent.id)}
    assert rows(agent_service, "agent_credentials") == preserved["agent_credentials"]


@pytest.mark.parametrize("pending", [False, True])
def test_preauthenticated_bootstrap_and_operational_contexts_deny_block(agent_service, pending):
    created = agent_service.create_agent("held-copilot")
    identity = agent_service.verify_credential(created.api_key) if pending else activate(agent_service, created)
    board = board_for(agent_service)
    roe = RoeService(agent_service.store, enforcement_mode="observe")
    roe.initialize()
    transition(agent_service, created.agent.id, "block")
    begin = agent_service.store.begin_bootstrap_operation if pending else (
        lambda a, c: agent_service.store.begin_roe_operation(a, c, require_receipt=False)
    )
    end = agent_service.store.end_bootstrap_operation if pending else agent_service.store.end_roe_operation
    token = begin(identity.id, identity.credential.id)
    try:
        for operation in (
            lambda: board.list_channels(),
            lambda: board.create_channel("denied", purpose="", created_by=identity.id),
            lambda: agent_service.store.get_active_agent(identity.id),
            lambda: agent_service.store.require_bootstrap_identity(
                identity.id, identity.credential.id, checked_at=datetime.now(UTC),
            ),
        ):
            with pytest.raises(CredentialNotFoundError):
                operation()
    finally:
        end(token)
    with pytest.raises((AgentNotFoundError, CredentialNotFoundError)):
        roe.get_effective(identity.id, identity.credential.id)


def test_block_denies_pending_proof_and_successful_proof_replay(agent_service):
    created = agent_service.create_agent("proof-copilot")
    identity = agent_service.verify_credential(created.api_key)
    intent = dict(
        request_id=request_id(), expected_agent_id=identity.id, expected_agent_name=identity.name,
        expected_credential_epoch=identity.agent.credential_epoch,
        expected_credential_version=identity.credential.version,
    )
    transition(agent_service, identity.id, "block")
    with pytest.raises(CredentialNotFoundError):
        agent_service.prove(identity, **intent)
    transition(agent_service, identity.id, "unblock")
    identity = agent_service.verify_credential(created.api_key)
    intent["expected_credential_epoch"] = identity.agent.credential_epoch
    agent_service.prove(identity, **intent)
    transition(agent_service, identity.id, "block")
    before = rows(agent_service, "agent_credentials"), rows(agent_service, "agent_credential_audit")
    with pytest.raises(CredentialNotFoundError):
        agent_service.prove(identity, **intent)
    assert (rows(agent_service, "agent_credentials"), rows(agent_service, "agent_credential_audit")) == before


def test_blocked_human_recovery_does_not_unblock_or_revive_terminal_credentials(agent_service):
    created = agent_service.create_agent("recover-blocked")
    active = activate(agent_service, created)
    transition(agent_service, created.agent.id, "block")
    agent_service.store.set_access_freeze(frozen=True, reason="local incident", changed_at=datetime.now(UTC))
    with pytest.raises(AgentAccessFrozenError):
        agent_service.recover_agent(
            created.agent.name, request_id=request_id(),
            expected_credential_epoch=active.agent.credential_epoch + 1, reason="remote denied",
        )
    recovered = agent_service.recover_agent(
        created.agent.name, request_id=request_id(),
        expected_credential_epoch=active.agent.credential_epoch + 1, reason="protected repair",
        actor_type="local-admin", actor_id="local-admin",
    )
    assert recovered.credential.status == "pending"
    assert agent_service.list_credentials(created.agent.name, require_access=False)[0].status == "revoked"
    assert agent_service.get_active_agent(created.agent.id).state == "blocked"
    assert agent_service.verify_credential(recovered.secret) is None
    agent_service.store.set_access_freeze(frozen=False, reason="local clearance", changed_at=datetime.now(UTC))
    transition(agent_service, created.agent.id, "unblock")
    assert agent_service.verify_credential(created.api_key) is None
    assert agent_service.verify_credential(recovered.secret) is not None


def test_pending_expiry_while_blocked_is_not_extended(app_config):
    moment = [datetime.now(UTC)]
    service = AgentService(SQLiteStore(app_config.database_path, backup_dir=app_config.backup_dir),
                           clock=lambda: moment[0], pending_seconds=10)
    service.initialize()
    created = service.create_agent("expiry-blocked")
    transition(service, created.agent.id, "block")
    before = rows(service, "agent_credentials")
    moment[0] += timedelta(seconds=11)
    assert service.authenticate(created.api_key) is None
    assert rows(service, "agent_credentials") == before
    transition(service, created.agent.id, "unblock")
    assert service.verify_credential(created.api_key) is None
    assert service.get_credential(created.agent.name, created.issued_credential.credential.id).status == "expired"


def test_retire_is_terminal_with_reserved_name_and_audit_without_live_keys(agent_service):
    created = agent_service.create_agent("retired-copilot")
    agent_service.revoke_credential(
        created.agent.name, created.issued_credential.credential.id, request_id=request_id(),
        expected_credential_epoch=1, expected_credential_version=0, reason="remove last key",
    )
    terminal = rows(agent_service, "agent_credentials")
    event = transition(agent_service, created.agent.id, "retire").event
    assert event.previous_epoch == 2 and event.resulting_epoch == 3
    assert rows(agent_service, "agent_credentials") == terminal
    assert agent_service.store.get_managed_agent(created.agent.id).state == "retired"
    with pytest.raises(CredentialConflictError):
        agent_service.transition_agent(
            created.agent.id, action="unblock", expected_credential_epoch=3,
            request_id=request_id(), reason="must not resurrect", actor=operator(),
        )
    with pytest.raises(AgentNotFoundError):
        agent_service.recover_agent(
            created.agent.name, request_id=request_id(),
            expected_credential_epoch=3, reason="must not resurrect",
        )
    board = board_for(agent_service)
    sender = agent_service.create_agent("retirement-sender")
    with pytest.raises(UnknownMentionError):
        board.create_message("status", agent_id=sender.agent.id, body="@retired-copilot",
                             kind="chat", reply_to=None, metadata={})


def test_exact_lifecycle_replay_and_stale_or_changed_intent(agent_service):
    created = agent_service.create_agent("cas-copilot")
    intent = dict(action="block", expected_credential_epoch=1, request_id=request_id(),
                  reason="containment", actor=operator())
    first = agent_service.transition_agent(created.agent.id, **intent)
    transition(agent_service, created.agent.id, "unblock")
    replay = agent_service.transition_agent(created.agent.id, **intent)
    assert replay.event == first.event and not replay.changed
    assert agent_service.get_active_agent(created.agent.id).state == "enabled"
    for changes in (
        {"reason": "changed"}, {"actor": operator()}, {"expected_credential_epoch": 3},
        {"action": "retire"},
    ):
        with pytest.raises(CredentialConflictError):
            agent_service.transition_agent(created.agent.id, **(intent | changes))
    with pytest.raises(CredentialConflictError):
        agent_service.transition_agent(created.agent.id, **(intent | {"request_id": request_id()}))


@pytest.mark.parametrize("reason", ["", " trim", "x" * 257, "x\nx", "x\x00x", "x\x7fx", "x\u202ex"])
def test_reasons_fail_before_any_mutation(agent_service, reason):
    created = agent_service.create_agent("limits-copilot")
    with pytest.raises((ConfigurationError, DomainValidationError)):
        agent_service.transition_agent(
            created.agent.id, action="block", expected_credential_epoch=1,
            request_id=request_id(), reason=reason, actor=operator(),
        )
    assert agent_service.get_active_agent(created.agent.id).credential_epoch == 1
    assert rows(agent_service, "agent_lifecycle_audit") == []


@pytest.mark.parametrize("statement", [
    "UPDATE agents SET blocked_at = '2026-09-01T00:00:00Z'",
    "UPDATE agents SET credential_epoch = credential_epoch - 1",
    "UPDATE agents SET name = 'new-name'",
    "DELETE FROM agents",
    "UPDATE agent_lifecycle_audit SET reason = 'changed'",
    "DELETE FROM agent_lifecycle_audit",
])
def test_database_guards_lifecycle_and_immutable_audit(agent_service, statement):
    created = agent_service.create_agent("guard-copilot")
    transition(agent_service, created.agent.id, "block")
    with sqlite3.connect(agent_service.store.database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement)


def test_block_first_waiting_writer_denied_and_writer_first_commits(agent_service, monkeypatch):
    created = agent_service.create_agent("race-copilot")
    board = board_for(agent_service)
    entered, release = Event(), Event()
    original = store_common._record_lifecycle_event

    def hold_block(*args, **kwargs):
        event = original(*args, **kwargs)
        if kwargs["action"] == "block":
            entered.set()
            assert release.wait(5)
        return event

    for module in (store_common, store_lifecycle):
        monkeypatch.setattr(module, "_record_lifecycle_event", hold_block)
    with ThreadPoolExecutor(max_workers=2) as executor:
        blocked = executor.submit(transition, agent_service, created.agent.id, "block")
        assert entered.wait(5)
        waiting = executor.submit(
            board.create_message, "status", agent_id=created.agent.id, body="too late",
            kind="chat", reply_to=None, metadata={},
        )
        release.set()
        blocked.result(timeout=5)
        with pytest.raises(AgentNotFoundError):
            waiting.result(timeout=5)
    transition(agent_service, created.agent.id, "unblock")
    for module in (store_common, store_lifecycle):
        monkeypatch.setattr(module, "_record_lifecycle_event", original)
    entered.clear()
    release.clear()
    original_check = store_common._require_active_agent

    def hold_writer(connection, agent_id):
        original_check(connection, agent_id)
        if agent_id == created.agent.id:
            entered.set()
            assert release.wait(5)

    for module in (store_roe, store_messages, store_task_claims):
        monkeypatch.setattr(module, "_require_active_agent", hold_writer)
    with ThreadPoolExecutor(max_workers=2) as executor:
        written = executor.submit(
            board.create_message, "status", agent_id=created.agent.id, body="won lock",
            kind="chat", reply_to=None, metadata={},
        )
        assert entered.wait(5)
        blocked = executor.submit(transition, agent_service, created.agent.id, "block")
        release.set()
        assert written.result(timeout=5).body == "won lock"
        blocked.result(timeout=5)
    assert len(rows(agent_service, "messages")) == 1


@pytest.mark.parametrize("active", [False, True])
def test_authentication_rechecks_block_before_fast_path_or_telemetry(agent_service, monkeypatch, active):
    created = agent_service.create_agent("auth-race")
    if active:
        activate(agent_service, created)
    before = rows(agent_service, "agent_credentials")
    original = store_common._credential_auth_row
    calls = []

    def block_after_verifier_read(*args, **kwargs):
        row = original(*args, **kwargs)
        if not calls:
            calls.append(1)
            transition(agent_service, created.agent.id, "block")
        return row

    monkeypatch.setattr(store_credentials, "_credential_auth_row", block_after_verifier_read)
    assert agent_service.authenticate(created.api_key) is None
    assert rows(agent_service, "agent_credentials") == before


@pytest.mark.parametrize("include_stale", [False, True])
def test_unexpired_drain_resumes_after_unblock_without_epoch_binding(agent_service, include_stale):
    created = agent_service.create_agent("drain-blocked")
    active = activate(agent_service, created)
    board = board_for(agent_service)
    board.subscribe("status", agent_id=active.id)
    for index in range(3):
        board.create_message("status", agent_id=active.id, body=str(index),
                             kind="chat", reply_to=None, metadata={})
    first = board.catch_up_page(agent_id=active.id, start_drain=True, limit=1,
                                include_stale=include_stale)
    before = rows(agent_service, "cursors"), rows(agent_service, "mention_cursors")
    transition(agent_service, active.id, "block")
    with pytest.raises(AgentNotFoundError):
        board.catch_up_page(agent_id=active.id, continuation=first.continuation,
                            limit=1, include_stale=include_stale)
    assert (rows(agent_service, "cursors"), rows(agent_service, "mention_cursors")) == before
    transition(agent_service, active.id, "unblock")
    second = board.catch_up_page(agent_id=active.id, continuation=first.continuation,
                                 limit=1, include_stale=include_stale)
    assert second.snapshot_seq == first.snapshot_seq
    assert second.messages[0].seq == first.messages[0].seq + 1


def test_operator_context_rechecks_historical_reads_and_freeze(agent_service):
    created = agent_service.create_agent("read-boundary")
    valid = [True]

    def check():
        if not valid[0]:
            raise CredentialNotFoundError("session unavailable")

    token = agent_service.store.begin_operator_operation(operator(check))
    valid[0] = False
    try:
        with pytest.raises(CredentialNotFoundError):
            agent_service.store.list_managed_agents(state="all")
    finally:
        agent_service.store.end_operator_operation(token)
    valid[0] = True
    agent_service.store.set_access_freeze(frozen=True, reason="contain", changed_at=datetime.now(UTC))
    token = agent_service.store.begin_operator_operation(operator(check))
    try:
        # A freeze stops the agent plane, not the operator inspecting it. Reads
        # under an operator context now succeed, because blacking them out
        # meant the freeze prevented the very investigation and revocation it
        # exists to enable.
        assert agent_service.store.get_active_agent(created.agent.id).id == created.agent.id
        # Creating access stays refused for every actor that is not the
        # protected local CLI.
        with pytest.raises(AgentAccessFrozenError):
            agent_service.store.create_enrollment(
                enrollment_id=str(uuid.uuid4()),
                secret_hash="c" * 64,
                name_prefix="frozen-probe",
                name_match="exact",
                description="",
                uses_allowed=1,
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                actor_type="local-admin",
                actor_id="cli",
                creation_reason="frozen probe",
                require_access=True,
            )
    finally:
        agent_service.store.end_operator_operation(token)


def test_dashboard_counts_distinguish_enabled_blocked_retired(agent_service):
    board = board_for(agent_service)
    enabled = agent_service.create_agent("enabled-copilot")
    blocked = agent_service.create_agent("blocked-copilot")
    retired = agent_service.create_agent("retired-copilot")
    for agent in (enabled, blocked, retired):
        board.subscribe("status", agent_id=agent.agent.id)
    transition(agent_service, blocked.agent.id, "block")
    transition(agent_service, retired.agent.id, "retire")
    snapshot = agent_service.store.dashboard_snapshot(
        channel_name=None, agent_name=None, before=None, limit=10,
    )
    assert snapshot.counts.enabled_agents == 1
    assert snapshot.counts.blocked_agents == 1
    assert snapshot.counts.retired_agents == 1
    assert snapshot.counts.subscriptions == 1


def test_local_managed_roster_pages_include_blocked_targets_while_frozen(agent_service):
    enabled = agent_service.create_agent("enabled-local")
    blocked = agent_service.create_agent("blocked-local")
    retired = agent_service.create_agent("retired-local")
    transition(agent_service, blocked.agent.id, "block")
    transition(agent_service, retired.agent.id, "retire")
    agent_service.store.set_access_freeze(
        frozen=True, reason="protected local recovery", changed_at=datetime.now(UTC),
    )
    first = agent_service.list_managed_agents(limit=1, require_access=False)
    assert [a.id for a in first] == [blocked.agent.id]
    second = agent_service.list_managed_agents(
        limit=1, after_name=first[-1].name, require_access=False,
    )
    assert [a.id for a in second] == [enabled.agent.id]
    assert agent_service.list_managed_agents(
        limit=1, after_name=second[-1].name, require_access=False,
    ) == ()
    assert agent_service.get_managed_agent(blocked.agent.id, require_access=False).state == "blocked"
    assert len(agent_service.list_managed_agents(state="all", require_access=False)) == 3
    with pytest.raises(AgentAccessFrozenError):
        agent_service.list_managed_agents()
    with pytest.raises(AgentAccessFrozenError):
        agent_service.store.list_enabled_agents()


@pytest.mark.parametrize("actor_type", ["local-admin", "remote-admin"])
def test_frozen_unblock_is_denied_inside_transaction_without_any_lifecycle_side_effect(
    agent_service, actor_type,
):
    created = agent_service.create_agent("frozen-unblock")
    transition(agent_service, created.agent.id, "block")
    blocked = agent_service.get_managed_agent(created.agent.id)
    intent = {
        "action": "unblock", "expected_credential_epoch": blocked.credential_epoch,
        "request_id": request_id(), "reason": "restore after operator review",
        "actor": LifecycleActor(actor_type, "test-operator", lambda: None),
    }
    agent_service.store.set_access_freeze(
        frozen=True, reason="containment", changed_at=datetime.now(UTC),
    )
    tables = ("agents", "agent_credentials", "agent_credential_audit", "agent_lifecycle_audit")
    before = {table: rows(agent_service, table) for table in tables}
    with pytest.raises(AgentAccessFrozenError):
        agent_service.transition_agent(created.agent.id, **intent)
    assert {table: rows(agent_service, table) for table in tables} == before
    agent_service.store.set_access_freeze(
        frozen=False, reason="protected clearance", changed_at=datetime.now(UTC),
    )
    accepted = agent_service.transition_agent(created.agent.id, **intent)
    assert accepted.changed and accepted.event.resulting_state == "enabled"
    agent_service.store.set_access_freeze(
        frozen=True, reason="new containment", changed_at=datetime.now(UTC),
    )
    before = {table: rows(agent_service, table) for table in tables}
    with pytest.raises(AgentAccessFrozenError):
        agent_service.transition_agent(created.agent.id, **intent)
    assert {table: rows(agent_service, table) for table in tables} == before


@pytest.mark.parametrize("actor_type", ["local-admin", "remote-admin"])
@pytest.mark.parametrize("action", ["block", "retire"])
def test_frozen_operator_containment_remains_available(agent_service, actor_type, action):
    created = agent_service.create_agent("frozen-containment")
    agent_service.store.set_access_freeze(
        frozen=True, reason="containment", changed_at=datetime.now(UTC),
    )
    result = agent_service.transition_agent(
        created.agent.id, action=action,
        expected_credential_epoch=created.agent.credential_epoch,
        request_id=request_id(), reason="contain compromised identity",
        actor=LifecycleActor(actor_type, "test-operator", lambda: None),
    )
    assert result.changed
    assert agent_service.get_managed_agent(created.agent.id, require_access=False).state == (
        "blocked" if action == "block" else "retired"
    )
    assert agent_service.store.get_access_freeze().frozen


@pytest.mark.parametrize("actor_type", ["agent", "system"])
def test_nonhuman_lifecycle_actor_never_bypasses_freeze_gate(agent_service, actor_type):
    created = agent_service.create_agent("untrusted-unblock")
    transition(agent_service, created.agent.id, "block")
    blocked = agent_service.get_managed_agent(created.agent.id)
    agent_service.store.set_access_freeze(
        frozen=True, reason="containment", changed_at=datetime.now(UTC),
    )
    before = rows(agent_service, "agents"), rows(agent_service, "agent_lifecycle_audit")
    with pytest.raises(DomainValidationError, match="trusted human context"):
        agent_service.transition_agent(
            created.agent.id, action="unblock",
            expected_credential_epoch=blocked.credential_epoch,
            request_id=request_id(), reason="untrusted restoration",
            actor=LifecycleActor(actor_type, "untrusted", lambda: None),
        )
    assert (rows(agent_service, "agents"), rows(agent_service, "agent_lifecycle_audit")) == before


@pytest.mark.parametrize("missing_agent,error", [
    (False, DomainValidationError), (True, AgentNotFoundError),
])
def test_transition_rejects_unknown_action_or_identity_without_writes(
    agent_service, missing_agent, error,
):
    created = agent_service.create_agent("transition-boundary")
    before = rows(agent_service, "agents"), rows(agent_service, "agent_lifecycle_audit")
    with pytest.raises(error):
        agent_service.transition_agent(
            request_id() if missing_agent else created.agent.id,
            action="block" if missing_agent else "unknown",
            expected_credential_epoch=created.agent.credential_epoch,
            request_id=request_id(), reason="invalid transition probe", actor=operator(),
        )
    assert (rows(agent_service, "agents"), rows(agent_service, "agent_lifecycle_audit")) == before
