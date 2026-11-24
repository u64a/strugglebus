from __future__ import annotations

import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

import strugglebus.auth as auth_module
import strugglebus.store._common as store_common
import strugglebus.store._lifecycle as store_lifecycle
from strugglebus.auth import (
    AgentService, mint_credential, mint_enrollment_token, mint_reconnect_token,
    parse_credential, parse_enrollment_token, parse_reconnect_token,
)
from strugglebus.errors import (
    AgentAccessFrozenError, ConfigurationError, CredentialConflictError,
    CredentialLimitError, CredentialNotFoundError, DomainValidationError, StorageError,
)
from strugglebus.models import LifecycleActor
from strugglebus.operator_auth import (
    OperatorAuth, OperatorAuthError, OperatorContext, PasswordVerifier, create_password_verifier,
)
from strugglebus.store import SQLiteStore


def rid():
    return str(uuid.uuid4())


def actor(check=lambda: None):
    return LifecycleActor("remote-admin", f"operator:owner:{rid()}", check)


@pytest.fixture
def service(app_config):
    moment = [datetime.now(UTC)]
    service = AgentService(
        SQLiteStore(app_config.database_path, backup_dir=app_config.backup_dir),
        clock=lambda: moment[0],
    )
    service.initialize()
    return service, moment


def issue(service, created, **kwargs):
    current = service.get_active_agent(created.agent.id)
    defaults = dict(
        expected_agent_name=current.name, expected_credential_epoch=current.credential_epoch,
        request_id=rid(), reason="move to replacement computer", actor=actor(),
    )
    return service.issue_reconnect(current.id, **(defaults | kwargs))


def redeem(service, created, grant, **kwargs):
    return service.redeem_reconnect(
        grant.token, **(dict(expected_agent_id=created.agent.id,
                            expected_agent_name=created.agent.name, request_id=rid()) | kwargs),
    )


def query(service, sql, params=()):
    with sqlite3.connect(service.store.database_path) as connection:
        return connection.execute(sql, params).fetchall()


def prove(service, secret):
    identity = service.verify_credential(secret)
    service.prove(
        identity, request_id=rid(), expected_agent_id=identity.id, expected_agent_name=identity.name,
        expected_credential_epoch=identity.agent.credential_epoch,
        expected_credential_version=identity.credential.version,
    )
    return service.authenticate(secret)


def test_cutoff_every_live_key_redemption_is_independent_pending_and_preserves_identity(service, monkeypatch):
    service, moment = service
    created = service.create_agent("move-copilot", description="preserved", host="original")
    active = prove(service, created.api_key)
    rotated = service.rotate(
        active, request_id=rid(), expected_agent_id=active.id,
        expected_credential_id=active.credential.id,
        expected_credential_epoch=active.agent.credential_epoch,
    )
    before = service.get_active_agent(active.id)
    grant = issue(service, created)
    assert grant.grant.bound_epoch == before.credential_epoch + 1
    assert service.authenticate(created.api_key) is None
    assert service.verify_credential(rotated.secret) is None
    assert query(service, "SELECT DISTINCT status FROM agent_credentials") == [("revoked",)]
    assert service.get_active_agent(active.id) == replace(before, credential_epoch=before.credential_epoch + 1)
    minted = mint_credential()
    monkeypatch.setattr(auth_module, "mint_credential", lambda: minted)
    result = redeem(service, created, grant)
    assert result.agent.id == before.id and result.agent.name == before.name
    assert result.agent.description == before.description and result.agent.host == before.host
    assert result.issued_credential.secret == minted[2]
    assert result.issued_credential.secret != grant.token
    assert result.issued_credential.credential.status == "pending"
    assert result.issued_credential.credential.pending_expires_at == moment[0] + timedelta(seconds=900)
    assert result.grant.result_credential_id == minted[0]
    assert result.grant.bound_epoch == result.agent.credential_epoch - 1
    assert service.verify_credential(minted[2]).credential.status == "pending"
    assert query(service, "SELECT COUNT(*) FROM roe_acknowledgements") == [(0,)]
    assert grant.token not in repr(grant) and minted[2] not in repr(result)
    assert query(service, "SELECT secret_hash FROM agent_reconnect_grants") == [
        (parse_reconnect_token(grant.token)[1],)
    ]
    assert all(grant.token not in str(row) and minted[2] not in str(row)
               for row in query(service, "SELECT * FROM agent_lifecycle_audit"))


def test_issue_replay_is_metadata_only_changed_intent_conflicts_and_replacement_correlates(service):
    service, _ = service
    created = service.create_agent("reissue-copilot")
    request, context = rid(), actor()
    first = issue(service, created, request_id=request, actor=context)
    retry = issue(service, created, request_id=request, actor=context, expected_credential_epoch=1)
    assert retry.token is None and retry.grant == first.grant
    with pytest.raises(CredentialConflictError):
        issue(service, created, request_id=request, actor=context,
              expected_credential_epoch=1, reason="different intent")
    replacement_request = rid()
    second = issue(service, created, request_id=replacement_request)
    assert service.verify_reconnect(first.token) is None
    assert service.verify_reconnect(second.token) is not None
    events = query(service,
                  "SELECT action FROM agent_lifecycle_audit WHERE request_id = ? ORDER BY seq",
                  (replacement_request,))
    assert events == [("reconnect-invalidate",), ("reconnect-issue",)]
    assert query(service, "SELECT status FROM agent_reconnect_grants ORDER BY rowid") == [
        ("revoked",), ("pending",),
    ]
    assert query(
        service,
        "SELECT credential_epoch FROM agents WHERE name NOT IN ('system:strugglebus-maintenance', 'human:operator')",
    ) == [(3,)]


@pytest.mark.parametrize("field,value", [
    ("expected_agent_id", "wrong-id"), ("expected_agent_name", "wrong-name"),
    ("expected_agent_name", "MOVE-COPILOT"),
])
def test_pinned_identity_mismatch_consumes_nothing(service, field, value):
    service, _ = service
    created = service.create_agent("move-copilot")
    grant = issue(service, created)
    with pytest.raises(CredentialNotFoundError):
        redeem(service, created, grant, **{field: value})
    assert service.verify_reconnect(grant.token) is not None
    assert query(service, "SELECT COUNT(*) FROM agent_credentials") == [(1,)]


def test_token_kinds_domains_canonical_parsing_and_unknown_dummy_verifier(service, monkeypatch):
    service, _ = service
    grant_id, digest, token = mint_reconnect_token()
    assert parse_reconnect_token(token) == (grant_id, digest)
    assert parse_credential(token) is None and parse_enrollment_token(token) is None
    for foreign in (mint_credential()[2], mint_enrollment_token()[2], "legacy-key",
                    token + "=", token.replace("sbr1_", "sbr2_"), "x" * 257, None):
        assert parse_reconnect_token(foreign) is None
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    replacement = alphabet[alphabet.index(token[-1]) + 1]
    assert parse_reconnect_token(token[:-1] + replacement) is None
    compared = []
    original = store_lifecycle.hmac.compare_digest

    def compare(a, b):
        compared.append((a, b))
        return original(a, b)

    monkeypatch.setattr(store_lifecycle.hmac, "compare_digest", compare)
    assert service.verify_reconnect(token) is None
    assert compared == [(digest, "0" * 64)]


@pytest.mark.parametrize("invalid", ["blocked", "retired", "stale", "capacity", "session", "frozen"])
def test_preflight_failure_revokes_zero_credentials(service, invalid):
    service, moment = service
    created = service.create_agent("preflight-copilot")
    context = actor()
    if invalid in {"blocked", "retired"}:
        service.transition_agent(
            created.agent.id, action="block" if invalid == "blocked" else "retire",
            request_id=rid(), expected_credential_epoch=1, reason="contain",
            actor=context,
        )
    elif invalid == "capacity":
        service.max_outstanding_reconnect_grants = 1
        issue(service, service.create_agent("capacity-copilot"))
    elif invalid == "frozen":
        service.store.set_access_freeze(frozen=True, reason="contain", changed_at=moment[0])
    elif invalid == "session":
        calls = []

        def check():
            calls.append(1)
            if len(calls) == 2:
                raise CredentialNotFoundError("operator session is unavailable")

        context = actor(check)
    before = query(service, "SELECT * FROM agent_credentials")
    grants = query(service, "SELECT * FROM agent_reconnect_grants")
    with pytest.raises((CredentialConflictError, CredentialNotFoundError, CredentialLimitError,
                        AgentAccessFrozenError)):
        service.issue_reconnect(
            created.agent.id, expected_agent_name=created.agent.name,
            expected_credential_epoch=99 if invalid == "stale" else (
                2 if invalid in {"blocked", "retired"} else 1),
            request_id=rid(), reason="move", actor=context,
        )
    assert query(service, "SELECT * FROM agent_credentials") == before
    assert query(service, "SELECT * FROM agent_reconnect_grants") == grants


def test_exactly_once_redemption_and_lost_response_require_explicit_reissue(service):
    service, _ = service
    created = service.create_agent("once-copilot")
    grant = issue(service, created)
    request = rid()

    def attempt():
        try:
            return redeem(service, created, grant, request_id=request)
        except CredentialNotFoundError:
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: attempt(), range(4)))
    successes = [r for r in results if r is not None]
    assert len(successes) == 1
    with pytest.raises(CredentialNotFoundError):
        redeem(service, created, grant, request_id=request)
    assert query(service, "SELECT COUNT(*) FROM agent_credentials") == [(2,)]
    replacement = issue(service, created)
    assert service.verify_credential(successes[0].issued_credential.secret) is None
    assert redeem(service, created, replacement).issued_credential.secret is not None


@pytest.mark.parametrize("action", ["block", "retire", "issue", "recover"])
def test_later_epoch_change_invalidates_grant_including_local_human_recovery(service, action):
    service, moment = service
    created = service.create_agent("epoch-copilot")
    grant = issue(service, created)
    if action in {"block", "retire"}:
        service.transition_agent(
            created.agent.id, action=action, expected_credential_epoch=2,
            request_id=rid(), reason="new decision", actor=actor(),
        )
    else:
        service.store.set_access_freeze(frozen=True, reason="local recovery", changed_at=moment[0])
        operation = service.issue_for_agent if action == "issue" else service.recover_agent
        operation(created.agent.name, expected_credential_epoch=2, request_id=rid(),
                  reason="local recovery", actor_type="local-admin", actor_id="local-admin")
        service.store.set_access_freeze(frozen=False, reason="local clearance", changed_at=moment[0])
    assert service.verify_reconnect(grant.token) is None
    assert service.store.get_reconnect_grant(created.agent.id, grant.grant.id).status == "revoked"
    if action == "block":
        service.transition_agent(
            created.agent.id, action="unblock", expected_credential_epoch=3,
            request_id=rid(), reason="cleared", actor=actor(),
        )
        assert service.verify_reconnect(grant.token) is None


def test_actual_expiry_is_terminal_audited_without_epoch_change_and_thaw_does_not_extend(service):
    service, moment = service
    created = service.create_agent("expiry-copilot")
    first = issue(service, created)
    service.store.set_access_freeze(frozen=True, reason="freeze", changed_at=moment[0])
    moment[0] += timedelta(seconds=899)
    with pytest.raises(AgentAccessFrozenError):
        redeem(service, created, first)
    service.store.set_access_freeze(frozen=False, reason="thaw", changed_at=moment[0])
    assert service.verify_reconnect(first.token) is not None
    moment[0] += timedelta(seconds=1)
    with pytest.raises(CredentialNotFoundError):
        redeem(service, created, first)
    assert service.get_active_agent(created.agent.id).credential_epoch == 2
    assert service.store.get_reconnect_grant(created.agent.id, first.grant.id).status == "expired"
    assert query(service, "SELECT action FROM agent_lifecycle_audit ORDER BY seq") == [
        ("reconnect-issue",), ("reconnect-expire",),
    ]
    assert service.verify_reconnect(first.token) is None
    assert len(query(service, "SELECT * FROM agent_lifecycle_audit")) == 2


def test_redeem_transaction_rechecks_time_after_waiting_for_writer(service):
    service, moment = service
    created = service.create_agent("time-race")
    grant = issue(service, created)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with service.store._transaction():
            future = executor.submit(redeem, service, created, grant)
            moment[0] += timedelta(seconds=901)
        with pytest.raises(CredentialNotFoundError):
            future.result(timeout=5)
    assert query(service, "SELECT COUNT(*) FROM agent_credentials") == [(1,)]
    assert service.store.get_reconnect_grant(created.agent.id, grant.grant.id).status == "expired"


def test_prepared_package_expiry_and_metadata_replay_are_safe(service):
    service, moment = service
    created = service.create_agent("package-copilot")
    prepared = service.prepare_reconnect_grant()
    request, context = rid(), actor()
    first = issue(service, created, prepared=prepared, request_id=request, actor=context)
    moment[0] += timedelta(seconds=901)
    replay = issue(service, created, prepared=prepared, request_id=request, actor=context,
                   expected_credential_epoch=1)
    assert replay.token is None and replay.grant.id == first.grant.id
    before = query(service, "SELECT * FROM agent_credentials")
    with pytest.raises(CredentialConflictError):
        issue(service, created, prepared=prepared)
    assert query(service, "SELECT * FROM agent_credentials") == before


def test_transaction_rollback_on_audit_failure_preserves_cutoff_and_redemption(service):
    service, _ = service
    created = service.create_agent("rollback-copilot")
    with sqlite3.connect(service.store.database_path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_issue BEFORE INSERT ON agent_lifecycle_audit "
            "WHEN new.action = 'reconnect-issue' BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
    with pytest.raises(StorageError):
        issue(service, created)
    assert service.verify_credential(created.api_key) is not None
    assert query(service, "SELECT COUNT(*) FROM agent_reconnect_grants") == [(0,)]
    with sqlite3.connect(service.store.database_path) as connection:
        connection.execute("DROP TRIGGER fail_issue")
    grant = issue(service, created)
    with sqlite3.connect(service.store.database_path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_redeem BEFORE INSERT ON agent_lifecycle_audit "
            "WHEN new.action = 'reconnect-redeem' BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
    with pytest.raises(StorageError):
        redeem(service, created, grant)
    assert service.verify_reconnect(grant.token) is not None
    assert query(service, "SELECT COUNT(*) FROM agent_credentials") == [(1,)]
    assert service.get_active_agent(created.agent.id).credential_epoch == 2


@pytest.mark.parametrize("statement", [
    "UPDATE agent_reconnect_grants SET secret_hash = printf('%064d', 0)",
    "UPDATE agent_reconnect_grants SET bound_epoch = bound_epoch + 1",
    "UPDATE agent_reconnect_grants SET expires_at = '2099-01-01'",
    "UPDATE agent_reconnect_grants SET status = 'redeemed', version = 1",
    "UPDATE agents SET credential_epoch = credential_epoch + 1",
    "DELETE FROM agent_reconnect_grants",
])
def test_grant_database_guards(agent_service, statement):
    created = agent_service.create_agent("immutable-copilot")
    issue(agent_service, created)
    with sqlite3.connect(agent_service.store.database_path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement)


@pytest.mark.parametrize("context", [
    LifecycleActor("agent", "credential"),
    LifecycleActor("local-admin", "operator:owner:" + str(uuid.uuid4())),
    LifecycleActor("remote-admin", "admin"),
    LifecycleActor("remote-admin", "operator:owner:" + str(uuid.uuid4())),
])
def test_operator_context_cannot_be_replaced_by_actor_strings(service, context):
    service, _ = service
    created = service.create_agent("actor-copilot")
    with pytest.raises(DomainValidationError):
        issue(service, created, actor=context)
    assert service.verify_credential(created.api_key) is not None


def test_operator_enrollment_requires_session_and_transaction_revalidation(agent_service, monkeypatch):
    calls = []
    transaction = [False]
    original = agent_service.store._transaction

    @contextmanager
    def observe_transaction():
        with original() as connection:
            transaction[0] = connection.in_transaction
            try:
                yield connection
            finally:
                transaction[0] = False

    monkeypatch.setattr(agent_service.store, "_transaction", observe_transaction)
    context = OperatorContext(f"operator:owner:{rid()}", 1000.0, "fixture", "fixture")

    def check():
        calls.append(1)
        if len(calls) > 1:
            assert transaction[0]
            raise OperatorAuthError("session expired")

    with pytest.raises(OperatorAuthError):
        agent_service.create_dashboard_enrollment(
            name="new-copilot", operator=context, authorize=check,
        )
    assert query(agent_service, "SELECT COUNT(*) FROM agent_enrollments") == [(0,)]
    issued = agent_service.create_dashboard_enrollment(
        name="new-copilot", operator=context, authorize=lambda: None,
    )
    assert issued.enrollment.actor_type == "remote-admin"
    assert issued.enrollment.actor_id == context.actor_id


async def test_registry_logout_between_enrollment_checks_rolls_back(
    agent_service, app_config, monkeypatch,
):
    secret = "synthetic enrollment owner password"
    authority = OperatorAuth(
        app_config, PasswordVerifier.parse(create_password_verifier(secret)),
    )
    try:
        challenge, csrf = authority.challenge("fixture")
        _, operator = await authority.login(
            source="fixture", challenge=challenge, csrf=csrf,
            password=secret, guard=lambda: None,
        )
        enrolled = agent_service.create_dashboard_enrollment(
            name="first-copilot", operator=operator,
            authorize=lambda: authority.require_active(operator),
        )
        assert enrolled.enrollment.actor_id == operator.actor_id
        created = agent_service.create_agent("registry-copilot")
        grant = issue(
            agent_service, created,
            actor=LifecycleActor(
                "remote-admin", operator.actor_id, lambda: authority.require_active(operator),
            ),
        )
        assert grant.grant.actor_id == operator.actor_id
        original = agent_service.store._transaction

        @contextmanager
        def log_out_after_lock():
            with original() as connection:
                authority.logout(operator)
                yield connection

        monkeypatch.setattr(agent_service.store, "_transaction", log_out_after_lock)
        with pytest.raises(OperatorAuthError):
            agent_service.create_dashboard_enrollment(
                name="new-copilot", operator=operator,
                authorize=lambda: authority.require_active(operator),
            )
        assert query(agent_service, "SELECT COUNT(*) FROM agent_enrollments") == [(1,)]
    finally:
        authority.close()


def test_generic_operator_enrollment_cannot_omit_guard_or_freeze_check(agent_service):
    identity = f"operator:owner:{rid()}"
    with pytest.raises(DomainValidationError):
        agent_service.create_enrollment(
            name_prefix="new-copilot", actor_type="remote-admin", actor_id=identity,
        )
    agent_service.store.set_access_freeze(
        frozen=True, reason="freeze fixture", changed_at=datetime.now(UTC),
    )
    with pytest.raises(AgentAccessFrozenError):
        agent_service.create_enrollment(
            name_prefix="new-copilot", actor_type="remote-admin", actor_id=identity,
            authorize=lambda: None,
        )
    assert query(agent_service, "SELECT COUNT(*) FROM agent_enrollments") == [(0,)]
    assert agent_service.create_enrollment(name_prefix="local-copilot").token is not None


@pytest.mark.parametrize("containment", ["block", "retire", "recover", "freeze"])
def test_containment_first_denies_redemption_without_new_key(service, containment):
    service, moment = service
    created = service.create_agent("contained-redemption")
    grant = issue(service, created)
    assert service.verify_reconnect(grant.token) is not None
    if containment in {"block", "retire"}:
        service.transition_agent(
            created.agent.id, action=containment, expected_credential_epoch=2,
            request_id=rid(), reason="contain", actor=actor(),
        )
    elif containment == "recover":
        service.recover_agent(created.agent.name, expected_credential_epoch=2,
                              request_id=rid(), reason="human repair")
    else:
        service.store.set_access_freeze(frozen=True, reason="contain", changed_at=moment[0])
    before = query(service, "SELECT * FROM agent_credentials")
    with pytest.raises((CredentialNotFoundError, AgentAccessFrozenError)):
        redeem(service, created, grant)
    assert query(service, "SELECT * FROM agent_credentials") == before


@pytest.mark.parametrize("action", ["block", "retire", "recover"])
def test_redemption_first_then_containment_contains_new_pending_credential(service, action):
    service, _ = service
    created = service.create_agent("redeem-first")
    grant = issue(service, created)
    result = redeem(service, created, grant)
    if action in {"block", "retire"}:
        service.transition_agent(
            created.agent.id, action=action, expected_credential_epoch=3,
            request_id=rid(), reason="contain new key", actor=actor(),
        )
    else:
        service.recover_agent(created.agent.name, expected_credential_epoch=3,
                              request_id=rid(), reason="human repair")
    assert service.verify_credential(result.issued_credential.secret) is None
    assert service.store.get_reconnect_grant(created.agent.id, grant.grant.id).status == "redeemed"


def test_cutoff_blocks_old_pre_authenticated_writer_without_advancing_cursors(agent_service, monkeypatch):
    from test_agent_lifecycle import board_for

    created = agent_service.create_agent("cutoff-writer")
    active = prove(agent_service, created.api_key)
    board = board_for(agent_service)
    entered, release = Event(), Event()
    original = store_common._record_lifecycle_event

    def hold_cutoff(*args, **kwargs):
        result = original(*args, **kwargs)
        if kwargs["action"] == "reconnect-issue":
            entered.set()
            assert release.wait(5)
        return result

    def write():
        token = agent_service.store.begin_roe_operation(active.id, active.credential.id, require_receipt=False)
        try:
            return board.catch_up(agent_id=active.id)
        finally:
            agent_service.store.end_roe_operation(token)

    for module in (store_common, store_lifecycle):
        monkeypatch.setattr(module, "_record_lifecycle_event", hold_cutoff)
    before = query(agent_service, "SELECT * FROM cursors")
    with ThreadPoolExecutor(max_workers=2) as executor:
        cutoff = executor.submit(issue, agent_service, created)
        assert entered.wait(5)
        waiting = executor.submit(write)
        release.set()
        cutoff.result(timeout=5)
        with pytest.raises(CredentialNotFoundError):
            waiting.result(timeout=5)
    assert query(agent_service, "SELECT * FROM cursors") == before


def test_reconnect_preserves_drain_and_rejects_old_rotation_replay(agent_service):
    from test_agent_lifecycle import board_for

    created = agent_service.create_agent("move-drain")
    active = prove(agent_service, created.api_key)
    board = board_for(agent_service)
    board.subscribe("status", agent_id=active.id)
    for index in range(3):
        board.create_message("status", agent_id=active.id, body=str(index),
                             kind="chat", reply_to=None, metadata={})
    first = board.catch_up_page(agent_id=active.id, limit=1, start_drain=True)
    rotation_intent = dict(
        request_id=rid(), expected_agent_id=active.id, expected_credential_id=active.credential.id,
        expected_credential_epoch=active.agent.credential_epoch,
    )
    agent_service.rotate(active, **rotation_intent)
    before = {
        table: query(agent_service, f"SELECT * FROM {table}")
        for table in ("cursors", "mention_cursors", "subscriptions", "messages", "roe_acknowledgements")
    }
    grant = issue(agent_service, created)
    with pytest.raises(CredentialNotFoundError):
        agent_service.rotate(active, **rotation_intent)
    redeemed = redeem(agent_service, created, grant)
    assert {table: query(agent_service, f"SELECT * FROM {table}") for table in before} == before
    pending = redeemed.issued_credential
    token = agent_service.store.begin_roe_operation(active.id, pending.credential.id, require_receipt=False)
    try:
        with pytest.raises(CredentialNotFoundError):
            board.catch_up_page(agent_id=active.id, limit=1, continuation=first.continuation)
    finally:
        agent_service.store.end_roe_operation(token)
    prove(agent_service, pending.secret)
    token = agent_service.store.begin_roe_operation(active.id, pending.credential.id, require_receipt=False)
    try:
        next_page = board.catch_up_page(agent_id=active.id, limit=1, continuation=first.continuation)
    finally:
        agent_service.store.end_roe_operation(token)
    assert next_page.snapshot_seq == first.snapshot_seq
    assert next_page.messages[0].seq == first.messages[0].seq + 1


@pytest.mark.parametrize("value", [True, -1, 2**63, "1", None])
def test_invalid_epoch_fails_before_cutoff(service, value):
    service, _ = service
    created = service.create_agent("invalid-epoch")
    with pytest.raises(DomainValidationError):
        issue(service, created, expected_credential_epoch=value)
    assert service.verify_credential(created.api_key) is not None


@pytest.mark.parametrize("field,value", [
    ("request_id", None), ("request_id", "not-a-uuid"),
    ("expected_agent_name", "x" * 129), ("reason", "x\nx"),
])
def test_invalid_intent_fails_before_cutoff(service, field, value):
    service, _ = service
    created = service.create_agent("invalid-intent")
    with pytest.raises((ConfigurationError, DomainValidationError)):
        issue(service, created, **{field: value})
    assert service.verify_credential(created.api_key) is not None


def test_restored_current_snapshot_preserves_consumption_cutoff_and_block(service, tmp_path):
    service, moment = service
    created = service.create_agent("restore-copilot")
    grant = issue(service, created)
    result = redeem(service, created, grant)
    service.transition_agent(
        created.agent.id, action="block", expected_credential_epoch=3,
        request_id=rid(), reason="preserve containment", actor=actor(),
    )
    restored_path = tmp_path / "restored-twelve.db"
    with sqlite3.connect(service.store.database_path) as source:
        with sqlite3.connect(restored_path) as destination:
            source.backup(destination)
            assert destination.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    restored = AgentService(
        SQLiteStore(restored_path, backup_dir=tmp_path / "restored-backups"),
        clock=lambda: moment[0],
    )
    restored.initialize()
    assert restored.verify_credential(created.api_key) is None
    assert restored.verify_credential(result.issued_credential.secret) is None
    assert restored.verify_reconnect(grant.token) is None
    assert restored.get_active_agent(created.agent.id).state == "blocked"
    assert restored.get_active_agent(created.agent.id).credential_epoch == 4
    assert query(restored, "SELECT * FROM agent_lifecycle_audit") == query(
        service, "SELECT * FROM agent_lifecycle_audit",
    )
