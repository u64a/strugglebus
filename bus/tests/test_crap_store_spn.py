"""Service-principal persistence: idempotent requests, guards and containment."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from strugglebus.auth import (
    mint_credential,
    mint_spn_credential,
    mint_spn_enrollment_token,
)
from strugglebus.errors import (
    AgentNotFoundError,
    CredentialConflictError,
    CredentialNotFoundError,
    DomainValidationError,
    EnrollmentInvalidError,
    ServicePrincipalNotFoundError,
)
from strugglebus.models import LifecycleActor, ServicePrincipalIdentity
from strugglebus.store import SQLiteStore

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
_ACTOR = LifecycleActor("local-admin", "tester")


@pytest.fixture
def store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "strugglebus.db", backup_dir=tmp_path / "backups")
    store.initialize()
    return store


def _request_id() -> str:
    return str(uuid.uuid4())


def _create(
    store: SQLiteStore,
    *,
    name: str = "build-onboarder",
    prefix: str = "build",
    request_id: str | None = None,
):
    credential_id, verifier, _ = mint_spn_credential()
    principal, result_credential_id, created = store.create_service_principal(
        spn_id=str(uuid.uuid4()),
        name=name,
        agent_name_prefix=prefix,
        credential_id=credential_id,
        secret_hash=verifier,
        request_id=request_id or _request_id(),
        actor=_ACTOR,
        created_at=_NOW,
    )
    return principal, result_credential_id, created


def _identity(principal, credential_id: str) -> ServicePrincipalIdentity:
    return ServicePrincipalIdentity(
        spn_id=principal.id,
        spn_name=principal.name,
        agent_name_prefix=principal.agent_name_prefix,
        credential_id=credential_id,
        credential_kind="sbsp1",
    )


def _transition(store: SQLiteStore, spn_id: str, action: str, version: int, **overrides):
    return store.transition_service_principal(
        spn_id,
        action=action,
        expected_version=version,
        request_id=overrides.get("request_id") or _request_id(),
        reason=overrides.get("reason", "containment"),
        actor=_ACTOR,
        changed_at=overrides.get("changed_at", _NOW + timedelta(minutes=1)),
    )


def _rotate(store: SQLiteStore, spn_id: str, version: int, **overrides):
    credential_id, verifier, _ = mint_spn_credential()
    return store.rotate_service_principal_credential(
        spn_id,
        expected_version=version,
        credential_id=credential_id,
        secret_hash=verifier,
        request_id=overrides.get("request_id") or _request_id(),
        reason=overrides.get("reason", "scheduled rotation"),
        actor=_ACTOR,
        changed_at=_NOW + timedelta(minutes=2),
    )


def _issue(
    store: SQLiteStore,
    identity: ServicePrincipalIdentity,
    agent_name: str,
    *,
    identity_expires_at: datetime | None = None,
):
    enrollment_id, verifier, _ = mint_spn_enrollment_token()
    issuance, created = store.issue_spn_onboarding(
        identity=identity,
        request_id=_request_id(),
        intent_sha256=uuid.uuid4().hex * 2,
        enrollment_id=enrollment_id,
        secret_hash=verifier,
        agent_name=agent_name,
        description="",
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=5),
        max_outstanding=5,
        identity_expires_at=identity_expires_at,
    )
    assert created is True
    return issuance, verifier


def _redeem(store: SQLiteStore, issuance, verifier: str, *, at: datetime):
    credential_id, secret_hash, _ = mint_credential()
    return store.redeem_enrollment(
        enrollment_id=issuance.enrollment_id,
        candidate_digest=verifier,
        claimed_name=issuance.agent_name,
        description="",
        host="",
        agent_id=str(uuid.uuid4()),
        credential_id=credential_id,
        secret_hash=secret_hash,
        request_id=_request_id(),
        redeemed_at=at,
        pending_expires_at=at + timedelta(minutes=5),
    )


def _rows(store: SQLiteStore, query: str, *parameters: object) -> list[tuple]:
    with sqlite3.connect(store.database_path) as database:
        return database.execute(query, parameters).fetchall()


def test_create_replays_an_identical_request_without_a_second_principal(
    store: SQLiteStore,
) -> None:
    request_id = _request_id()
    principal, credential_id, created = _create(store, request_id=request_id)

    replayed, replayed_credential_id, replay_created = _create(store, request_id=request_id)

    assert (created, replay_created) == (True, False)
    assert replayed == principal
    assert replayed_credential_id == credential_id
    assert store.list_service_principals() == (principal,)
    assert _rows(store, "SELECT COUNT(*) FROM spn_credentials") == [(1,)]
    assert _rows(store, "SELECT event_type FROM spn_audit") == [("created",)]


def test_create_refuses_reused_request_ids_and_duplicate_names(store: SQLiteStore) -> None:
    request_id = _request_id()
    principal, _, _ = _create(store, request_id=request_id)

    with pytest.raises(CredentialConflictError, match="SPN request id is already in use"):
        _create(store, name="deploy-onboarder", prefix="deploy", request_id=request_id)
    with pytest.raises(CredentialConflictError, match="name is already registered"):
        _create(store, prefix="other")
    with pytest.raises(DomainValidationError, match="canonical UUID"):
        _create(store, name="third-onboarder", request_id=request_id.upper())
    with pytest.raises(DomainValidationError, match="trusted human context"):
        store.create_service_principal(
            spn_id=str(uuid.uuid4()), name="fourth-onboarder", agent_name_prefix="x",
            credential_id="unused", secret_hash="0" * 64, request_id=_request_id(),
            actor=LifecycleActor("agent", "tester"), created_at=_NOW,
        )

    assert store.list_service_principals() == (principal,)
    assert _rows(store, "SELECT COUNT(*) FROM spn_credentials") == [(1,)]


def test_transition_validates_action_target_and_expected_state(store: SQLiteStore) -> None:
    create_request = _request_id()
    principal, _, _ = _create(store, request_id=create_request)

    with pytest.raises(DomainValidationError, match="invalid SPN lifecycle action"):
        _transition(store, principal.id, "pause", principal.version)
    with pytest.raises(ServicePrincipalNotFoundError, match="does not exist"):
        _transition(store, str(uuid.uuid4()), "block", 1)
    # A request id that created a principal cannot later drive a transition.
    with pytest.raises(CredentialConflictError, match="SPN request id is already in use"):
        _transition(store, principal.id, "block", principal.version, request_id=create_request)
    with pytest.raises(CredentialConflictError, match="service principal state changed"):
        _transition(store, principal.id, "block", principal.version + 1)
    with pytest.raises(CredentialConflictError, match="service principal state changed"):
        _transition(store, principal.id, "unblock", principal.version)

    assert store.list_service_principals() == (principal,)
    assert _rows(store, "SELECT event_type FROM spn_audit") == [("created",)]


def test_block_unblock_and_revoke_move_through_the_allowed_states(
    store: SQLiteStore,
) -> None:
    principal, credential_id, _ = _create(store)

    blocked = _transition(store, principal.id, "block", principal.version)
    with pytest.raises(CredentialConflictError, match="service principal state changed"):
        _transition(store, principal.id, "block", blocked.version)
    unblocked = _transition(store, principal.id, "unblock", blocked.version)
    reblocked = _transition(store, principal.id, "block", unblocked.version)
    revoked = _transition(
        store, principal.id, "revoke", reblocked.version,
        changed_at=_NOW + timedelta(minutes=9),
    )
    with pytest.raises(CredentialConflictError, match="service principal state changed"):
        _transition(store, principal.id, "unblock", revoked.version)

    assert (blocked.status, blocked.blocked_at) == ("blocked", _NOW + timedelta(minutes=1))
    assert (unblocked.status, unblocked.blocked_at) == ("enabled", None)
    assert revoked.status == "revoked"
    assert revoked.revoked_at == _NOW + timedelta(minutes=9)
    # Revocation keeps the record of when it was last blocked.
    assert revoked.blocked_at == reblocked.blocked_at
    assert [version.version for version in (blocked, unblocked, reblocked, revoked)] == [
        principal.version + 1, principal.version + 2,
        principal.version + 3, principal.version + 4,
    ]
    assert _rows(
        store, "SELECT status FROM spn_credentials WHERE id = ?", credential_id,
    ) == [("revoked",)]
    assert [row[0] for row in _rows(store, "SELECT event_type FROM spn_audit ORDER BY seq")] == [
        "created", "blocked", "unblocked", "blocked", "revoked",
    ]


def test_transition_replay_returns_the_recorded_result_and_rejects_other_intent(
    store: SQLiteStore,
) -> None:
    principal, _, _ = _create(store)
    request_id = _request_id()
    blocked = _transition(store, principal.id, "block", principal.version, request_id=request_id)
    _transition(store, principal.id, "unblock", blocked.version)

    replayed = _transition(
        store, principal.id, "block", principal.version, request_id=request_id,
    )

    # The replay reports what the request did, not the principal's later state.
    assert replayed == blocked
    for action, version, reason in (
        ("revoke", principal.version, "containment"),
        ("block", principal.version + 5, "containment"),
        ("block", principal.version, "a different reason"),
    ):
        with pytest.raises(CredentialConflictError, match="SPN request id is already in use"):
            _transition(
                store, principal.id, action, version, request_id=request_id, reason=reason,
            )
    other, _, _ = _create(store, name="deploy-onboarder", prefix="deploy")
    with pytest.raises(CredentialConflictError, match="SPN request id is already in use"):
        _transition(store, other.id, "block", other.version, request_id=request_id)


def test_block_withdraws_unredeemed_packages_and_retires_time_limited_identities(
    store: SQLiteStore,
) -> None:
    principal, credential_id, _ = _create(store)
    identity = _identity(principal, credential_id)
    redeemed_issue, redeemed_verifier = _issue(
        store, identity, "build-temp", identity_expires_at=_NOW + timedelta(hours=1),
    )
    permanent_issue, permanent_verifier = _issue(store, identity, "build-keeper")
    outstanding_issue, outstanding_verifier = _issue(store, identity, "build-late")
    temporary, _ = _redeem(store, redeemed_issue, redeemed_verifier, at=_NOW)
    permanent, _ = _redeem(store, permanent_issue, permanent_verifier, at=_NOW)

    _transition(store, principal.id, "block", principal.version)

    assert store.get_managed_agent(temporary.id).revoked_at == _NOW + timedelta(minutes=1)
    assert store.get_managed_agent(permanent.id).revoked_at is None
    assert _rows(
        store,
        "SELECT status, uses_remaining, revocation_reason FROM agent_enrollments WHERE id = ?",
        outstanding_issue.enrollment_id,
    ) == [("revoked", 0, "issuing SPN blocked")]
    with pytest.raises(EnrollmentInvalidError, match="no longer available"):
        _redeem(store, outstanding_issue, outstanding_verifier, at=_NOW + timedelta(minutes=2))
    # Blocking contains the principal but leaves its credential in place.
    assert _rows(
        store, "SELECT status FROM spn_credentials WHERE id = ?", credential_id,
    ) == [("active",)]


def test_operator_rotation_checks_target_state_and_replays(store: SQLiteStore) -> None:
    principal, original_credential_id, _ = _create(store)

    with pytest.raises(ServicePrincipalNotFoundError, match="does not exist"):
        _rotate(store, str(uuid.uuid4()), 1)
    with pytest.raises(CredentialConflictError, match="service principal state changed"):
        _rotate(store, principal.id, principal.version + 1)

    request_id = _request_id()
    rotated, new_credential_id, created = _rotate(
        store, principal.id, principal.version, request_id=request_id,
    )
    replayed, replayed_credential_id, replay_created = _rotate(
        store, principal.id, principal.version, request_id=request_id,
    )

    assert (created, replay_created) == (True, False)
    assert rotated.version == principal.version + 1
    assert replayed == rotated
    assert replayed_credential_id == new_credential_id != original_credential_id
    assert _rows(
        store, "SELECT id, status FROM spn_credentials ORDER BY created_at, status",
    ) == [(original_credential_id, "revoked"), (new_credential_id, "active")]
    with pytest.raises(CredentialConflictError, match="SPN request id is already in use"):
        _rotate(store, principal.id, principal.version, request_id=request_id, reason="other")
    other, _, _ = _create(store, name="deploy-onboarder", prefix="deploy")
    with pytest.raises(CredentialConflictError, match="SPN request id is already in use"):
        _rotate(store, other.id, other.version, request_id=request_id)

    blocked = _transition(store, principal.id, "block", rotated.version)
    with pytest.raises(CredentialConflictError, match="service principal state changed"):
        _rotate(store, principal.id, blocked.version)
    assert _rows(store, "SELECT COUNT(*) FROM spn_credentials WHERE spn_id = ?", principal.id) == [
        (2,),
    ]


def test_onboarding_needs_an_enabled_principal_and_its_current_prefix(
    store: SQLiteStore,
) -> None:
    principal, credential_id, _ = _create(store)
    identity = _identity(principal, credential_id)

    for stale in (
        ServicePrincipalIdentity(
            principal.id, principal.name, "deploy", credential_id, "sbsp1",
        ),
        ServicePrincipalIdentity(
            principal.id, principal.name, principal.agent_name_prefix,
            "spc_not-this-principals", "sbsp1",
        ),
    ):
        with pytest.raises(CredentialNotFoundError, match="SPN credential is unavailable"):
            _issue(store, stale, "build-alpha")
    _transition(store, principal.id, "block", principal.version)
    with pytest.raises(CredentialNotFoundError, match="SPN credential is unavailable"):
        _issue(store, identity, "build-alpha")

    assert _rows(store, "SELECT COUNT(*) FROM agent_enrollments") == [(0,)]
    assert _rows(store, "SELECT COUNT(*) FROM spn_onboarding_issuances") == [(0,)]


def test_spn_enrollment_records_the_issuing_principal_and_identity_lifetime(
    store: SQLiteStore,
) -> None:
    principal, credential_id, _ = _create(store)
    identity = _identity(principal, credential_id)
    expires = _NOW + timedelta(hours=1)
    issuance, verifier = _issue(store, identity, "build-alpha", identity_expires_at=expires)

    agent, credential = _redeem(store, issuance, verifier, at=_NOW + timedelta(minutes=1))

    assert agent.name == "build-alpha"
    assert credential.creation_method == "enrollment"
    assert _rows(store, "SELECT expires_at FROM agents WHERE id = ?", agent.id) == [
        ("2026-09-01T13:00:00.000000Z",),
    ]
    page = store.list_identity_creation_provenance(creator_type="spn", creator_id=principal.id)
    assert page.total_count == 1
    (item,) = page.items
    assert item.agent.id == agent.id
    assert item.creation_method == "spn-enrollment"
    assert item.originating_enrollment_id == issuance.enrollment_id
    assert item.originating_issuance_request_id == issuance.request_id


def test_spn_enrollment_cannot_create_an_identity_past_its_lifetime(
    store: SQLiteStore,
) -> None:
    principal, credential_id, _ = _create(store)
    identity = _identity(principal, credential_id)
    issuance, verifier = _issue(
        store, identity, "build-alpha", identity_expires_at=_NOW + timedelta(minutes=2),
    )

    with pytest.raises(EnrollmentInvalidError, match="identity lifetime has passed"):
        _redeem(store, issuance, verifier, at=_NOW + timedelta(minutes=2))

    assert _rows(store, "SELECT COUNT(*) FROM agents WHERE name = 'build-alpha'") == [(0,)]
    assert _rows(
        store, "SELECT status, uses_remaining FROM agent_enrollments WHERE id = ?",
        issuance.enrollment_id,
    ) == [("pending", 1)]


def test_identity_retirement_is_scoped_idempotent_and_rejects_reused_request_ids(
    store: SQLiteStore,
) -> None:
    principal, credential_id, _ = _create(store)
    identity = _identity(principal, credential_id)
    other_principal, other_credential_id, _ = _create(
        store, name="deploy-onboarder", prefix="deploy",
    )
    first_issue, first_verifier = _issue(store, identity, "build-alpha")
    second_issue, second_verifier = _issue(store, identity, "build-bravo")
    first, _ = _redeem(store, first_issue, first_verifier, at=_NOW)
    second, _ = _redeem(store, second_issue, second_verifier, at=_NOW)
    retired_at = _NOW + timedelta(minutes=3)
    request_id = _request_id()

    def retire(who: ServicePrincipalIdentity, name: str, request: str, at: datetime):
        return store.retire_spn_identity(
            identity=who, agent_name=name, request_id=request, retired_at=at,
        )

    with pytest.raises(AgentNotFoundError, match="not an identity of this service principal"):
        retire(_identity(other_principal, other_credential_id), "build-alpha", _request_id(), retired_at)
    assert retire(identity, "build-alpha", request_id, retired_at) == retired_at
    # Replaying the request, or retiring again, reports the original time.
    assert retire(identity, "build-alpha", request_id, retired_at + timedelta(hours=1)) == retired_at
    assert retire(identity, "build-alpha", _request_id(), retired_at + timedelta(hours=2)) == retired_at
    with pytest.raises(CredentialConflictError, match="retire request id is already in use"):
        retire(identity, "build-bravo", request_id, retired_at)

    assert store.get_managed_agent(first.id).revoked_at == retired_at
    assert store.get_managed_agent(second.id).revoked_at is None
