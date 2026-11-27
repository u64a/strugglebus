from __future__ import annotations

import io
import asyncio
import json
import os
import secrets
import socket
import sqlite3
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest
import uvicorn
from fastapi.testclient import TestClient

import strugglebus.cli as cli
from strugglebus.access import access_freeze_transition_lock
from strugglebus.app import create_app
from strugglebus.auth import parse_credential
from strugglebus.cli import (
    EXIT_AUTH,
    EXIT_CONFIG,
    EXIT_INTERRUPTED,
    EXIT_NETWORK,
    EXIT_OK,
    EXIT_SERVER,
    EXIT_USAGE,
    main,
)

REAL_ASSERT_EXPECTED_IDENTITY = cli._assert_expected_identity


class _Response(io.BytesIO):
    def __init__(
        self,
        body: bytes,
        *,
        content_type: str = "application/json",
    ) -> None:
        super().__init__(body)
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _configure_local(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Path:
    credential = tmp_path / "admin-token"
    credential.write_text("test-admin-token", encoding="utf-8")
    credential.chmod(0o600)
    values = {
        "STRUGGLEBUS_DATA_DIR": str(tmp_path),
        "STRUGGLEBUS_RUNTIME_DIR": str(tmp_path / "run"),
        "STRUGGLEBUS_BACKUP_DIR": str(tmp_path / "backups"),
        "STRUGGLEBUS_DATABASE_PATH": str(tmp_path / "strugglebus.db"),
        "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": str(credential),
        "STRUGGLEBUS_PUBLIC_BASE_URL": "https://bus.lan",
        "CREDENTIALS_DIRECTORY": str(tmp_path),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("STRUGGLEBUS_EXPECTED_AGENT_ID", "agent-test")
    monkeypatch.setenv("STRUGGLEBUS_EXPECTED_AGENT_NAME", "test-agent")
    monkeypatch.setattr(cli, "_assert_expected_identity", lambda **kwargs: None)
    return tmp_path / "strugglebus.db"


def test_cli_shows_help(capsys):
    assert main([]) == EXIT_OK
    assert "LAN message board for AI agents." in capsys.readouterr().out


def test_cli_shows_version(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--version"])

    assert error.value.code == 0
    assert "strugglebus 0.2.74" in capsys.readouterr().out


def test_agent_lifecycle_prints_key_once_without_persisting_plaintext(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database = _configure_local(monkeypatch, tmp_path)
    add_output = io.StringIO()
    diagnostics = io.StringIO()
    credential_output = tmp_path / "project-copilot.credential"

    assert (
        main(
            [
                "agent",
                "add",
                "project-copilot",
                "--description",
                "builder",
                "--host",
                "devbox.lan",
                "--credential-output",
                str(credential_output),
            ],
            stdout=add_output,
            stderr=diagnostics,
        )
        == EXIT_OK
    )
    api_key = credential_output.read_text(encoding="ascii").strip()
    assert api_key
    assert add_output.getvalue() == ""
    if os.name != "nt":
        assert credential_output.stat().st_mode & 0o077 == 0
    assert api_key not in diagnostics.getvalue()
    assert api_key.encode() not in database.read_bytes()

    list_output = io.StringIO()
    assert main(["agent", "list"], stdout=list_output) == EXIT_OK
    agents = json.loads(list_output.getvalue())
    assert agents[0]["name"] == "project-copilot"
    assert "api_key" not in agents[0]
    assert api_key not in list_output.getvalue()

    revoke_output = io.StringIO()
    assert (
        main(
            ["agent", "revoke", "project-copilot"],
            stdout=revoke_output,
        )
        == EXIT_OK
    )
    assert json.loads(revoke_output.getvalue()) == {
        "id": agents[0]["id"],
        "name": "project-copilot",
        "revoked": True,
    }
    after_revoke = io.StringIO()
    assert main(["agent", "list"], stdout=after_revoke) == EXIT_OK
    assert json.loads(after_revoke.getvalue()) == []


def _create_cli_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
) -> tuple[str, str]:
    _configure_local(monkeypatch, tmp_path)
    output = tmp_path / f"{name}.credential"
    assert main(["agent", "add", name, "--credential-output", str(output)]) == EXIT_OK
    secret = output.read_text(encoding="ascii").rstrip("\n")
    parsed = parse_credential(secret)
    assert parsed is not None and parsed[1] is not None
    return secret, parsed[1]


def _prove_cli_credential(secret: str):
    config = cli.AppConfig.from_env()
    agents, board = cli._services(config)
    board.initialize()
    identity = agents.verify_credential(secret)
    assert identity is not None
    agents.prove(
        identity,
        request_id=str(uuid.uuid4()),
        expected_agent_id=identity.agent.id,
        expected_agent_name=identity.agent.name,
        expected_credential_epoch=identity.agent.credential_epoch,
        expected_credential_version=identity.credential.version,
    )
    return agents


@pytest.fixture
def unproved_enrollment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    request: pytest.FixtureRequest,
):
    _configure_local(monkeypatch, tmp_path)
    config = cli.AppConfig.from_env()
    expired = getattr(request, "param", False)
    with TestClient(create_app(config=config)) as client:
        service = client.app.state.agent_service
        with monkeypatch.context() as clock_patch:
            if expired:
                before_expiry = datetime.now(UTC) - timedelta(
                    seconds=config.credential_pending_seconds + 60
                )
                clock_patch.setattr(service, "_clock", lambda: before_expiry)
            issued = service.create_enrollment(name_prefix="recovery")
            assert issued.token is not None
            response = client.post(
                "/api/enrollments/redeem",
                json={
                    "request_id": str(uuid.uuid4()),
                    "name": "recovery-cli-win",
                },
                headers={"Authorization": f"Bearer {issued.token}"},
            )
            assert response.status_code == 201
        # Retain the lost response only as a test oracle, never as CLI input.
        yield SimpleNamespace(
            client=client,
            service=service,
            body=response.json(),
            token=issued.token,
            expired=expired,
        )


def _run_recovery_cli(arguments: list[str]) -> tuple[int, str, str]:
    output = io.StringIO()
    diagnostics = io.StringIO()
    result = main(arguments, stdout=output, stderr=diagnostics)
    return result, output.getvalue(), diagnostics.getvalue()


def _listed_recovery_agent(enrollment) -> dict[str, object]:
    result, output, diagnostics = _run_recovery_cli(["agent", "list"])
    assert result == EXIT_OK
    assert diagnostics == ""
    for forbidden in (
        enrollment.token,
        enrollment.body["credential_secret"],
        "test-admin-token",
        "sb1_",
        "sbe1_",
        "secret_hash",
        "credential_secret",
    ):
        assert forbidden not in output
    agents = json.loads(output)
    assert len(agents) == 1
    listed = agents[0]
    assert listed["id"] == enrollment.body["agent"]["id"]
    assert listed["name"] == "recovery-cli-win"
    persisted = enrollment.service.get_active_agent(listed["id"])
    assert type(listed["credential_epoch"]) is int
    assert listed["credential_epoch"] == persisted.credential_epoch
    return listed


def test_agent_enroll_list_distinguishes_dashboard_exact_and_cli_prefix_without_tokens(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    token_path = (tmp_path / "generic-enrollment.token").resolve()
    result, create_output, create_diagnostics = _run_recovery_cli(
        [
            "agent", "enroll", "create", "review-reader",
            "--token-output", str(token_path),
        ]
    )
    assert result == EXIT_OK
    assert create_output == ""
    generic_token = token_path.read_text(encoding="ascii").strip()
    assert generic_token.startswith("sbe1_")
    service, _ = cli._services(cli.AppConfig.from_env())
    from strugglebus.operator_auth import OperatorAuth, PasswordVerifier, create_password_verifier

    password = "synthetic operator enrollment password"
    authority = OperatorAuth(
        cli.AppConfig.from_env(), PasswordVerifier.parse(create_password_verifier(password)),
    )
    challenge, csrf = authority.challenge("127.0.0.1")

    def unfrozen():
        service.list_managed_agents(limit=1)

    try:
        _, operator = asyncio.run(authority.login(
            source="127.0.0.1", challenge=challenge, csrf=csrf,
            password=password, guard=unfrozen,
        ))
        dashboard = service.create_dashboard_enrollment(
            name="dashboard-cli-win", operator=operator,
            authorize=lambda: authority.require_active(operator),
        )
    finally:
        authority.close()
    assert dashboard.token is not None

    result, output, diagnostics = _run_recovery_cli(["agent", "enroll", "list"])

    assert result == EXIT_OK
    assert diagnostics == ""
    listed = json.loads(output)
    assert len(listed) == 2
    by_prefix = {item["name_prefix"]: item for item in listed}
    assert by_prefix["review-reader"]["name_match"] == "prefix"
    assert by_prefix["dashboard-cli-win"]["name_match"] == "exact"
    assert by_prefix["dashboard-cli-win"]["id"] == dashboard.enrollment.id
    for item in listed:
        assert item["status"] == "pending"
        assert item["uses_allowed"] == item["uses_remaining"] == 1
        assert "token" not in item
        assert "secret_hash" not in item
    for forbidden in (
        generic_token, dashboard.token, "sbe1_", "test-admin-token",
    ):
        assert forbidden not in output + diagnostics + create_output + create_diagnostics


def test_protected_agent_list_keeps_blocked_recovery_targets_while_frozen(
    monkeypatch, tmp_path,
):
    from strugglebus.models import LifecycleActor

    _configure_local(monkeypatch, tmp_path)
    config = cli.AppConfig.from_env()
    agents, _ = cli._services(config)
    agents.initialize()
    enabled = agents.create_agent("enabled-cli-win").agent
    blocked = agents.create_agent("blocked-cli-win").agent
    retired = agents.create_agent("retired-cli-win").agent
    for agent, action in ((blocked, "block"), (retired, "retire")):
        agents.transition_agent(
            agent.id, action=action, expected_credential_epoch=agent.credential_epoch,
            request_id=str(uuid.uuid4()), reason="synthetic local lifecycle",
            actor=LifecycleActor("local-admin", "local-cli"),
        )
    cli._access_freeze(config).operator_freeze("synthetic frozen recovery")
    result, output, diagnostics = _run_recovery_cli(["agent", "list"])
    assert result == EXIT_OK, diagnostics
    assert diagnostics == ""
    listed = {entry["id"]: entry for entry in json.loads(output)}
    assert set(listed) == {enabled.id, blocked.id}
    assert listed[enabled.id]["state"] == "enabled"
    assert listed[enabled.id]["blocked_at"] is None
    assert listed[blocked.id]["state"] == "blocked"
    assert listed[blocked.id]["blocked_at"] is not None
    assert agents.store.get_access_freeze().frozen


@pytest.mark.parametrize(
    "unproved_enrollment",
    [False, True],
    indirect=True,
    ids=["lost-response", "expired-before-proof"],
)
def test_enrollment_recovery_uses_listed_epoch_and_keeps_stable_identity(
    unproved_enrollment,
    tmp_path: Path,
) -> None:
    enrollment = unproved_enrollment
    service = enrollment.service
    original = service.get_credential(
        "recovery-cli-win", enrollment.body["credential"]["id"]
    )
    assert original.status == "pending"
    assert original.creation_method == "enrollment"
    assert original.identity_verified_at is None
    assert original.activated_at is None
    assert original.pending_expires_at is not None
    assert (original.pending_expires_at <= datetime.now(UTC)) is enrollment.expired
    if enrollment.expired:
        assert service.verify_credential(enrollment.body["credential_secret"]) is None
        expired = service.get_credential("recovery-cli-win", original.id)
        assert expired.status == "expired"
        assert expired.identity_verified_at is None

    prior_secrets = [enrollment.body["credential_secret"]]
    previous_epoch = None
    for attempt in range(2):
        listed = _listed_recovery_agent(enrollment)
        if previous_epoch is not None:
            assert listed["credential_epoch"] == previous_epoch + 1
        replacement_path = (tmp_path / f"recovered-{attempt}.credential").resolve()
        assert replacement_path.is_absolute()
        assert not replacement_path.exists()
        result, output, diagnostics = _run_recovery_cli(
            [
                "agent", "recover", listed["name"],
                "--expected-credential-epoch", str(listed["credential_epoch"]),
                "--reason", "lost enrollment response",
                "--credential-output", str(replacement_path),
            ]
        )
        assert result == EXIT_OK
        assert output == ""
        replacement = replacement_path.read_text(encoding="ascii").rstrip("\n")
        assert parse_credential(replacement) is not None
        assert replacement not in prior_secrets
        if os.name == "posix":
            assert replacement_path.stat().st_mode & 0o777 == 0o600
        for secret in (
            *prior_secrets, replacement, enrollment.token, "test-admin-token",
        ):
            assert secret not in output + diagnostics

        identity = service.verify_credential(replacement)
        assert identity is not None
        assert identity.agent.id == listed["id"]
        assert identity.agent.name == listed["name"]
        assert identity.agent.credential_epoch == listed["credential_epoch"] + 1
        assert identity.credential.status == "pending"
        assert identity.credential.identity_verified_at is None
        assert identity.credential.activated_at is None
        assert identity.credential.creation_method == "recover"
        assert identity.credential.creation_reason == "lost enrollment response"
        whoami = enrollment.client.get(
            "/api/whoami",
            headers={"Authorization": f"Bearer {replacement}"},
        )
        assert whoami.status_code == 200
        assert whoami.json()["agent"]["id"] == listed["id"]
        assert whoami.json()["agent"]["name"] == listed["name"]
        assert whoami.json()["agent"]["credential_epoch"] == listed["credential_epoch"] + 1
        assert whoami.json()["credential"]["status"] == "pending"
        assert enrollment.client.get(
            "/api/channels",
            headers={"Authorization": f"Bearer {replacement}"},
        ).status_code == 403
        for prior in prior_secrets:
            assert service.verify_credential(prior) is None
            assert enrollment.client.get(
                "/api/whoami",
                headers={"Authorization": f"Bearer {prior}"},
            ).status_code == 401
        previous_epoch = listed["credential_epoch"]
        prior_secrets.append(replacement)
    assert _listed_recovery_agent(enrollment)["credential_epoch"] == previous_epoch + 1


def test_enrollment_recovery_rejects_stale_listed_epoch_without_issuing(
    unproved_enrollment,
    tmp_path: Path,
) -> None:
    enrollment = unproved_enrollment
    listed = _listed_recovery_agent(enrollment)
    first_path = (tmp_path / "first-recovery.credential").resolve()
    arguments = [
        "agent", "recover", listed["name"],
        "--expected-credential-epoch", str(listed["credential_epoch"]),
        "--reason", "lost enrollment response",
        "--credential-output",
    ]
    assert _run_recovery_cli([*arguments, str(first_path)])[0] == EXIT_OK
    replacement = first_path.read_text(encoding="ascii").strip()
    before = enrollment.service.list_credentials(listed["name"])
    current = _listed_recovery_agent(enrollment)
    assert current["credential_epoch"] == listed["credential_epoch"] + 1
    stale_path = (tmp_path / "stale-recovery.credential").resolve()

    result, output, diagnostics = _run_recovery_cli([*arguments, str(stale_path)])

    assert result == EXIT_SERVER
    assert output == ""
    assert "credential lifecycle state changed" in diagnostics
    assert not stale_path.exists()
    assert enrollment.service.list_credentials(listed["name"]) == before
    assert _listed_recovery_agent(enrollment) == current
    assert enrollment.service.verify_credential(replacement) is not None
    for secret in (
        replacement, enrollment.body["credential_secret"],
        enrollment.token, "test-admin-token",
    ):
        assert secret not in output + diagnostics


@pytest.mark.parametrize("authorization", ["absent", "empty", "overlong", "unsafe-mode"])
def test_enrollment_recovery_and_listing_require_local_admin_authorization(
    unproved_enrollment,
    tmp_path: Path,
    authorization: str,
) -> None:
    if authorization == "unsafe-mode" and os.name != "posix":
        pytest.skip("POSIX credential-file permissions are required")
    enrollment = unproved_enrollment
    listed = _listed_recovery_agent(enrollment)
    before = enrollment.service.list_credentials(listed["name"])
    credential_file = tmp_path / "admin-token"
    if authorization == "absent":
        credential_file.unlink()
    elif authorization == "unsafe-mode":
        credential_file.chmod(0o644)
    else:
        credential_file.write_bytes(b"" if authorization == "empty" else b"x" * 4097)
    replacement_path = (tmp_path / "unauthorized.credential").resolve()

    for arguments in (
        ["agent", "list"],
        [
            "agent", "recover", listed["name"],
            "--expected-credential-epoch", str(listed["credential_epoch"]),
            "--reason", "lost enrollment response",
            "--credential-output", str(replacement_path),
        ],
    ):
        result, output, diagnostics = _run_recovery_cli(arguments)
        assert result == EXIT_CONFIG
        assert output == ""
        assert "admin credential" in diagnostics
        for secret in (
            enrollment.body["credential_secret"], enrollment.token,
            "test-admin-token", "x" * 4097,
        ):
            assert secret not in output + diagnostics
    assert not replacement_path.exists()
    assert enrollment.service.list_credentials(listed["name"]) == before
    assert (
        enrollment.service.get_active_agent(listed["id"]).credential_epoch
        == listed["credential_epoch"]
    )


@pytest.mark.parametrize("reason", ["", "x" * 257], ids=["empty", "overlong"])
def test_enrollment_recovery_rejects_unbounded_reason_without_issuing(
    unproved_enrollment,
    tmp_path: Path,
    reason: str,
) -> None:
    enrollment = unproved_enrollment
    listed = _listed_recovery_agent(enrollment)
    before = enrollment.service.list_credentials(listed["name"])
    replacement_path = (tmp_path / "invalid-reason.credential").resolve()

    result, output, diagnostics = _run_recovery_cli(
        [
            "agent", "recover", listed["name"],
            "--expected-credential-epoch", str(listed["credential_epoch"]),
            "--reason", reason,
            "--credential-output", str(replacement_path),
        ]
    )

    assert result == EXIT_CONFIG
    assert output == ""
    assert "reason" in diagnostics
    assert not replacement_path.exists()
    assert enrollment.service.list_credentials(listed["name"]) == before
    assert _listed_recovery_agent(enrollment) == listed


def test_enrollment_recovery_cannot_revive_revoked_unproved_agent_or_reuse_name(
    unproved_enrollment,
    tmp_path: Path,
) -> None:
    enrollment = unproved_enrollment
    listed = _listed_recovery_agent(enrollment)
    result, output, diagnostics = _run_recovery_cli(
        ["agent", "revoke", listed["name"]]
    )
    assert result == EXIT_OK
    assert diagnostics == ""
    assert json.loads(output) == {
        "id": listed["id"], "name": listed["name"], "revoked": True,
    }
    revoked = enrollment.service.store.get_credential(
        listed["id"], enrollment.body["credential"]["id"]
    )
    assert revoked.status == "revoked"
    assert revoked.identity_verified_at is None
    assert enrollment.client.get(
        "/api/whoami",
        headers={"Authorization": f"Bearer {enrollment.body['credential_secret']}"},
    ).status_code == 401
    result, output, diagnostics = _run_recovery_cli(["agent", "list"])
    assert result == EXIT_OK
    assert json.loads(output) == []
    assert diagnostics == ""
    with sqlite3.connect(tmp_path / "strugglebus.db") as database:
        actual_epoch, revoked_at = database.execute(
            "SELECT credential_epoch, revoked_at FROM agents WHERE id = ?",
            (listed["id"],),
        ).fetchone()
    assert revoked_at is not None
    replacement_path = (tmp_path / "terminal-recovery.credential").resolve()

    result, output, diagnostics = _run_recovery_cli(
        [
            "agent", "recover", listed["name"],
            "--expected-credential-epoch", str(actual_epoch),
            "--reason", "must not resurrect",
            "--credential-output", str(replacement_path),
        ]
    )

    assert result == EXIT_SERVER
    assert output == ""
    assert "was not found" in diagnostics
    assert not replacement_path.exists()
    assert enrollment.service.store.get_credential(
        listed["id"], revoked.id
    ) == revoked
    with sqlite3.connect(tmp_path / "strugglebus.db") as database:
        assert database.execute(
            "SELECT COUNT(*) FROM agent_credentials WHERE agent_id = ?",
            (listed["id"],),
        ).fetchone() == (1,)
    new_enrollment = enrollment.service.create_enrollment(name_prefix="recovery")
    conflict = enrollment.client.post(
        "/api/enrollments/redeem",
        json={"request_id": str(uuid.uuid4()), "name": listed["name"]},
        headers={"Authorization": f"Bearer {new_enrollment.token}"},
    )
    assert conflict.status_code == 409
    remaining = next(
        item for item in enrollment.service.list_enrollments()
        if item.id == new_enrollment.enrollment.id
    )
    assert remaining.uses_remaining == 1
    for secret in (
        enrollment.body["credential_secret"], enrollment.token, "test-admin-token",
    ):
        assert secret not in output + diagnostics


def test_enrollment_recovery_while_frozen_preserves_remote_denial(
    unproved_enrollment,
    tmp_path: Path,
) -> None:
    enrollment = unproved_enrollment
    result, _, diagnostics = _run_recovery_cli(
        ["access-freeze", "freeze", "--reason", "contain lost enrollment response"]
    )
    assert result == EXIT_OK
    assert diagnostics == ""
    before = enrollment.service.store.get_access_freeze()
    assert before.frozen is True
    assert enrollment.client.get(
        "/api/whoami",
        headers={"Authorization": f"Bearer {enrollment.body['credential_secret']}"},
    ).status_code == 503
    listed = _listed_recovery_agent(enrollment)
    replacement_path = (tmp_path / "frozen-recovery.credential").resolve()

    result, output, diagnostics = _run_recovery_cli(
        [
            "agent", "recover", listed["name"],
            "--expected-credential-epoch", str(listed["credential_epoch"]),
            "--reason", "recover without unfreezing",
            "--credential-output", str(replacement_path),
        ]
    )

    assert result == EXIT_OK
    assert output == ""
    replacement = replacement_path.read_text(encoding="ascii").strip()
    identity = enrollment.service.verify_credential(replacement)
    assert identity is not None
    assert identity.agent.id == listed["id"]
    assert identity.agent.name == listed["name"]
    assert identity.credential.status == "pending"
    assert identity.credential.identity_verified_at is None
    assert enrollment.service.verify_credential(enrollment.body["credential_secret"]) is None
    assert _listed_recovery_agent(enrollment)["credential_epoch"] == listed["credential_epoch"] + 1
    proof = {
        "request_id": str(uuid.uuid4()),
        "expected_agent_id": identity.agent.id,
        "expected_agent_name": identity.agent.name,
        "expected_credential_epoch": identity.agent.credential_epoch,
        "expected_credential_version": identity.credential.version,
    }
    for secret, status, detail in (
        (enrollment.body["credential_secret"], 401, "invalid agent credential"),
        (replacement, 503, "agent access is frozen"),
    ):
        headers = {"Authorization": f"Bearer {secret}"}
        for path in ("/api/whoami", "/api/channels", "/api/agents"):
            response = enrollment.client.get(path, headers=headers)
            assert response.status_code == status
            assert response.json()["detail"] == detail
        response = enrollment.client.post(
            "/api/credentials/prove", json=proof, headers=headers
        )
        assert response.status_code == status
        assert response.json()["detail"] == detail
        assert secret not in output + diagnostics
    assert enrollment.client.get("/healthz").status_code == 200
    assert enrollment.service.store.get_access_freeze() == before
    assert enrollment.service.get_credential(
        listed["name"], identity.credential.id
    ).identity_verified_at is None
    for secret in (enrollment.token, "test-admin-token"):
        assert secret not in output + diagnostics


def test_credential_secret_writer_requires_exact_sb1_and_no_clobber(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "credential").resolve()
    secret = "sb1_" + "a" * 22 + "_" + "b" * 43
    cli._write_credential_secret(path, secret)
    assert path.read_bytes() == secret.encode("ascii") + b"\n"
    assert len(path.read_bytes()) == 71
    with pytest.raises(cli.ConfigurationError, match="already exists"):
        cli._write_credential_secret(path, secret)
    with pytest.raises(cli.ConfigurationError, match="invalid format"):
        cli._write_credential_secret((tmp_path / "bad").resolve(), "sb1_bad")


def test_credential_secret_writer_rejects_link_count_fault(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = (tmp_path / "credential").resolve()
    secret = "sb1_" + "a" * 22 + "_" + "b" * 43
    real_fstat = cli.os.fstat

    def linked_fstat(descriptor):
        metadata = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_nlink=2,
            st_uid=metadata.st_uid,
        )

    monkeypatch.setattr(cli.os, "fstat", linked_fstat)
    with pytest.raises(cli.ConfigurationError, match="could not be created safely"):
        cli._write_credential_secret(path, secret)
    assert not path.exists()


def test_credential_evidence_requires_active_proof_and_exact_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secret, credential_id = _create_cli_agent(monkeypatch, tmp_path, "evidence-copilot")
    receipt = (tmp_path / "pending.json").resolve()
    operation_id = "1" * 32
    diagnostics = io.StringIO()
    assert main(
        [
            "agent", "credential-evidence", "verify", "evidence-copilot",
            "--credential-id", credential_id, "--operation-id", operation_id,
            "--receipt-path", str(receipt),
        ],
        stderr=diagnostics,
    ) == EXIT_CONFIG
    assert not receipt.exists()
    assert secret not in diagnostics.getvalue()

    _prove_cli_credential(secret)
    mismatch = (tmp_path / "mismatch.json").resolve()
    assert main(
        [
            "agent", "credential-evidence", "verify", "other-copilot",
            "--credential-id", credential_id, "--operation-id", operation_id,
            "--receipt-path", str(mismatch),
        ],
        stderr=io.StringIO(),
    ) == EXIT_SERVER
    assert not mismatch.exists()


def test_credential_evidence_receipts_are_redacted_targeted_and_no_clobber(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secret, credential_id = _create_cli_agent(monkeypatch, tmp_path, "handoff-copilot")
    agents = _prove_cli_credential(secret)
    verify_receipt = (tmp_path / "verified.json").resolve()
    verify_operation = "2" * 32
    args = [
        "agent", "credential-evidence", "verify", "handoff-copilot",
        "--credential-id", credential_id, "--operation-id", verify_operation,
        "--receipt-path", str(verify_receipt),
    ]
    assert main(args, stdout=io.StringIO(), stderr=io.StringIO()) == EXIT_OK
    verified = json.loads(verify_receipt.read_text(encoding="ascii"))
    assert verified["operation_id"] == verify_operation
    assert verified["agent_name"] == "handoff-copilot"
    assert verified["credential_id"] == credential_id
    assert set(verified) == {
        "version",
        "operation_id",
        "agent_name",
        "credential_id",
        "outcome",
        "credential_status",
        "credential_version",
        "observed_at",
    }
    assert verified["version"] == 1
    assert verified["outcome"] == "proved"
    assert verified["credential_status"] == "active"
    assert verified["observed_at"].endswith("Z")
    raw = verify_receipt.read_text(encoding="ascii")
    for forbidden in (secret, "test-admin-token", "secret_hash", "verifier", "host", "message"):
        assert forbidden not in raw
    original = verify_receipt.read_bytes()
    assert main(args, stdout=io.StringIO(), stderr=io.StringIO()) == EXIT_CONFIG
    assert verify_receipt.read_bytes() == original

    revoke_receipt = (tmp_path / "revoked.json").resolve()
    revoke_operation = "3" * 32
    assert main(
        [
            "agent", "credential-evidence", "revoke", "handoff-copilot",
            "--credential-id", credential_id, "--operation-id", revoke_operation,
            "--receipt-path", str(revoke_receipt), "--reason", "handoff complete",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    ) == EXIT_OK
    revoked = json.loads(revoke_receipt.read_text(encoding="ascii"))
    assert revoked["outcome"] == "revoked"
    assert revoked["credential_status"] == "revoked"
    assert revoked["observed_at"].endswith("Z")
    assert revoked["credential_version"] == verified["credential_version"] + 1
    assert agents.get_credential("handoff-copilot", credential_id).status == "revoked"
    replay_receipt = (tmp_path / "revoked-replay.json").resolve()
    assert main(
        [
            "agent", "credential-evidence", "revoke", "handoff-copilot",
            "--credential-id", credential_id, "--operation-id", revoke_operation,
            "--receipt-path", str(replay_receipt), "--reason", "handoff complete",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    ) == EXIT_OK
    assert replay_receipt.read_bytes() == revoke_receipt.read_bytes()

    observed_receipt = (tmp_path / "revoked-observed.json").resolve()
    assert main(
        [
            "agent", "credential-evidence", "revoke", "handoff-copilot",
            "--credential-id", credential_id, "--operation-id", "different-operation",
            "--receipt-path", str(observed_receipt), "--reason", "already revoked",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    ) == EXIT_OK
    assert json.loads(observed_receipt.read_text(encoding="ascii"))["outcome"] == "revoked"


def test_credential_receipt_rejects_existing_and_symlink_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secret, credential_id = _create_cli_agent(monkeypatch, tmp_path, "receipt-copilot")
    _prove_cli_credential(secret)
    target = (tmp_path / "target").resolve()
    target.write_text("unchanged", encoding="ascii")
    common = [
        "agent", "credential-evidence", "verify", "receipt-copilot",
        "--credential-id", credential_id, "--operation-id", "4" * 32,
    ]
    assert main(
        [*common, "--receipt-path", str(target)],
        stderr=io.StringIO(),
    ) == EXIT_CONFIG
    assert target.read_text(encoding="ascii") == "unchanged"
    link = tmp_path / "receipt-link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable")
    assert main(
        [*common, "--receipt-path", str(link)],
        stderr=io.StringIO(),
    ) == EXIT_CONFIG
    assert target.read_text(encoding="ascii") == "unchanged"


def test_credential_receipt_link_failure_cleans_temporary_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secret, credential_id = _create_cli_agent(monkeypatch, tmp_path, "link-copilot")
    _prove_cli_credential(secret)
    receipt = (tmp_path / "receipt.json").resolve()
    monkeypatch.setattr(
        cli.os,
        "link",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("fault")),
    )
    assert main(
        [
            "agent", "credential-evidence", "verify", "link-copilot",
            "--credential-id", credential_id, "--operation-id", "5" * 32,
            "--receipt-path", str(receipt),
        ],
        stderr=io.StringIO(),
    ) == EXIT_CONFIG
    assert not receipt.exists()
    assert not list(tmp_path.glob(".receipt.json.*.tmp"))


def test_agent_command_requires_secure_admin_credential(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH",
        str(tmp_path / "missing"),
    )
    diagnostics = io.StringIO()

    assert main(["agent", "list"], stderr=diagnostics) == EXIT_CONFIG
    assert "credential file is unavailable" in diagnostics.getvalue()
    assert "test-admin-token" not in diagnostics.getvalue()


def test_access_freeze_cli_is_idempotent_and_requires_recovery_reason(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    status_output = io.StringIO()
    assert main(["access-freeze", "status"], stdout=status_output) == EXIT_OK
    assert json.loads(status_output.getvalue()) == {
        "frozen": False,
        "transition": "initialized",
        "changed_at": None,
        "reason": None,
    }

    frozen_output = io.StringIO()
    assert (
        main(
            ["access-freeze", "freeze", "--reason", "operator incident"],
            stdout=frozen_output,
        )
        == EXIT_OK
    )
    assert json.loads(frozen_output.getvalue())["changed"] is True
    repeated_output = io.StringIO()
    assert (
        main(
            ["access-freeze", "freeze", "--reason", "replacement"],
            stdout=repeated_output,
        )
        == EXIT_OK
    )
    repeated = json.loads(repeated_output.getvalue())
    assert repeated["changed"] is False
    assert repeated["reason"] == "operator incident"

    recovered_output = io.StringIO()
    assert (
        main(
            ["access-freeze", "unfreeze", "--reason", "reviewed recovery"],
            stdout=recovered_output,
        )
        == EXIT_OK
    )
    assert json.loads(recovered_output.getvalue())["changed"] is True

    with pytest.raises(SystemExit) as missing:
        main(["access-freeze", "freeze"])
    assert missing.value.code == EXIT_USAGE


def test_access_freeze_cli_does_not_open_sqlite_before_shared_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    initialized = threading.Event()
    result: list[int] = []
    original_initialize = cli.SQLiteStore.initialize

    def tracked_initialize(store):
        initialized.set()
        return original_initialize(store)

    monkeypatch.setattr(cli.SQLiteStore, "initialize", tracked_initialize)
    lock_directory = tmp_path / ".access-freeze-lock"
    with access_freeze_transition_lock(lock_directory):
        worker = threading.Thread(
            target=lambda: result.append(
                main(
                    [
                        "access-freeze",
                        "freeze",
                        "--reason",
                        "serialized CLI incident",
                    ],
                    stdout=io.StringIO(),
                )
            )
        )
        worker.start()
        time.sleep(0.1)
        assert not initialized.is_set()

    worker.join(timeout=2)
    assert not worker.is_alive()
    assert initialized.is_set()
    assert result == [EXIT_OK]


def test_revoke_unknown_agent_is_server_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    diagnostics = io.StringIO()

    assert (
        main(
            ["agent", "revoke", "missing-agent"],
            stderr=diagnostics,
        )
        == EXIT_SERVER
    )
    assert "missing-agent" in diagnostics.getvalue()


def test_serve_uses_safe_config_and_disables_access_logs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_BIND_HOST", "::1")
    monkeypatch.setenv("STRUGGLEBUS_BIND_PORT", "9090")
    captured: dict[str, object] = {}

    class _Config:
        def __init__(self, app, **kwargs):
            captured["app"] = app
            captured.update(kwargs)

    class _Server:
        def __init__(self, config):
            captured["server_config"] = config
            captured["server"] = self
            self.started = True
            self.should_exit = False

        def run(self):
            captured["ran"] = True

    import strugglebus.app

    application = SimpleNamespace(state=SimpleNamespace())
    monkeypatch.setattr(
        strugglebus.app, "create_app", lambda *, config: application,
    )
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(Config=_Config, Server=_Server),
    )

    assert main(["serve"]) == EXIT_OK
    assert captured["host"] == "::1"
    assert captured["port"] == 9090
    assert captured["access_log"] is False
    assert captured["server_header"] is False
    assert captured["proxy_headers"] is False
    assert captured["ran"] is True
    # Graceful shutdown must be bounded, or a live tail can hold a stop past the
    # unit's stop timeout and leave a killed, failed unit behind.
    assert captured["timeout_graceful_shutdown"] == 10
    # And the stop must be observable from inside a stream while that bounded
    # wait is happening, which is what ends the tail early. Track the server's
    # own flag rather than a snapshot of it.
    assert application.state.shutdown_requested() is False
    captured["server"].should_exit = True
    assert application.state.shutdown_requested() is True


def test_serve_refuses_public_bind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_BIND_HOST", "0.0.0.0")
    diagnostics = io.StringIO()

    assert main(["serve"], stderr=diagnostics) == EXIT_CONFIG
    assert "loopback-only" in diagnostics.getvalue()


def test_serve_maps_uvicorn_bind_failure_to_server_exit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)

    class _Server:
        started = False

        def __init__(self, config):
            pass

        def run(self):
            raise SystemExit(1)

    import strugglebus.app

    monkeypatch.setattr(
        strugglebus.app,
        "create_app",
        lambda *, config: SimpleNamespace(state=SimpleNamespace()),
    )
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(Config=lambda *args, **kwargs: object(), Server=_Server),
    )
    diagnostics = io.StringIO()

    assert main(["serve"], stderr=diagnostics) == EXIT_SERVER
    warning, _, failure = diagnostics.getvalue().partition("\n")
    # The fixture's admin token is deliberately short; serve says so and carries on.
    assert warning.startswith("warning: the admin token in ")
    assert "only 16 characters long" in warning and "test-admin-token" not in warning
    assert failure == "server error: server did not start\n"


def test_health_uses_configured_url_timeout_and_json_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    calls: list[tuple[object, float, object]] = []
    context = object()
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: context)

    def open_request(request, *, timeout, context):
        calls.append((request, timeout, context))
        return _Response(b'{"status":"ok"}')

    monkeypatch.setattr(cli, "_open", open_request)
    output = io.StringIO()

    assert main(["health", "--timeout", "1.5"], stdout=output) == EXIT_OK
    request, timeout, used_context = calls[0]
    assert request.full_url == "https://bus.lan/healthz"
    assert timeout == 1.5
    assert used_context is context
    assert output.getvalue() == '{"status":"ok"}\n'


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, EXIT_AUTH),
        (403, EXIT_AUTH),
        (500, EXIT_SERVER),
        (503, EXIT_SERVER),
    ],
)
def test_health_maps_http_failures_to_stable_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: int,
    expected: int,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())

    def fail(request, **kwargs):
        raise HTTPError(request.full_url, status, "failure", {}, None)

    monkeypatch.setattr(cli, "_open", fail)
    assert main(["health"], stderr=io.StringIO()) == expected


def test_health_network_failure_does_not_leak_url_details(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    monkeypatch.setattr(
        cli,
        "_open",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            cli._NetworkFailure("network request failed")
        ),
    )
    diagnostics = io.StringIO()

    assert main(["health"], stderr=diagnostics) == EXIT_NETWORK
    assert diagnostics.getvalue() == "network error: network request failed\n"


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1",
        "https://bus.lan:invalid",
        "https://bus.lan:0",
        "https://bus.lan/\nignored",
    ],
)
def test_health_rejects_malformed_origins_as_configuration_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    url: str,
) -> None:
    _configure_local(monkeypatch, tmp_path)

    assert (
        main(["health", "--url", url], stderr=io.StringIO())
        == EXIT_CONFIG
    )


def test_health_enforces_total_response_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    monkeypatch.setattr(
        cli,
        "_open",
        lambda *args, **kwargs: _Response(b'{"status":"ok"}'),
    )
    moments = iter([0.0, 2.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(moments))

    assert (
        main(["health", "--timeout", "1"], stderr=io.StringIO())
        == EXIT_NETWORK
    )


def test_tail_resumes_reconnects_and_suppresses_duplicates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "secret-agent-key")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    monkeypatch.setattr(cli.time, "sleep", lambda delay: None)
    resume_file = tmp_path / "resume"
    responses = iter(
        [
            _Response(
                b'id: 1\nevent: message\ndata: {"seq":1,"body":"first"}\n\n',
                content_type="text/event-stream",
            ),
            _Response(
                (
                    b'id: 1\nevent: message\ndata: {"seq":1,"body":"duplicate"}\n\n'
                    b'id: 2\nevent: message\ndata: {"seq":2,"body":"second"}\n\n'
                ),
                content_type="text/event-stream",
            ),
        ]
    )
    requests = []

    def open_stream(request, **kwargs):
        requests.append(request)
        return next(responses)

    monkeypatch.setattr(cli, "_open", open_stream)
    output = io.StringIO()

    assert (
        main(
            [
                "tail",
                "--max-events",
                "2",
                "--resume-file",
                str(resume_file),
            ],
            stdout=output,
        )
        == EXIT_OK
    )
    assert [json.loads(line)["body"] for line in output.getvalue().splitlines()] == [
        "first",
        "second",
    ]
    assert requests[0].get_header("Last-event-id") is None
    assert requests[1].get_header("Last-event-id") == "1"
    assert resume_file.read_text(encoding="ascii").strip() == "2"


def test_tail_identity_mismatch_aborts_before_stream_or_cursor_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_assert_expected_identity", REAL_ASSERT_EXPECTED_IDENTITY)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "secret-agent-key")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    resume_file = tmp_path / "resume"
    resume_file.write_text("7\n", encoding="ascii")
    requests = []

    def identity_response(request, **kwargs):
        requests.append(request)
        return _Response(
            json.dumps(
                {
                    "agent": {
                        "id": "unexpected-agent",
                        "name": "unexpected-name",
                    },
                    "credential": {"status": "active"},
                }
            ).encode("ascii")
        )

    monkeypatch.setattr(cli, "_open", identity_response)
    diagnostics = io.StringIO()

    assert (
        main(
            ["tail", "--resume-file", str(resume_file)],
            stderr=diagnostics,
        )
        == EXIT_AUTH
    )
    assert len(requests) == 1
    assert requests[0].full_url.endswith("/api/whoami")
    assert resume_file.read_text(encoding="ascii") == "7\n"
    assert diagnostics.getvalue() == (
        "authentication error: authenticated agent identity mismatch\n"
    )


def test_tail_stops_without_reconnecting_on_access_freeze_event(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "secret-agent-key")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    calls = 0

    def open_stream(request, **kwargs):
        nonlocal calls
        calls += 1
        return _Response(
            (
                b"event: agent_access_frozen\n"
                b'data: {"detail":"agent access is frozen"}\n\n'
            ),
            content_type="text/event-stream",
        )

    monkeypatch.setattr(cli, "_open", open_stream)
    diagnostics = io.StringIO()

    assert main(["tail"], stderr=diagnostics) == EXIT_AUTH
    assert calls == 1
    assert diagnostics.getvalue() == "authentication error: agent access is frozen\n"


def test_tail_authenticates_against_real_sse_endpoint_without_key_leakage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    app_config,
    agent_service,
) -> None:
    created = agent_service.create_agent("cli-integration")
    application = create_app(config=app_config, agent_service=agent_service)
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            host="127.0.0.1",
            port=0,
            access_log=False,
            log_level="error",
            timeout_graceful_shutdown=1,
        )
    )
    listening_socket = socket.socket()
    listening_socket.bind(("127.0.0.1", 0))
    listening_socket.listen()
    port = listening_socket.getsockname()[1]
    server_thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listening_socket]},
        daemon=True,
    )
    server_thread.start()
    deadline = time.monotonic() + 5
    while not server.started:
        if not server_thread.is_alive() or time.monotonic() >= deadline:
            pytest.fail("Uvicorn did not start")
        time.sleep(0.01)

    try:
        message = application.state.board_service.create_message(
            "announce",
            agent_id=created.agent.id,
            body="authenticated tail event",
            kind="chat",
            reply_to=None,
            metadata={},
        )
        key_file = tmp_path / "agent-key"
        key_file.write_text(f"{created.api_key}\n", encoding="utf-8")
        key_file.chmod(0o600)
        monkeypatch.delenv("STRUGGLEBUS_API_KEY", raising=False)
        monkeypatch.setenv("STRUGGLEBUS_API_KEY_FILE", str(key_file))
        base_url = f"http://127.0.0.1:{port}"
        output = io.StringIO()
        diagnostics = io.StringIO()

        assert (
            main(
                [
                    "tail",
                    "--url",
                    base_url,
                    "--max-events",
                    "1",
                    "--timeout",
                    "5",
                    "--expected-agent-id",
                    created.agent.id,
                    "--expected-agent-name",
                    created.agent.name,
                ],
                stdout=output,
                stderr=diagnostics,
            )
            == EXIT_OK
        )
        payload = json.loads(output.getvalue())
        assert payload["seq"] == message.seq
        assert payload["body"] == "authenticated tail event"
        assert created.api_key not in output.getvalue()
        assert created.api_key not in diagnostics.getvalue()

        wrong_key = secrets.token_urlsafe(32)
        key_file.write_text(f"{wrong_key}\n", encoding="utf-8")
        rejected_output = io.StringIO()
        rejected_diagnostics = io.StringIO()
        assert (
            main(
                [
                    "tail",
                    "--url",
                    base_url,
                    "--max-events",
                    "1",
                    "--timeout",
                    "5",
                    "--expected-agent-id",
                    created.agent.id,
                    "--expected-agent-name",
                    created.agent.name,
                ],
                stdout=rejected_output,
                stderr=rejected_diagnostics,
            )
            == EXIT_AUTH
        )
        assert rejected_output.getvalue() == ""
        assert created.api_key not in rejected_diagnostics.getvalue()
        assert wrong_key not in rejected_diagnostics.getvalue()
    finally:
        server.should_exit = True
        server_thread.join(timeout=3)
        listening_socket.close()
        if server_thread.is_alive():
            pytest.fail("Uvicorn did not stop")


def test_tail_uses_resume_cursor_and_escapes_terminal_controls(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    key_file = tmp_path / "agent-key"
    key_file.write_text("file-agent-key\n", encoding="utf-8")
    key_file.chmod(0o600)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY_FILE", str(key_file))
    resume_file = tmp_path / "resume"
    resume_file.write_text("7\n", encoding="ascii")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    seen = {}

    def open_stream(request, **kwargs):
        seen["request"] = request
        return _Response(
            b'id: 8\nevent: message\ndata: {"seq":8,"body":"bad\\u001b[31m"}\n\n',
            content_type="text/event-stream",
        )

    monkeypatch.setattr(cli, "_open", open_stream)
    output = io.StringIO()
    assert (
        main(
            [
                "tail",
                "--max-events",
                "1",
                "--resume-file",
                str(resume_file),
            ],
            stdout=output,
        )
        == EXIT_OK
    )
    assert seen["request"].get_header("Last-event-id") == "7"
    assert "\x1b" not in output.getvalue()
    assert "\\u001b" in output.getvalue()


def test_tail_401_never_prints_bearer_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "do-not-print-me")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())

    def unauthorized(request, **kwargs):
        raise HTTPError(request.full_url, 401, "no", {}, None)

    monkeypatch.setattr(cli, "_open", unauthorized)
    diagnostics = io.StringIO()
    assert main(["tail"], stderr=diagnostics) == EXIT_AUTH
    assert "do-not-print-me" not in diagnostics.getvalue()
    assert diagnostics.getvalue() == "authentication error: agent authentication failed\n"


def test_tail_reconnect_limit_is_network_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "agent-key")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    monkeypatch.setattr(cli.time, "sleep", lambda delay: None)
    monkeypatch.setattr(
        cli,
        "_open",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            cli._NetworkFailure("network request failed")
        ),
    )

    assert (
        main(["tail", "--retries", "1"], stderr=io.StringIO())
        == EXIT_NETWORK
    )


def test_tail_post_header_failures_consume_retry_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "agent-key")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    monkeypatch.setattr(cli.time, "sleep", lambda delay: None)
    calls = 0

    class _FailedBody(_Response):
        def readline(self, size=-1):
            raise OSError("connection reset")

    def open_stream(*args, **kwargs):
        nonlocal calls
        calls += 1
        return _FailedBody(b"", content_type="text/event-stream")

    monkeypatch.setattr(cli, "_open", open_stream)

    assert (
        main(["tail", "--retries", "1"], stderr=io.StringIO())
        == EXIT_NETWORK
    )
    assert calls == 2


def test_tail_clean_idle_rotation_does_not_consume_retry_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "agent-key")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    monkeypatch.setattr(cli.time, "sleep", lambda delay: None)
    responses = iter(
        [
            _Response(b": heartbeat\n\n", content_type="text/event-stream"),
            _Response(
                b'id: 1\nevent: message\ndata: {"seq":1}\n\n',
                content_type="text/event-stream",
            ),
        ]
    )
    monkeypatch.setattr(cli, "_open", lambda *args, **kwargs: next(responses))

    assert (
        main(
            ["tail", "--retries", "0", "--max-events", "1"],
            stdout=io.StringIO(),
        )
        == EXIT_OK
    )


def test_tail_ctrl_c_is_clean(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "agent-key")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    monkeypatch.setattr(
        cli,
        "_open",
        lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    diagnostics = io.StringIO()

    assert main(["tail"], stderr=diagnostics) == EXIT_INTERRUPTED
    assert diagnostics.getvalue() == "interrupted\n"


def test_tail_closed_output_pipe_stops_without_reconnecting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "agent-key")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: object())
    calls = 0

    def open_stream(*args, **kwargs):
        nonlocal calls
        calls += 1
        return _Response(
            b'id: 1\nevent: message\ndata: {"seq":1}\n\n',
            content_type="text/event-stream",
        )

    class _ClosedOutput(io.StringIO):
        def write(self, value):
            raise BrokenPipeError

    monkeypatch.setattr(cli, "_open", open_stream)

    assert main(["tail"], stdout=_ClosedOutput()) == EXIT_OK
    assert calls == 1


def test_backup_command_verifies_and_retains_requested_count(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database = _configure_local(monkeypatch, tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sample(value TEXT)")
        connection.execute("INSERT INTO sample VALUES ('safe')")
    outputs = []
    for _ in range(3):
        output = io.StringIO()
        assert (
            main(
                [
                    "backup",
                    "--database",
                    str(database),
                    "--destination",
                    str(tmp_path / "backups"),
                    "--retention",
                    "2",
                ],
                stdout=output,
            )
            == EXIT_OK
        )
        outputs.append(Path(output.getvalue().strip()))

    backups = list((tmp_path / "backups").glob("strugglebus-*.db"))
    assert len(backups) == 2
    assert outputs[-1] in backups
    with sqlite3.connect(outputs[-1]) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM sample").fetchone() == ("safe",)


def test_backup_retention_never_deletes_matching_source_database(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_local(monkeypatch, tmp_path)
    database = tmp_path / "backups" / "strugglebus-live.db"
    database.parent.mkdir(mode=0o700)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sample(value TEXT)")
        connection.execute("INSERT INTO sample VALUES ('live')")
    output = io.StringIO()

    assert (
        main(
            [
                "backup",
                "--database",
                str(database),
                "--destination",
                str(database.parent),
                "--retention",
                "1",
            ],
            stdout=output,
        )
        == EXIT_OK
    )
    destination = Path(output.getvalue().strip())
    assert database.exists()
    assert destination.exists()
    assert destination != database
