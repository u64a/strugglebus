import hashlib
import base64
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from strugglebus.auth import (
    API_KEY_ENTROPY_BYTES, SB1_HASH_DOMAIN, AgentService, parse_credential,
    parse_enrollment_token, parse_reconnect_token,
)
from strugglebus.errors import DuplicateAgentNameError
from strugglebus.models import Agent, CreatedAgent
from strugglebus.store import SQLiteStore


class _RecordingStore(SQLiteStore):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.statements: list[str] = []

    @contextmanager
    def _connection(self):
        with super()._connection() as connection:
            connection.set_trace_callback(self.statements.append)
            yield connection


def test_agent_key_is_random_hashed_and_returned_only_at_creation(
    agent_service: AgentService,
    app_config,
) -> None:
    created = agent_service.create_agent(
        "strugglebus-copilot",
        description="Build agent",
        host="devbox.lan",
    )

    assert isinstance(created, CreatedAgent)
    assert len(created.api_key) >= API_KEY_ENTROPY_BYTES
    assert created.api_key not in repr(created)
    assert "key_hash" not in {field.name for field in fields(Agent)}
    with sqlite3.connect(app_config.database_path) as database:
        stored_hash = database.execute(
            "SELECT secret_hash FROM agent_credentials WHERE agent_id = ?",
            (created.agent.id,),
        ).fetchone()[0]
    assert stored_hash == parse_credential(created.api_key)[2]
    assert stored_hash != created.api_key
    for database_file in app_config.database_path.parent.glob(
        f"{app_config.database_path.name}*"
    ):
        assert created.api_key.encode("utf-8") not in database_file.read_bytes()


def test_duplicate_agent_name_is_rejected(
    agent_service: AgentService,
) -> None:
    agent_service.create_agent("strugglebus-copilot")

    with pytest.raises(DuplicateAgentNameError):
        agent_service.create_agent("strugglebus-copilot")


def test_authentication_updates_last_seen_and_revocation_is_immediate(
    app_config,
) -> None:
    started = datetime(2026, 8, 28, 1, 0, tzinfo=UTC)
    moments = iter(
        (started, started + timedelta(minutes=1), started + timedelta(minutes=2))
    )
    service = AgentService(
        SQLiteStore(
            app_config.database_path,
            backup_dir=app_config.backup_dir,
        ),
        clock=lambda: next(moments),
    )
    service.initialize()
    created = service.create_agent("strugglebus-copilot")

    authenticated = service.authenticate(created.api_key)
    assert authenticated is not None
    assert authenticated.id == created.agent.id
    assert authenticated.last_seen_at == started + timedelta(minutes=1)
    assert service.authenticate("not-the-key") is None

    revoked = service.revoke_agent(created.agent.id)
    assert revoked.revoked_at == started + timedelta(minutes=2)
    assert service.authenticate(created.api_key) is None


def test_revocation_by_name_uses_normalized_service_lookup(
    agent_service: AgentService,
) -> None:
    created = agent_service.create_agent("project-copilot")

    revoked = agent_service.revoke_agent_by_name("PROJECT COPILOT")

    assert revoked.id == created.agent.id
    assert revoked.revoked_at is not None
    assert agent_service.authenticate(created.api_key) is None


def test_invalid_authentication_uses_indexed_read_without_write_lock(
    app_config,
) -> None:
    store = _RecordingStore(
        app_config.database_path,
        backup_dir=app_config.backup_dir,
    )
    service = AgentService(store)
    service.initialize()
    service.create_agent("strugglebus-copilot")
    store.statements.clear()

    assert service.authenticate("not-the-key") is None

    statements = tuple(statement.upper() for statement in store.statements)
    assert any(
        "CREDENTIAL.SECRET_HASH = " in statement for statement in statements
    )
    assert all("ORDER BY ID" not in statement for statement in statements)
    assert all("BEGIN IMMEDIATE" not in statement for statement in statements)


def test_concurrent_operations_use_independent_connections(
    agent_service: AgentService,
) -> None:
    def create_and_authenticate(index: int) -> str:
        created = agent_service.create_agent(f"project-{index}")
        authenticated = agent_service.authenticate(created.api_key)
        assert authenticated is not None
        return authenticated.id

    with ThreadPoolExecutor(max_workers=8) as executor:
        agent_ids = list(executor.map(create_and_authenticate, range(16)))

    assert len(set(agent_ids)) == 16


def test_existing_sb1_and_enrollment_noncanonical_pad_bits_remain_compatible(agent_service):
    lookup, secret_part = "a" * 22, "b" * 43
    secret = f"sb1_{lookup}_{secret_part}"
    credential_id = f"cred_{lookup}"
    digest = hashlib.sha256(
        SB1_HASH_DOMAIN + credential_id.encode("ascii") + b"\0"
        + base64.urlsafe_b64decode(secret_part + "=")
    ).hexdigest()
    assert parse_credential(secret) == ("sb1", credential_id, digest)
    assert parse_enrollment_token(f"sbe1_{lookup}_{secret_part}") is not None
    assert parse_reconnect_token(f"sbr1_{lookup}_{secret_part}") is None
    now = datetime.now(UTC)
    agent, credential, _ = agent_service.store.create_agent_with_credential(
        agent_id=str(uuid.uuid4()), name="compatible-copilot", description="", host="",
        credential_id=credential_id, secret_hash=digest, request_id=str(uuid.uuid4()),
        created_at=now, pending_expires_at=now + timedelta(minutes=15),
    )
    authenticated = agent_service.verify_credential(secret)
    assert authenticated is not None
    assert authenticated.agent.id == agent.id
    assert authenticated.credential.id == credential.id
