"""Offline failure injection and cleanup tests for the disposable smoke helper."""

from __future__ import annotations

import asyncio
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from typing import Any


DEPLOY_DIR = Path(__file__).resolve().parents[1]
HELPER_PATH = DEPLOY_DIR / "files/strugglebus_disposable_smoke.py"
PLAYBOOK_PATH = DEPLOY_DIR / "playbooks/smoke.yml"
SPEC = importlib.util.spec_from_file_location("strugglebus_smoke", HELPER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("smoke helper could not be loaded")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)

NAMESPACE = "smoke-0123456789abcdef"
WRITER_NAME = f"{NAMESPACE}-writer"
READER_NAME = f"{NAMESPACE}-reader"
IDENTITY_MARKER = f"{smoke.MARKER_VERSION}:{NAMESPACE}"
FORBIDDEN_KEYS = {
    "api_key",
    "args",
    "authorization",
    "body",
    "environment",
    "exception",
    "metadata",
    "path",
    "payload",
    "response",
    "secret",
    "token",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def create_database(path: Path, *, partial: bool = False, schema: int = 11) -> None:
    migration_dir = DEPLOY_DIR.parent / "src/strugglebus/migrations"
    require(schema in {11, 12, 13, 14, 15, 16}, "unsupported fixture schema")
    with closing(sqlite3.connect(path)) as database, database:
        for migration in sorted(migration_dir.glob("*.sql"))[:schema]:
            database.executescript(migration.read_text(encoding="utf-8"))
        database.execute(f"PRAGMA user_version = {schema}")
        timestamp = "2026-01-01T00:00:00.000000Z"
        database.executemany(
            """
            INSERT INTO agents (
                id, name, description, host, created_at, credential_epoch
            ) VALUES (?, ?, ?, ?, ?, 1)
            """,
            [
                (
                    "existing-agent",
                    "existing-agent",
                    "existing",
                    "existing.invalid",
                    timestamp,
                ),
                (
                    "writer-id",
                    WRITER_NAME,
                    IDENTITY_MARKER,
                    smoke.HOST_MARKER,
                    timestamp,
                ),
            ],
        )
        if not partial:
            database.execute(
                """
                INSERT INTO agents (
                    id, name, description, host, created_at, credential_epoch
                ) VALUES (?, ?, ?, ?, ?, 1)
                """,
                (
                    "reader-id",
                    READER_NAME,
                    IDENTITY_MARKER,
                    smoke.HOST_MARKER,
                    timestamp,
                ),
            )
        credential_agents = ["existing-agent", "writer-id"]
        if not partial:
            credential_agents.append("reader-id")
        database.executemany(
            """
            INSERT INTO agent_credentials (
                id, agent_id, kind, secret_hash, status, predecessor_id,
                creation_method, creation_reason, issuance_request_id,
                created_at, activated_at, identity_verified_at,
                pending_expires_at, last_used_at, retired_at, revoked_at,
                expired_at, version
            ) VALUES (?, ?, 'sb1', ?, 'active', NULL,
                      'enrollment', 'self-registered through enrollment', ?, ?, ?, ?, NULL,
                      NULL, NULL, NULL, NULL, 0)
            """,
            [
                (
                    f"legacy-agent:{agent_id}",
                    agent_id,
                    character * 64,
                    f"migration:{agent_id}",
                    timestamp,
                    timestamp,
                    timestamp,
                )
                for agent_id, character in zip(
                    credential_agents, ("a", "b", "c")[: len(credential_agents)],
                    strict=True,
                )
            ],
        )
        for agent_id, name in [("writer-id", WRITER_NAME)] + (
            [] if partial else [("reader-id", READER_NAME)]
        ):
            database.execute(
                """
                INSERT INTO agent_enrollments (
                    id, secret_hash, name_prefix, description, status, uses_allowed,
                    uses_remaining, created_at, expires_at, exhausted_at,
                    actor_type, actor_id, creation_reason, name_match
                ) VALUES (?, ?, ?, ?, 'exhausted', 1, 0, ?, ?, ?,
                          'local-admin', ?, ?, 'exact')
                """,
                (f"enrollment:{agent_id}", ("d" if agent_id == "writer-id" else "e") * 64,
                 name, IDENTITY_MARKER, timestamp, "2026-01-02T00:00:00Z",
                 timestamp, NAMESPACE, smoke.ENROLLMENT_REASON),
            )
            database.execute(
                """
                INSERT INTO agent_enrollment_redemptions (
                    enrollment_id, agent_id, credential_id, claimed_name,
                    request_id, redeemed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (f"enrollment:{agent_id}", agent_id, f"legacy-agent:{agent_id}",
                 name, f"redemption:{agent_id}", timestamp),
            )
        database.executemany(
            """
            INSERT INTO channels (id, name, purpose, created_at, created_by)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("help-id", "help", "", timestamp, None),
                ("existing-channel", "existing", "", timestamp, "existing-agent"),
                (
                    "smoke-channel",
                    NAMESPACE,
                    f"{smoke.MARKER_VERSION}:{NAMESPACE}",
                    timestamp,
                    "writer-id",
                ),
            ],
        )
        database.execute(
            """
            INSERT INTO messages (
                id, channel_id, agent_id, body, kind, meta, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "existing-message",
                "existing-channel",
                "existing-agent",
                "existing body",
                "chat",
                "{}",
                timestamp,
            ),
        )
        if partial:
            return
        marker = f"{smoke.MARKER_VERSION}:{NAMESPACE}"
        metadata = json.dumps(
            {"marker": smoke.MARKER_VERSION, "run": NAMESPACE},
            separators=(",", ":"),
        )
        database.execute(
            """
            INSERT INTO messages (
                id, channel_id, agent_id, body, kind, meta, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "question",
                "smoke-channel",
                "writer-id",
                f"{marker} question",
                "question",
                metadata,
                timestamp,
            ),
        )
        question_seq = database.execute(
            "SELECT seq FROM messages WHERE id = 'question'"
        ).fetchone()[0]
        database.execute(
            """
            INSERT INTO messages (
                id, channel_id, agent_id, body, kind, reply_to, meta, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "answer",
                "smoke-channel",
                "reader-id",
                f"{marker} answer",
                "answer",
                question_seq,
                metadata,
                timestamp,
            ),
        )
        database.execute(
            """
            INSERT INTO messages (
                id, channel_id, agent_id, body, kind, meta, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "mention",
                "help-id",
                "writer-id",
                f"{marker} mention",
                "chat",
                metadata,
                timestamp,
            ),
        )
        mention_seq = database.execute(
            "SELECT seq FROM messages WHERE id = 'mention'"
        ).fetchone()[0]
        database.execute(
            "INSERT INTO mentions (message_seq, agent_id) VALUES (?, ?)",
            (mention_seq, "reader-id"),
        )
        database.execute(
            """
            INSERT INTO subscriptions (agent_id, channel_id, created_at)
            VALUES ('reader-id', 'smoke-channel', ?)
            """,
            (timestamp,),
        )
        database.execute(
            """
            INSERT INTO cursors (
                agent_id, channel_id, include_stale, last_seq, updated_at
            ) VALUES ('reader-id', 'smoke-channel', 0, ?, ?)
            """,
            (question_seq, timestamp),
        )
        database.execute(
            """
            INSERT INTO mention_cursors (
                agent_id, include_stale, last_seq, updated_at
            ) VALUES ('reader-id', 0, ?, ?)
            """,
            (mention_seq, timestamp),
        )


def assert_namespace_absent(path: Path) -> None:
    with closing(sqlite3.connect(path)) as database:
        require(
            database.execute(
                """
                SELECT COUNT(*) FROM agents
                WHERE name IN (?, ?) AND description = ? AND host = ?
                """,
                (
                    WRITER_NAME,
                    READER_NAME,
                    IDENTITY_MARKER,
                    smoke.HOST_MARKER,
                ),
            ).fetchone()
            in {(1,), (2,)},
            "immutable smoke identity history was removed",
        )
        require(
            database.execute(
                "SELECT COUNT(*) FROM agents WHERE id IN ('writer-id', 'reader-id') "
                "AND revoked_at IS NULL"
            ).fetchone() == (0,),
            "synthetic identity remains on enabled roster",
        )
        require(
            database.execute(
                """
                SELECT COUNT(*) FROM agent_credentials
                WHERE agent_id IN ('writer-id', 'reader-id')
                  AND status IN ('pending', 'active')
                """
            ).fetchone()
            == (0,),
            "live disposable credentials remain",
        )
        require(
            database.execute(
                "SELECT COUNT(*) FROM channels WHERE name = ?", (NAMESPACE,)
            ).fetchone()
            == (0,),
            "disposable channel remains",
        )
        require(
            database.execute(
                "SELECT COUNT(*) FROM agents WHERE name = 'existing-agent'"
            ).fetchone()
            == (1,),
            "existing agent was changed",
        )
        require(
            database.execute(
                "SELECT COUNT(*) FROM agents WHERE id = 'existing-agent' "
                "AND revoked_at IS NULL AND credential_epoch = 1"
            ).fetchone() == (1,),
            "existing identity lifecycle was changed",
        )
        require(
            database.execute(
                "SELECT COUNT(*) FROM messages WHERE id = 'existing-message'"
            ).fetchone()
            == (1,),
            "existing message was changed",
        )


class FakeBackend:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.binding = (*smoke._file_identity(database_path), 11)
        self.cleanup_calls = 0

    async def setup(self) -> None:
        return None

    def __getattr__(self, name: str):
        if name not in smoke.PHASES:
            raise AttributeError(name)

        async def operation() -> tuple[str, bool, bool]:
            return "ok", True, True

        return operation

    def cleanup(self) -> None:
        self.cleanup_calls += 1
        smoke.cleanup_database(self.database_path, namespace=NAMESPACE, binding=self.binding)

    async def close(self) -> None:
        return None


def assert_safe_result(path: Path, *, failed_phase: str | None) -> None:
    raw = path.read_text(encoding="ascii")
    values = json.loads(raw)
    require(
        len(raw.encode("ascii")) <= smoke.MAX_RESULT_BYTES,
        "result is not bounded",
    )
    require(isinstance(values, list), "result is not a list")
    require(
        len(values) == len(smoke.PHASES) + 1
        if failed_phase is None
        else len(values) <= len(smoke.PHASES) + 1,
        "result phase count is incorrect",
    )
    require(
        all(
            set(item)
            == {
                "phase",
                "passed",
                "status_category",
                "shape_matches",
                "count_matches",
                "error_code",
            }
            for item in values
        ),
        "result contains a forbidden field",
    )
    serialized = raw.lower()
    require("offline-test-secret" not in serialized, "secret reached result")
    require(
        not any(f'"{key}"' in serialized for key in FORBIDDEN_KEYS),
        "forbidden key reached result",
    )
    failures = [item["phase"] for item in values if not item["passed"]]
    require(
        failures == ([] if failed_phase is None else [failed_phase]),
        "failure attribution is not exact",
    )


def run_failure_injection(root: Path, phase: str | None) -> None:
    database_path = root / f"{phase or 'success'}.db"
    result_path = root / f"{phase or 'success'}.json"
    create_database(database_path)
    backend = FakeBackend(database_path)
    store = smoke.ResultStore(result_path)
    success = asyncio.run(
        smoke.run_smoke(backend, store, failure_phase=phase)
    )
    require(success is (phase is None), "run success state is incorrect")
    require(backend.cleanup_calls == 1, "helper cleanup did not run exactly once")
    assert_safe_result(result_path, failed_phase=phase)
    assert_namespace_absent(database_path)


def test_cleanup_contracts(root: Path) -> None:
    partial = root / "partial.db"
    create_database(partial, partial=True)
    smoke.cleanup_database(partial, namespace=NAMESPACE, binding=(*smoke._file_identity(partial), 11))
    assert_namespace_absent(partial)

    refusal = root / "refusal.db"
    create_database(refusal)
    with closing(sqlite3.connect(refusal)) as database, database:
        database.execute(
            """
            INSERT INTO messages (
                id, channel_id, agent_id, body, kind, meta, created_at
            ) VALUES (
                'unexpected', 'smoke-channel', 'existing-agent',
                'unexpected', 'chat', '{}', '2026-01-01T00:00:00.000000Z'
            )
            """
        )
    try:
        smoke.cleanup_database(
            refusal, namespace=NAMESPACE, binding=(*smoke._file_identity(refusal), 11)
        )
    except smoke.SmokeError as error:
        require(
            error.error_code == "artifact_cleanup_refused",
            "unexpected cleanup error classification",
        )
    else:
        raise AssertionError("cleanup accepted an unexpected channel occupant")
    with closing(sqlite3.connect(refusal)) as database:
        require(
            database.execute(
                "SELECT COUNT(*) FROM messages WHERE id = 'unexpected'"
            ).fetchone()
            == (1,),
            "cleanup touched an unexpected occupant",
        )
        require(
            database.execute(
                "SELECT COUNT(*) FROM agents WHERE name IN (?, ?)",
                (WRITER_NAME, READER_NAME),
            ).fetchone()
            == (2,),
            "contained identity history was removed",
        )
        require(
            database.execute(
                "SELECT COUNT(*) FROM agent_credentials WHERE agent_id IN "
                "('writer-id', 'reader-id') AND status IN ('pending', 'active')"
            ).fetchone() == (0,),
            "artifact contamination left synthetic credentials live",
        )


def test_playbook_contract() -> None:
    content = PLAYBOOK_PATH.read_text(encoding="utf-8")
    markers = (
        "- name: Execute and clean the disposable production smoke",
        "      block:",
        "- name: Run named smoke phases with credential-bearing input hidden",
        "          no_log: true",
        "      always:",
        "- name: Re-run exact marker cleanup from the Ansible always path",
        "- name: Read the sanitized smoke result",
        "- name: Remove disposable smoke workspace only after exact cleanup",
        "- name: Report only the sanitized named smoke result",
        "- name: Require every smoke phase and both cleanup paths to pass",
    )
    positions = [content.index(marker) for marker in markers]
    require(positions == sorted(positions), "smoke cleanup tasks are out of order")
    require(
        content.count("no_log: true") == 1,
        "smoke playbook hides more than the credential-bearing task",
    )
    require(
        "strugglebus_smoke_result" in content,
        "smoke playbook does not report the sanitized result",
    )
    require("state: absent" in content, "smoke workspace is not removed")
    require(
        "when: strugglebus_smoke_cleanup.rc | default(1) == 0" in content,
        "cleanup refusal must retain root-only provenance",
    )
    phase_block = content.split("strugglebus_smoke_expected_phases:\n")[1].split("  tasks:")[0]
    require(
        tuple(line.strip()[2:] for line in phase_block.splitlines() if line.strip())
        == smoke.ALL_PHASES,
        "playbook phase names/order differ from the helper",
    )
    require(len(smoke.ALL_PHASES) == 16, "expected phase count changed")
    run_task = content.index(
        "- name: Run named smoke phases with credential-bearing input hidden"
    )
    always_task = content.index("      always:")
    cleanup_task = content.index(
        "- name: Re-run exact marker cleanup from the Ansible always path"
    )
    require(
        run_task
        < content.index("strugglebus_smoke_input", run_task)
        < always_task,
        "run task does not receive the full hidden input",
    )
    require(
        cleanup_task
        < content.index(
            "{{ {'work_dir': strugglebus_smoke_workspace.path} | to_json }}",
            cleanup_task,
        ),
        "always cleanup does not receive the narrow input",
    )
    run_input = {
        "admin_credential_path": "/protected/admin",
        "base_url": "https://bus.lan",
        "ca_path": "/protected/public-ca",
        "database_path": "/var/lib/strugglebus/strugglebus.db",
        "expected_release_id": "0.2.20",
        "release_environment_path": "/opt/strugglebus/current/release.env",
        "work_dir": "/run/strugglebus-smoke-test",
    }
    require(
        smoke._configuration_for_action("run", run_input) == run_input,
        "helper rejects the playbook run input contract",
    )
    require(
        smoke._configuration_for_action(
            "cleanup", {"work_dir": run_input["work_dir"]}
        )
        == {"work_dir": run_input["work_dir"]},
        "helper rejects the playbook cleanup input contract",
    )
    requirements = (DEPLOY_DIR.parent / "requirements.lock").read_text(
        encoding="utf-8"
    )
    helper = HELPER_PATH.read_text(encoding="utf-8")
    require("httpx2==" in requirements, "production HTTP client is not locked")
    require(
        "import httpx2 as httpx" in helper,
        "smoke helper does not use the production HTTP client",
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="strugglebus-smoke-unit-") as directory:
        root = Path(directory)
        for phase in (*smoke.PHASES, None):
            run_failure_injection(root, phase)
        test_cleanup_contracts(root)
    test_playbook_contract()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
