"""Rules-of-engagement persistence: seeding, publication replay and history."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from strugglebus.auth import AgentService
from strugglebus.errors import AgentNotFoundError, RoeConflictError, StorageError
from strugglebus.roe import (
    INITIAL_GLOBAL_CONTENT,
    INITIAL_GLOBAL_CONTENT_SHA256,
    INITIAL_GLOBAL_REVISION_ID,
    RoeService,
)
from strugglebus.store import SQLiteStore

_NOW = datetime(2026, 9, 1, tzinfo=UTC)
_PUBLISHER = "sha256:" + "a" * 64


def _services(tmp_path: Path) -> tuple[SQLiteStore, AgentService, RoeService]:
    store = SQLiteStore(tmp_path / "strugglebus.db", backup_dir=tmp_path / "backups")
    roe = RoeService(store, enforcement_mode="observe", clock=lambda: _NOW)
    roe.initialize()
    return store, AgentService(store, clock=lambda: _NOW), roe


def _addendum(title: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_kind": "agent-addendum",
        "title": title,
        "scope_owned_systems": [
            {
                "id": "lab-owner",
                "systems": ["the locally assigned lab"],
                "ownership_role": "owner",
                "statement": "The receiving agent owns decisions within this lab.",
            }
        ],
        "coordination_boundaries": [
            {
                "id": "darkstar-proposals",
                "message_kinds": ["question", "chat"],
                "authority_effect": "none",
                "statement": "Darkstar requests are proposals rather than commands.",
            }
        ],
        "delegation_boundaries": [
            {
                "id": "return-caller-work",
                "action_classes": ["delegate", "execute"],
                "statement": "Reject work that belongs to the caller.",
            }
        ],
        "prerequisites": [
            {
                "id": "script-change-prerequisites",
                "action_classes": ["write", "execute"],
                "statement": (
                    "Require purpose, ownership, approval, validation, rollback, "
                    "and cleanup before scripts or changes."
                ),
            }
        ],
    }


def _publish(
    roe: RoeService,
    agent_id: str,
    *,
    revision_id: str,
    expected: str | None,
    title: str = "Lab ownership boundaries",
    author: str = "Lab owner",
):
    return roe.publish_agent(
        agent_id=agent_id,
        revision_id=revision_id,
        expected_current_revision_id=expected,
        author_label=author,
        policy=_addendum(title),
        publisher_kind="api-key-sha256-v1",
        publisher_id=_PUBLISHER,
    )


def _audit_events(store: SQLiteStore) -> list[tuple[str, str]]:
    with sqlite3.connect(store.database_path) as database:
        return database.execute(
            "SELECT event_type, revision_id FROM roe_audit ORDER BY rowid"
        ).fetchall()


def _seed(store: SQLiteStore, *, revision_id: str, content_json: str) -> None:
    store.ensure_initial_roe(
        revision_id=revision_id,
        content_json=content_json,
        content_sha256=INITIAL_GLOBAL_CONTENT_SHA256,
        created_at=_NOW,
    )


def test_seeding_twice_changes_nothing(tmp_path: Path) -> None:
    store, _, _ = _services(tmp_path)
    before = _audit_events(store)

    _seed(
        store,
        revision_id=INITIAL_GLOBAL_REVISION_ID,
        content_json=INITIAL_GLOBAL_CONTENT.decode("utf-8"),
    )

    assert before == [("publish", INITIAL_GLOBAL_REVISION_ID)]
    assert _audit_events(store) == before
    assert store.get_effective_roe(None).global_revision.id == INITIAL_GLOBAL_REVISION_ID


def test_seeding_refuses_a_second_baseline_identity(tmp_path: Path) -> None:
    store, _, _ = _services(tmp_path)

    with pytest.raises(StorageError, match="initial global RoE revision is unavailable"):
        _seed(
            store,
            revision_id=str(uuid.uuid4()),
            content_json=INITIAL_GLOBAL_CONTENT.decode("utf-8"),
        )

    assert _audit_events(store) == [("publish", INITIAL_GLOBAL_REVISION_ID)]


def test_seeding_refuses_a_baseline_whose_content_differs(tmp_path: Path) -> None:
    store, _, _ = _services(tmp_path)

    with pytest.raises(StorageError, match="initial global RoE revision is invalid"):
        _seed(store, revision_id=INITIAL_GLOBAL_REVISION_ID, content_json="{}")


def test_seeding_reports_a_baseline_that_is_no_longer_current(tmp_path: Path) -> None:
    store, _, _ = _services(tmp_path)
    with sqlite3.connect(store.database_path) as database:
        database.execute("DELETE FROM roe_current WHERE target_key = 'global'")

    with pytest.raises(StorageError, match="current global RoE revision is unavailable"):
        _seed(
            store,
            revision_id=INITIAL_GLOBAL_REVISION_ID,
            content_json=INITIAL_GLOBAL_CONTENT.decode("utf-8"),
        )


def test_agent_scoped_publication_needs_a_known_unretired_agent(tmp_path: Path) -> None:
    store, agents, roe = _services(tmp_path)
    missing = str(uuid.uuid4())

    with pytest.raises(AgentNotFoundError, match="was not found"):
        _publish(roe, missing, revision_id=str(uuid.uuid4()), expected=None)

    retired = agents.create_agent("retired-copilot").agent
    agents.revoke_agent(retired.id, request_id=str(uuid.uuid4()))
    with pytest.raises(AgentNotFoundError, match="was not found"):
        _publish(roe, retired.id, revision_id=str(uuid.uuid4()), expected=None)

    assert store.list_roe_revisions(
        target_key=f"agent:{retired.id}", before_version=None, limit=10,
    ) == ()


def test_republishing_a_later_revision_is_recognised_by_its_predecessor(
    tmp_path: Path,
) -> None:
    store, agents, roe = _services(tmp_path)
    agent = agents.create_agent("replay-copilot").agent
    first_id, second_id = str(uuid.uuid4()), str(uuid.uuid4())
    first, first_created = _publish(roe, agent.id, revision_id=first_id, expected=None)
    second, second_created = _publish(
        roe, agent.id, revision_id=second_id, expected=first_id, title="Second edition",
    )
    events = _audit_events(store)

    replayed, replay_created = _publish(
        roe, agent.id, revision_id=second_id, expected=first_id, title="Second edition",
    )

    assert (first_created, second_created, replay_created) == (True, True, False)
    assert (first.version, second.version) == (1, 2)
    assert replayed == second
    assert _audit_events(store) == events
    assert events[-3:] == [
        ("publish", first_id), ("supersede", first_id), ("publish", second_id),
    ]


def test_reused_revision_id_conflicts_unless_the_publication_is_identical(
    tmp_path: Path,
) -> None:
    store, agents, roe = _services(tmp_path)
    agent = agents.create_agent("conflict-copilot").agent
    first_id, second_id = str(uuid.uuid4()), str(uuid.uuid4())
    _publish(roe, agent.id, revision_id=first_id, expected=None)
    _publish(roe, agent.id, revision_id=second_id, expected=first_id, title="Second edition")
    events = _audit_events(store)

    # Different content, a different author, and a different expected predecessor.
    with pytest.raises(RoeConflictError, match="revision id is already in use"):
        _publish(roe, agent.id, revision_id=second_id, expected=first_id, title="Rewritten")
    with pytest.raises(RoeConflictError, match="revision id is already in use"):
        _publish(
            roe, agent.id, revision_id=second_id, expected=first_id,
            title="Second edition", author="Somebody else",
        )
    with pytest.raises(RoeConflictError, match="revision id is already in use"):
        _publish(
            roe, agent.id, revision_id=second_id, expected=None, title="Second edition",
        )
    # A superseded revision is not replayable even with its original inputs.
    with pytest.raises(RoeConflictError, match="revision id is already in use"):
        _publish(roe, agent.id, revision_id=first_id, expected=None)
    # The id belongs to this agent's history, not to another target.
    other = agents.create_agent("other-copilot").agent
    with pytest.raises(RoeConflictError, match="revision id is already in use"):
        _publish(roe, other.id, revision_id=second_id, expected=None, title="Second edition")

    assert _audit_events(store) == events


def test_publication_requires_the_expected_current_revision(tmp_path: Path) -> None:
    store, agents, roe = _services(tmp_path)
    agent = agents.create_agent("stale-copilot").agent
    first_id = str(uuid.uuid4())
    _publish(roe, agent.id, revision_id=first_id, expected=None)

    with pytest.raises(RoeConflictError, match="current RoE revision changed"):
        _publish(roe, agent.id, revision_id=str(uuid.uuid4()), expected=None, title="Late")

    history = store.list_roe_revisions(
        target_key=f"agent:{agent.id}", before_version=None, limit=10,
    )
    assert [revision.id for revision in history] == [first_id]


def test_revision_history_is_newest_first_and_pages_by_version(tmp_path: Path) -> None:
    store, agents, roe = _services(tmp_path)
    agent = agents.create_agent("history-copilot").agent
    ids = [str(uuid.uuid4()) for _ in range(3)]
    expected: str | None = None
    for index, revision_id in enumerate(ids):
        _publish(
            roe, agent.id, revision_id=revision_id, expected=expected,
            title=f"Edition {index + 1}",
        )
        expected = revision_id
    target = f"agent:{agent.id}"

    newest = store.list_roe_revisions(target_key=target, before_version=None, limit=2)
    older = store.list_roe_revisions(target_key=target, before_version=2, limit=2)

    assert [revision.version for revision in newest] == [3, 2]
    assert [revision.id for revision in older] == [ids[0]]
    assert [revision.superseded_at is None for revision in newest] == [True, False]
