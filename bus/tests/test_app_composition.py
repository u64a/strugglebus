from __future__ import annotations

from datetime import UTC, datetime
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from strugglebus.access import AccessFreezeService
from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.config import AppConfig
from strugglebus.errors import ConfigurationError
from strugglebus.service import BoardService
from strugglebus.store import SQLiteStore


def _store(path: Path, config: AppConfig) -> SQLiteStore:
    return SQLiteStore(
        path,
        backup_dir=config.backup_dir,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
    )


def _board(store: SQLiteStore, config: AppConfig) -> BoardService:
    return BoardService(
        store,
        max_message_bytes=config.max_message_bytes,
        max_metadata_bytes=config.max_metadata_bytes,
        max_channels=config.max_channels,
    )


def test_composition_forwards_all_reconnect_limits(app_config):
    config = replace(
        app_config, orientation_count_cap=7, orientation_channel_cap=3,
        orientation_candidate_limit=11, catch_up_candidate_limit=13,
        catch_up_drain_ttl_seconds=17, catch_up_max_drains=19,
        catch_up_max_drains_per_agent=2,
    )
    board = create_app(config=config).state.board_service
    assert board.orientation_count_cap == 7
    assert board.orientation_channel_cap == 3
    assert board.orientation_candidate_limit == 11
    assert board.catch_up_candidate_limit == 13
    assert board._drains._ttl_seconds == 17
    assert board._drains._maximum == 19
    assert board._drains._per_agent == 2


def test_board_only_injection_constructs_agent_service_on_shared_store(
    app_config: AppConfig,
) -> None:
    store = _store(app_config.database_path, app_config)
    board = _board(store, app_config)
    application = create_app(config=app_config, board_service=board)

    assert application.state.board_service is board
    assert application.state.agent_service.store is store
    with TestClient(application) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        created = application.state.agent_service.create_agent(
            "board-only-agent"
        )
        assert application.state.agent_service.authenticate(
            created.api_key
        ) is not None


def test_agent_only_injection_constructs_board_service_on_shared_store(
    app_config: AppConfig,
) -> None:
    store = _store(app_config.database_path, app_config)
    agents = AgentService(store)
    application = create_app(config=app_config, agent_service=agents)

    assert application.state.agent_service is agents
    assert application.state.board_service.store is store
    with TestClient(application) as client:
        assert client.get("/healthz").status_code == 200
        assert {
            channel.name
            for channel in application.state.board_service.list_channels()
        } == {
            "announce",
            "help",
            "humans",
            "status",
            "strugglebus-improvements",
        }


def test_startup_adds_missing_defaults_without_replacing_existing_channels(
    app_config: AppConfig,
) -> None:
    store = _store(app_config.database_path, app_config)
    board = _board(store, app_config)
    board.initialize()
    with store._transaction() as database:
        database.execute(
            "DELETE FROM channels WHERE name = ?",
            ("strugglebus-improvements",),
        )
        database.execute(
            "UPDATE channels SET purpose = ? WHERE name = ?",
            ("operator-owned purpose", "help"),
        )

    board.initialize()
    channels = {channel.name: channel for channel in board.list_channels()}

    assert channels["help"].purpose == "operator-owned purpose"
    assert (
        "untrusted coordination data"
        in channels["strugglebus-improvements"].purpose
    )
    assert channels["strugglebus-improvements"].created_by is None


def test_dual_injection_accepts_services_with_same_store(
    app_config: AppConfig,
) -> None:
    store = _store(app_config.database_path, app_config)
    agents = AgentService(store)
    board = _board(store, app_config)
    application = create_app(
        config=app_config,
        agent_service=agents,
        board_service=board,
    )

    assert application.state.agent_service is agents
    assert application.state.board_service is board
    with TestClient(application) as client:
        assert client.get("/healthz").status_code == 200


def test_dual_injection_rejects_mismatched_stores(
    app_config: AppConfig,
) -> None:
    agents = AgentService(_store(app_config.database_path, app_config))
    other_store = _store(app_config.data_dir / "other.db", app_config)
    board = _board(other_store, app_config)

    with pytest.raises(
        ConfigurationError,
        match="must share one store",
    ):
        create_app(
            config=app_config,
            agent_service=agents,
            board_service=board,
        )


def test_access_freeze_only_injection_constructs_all_services_on_its_store(
    app_config: AppConfig,
) -> None:
    store = _store(app_config.database_path, app_config)
    access = AccessFreezeService(
        store,
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        transition_lock_directory=app_config.data_dir / ".access-freeze-lock",
    )

    application = create_app(config=app_config, access_freeze_service=access)

    assert application.state.access_freeze_service is access
    assert application.state.agent_service.store is store
    assert application.state.board_service.store is store


def test_access_freeze_injection_rejects_a_mismatched_store(
    app_config: AppConfig,
) -> None:
    store = _store(app_config.database_path, app_config)
    agents = AgentService(store)
    access = AccessFreezeService(
        _store(app_config.data_dir / "other.db", app_config),
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        transition_lock_directory=app_config.data_dir / ".access-freeze-lock",
    )

    with pytest.raises(ConfigurationError, match="must share one store"):
        create_app(
            config=app_config,
            agent_service=agents,
            access_freeze_service=access,
        )


def test_single_injected_service_must_use_configured_storage(
    app_config: AppConfig,
) -> None:
    agents = AgentService(_store(app_config.data_dir / "other.db", app_config))

    with pytest.raises(ConfigurationError, match="configured database"):
        create_app(config=app_config, agent_service=agents)


def test_injected_access_service_must_use_configured_transition_lock(
    app_config: AppConfig,
) -> None:
    store = _store(app_config.database_path, app_config)
    access = AccessFreezeService(
        store,
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        transition_lock_directory=app_config.data_dir / "other-lock",
    )

    with pytest.raises(ConfigurationError, match="configured transition lock"):
        create_app(config=app_config, access_freeze_service=access)
