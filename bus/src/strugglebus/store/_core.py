from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import datetime
from pathlib import Path
from collections.abc import Callable, Iterator

from strugglebus.errors import RoeAcknowledgementRequiredError, StorageError
from strugglebus.migrations import LATEST_SCHEMA_VERSION, migrate_database
from strugglebus.models import LifecycleActor
from strugglebus.store._common import (
    _access_freeze_from_connection,
    _effective_roe_from_connection,
    _require_active_credential,
    _require_live_credential,
    _validate_actor,
    utc_now,
)


class CoreMixin:
    def __init__(
        self,
        database_path: Path,
        *,
        backup_dir: Path,
        busy_timeout_ms: int = 5_000,
        liveness_refresh_seconds: int = 60,
    ) -> None:
        if not database_path.is_absolute() or not backup_dir.is_absolute():
            raise StorageError("database and backup paths must be absolute")
        if isinstance(busy_timeout_ms, bool) or busy_timeout_ms <= 0:
            raise StorageError("busy_timeout_ms must be positive")
        if (
            isinstance(liveness_refresh_seconds, bool)
            or liveness_refresh_seconds <= 0
        ):
            raise StorageError("liveness_refresh_seconds must be positive")
        self.database_path = database_path
        self.backup_dir = backup_dir
        self.busy_timeout_ms = busy_timeout_ms
        # How stale a liveness timestamp may be before authentication takes a
        # write transaction to refresh it. Authentication is otherwise a write
        # on every request, including pure reads, which turns every polling
        # reader into a writer competing for SQLite's single write path.
        self.liveness_refresh_seconds = liveness_refresh_seconds
        self._roe_operation_identity: ContextVar[
            tuple[str, str, bool] | None
        ] = ContextVar(
            f"strugglebus_roe_operation_identity_{id(self)}",
            default=None,
        )
        self._bootstrap_identity: ContextVar[
            tuple[str, str, Callable[[], datetime]] | None
        ] = ContextVar(f"strugglebus_bootstrap_{id(self)}", default=None)
        self._operator_actor: ContextVar[LifecycleActor | None] = ContextVar(
            f"strugglebus_operator_{id(self)}", default=None,
        )

    def begin_bootstrap_operation(
        self, agent_id: str, credential_id: str, *,
        clock: Callable[[], datetime] = utc_now,
    ) -> Token[tuple[str, str, Callable[[], datetime]] | None]:
        return self._bootstrap_identity.set((agent_id, credential_id, clock))

    def end_bootstrap_operation(
        self, token: Token[tuple[str, str, Callable[[], datetime]] | None],
    ) -> None:
        self._bootstrap_identity.reset(token)

    def begin_operator_operation(self, actor: LifecycleActor) -> Token[LifecycleActor | None]:
        _validate_actor(actor, operator_only=True)
        return self._operator_actor.set(actor)

    def end_operator_operation(self, token: Token[LifecycleActor | None]) -> None:
        self._operator_actor.reset(token)

    def require_bootstrap_identity(
        self, agent_id: str, credential_id: str, *, checked_at: datetime,
    ) -> None:
        """Validate generated bootstrap replies as well as database-backed ones."""
        with self._read_transaction() as connection:
            _require_live_credential(
                connection, agent_id, credential_id, checked_at=checked_at,
            )

    def begin_roe_operation(
        self,
        agent_id: str,
        credential_id: str,
        *,
        require_receipt: bool,
    ) -> Token[tuple[str, str, bool] | None]:
        return self._roe_operation_identity.set(
            (agent_id, credential_id, require_receipt)
        )

    def end_roe_operation(
        self,
        token: Token[tuple[str, str, bool] | None],
    ) -> None:
        self._roe_operation_identity.reset(token)

    def _require_enforced_roe_receipt(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        actor = self._operator_actor.get()
        if actor is not None:
            _validate_actor(actor, operator_only=True)
            # Deliberately no freeze gate here. This runs on every transaction,
            # so gating it blanket-denied the entire operator plane while
            # frozen - which is why the console returned 503 for every page and
            # the freeze prevented the very revocation it exists to enable.
            # Operations that create or redeem access keep their own explicit
            # gates, so minting stays denied while reads and containment work.
        bootstrap = self._bootstrap_identity.get()
        if bootstrap is not None:
            agent_id, credential_id, clock = bootstrap
            _require_live_credential(
                connection, agent_id, credential_id, checked_at=clock(),
            )
        identity = self._roe_operation_identity.get()
        if identity is None:
            return
        agent_id, credential_id, require_receipt = identity
        _require_active_credential(connection, agent_id, credential_id)
        if require_receipt and (
            _effective_roe_from_connection(
                connection,
                agent_id,
                credential_id,
            ).acknowledgement_status
            != "current"
        ):
            raise RoeAcknowledgementRequiredError(
                "current rules of engagement receipt required"
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if not self.database_path.parent.is_dir():
            raise StorageError("database parent directory does not exist")
        try:
            connection = sqlite3.connect(
                self.database_path,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = NORMAL")
            yield connection
        except sqlite3.Error as error:
            raise StorageError("SQLite operation failed") from error
        finally:
            if "connection" in locals():
                connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._require_enforced_roe_receipt(connection)
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            try:
                connection.execute("BEGIN")
                self._require_enforced_roe_receipt(connection)
                yield connection
            finally:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")

    def initialize(self) -> int:
        with self._connection() as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise StorageError("SQLite WAL mode could not be enabled")
            version = migrate_database(
                connection,
                database_path=self.database_path,
                backup_dir=self.backup_dir,
            )
            _access_freeze_from_connection(connection)
            return version

    def check_readiness(self) -> None:
        with self._transaction() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version != LATEST_SCHEMA_VERSION:
                raise StorageError("database schema is not current")
            _access_freeze_from_connection(connection)
            row = connection.execute("SELECT 1").fetchone()
            if row is None or row[0] != 1:
                raise StorageError("database readiness query failed")
