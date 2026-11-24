from __future__ import annotations

import hmac
from datetime import datetime

from strugglebus.errors import StorageError
from strugglebus.models import AccessFreezeState
from strugglebus.store._common import (
    _DUMMY_KEY_HASH,
    _access_freeze_from_connection,
    _format_utc,
    _validate_access_freeze_actor,
)


class AccessFreezeMixin:
    def get_access_freeze(self) -> AccessFreezeState:
        with self._read_transaction() as connection:
            return _access_freeze_from_connection(connection)

    def set_access_freeze(
        self,
        *,
        frozen: bool,
        reason: str,
        changed_at: datetime,
        actor_type: str = "system",
        actor_id: str = "system:direct-store",
    ) -> tuple[AccessFreezeState, bool]:
        if not isinstance(frozen, bool):
            raise StorageError("agent access transition is invalid")
        _validate_access_freeze_actor(actor_type, actor_id)
        transition = "freeze" if frozen else "unfreeze"
        timestamp = _format_utc(changed_at)
        with self._transaction() as connection:
            current = _access_freeze_from_connection(connection)
            if current.frozen == frozen:
                return current, False
            updated = connection.execute(
                """
                UPDATE agent_access_state
                SET frozen = ?, transition = ?, changed_at = ?, reason = ?
                WHERE singleton = 1
                """,
                (int(frozen), transition, timestamp, reason),
            )
            if updated.rowcount != 1:
                raise StorageError("agent access state could not be updated")
            connection.execute(
                """
                INSERT INTO agent_access_audit (
                    transition, changed_at, reason, actor_type, actor_id
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (transition, timestamp, reason, actor_type, actor_id),
            )
            state = _access_freeze_from_connection(connection)
        return state, True

    def clear_access_freeze_for_mobile(
        self,
        *,
        reason: str,
        changed_at: datetime,
        device_id: str,
        credential_id: str,
        candidate_grant_digest: str,
    ) -> tuple[AccessFreezeState, bool] | None:
        """Atomically revalidate a device's two proofs and clear the freeze."""

        timestamp = _format_utc(changed_at)
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT g.id, g.secret_hash
                FROM mobile_devices AS d
                JOIN mobile_device_credentials AS c
                  ON c.device_id = d.id AND c.id = ?
                JOIN mobile_write_grants AS g ON g.device_id = d.id
                WHERE d.id = ? AND d.status = 'enabled'
                  AND c.status = 'active' AND g.status = 'active'
                """,
                (credential_id, device_id),
            ).fetchone()
            stored_digest = _DUMMY_KEY_HASH if row is None else row["secret_hash"]
            if (
                not hmac.compare_digest(candidate_grant_digest, stored_digest)
                or row is None
            ):
                return None
            connection.execute(
                "UPDATE mobile_write_grants SET last_used_at = ? WHERE id = ?",
                (timestamp, row["id"]),
            )
            current = _access_freeze_from_connection(connection)
            if not current.frozen:
                return current, False
            updated = connection.execute(
                """
                UPDATE agent_access_state
                SET frozen = 0, transition = 'unfreeze', changed_at = ?, reason = ?
                WHERE singleton = 1 AND frozen = 1
                """,
                (timestamp, reason),
            )
            if updated.rowcount != 1:
                raise StorageError("agent access state could not be updated")
            connection.execute(
                """
                INSERT INTO agent_access_audit (
                    transition, changed_at, reason, actor_type, actor_id
                )
                VALUES ('unfreeze', ?, ?, 'remote-admin', ?)
                """,
                (timestamp, reason, f"device:{device_id}"),
            )
            return _access_freeze_from_connection(connection), True
