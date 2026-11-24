from __future__ import annotations

from datetime import datetime

from strugglebus.errors import (
    MessageClaimConflictError,
    MessageClaimNotFoundError,
    MessageNotClaimableError,
    MessageNotFoundError,
    StorageError,
)
from strugglebus.models import MessageClaim
from strugglebus.store._common import (
    _format_utc,
    _require_active_agent,
    _select_claim,
)


class TaskClaimsMixin:
    def claim_message(
        self,
        *,
        message_seq: int,
        agent_id: str,
        claimed_at: datetime,
    ) -> tuple[MessageClaim, bool]:
        """Claim a task message; returns the claim and whether it is new."""

        with self._transaction() as connection:
            _require_active_agent(connection, agent_id)
            target = connection.execute(
                "SELECT kind FROM messages WHERE seq = ?", (message_seq,),
            ).fetchone()
            if target is None:
                raise MessageNotFoundError("message was not found")
            if target["kind"] != "task":
                raise MessageNotClaimableError("only task messages can be claimed")
            existing = _select_claim(connection, message_seq)
            if existing is not None and connection.execute(
                """
                SELECT 1 FROM agents WHERE id = ?
                AND (revoked_at IS NOT NULL OR blocked_at IS NOT NULL)
                """,
                (existing.agent_id,),
            ).fetchone() is not None:
                # A claim held by an agent that can no longer act is abandoned.
                connection.execute(
                    "DELETE FROM message_claims WHERE message_seq = ?", (message_seq,),
                )
                existing = None
            if existing is not None:
                if existing.agent_id == agent_id:
                    return existing, False
                raise MessageClaimConflictError(
                    "message is claimed by another agent", existing
                )
            connection.execute(
                """
                INSERT INTO message_claims (message_seq, agent_id, claimed_at)
                VALUES (?, ?, ?)
                """,
                (message_seq, agent_id, _format_utc(claimed_at)),
            )
            claim = _select_claim(connection, message_seq)
        if claim is None:
            raise StorageError("created claim could not be read back")
        return claim, True

    def get_message_claim(self, *, message_seq: int) -> MessageClaim:
        with self._read_transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM messages WHERE seq = ?", (message_seq,),
            ).fetchone() is None:
                raise MessageNotFoundError("message was not found")
            claim = _select_claim(connection, message_seq)
        if claim is None:
            raise MessageClaimNotFoundError("message is not claimed")
        return claim

    def release_message_claim(self, *, message_seq: int, agent_id: str) -> None:
        with self._transaction() as connection:
            _require_active_agent(connection, agent_id)
            claim = _select_claim(connection, message_seq)
            if claim is None:
                raise MessageClaimNotFoundError("message is not claimed")
            if claim.agent_id != agent_id:
                raise MessageClaimConflictError(
                    "only the claimant can release a claim", claim
                )
            connection.execute(
                "DELETE FROM message_claims WHERE message_seq = ? AND agent_id = ?",
                (message_seq, agent_id),
            )
