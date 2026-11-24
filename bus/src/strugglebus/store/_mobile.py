from __future__ import annotations

import hmac
import json
import uuid
from datetime import datetime, timedelta
from collections.abc import Callable
from typing import Any

from strugglebus.errors import (
    DuplicateAgentNameError,
    CredentialConflictError,
    CredentialNotFoundError,
    EnrollmentInvalidError,
)
from strugglebus.models import MobileIdentity
from strugglebus.store._common import (
    _DUMMY_KEY_HASH,
    _format_utc,
    _parse_utc,
    _require_agent_access,
)


class MobileMixin:
    def create_mobile_enrollment(
        self,
        *,
        enrollment_id: str,
        secret_hash: str,
        device_label: str,
        created_at: datetime,
        expires_at: datetime,
        actor_type: str,
        actor_id: str,
        creation_reason: str,
    ) -> None:
        """Mint one single-use allowance bound to an exact device label.

        The freeze read and the insert share one write transaction, so a freeze
        committed while a form body is still arriving denies the mint without
        leaving a partial record.
        """

        with self._transaction() as connection:
            _require_agent_access(connection)
            existing = connection.execute(
                "SELECT 1 FROM mobile_devices WHERE label = ?", (device_label,),
            ).fetchone()
            if existing is not None:
                raise DuplicateAgentNameError(
                    "device label is already registered"
                )
            connection.execute(
                """
                INSERT INTO mobile_enrollments (
                    id, secret_hash, device_label, status, uses_allowed,
                    uses_remaining, created_at, expires_at, actor_type,
                    actor_id, creation_reason
                )
                VALUES (?, ?, ?, 'pending', 1, 1, ?, ?, ?, ?, ?)
                """,
                (
                    enrollment_id, secret_hash, device_label,
                    _format_utc(created_at), _format_utc(expires_at),
                    actor_type, actor_id, creation_reason,
                ),
            )

    def redeem_mobile_enrollment(
        self,
        *,
        enrollment_id: str,
        candidate_digest: str,
        device_id: str,
        credential_id: str,
        secret_hash: str,
        request_id: str,
        redeemed_at: datetime,
    ) -> MobileIdentity:
        """Consume one allowance and create exactly one device, atomically.

        Redemption cannot be idempotent: only a hash of the issued secret is
        retained, so a replay could never return it. A lost response is
        therefore terminal and recovered by the operator, not by retrying.
        """

        timestamp = _format_utc(redeemed_at)
        with self._transaction() as connection:
            _require_agent_access(connection)
            row = connection.execute(
                "SELECT id, secret_hash, device_label, status, uses_remaining, "
                "expires_at FROM mobile_enrollments WHERE id = ?",
                (enrollment_id,),
            ).fetchone()
            stored = _DUMMY_KEY_HASH if row is None else row["secret_hash"]
            if not hmac.compare_digest(stored, candidate_digest) or row is None:
                raise EnrollmentInvalidError("enrollment token is not valid")
            if row["status"] != "pending" or int(row["uses_remaining"]) <= 0:
                raise EnrollmentInvalidError(
                    "enrollment token is no longer available"
                )
            if timestamp >= row["expires_at"]:
                raise EnrollmentInvalidError("enrollment token has expired")
            label = row["device_label"]
            if connection.execute(
                "SELECT 1 FROM mobile_devices WHERE label = ?", (label,),
            ).fetchone() is not None:
                raise DuplicateAgentNameError(
                    "device label is already registered"
                )
            consumed = connection.execute(
                """
                UPDATE mobile_enrollments
                SET uses_remaining = 0, status = 'exhausted',
                    exhausted_at = ?, last_redeemed_at = ?, version = version + 1
                WHERE id = ? AND status = 'pending' AND uses_remaining = 1
                """,
                (timestamp, timestamp, enrollment_id),
            )
            if consumed.rowcount != 1:
                raise EnrollmentInvalidError("enrollment token was already redeemed")
            connection.execute(
                "INSERT INTO mobile_devices (id, label, status, created_at) "
                "VALUES (?, ?, 'enabled', ?)",
                (device_id, label, timestamp),
            )
            connection.execute(
                """
                INSERT INTO mobile_device_credentials (
                    id, device_id, kind, secret_hash, status, creation_method,
                    creation_reason, issuance_request_id, created_at
                )
                VALUES (?, ?, 'sbm1', ?, 'active', 'enrollment',
                        'self-registered through mobile enrollment', ?, ?)
                """,
                (credential_id, device_id, secret_hash, request_id, timestamp),
            )
            connection.execute(
                """
                INSERT INTO mobile_enrollment_redemptions (
                    request_id, enrollment_id, device_id, credential_id, redeemed_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (request_id, enrollment_id, device_id, credential_id, timestamp),
            )
            connection.execute(
                """
                INSERT INTO mobile_device_audit (
                    id, event_type, device_id, credential_id, actor_type,
                    actor_id, reason, request_id, occurred_at
                )
                VALUES (?, 'issued', ?, ?, 'system', 'mobile:enrollment',
                        'device enrolled', ?, ?)
                """,
                (str(uuid.uuid4()), device_id, credential_id, request_id, timestamp),
            )
            return MobileIdentity(
                device_id=device_id,
                device_label=label,
                credential_id=credential_id,
                credential_kind="sbm1",
            )

    def list_mobile_devices(self) -> tuple[dict[str, object], ...]:
        with self._read_transaction() as connection:
            rows = connection.execute(
                """
                SELECT d.id, d.label, d.status, d.created_at, d.last_seen_at,
                       d.revoked_at, d.version,
                       (SELECT COUNT(*) FROM mobile_device_credentials AS c
                        WHERE c.device_id = d.id AND c.status = 'active')
                       AS active_credentials,
                       (SELECT COUNT(*) FROM mobile_write_grants AS g
                        WHERE g.device_id = d.id AND g.status = 'active')
                       AS active_write_grants
                FROM mobile_devices AS d
                ORDER BY d.label
                """
            ).fetchall()
        return tuple(dict(row) for row in rows)

    def revoke_mobile_device(
        self,
        *,
        device_id: str,
        reason: str,
        actor_type: str,
        actor_id: str,
        revoked_at: datetime,
    ) -> bool:
        """Terminally revoke a device and every credential it holds.

        Revocation is the primary containment control for an operator-class
        read grant, so it revokes credentials in the same transaction rather
        than leaving a live key behind a disabled device.
        """

        timestamp = _format_utc(revoked_at)
        with self._transaction() as connection:
            updated = connection.execute(
                """
                UPDATE mobile_devices
                SET status = 'revoked', revoked_at = ?, revocation_reason = ?,
                    version = version + 1
                WHERE id = ? AND status = 'enabled'
                """,
                (timestamp, reason, device_id),
            )
            if updated.rowcount != 1:
                return False
            connection.execute(
                """
                UPDATE mobile_device_credentials
                SET status = 'revoked', revoked_at = ?, version = version + 1
                WHERE device_id = ? AND status = 'active'
                """,
                (timestamp, device_id),
            )
            # The write grant dies with the device, in the same transaction.
            # Containment is the whole justification for holding a second
            # secret on a handset: if revoking the device left a live grant
            # behind, the argument for storing a per-device secret instead of
            # the operator password would collapse.
            connection.execute(
                """
                UPDATE mobile_write_grants
                SET status = 'revoked', revoked_at = ?,
                    revocation_reason = ?, version = version + 1
                WHERE device_id = ? AND status = 'active'
                """,
                (timestamp, reason, device_id),
            )
            connection.execute(
                """
                INSERT INTO mobile_device_audit (
                    id, event_type, device_id, actor_type, actor_id,
                    reason, occurred_at
                )
                VALUES (?, 'revoked', ?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), device_id, actor_type, actor_id, reason, timestamp),
            )
            return True

    def replace_mobile_device(
        self,
        *,
        device_id: str,
        new_label: str,
        enrollment_id: str,
        secret_hash: str,
        created_at: datetime,
        expires_at: datetime,
        actor_type: str,
        actor_id: str,
        reason: str,
    ) -> str:
        """Revoke a device and mint its replacement's allowance, atomically.

        Modelled on the reconnect grant: the outgoing keys die at **issue**
        time, not at redemption, which is the property a lost handset needs.
        The replacement is a new device with a new label rather than a
        re-credentialed row, because a label is permanently reserved and
        reusing one would let history be silently reattributed.

        Returns the replaced device's label so the operator sees what was
        retired in the same response that shows the new code.
        """

        timestamp = _format_utc(created_at)
        with self._transaction() as connection:
            _require_agent_access(connection)
            row = connection.execute(
                "SELECT label FROM mobile_devices WHERE id = ? AND status = 'enabled'",
                (device_id,),
            ).fetchone()
            if row is None:
                raise CredentialConflictError("device is not available for replacement")
            previous_label = row["label"]
            if connection.execute(
                "SELECT 1 FROM mobile_devices WHERE label = ?", (new_label,),
            ).fetchone() is not None:
                raise DuplicateAgentNameError("device label is already registered")
            updated = connection.execute(
                """
                UPDATE mobile_devices
                SET status = 'revoked', revoked_at = ?, revocation_reason = ?,
                    version = version + 1
                WHERE id = ? AND status = 'enabled'
                """,
                (timestamp, reason, device_id),
            )
            if updated.rowcount != 1:
                raise CredentialConflictError("device is not available for replacement")
            connection.execute(
                """
                UPDATE mobile_device_credentials
                SET status = 'revoked', revoked_at = ?, version = version + 1
                WHERE device_id = ? AND status = 'active'
                """,
                (timestamp, device_id),
            )
            # A replacement retires the outgoing device's write grant with its
            # read credential. The successor establishes its own grant, which
            # keeps the rule that a grant is proved once per device and never
            # inherited.
            connection.execute(
                """
                UPDATE mobile_write_grants
                SET status = 'revoked', revoked_at = ?,
                    revocation_reason = ?, version = version + 1
                WHERE device_id = ? AND status = 'active'
                """,
                (timestamp, reason, device_id),
            )
            connection.execute(
                """
                INSERT INTO mobile_enrollments (
                    id, secret_hash, device_label, status, uses_allowed,
                    uses_remaining, created_at, expires_at, actor_type,
                    actor_id, creation_reason
                )
                VALUES (?, ?, ?, 'pending', 1, 1, ?, ?, ?, ?, ?)
                """,
                (
                    enrollment_id, secret_hash, new_label, timestamp,
                    _format_utc(expires_at), actor_type, actor_id, reason,
                ),
            )
            connection.execute(
                """
                INSERT INTO mobile_device_audit (
                    id, event_type, device_id, actor_type, actor_id, reason,
                    occurred_at, details_json
                )
                VALUES (?, 'replaced', ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), device_id, actor_type, actor_id, reason,
                    timestamp,
                    json.dumps(
                        {"replacement_label": new_label},
                        ensure_ascii=True, separators=(",", ":"),
                    ),
                ),
            )
            return previous_label

    def mobile_credential_is_active(self, credential_id: str) -> bool:
        with self._read_transaction() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM mobile_device_credentials AS c
                JOIN mobile_devices AS d ON d.id = c.device_id
                WHERE c.id = ? AND c.status = 'active' AND d.status = 'enabled'
                """,
                (credential_id,),
            ).fetchone()
        return row is not None

    def authenticate_mobile_credential(
        self,
        *,
        credential_id: str,
        candidate_digest: str,
        seen_at_factory: Callable[[], datetime],
    ) -> MobileIdentity | None:
        """Resolve a mobile credential to its device, or to nothing.

        The prefix that routed the caller here is not an authorisation
        decision: the identifier is resolved in the mobile credential table,
        and an unknown identifier still performs one constant-time comparison
        so a missing row and a wrong secret are indistinguishable.

        A recently refreshed liveness timestamp is left alone and the whole
        authentication resolves in a read transaction, mirroring the agent
        path. Monitors poll far harder than agents do, so without this every
        read competes with message creation for SQLite's single write path.
        The authorisation decision is identical either way; only the timestamp
        write is skipped.
        """

        def resolve(connection) -> tuple[Any | None, datetime | None]:
            row = connection.execute(
                """
                SELECT c.id, c.device_id, c.kind, c.secret_hash, c.status,
                       c.created_at, c.last_used_at, c.version,
                       d.label AS device_label, d.status AS device_status
                FROM mobile_device_credentials AS c
                JOIN mobile_devices AS d ON d.id = c.device_id
                WHERE c.id = ?
                """,
                (credential_id,),
            ).fetchone()
            stored_digest = _DUMMY_KEY_HASH if row is None else row["secret_hash"]
            if (
                not hmac.compare_digest(candidate_digest, stored_digest)
                or row is None
                or row["status"] != "active"
                or row["device_status"] != "enabled"
            ):
                return None, None
            return row, _parse_utc(row["last_used_at"])

        def identity(row) -> MobileIdentity:
            return MobileIdentity(
                device_id=row["device_id"],
                device_label=row["device_label"],
                credential_id=row["id"],
                credential_kind=row["kind"],
            )

        with self._read_transaction() as connection:
            row, last_used_at = resolve(connection)
            if row is None:
                return None
            if last_used_at is not None and (
                seen_at_factory() - last_used_at
                < timedelta(seconds=self.liveness_refresh_seconds)
            ):
                return identity(row)

        with self._transaction() as connection:
            row, _last_used_at = resolve(connection)
            if row is None:
                return None
            seen_at = _format_utc(seen_at_factory())
            connection.execute(
                "UPDATE mobile_device_credentials SET last_used_at = ? WHERE id = ?",
                (seen_at, row["id"]),
            )
            connection.execute(
                "UPDATE mobile_devices SET last_seen_at = ? WHERE id = ?",
                (seen_at, row["device_id"]),
            )
            return identity(row)

    def issue_mobile_write_grant(
        self,
        *,
        device_id: str,
        grant_id: str,
        secret_hash: str,
        request_id: str,
        reason: str,
        actor_type: str,
        actor_id: str,
        created_at: datetime,
    ) -> None:
        """Establish a device's write grant, retiring any predecessor.

        Establishing a grant proves the operator password once. It is a
        credential-creating operation, so it is refused while access is frozen:
        a freeze must never be a moment when new authority comes into
        existence, even authority the owner asked for.

        The predecessor is revoked in the same transaction rather than left to
        expire, so a device can never hold two write secrets and a re-established
        grant immediately invalidates whatever the old handset state held.
        """

        timestamp = _format_utc(created_at)
        with self._transaction() as connection:
            _require_agent_access(connection)
            device = connection.execute(
                "SELECT status FROM mobile_devices WHERE id = ?", (device_id,),
            ).fetchone()
            if device is None or device["status"] != "enabled":
                raise CredentialNotFoundError("device is not available for a write grant")
            connection.execute(
                """
                UPDATE mobile_write_grants
                SET status = 'revoked', revoked_at = ?,
                    revocation_reason = 'replaced by a newly established grant',
                    version = version + 1
                WHERE device_id = ? AND status = 'active'
                """,
                (timestamp, device_id),
            )
            connection.execute(
                """
                INSERT INTO mobile_write_grants (
                    id, device_id, kind, secret_hash, status,
                    issuance_request_id, creation_reason, created_at
                )
                VALUES (?, ?, 'sbmw1', ?, 'active', ?, ?, ?)
                """,
                (grant_id, device_id, secret_hash, request_id, reason, timestamp),
            )
            connection.execute(
                """
                INSERT INTO mobile_device_audit (
                    id, event_type, device_id, actor_type, actor_id,
                    reason, request_id, occurred_at
                )
                VALUES (?, 'write-grant-issued', ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), device_id, actor_type, actor_id,
                    reason, request_id, timestamp,
                ),
            )

    def verify_mobile_write_grant(
        self,
        *,
        device_id: str,
        candidate_digest: str,
        used_at: datetime,
    ) -> bool:
        """Confirm a device's write grant without leaking whether one exists.

        A device with no grant still costs one constant-time comparison, so a
        handset that never established one is indistinguishable from a wrong
        secret. Unlike the read credential this is not coalesced: writes are
        rare and individually consequential, so the used-at timestamp is
        recorded every time rather than sampled.
        """

        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT g.id, g.secret_hash
                FROM mobile_write_grants AS g
                JOIN mobile_devices AS d ON d.id = g.device_id
                WHERE g.device_id = ? AND g.status = 'active'
                  AND d.status = 'enabled'
                """,
                (device_id,),
            ).fetchone()
            stored_digest = _DUMMY_KEY_HASH if row is None else row["secret_hash"]
            if not hmac.compare_digest(candidate_digest, stored_digest) or row is None:
                return False
            connection.execute(
                "UPDATE mobile_write_grants SET last_used_at = ? WHERE id = ?",
                (_format_utc(used_at), row["id"]),
            )
            return True

    def create_mobile_action_confirmation(
        self,
        *,
        confirmation_id: str,
        device_id: str,
        action: str,
        target_kind: str,
        target_id: str,
        target_label: str,
        target_version: int,
        request_id: str,
        created_at: datetime,
        expires_at: datetime,
    ) -> None:
        """Bind one action to one target for one device, briefly.

        Deliberately allowed while frozen. A confirmation grants nothing on its
        own - it cannot be spent without the write grant - and the actions it
        can name are containment actions the owner may well need *during* a
        freeze. Refusing here would make the freeze block the response to the
        incident it was declared for.
        """

        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO mobile_action_confirmations (
                    id, device_id, action, target_kind, target_id,
                    target_label, target_version, status, request_id,
                    created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                """,
                (
                    confirmation_id, device_id, action, target_kind, target_id,
                    target_label, target_version, request_id,
                    _format_utc(created_at), _format_utc(expires_at),
                ),
            )

    def consume_mobile_action_confirmation(
        self,
        *,
        confirmation_id: str,
        device_id: str,
        action: str,
        target_id: str,
        consumed_at: datetime,
    ) -> dict[str, Any] | None:
        """Spend a confirmation, or refuse and leave it untouched.

        The action and target are matched here rather than trusted from the
        confirmation alone. A caller that displayed one action and spent a
        confirmation bound to another is refused outright instead of silently
        executing the bound one, so a mismatch cannot produce an audit record
        that is truthful about the wrong thing.

        Consumption is a single conditional UPDATE, so two concurrent requests
        cannot both spend it.
        """

        timestamp = _format_utc(consumed_at)
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT id, device_id, action, target_kind, target_id,
                       target_label, target_version, status, expires_at
                FROM mobile_action_confirmations
                WHERE id = ?
                """,
                (confirmation_id,),
            ).fetchone()
            if (
                row is None
                or row["device_id"] != device_id
                or row["action"] != action
                or row["target_id"] != target_id
                or row["status"] != "pending"
                or timestamp >= row["expires_at"]
            ):
                return None
            updated = connection.execute(
                """
                UPDATE mobile_action_confirmations
                SET status = 'consumed', consumed_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                (timestamp, confirmation_id),
            )
            if updated.rowcount != 1:
                return None
            return {
                "action": row["action"],
                "target_kind": row["target_kind"],
                "target_id": row["target_id"],
                "target_label": row["target_label"],
                "target_version": row["target_version"],
            }
