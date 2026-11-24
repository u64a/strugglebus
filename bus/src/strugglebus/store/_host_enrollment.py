from __future__ import annotations

import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime

from strugglebus.errors import (
    CredentialConflictError,
    CredentialLimitError,
    DuplicateAgentNameError,
    EnrollmentExpiredError,
    EnrollmentInvalidError,
)
from strugglebus.models import LifecycleActor
from strugglebus.store._common import (
    _DUMMY_KEY_HASH,
    _canonical_request_id,
    _format_utc,
    _parse_utc,
    _require_agent_access,
    _validate_actor,
)

#: How many unredeemed codes may be outstanding at once. Codes last minutes,
#: so reaching this means something is minting in a loop.
MAX_PENDING_HOST_ENROLLMENTS = 32


@dataclass(frozen=True, slots=True)
class RedeemedHostEnrollment:
    """What redeeming a host code produced. ``created`` is false for a repeat."""

    spn_id: str
    name: str
    created: bool


@dataclass(frozen=True, slots=True)
class HostEnrollmentRecord:
    """Where a host's service principal came from, for the operator to check."""

    spn_id: str
    host_prefix: str
    redeem_request_id: str
    redeemed_from: str
    redeemed_at: datetime


def _spn_named(connection, name: str):
    return connection.execute(
        "SELECT id FROM spn_principals WHERE name = ?", (name,),
    ).fetchone()


def _issue_host_credential(
    connection, *, spn_id: str, credential_id: str, secret_hash: str, timestamp: str,
) -> None:
    """Make ``credential_id`` the host principal's only working credential."""

    connection.execute(
        """
        UPDATE spn_credentials
        SET status = 'revoked', revoked_at = ?, version = version + 1
        WHERE spn_id = ? AND status = 'active'
        """,
        (timestamp, spn_id),
    )
    connection.execute(
        """
        INSERT INTO spn_credentials (
            id, spn_id, kind, secret_hash, status, issuance_request_id, created_at
        )
        VALUES (?, ?, 'sbsp1', ?, 'active', ?, ?)
        """,
        # The host's request id is kept on the enrollment. A credential's
        # issuance id must be unique across every credential, so it is the
        # bus's own.
        (credential_id, spn_id, secret_hash, str(uuid.uuid4()), timestamp),
    )


def _audit_host_principal(
    connection, *, event: str, spn_id: str, credential_id: str, row,
    request_id: str, source: str, timestamp: str,
) -> None:
    connection.execute(
        """
        INSERT INTO spn_audit (
            id, event_type, spn_id, credential_id, actor_type, actor_id,
            reason, request_id, occurred_at, details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()), event, spn_id, credential_id,
            # The redeemer holds no identity of its own. The decision to admit
            # this host was the operator's, when they minted the code.
            row["actor_type"], row["actor_id"],
            "host enrollment code redeemed", request_id, timestamp,
            json.dumps(
                {"host_enrollment": row["id"], "redeemed_from": source},
                ensure_ascii=True, separators=(",", ":"),
            ),
        ),
    )


class HostEnrollmentMixin:
    def create_host_enrollment(
        self,
        *,
        enrollment_id: str,
        secret_hash: str,
        host_prefix: str,
        request_id: str,
        reason: str,
        actor: LifecycleActor,
        created_at: datetime,
        expires_at: datetime,
    ) -> bool:
        """Mint one single-use code for exactly one host prefix.

        Returns false when this request id already minted a code: the code was
        shown once and cannot be shown again. Minting for a prefix that has an
        unredeemed code replaces that code, so a host has at most one.
        """

        _validate_actor(actor)
        request_id = _canonical_request_id(request_id)
        timestamp = _format_utc(created_at)
        with self._transaction() as connection:
            _validate_actor(actor)
            _require_agent_access(connection)
            earlier = connection.execute(
                "SELECT host_prefix FROM host_enrollments WHERE mint_request_id = ?",
                (request_id,),
            ).fetchone()
            if earlier is not None:
                if earlier["host_prefix"] != host_prefix:
                    raise CredentialConflictError("request id is already in use")
                return False
            if _spn_named(connection, host_prefix) is not None:
                raise DuplicateAgentNameError("host name is already registered")
            connection.execute(
                """
                UPDATE host_enrollments SET status = 'revoked', revoked_at = ?
                WHERE status = 'pending' AND (host_prefix = ? OR expires_at <= ?)
                """,
                (timestamp, host_prefix, timestamp),
            )
            pending = connection.execute(
                "SELECT COUNT(*) FROM host_enrollments WHERE status = 'pending'",
            ).fetchone()[0]
            if int(pending) >= MAX_PENDING_HOST_ENROLLMENTS:
                raise CredentialLimitError("too many host codes are waiting to be used")
            connection.execute(
                """
                INSERT INTO host_enrollments (
                    id, secret_hash, host_prefix, status, mint_request_id,
                    actor_type, actor_id, reason, created_at, expires_at
                )
                VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
                """,
                (
                    enrollment_id, secret_hash, host_prefix, request_id,
                    actor.actor_type, actor.actor_id, reason, timestamp,
                    _format_utc(expires_at),
                ),
            )
        return True

    def redeem_host_enrollment(
        self,
        *,
        enrollment_id: str,
        candidate_digest: str,
        request_id: str,
        source: str,
        spn_id: str,
        credential_id: str,
        secret_hash: str,
        redeemed_at: datetime,
    ) -> RedeemedHostEnrollment:
        """Exchange a host code for the host's own service principal.

        Nothing about a code is disclosed to a caller who does not hold it: an
        unknown id and a wrong secret are refused identically, and "expired"
        or "name taken" are only ever said to someone who presented the right
        secret.
        """

        request_id = _canonical_request_id(request_id)
        timestamp = _format_utc(redeemed_at)
        with self._transaction() as connection:
            _require_agent_access(connection)
            row = connection.execute(
                "SELECT * FROM host_enrollments WHERE id = ?", (enrollment_id,),
            ).fetchone()
            stored = _DUMMY_KEY_HASH if row is None else row["secret_hash"]
            if not hmac.compare_digest(stored, candidate_digest) or row is None:
                raise EnrollmentInvalidError("host code is not valid")
            if row["status"] == "redeemed":
                return self._repeat_host_redemption(
                    connection, row, request_id=request_id, source=source,
                    credential_id=credential_id, secret_hash=secret_hash,
                    timestamp=timestamp,
                )
            if row["status"] != "pending":
                raise EnrollmentInvalidError("host code is no longer available")
            if timestamp >= row["expires_at"]:
                raise EnrollmentExpiredError("host code has expired")
            prefix = row["host_prefix"]
            if _spn_named(connection, prefix) is not None:
                raise DuplicateAgentNameError("host name is already registered")
            connection.execute(
                """
                INSERT INTO spn_principals (
                    id, name, agent_name_prefix, status, created_at
                )
                VALUES (?, ?, ?, 'enabled', ?)
                """,
                (spn_id, prefix, prefix, timestamp),
            )
            _issue_host_credential(
                connection, spn_id=spn_id, credential_id=credential_id,
                secret_hash=secret_hash, timestamp=timestamp,
            )
            connection.execute(
                """
                UPDATE host_enrollments
                SET status = 'redeemed', redeemed_at = ?, redeem_request_id = ?,
                    redeemed_from = ?, spn_id = ?
                WHERE id = ? AND status = 'pending'
                """,
                (timestamp, request_id, source, spn_id, enrollment_id),
            )
            _audit_host_principal(
                connection, event="created", spn_id=spn_id,
                credential_id=credential_id, row=row, request_id=request_id,
                source=source, timestamp=timestamp,
            )
            return RedeemedHostEnrollment(spn_id=spn_id, name=prefix, created=True)

    @staticmethod
    def _repeat_host_redemption(
        connection, row, *, request_id: str, source: str, credential_id: str,
        secret_hash: str, timestamp: str,
    ) -> RedeemedHostEnrollment:
        """The same host asking again because its first answer was lost.

        Only a hash of a credential is kept, so the first cannot be returned.
        It is replaced instead, which leaves the host with one working
        credential either way.
        """

        if (
            not hmac.compare_digest(row["redeem_request_id"], request_id)
            or timestamp >= row["expires_at"]
        ):
            raise EnrollmentInvalidError("host code is no longer available")
        spn = connection.execute(
            "SELECT status FROM spn_principals WHERE id = ?", (row["spn_id"],),
        ).fetchone()
        if spn is None or spn["status"] != "enabled":
            raise EnrollmentInvalidError("host code is no longer available")
        _issue_host_credential(
            connection, spn_id=row["spn_id"], credential_id=credential_id,
            secret_hash=secret_hash, timestamp=timestamp,
        )
        connection.execute(
            "UPDATE spn_principals SET version = version + 1 WHERE id = ?",
            (row["spn_id"],),
        )
        _audit_host_principal(
            connection, event="rotated", spn_id=row["spn_id"],
            credential_id=credential_id, row=row, request_id=request_id,
            source=source, timestamp=timestamp,
        )
        return RedeemedHostEnrollment(
            spn_id=row["spn_id"], name=row["host_prefix"], created=False,
        )

    def host_enrollment_records(self) -> dict[str, HostEnrollmentRecord]:
        """Every service principal that a host code created, by principal id."""

        with self._read_transaction() as connection:
            rows = connection.execute(
                """
                SELECT spn_id, host_prefix, redeem_request_id, redeemed_from,
                       redeemed_at
                FROM host_enrollments WHERE status = 'redeemed'
                """,
            ).fetchall()
        return {
            row["spn_id"]: HostEnrollmentRecord(
                spn_id=row["spn_id"],
                host_prefix=row["host_prefix"],
                redeem_request_id=row["redeem_request_id"],
                redeemed_from=row["redeemed_from"],
                redeemed_at=_parse_utc(row["redeemed_at"]),
            )
            for row in rows
        }
