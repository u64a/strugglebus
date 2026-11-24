from __future__ import annotations

from datetime import datetime

from strugglebus.errors import DuplicateAgentNameError
from strugglebus.store._common import _format_utc, _require_agent_access


class SatelliteSiteMixin:
    def create_satellite_site(
        self,
        *,
        site_id: str,
        label: str,
        cert_sha256: str,
        cert_expires_at: datetime,
        created_at: datetime,
        actor_id: str,
    ) -> None:
        """Record a newly issued site certificate.

        Admitting a site restores a path to the agent plane, so the freeze read
        and the insert share one write transaction, as enrollment does.
        """

        with self._transaction() as connection:
            _require_agent_access(connection)
            existing = connection.execute(
                "SELECT 1 FROM satellite_sites WHERE label = ?", (label,),
            ).fetchone()
            if existing is not None:
                raise DuplicateAgentNameError("site label is already registered")
            connection.execute(
                """
                INSERT INTO satellite_sites (
                    id, label, cert_sha256, cert_expires_at, status,
                    created_at, created_by
                )
                VALUES (?, ?, ?, ?, 'enabled', ?, ?)
                """,
                (
                    site_id, label, cert_sha256, _format_utc(cert_expires_at),
                    _format_utc(created_at), actor_id,
                ),
            )

    def list_satellite_sites(self) -> tuple[dict[str, object], ...]:
        with self._read_transaction() as connection:
            rows = connection.execute(
                """
                SELECT id, label, status, cert_expires_at, created_at,
                       revoked_at, revocation_reason
                FROM satellite_sites
                ORDER BY label
                """
            ).fetchall()
        return tuple(dict(row) for row in rows)

    def revoke_satellite_site(
        self,
        *,
        site_id: str,
        reason: str,
        actor_id: str,
        revoked_at: datetime,
    ) -> bool:
        """Terminally revoke a site. Allowed while frozen: it only removes access."""

        with self._transaction() as connection:
            updated = connection.execute(
                """
                UPDATE satellite_sites
                SET status = 'revoked', revoked_at = ?, revoked_by = ?,
                    revocation_reason = ?
                WHERE id = ? AND status = 'enabled'
                """,
                (_format_utc(revoked_at), actor_id, reason, site_id),
            )
            return updated.rowcount == 1

    def satellite_site_admits(self, cert_sha256: str) -> bool:
        with self._read_transaction() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM satellite_sites
                WHERE cert_sha256 = ? AND status = 'enabled'
                """,
                (cert_sha256,),
            ).fetchone()
        return row is not None

    def satellite_site_label(self, cert_sha256: str) -> str | None:
        with self._read_transaction() as connection:
            row = connection.execute(
                """
                SELECT label FROM satellite_sites
                WHERE cert_sha256 = ? AND status = 'enabled'
                """,
                (cert_sha256,),
            ).fetchone()
        return None if row is None else str(row["label"])

    def replace_satellite_site_cert(
        self,
        *,
        current_sha256: str,
        cert_sha256: str,
        cert_expires_at: datetime,
    ) -> bool:
        """Swap a site onto its renewed certificate; the old one stops admitting.

        Renewal keeps a path to the agent plane open, so it is refused while
        frozen like the original admission.
        """

        with self._transaction() as connection:
            _require_agent_access(connection)
            updated = connection.execute(
                """
                UPDATE satellite_sites
                SET cert_sha256 = ?, cert_expires_at = ?
                WHERE cert_sha256 = ? AND status = 'enabled'
                """,
                (cert_sha256, _format_utc(cert_expires_at), current_sha256),
            )
            return updated.rowcount == 1
