from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from strugglebus.errors import CredentialConflictError, StorageError
from strugglebus.models import LifecycleActor
from strugglebus.store._common import _format_utc, _parse_utc, _validate_actor


@dataclass(frozen=True, slots=True)
class SiteDocument:
    """Signed bytes the bus holds for a site. The bus never reads them."""

    name: str
    serial: int
    body: bytes
    signature: str
    signer_fingerprint: str
    stored_at: datetime


def _document_from_row(row) -> SiteDocument:
    stored_at = _parse_utc(row["stored_at"])
    if stored_at is None:
        raise StorageError("database contains a site document without stored_at")
    return SiteDocument(
        name=row["name"],
        serial=int(row["serial"]),
        body=bytes(row["body"]),
        signature=row["signature"],
        signer_fingerprint=row["signer_fingerprint"],
        stored_at=stored_at,
    )


class SiteDocumentMixin:
    def store_site_document(
        self,
        *,
        name: str,
        serial: int,
        body: bytes,
        signature: str,
        signer_fingerprint: str,
        reason: str,
        actor: LifecycleActor,
        stored_at: datetime,
    ) -> SiteDocument:
        """Replace a site's document with one whose serial is higher.

        This is deliberately allowed while agent access is frozen. Publishing a
        fleet that removes a coordinator is something an operator may need to
        do during the incident the freeze was declared for.
        """

        _validate_actor(actor)
        timestamp = _format_utc(stored_at)
        with self._transaction() as connection:
            _validate_actor(actor)
            current = connection.execute(
                "SELECT serial FROM site_documents WHERE name = ?", (name,),
            ).fetchone()
            if current is not None and serial <= int(current["serial"]):
                raise CredentialConflictError(
                    f"the stored document has serial {int(current['serial'])}; "
                    "a new one must be higher"
                )
            values = (
                serial, body, signature, signer_fingerprint, timestamp,
                actor.actor_type, actor.actor_id, reason,
            )
            if current is None:
                connection.execute(
                    """
                    INSERT INTO site_documents (
                        serial, body, signature, signer_fingerprint, stored_at,
                        actor_type, actor_id, reason, name
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*values, name),
                )
            else:
                connection.execute(
                    """
                    UPDATE site_documents
                    SET serial = ?, body = ?, signature = ?, signer_fingerprint = ?,
                        stored_at = ?, actor_type = ?, actor_id = ?, reason = ?
                    WHERE name = ?
                    """,
                    (*values, name),
                )
            connection.execute(
                """
                INSERT INTO site_document_audit (
                    name, serial, body_sha256, signer_fingerprint, actor_type,
                    actor_id, reason, occurred_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name, serial, hashlib.sha256(body).hexdigest(),
                    signer_fingerprint, actor.actor_type, actor.actor_id, reason,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM site_documents WHERE name = ?", (name,),
            ).fetchone()
        return _document_from_row(row)

    def get_site_document(self, name: str) -> SiteDocument | None:
        with self._read_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM site_documents WHERE name = ?", (name,),
            ).fetchone()
        return None if row is None else _document_from_row(row)
