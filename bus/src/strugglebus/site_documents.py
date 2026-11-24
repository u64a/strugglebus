"""A store for a site's signed documents. The bus keeps and returns them; it never reads them.

Hosts verify a document against keys an administrator pinned on each host, and
refuse a serial that goes backwards. So a compromised bus can withhold a
document, but cannot forge one or roll one back.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from datetime import datetime

from strugglebus.errors import ConfigurationError
from strugglebus.models import LifecycleActor
from strugglebus.store import SQLiteStore, _audit_text, utc_now
from strugglebus.store._site_documents import SiteDocument

#: The documents a site may publish. One for now: the fleet.
DOCUMENT_NAMES = frozenset({"fleet"})
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_SIGNATURE_CHARACTERS = 4096
MAX_SERIAL = 2**53 - 1
_SIGNATURE = re.compile(
    r"\A-----BEGIN SSH SIGNATURE-----\n[A-Za-z0-9+/=\n]+\n-----END SSH SIGNATURE-----\n?\Z"
)
#: An OpenSSH key fingerprint, as `ssh-keygen -l` prints it. Recorded for the
#: audit trail only: the bus does not check that it matches the signature.
_FINGERPRINT = re.compile(r"\ASHA256:[A-Za-z0-9+/]{43}\Z")


def validate_document_name(name: str) -> str:
    if name not in DOCUMENT_NAMES:
        raise ConfigurationError("unknown site document")
    return name


def decode_document(encoded: str) -> bytes:
    """The exact bytes that were signed, from their base64 form."""

    try:
        body = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ConfigurationError("the document is not valid base64") from None
    if not 1 <= len(body) <= MAX_DOCUMENT_BYTES:
        raise ConfigurationError(
            f"a document is 1 to {MAX_DOCUMENT_BYTES} bytes"
        )
    return body


def _validate_signature(signature: str) -> str:
    normalized = signature.replace("\r\n", "\n") if isinstance(signature, str) else ""
    if (
        len(normalized) > MAX_SIGNATURE_CHARACTERS
        or _SIGNATURE.fullmatch(normalized) is None
    ):
        raise ConfigurationError("the signature is not an armored SSH signature")
    return normalized


def _validate_fingerprint(fingerprint: str) -> str:
    if fingerprint and _FINGERPRINT.fullmatch(fingerprint) is None:
        raise ConfigurationError("the signer fingerprint is not an SSH SHA256 fingerprint")
    return fingerprint


def _validate_serial(serial: int) -> int:
    if type(serial) is not int or not 1 <= serial <= MAX_SERIAL:
        raise ConfigurationError("a document serial is a whole number from 1")
    return serial


class SiteDocumentService:
    def __init__(
        self, store: SQLiteStore, *, clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.store = store
        self._clock = clock

    def publish(
        self,
        *,
        name: str,
        serial: int,
        body: bytes,
        signature: str,
        signer_fingerprint: str,
        reason: str,
        actor: LifecycleActor,
    ) -> SiteDocument:
        return self.store.store_site_document(
            name=validate_document_name(name),
            serial=_validate_serial(serial),
            body=body,
            signature=_validate_signature(signature),
            signer_fingerprint=_validate_fingerprint(signer_fingerprint),
            reason=_audit_text(reason),
            actor=actor,
            stored_at=self._clock(),
        )

    def read(self, name: str) -> SiteDocument | None:
        return self.store.get_site_document(validate_document_name(name))
