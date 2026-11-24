"""Bounded, digest-pinned publication of the operator's public LAN trust anchor."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import ssl
import time
from pathlib import Path

from strugglebus.errors import TrustAnchorError

MAX_BUNDLE_BYTES = 256 * 1024
_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s*(?P<body>[A-Za-z0-9+/=\s]+?)\s*"
    rb"-----END CERTIFICATE-----"
)


def _certificate_blocks(pem: bytes) -> list[bytes]:
    blocks: list[bytes] = []
    for match in _PEM_BLOCK.finditer(pem):
        try:
            der = base64.b64decode(
                re.sub(rb"\s+", b"", match.group("body")), validate=True
            )
        except (binascii.Error, ValueError):
            continue
        if der:
            blocks.append(der)
    return blocks


def _is_lowercase_sha256(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _read_bundle(candidate: Path, unavailable: str) -> bytes:
    try:
        if candidate.is_symlink() or not candidate.is_file():
            raise TrustAnchorError(unavailable)
        with candidate.open("rb") as bundle:
            return bundle.read(MAX_BUNDLE_BYTES + 1)
    except OSError:
        raise TrustAnchorError(unavailable) from None


def load_trust_anchor(path: str, expected_sha256: str) -> bytes | None:
    """Return a validated public CA, or None only for deliberate manual trust."""

    if not path and not expected_sha256:
        return None
    unavailable = "Configured LAN CA publication is unavailable; contact the operator."
    expected = expected_sha256
    if not _is_lowercase_sha256(expected):
        raise TrustAnchorError(unavailable)
    candidate = Path(path)
    if not path or not candidate.is_absolute():
        raise TrustAnchorError(unavailable)
    pem = _read_bundle(candidate, unavailable)
    return validate_trust_anchor(pem, expected)


def validate_trust_anchor(pem: bytes, expected_sha256: str) -> bytes:
    """Validate in-memory public CA data without creating a temporary file."""
    unavailable = "Configured LAN CA publication is unavailable; contact the operator."
    expected = expected_sha256
    if (
        len(pem) > MAX_BUNDLE_BYTES
        or re.fullmatch(r"[0-9a-f]{64}", expected) is None
    ):
        raise TrustAnchorError(unavailable)
    for der in _certificate_blocks(pem):
        if hashlib.sha256(der).hexdigest() == expected:
            anchor = ssl.DER_cert_to_PEM_cert(der)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            try:
                context.load_verify_locations(cadata=anchor)
                certificates = context.get_ca_certs()
                if len(certificates) != 1:
                    raise TrustAnchorError(unavailable)
                certificate = certificates[0]
                not_before = ssl.cert_time_to_seconds(certificate["notBefore"])
                not_after = ssl.cert_time_to_seconds(certificate["notAfter"])
            except (ssl.SSLError, ValueError, OverflowError):
                raise TrustAnchorError(unavailable) from None
            now = time.time()
            if not not_before <= now < not_after:
                raise TrustAnchorError(unavailable)
            return anchor.encode("ascii")
    raise TrustAnchorError(unavailable)


def der_base64(anchor: bytes) -> str:
    """Return the single certificate in a validated anchor as base64 DER.

    Used to carry the public root inside a device enrollment code, so a
    handset can pin it without first trusting an untrusted download.
    """

    blocks = _certificate_blocks(anchor)
    if len(blocks) != 1:
        raise TrustAnchorError(
            "Configured LAN CA publication is unavailable; contact the operator."
        )
    return base64.b64encode(blocks[0]).decode("ascii")


def fingerprint_display(expected_sha256: str) -> str:
    """Return the colon-grouped uppercase form operators see in tooling."""

    value = expected_sha256.strip().lower()
    return ":".join(
        value[index : index + 2].upper() for index in range(0, len(value), 2)
    )
