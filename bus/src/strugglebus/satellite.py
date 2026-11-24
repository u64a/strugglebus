"""Satellite sites: remote machines admitted to the agent plane by certificate.

A site is admitted, not authenticated. Its certificate lets a connection reach
the satellite Caddy site at all; the agents behind it still present their own
credentials, so a site grants no board authority and is never a principal.
The bus signs site certificates with its own CA. The site's private key is
generated on the site and never seen here, so joining needs no network route
that answers before a certificate exists: the operator carries a join request
in and a site bundle out.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from strugglebus.config import AppConfig
from strugglebus.errors import (
    ConfigurationError,
    CredentialConflictError,
    DomainValidationError,
)
from strugglebus.store import SQLiteStore

#: Set only by the satellite Caddy site, from the client certificate it
#: verified. Its presence can only add refusals, so a LAN client sending it
#: gains nothing and the LAN site does not need to strip it.
SITE_CERT_HEADER = "x-strugglebus-satellite-cert"
JOIN_PREFIX = "sb-join-1."
BUNDLE_PREFIX = "sb-site-1."
MAX_JOIN_REQUEST_CHARS = 4096
_CA_CERT_MAX_BYTES = 64 * 1024


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def certificate_sha256(certificate: x509.Certificate) -> str:
    """The digest Caddy reports for a verified client certificate."""

    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()


def site_fingerprint(value: str | bytes) -> str | None:
    """Normalise the header value; anything but a SHA-256 digest is refused."""

    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    value = value.strip().lower()
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
        return value
    return None


def encode_join_request(csr: x509.CertificateSigningRequest) -> str:
    return JOIN_PREFIX + _b64url(csr.public_bytes(serialization.Encoding.DER))


def parse_join_request(text: str) -> x509.CertificateSigningRequest:
    """Accept only a self-signed P-256 request. Its subject is ignored."""

    text = "".join(text.split())
    if not text.startswith(JOIN_PREFIX) or len(text) > MAX_JOIN_REQUEST_CHARS:
        raise DomainValidationError("not a satellite join request")
    try:
        csr = x509.load_der_x509_csr(_unb64url(text[len(JOIN_PREFIX):]))
        key = csr.public_key()
        valid = csr.is_signature_valid
    except (ValueError, binascii.Error, InvalidSignature):
        raise DomainValidationError("not a satellite join request") from None
    if not valid:
        raise DomainValidationError("the join request signature is invalid")
    curve = getattr(key, "curve", None)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(curve, ec.SECP256R1):
        raise DomainValidationError("site keys must be P-256")
    return csr


def parse_site_bundle(text: str) -> dict[str, object]:
    """Decode a site bundle. The satellite trusts only the CA it carries."""

    text = "".join(text.split())
    if not text.startswith(BUNDLE_PREFIX) or len(text) > 64 * 1024:
        raise DomainValidationError("not a satellite site bundle")
    try:
        bundle = json.loads(_unb64url(text[len(BUNDLE_PREFIX):]))
    except (ValueError, binascii.Error):
        raise DomainValidationError("not a satellite site bundle") from None
    fields = {"version", "site", "hostname", "port", "ca_pem", "cert_pem", "expires_at"}
    if not isinstance(bundle, dict) or bundle.get("version") != 1 or not fields <= bundle.keys():
        raise DomainValidationError("not a satellite site bundle")
    return bundle


def release_directory() -> Path:
    """The running release: the directory holding this interpreter's venv."""

    return Path(sys.prefix).parent


def release_manifest(directory: Path | None = None) -> dict[str, object]:
    """Describe the running release's wheel and lock for satellite updates."""

    from strugglebus import __version__

    directory = release_directory() if directory is None else directory
    wheels = sorted(directory.glob("*.whl"))
    lock = directory / "requirements.lock"
    if len(wheels) != 1 or not lock.is_file():
        raise ConfigurationError("the running release files are unavailable")

    def described(path: Path) -> dict[str, object]:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return {"name": path.name, "sha256": digest.hexdigest(), "size": path.stat().st_size}

    return {
        "version": __version__,
        "wheel": described(wheels[0]),
        "requirements_lock": described(lock),
    }


@dataclass(frozen=True, slots=True)
class IssuedSite:
    site_id: str
    label: str
    cert_sha256: str
    expires_at: datetime
    bundle: str


class SiteAuthority:
    """The site CA: signs join requests into short-lived client certificates."""

    def __init__(
        self,
        config: AppConfig,
        ca_certificate: x509.Certificate,
        ca_key: ec.EllipticCurvePrivateKey,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.config = config
        self.ca_certificate = ca_certificate
        self._ca_key = ca_key
        self._clock = clock

    @classmethod
    def load(cls, config: AppConfig) -> SiteAuthority | None:
        """Load at startup. Returns None when satellites are not configured."""

        cert_path = config.satellite_ca_cert_path
        if not config.satellite_enabled or cert_path is None:
            return None
        try:
            with cert_path.open("rb") as stream:
                pem = stream.read(_CA_CERT_MAX_BYTES + 1)
        except OSError:
            raise ConfigurationError("satellite CA certificate is unavailable") from None
        try:
            if len(pem) > _CA_CERT_MAX_BYTES:
                raise ValueError
            certificate = x509.load_pem_x509_certificate(pem)
            key = serialization.load_pem_private_key(
                config.load_satellite_ca_key(), password=None,
            )
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except (ValueError, TypeError, x509.ExtensionNotFound):
            raise ConfigurationError("satellite CA material is invalid") from None
        if (
            not constraints.ca
            or not isinstance(key, ec.EllipticCurvePrivateKey)
            or key.public_key() != certificate.public_key()
        ):
            raise ConfigurationError("satellite CA key does not match its certificate")
        return cls(config, certificate, key)

    def issue(self, label: str, csr: x509.CertificateSigningRequest) -> IssuedSite:
        now = self._clock()
        expires_at = now + timedelta(days=self.config.satellite_cert_days)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
            .issuer_name(self.ca_certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(expires_at)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        pem = serialization.Encoding.PEM
        bundle = BUNDLE_PREFIX + _b64url(
            json.dumps(
                {
                    "version": 1,
                    "site": label,
                    "hostname": self.config.satellite_hostname,
                    "port": self.config.satellite_port,
                    "ca_pem": self.ca_certificate.public_bytes(pem).decode("ascii"),
                    "cert_pem": certificate.public_bytes(pem).decode("ascii"),
                    "expires_at": expires_at.astimezone(UTC).isoformat(),
                },
                separators=(",", ":"),
            ).encode("ascii")
        )
        return IssuedSite(
            site_id=str(uuid4()),
            label=label,
            cert_sha256=certificate_sha256(certificate),
            expires_at=expires_at,
            bundle=bundle,
        )


class SatelliteService:
    """Issue, list, revoke and admit satellite sites."""

    def __init__(
        self,
        store: SQLiteStore,
        authority: SiteAuthority | None,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.store = store
        self.authority = authority
        self._clock = clock

    def add_site(self, *, label: str, join_request: str, actor_id: str) -> IssuedSite:
        if self.authority is None:
            raise ConfigurationError("satellite sites are not configured")
        issued = self.authority.issue(label, parse_join_request(join_request))
        self.store.create_satellite_site(
            site_id=issued.site_id,
            label=label,
            cert_sha256=issued.cert_sha256,
            cert_expires_at=issued.expires_at,
            created_at=self._clock(),
            actor_id=actor_id,
        )
        return issued

    def renew_site(self, cert_sha256: str, *, join_request: str) -> IssuedSite:
        """Issue a fresh certificate to an admitted site, retiring its current one."""

        if self.authority is None:
            raise ConfigurationError("satellite sites are not configured")
        csr = parse_join_request(join_request)
        label = self.store.satellite_site_label(cert_sha256)
        if label is None:
            raise CredentialConflictError("satellite site is not admitted")
        issued = self.authority.issue(label, csr)
        if not self.store.replace_satellite_site_cert(
            current_sha256=cert_sha256,
            cert_sha256=issued.cert_sha256,
            cert_expires_at=issued.expires_at,
        ):
            raise CredentialConflictError("satellite site changed state")
        return issued

    def list_sites(self) -> tuple[dict[str, object], ...]:
        return self.store.list_satellite_sites()

    def revoke_site(self, site_id: str, *, reason: str, actor_id: str) -> bool:
        return self.store.revoke_satellite_site(
            site_id=site_id, reason=reason, actor_id=actor_id, revoked_at=self._clock(),
        )

    def admits(self, cert_sha256: str) -> bool:
        return self.store.satellite_site_admits(cert_sha256)
