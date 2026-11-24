"""Stable agent identities and bounded API credential lifecycle."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import uuid
from collections.abc import Callable
from contextvars import Token
from datetime import datetime, timedelta

from strugglebus.config import (
    DEFAULT_CREDENTIAL_PENDING_SECONDS,
    DEFAULT_ENROLLMENT_TTL_SECONDS,
    DEFAULT_MAX_ACTIVE_CREDENTIALS,
    DEFAULT_MAX_ENROLLMENT_USES,
    DEFAULT_MAX_PENDING_CREDENTIALS,
    DEFAULT_SELF_ROTATIONS_PER_WINDOW,
    DEFAULT_SELF_ROTATION_WINDOW_SECONDS,
)
from strugglebus.errors import (
    ConfigurationError,
    DomainValidationError,
    EnrollmentInvalidError,
    CredentialNotFoundError,
)
from strugglebus.models import (
    Agent,
    AgentCredential,
    AgentEnrollment,
    AuthenticatedIdentity,
    CreatedAgent,
    IssuedCredential,
    IssuedEnrollment,
    IdentityCreationProvenancePage,
    RedeemedEnrollment,
    AgentLifecycleResult,
    AgentReconnectGrant,
    IssuedReconnectGrant,
    PreparedReconnectGrant,
    RedeemedReconnectGrant,
    LifecycleActor,
)
from strugglebus.service import normalize_name
from strugglebus.store import SQLiteStore, utc_now, _audit_text
from strugglebus.operator_auth import OperatorContext

LEGACY_CREDENTIAL_KIND = "legacy-sha256-v1"
SB1_CREDENTIAL_KIND = "sb1"
SB1_HASH_DOMAIN = b"strugglebus-agent-credential-v1\0"
ENROLLMENT_PREFIX = "sbe1_"
ENROLLMENT_HASH_DOMAIN = b"strugglebus-agent-enrollment-v1\0"
RECONNECT_PREFIX = "sbr1_"
RECONNECT_HASH_DOMAIN = b"strugglebus-agent-reconnect-v1\0"
MOBILE_CREDENTIAL_KIND = "sbm1"
MOBILE_PREFIX = "sbm1_"
MOBILE_HASH_DOMAIN = b"strugglebus-mobile-credential-v1\0"
MOBILE_ENROLLMENT_PREFIX = "sbme1_"
MOBILE_ENROLLMENT_HASH_DOMAIN = b"strugglebus-mobile-enrollment-v1\0"
MOBILE_WRITE_GRANT_KIND = "sbmw1"
MOBILE_WRITE_PREFIX = "sbmw1_"
MOBILE_WRITE_HASH_DOMAIN = b"strugglebus-mobile-write-grant-v1\0"
SPN_CREDENTIAL_KIND = "sbsp1"
SPN_CREDENTIAL_PREFIX = "sbsp1_"
SPN_CREDENTIAL_HASH_DOMAIN = b"strugglebus-spn-credential-v1\0"
SPN_ENROLLMENT_PREFIX = "sbse1_"
SPN_ENROLLMENT_HASH_DOMAIN = b"strugglebus-spn-enrollment-v1\0"
HOST_ENROLLMENT_PREFIX = "sbhe1_"
HOST_ENROLLMENT_HASH_DOMAIN = b"strugglebus-host-enrollment-v1\0"
MAX_CREDENTIAL_BYTES = 256
API_KEY_ENTROPY_BYTES = 32
#: Every credential-shaped prefix the parser recognises. A value carrying one
#: of these must parse as that kind or be refused outright: falling through to
#: the legacy hash would let one principal class be evaluated as another.
RESERVED_PREFIXES = (
    "sb1_",
    ENROLLMENT_PREFIX,
    RECONNECT_PREFIX,
    MOBILE_PREFIX,
    MOBILE_ENROLLMENT_PREFIX,
    MOBILE_WRITE_PREFIX,
    SPN_CREDENTIAL_PREFIX,
    SPN_ENROLLMENT_PREFIX,
    HOST_ENROLLMENT_PREFIX,
)
_SBHE1_PATTERN = re.compile(
    r"^sbhe1_(?P<lookup>[A-Za-z0-9_-]{22})_(?P<secret>[A-Za-z0-9_-]{43})$"
)
_SB1_PATTERN = re.compile(
    r"^sb1_(?P<lookup>[A-Za-z0-9_-]{22})_(?P<secret>[A-Za-z0-9_-]{43})$"
)
_SBE1_PATTERN = re.compile(
    r"^sbe1_(?P<lookup>[A-Za-z0-9_-]{22})_(?P<secret>[A-Za-z0-9_-]{43})$"
)
_SBR1_PATTERN = re.compile(
    r"^sbr1_(?P<lookup>[A-Za-z0-9_-]{22})_(?P<secret>[A-Za-z0-9_-]{43})$"
)
_SBM1_PATTERN = re.compile(
    r"^sbm1_(?P<lookup>[A-Za-z0-9_-]{22})_(?P<secret>[A-Za-z0-9_-]{43})$"
)
_SBME1_PATTERN = re.compile(
    r"^sbme1_(?P<lookup>[A-Za-z0-9_-]{22})_(?P<secret>[A-Za-z0-9_-]{43})$"
)
_SBSP1_PATTERN = re.compile(
    r"^sbsp1_(?P<lookup>[A-Za-z0-9_-]{22})_(?P<secret>[A-Za-z0-9_-]{43})$"
)
_SBSE1_PATTERN = re.compile(
    r"^sbse1_(?P<lookup>[A-Za-z0-9_-]{22})_(?P<secret>[A-Za-z0-9_-]{43})$"
)
#: A write grant carries no lookup of its own. The device is already proven by
#: the read credential on the same request, so a second identifier space would
#: add a way for the two to disagree about who is asking without adding any
#: security. The device identity is bound into the hash instead, which means a
#: grant lifted from one device cannot be replayed as another's.
_SBMW1_PATTERN = re.compile(r"^sbmw1_(?P<secret>[A-Za-z0-9_-]{43})$")


def _decode_unpadded(
    value: str, expected_bytes: int, *, canonical: bool = False,
) -> bytes | None:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        return None
    if len(decoded) != expected_bytes:
        return None
    if canonical and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        return None
    return decoded


def parse_credential(value: str) -> tuple[str, str | None, str] | None:
    """Return credential kind, public ID, and candidate verifier."""

    if not isinstance(value, str) or not value or len(value) > MAX_CREDENTIAL_BYTES:
        return None
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return None
    match = _SB1_PATTERN.fullmatch(value)
    if match is None:
        if value.startswith(RESERVED_PREFIXES):
            return None
        return (
            LEGACY_CREDENTIAL_KIND,
            None,
            hashlib.sha256(encoded).hexdigest(),
        )
    lookup = match.group("lookup")
    secret = _decode_unpadded(match.group("secret"), 32)
    if _decode_unpadded(lookup, 16) is None or secret is None:
        return None
    credential_id = f"cred_{lookup}"
    verifier = hashlib.sha256(
        SB1_HASH_DOMAIN + credential_id.encode("ascii") + b"\0" + secret
    ).hexdigest()
    return SB1_CREDENTIAL_KIND, credential_id, verifier


def mint_credential() -> tuple[str, str, str]:
    lookup = secrets.token_urlsafe(16)
    secret_part = secrets.token_urlsafe(32)
    secret = f"sb1_{lookup}_{secret_part}"
    parsed = parse_credential(secret)
    if parsed is None:
        raise RuntimeError("generated credential was invalid")
    kind, credential_id, verifier = parsed
    if kind != SB1_CREDENTIAL_KIND or credential_id is None:
        raise RuntimeError("generated credential had an invalid kind")
    return credential_id, verifier, secret


def parse_enrollment_token(value: str) -> tuple[str, str] | None:
    """Return the enrollment ID and candidate verifier for a token."""

    if not isinstance(value, str) or not value or len(value) > MAX_CREDENTIAL_BYTES:
        return None
    match = _SBE1_PATTERN.fullmatch(value)
    if match is None:
        return None
    lookup = match.group("lookup")
    secret = _decode_unpadded(match.group("secret"), 32)
    if _decode_unpadded(lookup, 16) is None or secret is None:
        return None
    enrollment_id = f"enr_{lookup}"
    verifier = hashlib.sha256(
        ENROLLMENT_HASH_DOMAIN + enrollment_id.encode("ascii") + b"\0" + secret
    ).hexdigest()
    return enrollment_id, verifier


def mint_enrollment_token() -> tuple[str, str, str]:
    """Return a new enrollment ID, its stored verifier, and the one-time token."""

    lookup = secrets.token_urlsafe(16)
    secret_part = secrets.token_urlsafe(32)
    token = f"{ENROLLMENT_PREFIX}{lookup}_{secret_part}"
    parsed = parse_enrollment_token(token)
    if parsed is None:
        raise RuntimeError("generated enrollment token was invalid")
    enrollment_id, verifier = parsed
    if parse_credential(token) is not None:
        raise RuntimeError("enrollment token must never parse as a credential")
    return enrollment_id, verifier, token


def parse_mobile_credential(value: str) -> tuple[str, str] | None:
    """Return the mobile credential ID and candidate verifier.

    A mobile credential is deliberately unrelated to an agent credential: a
    distinct prefix, a distinct hash domain and a distinct identifier space.
    The prefix alone is only a routing hint, never an authorisation decision,
    so callers must still resolve the returned identifier in the mobile
    credential table before trusting it.
    """

    if not isinstance(value, str) or not value or len(value) > MAX_CREDENTIAL_BYTES:
        return None
    match = _SBM1_PATTERN.fullmatch(value)
    if match is None:
        return None
    lookup = match.group("lookup")
    secret = _decode_unpadded(match.group("secret"), 32, canonical=True)
    if _decode_unpadded(lookup, 16, canonical=True) is None or secret is None:
        return None
    credential_id = f"mob_{lookup}"
    verifier = hashlib.sha256(
        MOBILE_HASH_DOMAIN + credential_id.encode("ascii") + b"\0" + secret
    ).hexdigest()
    return credential_id, verifier


def mint_mobile_credential() -> tuple[str, str, str]:
    """Return a new mobile credential ID, stored verifier and one-time secret."""

    token = f"{MOBILE_PREFIX}{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"
    parsed = parse_mobile_credential(token)
    if parsed is None:
        raise RuntimeError("generated mobile credential was invalid")
    credential_id, verifier = parsed
    if parse_credential(token) is not None:
        raise RuntimeError("mobile credential must never parse as an agent credential")
    if parse_enrollment_token(token) is not None:
        raise RuntimeError("mobile credential must never parse as an enrollment")
    return credential_id, verifier, token


def parse_mobile_write_grant(value: str, device_id: str) -> str | None:
    """Return the stored verifier a write grant proves for one device.

    The device identity is part of the hash input, so the same secret bytes
    presented for a different device produce a different verifier and cannot
    match. That is what stops a grant read off one handset being replayed as
    another device's second proof.
    """

    if not isinstance(value, str) or not value or len(value) > MAX_CREDENTIAL_BYTES:
        return None
    if not isinstance(device_id, str) or not device_id or len(device_id) > 256:
        return None
    match = _SBMW1_PATTERN.fullmatch(value)
    if match is None:
        return None
    secret = _decode_unpadded(match.group("secret"), 32, canonical=True)
    if secret is None:
        return None
    return hashlib.sha256(
        MOBILE_WRITE_HASH_DOMAIN + device_id.encode("utf-8") + b"\0" + secret
    ).hexdigest()


def mint_mobile_write_grant(device_id: str) -> tuple[str, str]:
    """Return a device write grant's stored verifier and one-time secret.

    The secret is server-generated with 256 bits of entropy and is never shown
    to a human, so it is stored as a plain domain-separated hash rather than a
    password verifier. Applying the operator password's PBKDF2 work factor here
    would put an expensive verification on the write path that shares a bounded
    worker pool with operator login, and a burst of writes would lock the owner
    out of their own console - the exact denial of service that ruled out
    sending the password on every request.
    """

    token = f"{MOBILE_WRITE_PREFIX}{secrets.token_urlsafe(32)}"
    verifier = parse_mobile_write_grant(token, device_id)
    if verifier is None:
        raise RuntimeError("generated mobile write grant was invalid")
    for parser in (parse_credential, parse_enrollment_token, parse_mobile_credential):
        if parser(token) is not None:
            raise RuntimeError("write grant must never parse as another principal")
    if parse_mobile_enrollment_token(token) is not None:
        raise RuntimeError("write grant must never parse as a mobile enrollment")
    return verifier, token


def parse_mobile_enrollment_token(value: str) -> tuple[str, str] | None:
    """Return the mobile enrollment ID and candidate verifier for a token."""

    if not isinstance(value, str) or not value or len(value) > MAX_CREDENTIAL_BYTES:
        return None
    match = _SBME1_PATTERN.fullmatch(value)
    if match is None:
        return None
    lookup = match.group("lookup")
    secret = _decode_unpadded(match.group("secret"), 32, canonical=True)
    if _decode_unpadded(lookup, 16, canonical=True) is None or secret is None:
        return None
    enrollment_id = f"mnr_{lookup}"
    verifier = hashlib.sha256(
        MOBILE_ENROLLMENT_HASH_DOMAIN + enrollment_id.encode("ascii") + b"\0" + secret
    ).hexdigest()
    return enrollment_id, verifier


def mint_mobile_enrollment_token() -> tuple[str, str, str]:
    """Return a new mobile enrollment ID, verifier and one-time token."""

    token = (
        f"{MOBILE_ENROLLMENT_PREFIX}"
        f"{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"
    )
    parsed = parse_mobile_enrollment_token(token)
    if parsed is None:
        raise RuntimeError("generated mobile enrollment token was invalid")
    enrollment_id, verifier = parsed
    if parse_credential(token) is not None:
        raise RuntimeError("mobile enrollment must never parse as a credential")
    if parse_mobile_credential(token) is not None:
        raise RuntimeError("mobile enrollment must never parse as a mobile credential")
    return enrollment_id, verifier, token


def parse_spn_credential(value: str) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value or len(value) > MAX_CREDENTIAL_BYTES:
        return None
    match = _SBSP1_PATTERN.fullmatch(value)
    if match is None:
        return None
    lookup = match.group("lookup")
    secret = _decode_unpadded(match.group("secret"), 32, canonical=True)
    if _decode_unpadded(lookup, 16, canonical=True) is None or secret is None:
        return None
    credential_id = f"spc_{lookup}"
    verifier = hashlib.sha256(
        SPN_CREDENTIAL_HASH_DOMAIN
        + credential_id.encode("ascii")
        + b"\0"
        + secret
    ).hexdigest()
    return credential_id, verifier


def mint_spn_credential() -> tuple[str, str, str]:
    token = (
        f"{SPN_CREDENTIAL_PREFIX}"
        f"{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"
    )
    parsed = parse_spn_credential(token)
    if parsed is None:
        raise RuntimeError("generated SPN credential was invalid")
    credential_id, verifier = parsed
    if parse_credential(token) is not None:
        raise RuntimeError("SPN credential must never parse as an agent credential")
    return credential_id, verifier, token


def parse_spn_enrollment_token(value: str) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value or len(value) > MAX_CREDENTIAL_BYTES:
        return None
    match = _SBSE1_PATTERN.fullmatch(value)
    if match is None:
        return None
    lookup = match.group("lookup")
    secret = _decode_unpadded(match.group("secret"), 32, canonical=True)
    if _decode_unpadded(lookup, 16, canonical=True) is None or secret is None:
        return None
    enrollment_id = f"sen_{lookup}"
    verifier = hashlib.sha256(
        SPN_ENROLLMENT_HASH_DOMAIN
        + enrollment_id.encode("ascii")
        + b"\0"
        + secret
    ).hexdigest()
    return enrollment_id, verifier


def mint_spn_enrollment_token() -> tuple[str, str, str]:
    token = (
        f"{SPN_ENROLLMENT_PREFIX}"
        f"{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"
    )
    parsed = parse_spn_enrollment_token(token)
    if parsed is None:
        raise RuntimeError("generated SPN enrollment token was invalid")
    enrollment_id, verifier = parsed
    if parse_credential(token) is not None:
        raise RuntimeError("SPN enrollment must never parse as an agent credential")
    return enrollment_id, verifier, token


def parse_host_enrollment_token(value: str) -> tuple[str, str] | None:
    """Return a host code's enrollment id and verifier, or None if it is not one."""

    if not isinstance(value, str) or not value or len(value) > MAX_CREDENTIAL_BYTES:
        return None
    match = _SBHE1_PATTERN.fullmatch(value)
    if match is None:
        return None
    lookup = match.group("lookup")
    secret = _decode_unpadded(match.group("secret"), 32, canonical=True)
    if _decode_unpadded(lookup, 16, canonical=True) is None or secret is None:
        return None
    enrollment_id = f"hen_{lookup}"
    verifier = hashlib.sha256(
        HOST_ENROLLMENT_HASH_DOMAIN
        + enrollment_id.encode("ascii")
        + b"\0"
        + secret
    ).hexdigest()
    return enrollment_id, verifier


def mint_host_enrollment_token() -> tuple[str, str, str]:
    """Return a new host enrollment id, verifier and one-time code (256 bits of secret)."""

    token = (
        f"{HOST_ENROLLMENT_PREFIX}"
        f"{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"
    )
    parsed = parse_host_enrollment_token(token)
    if parsed is None:
        raise RuntimeError("generated host enrollment code was invalid")
    enrollment_id, verifier = parsed
    if parse_credential(token) is not None:
        raise RuntimeError("host enrollment must never parse as an agent credential")
    return enrollment_id, verifier, token


def parse_reconnect_token(value: str) -> tuple[str, str] | None:
    if not isinstance(value, str) or len(value) > MAX_CREDENTIAL_BYTES:
        return None
    match = _SBR1_PATTERN.fullmatch(value)
    if match is None:
        return None
    lookup = match.group("lookup")
    secret = _decode_unpadded(match.group("secret"), 32, canonical=True)
    if _decode_unpadded(lookup, 16, canonical=True) is None or secret is None:
        return None
    grant_id = f"rcg_{lookup}"
    verifier = hashlib.sha256(
        RECONNECT_HASH_DOMAIN + grant_id.encode("ascii") + b"\0" + secret
    ).hexdigest()
    return grant_id, verifier


def mint_reconnect_token() -> tuple[str, str, str]:
    token = f"{RECONNECT_PREFIX}{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"
    parsed = parse_reconnect_token(token)
    if parsed is None:
        raise RuntimeError("generated reconnect token was invalid")
    return *parsed, token


_NAME_PREFIX = re.compile(r"^[0-9a-z]+(?:-[0-9a-z]+)*$")


def _validate_name_prefix(value: str) -> str:
    """Return the bounded lowercase kebab prefix an enrollment may claim."""

    if not isinstance(value, str):
        raise ConfigurationError("name_prefix must be text")
    prefix = value.strip().lower()
    if not prefix or len(prefix) > 128 or _NAME_PREFIX.fullmatch(prefix) is None:
        raise ConfigurationError(
            "name_prefix must be lowercase kebab-case without leading or "
            "trailing hyphens"
        )
    return prefix


def _validate_agent_text(name: str, value: str, *, maximum_length: int) -> str:
    if not isinstance(value, str):
        raise ConfigurationError(f"{name} must be text")
    if len(value) > maximum_length or "\x00" in value:
        raise ConfigurationError(
            f"{name} must not exceed {maximum_length} characters or contain NUL"
        )
    return value


def _request_id(value: str | None) -> str:
    if value is None:
        return str(uuid.uuid4())
    if not isinstance(value, str):
        raise ConfigurationError("request_id must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ConfigurationError("request_id must be a canonical UUID") from error
    if str(parsed) != value:
        raise ConfigurationError("request_id must be a canonical UUID")
    return value


def _required_request_id(value: str) -> str:
    if value is None:
        raise ConfigurationError("request_id must be a canonical UUID")
    return _request_id(value)


def _enrollment_name_prefix(name_prefix: str, name_match: str) -> str:
    if not isinstance(name_match, str) or name_match not in {"prefix", "exact"}:
        raise ConfigurationError("name_match must be prefix or exact")
    prefix = _validate_name_prefix(name_prefix)
    if name_match != "exact":
        return prefix
    try:
        return normalize_name(prefix, agent=True)
    except DomainValidationError as error:
        raise ConfigurationError(
            "exact enrollment requires a complete agent name"
        ) from error


def _require_bounded_positive(name: str, value: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConfigurationError(f"{name} must be a positive integer")
    if value > maximum:
        raise ConfigurationError(f"{name} must not exceed {maximum}")


def _reason(value: str) -> str:
    value = _validate_agent_text("reason", value, maximum_length=256)
    if not value or value != value.strip():
        raise ConfigurationError("reason must be non-empty trimmed text")
    try:
        return _audit_text(value)
    except DomainValidationError as error:
        raise ConfigurationError("reason must be bounded printable text") from error


class AgentService:
    def __init__(
        self,
        store: SQLiteStore,
        *,
        clock: Callable[[], datetime] = utc_now,
        max_active_credentials: int = DEFAULT_MAX_ACTIVE_CREDENTIALS,
        max_pending_credentials: int = DEFAULT_MAX_PENDING_CREDENTIALS,
        pending_seconds: int = DEFAULT_CREDENTIAL_PENDING_SECONDS,
        rotations_per_window: int = DEFAULT_SELF_ROTATIONS_PER_WINDOW,
        rotation_window_seconds: int = DEFAULT_SELF_ROTATION_WINDOW_SECONDS,
        enrollment_ttl_seconds: int = DEFAULT_ENROLLMENT_TTL_SECONDS,
        max_enrollment_uses: int = DEFAULT_MAX_ENROLLMENT_USES,
        reconnect_ttl_seconds: int = 900,
        max_outstanding_reconnect_grants: int = 256,
    ) -> None:
        self.store = store
        self._clock = clock
        self.max_active_credentials = max_active_credentials
        self.max_pending_credentials = max_pending_credentials
        self.pending_seconds = pending_seconds
        if type(pending_seconds) is not int or not 1 <= pending_seconds <= 86_400:
            raise ConfigurationError("invalid pending credential lifetime")
        self.rotations_per_window = rotations_per_window
        self.rotation_window_seconds = rotation_window_seconds
        self.enrollment_ttl_seconds = enrollment_ttl_seconds
        self.max_enrollment_uses = max_enrollment_uses
        if (type(reconnect_ttl_seconds) is not int or not 1 <= reconnect_ttl_seconds <= 900
                or type(max_outstanding_reconnect_grants) is not int
                or not 1 <= max_outstanding_reconnect_grants <= 1024):
            raise ConfigurationError("invalid reconnect grant limits")
        self.reconnect_ttl_seconds = reconnect_ttl_seconds
        self.max_outstanding_reconnect_grants = max_outstanding_reconnect_grants

    def begin_bootstrap(
        self, agent_id: str, credential_id: str,
    ) -> Token[tuple[str, str, Callable[[], datetime]] | None]:
        return self.store.begin_bootstrap_operation(
            agent_id, credential_id, clock=self._clock,
        )

    def end_bootstrap(
        self, token: Token[tuple[str, str, Callable[[], datetime]] | None],
    ) -> None:
        self.store.end_bootstrap_operation(token)

    def require_live_identity(self, agent_id: str, credential_id: str) -> None:
        self.store.require_bootstrap_identity(
            agent_id, credential_id, checked_at=self._clock(),
        )

    def transition_agent(
        self, agent_id: str, *, action: str, expected_credential_epoch: int,
        request_id: str, reason: str, actor: LifecycleActor,
    ) -> AgentLifecycleResult:
        return self.store.transition_agent(
            agent_id, action=action, expected_credential_epoch=expected_credential_epoch,
            request_id=_required_request_id(request_id), reason=_reason(reason),
            actor=actor, changed_at=self._clock(),
        )

    def prepare_reconnect_grant(self) -> PreparedReconnectGrant:
        grant_id, verifier, token = mint_reconnect_token()
        now = self._clock()
        return PreparedReconnectGrant(
            grant_id, now, now + timedelta(seconds=self.reconnect_ttl_seconds),
            verifier, token,
        )

    def issue_reconnect(
        self, agent_id: str, *, expected_agent_name: str,
        expected_credential_epoch: int, request_id: str, reason: str,
        actor: LifecycleActor, prepared: PreparedReconnectGrant | None = None,
    ) -> IssuedReconnectGrant:
        """Commit only after the caller has validated/serialized the trust package."""
        prepared = prepared or self.prepare_reconnect_grant()
        parsed = parse_reconnect_token(prepared.token)
        if (parsed != (prepared.id, prepared.secret_hash)
                or (prepared.expires_at - prepared.created_at).total_seconds()
                > self.reconnect_ttl_seconds):
            raise ConfigurationError("invalid prepared reconnect material")
        grant, created = self.store.issue_reconnect_grant(
            agent_id=agent_id, expected_agent_name=expected_agent_name,
            expected_credential_epoch=expected_credential_epoch,
            request_id=_required_request_id(request_id), reason=_reason(reason), actor=actor,
            grant_id=prepared.id, secret_hash=prepared.secret_hash,
            created_at=prepared.created_at, expires_at=prepared.expires_at,
            checked_at=self._clock(), max_outstanding=self.max_outstanding_reconnect_grants,
            clock=self._clock,
        )
        return IssuedReconnectGrant(grant, prepared.token if created else None)

    def verify_reconnect(self, token: str) -> AgentReconnectGrant | None:
        parsed = parse_reconnect_token(token)
        if parsed is None:
            return None
        return self.store.verify_reconnect_grant(
            grant_id=parsed[0], candidate_digest=parsed[1], checked_at=self._clock(),
            clock=self._clock,
        )

    def redeem_reconnect(
        self, token: str, *, expected_agent_id: str, expected_agent_name: str,
        request_id: str,
    ) -> RedeemedReconnectGrant:
        parsed = parse_reconnect_token(token)
        if parsed is None:
            raise CredentialNotFoundError("reconnect grant is unavailable")
        credential_id, verifier, secret = mint_credential()
        now = self._clock()
        agent, credential, grant = self.store.redeem_reconnect_grant(
            grant_id=parsed[0], candidate_digest=parsed[1],
            expected_agent_id=expected_agent_id, expected_agent_name=expected_agent_name,
            request_id=_required_request_id(request_id), credential_id=credential_id,
            secret_hash=verifier, redeemed_at=now,
            pending_expires_at=now + timedelta(seconds=self.pending_seconds),
            clock=self._clock,
        )
        return RedeemedReconnectGrant(
            agent, IssuedCredential(credential, secret, True), grant,
        )

    def initialize(self) -> int:
        return self.store.initialize()

    def list_identity_creation_provenance(
        self,
        *,
        creator_type: str | None = None,
        creator_id: str | None = None,
        after_created_at: datetime | None = None,
        after_agent_id: str | None = None,
        limit: int = 100,
    ) -> IdentityCreationProvenancePage:
        return self.store.list_identity_creation_provenance(
            creator_type=creator_type,
            creator_id=creator_id,
            after_created_at=after_created_at,
            after_agent_id=after_agent_id,
            limit=limit,
        )

    def create_agent(
        self,
        name: str,
        *,
        description: str = "",
        host: str = "",
        require_access: bool = False,
        request_id: str | None = None,
        creator_type: str = "local-admin",
        creator_id: str = "local-service",
    ) -> CreatedAgent:
        try:
            name = normalize_name(name, agent=True)
        except DomainValidationError as error:
            raise ConfigurationError(
                "agent name must be lowercase kebab-case with project and platform"
            ) from error
        description = _validate_agent_text(
            "description", description, maximum_length=1024
        )
        host = _validate_agent_text("host", host, maximum_length=255)
        credential_id, verifier, secret = mint_credential()
        now = self._clock()
        agent, credential, created = self.store.create_agent_with_credential(
            agent_id=str(uuid.uuid4()),
            name=name,
            description=description,
            host=host,
            credential_id=credential_id,
            secret_hash=verifier,
            request_id=_request_id(request_id),
            created_at=now,
            pending_expires_at=now + timedelta(seconds=self.pending_seconds),
            require_access=require_access,
            creator_type=creator_type,
            creator_id=creator_id,
        )
        return CreatedAgent(
            agent=agent,
            issued_credential=IssuedCredential(
                credential=credential,
                secret=secret if created else None,
                secret_issued=created,
            ),
        )

    def create_enrollment(
        self,
        *,
        name_prefix: str,
        name_match: str = "prefix",
        description: str = "",
        uses: int = 1,
        ttl_seconds: int | None = None,
        actor_type: str = "local-admin",
        actor_id: str = "operator",
        reason: str = "agent self-registration",
        require_access: bool = False,
        authorize: Callable[[], None] | None = None,
    ) -> IssuedEnrollment:
        prefix = _enrollment_name_prefix(name_prefix, name_match)
        description = _validate_agent_text(
            "description", description, maximum_length=1024
        )
        _require_bounded_positive("uses", uses, self.max_enrollment_uses)
        ttl = self.enrollment_ttl_seconds if ttl_seconds is None else ttl_seconds
        _require_bounded_positive("ttl_seconds", ttl, self.enrollment_ttl_seconds)
        enrollment_id, verifier, token = mint_enrollment_token()
        now = self._clock()
        enrollment = self.store.create_enrollment(
            enrollment_id=enrollment_id,
            secret_hash=verifier,
            name_prefix=prefix,
            name_match=name_match,
            description=description,
            uses_allowed=uses,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            actor_type=actor_type,
            actor_id=actor_id,
            creation_reason=_reason(reason),
            require_access=require_access,
            authorize=authorize,
        )
        return IssuedEnrollment(enrollment=enrollment, token=token)

    def create_dashboard_enrollment(
        self,
        *,
        name: str,
        description: str = "",
        operator: OperatorContext,
        authorize: Callable[[], None],
    ) -> IssuedEnrollment:
        if not isinstance(operator, OperatorContext) or not callable(authorize):
            raise ConfigurationError("operator context and authorization guard are required")
        authorize()
        return self.create_enrollment(
            name_prefix=name,
            name_match="exact",
            description=description,
            uses=1,
            require_access=True,
            actor_type="remote-admin",
            actor_id=operator.actor_id,
            reason="dashboard registration",
            authorize=authorize,
        )

    def redeem_enrollment(
        self,
        token: str,
        *,
        claimed_name: str,
        description: str = "",
        host: str = "",
        request_id: str | None = None,
    ) -> RedeemedEnrollment:
        parsed = parse_enrollment_token(token) or parse_spn_enrollment_token(token)
        if parsed is None:
            raise EnrollmentInvalidError("enrollment token is not valid")
        enrollment_id, verifier = parsed
        try:
            name = normalize_name(claimed_name, agent=True)
        except DomainValidationError as error:
            raise ConfigurationError(
                "agent name must be lowercase kebab-case with project and platform"
            ) from error
        description = _validate_agent_text(
            "description", description, maximum_length=1024
        )
        host = _validate_agent_text("host", host, maximum_length=255)
        credential_id, secret_hash, secret = mint_credential()
        now = self._clock()
        agent, credential = self.store.redeem_enrollment(
            enrollment_id=enrollment_id,
            candidate_digest=verifier,
            claimed_name=name,
            description=description,
            host=host,
            agent_id=str(uuid.uuid4()),
            credential_id=credential_id,
            secret_hash=secret_hash,
            request_id=_request_id(request_id),
            redeemed_at=now,
            pending_expires_at=now + timedelta(seconds=self.pending_seconds),
        )
        return RedeemedEnrollment(
            agent=agent,
            issued_credential=IssuedCredential(
                credential=credential,
                secret=secret,
                secret_issued=True,
            ),
            enrollment_id=enrollment_id,
        )

    def list_enrollments(self) -> tuple[AgentEnrollment, ...]:
        return self.store.list_enrollments()

    def revoke_enrollment(
        self,
        enrollment_id: str,
        *,
        reason: str = "operator revocation",
    ) -> AgentEnrollment:
        if (
            not isinstance(enrollment_id, str)
            or not enrollment_id
            or len(enrollment_id) > 256
            or "\x00" in enrollment_id
        ):
            raise ConfigurationError("enrollment_id must be bounded non-empty text")
        return self.store.revoke_enrollment(
            enrollment_id=enrollment_id,
            reason=_reason(reason),
            revoked_at=self._clock(),
        )

    def authenticate(self, api_key: str) -> AuthenticatedIdentity | None:
        return self._authenticate(api_key, require_access=False)

    def authorize(self, api_key: str) -> AuthenticatedIdentity | None:
        return self._authenticate(api_key, require_access=True)

    def _authenticate(
        self,
        api_key: str,
        *,
        require_access: bool,
    ) -> AuthenticatedIdentity | None:
        parsed = parse_credential(api_key)
        if parsed is None:
            return None
        kind, credential_id, verifier = parsed
        return self.store.authenticate_credential(
            kind=kind,
            credential_id=credential_id,
            candidate_digest=verifier,
            seen_at_factory=self._clock,
            require_access=require_access,
        )

    def verify_credential(
        self, api_key: str, *, require_access: bool = False,
    ) -> AuthenticatedIdentity | None:
        parsed = parse_credential(api_key)
        if parsed is None:
            return None
        kind, credential_id, verifier = parsed
        return self.store.verify_credential(
            kind=kind,
            credential_id=credential_id,
            candidate_digest=verifier,
            checked_at=self._clock(),
            require_access=require_access,
        )

    def rotate(
        self,
        identity: AuthenticatedIdentity,
        *,
        request_id: str,
        expected_agent_id: str,
        expected_credential_id: str,
        expected_credential_epoch: int,
        reason: str = "scheduled rotation",
    ) -> IssuedCredential:
        credential_id, verifier, secret = mint_credential()
        now = self._clock()
        credential, created = self.store.rotate_credential(
            identity=identity,
            new_credential_id=credential_id,
            secret_hash=verifier,
            request_id=_request_id(request_id),
            expected_agent_id=expected_agent_id,
            expected_credential_id=expected_credential_id,
            expected_credential_epoch=expected_credential_epoch,
            reason=_reason(reason),
            created_at=now,
            pending_expires_at=now + timedelta(seconds=self.pending_seconds),
            max_active=self.max_active_credentials,
            max_pending=self.max_pending_credentials,
            rotation_not_before=now - timedelta(seconds=self.rotation_window_seconds),
            max_rotations=self.rotations_per_window,
        )
        return IssuedCredential(
            credential=credential,
            secret=secret if created else None,
            secret_issued=created,
        )

    def prove(
        self,
        identity: AuthenticatedIdentity,
        *,
        request_id: str,
        expected_agent_id: str,
        expected_agent_name: str,
        expected_credential_epoch: int,
        expected_credential_version: int,
    ) -> AgentCredential:
        return self.store.prove_credential(
            identity=identity,
            request_id=_request_id(request_id),
            expected_agent_id=expected_agent_id,
            expected_agent_name=expected_agent_name,
            expected_credential_epoch=expected_credential_epoch,
            expected_credential_version=expected_credential_version,
            verified_at=self._clock(),
            max_active=self.max_active_credentials,
            clock=self._clock,
        )

    def retire_predecessor(
        self,
        identity: AuthenticatedIdentity,
        *,
        credential_id: str,
        request_id: str,
        expected_credential_epoch: int,
        expected_credential_version: int,
        reason: str = "rotation completed",
    ) -> AgentCredential:
        return self.store.retire_credential(
            identity=identity,
            credential_id=credential_id,
            request_id=_request_id(request_id),
            expected_credential_epoch=expected_credential_epoch,
            expected_credential_version=expected_credential_version,
            reason=_reason(reason),
            retired_at=self._clock(),
        )

    def issue_for_agent(
        self,
        name: str,
        *,
        request_id: str,
        expected_credential_epoch: int,
        reason: str,
        actor_type: str = "remote-admin",
        actor_id: str = "admin",
    ) -> IssuedCredential:
        agent = self.get_active_agent_by_name(name)
        credential_id, verifier, secret = mint_credential()
        now = self._clock()
        credential, created = self.store.issue_credential(
            agent_id=agent.id,
            credential_id=credential_id,
            secret_hash=verifier,
            request_id=_request_id(request_id),
            expected_credential_epoch=expected_credential_epoch,
            reason=_reason(reason),
            actor_type=actor_type,
            actor_id=actor_id,
            created_at=now,
            pending_expires_at=now + timedelta(seconds=self.pending_seconds),
            max_active=self.max_active_credentials,
            max_pending=self.max_pending_credentials,
        )
        return IssuedCredential(
            credential=credential,
            secret=secret if created else None,
            secret_issued=created,
        )

    def recover_agent(
        self,
        name: str,
        *,
        request_id: str,
        expected_credential_epoch: int,
        reason: str,
        actor_type: str = "remote-admin",
        actor_id: str = "admin",
    ) -> IssuedCredential:
        agent = self.get_active_agent_by_name(name)
        credential_id, verifier, secret = mint_credential()
        now = self._clock()
        credential, created = self.store.recover_credential(
            agent_id=agent.id,
            credential_id=credential_id,
            secret_hash=verifier,
            request_id=_request_id(request_id),
            expected_credential_epoch=expected_credential_epoch,
            reason=_reason(reason),
            actor_type=actor_type,
            actor_id=actor_id,
            created_at=now,
            pending_expires_at=now + timedelta(seconds=self.pending_seconds),
        )
        return IssuedCredential(
            credential=credential,
            secret=secret if created else None,
            secret_issued=created,
        )

    def revoke_credential(
        self,
        name: str,
        credential_id: str,
        *,
        request_id: str,
        expected_credential_epoch: int,
        expected_credential_version: int,
        reason: str,
        actor_type: str = "remote-admin",
        actor_id: str = "admin",
    ) -> AgentCredential:
        agent = self.get_active_agent_by_name(name)
        return self.store.revoke_credential(
            agent_id=agent.id,
            credential_id=credential_id,
            request_id=_request_id(request_id),
            expected_credential_epoch=expected_credential_epoch,
            expected_credential_version=expected_credential_version,
            reason=_reason(reason),
            actor_type=actor_type,
            actor_id=actor_id,
            revoked_at=self._clock(),
        )

    def list_credentials(
        self, name: str, *, require_access: bool = True,
    ) -> tuple[AgentCredential, ...]:
        return self.store.list_credentials(
            self.get_active_agent_by_name(name).id, require_access=require_access,
        )

    def get_credential(self, name: str, credential_id: str) -> AgentCredential:
        if (
            not isinstance(credential_id, str)
            or not credential_id
            or len(credential_id) > 128
            or "\x00" in credential_id
        ):
            raise ConfigurationError("credential_id must be bounded non-empty text")
        agent = self.get_active_agent_by_name(name)
        return self.store.get_credential(agent.id, credential_id)

    def get_active_agent(self, agent_id: str) -> Agent:
        if not isinstance(agent_id, str) or not agent_id:
            raise ConfigurationError("agent_id must be non-empty text")
        return self.store.get_active_agent(agent_id)

    def list_managed_agents(
        self, *, state: str = "managed", after_name: str | None = None,
        limit: int = 100, require_access: bool = True,
    ) -> tuple[Agent, ...]:
        """Use require_access=False only after protected local-admin authorization."""
        return self.store.list_managed_agents(
            state=state, after_name=after_name, limit=limit, require_access=require_access,
        )

    def get_managed_agent(self, agent_id: str, *, require_access: bool = True) -> Agent:
        return self.store.get_managed_agent(agent_id, require_access=require_access)

    def get_active_agent_by_name(self, name: str) -> Agent:
        try:
            normalized_name = normalize_name(name, agent=True)
        except DomainValidationError as error:
            raise ConfigurationError(
                "agent name must be lowercase kebab-case with project and platform"
            ) from error
        return self.store.get_active_agent_by_name(normalized_name)

    def revoke_agent(
        self,
        agent_id: str,
        *,
        request_id: str | None = None,
        actor_type: str = "remote-admin",
        actor_id: str = "admin",
        reason: str = "stable agent revoked",
        expected_credential_epoch: int | None = None,
    ) -> Agent:
        if not isinstance(agent_id, str) or not agent_id:
            raise ConfigurationError("agent_id must be non-empty text")
        return self.store.revoke_agent(
            agent_id,
            revoked_at=self._clock(),
            request_id=_request_id(request_id),
            actor_type=actor_type,
            actor_id=actor_id,
            reason=_reason(reason),
            expected_credential_epoch=expected_credential_epoch,
        )

    def revoke_agent_by_name(
        self,
        name: str,
        *,
        request_id: str | None = None,
        actor_type: str = "remote-admin",
        actor_id: str = "admin",
        reason: str = "stable agent revoked",
        expected_credential_epoch: int | None = None,
    ) -> Agent:
        agent = self.get_active_agent_by_name(name)
        return self.revoke_agent(
            agent.id,
            request_id=request_id,
            actor_type=actor_type,
            actor_id=actor_id,
            reason=reason,
            expected_credential_epoch=expected_credential_epoch,
        )
