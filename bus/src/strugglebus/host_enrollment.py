"""Single-use codes that let a worker host join the bus as its own service principal."""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from strugglebus.auth import (
    mint_host_enrollment_token,
    mint_spn_credential,
    parse_host_enrollment_token,
)
from strugglebus.errors import ConfigurationError, EnrollmentInvalidError
from strugglebus.models import LifecycleActor
from strugglebus.store import SQLiteStore, _audit_text, utc_now
from strugglebus.store._host_enrollment import HostEnrollmentRecord

#: A host's prefix is also its service principal's name, so it follows that
#: rule, within the length a worker host accepts.
HOST_PREFIX = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MIN_HOST_PREFIX_LENGTH = 2
MAX_HOST_PREFIX_LENGTH = 31
MAX_HOST_CODE_SECONDS = 900


@dataclass(frozen=True, slots=True)
class IssuedHostCode:
    host_prefix: str
    expires_at: datetime
    #: None when this request id already minted a code, which was shown then.
    code: str | None


@dataclass(frozen=True, slots=True)
class RedeemedHostCode:
    name: str
    credential: str
    created: bool


def validate_host_prefix(value: str) -> str:
    """Return the prefix as stored: trimmed and lowercased, or refuse it."""

    prefix = value.strip().lower() if isinstance(value, str) else ""
    if (
        not MIN_HOST_PREFIX_LENGTH <= len(prefix) <= MAX_HOST_PREFIX_LENGTH
        or HOST_PREFIX.fullmatch(prefix) is None
    ):
        raise ConfigurationError(
            "host names use lowercase letters, digits and single hyphens, "
            f"{MIN_HOST_PREFIX_LENGTH} to {MAX_HOST_PREFIX_LENGTH} characters"
        )
    return prefix


def confirmation_code(agent_id: str, redeem_request_id: str) -> str:
    """What the operator compares with the host's own printout before trusting it.

    The first eight hex characters of SHA-256 over the host agent's id, a line
    feed and the request id the host redeemed with. Only the host that
    redeemed knows that request id.
    """

    digest = hashlib.sha256(f"{agent_id}\n{redeem_request_id}".encode("utf-8"))
    return digest.hexdigest()[:8]


class HostEnrollmentService:
    def __init__(
        self,
        store: SQLiteStore,
        *,
        clock: Callable[[], datetime] = utc_now,
        code_seconds: int = MAX_HOST_CODE_SECONDS,
    ) -> None:
        if type(code_seconds) is not int or not 60 <= code_seconds <= MAX_HOST_CODE_SECONDS:
            raise ConfigurationError("invalid host code lifetime")
        self.store = store
        self._clock = clock
        self.code_seconds = code_seconds

    def mint(
        self, *, host_prefix: str, request_id: str, reason: str, actor: LifecycleActor,
    ) -> IssuedHostCode:
        prefix = validate_host_prefix(host_prefix)
        reason = _audit_text(reason)
        enrollment_id, verifier, code = mint_host_enrollment_token()
        now = self._clock()
        expires_at = now + timedelta(seconds=self.code_seconds)
        created = self.store.create_host_enrollment(
            enrollment_id=enrollment_id,
            secret_hash=verifier,
            host_prefix=prefix,
            request_id=request_id,
            reason=reason,
            actor=actor,
            created_at=now,
            expires_at=expires_at,
        )
        return IssuedHostCode(
            host_prefix=prefix, expires_at=expires_at, code=code if created else None,
        )

    def redeem(self, code: str, *, request_id: str, source: str) -> RedeemedHostCode:
        parsed = parse_host_enrollment_token(code)
        if parsed is None:
            raise EnrollmentInvalidError("host code is not valid")
        credential_id, verifier, secret = mint_spn_credential()
        redeemed = self.store.redeem_host_enrollment(
            enrollment_id=parsed[0],
            candidate_digest=parsed[1],
            request_id=request_id,
            source=source[:64] or "unknown",
            spn_id=str(uuid.uuid4()),
            credential_id=credential_id,
            secret_hash=verifier,
            redeemed_at=self._clock(),
        )
        return RedeemedHostCode(
            name=redeemed.name, credential=secret, created=redeemed.created,
        )

    def records(self) -> dict[str, HostEnrollmentRecord]:
        return self.store.host_enrollment_records()
