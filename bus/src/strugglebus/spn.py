"""Dedicated service-principal authority for automated agent onboarding."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from strugglebus.auth import (
    mint_spn_credential,
    mint_spn_enrollment_token,
    parse_spn_credential,
    parse_spn_enrollment_token,
)
from strugglebus.ca import validate_trust_anchor
from strugglebus.errors import ConfigurationError, DomainValidationError, TrustAnchorError
from strugglebus.models import (
    IssuedServicePrincipal,
    LifecycleActor,
    OnboardingIssuance,
    ServicePrincipal,
    ServicePrincipalIdentity,
)
from strugglebus.service import normalize_name
from strugglebus.store import SQLiteStore, utc_now

SPN_NAME = re.compile(r"^[0-9a-z]+(?:-[0-9a-z]+)*$")


@dataclass(frozen=True, slots=True)
class PreparedOnboarding:
    enrollment_id: str
    secret_hash: str
    token: str
    created_at: datetime
    expires_at: datetime


def _request_id(value: str) -> str:
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise ConfigurationError("request_id must be a canonical UUID") from None
    return value


def _text(name: str, value: str, maximum: int, *, required: bool = False) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or "\x00" in value
        or (required and (not value or value != value.strip()))
    ):
        raise ConfigurationError(f"{name} is invalid")
    return value


def _kebab(name: str, value: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ConfigurationError(f"{name} must be lowercase kebab-case")
    normalized = value.strip().lower()
    if (
        not normalized
        or len(normalized) > maximum
        or SPN_NAME.fullmatch(normalized) is None
    ):
        raise ConfigurationError(f"{name} must be lowercase kebab-case")
    return normalized


def _bare_https_origin(base_url: str) -> str:
    origin = base_url.rstrip("/")
    parsed = urlsplit(origin)
    if (
        not origin.isascii()
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError
    return origin


def encode_onboarding_package(
    *,
    agent_name: str,
    base_url: str,
    ca_root: bytes,
    ca_sha256: str,
    expires_at: datetime,
    enrollment_token: str,
) -> dict[str, object]:
    try:
        canonical_name = normalize_name(agent_name, agent=True)
        origin = _bare_https_origin(base_url)
        anchor = validate_trust_anchor(ca_root, ca_sha256)
        if parse_spn_enrollment_token(enrollment_token) is None:
            raise ValueError
        anchor_text = anchor.decode("ascii")
    except (ValueError, UnicodeError, DomainValidationError, TrustAnchorError):
        raise ConfigurationError("onboarding package could not be prepared") from None
    return {
        "version": 1,
        "agent_name": canonical_name,
        "base_url": origin,
        "redeem_path": "/api/enrollments/redeem",
        "ca_root": anchor_text,
        "ca_sha256": ca_sha256,
        "expires_at": expires_at.isoformat(),
        "enrollment_token": enrollment_token,
    }


#: The longest a worker identity issued by an SPN may live. It covers a task's
#: runtime limit with room for a resume, and keeps a leaked worker credential
#: worth hours, not weeks.
MAX_IDENTITY_TTL_SECONDS = 43200
#: Self-rotations an SPN may make in a rolling 24 hours.
MAX_SELF_ROTATIONS_PER_DAY = 2


def _require_identity_ttl(identity_ttl_seconds: int | None) -> None:
    if identity_ttl_seconds is not None and (
        type(identity_ttl_seconds) is not int
        or not 60 <= identity_ttl_seconds <= MAX_IDENTITY_TTL_SECONDS
    ):
        raise ConfigurationError(
            "identity_ttl_seconds must be between 60 and "
            f"{MAX_IDENTITY_TTL_SECONDS}"
        )


def _agent_name_within_prefix(agent_name: str, prefix: str) -> str:
    name = normalize_name(agent_name, agent=True)
    if name != prefix and not name.startswith(prefix + "-"):
        raise ConfigurationError("agent name is outside the SPN prefix")
    return name


def _onboarding_intent(
    identity: ServicePrincipalIdentity,
    name: str,
    description: str,
    prepared: PreparedOnboarding,
    identity_ttl_seconds: int | None,
) -> str:
    """Digest of what a request asked for, so a replayed request_id must match."""
    return hashlib.sha256(
        json.dumps(
            [identity.spn_id, name, description, int(
                (prepared.expires_at - prepared.created_at).total_seconds()
            ), identity_ttl_seconds],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


class ServicePrincipalService:
    def __init__(
        self,
        store: SQLiteStore,
        *,
        clock: Callable[[], datetime] = utc_now,
        package_ttl_seconds: int = 300,
        max_outstanding_packages: int = 32,
    ) -> None:
        if (
            type(package_ttl_seconds) is not int
            or not 60 <= package_ttl_seconds <= 900
            or type(max_outstanding_packages) is not int
            or not 1 <= max_outstanding_packages <= 1024
        ):
            raise ConfigurationError("invalid SPN onboarding limits")
        self.store = store
        self._clock = clock
        self.package_ttl_seconds = package_ttl_seconds
        self.max_outstanding_packages = max_outstanding_packages

    def create(
        self,
        *,
        name: str,
        agent_name_prefix: str,
        request_id: str,
        actor: LifecycleActor,
    ) -> IssuedServicePrincipal:
        canonical_name = _kebab("SPN name", name, 64)
        prefix = _kebab("agent_name_prefix", agent_name_prefix, 128)
        credential_id, verifier, secret = mint_spn_credential()
        principal, result_credential_id, created = self.store.create_service_principal(
            spn_id=str(uuid.uuid4()),
            name=canonical_name,
            agent_name_prefix=prefix,
            credential_id=credential_id,
            secret_hash=verifier,
            request_id=_request_id(request_id),
            actor=actor,
            created_at=self._clock(),
        )
        return IssuedServicePrincipal(
            principal=principal,
            credential_id=result_credential_id,
            secret=secret if created else None,
            secret_issued=created,
        )

    def list(self) -> tuple[ServicePrincipal, ...]:
        return self.store.list_service_principals()

    def authorize(self, secret: str) -> ServicePrincipalIdentity | None:
        parsed = parse_spn_credential(secret)
        if parsed is None:
            return None
        return self.store.authenticate_service_principal(
            credential_id=parsed[0],
            candidate_digest=parsed[1],
            seen_at=self._clock(),
        )

    def identity_is_active(
        self, identity: ServicePrincipalIdentity,
    ) -> bool:
        return self.store.service_principal_credential_is_active(
            identity.spn_id, identity.credential_id,
        )

    def prepare_onboarding(self, *, ttl_seconds: int | None = None) -> PreparedOnboarding:
        ttl = self.package_ttl_seconds if ttl_seconds is None else ttl_seconds
        if type(ttl) is not int or not 60 <= ttl <= self.package_ttl_seconds:
            raise ConfigurationError(
                f"ttl_seconds must be between 60 and {self.package_ttl_seconds}"
            )
        enrollment_id, verifier, token = mint_spn_enrollment_token()
        now = self._clock()
        return PreparedOnboarding(
            enrollment_id=enrollment_id,
            secret_hash=verifier,
            token=token,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )

    def issue_onboarding(
        self,
        identity: ServicePrincipalIdentity,
        *,
        request_id: str,
        agent_name: str,
        description: str = "",
        ttl_seconds: int | None = None,
        prepared: PreparedOnboarding | None = None,
        identity_ttl_seconds: int | None = None,
    ) -> OnboardingIssuance:
        if not isinstance(identity, ServicePrincipalIdentity):
            raise ConfigurationError("SPN identity is required")
        _require_identity_ttl(identity_ttl_seconds)
        name = _agent_name_within_prefix(agent_name, identity.agent_name_prefix)
        description = _text("description", description, 1024)
        prepared = prepared or self.prepare_onboarding(ttl_seconds=ttl_seconds)
        parsed = parse_spn_enrollment_token(prepared.token)
        if parsed != (prepared.enrollment_id, prepared.secret_hash):
            raise ConfigurationError("invalid prepared onboarding material")
        intent = _onboarding_intent(
            identity, name, description, prepared, identity_ttl_seconds,
        )
        issuance, created = self.store.issue_spn_onboarding(
            identity=identity,
            request_id=_request_id(request_id),
            intent_sha256=intent,
            enrollment_id=prepared.enrollment_id,
            secret_hash=prepared.secret_hash,
            agent_name=name,
            description=description,
            created_at=prepared.created_at,
            expires_at=prepared.expires_at,
            max_outstanding=self.max_outstanding_packages,
            identity_expires_at=(
                None if identity_ttl_seconds is None
                else prepared.created_at + timedelta(seconds=identity_ttl_seconds)
            ),
        )
        return OnboardingIssuance(
            request_id=issuance.request_id,
            spn_id=issuance.spn_id,
            enrollment_id=issuance.enrollment_id,
            agent_name=issuance.agent_name,
            created_at=issuance.created_at,
            expires_at=issuance.expires_at,
            token=prepared.token if created else None,
            secret_issued=created,
        )

    def transition(
        self,
        spn_id: str,
        *,
        action: str,
        expected_version: int,
        request_id: str,
        reason: str,
        actor: LifecycleActor,
    ) -> ServicePrincipal:
        return self.store.transition_service_principal(
            spn_id,
            action=action,
            expected_version=expected_version,
            request_id=_request_id(request_id),
            reason=_text("reason", reason, 256, required=True),
            actor=actor,
            changed_at=self._clock(),
        )

    def rotate(
        self,
        spn_id: str,
        *,
        expected_version: int,
        request_id: str,
        reason: str,
        actor: LifecycleActor,
    ) -> IssuedServicePrincipal:
        credential_id, verifier, secret = mint_spn_credential()
        principal, result_credential_id, created = (
            self.store.rotate_service_principal_credential(
                spn_id,
                expected_version=expected_version,
                credential_id=credential_id,
                secret_hash=verifier,
                request_id=_request_id(request_id),
                reason=_text("reason", reason, 256, required=True),
                actor=actor,
                changed_at=self._clock(),
            )
        )
        return IssuedServicePrincipal(
            principal=principal,
            credential_id=result_credential_id,
            secret=secret if created else None,
            secret_issued=created,
        )

    def retire_identity(
        self,
        identity: ServicePrincipalIdentity,
        *,
        agent_name: str,
        request_id: str,
    ) -> datetime:
        return self.store.retire_spn_identity(
            identity=identity,
            agent_name=normalize_name(agent_name, agent=True),
            request_id=_request_id(request_id),
            retired_at=self._clock(),
        )

    def rotate_self(
        self, identity: ServicePrincipalIdentity, *, request_id: str,
    ) -> tuple[str, str | None]:
        """Return the new credential id and, on first issue only, its secret."""

        credential_id, verifier, secret = mint_spn_credential()
        result_credential_id, created = self.store.rotate_own_spn_credential(
            identity=identity,
            credential_id=credential_id,
            secret_hash=verifier,
            request_id=_request_id(request_id),
            changed_at=self._clock(),
            max_per_day=MAX_SELF_ROTATIONS_PER_DAY,
        )
        return result_credential_id, secret if created else None
