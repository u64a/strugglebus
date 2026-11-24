"""Mobile monitor authentication, kept apart from the agent surface.

A monitor is a read-only principal with no coordination authority. It cannot
post, subscribe, hold a delivery cursor, or appear in agent discovery, so it
deliberately does not reuse ``AgentService`` or return an
``AuthenticatedIdentity``. Nothing here can produce an agent identity, and
nothing here accepts an agent credential.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from strugglebus.auth import (
    mint_mobile_credential,
    mint_mobile_enrollment_token,
    mint_mobile_write_grant,
    parse_mobile_credential,
    parse_mobile_enrollment_token,
    parse_mobile_write_grant,
)
from strugglebus.errors import EnrollmentInvalidError
from strugglebus.models import MobileIdentity
from strugglebus.service import normalize_name
from strugglebus.store import SQLiteStore


def _utc_now() -> datetime:
    return datetime.now(UTC)


class MobileService:
    """Resolve mobile credentials to devices."""

    def __init__(
        self,
        store: SQLiteStore,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.store = store
        self._clock = clock

    def authorize(self, secret: str) -> MobileIdentity | None:
        """Return the device a mobile secret proves, or nothing.

        The prefix only routes the value to this parser. Authorisation comes
        from resolving the parsed identifier in the mobile credential table, so
        a prefix collision or a parser mistake cannot by itself admit a caller.
        """

        parsed = parse_mobile_credential(secret)
        if parsed is None:
            return None
        credential_id, verifier = parsed
        return self.store.authenticate_mobile_credential(
            credential_id=credential_id,
            candidate_digest=verifier,
            seen_at_factory=self._clock,
        )

    def authorize_device(self, credential_id: str) -> bool:
        """Report whether a mobile credential is still live.

        Used to revalidate an open stream between messages, so a revoked
        handset stops receiving mid-stream rather than at the next connect.
        """

        return self.store.mobile_credential_is_active(credential_id)

    def mint_enrollment(
        self,
        *,
        device_label: str,
        ttl_seconds: int,
        actor_id: str,
        actor_type: str = "remote-admin",
        reason: str = "operator device enrollment",
    ) -> tuple[str, datetime]:
        """Mint a single-use, label-bound allowance and return its one-time token.

        The token is short lived on purpose. It is displayed on a screen rather
        than handed over a private channel, and it grants an operator-class
        read surface, so its window is deliberately much smaller than an
        agent's.
        """

        label = normalize_name(device_label)
        now = self._clock()
        expires_at = now + timedelta(seconds=ttl_seconds)
        enrollment_id, verifier, token = mint_mobile_enrollment_token()
        self.store.create_mobile_enrollment(
            enrollment_id=enrollment_id,
            secret_hash=verifier,
            device_label=label,
            created_at=now,
            expires_at=expires_at,
            actor_type=actor_type,
            actor_id=actor_id,
            creation_reason=reason,
        )
        return token, expires_at

    def redeem_enrollment(self, token: str, *, request_id: str) -> tuple[MobileIdentity, str]:
        """Exchange an allowance for exactly one device credential.

        Returns the identity and the only copy of its secret. A replay cannot
        return the secret again, so a caller that loses this response must ask
        the operator for a new enrollment rather than retrying.
        """

        parsed = parse_mobile_enrollment_token(token)
        if parsed is None:
            raise EnrollmentInvalidError("enrollment token is not valid")
        enrollment_id, verifier = parsed
        credential_id, secret_hash, secret = mint_mobile_credential()
        identity = self.store.redeem_mobile_enrollment(
            enrollment_id=enrollment_id,
            candidate_digest=verifier,
            device_id=str(uuid4()),
            credential_id=credential_id,
            secret_hash=secret_hash,
            request_id=request_id,
            redeemed_at=self._clock(),
        )
        return identity, secret

    def replace_device(
        self,
        device_id: str,
        *,
        new_label: str,
        ttl_seconds: int,
        actor_id: str,
        actor_type: str = "remote-admin",
        reason: str = "operator device replacement",
    ) -> tuple[str, datetime, str]:
        """Retire a device and mint its replacement's allowance in one step.

        The outgoing keys are revoked at **issue** time, not at redemption, so
        a lost handset stops working the moment the operator asks for a
        replacement rather than whenever the new one is finally set up.

        Returns the one-time token, its expiry, and the retired device's label.
        """

        label = normalize_name(new_label)
        now = self._clock()
        expires_at = now + timedelta(seconds=ttl_seconds)
        enrollment_id, verifier, token = mint_mobile_enrollment_token()
        previous_label = self.store.replace_mobile_device(
            device_id=device_id,
            new_label=label,
            enrollment_id=enrollment_id,
            secret_hash=verifier,
            created_at=now,
            expires_at=expires_at,
            actor_type=actor_type,
            actor_id=actor_id,
            reason=reason,
        )
        return token, expires_at, previous_label

    def list_devices(self) -> tuple[dict[str, object], ...]:
        return self.store.list_mobile_devices()

    def revoke_device(self, device_id: str, *, reason: str, actor_id: str) -> bool:
        return self.store.revoke_mobile_device(
            device_id=device_id,
            reason=reason,
            actor_type="remote-admin",
            actor_id=actor_id,
            revoked_at=self._clock(),
        )

    def device_is_enabled(self, device_id: str) -> bool:
        """Report whether a device itself is still enabled.

        Separate from the credential check: a device can be revoked while a
        credential row lingers, and a write must be refused on either.
        """

        return any(
            device["id"] == device_id and device["status"] == "enabled"
            for device in self.store.list_mobile_devices()
        )

    #: Containment actions a device grant may authorise through the two-phase
    #: confirmation flow. The database enforces this set independently, so a
    #: mistake here cannot widen it. Enrollment and management (unblock,
    #: retire, service principals) are separate, deliberate
    #: allowances with their own routes (routes/mobile.py and
    #: routes/mobile_admin.py), not confirmation actions.
    CONTAINMENT_ACTIONS = frozenset({
        "revoke-device",
        "block-agent",
        "activate-freeze",
        "clear-freeze",
    })

    def establish_write_grant(
        self,
        *,
        device_id: str,
        request_id: str,
        reason: str,
        actor_id: str,
    ) -> str:
        """Prove the operator password once, then hold a per-device secret.

        Returns the secret exactly once. Nothing retains it, so a lost response
        is terminal and needs a fresh establishment rather than a retry, and
        the owner never has to know the value.
        """

        verifier, token = mint_mobile_write_grant(device_id)
        self.store.issue_mobile_write_grant(
            device_id=device_id,
            grant_id=f"mwg_{uuid4().hex}",
            secret_hash=verifier,
            request_id=request_id,
            reason=reason,
            actor_type="remote-admin",
            actor_id=actor_id,
            created_at=self._clock(),
        )
        return token

    def verify_write_grant(self, *, device_id: str, secret: str) -> bool:
        """Check a device's second proof.

        A malformed value still reaches the store, so a device with no grant
        and a device with a wrong grant cost the same and are indistinguishable
        from outside.
        """

        verifier = parse_mobile_write_grant(secret, device_id)
        return self.store.verify_mobile_write_grant(
            device_id=device_id,
            candidate_digest=verifier if verifier is not None else "",
            used_at=self._clock(),
        )

    def request_confirmation(
        self,
        *,
        device_id: str,
        action: str,
        target_kind: str,
        target_id: str,
        target_label: str,
        target_version: int,
        request_id: str,
        lifetime_seconds: int,
    ) -> tuple[str, datetime]:
        """Bind one action to one target for one device, briefly."""

        if action not in self.CONTAINMENT_ACTIONS:
            raise EnrollmentInvalidError("action is not available to a device")
        now = self._clock()
        expires_at = now + timedelta(seconds=lifetime_seconds)
        confirmation_id = f"mac_{uuid4().hex}"
        self.store.create_mobile_action_confirmation(
            confirmation_id=confirmation_id,
            device_id=device_id,
            action=action,
            target_kind=target_kind,
            target_id=target_id,
            target_label=target_label,
            target_version=target_version,
            request_id=request_id,
            created_at=now,
            expires_at=expires_at,
        )
        return confirmation_id, expires_at

    def consume_confirmation(
        self,
        *,
        confirmation_id: str,
        device_id: str,
        action: str,
        target_id: str,
    ) -> dict[str, object] | None:
        """Spend a confirmation only for the action the caller re-declared."""

        return self.store.consume_mobile_action_confirmation(
            confirmation_id=confirmation_id,
            device_id=device_id,
            action=action,
            target_id=target_id,
            consumed_at=self._clock(),
        )
