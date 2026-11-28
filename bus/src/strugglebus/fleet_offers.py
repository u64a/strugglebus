"""
A worker host offers the fleet it already accepts, so an operator can take it over with no file.

A site that kept its fleet in a repository has hosts running a signed fleet the bus has never
held. Each such host, on finding the bus holds none, offers the exact bytes and the signature it
accepted. The operator's App reads the offers, verifies one against the signer keys it holds, and
publishes it unchanged through the ordinary site-document route.

**The bus is only a carrier.** It checks an offer's shape and size and who sent it. It does not
verify the signature and does not compare the serial with the bytes: a host or a bus that lied
would produce something the App refuses, because the signature is what carries the trust.

Offers are kept in memory, one per host. They are not worth a table: a host offers again on its
next fleet refresh, so a restart loses nothing that does not come back, and they are dropped for
good the moment the bus holds a fleet.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Protocol

from strugglebus.errors import ConfigurationError, DomainValidationError

DOCUMENT = "fleet"
#: The whole request. A 64 KB fleet in base64 is about 88 KB.
MAX_BYTES = 100_000
MAX_FLEET_BYTES = 64 * 1024
MAX_SIGNATURE_CHARS = 4200
SIGNATURE_START = "-----BEGIN SSH SIGNATURE-----"
MINIMUM_GAP = timedelta(seconds=60)
#: More hosts than this offering at once is not a site this is meant for; the oldest offer goes.
MAX_HOSTS = 64
_KEYS = ("serial", "fleet", "sig")


class NotAHostError(DomainValidationError):
    """The caller is not marked as a host, so it may not offer a fleet."""


class FleetHeldError(DomainValidationError):
    """The bus already holds a fleet. The host should stop offering."""


class TooLargeError(DomainValidationError):
    """The offer is larger than an offer may be."""


class TooSoonError(DomainValidationError):
    """The host offered too soon after its last offer."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("offer again later")
        self.retry_after = retry_after


class RefusedError(DomainValidationError):
    """The offer does not fit the contract. ``reason`` is the bus's own fixed words."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class FleetOffer:
    """What one host says it accepts. ``fleet`` is base64 of the exact bytes, as the host sent it."""

    agent_id: str
    agent: str
    serial: int
    fleet: str
    sig: str
    received_at: str


class _Hosts(Protocol):
    def host_statuses(self) -> list[tuple[str, str, str, str | None, str | None]]: ...


class _Documents(Protocol):
    def read(self, name: str) -> Any: ...


def _keys_fault(offer: dict[str, Any]) -> str | None:
    """Why the offer's keys are wrong. A key the bus knows is named; one it does not is the sender's text and is not."""
    for name in _KEYS:
        if name not in offer:
            return f"missing-field:{name}"
    return "unknown-field" if set(offer) - set(_KEYS) else None


def _fleet_fault(fleet: object) -> str | None:
    if type(fleet) is not str:
        return "bad-offer"
    try:
        decoded = base64.b64decode(fleet, validate=True)
    except (binascii.Error, ValueError):
        return "bad-offer"
    return None if 0 < len(decoded) <= MAX_FLEET_BYTES else "bad-offer"


def _signature_fits(sig: object) -> bool:
    return type(sig) is str and len(sig) <= MAX_SIGNATURE_CHARS and sig.startswith(SIGNATURE_START) and sig.isascii()


def refusal(offer: object) -> str | None:
    """Why an offer's shape is refused, or None. Shape only: nothing here says the offer is true."""
    if type(offer) is not dict:
        return "bad-offer"
    fault = _keys_fault(offer)  # type: ignore[arg-type]
    if fault is not None:
        return fault
    serial = offer["serial"]  # type: ignore[index]
    if type(serial) is not int or not 1 <= serial <= 2_000_000_000:
        return "bad-offer"
    fault = _fleet_fault(offer["fleet"])  # type: ignore[index]
    if fault is not None:
        return fault
    return None if _signature_fits(offer["sig"]) else "bad-offer"  # type: ignore[index]


def parsed(body: bytes) -> object:
    """An offer's JSON. One that is too large, or is not JSON, is refused before anything reads it."""
    if len(body) > MAX_BYTES:
        raise TooLargeError("offer is too large")
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        raise RefusedError("bad-json") from None


class FleetOfferService:
    def __init__(self, hosts: _Hosts, documents: _Documents, *, clock: Callable[[], datetime]) -> None:
        self._hosts = hosts
        self._documents = documents
        self._clock = clock
        self._lock = Lock()
        self._offers: dict[str, FleetOffer] = {}
        self._last: dict[str, datetime] = {}

    def _held(self) -> bool:
        """Whether the bus holds a fleet. Once it does, every stored offer is dropped."""
        try:
            document = self._documents.read(DOCUMENT)
        except ConfigurationError:
            document = None
        if document is None:
            return False
        with self._lock:
            self._offers.clear()
        return True

    def _wait(self, agent_id: str, now: datetime) -> int:
        """How many seconds this host must still wait, or 0. Records the attempt when it may go on."""
        last = self._last.get(agent_id)
        if last is not None and now - last < MINIMUM_GAP:
            return max(1, int((MINIMUM_GAP - (now - last)).total_seconds()))
        self._last[agent_id] = now
        return 0

    def offer(self, agent_id: str, agent_name: str, body: bytes) -> None:
        """Keeps a host's offer in place of its last one. Raises to say why not."""
        if agent_id not in {row[0] for row in self._hosts.host_statuses()}:
            raise NotAHostError("not a host")
        offered = parsed(body)
        reason = refusal(offered)
        if reason is not None:
            raise RefusedError(reason)
        if self._held():
            raise FleetHeldError("the bus holds a fleet")
        now = self._clock()
        with self._lock:
            wait = self._wait(agent_id, now)
            if wait:
                raise TooSoonError(wait)
            self._offers.pop(agent_id, None)
            while len(self._offers) >= MAX_HOSTS:
                self._offers.pop(next(iter(self._offers)))
            self._offers[agent_id] = FleetOffer(
                agent_id, agent_name, offered["serial"], offered["fleet"], offered["sig"],  # type: ignore[index]
                now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )

    def offers(self) -> tuple[bool, list[FleetOffer]]:
        """Whether the bus holds a fleet, and the offers of hosts that are still marked, by name."""
        if self._held():
            return True, []
        marked = {row[0] for row in self._hosts.host_statuses()}
        with self._lock:
            kept = [offer for offer in self._offers.values() if offer.agent_id in marked]
        return False, sorted(kept, key=lambda offer: offer.agent)
