"""Durable updater intent, replay and single-slot publication state machine."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hmac
from pathlib import Path
import time
from uuid import uuid4

from strugglebus import __version__
from strugglebus.update_storage import StateStorage
from strugglebus.update_types import (
    JsonObject, JsonValue, MAX_TIMESTAMP, UpdateCandidate, UpdateDiscovery, UpdateError,
    UpdateLimits, UpdateObservation, UpdateOperation, UpdatePrepared, UpdateRequest,
    UpdateStatus, observation_from_json, observation_to_json, operation_from_json,
    operation_to_json, prepared_from_json, prepared_to_json, request_from_json,
    request_to_json, require_hex, require_int, require_object, require_safe_text,
)

_PUBLIC_REPOSITORY_IDENTITY_FIRST_VERSION = (0, 2, 31)


def _candidate_digest_matches(candidate: UpdateCandidate, request: UpdateRequest) -> bool:
    supplied = request.candidate_digest
    if supplied is None:
        return False
    if hmac.compare_digest(candidate.digest, supplied):
        return True
    application_version = request.application_version
    if application_version is None:
        return False
    version = tuple(int(part) for part in application_version.split("."))
    return (
        version < _PUBLIC_REPOSITORY_IDENTITY_FIRST_VERSION
        and hmac.compare_digest(candidate.legacy_private_repository_digest, supplied)
    )


@dataclass(frozen=True)
class Receipt:
    request: UpdateRequest
    operation: UpdateOperation
    observation: UpdateObservation | None
    prepared: UpdatePrepared | None


@dataclass(frozen=True)
class Journal:
    policy_id: str
    last_check_at: int | None = None
    current: Receipt | None = None
    observation: UpdateObservation | None = None
    prepared: UpdatePrepared | None = None
    quarantine: str | None = None
    cleanup: str | None = None
    receipts: tuple[Receipt, ...] = ()


def _receipt_to_json(receipt: Receipt) -> JsonObject:
    return {
        "request": request_to_json(receipt.request),
        "operation": operation_to_json(receipt.operation),
        "observation": None if receipt.observation is None else observation_to_json(receipt.observation),
        "prepared": None if receipt.prepared is None else prepared_to_json(receipt.prepared),
    }


def _receipt_from_json(value: JsonValue) -> Receipt:
    obj = require_object(value, {"request", "operation", "observation", "prepared"})
    request = request_from_json(obj["request"])
    operation = operation_from_json(obj["operation"])
    if (request.action != operation.action or request.operation_id != operation.operation_id
            or request.actor_id != operation.actor_id):
        raise UpdateError("state_corrupt")
    return Receipt(
        request, operation,
        None if obj["observation"] is None else observation_from_json(obj["observation"]),
        None if obj["prepared"] is None else prepared_from_json(obj["prepared"]),
    )


def journal_to_json(journal: Journal) -> JsonObject:
    return {
        "version": 1, "policy_id": journal.policy_id, "last_check_at": journal.last_check_at,
        "current": None if journal.current is None else _receipt_to_json(journal.current),
        "observation": None if journal.observation is None else observation_to_json(journal.observation),
        "prepared": None if journal.prepared is None else prepared_to_json(journal.prepared),
        "quarantine": journal.quarantine, "cleanup": journal.cleanup,
        "receipts": [_receipt_to_json(receipt) for receipt in journal.receipts],
    }


def journal_from_json(value: JsonValue, limits: UpdateLimits) -> Journal:
    try:
        obj = require_object(value, {"version", "policy_id", "last_check_at", "current",
                                     "observation", "prepared", "quarantine", "cleanup", "receipts"})
        require_int(obj["version"], 1, 1)
        receipts = obj["receipts"]
        if not isinstance(receipts, list) or len(receipts) > limits.receipt_count:
            raise UpdateError("state_corrupt")
        result = _decode_journal(obj, tuple(_receipt_from_json(r) for r in receipts))
        _validate_journal(result)
        return result
    except UpdateError:
        raise UpdateError("state_corrupt") from None


def _decode_journal(obj: JsonObject, receipts: tuple[Receipt, ...]) -> Journal:
    return Journal(
        require_safe_text(obj["policy_id"]),
        None if obj["last_check_at"] is None else require_int(obj["last_check_at"], MAX_TIMESTAMP),
        None if obj["current"] is None else _receipt_from_json(obj["current"]),
        None if obj["observation"] is None else observation_from_json(obj["observation"]),
        None if obj["prepared"] is None else prepared_from_json(obj["prepared"]),
        None if obj["quarantine"] is None else require_hex(obj["quarantine"], 32),
        None if obj["cleanup"] is None else require_hex(obj["cleanup"], 32),
        receipts,
    )


def _validate_journal(journal: Journal) -> None:
    ids = [receipt.operation.operation_id for receipt in journal.receipts]
    if len(set(ids)) != len(ids):
        raise UpdateError("state_corrupt")
    if any(r.operation.phase not in {"succeeded", "failed", "interrupted"} for r in journal.receipts):
        raise UpdateError("state_corrupt")
    if journal.current is not None:
        operation = journal.current.operation
        if operation.phase not in {"accepted", "running"} or operation.operation_id in ids:
            raise UpdateError("state_corrupt")
    _validate_slots(journal)
    UpdateStatus("idle", __version__, journal.policy_id, None, journal.observation,
                 journal.prepared, True)


def _validate_slots(journal: Journal) -> None:
    prepared = None if journal.prepared is None else journal.prepared.operation_id
    slots = [slot for slot in (prepared, journal.quarantine, journal.cleanup) if slot is not None]
    if len(slots) > 2 or len(set(slots)) != len(slots):
        raise UpdateError("state_corrupt")
    _validate_pending_slots(journal)


def _validate_pending_slots(journal: Journal) -> None:
    if journal.quarantine is not None:
        if journal.current is None or journal.current.request.action != "prepare":
            raise UpdateError("state_corrupt")
        if journal.quarantine != journal.current.operation.operation_id:
            raise UpdateError("state_corrupt")
    if journal.cleanup is not None and journal.current is not None:
        raise UpdateError("state_corrupt")


class UpdateState:
    def __init__(self, storage: StateStorage, policy_id: str, limits: UpdateLimits, *,
                 adopt_policy: bool = False):
        self.storage = storage
        self.limits = limits
        self.journal = journal_from_json(storage.load(), limits)
        self.healthy = True
        if self.journal.policy_id != policy_id:
            if not adopt_policy:
                raise UpdateError("policy_mismatch")
            self._adopt_policy(policy_id)

    def _adopt_policy(self, policy_id: str) -> None:
        """Let a newly installed verifier take over a quiescent predecessor journal.

        Nothing verified under the predecessor policy is trusted: observations,
        the prepared candidate and receipt history are dropped, and the old
        prepared slot is queued for retirement. Only the check cooldown carries.
        """
        journal = self.journal
        if journal.current is not None or journal.quarantine is not None or journal.cleanup is not None:
            raise UpdateError("policy_mismatch")
        self._publish(Journal(
            policy_id, last_check_at=journal.last_check_at,
            cleanup=None if journal.prepared is None else journal.prepared.operation_id,
        ))

    def _publish(self, journal: Journal) -> None:
        _validate_journal(journal)
        try:
            self.storage.save(journal_to_json(journal))
        except (OSError, UpdateError):
            self.healthy = False
            raise UpdateError("state_corrupt") from None
        self.journal = journal

    def status(self, operation_id: str | None = None) -> UpdateStatus:
        if not self.healthy:
            raise UpdateError("state_corrupt")
        journal = self.journal
        receipt = journal.current or (journal.receipts[-1] if journal.receipts else None)
        if operation_id is not None:
            require_hex(operation_id, 32)
            receipt = self._find(operation_id)
        observation = journal.observation
        prepared = journal.prepared
        if operation_id is not None and receipt is not None:
            observation = receipt.observation
        return UpdateStatus(
            _global_state(journal), __version__, journal.policy_id,
            None if receipt is None else receipt.operation,
            observation, prepared, operation_id is None or receipt is not None,
        )

    def _find(self, operation_id: str) -> Receipt | None:
        records = list(self.journal.receipts)
        if self.journal.current is not None:
            records.append(self.journal.current)
        return next((r for r in records if r.operation.operation_id == operation_id), None)

    def accept(self, request: UpdateRequest, *, now: int | None = None) -> bool:
        request = request_from_json(request_to_json(request))
        if request.action == "status" or not self.healthy:
            raise UpdateError("invalid_request")
        operation_id = require_hex(request.operation_id, 32)
        existing = self._find(operation_id)
        if existing is not None:
            if existing.request != request:
                raise UpdateError("conflict")
            return False
        self._admit(request, int(time.time()) if now is None else now)
        return True

    def _admit(self, request: UpdateRequest, now: int) -> None:
        require_int(now, MAX_TIMESTAMP)
        journal = self.journal
        if journal.current is not None:
            raise UpdateError("busy")
        if journal.cleanup is not None:
            raise UpdateError("cleanup_pending")
        if request.action == "check":
            if journal.last_check_at is not None and now - journal.last_check_at < self.limits.check_cooldown:
                raise UpdateError("cooldown")
        else:
            self.candidate_for(request, now=now)
        operation = UpdateOperation(
            require_hex(request.operation_id, 32), request.action,
            require_safe_text(request.actor_id), "accepted", now, None, None,
        )
        receipt = Receipt(request, operation, journal.observation, journal.prepared)
        self._publish(replace(
            journal, current=receipt,
            last_check_at=now if request.action == "check" else journal.last_check_at,
        ))

    def candidate_for(self, request: UpdateRequest, *, now: int) -> UpdateCandidate:
        observation = self._bound_observation(request, now)
        candidate = observation.discovery.candidate
        if candidate is None:
            raise UpdateError("no_candidate")
        if not _candidate_digest_matches(candidate, request):
            raise UpdateError("observation_mismatch")
        if candidate.policy_id != self.journal.policy_id:
            raise UpdateError("policy_mismatch")
        if sum(asset.size_bytes for asset in candidate.assets) > self.limits.candidate_bytes:
            raise UpdateError("storage_full")
        return candidate

    def _bound_observation(self, request: UpdateRequest, now: int) -> UpdateObservation:
        observation = self.journal.observation
        if observation is None or observation.observation_id != request.observation_id:
            raise UpdateError("observation_mismatch")
        if not observation.checked_at <= now < observation.expires_at:
            raise UpdateError("observation_expired")
        if (observation.application_version != request.application_version
                or observation.application_release_id != request.application_release_id):
            raise UpdateError("observation_mismatch")
        return observation

    def start(self) -> Path | None:
        current = self._current()
        operation = replace(current.operation, phase="running")
        quarantine = operation.operation_id if operation.action == "prepare" else None
        self._publish(replace(self.journal, current=replace(current, operation=operation),
                              quarantine=quarantine))
        if quarantine is not None:
            return self.storage.create_slot(quarantine)
        return None

    def _current(self) -> Receipt:
        current = self.journal.current
        if current is None or not self.healthy:
            raise UpdateError("state_corrupt")
        return current

    def finish_check(self, discovery: UpdateDiscovery, *, now: int) -> None:
        current = self._current()
        request = current.request
        if request.action != "check" or request.application_version is None:
            raise UpdateError("state_corrupt")
        if discovery.candidate is not None and discovery.candidate.policy_id != self.journal.policy_id:
            raise UpdateError("policy_mismatch")
        observation = UpdateObservation(
            uuid4().hex, now, now + self.limits.observation_ttl,
            request.application_version, request.application_release_id, discovery,
        )
        self._finish("succeeded", now, None, observation=observation)

    def finish_prepare(self, *, now: int) -> None:
        current = self._current()
        observation = current.observation
        if observation is None or observation.discovery.candidate is None:
            raise UpdateError("state_corrupt")
        self.storage.validate_slot(current.operation.operation_id, observation.discovery.candidate)
        self._publish_prepared(now=now)

    def _publish_prepared(self, *, now: int) -> None:
        """Publish only after the owned job has completed byte and inode verification."""
        current = self._current()
        observation = current.observation
        if observation is None or observation.discovery.candidate is None:
            raise UpdateError("state_corrupt")
        if self.journal.quarantine != current.operation.operation_id:
            raise UpdateError("state_corrupt")
        candidate = observation.discovery.candidate
        prepared = UpdatePrepared(candidate, now, current.operation.operation_id)
        cleanup = None if self.journal.prepared is None else self.journal.prepared.operation_id
        self._finish("succeeded", now, None, prepared=prepared, cleanup=cleanup)
        self.cleanup()

    def fail(self, code: str, *, now: int, interrupted: bool = False) -> None:
        self._finish("interrupted" if interrupted else "failed", now, code,
                     cleanup=self.journal.quarantine)
        self.cleanup()

    def _finish(
        self, phase: str, now: int, error: str | None, *,
        observation: UpdateObservation | None = None,
        prepared: UpdatePrepared | None = None, cleanup: str | None = None,
    ) -> None:
        current = self._current()
        operation = replace(current.operation, phase=phase,
                            finished_at=max(now, current.operation.started_at), error=error)
        observation = observation or self.journal.observation
        prepared = prepared or self.journal.prepared
        receipt = Receipt(current.request, operation, observation, prepared)
        receipts = (self.journal.receipts + (receipt,))[-self.limits.receipt_count:]
        self._publish(replace(
            self.journal, current=None, observation=observation, prepared=prepared,
            quarantine=None, cleanup=cleanup, receipts=receipts,
        ))

    def cleanup(self) -> None:
        operation_id = self.journal.cleanup
        if operation_id is None:
            return
        try:
            self.storage.retire_slot(operation_id)
        except (OSError, UpdateError):
            return
        self._publish(replace(self.journal, cleanup=None))

    def reconcile(self, *, now: int) -> None:
        slots = [self.journal.quarantine, self.journal.cleanup]
        if self.journal.prepared is not None:
            slots.append(self.journal.prepared.operation_id)
        self.storage.validate_inventory(tuple(slot for slot in slots if slot is not None))
        prepared = self.journal.prepared
        if prepared is not None:
            self.storage.validate_slot(prepared.operation_id, prepared.candidate)
        if self.journal.current is not None:
            self.fail("interrupted", now=now, interrupted=True)
        else:
            self.cleanup()


def _global_state(journal: Journal) -> str:
    if journal.current is not None:
        return "checking" if journal.current.operation.action == "check" else "preparing"
    if journal.receipts:
        latest = journal.receipts[-1].operation
        if latest.phase in {"failed", "interrupted"}:
            return latest.phase
    if journal.prepared is not None:
        return "prepared"
    if journal.observation is not None:
        return "observed"
    return "idle"
