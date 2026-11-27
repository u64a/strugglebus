"""Strict, credential-free contracts shared by the updater and operator client."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import TypeAlias

JsonValue: TypeAlias = (
    None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]

PROTOCOL_VERSION = 1
# Releases are published in the project's own repository, which also holds the releases of its
# other parts. There a bus release is tagged bus/vX.Y.Z; inside the release, and everywhere in
# this protocol, its tag is still vX.Y.Z.
UPDATE_REPOSITORY = "u64a/strugglebus"
UPDATE_SOURCE_REPOSITORY = "u64a/strugglebus"
RELEASE_TAG_PREFIX = "bus/"
# Where releases were published and built up to 0.2.73. An updater's configuration file written
# for those is still accepted, so moving does not need the file changed at the same moment.
FORMER_UPDATE_REPOSITORY = "NZCypher819/strugglebus-releases"
FORMER_UPDATE_SOURCE_REPOSITORY = "NZCypher819/strugglebus"
LEGACY_UPDATE_REPOSITORY = FORMER_UPDATE_SOURCE_REPOSITORY


def names_the_release_source(release_repository: str, source_repository: str) -> bool:
    """
    Whether an updater's configuration names where releases come from. It may name the present
    place or the former one: the file only confirms what this code already fixes, and a file
    written before the move must not stop the updater that carries the move from starting.
    """
    return (release_repository, source_repository) in {
        (UPDATE_REPOSITORY, UPDATE_SOURCE_REPOSITORY),
        (FORMER_UPDATE_REPOSITORY, FORMER_UPDATE_SOURCE_REPOSITORY),
    }
REQUEST_BYTES = 4096
RESPONSE_BYTES = 65536
MAX_TIMESTAMP = 253402300799
ERROR_CODES = frozenset(
    {
        "invalid_request", "invalid_response", "unavailable", "timeout", "busy",
        "forbidden", "conflict", "cooldown", "history_unavailable", "unknown_outcome",
        "observation_expired", "observation_mismatch", "policy_mismatch",
        "no_candidate", "interrupted", "source_unavailable", "authentication_failed",
        "verification_failed", "publication_changed", "storage_unsafe",
        "storage_full", "state_corrupt", "cleanup_pending", "internal_error",
        "invalid_metadata", "rate_limited", "incomplete", "unsupported_release",
    }
)
ERROR_MESSAGES = MappingProxyType({
    "invalid_request": "The updater request does not match the supported protocol.",
    "invalid_response": "The updater response could not be validated. The outcome is not confirmed.",
    "unavailable": "The updater is unavailable. Existing operation outcomes are not confirmed.",
    "timeout": "The updater deadline expired. Check the operation status before trying again.",
    "busy": "Another updater operation is active. No additional operation was queued.",
    "forbidden": "This caller is not authorized to use the updater.",
    "conflict": "This operation ID is already bound to a different request.",
    "cooldown": "The global update-check cooldown has not elapsed.",
    "history_unavailable": "No retained receipt is available. This does not prove that no work occurred.",
    "unknown_outcome": (
        "The worker did not confirm this operation. It may have started or completed. "
        "Look up the same operation ID before submitting another operation."
    ),
    "observation_expired": "The reviewed update observation has expired. Check for updates again.",
    "observation_mismatch": "The request no longer matches the reviewed update observation.",
    "policy_mismatch": "The installed verifier policy does not match this update state.",
    "no_candidate": "The observation contains no eligible candidate to prepare.",
    "interrupted": "The operation was interrupted. Review its receipt and any pending cleanup.",
    "source_unavailable": "The fixed release source could not be queried successfully.",
    "authentication_failed": "The worker could not authenticate to the fixed release source.",
    "verification_failed": "The candidate files did not pass the installed verification policy.",
    "publication_changed": "The exact release publication changed during verification.",
    "storage_unsafe": "The updater storage does not meet the required safety checks.",
    "storage_full": "The updater storage budget or required free-space reserve is exhausted.",
    "state_corrupt": "The durable updater state cannot be trusted. Do not assume the operation did not run.",
    "cleanup_pending": "Owned cache cleanup remains pending. New work is blocked.",
    "internal_error": "The updater could not complete the request. Check operation status before retrying.",
    "invalid_metadata": "The release metadata does not match the supported format.",
    "rate_limited": "The fixed release source is limiting requests. Try again later.",
    "incomplete": "The bounded release query did not produce complete results.",
    "unsupported_release": "The release is not supported by the installed verification policy.",
})
STATES = frozenset(
    {"idle", "checking", "observed", "preparing", "prepared", "failed",
     "interrupted", "unavailable"}
)
PHASES = frozenset({"accepted", "running", "succeeded", "failed", "interrupted"})
_VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})")
_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+-]*")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


class UpdateError(Exception):
    """A static public failure; never retains upstream messages or credentials."""

    def __init__(self, code: str):
        self.code = code if isinstance(code, str) and code in ERROR_CODES else "internal_error"
        super().__init__(self.code)

    @property
    def message(self) -> str:
        """Static display text; ``str(error)`` retains its existing code contract."""
        return ERROR_MESSAGES[self.code]


def require_object(value: JsonValue, keys: set[str]) -> JsonObject:
    if not isinstance(value, dict) or set(value) != keys:
        raise UpdateError("invalid_request")
    return value


def require_int(value: JsonValue, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise UpdateError("invalid_request")
    return value


def require_bool(value: JsonValue) -> bool:
    if type(value) is not bool:
        raise UpdateError("invalid_request")
    return value


def require_text(value: JsonValue, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value:
        raise UpdateError("invalid_request")
    try:
        if len(value.encode("utf-8")) > maximum:
            raise UpdateError("invalid_request")
    except UnicodeError:
        raise UpdateError("invalid_request") from None
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise UpdateError("invalid_request")
    return value


def require_safe_text(value: JsonValue, maximum: int = 128) -> str:
    text = require_text(value, maximum)
    if _SAFE.fullmatch(text) is None:
        raise UpdateError("invalid_request")
    return text


def require_hex(value: JsonValue, length: int) -> str:
    text = require_text(value, length)
    if re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", text) is None:
        raise UpdateError("invalid_request")
    return text


def require_version(value: JsonValue) -> str:
    text = require_text(value, 32)
    if _VERSION.fullmatch(text) is None:
        raise UpdateError("invalid_request")
    return text


def require_error(value: JsonValue) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in ERROR_CODES:
        raise UpdateError("invalid_request")
    return value


def optional_text(value: JsonValue) -> str | None:
    return None if value is None else require_safe_text(value)


def optional_timestamp(value: JsonValue) -> int | None:
    return None if value is None else require_int(value, MAX_TIMESTAMP)


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise UpdateError("invalid_request")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise UpdateError("invalid_request")


def decode_json(data: bytes, maximum: int) -> JsonValue:
    """Decode bounded JSON, rejecting floats, duplicate keys and excessive depth."""
    if len(data) > maximum:
        raise UpdateError("invalid_request")
    try:
        value: JsonValue = json.loads(
            data.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_float=_reject_number, parse_constant=_reject_number,
        )
        _validate_json(value, 0)
        return value
    except (UnicodeError, ValueError, RecursionError):
        raise UpdateError("invalid_request") from None


def _validate_json(value: JsonValue, depth: int) -> None:
    if depth > 16:
        raise UpdateError("invalid_request")
    if isinstance(value, dict):
        for key, item in value.items():
            require_text(key, 128)
            _validate_json(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_json(item, depth + 1)
    else:
        _validate_json_scalar(value)


def _validate_json_scalar(value: JsonValue) -> None:
    if isinstance(value, str) and value:
        require_text(value, RESPONSE_BYTES)
    elif value is not None and type(value) not in {bool, int, str}:
        raise UpdateError("invalid_request")


def encode_json(value: JsonValue, maximum: int) -> bytes:
    _validate_json(value, 0)
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(data) > maximum:
        raise UpdateError("invalid_request")
    return data


def decode_frame(data: bytes, maximum: int) -> JsonValue:
    if not data.endswith(b"\n") or len(data) > maximum:
        raise UpdateError("invalid_request")
    if any(byte < 32 for byte in data[:-1]):
        raise UpdateError("invalid_request")
    return decode_json(data[:-1], maximum - 1)


def encode_frame(value: JsonValue, maximum: int) -> bytes:
    return encode_json(value, maximum - 1) + b"\n"


@dataclass(frozen=True)
class UpdateLimits:
    """Reviewed ceilings; deployment configuration may only narrow these."""

    release_pages: int = 2
    releases_per_page: int = 20
    metadata_bytes: int = 2 * 1024 * 1024
    observation_ttl: int = 900
    request_timeout: int = 30
    request_attempts: int = 3
    retry_delay: int = 5
    check_timeout: int = 120
    prepare_timeout: int = 600
    candidate_bytes: int = 256 * 1024 * 1024
    artifact_bytes: int = 512 * 1024 * 1024
    journal_bytes: int = 4 * 1024 * 1024
    reserve_bytes: int = 256 * 1024 * 1024
    bytes_per_second: int = 4 * 1024 * 1024
    check_cooldown: int = 60
    receipt_count: int = 16
    connections: int = 4

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            default = field.default
            if type(value) is not int or type(default) is not int or value < 1:
                raise UpdateError("invalid_request")
            if field.name in {"reserve_bytes", "check_cooldown"}:
                if value < default or value > 1024 * 1024 * 1024:
                    raise UpdateError("invalid_request")
            elif value > default:
                raise UpdateError("invalid_request")


def limits_to_json(limits: UpdateLimits) -> JsonObject:
    return {field.name: getattr(limits, field.name) for field in fields(limits)}


def limits_from_json(value: JsonValue) -> UpdateLimits:
    if not isinstance(value, dict):
        raise UpdateError("invalid_request")
    defaults = limits_to_json(UpdateLimits())
    if set(value) - set(defaults):
        raise UpdateError("invalid_request")
    supplied = {key: require_int(item, 1024 * 1024 * 1024, 1) for key, item in value.items()}
    return UpdateLimits(**supplied)


@dataclass(frozen=True)
class UpdateAsset:
    asset_id: int
    name: str
    size_bytes: int
    sha256: str
    media_type: str

    def __post_init__(self) -> None:
        require_int(self.asset_id, 2**63 - 1, 1)
        if _NAME.fullmatch(require_text(self.name, 192)) is None:
            raise UpdateError("invalid_request")
        require_int(self.size_bytes, 256 * 1024 * 1024, 1)
        require_hex(self.sha256, 64)
        require_safe_text(self.media_type)


@dataclass(frozen=True)
class UpdateCandidate:
    version: str
    release_id: int
    tag: str
    tag_object_sha: str
    commit: str
    tree: str
    policy_id: str
    assets: tuple[UpdateAsset, ...]

    def __post_init__(self) -> None:
        require_version(self.version)
        require_int(self.release_id, 2**63 - 1, 1)
        if self.tag != "v" + self.version:
            raise UpdateError("invalid_request")
        for value in (self.tag_object_sha, self.commit, self.tree):
            require_hex(value, 40)
        require_safe_text(self.policy_id)
        _validate_assets(self.assets)

    @property
    def digest(self) -> str:
        return self._repository_digest(UPDATE_REPOSITORY)

    @property
    def legacy_private_repository_digest(self) -> str:
        return self._repository_digest(LEGACY_UPDATE_REPOSITORY)

    def _repository_digest(self, repository: str) -> str:
        identity: JsonObject = {"repository": repository, "candidate": candidate_to_json(self)}
        return hashlib.sha256(encode_json(identity, RESPONSE_BYTES)).hexdigest()


def _validate_assets(assets: tuple[UpdateAsset, ...]) -> None:
    if not isinstance(assets, tuple) or len(assets) != 5:
        raise UpdateError("invalid_request")
    if not all(isinstance(asset, UpdateAsset) for asset in assets):
        raise UpdateError("invalid_request")
    _validate_asset_uniqueness(assets)
    if sum(asset.size_bytes for asset in assets) > UpdateLimits().candidate_bytes:
        raise UpdateError("invalid_request")


def _validate_asset_uniqueness(assets: tuple[UpdateAsset, ...]) -> None:
    if len({asset.asset_id for asset in assets}) != 5 or len({asset.name for asset in assets}) != 5:
        raise UpdateError("invalid_request")


@dataclass(frozen=True)
class UpdateDiscovery:
    candidate: UpdateCandidate | None
    complete: bool
    inspected: int
    blocked_version: str | None
    blocked_reason: str | None

    def __post_init__(self) -> None:
        _optional_instance(self.candidate, UpdateCandidate)
        require_bool(self.complete)
        require_int(self.inspected, 40)
        if self.blocked_version is not None:
            require_version(self.blocked_version)
        require_error(self.blocked_reason)
        if (self.blocked_version is None) != (self.blocked_reason is None):
            raise UpdateError("invalid_request")
        if self.candidate is not None and self.blocked_version is not None:
            raise UpdateError("invalid_request")


@dataclass(frozen=True)
class UpdateOperation:
    operation_id: str
    action: str
    actor_id: str
    phase: str
    started_at: int
    finished_at: int | None
    error: str | None

    def __post_init__(self) -> None:
        require_hex(self.operation_id, 32)
        require_safe_text(self.actor_id)
        if require_text(self.action) not in {"check", "prepare"} or require_text(self.phase) not in PHASES:
            raise UpdateError("invalid_request")
        require_int(self.started_at, MAX_TIMESTAMP)
        optional_timestamp(self.finished_at)
        require_error(self.error)
        _validate_operation_end(self)


def _validate_operation_end(operation: UpdateOperation) -> None:
    terminal = operation.phase in {"succeeded", "failed", "interrupted"}
    if terminal != (operation.finished_at is not None):
        raise UpdateError("invalid_request")
    if operation.finished_at is not None and operation.finished_at < operation.started_at:
        raise UpdateError("invalid_request")
    failed = operation.phase in {"failed", "interrupted"}
    if failed != (operation.error is not None):
        raise UpdateError("invalid_request")


@dataclass(frozen=True)
class UpdateObservation:
    observation_id: str
    checked_at: int
    expires_at: int
    application_version: str
    application_release_id: str | None
    discovery: UpdateDiscovery

    def __post_init__(self) -> None:
        require_hex(self.observation_id, 32)
        require_int(self.checked_at, MAX_TIMESTAMP)
        require_int(self.expires_at, MAX_TIMESTAMP)
        if not 0 < self.expires_at - self.checked_at <= 900:
            raise UpdateError("invalid_request")
        require_version(self.application_version)
        optional_text(self.application_release_id)
        if not isinstance(self.discovery, UpdateDiscovery):
            raise UpdateError("invalid_request")


@dataclass(frozen=True)
class UpdatePrepared:
    candidate: UpdateCandidate
    verified_at: int
    operation_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.candidate, UpdateCandidate):
            raise UpdateError("invalid_request")
        require_int(self.verified_at, MAX_TIMESTAMP)
        require_hex(self.operation_id, 32)


@dataclass(frozen=True)
class UpdateStatus:
    state: str
    worker_version: str
    policy_id: str
    operation: UpdateOperation | None
    observation: UpdateObservation | None
    prepared: UpdatePrepared | None
    history_available: bool

    def __post_init__(self) -> None:
        if require_text(self.state) not in STATES:
            raise UpdateError("invalid_request")
        require_version(self.worker_version)
        require_safe_text(self.policy_id)
        _optional_instance(self.operation, UpdateOperation)
        _optional_instance(self.observation, UpdateObservation)
        _optional_instance(self.prepared, UpdatePrepared)
        require_bool(self.history_available)
        _validate_status_policy(self)


def _optional_instance(value: object, kind: type) -> None:
    if value is not None and not isinstance(value, kind):
        raise UpdateError("invalid_request")


def _validate_status_policy(status: UpdateStatus) -> None:
    candidates = [status.prepared.candidate] if status.prepared is not None else []
    if status.observation is not None and status.observation.discovery.candidate is not None:
        candidates.append(status.observation.discovery.candidate)
    if any(candidate.policy_id != status.policy_id for candidate in candidates):
        raise UpdateError("invalid_request")


def asset_to_json(value: UpdateAsset) -> JsonObject:
    return {"asset_id": value.asset_id, "name": value.name, "size_bytes": value.size_bytes,
            "sha256": value.sha256, "media_type": value.media_type}


def asset_from_json(value: JsonValue) -> UpdateAsset:
    obj = require_object(value, {"asset_id", "name", "size_bytes", "sha256", "media_type"})
    return UpdateAsset(require_int(obj["asset_id"], 2**63 - 1, 1),
                       require_text(obj["name"], 192),
                       require_int(obj["size_bytes"], 256 * 1024 * 1024, 1),
                       require_hex(obj["sha256"], 64), require_safe_text(obj["media_type"]))


def candidate_to_json(value: UpdateCandidate) -> JsonObject:
    return {"version": value.version, "release_id": value.release_id, "tag": value.tag,
            "tag_object_sha": value.tag_object_sha, "commit": value.commit, "tree": value.tree,
            "policy_id": value.policy_id, "assets": [asset_to_json(a) for a in value.assets]}


def candidate_from_json(value: JsonValue) -> UpdateCandidate:
    obj = require_object(value, {"version", "release_id", "tag", "tag_object_sha",
                                 "commit", "tree", "policy_id", "assets"})
    assets = obj["assets"]
    if not isinstance(assets, list) or len(assets) != 5:
        raise UpdateError("invalid_request")
    return UpdateCandidate(
        require_version(obj["version"]), require_int(obj["release_id"], 2**63 - 1, 1),
        require_text(obj["tag"]), require_hex(obj["tag_object_sha"], 40),
        require_hex(obj["commit"], 40), require_hex(obj["tree"], 40),
        require_safe_text(obj["policy_id"]), tuple(asset_from_json(a) for a in assets),
    )


def discovery_to_json(value: UpdateDiscovery) -> JsonObject:
    return {"candidate": None if value.candidate is None else candidate_to_json(value.candidate),
            "complete": value.complete, "inspected": value.inspected,
            "blocked_version": value.blocked_version, "blocked_reason": value.blocked_reason}


def discovery_from_json(value: JsonValue) -> UpdateDiscovery:
    obj = require_object(value, {"candidate", "complete", "inspected", "blocked_version", "blocked_reason"})
    return UpdateDiscovery(
        None if obj["candidate"] is None else candidate_from_json(obj["candidate"]),
        require_bool(obj["complete"]), require_int(obj["inspected"], 40),
        None if obj["blocked_version"] is None else require_version(obj["blocked_version"]),
        require_error(obj["blocked_reason"]),
    )


def operation_to_json(value: UpdateOperation) -> JsonObject:
    return {"operation_id": value.operation_id, "action": value.action, "actor_id": value.actor_id,
            "phase": value.phase, "started_at": value.started_at, "finished_at": value.finished_at,
            "error": value.error}


def operation_from_json(value: JsonValue) -> UpdateOperation:
    obj = require_object(value, {"operation_id", "action", "actor_id", "phase", "started_at",
                                 "finished_at", "error"})
    return UpdateOperation(
        require_hex(obj["operation_id"], 32), require_text(obj["action"]),
        require_safe_text(obj["actor_id"]), require_text(obj["phase"]),
        require_int(obj["started_at"], MAX_TIMESTAMP), optional_timestamp(obj["finished_at"]),
        require_error(obj["error"]),
    )


def observation_to_json(value: UpdateObservation) -> JsonObject:
    return {"observation_id": value.observation_id, "checked_at": value.checked_at,
            "expires_at": value.expires_at, "application_version": value.application_version,
            "application_release_id": value.application_release_id,
            "discovery": discovery_to_json(value.discovery)}


def observation_from_json(value: JsonValue) -> UpdateObservation:
    obj = require_object(value, {"observation_id", "checked_at", "expires_at", "application_version",
                                 "application_release_id", "discovery"})
    return UpdateObservation(
        require_hex(obj["observation_id"], 32), require_int(obj["checked_at"], MAX_TIMESTAMP),
        require_int(obj["expires_at"], MAX_TIMESTAMP), require_version(obj["application_version"]),
        optional_text(obj["application_release_id"]), discovery_from_json(obj["discovery"]),
    )


def prepared_to_json(value: UpdatePrepared) -> JsonObject:
    return {"candidate": candidate_to_json(value.candidate), "verified_at": value.verified_at,
            "operation_id": value.operation_id}


def prepared_from_json(value: JsonValue) -> UpdatePrepared:
    obj = require_object(value, {"candidate", "verified_at", "operation_id"})
    return UpdatePrepared(candidate_from_json(obj["candidate"]),
                          require_int(obj["verified_at"], MAX_TIMESTAMP),
                          require_hex(obj["operation_id"], 32))


def status_to_json(value: UpdateStatus) -> JsonObject:
    return {"state": value.state, "worker_version": value.worker_version, "policy_id": value.policy_id,
            "operation": None if value.operation is None else operation_to_json(value.operation),
            "observation": None if value.observation is None else observation_to_json(value.observation),
            "prepared": None if value.prepared is None else prepared_to_json(value.prepared),
            "history_available": value.history_available}


def status_from_json(value: JsonValue) -> UpdateStatus:
    obj = require_object(value, {"state", "worker_version", "policy_id", "operation", "observation",
                                 "prepared", "history_available"})
    return UpdateStatus(
        require_text(obj["state"]), require_version(obj["worker_version"]),
        require_safe_text(obj["policy_id"]),
        None if obj["operation"] is None else operation_from_json(obj["operation"]),
        None if obj["observation"] is None else observation_from_json(obj["observation"]),
        None if obj["prepared"] is None else prepared_from_json(obj["prepared"]),
        require_bool(obj["history_available"]),
    )


@dataclass(frozen=True)
class UpdateRequest:
    action: str
    operation_id: str | None = None
    actor_id: str | None = None
    application_version: str | None = None
    application_release_id: str | None = None
    observation_id: str | None = None
    candidate_digest: str | None = None


def request_to_json(value: UpdateRequest) -> JsonObject:
    result: JsonObject = {"version": PROTOCOL_VERSION, "action": value.action,
                          "operation_id": value.operation_id}
    if value.action != "status":
        result.update(actor_id=value.actor_id, application_version=value.application_version,
                      application_release_id=value.application_release_id)
    if value.action == "prepare":
        result.update(observation_id=value.observation_id, candidate_digest=value.candidate_digest)
    request_from_json(result)
    return result


def request_from_json(value: JsonValue) -> UpdateRequest:
    if not isinstance(value, dict):
        raise UpdateError("invalid_request")
    action = require_text(value.get("action"))
    if action not in {"status", "check", "prepare"}:
        raise UpdateError("invalid_request")
    keys = {"version", "action", "operation_id"}
    if action != "status":
        keys |= {"actor_id", "application_version", "application_release_id"}
    if action == "prepare":
        keys |= {"observation_id", "candidate_digest"}
    obj = require_object(value, keys)
    require_int(obj["version"], 1, 1)
    operation_id = obj["operation_id"]
    if action == "status":
        return UpdateRequest(action, None if operation_id is None else require_hex(operation_id, 32))
    return _work_request(obj, action)


def _work_request(obj: JsonObject, action: str) -> UpdateRequest:
    return UpdateRequest(
        action, require_hex(obj["operation_id"], 32), require_safe_text(obj["actor_id"]),
        require_version(obj["application_version"]), optional_text(obj["application_release_id"]),
        require_hex(obj["observation_id"], 32) if action == "prepare" else None,
        require_hex(obj["candidate_digest"], 64) if action == "prepare" else None,
    )


def response_to_json(status: UpdateStatus | None = None, error: str | None = None) -> JsonObject:
    require_error(error)
    if (status is None) == (error is None):
        raise UpdateError("invalid_response")
    return {"version": PROTOCOL_VERSION, "ok": error is None, "error": error,
            "status": None if status is None else status_to_json(status)}


def response_from_json(value: JsonValue) -> UpdateStatus:
    obj = require_object(value, {"version", "ok", "error", "status"})
    require_int(obj["version"], 1, 1)
    ok = require_bool(obj["ok"])
    error = require_error(obj["error"])
    if ok and error is None and obj["status"] is not None:
        return status_from_json(obj["status"])
    if not ok and error is not None and obj["status"] is None:
        raise UpdateError(error)
    raise UpdateError("invalid_response")
