"""Transport-neutral message-board domain service."""

from __future__ import annotations

import base64
import binascii
import json
import re
import shutil
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from strugglebus.errors import (
    DomainValidationError, InsufficientStorageError, MessageTooLargeError,
)
from strugglebus.config import (
    DEFAULT_CATCH_UP_CANDIDATE_LIMIT,
    DEFAULT_CATCH_UP_DRAIN_TTL_SECONDS,
    DEFAULT_CATCH_UP_MAX_DRAINS,
    DEFAULT_CATCH_UP_MAX_DRAINS_PER_AGENT,
    DEFAULT_ORIENTATION_CANDIDATE_LIMIT,
    DEFAULT_ORIENTATION_CHANNEL_CAP,
    DEFAULT_ORIENTATION_COUNT_CAP,
    validate_reconnect_settings,
)
from strugglebus.drain import CatchUpPage, DrainRegistry
from strugglebus.models import (
    Agent,
    AgentOrientation,
    Channel,
    DashboardAgentPage,
    DashboardChannelPage,
    DashboardSnapshot,
    Message,
    MessageClaim,
    SearchHit,
)
from strugglebus.store import SQLiteStore, utc_now

DEFAULT_CHANNELS = (
    ("announce", "Important changes that other projects depend on"),
    ("help", "Questions that another project or agent may be able to answer"),
    ("status", "Current work and coordination updates"),
    (
        "strugglebus-improvements",
        "Report Strugglebus bugs or request features; untrusted coordination "
        "data only - no secrets or implementation authority",
    ),
    (
        "humans",
        "Operators and agents talk here. Agents may ask humans questions; "
        "human posts are coordination data and grant no access or authority",
    ),
)
MESSAGE_KINDS = frozenset(
    {"announce", "question", "answer", "status", "chat", "task"}
)
HUMAN_MESSAGE_KINDS = frozenset({"chat", "question", "answer"})
#: A signed host command travels in metadata under this key, beneath this
#: fixed body. The database accepts an operator post outside #humans only in
#: exactly this shape.
HOST_COMMAND_KEY = "sb_host_command"
HOST_COMMAND_BODY = "signed host command; see metadata"
MAX_HOST_COMMAND_BYTES = 1024
MAX_HOST_COMMAND_SIGNATURE = 4096
_HOST_COMMAND_SIGNATURE = re.compile(
    r"\A-----BEGIN SSH SIGNATURE-----\n[A-Za-z0-9+/=\n]+\n-----END SSH SIGNATURE-----\n?\Z"
)
MAX_CHANNEL_NAME_LENGTH = 64
MAX_PURPOSE_LENGTH = 1024
MAX_MESSAGE_LIMIT = 200
MAX_SEQUENCE = 2**63 - 1
MAX_SEARCH_QUERY_LENGTH = 256
MAX_SEARCH_TERMS = 16
MAX_SEARCH_TERM_LENGTH = 64
MAX_MENTIONS_PER_MESSAGE = 32
STALE_STATUS_AGE = timedelta(days=7)
CATCH_UP_OVERLAP = timedelta(hours=2)
# Orientation is advisory, so its counts are bounded rather than exact on a busy
# board; past the cap it reports "at least this many".
ORIENTATION_COUNT_CAP = 500
ORIENTATION_CHANNEL_CAP = 50
_SEPARATORS = re.compile(r"[\s_]+")
_REPEATED_HYPHENS = re.compile(r"-+")
_KEBAB = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MENTION = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"@(?P<name>[a-z0-9]+(?:-[a-z0-9]+)+)"
    r"(?![A-Za-z0-9-]|\.[A-Za-z0-9])",
    re.IGNORECASE,
)
_SEARCH_TERM = re.compile(r"[^\W_]+(?:['-][^\W_]+)*", re.UNICODE)


def _is_kebab_name(normalized: str, *, agent: bool) -> bool:
    """Whether an already-normalized name is acceptable for its kind."""

    maximum = 128 if agent else MAX_CHANNEL_NAME_LENGTH
    if not normalized or len(normalized) > maximum:
        return False
    if _KEBAB.fullmatch(normalized) is None:
        return False
    # An agent name carries a project and a platform, so it has a hyphen.
    return not agent or "-" in normalized


def normalize_name(value: str, *, agent: bool = False) -> str:
    if not isinstance(value, str):
        raise DomainValidationError("name must be text")
    normalized = value.strip()
    if not agent:
        normalized = normalized.removeprefix("#")
    normalized = _REPEATED_HYPHENS.sub(
        "-", _SEPARATORS.sub("-", normalized.lower())
    )
    if not _is_kebab_name(normalized, agent=agent):
        kind = "agent" if agent else "channel"
        suffix = " with project and platform" if agent else ""
        raise DomainValidationError(
            f"{kind} name must be lowercase kebab-case{suffix}"
        )
    return normalized


def _bounded_text(name: str, value: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise DomainValidationError(f"{name} must be text")
    if "\x00" in value:
        raise DomainValidationError(f"{name} must not contain NUL")
    if len(value) > maximum:
        raise DomainValidationError(
            f"{name} must not exceed {maximum} characters"
        )
    return value


def _validate_json_number(value: float) -> None:
    if value != value or value in {float("inf"), float("-inf")}:
        raise DomainValidationError("metadata numbers must be finite")


def _has_json_keys(value: dict[Any, Any]) -> bool:
    return all(isinstance(key, str) and "\x00" not in key for key in value)


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 8:
        raise DomainValidationError("metadata nesting exceeds 8 levels")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        _validate_json_number(value)
        return
    if isinstance(value, list):
        children: Any = value
    elif isinstance(value, dict) and _has_json_keys(value):
        children = value.values()
    else:
        raise DomainValidationError("metadata must contain only JSON values")
    for item in children:
        _validate_json_value(item, depth=depth + 1)


def parse_mentions(body: str) -> tuple[str, ...]:
    mentions = tuple(
        dict.fromkeys(match.group("name").lower() for match in _MENTION.finditer(body))
    )
    if len(mentions) > MAX_MENTIONS_PER_MESSAGE:
        raise DomainValidationError(
            f"message must not mention more than {MAX_MENTIONS_PER_MESSAGE} agents"
        )
    return mentions


def _validate_message_body(body: str, maximum: int) -> None:
    if not isinstance(body, str):
        raise DomainValidationError("body must be text")
    if "\x00" in body:
        raise DomainValidationError("body must not contain NUL")
    if not body:
        raise DomainValidationError("body must not be empty")
    if len(body.encode("utf-8")) > maximum:
        raise MessageTooLargeError("message body exceeds configured limit")


# Below this much free space new messages are refused, so a looping agent
# cannot fill the disk to the point where SQLite, backups and the operator's
# own recovery commands stop working.
MINIMUM_FREE_BYTES = 64 * 1024 * 1024


def require_free_space(database_path: Path) -> None:
    try:
        free = shutil.disk_usage(database_path.parent).free
    except OSError:
        return  # The write itself reports an unusable disk.
    if free < MINIMUM_FREE_BYTES:
        raise InsufficientStorageError(
            "the bus is out of disk space and is not accepting new messages; "
            "tell the operator"
        )


def _validate_message_seq(message_seq: int) -> None:
    if (
        isinstance(message_seq, bool)
        or not isinstance(message_seq, int)
        or message_seq < 1
        or message_seq > MAX_SEQUENCE
    ):
        raise DomainValidationError(
            f"message_seq must be between 1 and {MAX_SEQUENCE}"
        )


def _validate_reply_to(reply_to: int | None) -> None:
    if reply_to is not None and (
        isinstance(reply_to, bool)
        or not isinstance(reply_to, int)
        or reply_to < 1
        or reply_to > MAX_SEQUENCE
    ):
        raise DomainValidationError(
            f"reply_to must be between 1 and {MAX_SEQUENCE}"
        )


def _serialize_message_metadata(metadata: Mapping[str, Any], maximum: int) -> str:
    if not isinstance(metadata, Mapping):
        raise DomainValidationError("metadata must be a JSON object")
    metadata_object = dict(metadata)
    _validate_json_value(metadata_object)
    serialized = json.dumps(
        metadata_object,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized.encode("utf-8")) > maximum:
        raise DomainValidationError(f"metadata must not exceed {maximum} bytes")
    return serialized


def _search_expression(query: str) -> str:
    _bounded_text("query", query, MAX_SEARCH_QUERY_LENGTH)
    terms = _SEARCH_TERM.findall(query)
    if not terms:
        raise DomainValidationError("query must contain a searchable term")
    if len(terms) > MAX_SEARCH_TERMS:
        raise DomainValidationError(
            f"query must contain at most {MAX_SEARCH_TERMS} terms"
        )
    if any(len(term) > MAX_SEARCH_TERM_LENGTH for term in terms):
        raise DomainValidationError(
            f"query terms must not exceed {MAX_SEARCH_TERM_LENGTH} characters"
        )
    escaped_terms = (term.replace('"', '""') for term in terms)
    return " AND ".join(f'"{term}"' for term in escaped_terms)


class BoardService:
    def __init__(
        self,
        store: SQLiteStore,
        *,
        max_message_bytes: int,
        max_metadata_bytes: int,
        max_channels: int,
        clock: Callable[[], datetime] = utc_now,
        orientation_count_cap: int = DEFAULT_ORIENTATION_COUNT_CAP,
        orientation_channel_cap: int = DEFAULT_ORIENTATION_CHANNEL_CAP,
        orientation_candidate_limit: int = DEFAULT_ORIENTATION_CANDIDATE_LIMIT,
        catch_up_candidate_limit: int = DEFAULT_CATCH_UP_CANDIDATE_LIMIT,
        catch_up_drain_ttl_seconds: int = DEFAULT_CATCH_UP_DRAIN_TTL_SECONDS,
        catch_up_max_drains: int = DEFAULT_CATCH_UP_MAX_DRAINS,
        catch_up_max_drains_per_agent: int = DEFAULT_CATCH_UP_MAX_DRAINS_PER_AGENT,
    ) -> None:
        validate_reconnect_settings({
            "orientation_count_cap": orientation_count_cap,
            "orientation_channel_cap": orientation_channel_cap,
            "orientation_candidate_limit": orientation_candidate_limit,
            "catch_up_candidate_limit": catch_up_candidate_limit,
            "catch_up_drain_ttl_seconds": catch_up_drain_ttl_seconds,
            "catch_up_max_drains": catch_up_max_drains,
            "catch_up_max_drains_per_agent": catch_up_max_drains_per_agent,
        })
        self.store = store
        self.max_message_bytes = max_message_bytes
        self.max_metadata_bytes = max_metadata_bytes
        self.max_channels = max_channels
        self._clock = clock
        self.orientation_count_cap = orientation_count_cap
        self.orientation_channel_cap = orientation_channel_cap
        self.orientation_candidate_limit = orientation_candidate_limit
        self.catch_up_candidate_limit = catch_up_candidate_limit
        self._drains = DrainRegistry(
            maximum=catch_up_max_drains,
            per_agent=catch_up_max_drains_per_agent,
            ttl_seconds=catch_up_drain_ttl_seconds,
        )

    def initialize(self) -> int:
        version = self.store.initialize()
        self.store.ensure_default_channels(
            DEFAULT_CHANNELS, created_at=self._clock()
        )
        return version

    def check_readiness(self) -> None:
        self.store.check_readiness()

    def list_agents(self, *, require_access: bool = True) -> tuple[Agent, ...]:
        return self.store.list_enabled_agents(require_access=require_access)

    def create_channel(
        self,
        name: str,
        *,
        purpose: str,
        created_by: str,
    ) -> Channel:
        normalized = normalize_name(name)
        purpose = _bounded_text("purpose", purpose, MAX_PURPOSE_LENGTH)
        return self.store.create_channel(
            channel_id=str(uuid.uuid4()),
            name=normalized,
            purpose=purpose,
            created_at=self._clock(),
            created_by=created_by,
            max_channels=self.max_channels,
        )

    def list_channels(self) -> tuple[Channel, ...]:
        return self.store.list_channels()

    def list_subscriptions(self, agent_id: str) -> tuple[Channel, ...]:
        return self.store.list_subscriptions(agent_id)

    def subscribe(self, channel_name: str, *, agent_id: str) -> Channel:
        normalized = normalize_name(channel_name)
        return self.store.subscribe(
            agent_id=agent_id,
            channel_name=normalized,
            created_at=self._clock(),
        )

    def unsubscribe(self, channel_name: str, *, agent_id: str) -> Channel:
        normalized = normalize_name(channel_name)
        return self.store.unsubscribe(
            agent_id=agent_id,
            channel_name=normalized,
        )

    def list_messages(
        self,
        channel_name: str,
        *,
        since: int = 0,
        limit: int = 50,
    ) -> tuple[Message, ...]:
        normalized = normalize_name(channel_name)
        if (
            isinstance(since, bool)
            or not isinstance(since, int)
            or since < 0
            or since > MAX_SEQUENCE
        ):
            raise DomainValidationError(
                f"since must be between 0 and {MAX_SEQUENCE}"
            )
        if (
            isinstance(limit, bool)
            or limit < 1
            or limit > MAX_MESSAGE_LIMIT
        ):
            raise DomainValidationError(
                f"limit must be between 1 and {MAX_MESSAGE_LIMIT}"
            )
        return self.store.list_messages(
            normalized, since=since, limit=limit
        )

    def create_message(
        self,
        channel_name: str,
        *,
        agent_id: str,
        body: str,
        kind: str,
        reply_to: int | None,
        metadata: Mapping[str, Any],
        request_id: str | None = None,
    ) -> Message:
        normalized = normalize_name(channel_name)
        _validate_message_body(body, self.max_message_bytes)
        require_free_space(self.store.database_path)
        if kind not in MESSAGE_KINDS:
            raise DomainValidationError("message kind is invalid")
        # The bus only guarantees a task carries a structured payload; the
        # payload's schema belongs to the coordinator and hosts, not the bus.
        if kind == "task" and not (
            isinstance(metadata, Mapping)
            and isinstance(metadata.get("task"), Mapping)
        ):
            raise DomainValidationError(
                "task messages require a metadata.task JSON object"
            )
        _validate_reply_to(reply_to)
        metadata_json = _serialize_message_metadata(metadata, self.max_metadata_bytes)
        return self.store.create_message(
            message_id=str(uuid.uuid4()),
            channel_name=normalized,
            agent_id=agent_id,
            body=body,
            kind=kind,
            reply_to=reply_to,
            metadata_json=metadata_json,
            created_at=self._clock(),
            mentioned_names=parse_mentions(body),
            request_id=request_id,
        )

    def create_human_message(
        self,
        *,
        body: str,
        kind: str,
        reply_to: int | None,
        request_id: str,
    ) -> Message:
        """Operator-plane post to #humans; callers must hold an operator session."""
        _validate_message_body(body, self.max_message_bytes)
        require_free_space(self.store.database_path)
        if kind not in HUMAN_MESSAGE_KINDS:
            raise DomainValidationError("message kind is invalid")
        _validate_reply_to(reply_to)
        return self.store.create_human_message(
            message_id=str(uuid.uuid4()),
            body=body,
            kind=kind,
            reply_to=reply_to,
            metadata_json="{}",
            created_at=self._clock(),
            mentioned_names=parse_mentions(body),
            request_id=request_id,
        )

    def create_host_command(
        self,
        *,
        channel_name: str,
        document: str,
        signature: str,
        request_id: str,
    ) -> Message:
        """Carry one signed host command to a worker hosts' channel.

        ``document`` is base64 of the signed bytes. The bus checks sizes and
        shape and nothing else: it never decodes what the command says.
        """
        require_free_space(self.store.database_path)
        try:
            size = len(base64.b64decode(document, validate=True))
        except (binascii.Error, ValueError):
            raise DomainValidationError("the command is not valid base64") from None
        if not 1 <= size <= MAX_HOST_COMMAND_BYTES:
            raise DomainValidationError(
                f"a host command is 1 to {MAX_HOST_COMMAND_BYTES} bytes"
            )
        signature = signature.replace("\r\n", "\n")
        if (
            len(signature) > MAX_HOST_COMMAND_SIGNATURE
            or _HOST_COMMAND_SIGNATURE.fullmatch(signature) is None
        ):
            raise DomainValidationError(
                "the signature is not an armored SSH signature"
            )
        return self.store.create_host_command_message(
            message_id=str(uuid.uuid4()),
            channel_name=normalize_name(channel_name),
            body=HOST_COMMAND_BODY,
            metadata_json=json.dumps(
                {HOST_COMMAND_KEY: {"doc": document, "sig": signature}},
                ensure_ascii=True, separators=(",", ":"),
            ),
            created_at=self._clock(),
            request_id=request_id,
        )

    def read_replies(
        self,
        message_seq: int,
        *,
        since: int = 0,
        limit: int = 50,
    ) -> tuple[Message, ...]:
        _validate_message_seq(message_seq)
        if (
            isinstance(since, bool)
            or not isinstance(since, int)
            or since < 0
            or since > MAX_SEQUENCE
        ):
            raise DomainValidationError(
                f"since must be between 0 and {MAX_SEQUENCE}"
            )
        self._validate_limit(limit)
        return self.store.read_replies(
            message_seq=message_seq,
            since=since,
            limit=limit,
        )

    def claim_message(
        self, message_seq: int, *, agent_id: str
    ) -> tuple[MessageClaim, bool]:
        _validate_message_seq(message_seq)
        return self.store.claim_message(
            message_seq=message_seq, agent_id=agent_id, claimed_at=self._clock()
        )

    def get_message_claim(self, message_seq: int) -> MessageClaim:
        _validate_message_seq(message_seq)
        return self.store.get_message_claim(message_seq=message_seq)

    def release_message_claim(self, message_seq: int, *, agent_id: str) -> None:
        _validate_message_seq(message_seq)
        self.store.release_message_claim(message_seq=message_seq, agent_id=agent_id)

    def orientation(
        self,
        *,
        agent_id: str,
        include_stale: bool = False,
    ) -> AgentOrientation:
        """Summarize unseen work for a reconnecting agent without moving cursors."""

        if not isinstance(include_stale, bool):
            raise DomainValidationError("include_stale must be true or false")
        now = self._clock()
        return self.store.agent_orientation(
            agent_id=agent_id,
            stale_before=now - STALE_STATUS_AGE,
            include_stale=include_stale,
            count_cap=self.orientation_count_cap,
            channel_cap=self.orientation_channel_cap,
            candidate_limit=self.orientation_candidate_limit,
            max_channels=self.max_channels,
        )

    def catch_up(
        self,
        *,
        agent_id: str,
        limit: int = 50,
        include_stale: bool = False,
    ) -> tuple[Message, ...]:
        self._validate_limit(limit)
        if not isinstance(include_stale, bool):
            raise DomainValidationError("include_stale must be true or false")
        now = self._clock()
        return self.store.catch_up(
            agent_id=agent_id,
            limit=limit,
            overlap_since=now - CATCH_UP_OVERLAP,
            stale_before=now - STALE_STATUS_AGE,
            include_stale=include_stale,
            updated_at=now,
        )

    def catch_up_page(
        self,
        *,
        agent_id: str,
        limit: int = 50,
        include_stale: bool = False,
        start_drain: bool = False,
        continuation: str | None = None,
    ) -> CatchUpPage:
        self._validate_limit(limit)
        if not isinstance(include_stale, bool) or not isinstance(start_drain, bool):
            raise DomainValidationError("catch-up flags must be true or false")
        if start_drain and continuation is not None:
            raise DomainValidationError(
                "start_drain and continuation cannot be combined"
            )
        if not start_drain and continuation is None:
            return CatchUpPage(
                messages=self.catch_up(
                    agent_id=agent_id, limit=limit, include_stale=include_stale
                )
            )
        now = self._clock()
        return self._drains.run(
            agent_id=agent_id,
            limit=limit,
            include_stale=include_stale,
            continuation=continuation,
            now=now,
            operation=lambda snapshot, position, build_page: self.store.catch_up_page(
                agent_id=agent_id,
                limit=limit,
                include_stale=include_stale,
                overlap_since=now - CATCH_UP_OVERLAP,
                stale_before=now - STALE_STATUS_AGE,
                updated_at=now,
                snapshot=snapshot,
                after_seq=position,
                candidate_limit=self.catch_up_candidate_limit,
                max_channels=self.max_channels,
                build_page=build_page,
            ),
        )

    def search(
        self,
        query: str,
        *,
        channel_name: str | None = None,
        limit: int = 50,
        include_stale: bool = False,
    ) -> tuple[SearchHit, ...]:
        self._validate_limit(limit)
        if not isinstance(include_stale, bool):
            raise DomainValidationError("include_stale must be true or false")
        normalized_channel = (
            None if channel_name is None else normalize_name(channel_name)
        )
        return self.store.search_messages(
            match_expression=_search_expression(query),
            channel_name=normalized_channel,
            limit=limit,
            stale_before=self._clock() - STALE_STATUS_AGE,
            include_stale=include_stale,
        )

    def stream_messages(
        self,
        *,
        since: int,
        limit: int = MAX_MESSAGE_LIMIT,
        channel_name: str | None = None,
    ) -> tuple[Message, ...]:
        if (
            isinstance(since, bool)
            or not isinstance(since, int)
            or since < 0
            or since > MAX_SEQUENCE
        ):
            raise DomainValidationError(
                f"since must be between 0 and {MAX_SEQUENCE}"
            )
        self._validate_limit(limit)
        normalized = (
            None if channel_name is None else normalize_name(channel_name)
        )
        return self.store.list_messages_after(
            since=since, limit=limit, channel_name=normalized
        )

    def require_channel(self, channel_name: str) -> None:
        """Reject an unknown channel loudly instead of streaming nothing."""

        self.store.require_channel(normalize_name(channel_name))

    def recent_activity(self, *, limit: int = 100) -> tuple[Message, ...]:
        self._validate_limit(limit)
        return self.store.list_recent_messages(limit=limit)

    def dashboard_snapshot(
        self,
        *,
        channel_name: str | None,
        agent_name: str | None,
        before: int | None,
        limit: int,
    ) -> DashboardSnapshot:
        normalized_channel = (
            None if channel_name is None else normalize_name(channel_name)
        )
        normalized_agent = (
            None
            if agent_name is None
            else normalize_name(agent_name, agent=True)
        )
        if before is not None and (
            isinstance(before, bool)
            or not isinstance(before, int)
            or before < 1
            or before > MAX_SEQUENCE
        ):
            raise DomainValidationError(
                f"before must be between 1 and {MAX_SEQUENCE}"
            )
        self._validate_limit(limit)
        return self.store.dashboard_snapshot(
            channel_name=normalized_channel,
            agent_name=normalized_agent,
            before=before,
            limit=limit,
        )

    def channel_activity(
        self,
        *,
        after: str | None,
        limit: int,
    ) -> DashboardChannelPage:
        normalized_after = self._validate_cursor(after, agent=False)
        self._validate_limit(limit)
        return self.store.dashboard_channels(after=normalized_after, limit=limit)

    def agent_activity(
        self,
        *,
        after: str | None,
        limit: int,
    ) -> DashboardAgentPage:
        normalized_after = self._validate_cursor(after, agent=True)
        self._validate_limit(limit)
        return self.store.dashboard_agents(after=normalized_after, limit=limit)

    @staticmethod
    def _validate_cursor(value: str | None, *, agent: bool) -> str | None:
        if value is None:
            return None
        normalized = normalize_name(value, agent=agent)
        if normalized != value:
            raise DomainValidationError("dashboard cursor names must be canonical")
        return normalized

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 1
            or limit > MAX_MESSAGE_LIMIT
        ):
            raise DomainValidationError(
                f"limit must be between 1 and {MAX_MESSAGE_LIMIT}"
            )
