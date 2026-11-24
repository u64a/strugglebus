"""Dedicated human authority; no agent or root-admin credential fallback."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypeVar
from urllib.parse import unquote_to_bytes, urlsplit
from uuid import uuid4

from strugglebus.config import (
    AppConfig,
    _systemd_credential_context,
    _validate_credential_metadata,
)
from strugglebus.errors import ConfigurationError, StrugglebusError
from strugglebus.rate_limit import SlidingWindowRateLimiter

SESSION_COOKIE = "__Host-strugglebus-operator"
CHALLENGE_COOKIE = "__Host-strugglebus-login"
PASSWORD_ITERATIONS = 600_000
MAX_PASSWORD_BYTES = 1_024
_VERIFIER = re.compile(rb"sbop1\$600000\$([0-9a-f]{32})\$([0-9a-f]{64})\n?")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
T = TypeVar("T")


class OperatorAuthError(StrugglebusError):
    """The browser authority is unavailable or no longer valid."""


class OperatorCapacityError(OperatorAuthError):
    """A bounded operator resource cannot admit more work."""


class OperatorFormError(OperatorAuthError):
    """A human form is malformed; its contents are never reflected."""


def password_bytes(password: str) -> bytes:
    try:
        encoded = password.encode("utf-8", errors="strict")
    except UnicodeError:
        raise OperatorFormError("invalid operator password") from None
    if len(password) < 15 or len(encoded) > MAX_PASSWORD_BYTES:
        raise OperatorFormError("invalid operator password")
    return encoded


@dataclass(frozen=True, slots=True, repr=False)
class PasswordVerifier:
    salt: bytes
    digest: bytes

    @classmethod
    def parse(cls, value: bytes) -> PasswordVerifier:
        match = _VERIFIER.fullmatch(value)
        if match is None:
            raise ConfigurationError("invalid operator credential format")
        return cls(
            bytes.fromhex(match[1].decode("ascii")),
            bytes.fromhex(match[2].decode("ascii")),
        )

    def verify(self, password: str) -> bool:
        encoded = password_bytes(password)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", encoded, self.salt, PASSWORD_ITERATIONS, dklen=32,
        )
        return hmac.compare_digest(candidate, self.digest)


def create_password_verifier(password: str) -> bytes:
    encoded = password_bytes(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", encoded, salt, PASSWORD_ITERATIONS, dklen=32,
    )
    return f"sbop1${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}\n".encode("ascii")


def _open_verifier_source(path: Path) -> tuple[os.stat_result, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or path.resolve(strict=True) != path.absolute()
            or getattr(before, "st_file_attributes", 0) & 0x400
        ):
            raise ConfigurationError("unsafe operator credential file")
        return before, os.open(path, flags)
    except (OSError, RuntimeError):
        raise ConfigurationError("operator credential file is unavailable") from None


def _require_protected_verifier(path: Path, metadata: os.stat_result) -> None:
    if os.name == "posix":
        runtime_uid, projection = _systemd_credential_context(
            path, os.environ.get("CREDENTIALS_DIRECTORY"),
            runtime_uid=os.geteuid(),
        )
        _validate_credential_metadata(
            metadata, require_root_owner=True, runtime_uid=runtime_uid,
            protected_systemd_projection=projection,
        )
    else:
        from strugglebus.private_files import require_private_path

        require_private_path(path, directory=False)


def _read_unchanged_verifier(descriptor: int, path: Path, before: os.stat_result) -> bytes:
    metadata = os.fstat(descriptor)
    if (
        (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
        or metadata.st_nlink != 1
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise ConfigurationError("operator credential file changed")
    _require_protected_verifier(path, metadata)
    value = os.read(descriptor, 257)
    after = os.fstat(descriptor)
    if (
        (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise ConfigurationError("operator credential file changed")
    return value


def load_password_verifier(path: Path | None) -> PasswordVerifier | None:
    """Load at app startup only, never during common/local CLI configuration."""
    if path is None:
        return None
    before, descriptor = _open_verifier_source(path)
    try:
        value = _read_unchanged_verifier(descriptor, path, before)
    except OSError:
        raise ConfigurationError("operator credential file is unreadable") from None
    finally:
        os.close(descriptor)
    return PasswordVerifier.parse(value)


# First-use setup. With no root-provisioned credential, the service keeps its
# own verifier in a private directory under its data directory. Until one
# exists it writes a one-time setup code there for the person who installed it.
SETUP_DIRECTORY = "operator"
MANAGED_VERIFIER = "password"
SETUP_CODE_FILE = "setup-code"
SETUP_CODE_SECONDS = 86_400
_SETUP_CODE = re.compile(r"[0-9a-f]{24}")


def load_managed_verifier(directory: Path) -> PasswordVerifier | None:
    from strugglebus.private_files import read_private_file, require_private_path

    path = directory / MANAGED_VERIFIER
    if not path.exists() and not path.is_symlink():
        return None
    require_private_path(directory, directory=True)
    return PasswordVerifier.parse(read_private_file(path, maximum=256))


def prepare_setup_code(directory: Path) -> bytes:
    """Write a fresh setup code for the installer; return only its digest."""
    from strugglebus.private_files import open_private_output, require_private_path

    try:
        directory.mkdir(mode=0o700, exist_ok=True)
    except OSError:
        raise ConfigurationError("operator setup directory is unavailable") from None
    require_private_path(directory, directory=True)
    path = directory / SETUP_CODE_FILE
    if path.exists() or path.is_symlink():
        require_private_path(path, directory=False)
        path.unlink()
    code = secrets.token_hex(12)
    _write_private(open_private_output(path, outside_repository=False), f"{code}\n".encode("ascii"))
    return hashlib.sha256(code.encode("ascii")).digest()


def _write_private(descriptor: int, value: bytes) -> None:
    try:
        view = memoryview(value)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_managed_verifier(directory: Path, verifier: bytes) -> None:
    from strugglebus.private_files import open_private_output

    # Create-only: an existing verifier is never replaced from the web.
    _write_private(
        open_private_output(directory / MANAGED_VERIFIER, outside_repository=False),
        verifier,
    )
    try:
        (directory / SETUP_CODE_FILE).unlink()
    except FileNotFoundError:
        pass


def _https_origin(config: AppConfig) -> bool:
    try:
        origin = config.public_base_url.rstrip("/")
        origin.encode("ascii")
        parsed = urlsplit(origin)
    except (UnicodeError, ValueError):
        return False
    return (
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
    )


@dataclass(frozen=True, slots=True)
class OperatorContext:
    actor_id: str
    expires_at: float
    session_id: str = field(repr=False)
    csrf_token: str = field(repr=False)

    @property
    def principal(self) -> str:
        return "owner"


@dataclass(frozen=True, slots=True, repr=False)
class LoginChallenge:
    expires_at: float
    csrf_token: str


def _decode_form_component(component: str) -> str:
    if re.search(r"%(?![0-9a-fA-F]{2})", component):
        raise OperatorFormError("invalid operator form")
    return unquote_to_bytes(component.replace("+", " ")).decode("utf-8")


def _form_field(part: str) -> tuple[str, str]:
    if "=" not in part:
        raise OperatorFormError("invalid operator form")
    key, value = part.split("=", 1)
    return _decode_form_component(key), _decode_form_component(value)


def parse_form(
    body: bytes, *, allowed: set[str], required: set[str], maximum: int,
) -> dict[str, str]:
    if len(body) > maximum:
        raise OperatorFormError("operator form is too large")
    try:
        text = body.decode("ascii")
        parts = text.split("&")
        if len(parts) > len(allowed):
            raise OperatorFormError("invalid operator form")
        result: dict[str, str] = {}
        for part in parts:
            key, value = _form_field(part)
            if key not in allowed or key in result:
                raise OperatorFormError("invalid operator form")
            result[key] = value
        if not required <= result.keys():
            raise OperatorFormError("invalid operator form")
        return result
    except UnicodeError:
        raise OperatorFormError("invalid operator form") from None


def _named_cookie_values(header: str, name: str) -> list[str] | None:
    """Every value the header gives the cookie; None when one has no separator."""
    found = []
    for part in header.split(";"):
        key, separator, value = part.strip().partition("=")
        if key == name:
            if not separator:
                return None
            found.append(value)
    return found


def operator_cookie(headers: list[tuple[bytes, bytes]], name: str) -> str | None:
    values = [value for key, value in headers if key.lower() == b"cookie"]
    if len(values) != 1:
        return None
    try:
        found = _named_cookie_values(values[0].decode("ascii"), name)
    except UnicodeError:
        return None
    if found is None or len(found) != 1 or _TOKEN.fullmatch(found[0]) is None:
        return None
    return found[0]


class OperatorAuth:
    """Absolute-lifetime in-memory sessions and fail-fast dedicated KDF workers."""

    def __init__(
        self, config: AppConfig, verifier: PasswordVerifier | None,
        *, clock: Callable[[], float] = time.monotonic,
        setup_directory: Path | None = None,
    ) -> None:
        if not _https_origin(config):
            if verifier is not None:
                raise ConfigurationError("operator origin must be HTTPS without user information")
            # The console needs HTTPS; without it, first-use setup stays off.
            setup_directory = None
        self.config = config
        self._verifier = verifier
        self._clock = clock
        self._sessions: dict[str, OperatorContext] = {}
        self._idle_deadlines: dict[str, float] = {}
        self._challenges: dict[str, LoginChallenge] = {}
        self._lock = threading.Lock()
        self._limiter = SlidingWindowRateLimiter(clock=clock)
        self._slots = threading.BoundedSemaphore(config.operator_password_workers)
        self._executor = ThreadPoolExecutor(
            max_workers=config.operator_password_workers,
            thread_name_prefix="operator-password",
        )
        self._closed = False
        self._setup_directory = setup_directory if verifier is None else None
        self._setup_digest: bytes | None = None
        self._setup_deadline = 0.0

    @property
    def configured(self) -> bool:
        return self._verifier is not None and not self._closed

    @property
    def setup_pending(self) -> bool:
        return (
            self._verifier is None and self._setup_digest is not None
            and not self._closed
        )

    def prepare_setup(self) -> None:
        """Issue the one-time setup code; called once at startup, off the loop."""
        if self._setup_directory is None or self._verifier is not None:
            return
        digest = prepare_setup_code(self._setup_directory)
        with self._lock:
            self._setup_digest = digest
            self._setup_deadline = self._clock() + SETUP_CODE_SECONDS

    async def complete_setup(
        self, *, source: str, code: str, password: str, confirmation: str,
    ) -> None:
        """Set the first operator password, once, with the installer's code."""
        self.admit("login", source)
        with self._lock:
            digest = self._setup_digest
            if not self.setup_pending or digest is None or self._clock() >= self._setup_deadline:
                raise OperatorAuthError("operator setup is unavailable")
        code = code.strip().lower()
        supplied = hashlib.sha256(code.encode("ascii", errors="replace")).digest()
        if _SETUP_CODE.fullmatch(code) is None or not hmac.compare_digest(supplied, digest):
            raise OperatorAuthError("invalid operator setup")
        if not hmac.compare_digest(password_bytes(password), password_bytes(confirmation)):
            raise OperatorFormError("operator passwords did not match")
        verifier = await self._password_work(create_password_verifier, password)
        with self._lock:
            # Consume the code before publishing, so a racing request cannot
            # also succeed. A failed publication needs a restart for a new code.
            if self._setup_digest is not digest or self._setup_directory is None:
                raise OperatorAuthError("operator setup is unavailable")
            self._setup_digest = None
            directory = self._setup_directory
        await asyncio.to_thread(publish_managed_verifier, directory, verifier)
        with self._lock:
            self._verifier = PasswordVerifier.parse(verifier)
            self._setup_directory = None

    @staticmethod
    def _lookup(token: str | None) -> str | None:
        if token is None or _TOKEN.fullmatch(token) is None:
            return None
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def _prune(self) -> None:
        now = self._clock()
        # A session ends at its absolute deadline or after an idle gap,
        # whichever comes first.
        self._sessions = {
            key: value for key, value in self._sessions.items()
            if value.expires_at > now
            and self._idle_deadlines.get(key, 0.0) > now
        }
        self._idle_deadlines = {
            key: value for key, value in self._idle_deadlines.items()
            if key in self._sessions
        }
        self._challenges = {
            key: value for key, value in self._challenges.items()
            if value.expires_at > now
        }

    def admit(
        self, kind: Literal[
            "login", "login-body", "challenge", "reconnect-issue",
            "reconnect-redeem", "device-enroll", "device-write-grant",
        ],
        source: str,
    ) -> None:
        if kind in {"login", "login-body", "challenge"}:
            global_limit = self.config.operator_login_global_per_minute
            source_limit = self.config.operator_login_source_per_minute
        elif kind == "reconnect-issue":
            global_limit = self.config.reconnect_issue_global_per_minute
            source_limit = self.config.reconnect_issue_session_per_minute
        elif kind == "reconnect-redeem":
            global_limit = self.config.reconnect_redeem_global_per_minute
            source_limit = self.config.reconnect_redeem_source_per_minute
        elif kind == "device-enroll":
            global_limit = self.config.mobile_enroll_global_per_minute
            source_limit = self.config.mobile_enroll_session_per_minute
        elif kind == "device-write-grant":
            # Its own family, and deliberately small. Establishing a grant is
            # the one mobile call that runs a password verification, and that
            # verification shares a bounded worker pool with console login. A
            # burst here must not be able to lock the owner out of the console
            # they would use to revoke the device causing it.
            global_limit = self.config.mobile_grant_global_per_minute
            source_limit = self.config.mobile_grant_device_per_minute
        else:
            raise ValueError("unsupported operator admission kind")
        # Global admission comes first, bounding the number of source keys.
        if not self._limiter.allow(f"{kind}:global", global_limit)[0]:
            raise OperatorCapacityError("operator request limit reached")
        if not self._limiter.allow(f"{kind}:source:{source}", source_limit)[0]:
            raise OperatorCapacityError("operator request limit reached")

    async def verify_device_password(self, password: str, *, source: str) -> bool:
        """Prove the operator password for a device, minting no session.

        Used once per device, to trade the password for a revocable per-device
        grant. There is no session and no remembered window: this proves
        presence for exactly this request and nothing later counts as
        recently authenticated.
        """

        if not self.configured:
            raise OperatorAuthError("operator access is unavailable")
        self.admit("device-write-grant", source)
        return await self._verify_password(password)

    def challenge(self, source: str) -> tuple[str, str]:
        if not self.configured:
            raise OperatorAuthError("operator access is unavailable")
        self.admit("challenge", source)
        with self._lock:
            self._prune()
            if len(self._challenges) >= 64:
                raise OperatorCapacityError("operator challenge capacity reached")
            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            lookup = self._lookup(token)
            if lookup is None or _TOKEN.fullmatch(csrf) is None:
                raise OperatorAuthError("operator access is unavailable")
            self._challenges[lookup] = LoginChallenge(self._clock() + 300, csrf)
            return token, csrf

    def consume_challenge(self, token: str | None, csrf: str) -> None:
        lookup = self._lookup(token)
        with self._lock:
            self._prune()
            challenge = self._challenges.get(lookup) if lookup is not None else None
            if challenge is None or not self._csrf_matches(csrf, challenge.csrf_token):
                raise OperatorAuthError("invalid operator login")
            del self._challenges[lookup]

    def require_challenge(self, token: str | None) -> None:
        lookup = self._lookup(token)
        with self._lock:
            self._prune()
            if not self.configured or lookup not in self._challenges:
                raise OperatorAuthError("invalid operator login")

    @staticmethod
    def _csrf_matches(supplied: str, expected: str) -> bool:
        return (
            _TOKEN.fullmatch(supplied) is not None
            and hmac.compare_digest(supplied, expected)
        )

    async def _verify_password(self, password: str) -> bool:
        if not self.configured or self._verifier is None:
            raise OperatorAuthError("operator access is unavailable")
        return await self._password_work(self._verifier.verify, password)

    async def _password_work(self, function: Callable[[str], T], password: str) -> T:
        password_bytes(password)
        if not self._slots.acquire(blocking=False):
            raise OperatorCapacityError("operator password capacity reached")
        try:
            future = self._executor.submit(function, password)
        except RuntimeError:
            self._slots.release()
            raise OperatorAuthError("operator access is unavailable") from None
        # Cancellation of the HTTP waiter must not release a running KDF's slot.
        future.add_done_callback(lambda completed: self._slots.release())
        return await asyncio.wrap_future(future)

    async def reauthenticate(
        self, context: OperatorContext, password: str, *, source: str,
        family: Literal["device-enroll", "updater-confirm"] = "device-enroll",
    ) -> None:
        """Prove the operator password again without minting a session.

        Nothing is remembered: there is no window during which a later request
        counts as recently reauthenticated. Update confirmation has a budget
        separate from device enrollment.
        """

        self.require_active(context)
        if family == "device-enroll":
            self.admit("device-enroll", context.session_id)
            self.admit("device-enroll", source)
        elif family == "updater-confirm":
            self._admit_confirmation(context.session_id, source, family)
        else:
            raise ValueError("unsupported operator reauthentication family")
        if not await self._verify_password(password):
            raise OperatorAuthError("operator reauthentication failed")
        self.require_active(context)

    def _admit_confirmation(
        self, session_id: str, source: str,
        family: Literal["updater-confirm"],
    ) -> None:
        per_caller = self.config.updater_confirm_session_per_minute
        global_limit = self.config.updater_confirm_global_per_minute
        for key, limit in (
            ("global", global_limit),
            (f"session:{session_id}", per_caller),
            (f"source:{source}", per_caller),
        ):
            if not self._limiter.allow(f"{family}:{key}", limit)[0]:
                raise OperatorCapacityError("operator request limit reached")

    async def login(
        self, *, source: str, challenge: str | None, csrf: str,
        password: str, guard: Callable[[], None],
    ) -> tuple[str, OperatorContext]:
        if not self.configured or self._verifier is None:
            raise OperatorAuthError("operator access is unavailable")
        self.admit("login", source)
        self.consume_challenge(challenge, csrf)
        valid = await self._verify_password(password)
        if not valid:
            raise OperatorAuthError("invalid operator login")
        await asyncio.to_thread(guard)
        with self._lock:
            self._prune()
            if not self.configured:
                raise OperatorAuthError("operator access is unavailable")
            if len(self._sessions) >= self.config.operator_max_sessions:
                raise OperatorCapacityError("operator session capacity reached")
            token = secrets.token_urlsafe(32)
            lookup = self._lookup(token)
            csrf = secrets.token_urlsafe(32)
            if lookup is None or _TOKEN.fullmatch(csrf) is None:
                raise OperatorAuthError("operator access is unavailable")
            context = OperatorContext(
                actor_id=f"operator:owner:{uuid4().hex}",
                expires_at=self._clock() + self.config.operator_session_seconds,
                session_id=lookup, csrf_token=csrf,
            )
            self._sessions[lookup] = context
            self._idle_deadlines[lookup] = min(
                self._clock() + self.config.operator_session_idle_seconds,
                context.expires_at,
            )
            return token, context

    def authenticate(self, token: str | None) -> OperatorContext | None:
        lookup = self._lookup(token)
        with self._lock:
            self._prune()
            if not self.configured or lookup is None:
                return None
            context = self._sessions.get(lookup)
            if context is None:
                return None
            # Activity slides the idle deadline forward, never past the
            # absolute deadline fixed at login.
            self._idle_deadlines[lookup] = min(
                self._clock() + self.config.operator_session_idle_seconds,
                context.expires_at,
            )
            return context

    def require_active(self, context: OperatorContext) -> None:
        with self._lock:
            self._prune()
            if (
                not self.configured
                or self._sessions.get(context.session_id) is not context
            ):
                raise OperatorAuthError("operator session is no longer valid")

    def require_csrf(self, context: OperatorContext, supplied: str) -> None:
        self.require_active(context)
        if not self._csrf_matches(supplied, context.csrf_token):
            raise OperatorAuthError("invalid operator form")

    def logout(self, context: OperatorContext) -> None:
        with self._lock:
            self._prune()
            if self._sessions.get(context.session_id) is not context:
                raise OperatorAuthError("operator session is no longer valid")
            del self._sessions[context.session_id]
            self._idle_deadlines.pop(context.session_id, None)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._sessions.clear()
            self._idle_deadlines.clear()
            self._challenges.clear()
        self._executor.shutdown(wait=True, cancel_futures=True)
