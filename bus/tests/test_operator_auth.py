import asyncio
import hashlib
import threading
from dataclasses import replace

import pytest

from strugglebus.config import AppConfig, OPERATOR_SETTING_BOUNDS
from strugglebus.errors import ConfigurationError
from strugglebus.operator_auth import (
    OperatorAuth,
    OperatorAuthError,
    OperatorCapacityError,
    OperatorFormError,
    PasswordVerifier,
    create_password_verifier,
    load_password_verifier,
    parse_form,
)

PASSWORD = "synthetic operator password for tests"


@pytest.fixture(scope="module")
def verifier():
    return PasswordVerifier.parse(create_password_verifier(PASSWORD))


@pytest.fixture
def clock():
    now = [1000.0]
    return now


@pytest.fixture
def authority(verifier, clock):
    manager = OperatorAuth(AppConfig(), verifier, clock=lambda: clock[0])
    yield manager
    manager.close()


async def sign_in(manager, *, password=PASSWORD, guard=lambda: None):
    challenge, csrf = manager.challenge("synthetic-source")
    return await manager.login(
        source="synthetic-source", challenge=challenge,
        csrf=csrf, password=password, guard=guard,
    )


def test_password_verifier_is_versioned_salted_bounded_and_nonsecret(verifier):
    encoded = create_password_verifier(PASSWORD)
    assert encoded != create_password_verifier(PASSWORD)
    assert PasswordVerifier.parse(encoded).verify(PASSWORD)
    assert not verifier.verify("different synthetic password")
    assert PASSWORD not in repr(verifier)
    assert verifier.digest.hex() not in repr(verifier)
    for value in (b"", encoded.replace(b"600000", b"9999999999"), b"x" * 257):
        with pytest.raises(ConfigurationError):
            PasswordVerifier.parse(value)
    for password in ("short", "a" * 1025, "\ud800" * 15):
        with pytest.raises(OperatorFormError):
            create_password_verifier(password)
    assert not verifier.verify(PASSWORD + " ")


@pytest.mark.real_password_hashing
def test_password_verifier_uses_the_production_work_factor():
    verifier = PasswordVerifier.parse(create_password_verifier(PASSWORD))
    expected = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), verifier.salt, 600_000, dklen=32)
    assert verifier.digest == expected
    assert verifier.verify(PASSWORD)


@pytest.mark.parametrize("name", OPERATOR_SETTING_BOUNDS)
def test_operator_settings_are_bounded_nonsecret_and_environment_parsed(name):
    minimum, maximum = OPERATOR_SETTING_BOUNDS[name]
    config = AppConfig.from_env({"STRUGGLEBUS_" + name.upper(): str(minimum)})
    assert getattr(config, name) == minimum
    for value in (True, 0, minimum - 1, maximum + 1, "1"):
        with pytest.raises(ConfigurationError):
            replace(config, **{name: value})


def test_operator_configuration_is_not_eager_and_has_no_secret_fallback(tmp_path):
    missing = tmp_path / "missing-verifier"
    config = AppConfig.from_env({
        "STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH": str(missing),
        "STRUGGLEBUS_OPERATOR_PASSWORD": PASSWORD,
    })
    assert config.operator_credential_path == missing
    assert PASSWORD not in repr(config)
    assert load_password_verifier(None) is None
    with pytest.raises(ConfigurationError):
        load_password_verifier(missing)
    disabled = OperatorAuth(config, None)
    try:
        assert not disabled.configured
        assert disabled.authenticate("x" * 43) is None
        with pytest.raises(OperatorAuthError):
            disabled.challenge("source")
    finally:
        disabled.close()


async def test_absolute_expiry_logout_forgery_and_restart(authority, clock):
    idle = AppConfig().operator_session_idle_seconds
    token, context = await sign_in(authority)
    assert authority.authenticate(token) is context
    assert token not in repr(context)
    authority.require_csrf(context, context.csrf_token)
    with pytest.raises(OperatorAuthError):
        authority.require_active(replace(context))
    with pytest.raises(OperatorAuthError):
        authority.require_csrf(context, "foreign")
    clock[0] += idle - 1
    assert authority.authenticate(token) is context
    clock[0] += idle
    assert authority.authenticate(token) is None
    with pytest.raises(OperatorAuthError):
        authority.require_active(context)
    token, context = await sign_in(authority)
    authority.logout(context)
    assert authority.authenticate(token) is None
    with pytest.raises(OperatorAuthError):
        authority.logout(context)
    token, context = await sign_in(authority)
    authority.close()
    assert authority.authenticate(token) is None


def _bounded_authority(verifier, clock, *, absolute: int, idle: int):
    return OperatorAuth(
        replace(
            AppConfig(),
            operator_session_seconds=absolute,
            operator_session_idle_seconds=idle,
        ),
        verifier,
        clock=lambda: clock[0],
    )


async def test_activity_slides_the_idle_window_up_to_the_absolute_deadline(
    verifier, clock
):
    manager = _bounded_authority(verifier, clock, absolute=600, idle=120)
    try:
        start = clock[0]
        token, context = await sign_in(manager)
        # Continuous activity keeps the session alive far beyond one idle
        # window, which is the whole point of sliding renewal.
        for _ in range(5):
            clock[0] += 100
            assert manager.authenticate(token) is context
        assert clock[0] - start == 500
        # The absolute deadline still ends it, despite unbroken activity.
        clock[0] += 100
        assert manager.authenticate(token) is None
        with pytest.raises(OperatorAuthError):
            manager.require_active(context)
    finally:
        manager.close()


async def test_idle_gap_ends_the_session_before_the_absolute_deadline(
    verifier, clock
):
    manager = _bounded_authority(verifier, clock, absolute=600, idle=120)
    try:
        token, _ = await sign_in(manager)
        clock[0] += 120
        assert manager.authenticate(token) is None
    finally:
        manager.close()


async def test_idle_window_is_clamped_to_the_absolute_deadline(verifier, clock):
    # A larger idle window than the absolute lifetime must not extend the
    # session; configuration is clamped rather than rejected so that lowering
    # the absolute lifetime cannot fail startup.
    manager = _bounded_authority(verifier, clock, absolute=120, idle=3_600)
    try:
        token, _ = await sign_in(manager)
        clock[0] += 119
        assert manager.authenticate(token) is not None
        clock[0] += 1
        assert manager.authenticate(token) is None
    finally:
        manager.close()


async def test_expiry_and_logout_release_idle_tracking(authority, clock):
    token, context = await sign_in(authority)
    assert context.session_id in authority._idle_deadlines
    authority.logout(context)
    assert context.session_id not in authority._idle_deadlines
    token, context = await sign_in(authority)
    clock[0] += AppConfig().operator_session_idle_seconds
    assert authority.authenticate(token) is None
    assert authority._idle_deadlines == {}
    assert authority._sessions == {}


async def test_single_use_challenge_and_failed_password(authority):
    challenge, csrf = authority.challenge("source")
    with pytest.raises(OperatorAuthError):
        await authority.login(
            source="source", challenge=challenge, csrf=csrf,
            password="different synthetic password", guard=lambda: None,
        )
    with pytest.raises(OperatorAuthError):
        await authority.login(
            source="source", challenge=challenge, csrf=csrf,
            password=PASSWORD, guard=lambda: None,
        )
    assert not authority._sessions


async def test_freeze_guard_failure_never_creates_session(authority):
    def frozen():
        raise OperatorAuthError("service is unavailable")

    with pytest.raises(OperatorAuthError):
        await sign_in(authority, guard=frozen)
    assert not authority._sessions


@pytest.mark.parametrize("invalid", ["", "short", "a" * 44, "!" * 43, "\u00e9" * 43])
@pytest.mark.parametrize("field", ["token", "csrf"])
def test_invalid_generated_challenge_is_rejected_without_retention(
    authority, monkeypatch, invalid, field,
):
    generated = iter((invalid, "c" * 43) if field == "token" else ("t" * 43, invalid))
    monkeypatch.setattr(
        "strugglebus.operator_auth.secrets.token_urlsafe", lambda size: next(generated),
    )
    with pytest.raises(OperatorAuthError, match="^operator access is unavailable$"):
        authority.challenge("source")
    assert not authority._challenges
    assert not authority._sessions


@pytest.mark.parametrize("invalid", ["", "short", "a" * 44, "!" * 43, "\u00e9" * 43])
@pytest.mark.parametrize("field", ["token", "csrf"])
async def test_invalid_generated_session_is_rejected_without_replacing_valid_session(
    authority, monkeypatch, invalid, field,
):
    existing_token, existing_context = await sign_in(authority)
    challenge, csrf = authority.challenge("source")
    sessions = dict(authority._sessions)
    generated = iter((invalid, "c" * 43) if field == "token" else ("t" * 43, invalid))
    with monkeypatch.context() as patch:
        patch.setattr(
            "strugglebus.operator_auth.secrets.token_urlsafe", lambda size: next(generated),
        )
        with pytest.raises(OperatorAuthError, match="^operator access is unavailable$"):
            await authority.login(
                source="source", challenge=challenge, csrf=csrf,
                password=PASSWORD, guard=lambda: None,
            )
    assert not authority._challenges
    assert authority._sessions == sessions
    assert authority.authenticate(existing_token) is existing_context
    with pytest.raises(OperatorAuthError):
        authority.require_challenge(challenge)
    assert (await sign_in(authority))[1] is not existing_context


async def test_capacity_never_evicts_live_sessions(verifier, clock):
    manager = OperatorAuth(
        replace(AppConfig(), operator_max_sessions=1), verifier,
        clock=lambda: clock[0],
    )
    try:
        token, context = await sign_in(manager)
        with pytest.raises(OperatorCapacityError):
            await sign_in(manager)
        assert manager.authenticate(token) is context
        clock[0] += AppConfig().operator_session_idle_seconds
        assert (await sign_in(manager))[1] is not context
    finally:
        manager.close()


def test_challenge_expiry_and_bounded_source_bookkeeping(authority, clock):
    challenge, csrf = authority.challenge("source")
    for index in range(20):
        try:
            authority.challenge(str(index))
        except OperatorCapacityError:
            pass
    for index in range(1000):
        with pytest.raises(OperatorCapacityError):
            authority.challenge(f"overflow-{index}")
    assert len(authority._limiter._events) <= 21
    clock[0] += 300
    with pytest.raises(OperatorAuthError):
        authority.consume_challenge(challenge, csrf)
    assert not authority._challenges


async def test_cancelled_kdf_keeps_its_slot_until_worker_exits(verifier, monkeypatch):
    started = threading.Event()
    release = threading.Event()

    def verify(self, password):
        started.set()
        assert release.wait(timeout=5)
        return True

    monkeypatch.setattr(PasswordVerifier, "verify", verify)
    manager = OperatorAuth(
        replace(AppConfig(), operator_password_workers=1), verifier,
    )
    try:
        task = asyncio.create_task(sign_in(manager))
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(OperatorCapacityError):
            await sign_in(manager)
        assert not manager._sessions
        release.set()
    finally:
        release.set()
        manager.close()


@pytest.mark.parametrize("body", [
    b"csrf=x&csrf=y", b"csrf=%GG", b"csrf=%ff", b"csrf", b"csrf=x&extra=y",
    b"csrf=%", b"csrf=x&&", b"csrf=x&", b"csrf=\xff",
])
def test_strict_forms_reject_duplicates_and_malformed_input(body):
    with pytest.raises(OperatorFormError):
        parse_form(body, allowed={"csrf"}, required={"csrf"}, maximum=8192)


def test_forms_preserve_password_bytes_and_enforce_body_limit():
    result = parse_form(
        b"password=+A%2B%C3%A9+&csrf=x", allowed={"password", "csrf"},
        required={"password", "csrf"}, maximum=8192,
    )
    assert result["password"] == " A+\u00e9 "
    with pytest.raises(OperatorFormError):
        parse_form(b"csrf=12345", allowed={"csrf"}, required={"csrf"}, maximum=5)
