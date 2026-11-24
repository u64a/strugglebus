import asyncio
from types import SimpleNamespace

import pytest

from strugglebus.app import create_app
from strugglebus.console_context import ConsoleAccessMiddleware, console_access_context
from strugglebus.errors import StorageError
from operator_test_support import operator_client


def context_scope(*, authenticated=True, frozen=False, failure=None):
    calls = []

    def status():
        calls.append("freeze-read")
        if failure is not None:
            raise failure
        return SimpleNamespace(frozen=frozen)

    return {
        "type": "http", "path": "/system",
        "state": {"operator_context": object() if authenticated else None},
        "app": SimpleNamespace(state=SimpleNamespace(
            access_freeze_service=SimpleNamespace(status=status),
        )),
    }, calls


@pytest.mark.parametrize("authenticated,frozen,error,expected", [
    (True, False, None, "available"),
    (True, True, None, "frozen"),
    (True, False, StorageError("private storage detail"), "unavailable"),
    (False, True, RuntimeError("must not read anonymously"), "unobserved"),
])
@pytest.mark.parametrize("downstream_failure", [False, True])
async def test_access_disclosure_is_authenticated_request_local_and_restored(
    authenticated, frozen, error, expected, downstream_failure,
):
    scope, calls = context_scope(authenticated=authenticated, frozen=frozen, failure=error)
    outer = console_access_context.set("frozen")

    async def application(_scope, _receive, _send):
        assert console_access_context.get() == expected
        if downstream_failure:
            raise RuntimeError("downstream")

    try:
        if downstream_failure:
            with pytest.raises(RuntimeError, match="downstream"):
                await ConsoleAccessMiddleware(application)(scope, None, None)
        else:
            await ConsoleAccessMiddleware(application)(scope, None, None)
        assert console_access_context.get() == "frozen"
        assert len(calls) == int(authenticated)
    finally:
        console_access_context.reset(outer)


async def test_unexpected_freeze_read_failure_does_not_become_a_normal_view():
    scope, _ = context_scope(failure=RuntimeError("unexpected failure"))

    async def forbidden(*args):
        pytest.fail("unexpected disclosure failure must propagate")

    with pytest.raises(RuntimeError, match="unexpected failure"):
        await ConsoleAccessMiddleware(forbidden)(scope, None, None)
    assert console_access_context.get() == "unobserved"


async def test_concurrent_freeze_disclosures_do_not_cross_requests():
    scopes = [context_scope(frozen=value)[0] for value in (False, True)]
    arrived = 0
    ready = asyncio.Event()

    async def application(scope, _receive, _send):
        nonlocal arrived
        expected = console_access_context.get()
        arrived += 1
        if arrived == 2:
            ready.set()
        await ready.wait()
        assert console_access_context.get() == expected

    await asyncio.gather(*(ConsoleAccessMiddleware(application)(scope, None, None) for scope in scopes))
    assert console_access_context.get() == "unobserved"


def test_real_operator_pages_observe_freeze_without_disclosing_reason_anonymously(app_config):
    application = create_app(config=app_config)
    with operator_client(application) as client:
        application.state.access_freeze_service.freeze("private operator reason")
        for path in ("/", "/activity", "/channels", "/system", "/register", "/devices"):
            page = client.get(path)
            assert page.status_code == 200
            assert "frozen" in page.text.lower()
            assert "private operator reason" not in page.text
        denied = client.register("frozen-example")
        assert denied.status_code == 503
        assert application.state.access_freeze_service.status().frozen
        client.cookies.clear()
        anonymous = client.get("/login")
        assert anonymous.status_code == 200
        assert "private operator reason" not in anonymous.text
        assert "Agent access is frozen" not in anonymous.text
    assert console_access_context.get() == "unobserved"
