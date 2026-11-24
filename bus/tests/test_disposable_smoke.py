"""The production smoke against disposable offline fixtures, never a LAN host."""

from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
import importlib.util
import hashlib
import html
import json
from pathlib import Path
import sqlite3
import time
from uuid import uuid4
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx2
import pytest

from strugglebus import __version__
from strugglebus.app import create_app
from strugglebus.migrations import LATEST_SCHEMA_VERSION
from operator_test_support import PASSWORD, verifier
from test_ca_anchor import chain, _digest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "disposable_smoke", ROOT / "deploy" / "tests" / "smoke_unit.py"
)
assert SPEC is not None and SPEC.loader is not None
offline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(offline)
smoke = offline.smoke


def configuration(tmp_path):
    return {
        "admin_credential_path": str(tmp_path / "admin"),
        "base_url": "https://smoke.invalid",
        "ca_path": str(tmp_path / "ca"),
        "database_path": str(tmp_path / "strugglebus.db"),
        "work_dir": str(tmp_path),
        "expected_release_id": __version__,
        "release_environment_path": str(tmp_path / "release.env"),
    }


def dashboard_responses(path, css="color-scheme: dark; .workspace {} .rail {}"):
    document = (
        f'<link rel="stylesheet" href="{path}">'
        + html.escape("fixture <script>smoke</script> searchable-question", quote=True)
    )
    return (
        httpx2.Response(200, text=document, headers={"content-security-policy": smoke.DASHBOARD_CSP}),
        httpx2.Response(200, text=css, headers={
            "content-type": "text/css; charset=utf-8", "x-content-type-options": "nosniff",
        }),
    )


@pytest.mark.parametrize("schema", [11, 12])
@pytest.mark.parametrize("path,css", [
    ("/assets/strugglebus-console." + "a" * 16 + ".css", "color-scheme: dark; .site-header {}"),
    ("/assets/strugglebus-console." + "b" * 16 + ".css", "color-scheme: dark; .workspace {} .rail {}"),
])
async def test_dashboard_smoke_accepts_both_contracts_and_asset_forms(tmp_path, monkeypatch, schema, path, css):
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.expected = {"schema": schema}
    backend.marker = "fixture"
    client = SimpleNamespace(get=AsyncMock(side_effect=dashboard_responses(path, css)))
    backend.operator_client = client
    monkeypatch.setattr(backend, "_http_client", lambda: client)
    assert await backend.dashboard_safety() == ("http_2xx", True, True)
    assert [call.args for call in client.get.await_args_list] == [("/",), (path,)]


async def test_dashboard_smoke_requires_operator_client(tmp_path):
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.expected = {"schema": 12}
    with pytest.raises(smoke.SmokeError) as error:
        await backend.dashboard_safety()
    assert error.value.error_code == "authentication"


@pytest.mark.parametrize("paths", [
    [], ["/assets/strugglebus-console." + "a" * 16 + ".css"] * 2,
    ["https://foreign.invalid/style.css"], ["//foreign.invalid/style.css"],
    ["/assets/strugglebus-console.invalid.css"],
    ["/assets/presentation-" + "a" * 63 + ".css"],
    ["/assets/presentation-" + "A" * 64 + ".css"],
    ["/assets/presentation-" + "a" * 64 + ".css?extra=1"],
    ["/assets/presentation-" + "a" * 64 + ".css#fragment"],
    ["/assets/../private.css"],
])
async def test_dashboard_smoke_rejects_asset_paths_before_fetch(tmp_path, paths):
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.expected = {"schema": 12}
    backend.marker = "fixture"
    document = "".join(f'<link rel="stylesheet" href="{path}">' for path in paths)
    document += html.escape("fixture <script>smoke</script> searchable-question", quote=True)
    response = httpx2.Response(200, text=document, headers={"content-security-policy": smoke.DASHBOARD_CSP})
    client = SimpleNamespace(get=AsyncMock(return_value=response))
    backend.operator_client = client
    with pytest.raises(smoke.SmokeError) as error:
        await backend.dashboard_safety()
    assert error.value.error_code == "invalid_response"
    assert client.get.await_count == 1


@pytest.mark.parametrize("fault", ["status", "raw", "escaped", "marker", "run", "style-tag", "style-attribute", "csp"])
async def test_dashboard_smoke_preserves_document_checks(tmp_path, fault):
    response, _ = dashboard_responses("/assets/strugglebus-console." + "a" * 16 + ".css")
    document = response.text
    status = 503 if fault == "status" else 200
    headers = {} if fault == "csp" else dict(response.headers)
    additions = {
        "raw": "fixture <script>smoke</script> searchable-question",
        "marker": '"marker"', "run": '"run"', "style-tag": "<STYLE></STYLE>",
        "style-attribute": '<p STYLE="color:red">',
    }
    document += additions.get(fault, "")
    if fault == "escaped":
        document = document.replace("&lt;script&gt;", "")
    response = httpx2.Response(status, text=document, headers=headers)
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.expected = {"schema": 12}
    backend.marker = "fixture"
    backend.operator_client = SimpleNamespace(get=AsyncMock(return_value=response))
    with pytest.raises(smoke.SmokeError) as error:
        await backend.dashboard_safety()
    assert error.value.error_code == "invalid_response"
    assert backend.operator_client.get.await_count == 1


@pytest.mark.parametrize("fault", ["status", "type", "nosniff", "scheme", "missing-layout", "missing-workspace", "missing-rail"])
async def test_dashboard_smoke_preserves_stylesheet_checks(tmp_path, fault):
    path = "/assets/strugglebus-console." + "a" * 16 + ".css"
    document, stylesheet = dashboard_responses(path)
    headers = dict(stylesheet.headers)
    text = stylesheet.text
    if fault in {"type", "nosniff"}:
        headers.pop("content-type" if fault == "type" else "x-content-type-options")
    for case, removed in (("scheme", "color-scheme: dark"), ("missing-workspace", ".workspace"), ("missing-rail", ".rail")):
        if fault == case:
            text = text.replace(removed, "")
    if fault == "missing-layout":
        text = "color-scheme: dark"
    stylesheet = httpx2.Response(503 if fault == "status" else 200, content=text.encode(), headers=headers)
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.expected = {"schema": 12}
    backend.marker = "fixture"
    backend.operator_client = SimpleNamespace(get=AsyncMock(side_effect=[document, stylesheet]))
    with pytest.raises(smoke.SmokeError) as error:
        await backend.dashboard_safety()
    assert error.value.error_code == "invalid_response"


def operator_harness(app, tmp_path, ca_path, monkeypatch):
    """Substitute transport/POSIX metadata only; retain genuine password/session auth."""
    root = tmp_path / "sessions"
    root.mkdir()
    monkeypatch.setattr(smoke, "SESSION_ROOT", root)
    monkeypatch.setattr(smoke, "_operator_password", lambda: PASSWORD)
    monkeypatch.setattr(smoke, "_ca_digest", lambda path: hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setattr(
        smoke, "_password_client",
        lambda origin, path, digest: httpx2.AsyncClient(
            base_url=origin, transport=httpx2.ASGITransport(app=app), follow_redirects=False,
        ),
    )
    monkeypatch.setattr(
        smoke, "_operator_client",
        lambda session: httpx2.AsyncClient(
            base_url=session["origin"], transport=httpx2.ASGITransport(app=app),
            follow_redirects=False,
            headers={
                "Cookie": f"{smoke.SESSION_COOKIE}={session['token']}",
                "Origin": session["origin"],
            },
        ),
    )
    monkeypatch.setattr(
        smoke, "_read_operator_session",
        lambda path, **kwargs: smoke._validate_session(json.loads(path.read_text()), **kwargs),
    )


@pytest.fixture
async def authenticated_smoke(
    tmp_path, app_config, agent_service, uvicorn_server, monkeypatch, chain, request
):
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda _: verifier())
    ca_path = chain / "root.crt"
    public_url = "https://bus.lan"
    app = create_app(
        agent_service=agent_service,
        config=replace(
            app_config, release_id=__version__, roe_enforcement_mode=getattr(request, "param", "enforce"),
            catch_up_candidate_limit=1,
            public_base_url=public_url, ca_bundle_path=str(ca_path),
            ca_root_sha256=_digest(ca_path.read_bytes()),
        ),
    )
    monkeypatch.setattr(
        smoke, "_release_environment",
        lambda _: f"STRUGGLEBUS_RELEASE_ID={__version__}\n".encode("ascii"),
    )
    monkeypatch.setattr(smoke, "_read_secret", lambda _: "test-only-admin-secret")
    operator_harness(app, tmp_path, ca_path, monkeypatch)
    with uvicorn_server(app) as url:
        session = await smoke.prepare_operator_session({
            "base_url": public_url, "ca_path": str(ca_path),
        })
        session_value = json.loads(Path(session["operator_session_path"]).read_text())
        config = configuration(tmp_path)
        # Only the offline harness substitutes the ephemeral loopback transport.
        config.update(
            base_url=url, ca_path=str(ca_path),
            operator_session_path=session["operator_session_path"],
        )
        origin = smoke._origin
        monkeypatch.setattr(smoke, "_origin", lambda value: public_url if value == url else origin(value))
        backend = smoke.RealSmokeBackend(config, tmp_path / "state.json")
        monkeypatch.setattr(
            smoke, "_paths", lambda _: (tmp_path / "result.json", tmp_path / "state.json")
        )
        try:
            yield backend
        finally:
            # Invalid-handoff tests intentionally corrupt their disposable file;
            # retire the original synthetic session using its genuine CSRF.
            async with smoke._operator_client(session_value) as client:
                response = await client.post("/logout", data={"csrf": session_value["csrf"]})
                assert response.status_code in {303, 401}
            if backend.operator_client is not None:
                await backend.operator_client.aclose()
            if backend.client is not None:
                await backend.client.aclose()


@pytest.mark.parametrize("authenticated_smoke", ["observe", "enforce"], indirect=True)
async def test_all_phases_against_disposable_server(
    authenticated_smoke, tmp_path, app_config, monkeypatch, capsys
):
    backend = authenticated_smoke
    failures = []
    classify = smoke._classify

    def record_failure(error):
        failures.append(error)
        return classify(error)

    cleanup = backend.cleanup

    def cleanup_legacy_posts():
        with closing(sqlite3.connect(app_config.database_path)) as database:
            assert database.execute(
                "SELECT post_request_id FROM messages ORDER BY seq"
            ).fetchall() == [(None,), (None,)]
        cleanup()

    monkeypatch.setattr(smoke, "_classify", record_failure)
    monkeypatch.setattr(backend, "cleanup", cleanup_legacy_posts)
    results = smoke.ResultStore(tmp_path / "result.json")
    success = await smoke.run_smoke(backend, results)
    if failures:
        raise failures[0]
    assert success, [item for item in results.results if not item["passed"]]
    assert [item["phase"] for item in results.results] == [*smoke.PHASES, "helper_cleanup"]
    assert smoke._execute("cleanup", {"work_dir": str(tmp_path)}) == 0
    complete_results = json.loads(capsys.readouterr().out)
    assert [item["phase"] for item in complete_results] == list(smoke.ALL_PHASES)
    with closing(sqlite3.connect(app_config.database_path)) as database:
        before_repeat = list(database.iterdump())
        for table, condition in (
            ("agents", "revoked_at IS NULL AND name NOT IN ('system:strugglebus-maintenance', 'human:operator')"),
            ("agent_credentials", "status IN ('pending','active')"),
            ("agent_enrollments", "status='pending'"),
            ("agent_reconnect_grants", "status='pending'"),
            ("messages", "1=1"),
        ):
            assert database.execute(f"SELECT COUNT(*) FROM {table} WHERE {condition}").fetchone() == (0,)
        assert database.execute(
            "SELECT COUNT(*) FROM agents WHERE name NOT IN ('system:strugglebus-maintenance', 'human:operator')"
        ).fetchone() == (2,)
        assert database.execute("SELECT COUNT(*) FROM roe_acknowledgements").fetchone() == (2,)
        assert database.execute(
            "SELECT COUNT(*) FROM agent_credential_audit WHERE event_type='agent-revoke'"
        ).fetchone() == (1,)
        assert database.execute(
            "SELECT action FROM agent_lifecycle_audit ORDER BY seq"
        ).fetchall() == [("retire",), ("retire",)]
    assert smoke._execute("cleanup", {"work_dir": str(tmp_path)}) == 0
    with closing(sqlite3.connect(app_config.database_path)) as database:
        assert list(database.iterdump()) == before_repeat
    for path in (tmp_path / "result.json", tmp_path / "state.json"):
        serialized = path.read_text()
        assert "test-only-admin-secret" not in serialized and PASSWORD not in serialized
        for secret in (backend.writer["api_key"], backend.reader["api_key"], backend.operator["token"]):
            assert secret not in serialized
    assert not backend.operator_session_path.exists()


def test_existing_failure_injection_and_playbook_contracts(tmp_path):
    for phase in (*smoke.PHASES, None):
        offline.run_failure_injection(tmp_path, phase)
    offline.test_cleanup_contracts(tmp_path)
    offline.test_playbook_contract()


async def test_smoke_post_requests_remain_legacy_unkeyed(tmp_path, monkeypatch):
    from contextlib import asynccontextmanager

    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.writer = {"api_key": "synthetic-writer-key"}
    backend.reader = {"api_key": "synthetic-reader-key"}
    requests = []

    async def rest_post(path, *, headers, json):
        requests.append(("rest", json))
        return httpx2.Response(201, json={"seq": 2})

    async def call_tool(name, parameters):
        if name == "post":
            requests.append(("mcp", parameters))
            content = {"seq": 1}
        else:
            assert name == "read"
            content = {"messages": [{"seq": 1}, {"seq": 2, "reply_to": 1}]}
        return SimpleNamespace(is_error=False, structured_content=content)

    @asynccontextmanager
    async def mcp(_):
        yield SimpleNamespace(call_tool=call_tool)

    backend.client = SimpleNamespace(
        post=rest_post, get=AsyncMock(return_value=httpx2.Response(200, json=[{"seq": 1}])),
    )
    backend.mcp = mcp
    for post_phase in (backend.mcp_post_rest_read, backend.rest_reply_mcp_read):
        assert await post_phase() == ("ok", True, True)
    assert [transport for transport, _ in requests] == ["mcp", "rest"]
    assert all("request_id" not in parameters for _, parameters in requests)


@pytest.mark.parametrize("field", [
    "missing", "token", "csrf", "actor_id", "ca_sha256", "origin", "expires_at", "extra",
])
async def test_operator_handoff_denial_precedes_enrollment(authenticated_smoke, field):
    backend = authenticated_smoke
    await backend.setup()
    await backend.candidate_contract()
    path = Path(backend.configuration["operator_session_path"])
    value = json.loads(path.read_text())
    if field == "missing":
        backend.configuration["operator_session_path"] = ""
    else:
        value[field] = {
            "token": "a" * 43, "csrf": "b" * 43, "actor_id": "operator:owner:" + "0" * 32,
            "ca_sha256": "0" * 64, "origin": "https://unrelated.invalid",
            "expires_at": value["issued_at"] - 1, "extra": "unexpected",
        }[field]
        smoke._atomic_json(path, value)
    with pytest.raises(smoke.SmokeError):
        await backend.operator_authority()
    with closing(sqlite3.connect(backend.database_path)) as database:
        assert database.execute("SELECT COUNT(*) FROM agent_enrollments").fetchone() == (0,)
        assert database.execute(
            "SELECT COUNT(*) FROM agents WHERE name NOT IN ('system:strugglebus-maintenance', 'human:operator')"
        ).fetchone() == (0,)


async def test_schema11_reports_operator_authority_as_not_applicable(tmp_path):
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.expected = {"schema": 11}
    assert await backend.operator_authority() == ("not_applicable", True, True)
    assert backend.operator is None


async def test_unrecorded_reconnect_grant_refuses_cleanup_without_mutation(
    authenticated_smoke, agent_service
):
    from strugglebus.models import LifecycleActor

    backend = authenticated_smoke
    await backend.setup()
    for phase in ("candidate_contract", "operator_authority", "enrollment"):
        await getattr(backend, phase)()
    agent_service.issue_reconnect(
        backend.reader["id"], expected_agent_name=backend.reader_name,
        expected_credential_epoch=backend.reader["credential_epoch"],
        request_id=str(uuid4()), reason=backend.marker,
        actor=LifecycleActor("remote-admin", backend.operator["actor_id"], lambda: None),
    )
    assert json.loads(backend.state_path.read_text())["operator"]["intents"] == []
    with closing(sqlite3.connect(backend.database_path)) as database:
        original = list(database.iterdump())
    with pytest.raises(smoke.SmokeError, match="cleanup_refused"):
        backend.cleanup()
    with closing(sqlite3.connect(backend.database_path)) as database:
        assert list(database.iterdump()) == original


def session_record(tmp_path):
    return {
        "version": 1, "origin": "https://bus.lan", "ca_path": str(tmp_path / "root.crt"),
        "ca_sha256": "0" * 64, "token": "t" * 43, "csrf": "c" * 43,
        "actor_id": "operator:owner:" + "1" * 32, "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 900,
    }


@pytest.mark.parametrize("status,location,successful", [
    (303, "/login", True), (401, "", True), (303, "/unrelated", False),
    (403, "", False), (429, "", False), (503, "", False),
])
async def test_logout_requires_revocation_or_denial_proof(
    tmp_path, monkeypatch, status, location, successful
):
    path = tmp_path / "operator-session.json"
    record = session_record(tmp_path)
    smoke._atomic_json(path, record)
    monkeypatch.setattr(smoke, "_read_operator_session", lambda *args, **kwargs: record)
    monkeypatch.setattr(smoke, "_operator_client", lambda _: httpx2.AsyncClient(
        base_url=record["origin"], transport=httpx2.MockTransport(
            lambda request: httpx2.Response(status, headers={"location": location}),
        ),
    ))
    if successful:
        await smoke._logout_operator(path)
        assert not path.exists()
    else:
        with pytest.raises(smoke.SmokeError, match="operator_logout_failed"):
            await smoke._logout_operator(path)
        assert json.loads(path.read_text()) == record


def test_always_cleanup_attempts_logout_without_hiding_containment_failure(
    tmp_path, monkeypatch, capsys
):
    state_path, result_path = tmp_path / "state.json", tmp_path / "result.json"
    session_path = tmp_path / "operator-session.json"
    smoke._atomic_json(session_path, session_record(tmp_path))
    monkeypatch.setattr(smoke, "_paths", lambda _: (result_path, state_path))

    def refuse(_):
        raise smoke.SmokeError("cleanup_refused")

    logout = AsyncMock(side_effect=smoke.SmokeError("operator_logout_failed"))
    monkeypatch.setattr(smoke, "_cleanup_state", refuse)
    monkeypatch.setattr(smoke, "_logout_operator", logout)
    assert smoke._execute("cleanup", {"work_dir": str(tmp_path)}) == 1
    logout.assert_awaited_once_with(session_path)
    assert json.loads(capsys.readouterr().out)[-1]["error_code"] == "cleanup_refused"
    assert session_path.exists()


@pytest.mark.parametrize("field,value", [
    ("version", True), ("token", "short"), ("csrf", "bad"),
    ("actor_id", "operator:owner:" + "-" * 32),
    ("origin", "https://name:password@bus.lan"), ("origin", "http://bus.lan"),
    ("origin", "https://bus.lan/other"), ("ca_sha256", "bad"),
    ("ca_path", "relative.crt"), ("expires_at", -1),
    ("issued_at", 2**62), ("expires_at", 2**62),
])
def test_session_input_bounds(tmp_path, field, value):
    record = session_record(tmp_path)
    record[field] = value
    with pytest.raises(smoke.SmokeError):
        smoke._validate_session(record)


@pytest.mark.parametrize("status", [401, 429, 503])
async def test_prepare_denial_never_prompts_for_password(tmp_path, monkeypatch, status):
    password = AsyncMock()
    monkeypatch.setattr(smoke, "_operator_password", password)
    monkeypatch.setattr(smoke, "_ca_digest", lambda _: "0" * 64)
    monkeypatch.setattr(smoke, "_password_client", lambda origin, *args: httpx2.AsyncClient(
        base_url=origin, transport=httpx2.MockTransport(lambda _: httpx2.Response(status)),
    ))
    with pytest.raises(smoke.SmokeError, match="authentication"):
        await smoke.prepare_operator_session({"base_url": "https://bus.lan", "ca_path": str(tmp_path / "ca")})
    password.assert_not_called()


@pytest.mark.parametrize("failure", ["short_password", "long_password", "mkdir", "write", "cookie"])
async def test_prepare_rejects_unsafe_input_and_logs_out_on_publication_failure(
    tmp_path, monkeypatch, failure
):
    requests = []
    record = session_record(tmp_path)

    def respond(request):
        requests.append((request.method, request.url.path))
        csrf_field = f'<input name="csrf" value="{record["csrf"]}">'
        if request.method == "GET" and request.url.path == "/login":
            return httpx2.Response(200, text=f'<form action="/login">{csrf_field}</form>')
        if request.url.path == "/operator/session":
            return httpx2.Response(200, text=(
                f'<code id="operator-identity">{record["actor_id"]}</code>'
                f'<form action="/logout">{csrf_field}</form>'
            ))
        if request.url.path == "/logout":
            return httpx2.Response(303, headers={"location": "/login"})
        flags = "Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=900"
        if failure == "cookie":
            flags = flags.replace("HttpOnly; ", "")
        return httpx2.Response(303, headers={
            "location": "/", "set-cookie": f"{smoke.SESSION_COOKIE}={record['token']}; {flags}",
        })

    monkeypatch.setattr(smoke, "_ca_digest", lambda _: record["ca_sha256"])
    monkeypatch.setattr(smoke, "_operator_password", lambda: {
        "short_password": "short", "long_password": "p" * 1025,
    }.get(failure, PASSWORD))
    monkeypatch.setattr(smoke, "_password_client", lambda origin, *args: httpx2.AsyncClient(
        base_url=origin, transport=httpx2.MockTransport(respond), follow_redirects=False,
    ))
    monkeypatch.setattr(smoke, "SESSION_ROOT", tmp_path)

    def refuse(*args, **kwargs):
        raise OSError("synthetic private publication failure")

    if failure == "mkdir":
        monkeypatch.setattr(smoke.tempfile, "mkdtemp", refuse)
    elif failure == "write":
        monkeypatch.setattr(smoke, "_atomic_json", refuse)
    with pytest.raises((smoke.SmokeError, OSError)):
        await smoke.prepare_operator_session({
            "base_url": record["origin"], "ca_path": record["ca_path"],
        })
    if failure in {"short_password", "long_password"}:
        assert requests == [("GET", "/login")]
    elif failure in {"mkdir", "write"}:
        assert requests[-1] == ("POST", "/logout")
    assert not list(tmp_path.rglob("session.json"))


def test_json_control_input_is_bounded_and_rejects_duplicates(monkeypatch):
    import io
    for raw in ('{"base_url":"https://a.invalid","base_url":"https://b.invalid"}', " " * 65537):
        monkeypatch.setattr(smoke.sys, "stdin", io.StringIO(raw))
        with pytest.raises(smoke.SmokeError, match="invalid_configuration"):
            smoke._read_input()


async def test_operator_tls_uses_only_digest_matched_material(chain, tmp_path, monkeypatch):
    import ssl
    raw = (chain / "root.crt").read_bytes()
    record = session_record(tmp_path)
    record["ca_sha256"] = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(smoke, "_ca_bytes", lambda _: raw)
    context = smoke._ca_context(Path(record["ca_path"]), record["ca_sha256"])
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert len(context.get_ca_certs()) == 1
    with pytest.raises(smoke.SmokeError, match="authentication"):
        smoke._ca_context(Path(record["ca_path"]), "0" * 64)
    async with smoke._operator_client(record) as client:
        assert client.headers["cookie"] == f"{smoke.SESSION_COOKIE}={record['token']}"
        assert "authorization" not in client.headers
        assert client.follow_redirects is False and client.trust_env is False


@pytest.mark.parametrize("release", ["", "development", "v0.2.20", "0.2.8", "0.2.20\n", "1"])
def test_invalid_or_wrong_operator_version(tmp_path, release):
    value = configuration(tmp_path)
    value["expected_release_id"] = release
    with pytest.raises(smoke.SmokeError):
        smoke._read_configuration(value)
        smoke._candidate_contract(release)


def test_installed_metadata_must_match_candidate(monkeypatch):
    monkeypatch.setattr(smoke, "version", lambda _: "0.2.8")
    with pytest.raises(smoke.SmokeError, match="invalid_configuration"):
        smoke._candidate_contract(__version__)


@pytest.mark.parametrize("field,value", [
    ("application_version", "0.2.8"),
    ("integration_guide_version", "1.4.0"),
    ("release_id", "wrong-release"),
    ("coordination_protocol_version", True),
    ("coordination_protocol_version", 2),
])
async def test_matching_rest_and_mcp_cannot_bless_wrong_runtime(tmp_path, field, value):
    from contextlib import asynccontextmanager

    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.expected = smoke._candidate_contract(__version__)
    backend.writer = {"api_key": "offline-test-secret"}
    info = {**backend.expected["info"], field: value}

    async def get(path, **kwargs):
        return httpx2.Response(200, json=(
            [{"name": backend.writer_name}, {"name": backend.reader_name}]
            if path == "/api/agents" else info
        ))

    @asynccontextmanager
    async def mcp(_):
        async def call(name):
            content = {"agent": {"name": backend.writer_name}} if name == "whoami" else info
            return SimpleNamespace(is_error=False, structured_content=content)
        yield SimpleNamespace(call_tool=call)

    backend.client = SimpleNamespace(get=get)
    backend.mcp = mcp
    with pytest.raises(smoke.SmokeError, match="invalid_response"):
        await backend.identity()


async def test_candidate_schema_and_release_environment_fail_before_enrollment(
    tmp_path, agent_service, monkeypatch
):
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    monkeypatch.setattr(smoke, "_release_environment", lambda _: b"STRUGGLEBUS_RELEASE_ID=0.2.8\n")
    with pytest.raises(smoke.SmokeError, match="invalid_configuration"):
        await backend.candidate_contract()
    monkeypatch.setattr(
        smoke, "_release_environment",
        lambda _: f"STRUGGLEBUS_RELEASE_ID={__version__}\n".encode(),
    )
    with closing(sqlite3.connect(tmp_path / "strugglebus.db")) as database:
        database.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION - 1}")
    with pytest.raises(smoke.SmokeError, match="invalid_configuration"):
        await backend.candidate_contract()
    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize("installed_schema,database_schema", [(11, 12), (12, 13), (17, 18), (18, 19), (19, 20)])
async def test_future_schema_refusal_has_zero_mutation(
    tmp_path, agent_service, monkeypatch, installed_schema, database_schema
):
    import strugglebus.migrations

    monkeypatch.setattr(strugglebus.migrations, "LATEST_SCHEMA_VERSION", installed_schema)
    monkeypatch.setattr(
        smoke, "_release_environment",
        lambda _: f"STRUGGLEBUS_RELEASE_ID={__version__}\n".encode(),
    )
    path = tmp_path / "strugglebus.db"
    with closing(sqlite3.connect(path)) as database:
        database.execute(f"PRAGMA user_version = {database_schema}")
        before = list(database.iterdump())
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.enrollment = AsyncMock()
    with pytest.raises(smoke.SmokeError, match="invalid_configuration"):
        await backend.candidate_contract()
    backend.enrollment.assert_not_awaited()
    backend.cleanup()
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == before
    assert backend.state_ready is False
    assert not backend.state_path.exists()


@pytest.mark.parametrize("schema", [11, 12, 13, 14, 15, 16])
@pytest.mark.parametrize("partial", [False, True])
def test_cleanup_preserves_legacy_and_lifecycle_history(tmp_path, schema, partial):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=schema, partial=partial)
    if schema >= 12:
        with closing(sqlite3.connect(path)) as database, database:
            database.execute(
                "UPDATE agents SET blocked_at='2026-01-02T00:00:00Z', "
                "credential_epoch=credential_epoch+1 WHERE id='writer-id'"
            )
    binding = (*smoke._file_identity(path), schema)
    smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=binding)
    offline.assert_namespace_absent(path)
    with closing(sqlite3.connect(path)) as database:
        before = list(database.iterdump())
        if schema >= 12:
            assert database.execute(
                "SELECT action, previous_state, resulting_state, previous_epoch, resulting_epoch "
                "FROM agent_lifecycle_audit WHERE agent_id='writer-id'"
            ).fetchall() == [("retire", "blocked", "retired", 2, 3)]
            assert database.execute(
                "SELECT blocked_at FROM agents WHERE id='writer-id'"
            ).fetchone() == (None,)
    smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=binding)
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == before


def _insert_keyed_cleanup_artifact(path, scope):
    with closing(sqlite3.connect(path)) as database, database:
        database.execute("PRAGMA foreign_keys = ON")
        if scope in {"smoke_author", "smoke_channel"}:
            database.execute("DELETE FROM messages WHERE id = 'answer'")
        question_seq = database.execute(
            "SELECT seq FROM messages WHERE id = 'question'"
        ).fetchone()[0]
        database.execute(
            """
            INSERT INTO messages (
                id, channel_id, agent_id, body, kind, reply_to, meta, created_at,
                post_request_id
            ) VALUES ('retained-keyed-message', ?, ?, ?, 'chat', ?, ?,
                      '2026-01-02T00:00:00Z', ?)
            """,
            (
                "smoke-channel" if scope == "smoke_channel" else (
                    "help-id" if scope == "smoke_author" else "existing-channel"
                ),
                "writer-id" if scope == "smoke_author" else "existing-agent",
                f"{offline.IDENTITY_MARKER} retained keyed post",
                question_seq if scope == "external_reply" else None,
                json.dumps({"marker": smoke.MARKER_VERSION, "run": offline.NAMESPACE}),
                str(uuid4()),
            ),
        )
        if scope == "external_mention":
            database.execute(
                "INSERT INTO mentions (message_seq, agent_id) "
                "SELECT seq, 'reader-id' FROM messages WHERE id = 'retained-keyed-message'"
            )


@pytest.mark.parametrize("scope", [
    "smoke_author", "smoke_channel", "external_reply", "external_mention",
])
@pytest.mark.parametrize("entrypoint", ["direct", "artifacts", "state", "contained_state"])
def test_schema_16_cleanup_refuses_keyed_artifacts_before_any_mutation(
    tmp_path, monkeypatch, scope, entrypoint,
):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=16)
    binding = (*smoke._file_identity(path), 16)
    if entrypoint == "contained_state":
        smoke._cleanup_transaction(
            path, namespace=offline.NAMESPACE, binding=binding, artifacts=False,
        )
    _insert_keyed_cleanup_artifact(path, scope)
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.namespace = offline.NAMESPACE
    backend.database_path = path
    backend.database_binding = binding
    backend._write_state()
    backend.state_ready = True
    if entrypoint == "contained_state":
        value = json.loads(backend.state_path.read_text())
        value["containment"] = "committed"
        smoke._atomic_json(backend.state_path, value)
    state_before = backend.state_path.read_bytes()
    with closing(sqlite3.connect(path)) as database:
        before = list(database.iterdump())
    statements = []
    open_database = smoke._database

    def traced_database(database_path):
        database = open_database(database_path)
        database.set_trace_callback(statements.append)
        return database

    monkeypatch.setattr(smoke, "_database", traced_database)
    for _ in range(2):
        with pytest.raises(smoke.SmokeError, match="^artifact_cleanup_refused$"):
            if entrypoint == "direct":
                smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=binding)
            elif entrypoint == "artifacts":
                smoke._remove_contained_artifacts(
                    path, namespace=offline.NAMESPACE, binding=binding,
                )
            else:
                backend.cleanup()
        with closing(sqlite3.connect(path)) as database:
            assert list(database.iterdump()) == before
            assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert database.execute("PRAGMA foreign_key_check").fetchall() == []
        assert backend.state_path.read_bytes() == state_before
    assert not any(
        statement.lstrip().split(maxsplit=1)[0].upper() in {"INSERT", "UPDATE", "DELETE"}
        for statement in statements
    )


def test_schema_16_cleanup_leaves_unrelated_keyed_history_untouched(tmp_path):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=16)
    _insert_keyed_cleanup_artifact(path, "unrelated")
    with closing(sqlite3.connect(path)) as database:
        before = database.execute(
            "SELECT * FROM messages WHERE id = 'retained-keyed-message'"
        ).fetchone()
    smoke.cleanup_database(
        path, namespace=offline.NAMESPACE, binding=(*smoke._file_identity(path), 16),
    )
    offline.assert_namespace_absent(path)
    with closing(sqlite3.connect(path)) as database:
        assert database.execute(
            "SELECT * FROM messages WHERE id = 'retained-keyed-message'"
        ).fetchone() == before
        assert database.execute(
            "SELECT rowid FROM messages_fts WHERE messages_fts MATCH 'retained'"
        ).fetchall() == [(before[0],)]


@pytest.mark.parametrize("schema", [10, 25, 99])
def test_cleanup_unknown_schema_refuses_before_any_mutation(tmp_path, schema):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=16)
    with closing(sqlite3.connect(path)) as database, database:
        database.execute(f"PRAGMA user_version = {schema}")
        before = list(database.iterdump())
    with pytest.raises(smoke.SmokeError, match="^cleanup_refused$"):
        smoke.cleanup_database(
            path, namespace=offline.NAMESPACE, binding=(*smoke._file_identity(path), schema),
        )
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == before


@pytest.mark.parametrize("failure", [
    "enrollment", "enrollment_shape", "proof", "proof_rejected",
    "roe", "roe_receipt_hash", "roe_fetch_hash",
])
async def test_bootstrap_failures_cleanup_only_operation(
    tmp_path, app_config, agent_service, uvicorn_server, monkeypatch, failure
):
    existing = agent_service.create_agent("existing-offline")
    app = create_app(
        agent_service=agent_service,
        config=replace(app_config, release_id=__version__, roe_enforcement_mode="enforce"),
    )
    monkeypatch.setattr(
        smoke, "_release_environment",
        lambda _: f"STRUGGLEBUS_RELEASE_ID={__version__}\n".encode(),
    )
    with uvicorn_server(app) as url:
        config = configuration(tmp_path)
        config.update(base_url=url, ca_path=True)
        backend = smoke.RealSmokeBackend(config, tmp_path / "state.json")
        await backend.setup()
        try:
            await backend.candidate_contract()
            if failure.startswith("enrollment"):
                if failure == "enrollment":
                    backend.client.post = AsyncMock(return_value=httpx2.Response(401))
                else:
                    original_post = backend.client.post

                    async def malformed_enrollment(*args, **kwargs):
                        response = await original_post(*args, **kwargs)
                        value = response.json()
                        value.pop("credential_secret")
                        return httpx2.Response(201, json=value, headers=response.headers)

                    backend.client.post = malformed_enrollment
                with pytest.raises(smoke.SmokeError):
                    await backend.enrollment()
            else:
                await backend.enrollment()
                if failure.startswith("proof"):
                    if failure == "proof":
                        backend.writer["id"] = "wrong-pinned-id"
                    else:
                        backend.client.post = AsyncMock(return_value=httpx2.Response(401))
                    with pytest.raises(smoke.SmokeError):
                        await backend.credential_proof()
                else:
                    await backend.credential_proof()
                    if failure == "roe":
                        backend.client.post = AsyncMock(return_value=httpx2.Response(409))
                    elif failure == "roe_receipt_hash":
                        original_post = backend.client.post

                        async def wrong_receipt(*args, **kwargs):
                            response = await original_post(*args, **kwargs)
                            value = response.json()
                            value["effective_sha256"] = "0" * 64
                            return httpx2.Response(response.status_code, json=value)

                        backend.client.post = wrong_receipt
                    else:
                        original_get = backend.client.get

                        async def wrong_effective(*args, **kwargs):
                            response = await original_get(*args, **kwargs)
                            value = response.json()
                            value["global_revision"]["content_sha256"] = "0" * 64
                            return httpx2.Response(response.status_code, json=value)

                        backend.client.get = wrong_effective
                    with pytest.raises(smoke.SmokeError):
                        await backend.roe_receipt()
        finally:
            backend.cleanup()
            await backend.close()
        backend.cleanup()
        assert agent_service.authenticate(existing.api_key) is not None
        with closing(sqlite3.connect(app_config.database_path)) as database:
            assert database.execute(
                "SELECT COUNT(*) FROM agents "
                "WHERE revoked_at IS NULL AND id != ? "
                "AND name NOT IN ('system:strugglebus-maintenance', 'human:operator')",
                (existing.agent.id,),
            ).fetchone() == (0,)
            assert database.execute(
                "SELECT COUNT(*) FROM agent_enrollments WHERE status = 'pending'"
            ).fetchone() == (0,)


@pytest.mark.parametrize("contamination", [
    "outsider_subscription", "external_reply", "identity_marker", "future_schema",
    "missing_redemption", "foreign_enrollment_actor",
])
def test_cleanup_refuses_foreign_data_atomically(tmp_path, contamination):
    path = tmp_path / "fixture.db"
    offline.create_database(path)
    with closing(sqlite3.connect(path)) as database, database:
        if contamination == "outsider_subscription":
            database.execute(
                "INSERT INTO subscriptions VALUES ('existing-agent', 'smoke-channel', '2026-01-01')"
            )
        elif contamination == "external_reply":
            database.execute(
                "UPDATE messages SET reply_to = (SELECT seq FROM messages WHERE id = 'question') "
                "WHERE id = 'existing-message'"
            )
        elif contamination == "identity_marker":
            database.execute("UPDATE agents SET description = 'unrelated' WHERE id = 'reader-id'")
        elif contamination == "future_schema":
            database.execute("PRAGMA user_version = 12")
        elif contamination == "missing_redemption":
            database.execute("DROP TRIGGER agent_enrollment_redemptions_no_delete")
            database.execute("DELETE FROM agent_enrollment_redemptions WHERE agent_id = 'reader-id'")
        else:
            database.execute("DROP TRIGGER agent_enrollments_immutable_identity")
            database.execute("DROP TRIGGER agent_enrollments_monotonic_consumption")
            database.execute("UPDATE agent_enrollments SET actor_id = 'foreign-operation'")
    with closing(sqlite3.connect(path)) as database:
        before = list(database.iterdump())
        artifacts_before = {
            table: database.execute(f"SELECT * FROM {table}").fetchall()
            for table in ("messages", "subscriptions", "cursors", "channels", "mentions")
        }
    contaminated_artifacts = contamination in {"outsider_subscription", "external_reply"}
    with pytest.raises(smoke.SmokeError, match=(
        "artifact_cleanup_refused" if contaminated_artifacts else "^cleanup_refused$"
    )):
        smoke.cleanup_database(
            path, namespace=offline.NAMESPACE, binding=(*smoke._file_identity(path), 11)
        )
    with closing(sqlite3.connect(path)) as database:
        if contaminated_artifacts:
            assert {
                table: database.execute(f"SELECT * FROM {table}").fetchall()
                for table in artifacts_before
            } == artifacts_before
            assert database.execute(
                "SELECT COUNT(*) FROM agents WHERE id IN ('writer-id', 'reader-id') "
                "AND revoked_at IS NULL"
            ).fetchone() == (0,)
        else:
            assert list(database.iterdump()) == before


@pytest.mark.parametrize("corruption", ["database_inode", "database_device", "schema_version"])
async def test_cleanup_state_is_bound_to_original_database(
    tmp_path, agent_service, monkeypatch, corruption
):
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    monkeypatch.setattr(
        smoke, "_release_environment",
        lambda _: f"STRUGGLEBUS_RELEASE_ID={__version__}\n".encode(),
    )
    await backend.candidate_contract()
    value = json.loads(backend.state_path.read_text())
    value[corruption] += 1
    smoke._atomic_json(backend.state_path, value)
    with pytest.raises(smoke.SmokeError, match="cleanup_refused"):
        smoke._load_state(backend.state_path)


@pytest.mark.parametrize("invalid", [
    [{"phase": "candidate_contract", "secret": "offline-test-secret"}],
    [{"phase": "candidate_contract", "passed": "yes", "status_category": "ok",
      "shape_matches": True, "count_matches": True, "error_code": "none"}],
    ["offline-test-secret"],
])
def test_saved_result_cannot_smuggle_unsanitized_output(tmp_path, invalid):
    path = tmp_path / "result.json"
    smoke._atomic_json(path, invalid)
    with pytest.raises(smoke.SmokeError, match="result_write_failed"):
        smoke.ResultStore(path).load()


async def test_mcp_connection_failure_is_not_revocation_denial(tmp_path):
    from contextlib import asynccontextmanager

    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.reader = {"api_key": "offline-test-secret"}

    @asynccontextmanager
    async def disconnected(_, **kwargs):
        raise httpx2.ConnectError("offline")
        yield  # pragma: no cover

    backend.mcp = disconnected
    with pytest.raises(httpx2.ConnectError):
        await backend.mcp_denial()


def test_both_cleanup_paths_refuse_replaced_database(tmp_path, monkeypatch, capsys):
    path = tmp_path / "strugglebus.db"
    offline.create_database(path)
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.namespace = offline.NAMESPACE
    backend.expected = {"schema": 11}
    backend.database_path = path
    backend.database_binding = (*smoke._file_identity(path), 11)
    backend._write_state()
    backend.state_ready = True
    original = tmp_path / "original.db"
    path.rename(original)
    with closing(sqlite3.connect(original)) as source, closing(sqlite3.connect(path)) as target:
        source.backup(target)
        before = list(target.iterdump())
    with pytest.raises(smoke.SmokeError, match="cleanup_refused"):
        backend.cleanup()
    monkeypatch.setattr(
        smoke, "_paths", lambda _: (tmp_path / "result.json", backend.state_path)
    )
    assert smoke._execute("cleanup", {"work_dir": str(tmp_path)}) == 1
    result = json.loads(capsys.readouterr().out)
    assert result[-1]["error_code"] == "cleanup_refused"
    for database_path in (original, path):
        with closing(sqlite3.connect(database_path)) as database:
            assert list(database.iterdump()) == before
    assert backend.state_path.exists()


@pytest.mark.parametrize("changed_at_check", [2, 3])
def test_cleanup_rechecks_binding_inside_transaction(tmp_path, monkeypatch, changed_at_check):
    path = tmp_path / "fixture.db"
    offline.create_database(path)
    identity = smoke._file_identity(path)
    with closing(sqlite3.connect(path)) as database:
        before = list(database.iterdump())
    checks = 0

    def changed_identity(_):
        nonlocal checks
        checks += 1
        return identity if checks < changed_at_check else (identity[0], identity[1] + 1)

    monkeypatch.setattr(smoke, "_file_identity", changed_identity)
    with pytest.raises(smoke.SmokeError, match="cleanup_refused"):
        smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=(*identity, 11))
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == before


@pytest.mark.parametrize("drift", ["replacement", "schema_advance", "precommit_refusal"])
async def test_enrollment_revalidates_preflight_binding_before_any_commit(
    tmp_path, agent_service, monkeypatch, drift
):
    path = tmp_path / "strugglebus.db"
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    monkeypatch.setattr(
        smoke, "_release_environment",
        lambda _: f"STRUGGLEBUS_RELEASE_ID={__version__}\n".encode(),
    )
    await backend.candidate_contract()
    backend.client = SimpleNamespace(post=AsyncMock())
    if drift == "replacement":
        original = tmp_path / "original.db"
        path.rename(original)
        with closing(sqlite3.connect(original)) as source, closing(sqlite3.connect(path)) as target:
            source.backup(target)
    elif drift == "schema_advance":
        with closing(sqlite3.connect(path)) as database:
            database.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION + 1}")
    else:
        check_binding = smoke._check_binding
        checks = 0

        def reject_precommit(*args, **kwargs):
            nonlocal checks
            checks += 1
            check_binding(*args, **kwargs)
            if checks == 3:
                raise smoke.SmokeError("cleanup_refused")

        monkeypatch.setattr(smoke, "_check_binding", reject_precommit)
    with closing(sqlite3.connect(path)) as database:
        before = list(database.iterdump())
    with pytest.raises(smoke.SmokeError, match="cleanup_refused"):
        await backend._register(backend.writer_name)
    backend.client.post.assert_not_awaited()
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == before
        for table in (
            "agent_enrollments", "agent_credentials", "agent_credential_requests",
            "agent_credential_audit", "agent_enrollment_redemptions",
        ):
            assert database.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)


async def test_candidate_cannot_capture_replacement_binding_after_validation(
    tmp_path, agent_service, monkeypatch
):
    path = tmp_path / "strugglebus.db"
    original = tmp_path / "original.db"
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    monkeypatch.setattr(
        smoke, "_release_environment",
        lambda _: f"STRUGGLEBUS_RELEASE_ID={__version__}\n".encode(),
    )
    open_database = smoke._database

    def replace_before_open(database_path):
        path.rename(original)
        with closing(sqlite3.connect(original)) as source, closing(sqlite3.connect(path)) as target:
            source.backup(target)
        return open_database(database_path)

    monkeypatch.setattr(smoke, "_database", replace_before_open)
    with pytest.raises(smoke.SmokeError, match="invalid_configuration"):
        await backend.candidate_contract()
    assert not backend.state_ready
    assert not backend.state_path.exists()
    with closing(sqlite3.connect(original)) as source, closing(sqlite3.connect(path)) as target:
        assert list(source.iterdump()) == list(target.iterdump())


async def test_bound_enrollment_preserves_domain_freeze_guard(tmp_path, agent_service, monkeypatch):
    from strugglebus.errors import AgentAccessFrozenError

    path = tmp_path / "strugglebus.db"
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    monkeypatch.setattr(
        smoke, "_release_environment",
        lambda _: f"STRUGGLEBUS_RELEASE_ID={__version__}\n".encode(),
    )
    await backend.candidate_contract()
    agent_service.store.set_access_freeze(
        frozen=True, reason="offline fixture", changed_at=datetime.now(UTC),
    )
    with closing(sqlite3.connect(path)) as database:
        before = list(database.iterdump())
    backend.client = SimpleNamespace(post=AsyncMock())
    with pytest.raises(AgentAccessFrozenError):
        await backend._register(backend.writer_name)
    backend.client.post.assert_not_awaited()
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == before


@pytest.mark.parametrize("artifact", ["subscription", "cursor", "reply", "foreign_message"])
async def test_artifact_refusal_still_contains_proven_identities_in_both_paths(
    tmp_path, app_config, agent_service, uvicorn_server, monkeypatch, capsys, artifact
):
    existing = agent_service.create_agent("existing-offline")
    app = create_app(
        agent_service=agent_service,
        config=replace(app_config, release_id=__version__, roe_enforcement_mode="enforce"),
    )
    monkeypatch.setattr(
        smoke, "_release_environment",
        lambda _: f"STRUGGLEBUS_RELEASE_ID={__version__}\n".encode(),
    )
    with uvicorn_server(app) as url:
        config = configuration(tmp_path)
        config.update(base_url=url, ca_path=True)
        backend = smoke.RealSmokeBackend(config, tmp_path / "state.json")
        await backend.setup()
        try:
            for phase in (
                "candidate_contract", "enrollment", "credential_proof", "roe_receipt",
                "channel_subscription", "mcp_post_rest_read", "rest_reply_mcp_read",
            ):
                await getattr(backend, phase)()
            path = app_config.database_path
            with closing(sqlite3.connect(path)) as database, database:
                channel_id = database.execute(
                    "SELECT id FROM channels WHERE name = ?", (backend.channel_name,)
                ).fetchone()[0]
                if artifact == "subscription":
                    database.execute(
                        "INSERT INTO subscriptions VALUES (?, ?, ?)",
                        (existing.agent.id, channel_id, datetime.now(UTC).isoformat()),
                    )
                elif artifact == "cursor":
                    database.execute(
                        "INSERT INTO cursors VALUES (?, ?, 0, ?, ?)",
                        (existing.agent.id, channel_id, backend.question_seq, datetime.now(UTC).isoformat()),
                    )
                else:
                    database.execute(
                        "INSERT INTO messages (id,channel_id,agent_id,body,kind,reply_to,meta,created_at) "
                        "VALUES ('foreign', ?, ?, 'foreign body', 'chat', ?, '{}', ?)",
                        (
                            channel_id, existing.agent.id,
                            backend.question_seq if artifact == "reply" else None,
                            datetime.now(UTC).isoformat(),
                        ),
                    )
            with closing(sqlite3.connect(path)) as database:
                foreign_agent = database.execute(
                    "SELECT * FROM agents WHERE id = ?", (existing.agent.id,)
                ).fetchone()
                immutable_before = {
                    table: database.execute(f"SELECT * FROM {table}").fetchall()
                    for table in (
                        "messages", "channels", "subscriptions", "cursors", "mentions",
                        "agent_enrollment_redemptions", "roe_acknowledgements",
                    )
                }
            with pytest.raises(smoke.SmokeError, match="artifact_cleanup_refused"):
                backend.cleanup()
            assert agent_service.authenticate(backend.writer["api_key"]) is None
            assert agent_service.authenticate(backend.reader["api_key"]) is None
            with closing(sqlite3.connect(path)) as database:
                assert database.execute(
                    "SELECT * FROM agents WHERE id = ?", (existing.agent.id,)
                ).fetchone() == foreign_agent
                assert {
                    table: database.execute(f"SELECT * FROM {table}").fetchall()
                    for table in immutable_before
                } == immutable_before
                assert database.execute(
                    "SELECT COUNT(*) FROM agent_credential_audit WHERE event_type='agent-revoke'"
                ).fetchone() == (2,)
                contained = list(database.iterdump())
            monkeypatch.setattr(
                smoke, "_paths", lambda _: (tmp_path / "result.json", backend.state_path)
            )
            for _ in range(2):
                assert smoke._execute("cleanup", {"work_dir": str(tmp_path)}) == 1
                result = json.loads(capsys.readouterr().out)
                assert result[-1]["error_code"] == "artifact_cleanup_refused"
                assert result[-1]["passed"] is False
                with closing(sqlite3.connect(path)) as database:
                    assert list(database.iterdump()) == contained
            assert backend.state_path.exists()
            assert (tmp_path / "result.json").exists()
        finally:
            await backend.close()


@pytest.mark.parametrize("interference", ["replacement", "identity_marker"])
async def test_interference_between_cleanup_transactions_preserves_phase_evidence(
    tmp_path, monkeypatch, capsys, interference
):
    path = tmp_path / "strugglebus.db"
    original = tmp_path / "contained-original.db" if interference == "replacement" else path
    offline.create_database(path)
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.namespace = offline.NAMESPACE
    backend.database_path = path
    backend.database_binding = (*smoke._file_identity(path), 11)
    backend._write_state()
    backend.state_ready = True
    backend.setup = AsyncMock()
    backend.close = AsyncMock()
    cleanup_transaction = smoke._cleanup_transaction
    replacement_before = []

    def replace_after_containment(*args, **kwargs):
        cleanup_transaction(*args, **kwargs)
        if not kwargs["artifacts"]:
            if interference == "replacement":
                path.rename(original)
                offline.create_database(path)
            else:
                with closing(sqlite3.connect(path)) as database, database:
                    database.execute(
                        "UPDATE agents SET description='interfered' WHERE id='writer-id'"
                    )
            with closing(sqlite3.connect(path)) as database:
                replacement_before.extend(database.iterdump())

    monkeypatch.setattr(smoke, "_cleanup_transaction", replace_after_containment)
    results = smoke.ResultStore(tmp_path / "result.json")
    assert await smoke.run_smoke(
        backend, results, failure_phase=smoke.PHASES[0]
    ) is False
    assert results.results[-1]["phase"] == "helper_cleanup"
    assert results.results[-1]["passed"] is False
    assert results.results[-1]["error_code"] == "artifact_cleanup_refused"
    receipt = json.loads(backend.state_path.read_text())
    assert receipt["containment"] == "committed"
    assert (receipt["database_device"], receipt["database_inode"]) == backend.database_binding[:2]
    with closing(sqlite3.connect(original)) as database:
        assert database.execute(
            "SELECT COUNT(*) FROM agents WHERE id IN ('writer-id','reader-id') "
            "AND revoked_at IS NULL"
        ).fetchone() == (0,)
        assert database.execute(
            "SELECT COUNT(*) FROM agent_credentials WHERE agent_id IN ('writer-id','reader-id') "
            "AND status IN ('pending','active')"
        ).fetchone() == (0,)
        assert database.execute(
            "SELECT COUNT(*) FROM agent_credential_audit WHERE event_type='agent-revoke'"
        ).fetchone() == (2,)
        assert database.execute("SELECT COUNT(*) FROM messages").fetchone() == (4,)
        contained = list(database.iterdump())
    monkeypatch.setattr(
        smoke, "_paths", lambda _: (tmp_path / "result.json", backend.state_path)
    )
    for _ in range(2):
        with pytest.raises(smoke.SmokeError, match="artifact_cleanup_refused"):
            backend.cleanup()
        assert smoke._execute("cleanup", {"work_dir": str(tmp_path)}) == 1
        final_results = json.loads(capsys.readouterr().out)
        assert final_results[-1]["phase"] == "ansible_always_cleanup"
        assert final_results[-1]["passed"] is False
        assert final_results[-1]["error_code"] == "artifact_cleanup_refused"
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == replacement_before
    with closing(sqlite3.connect(original)) as database:
        assert list(database.iterdump()) == contained
    assert backend.state_path.exists()


async def test_unrecorded_containment_commit_is_reported_as_unknown_on_retry(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "strugglebus.db"
    offline.create_database(path)
    backend = smoke.RealSmokeBackend(configuration(tmp_path), tmp_path / "state.json")
    backend.namespace = offline.NAMESPACE
    backend.database_path = path
    backend.database_binding = (*smoke._file_identity(path), 11)
    backend._write_state()
    backend.state_ready = True
    atomic_json = smoke._atomic_json

    def refuse_committed_marker(target, value):
        if target == backend.state_path and value["containment"] == "committed":
            raise smoke.SmokeError("result_write_failed")
        atomic_json(target, value)

    monkeypatch.setattr(smoke, "_atomic_json", refuse_committed_marker)
    with pytest.raises(smoke.SmokeError, match="artifact_cleanup_refused"):
        backend.cleanup()
    assert json.loads(backend.state_path.read_text())["containment"] == "unknown"
    with closing(sqlite3.connect(path)) as database, database:
        assert database.execute(
            "SELECT COUNT(*) FROM agents WHERE id IN ('writer-id','reader-id') "
            "AND revoked_at IS NULL"
        ).fetchone() == (0,)
        database.execute("UPDATE agents SET description='interfered' WHERE id='writer-id'")
    monkeypatch.setattr(smoke, "_atomic_json", atomic_json)
    with closing(sqlite3.connect(path)) as database:
        before_retry = list(database.iterdump())
    monkeypatch.setattr(
        smoke, "_paths", lambda _: (tmp_path / "result.json", backend.state_path)
    )
    for _ in range(2):
        with pytest.raises(smoke.SmokeError, match="containment_unknown"):
            backend.cleanup()
        assert smoke._execute("cleanup", {"work_dir": str(tmp_path)}) == 1
        result = json.loads(capsys.readouterr().out)
        assert result[-1]["error_code"] == "containment_unknown"
        assert result[-1]["passed"] is False
        with closing(sqlite3.connect(path)) as database:
            assert list(database.iterdump()) == before_retry


def _assert_offline_cleanup_transaction_refused(path, error_code, *, artifacts=False):
    binding = (*smoke._file_identity(path), 16)
    with closing(sqlite3.connect(path)) as database:
        before = list(database.iterdump())
    attempted_containment = []
    for _ in range(2):
        with pytest.raises(smoke.SmokeError, match=f"^{error_code}$"):
            smoke._cleanup_transaction(
                path, namespace=offline.NAMESPACE, binding=binding, artifacts=artifacts,
                before_containment=lambda: attempted_containment.append(True),
            )
        with closing(sqlite3.connect(path)) as database:
            assert list(database.iterdump()) == before
            assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert database.execute("PRAGMA foreign_key_check").fetchall() == []
    assert attempted_containment == []


@pytest.mark.parametrize("namespace", [
    "smoke-short", "other-0123456789abcdef", "smoke-0123456789abcdeg",
])
def test_offline_cleanup_rejects_noncanonical_namespace_without_mutation(tmp_path, namespace):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=16)
    with closing(sqlite3.connect(path)) as database:
        before = list(database.iterdump())
    with pytest.raises(smoke.SmokeError, match="^cleanup_refused$"):
        smoke.cleanup_database(
            path, namespace=namespace, binding=(*smoke._file_identity(path), 16),
        )
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == before


@pytest.mark.parametrize("partial", [False, True], ids=["too-many", "duplicate-name"])
def test_offline_cleanup_refuses_ambiguous_enrollment_allowances(tmp_path, partial):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=16, partial=partial)
    with closing(sqlite3.connect(path)) as database, database:
        database.execute("PRAGMA foreign_keys = ON")
        database.execute(
            """
            INSERT INTO agent_enrollments (
                id, secret_hash, name_prefix, description, status, uses_allowed,
                uses_remaining, created_at, expires_at, actor_type, actor_id,
                creation_reason, name_match
            ) VALUES ('extra-allowance', ?, ?, ?, 'pending', 1, 1,
                      '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z',
                      'local-admin', ?, ?, 'exact')
            """,
            (
                "f" * 64, offline.WRITER_NAME, offline.IDENTITY_MARKER,
                offline.NAMESPACE, smoke.ENROLLMENT_REASON,
            ),
        )
    _assert_offline_cleanup_transaction_refused(path, "cleanup_refused")


@pytest.mark.parametrize("provenance", [
    "foreign-redemption", "unredeemed-identity", "unproven-credential",
])
def test_offline_cleanup_refuses_incomplete_identity_provenance(tmp_path, provenance):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=16, partial=True)
    with closing(sqlite3.connect(path)) as database, database:
        database.execute("PRAGMA foreign_keys = ON")
        if provenance == "foreign-redemption":
            database.execute(
                """
                INSERT INTO agent_enrollments (
                    id, secret_hash, name_prefix, description, status, uses_allowed,
                    uses_remaining, created_at, expires_at, exhausted_at,
                    actor_type, actor_id, creation_reason, name_match
                ) VALUES ('foreign-redemption', ?, ?, ?, 'exhausted', 1, 0,
                          '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z',
                          '2026-01-01T00:00:00Z', 'local-admin', ?, ?, 'exact')
                """,
                (
                    "f" * 64, offline.READER_NAME, offline.IDENTITY_MARKER,
                    offline.NAMESPACE, smoke.ENROLLMENT_REASON,
                ),
            )
            database.execute(
                """
                INSERT INTO agent_enrollment_redemptions (
                    enrollment_id, agent_id, credential_id, claimed_name,
                    request_id, redeemed_at
                ) VALUES ('foreign-redemption', 'existing-agent',
                          'legacy-agent:existing-agent', ?, 'foreign-redemption-request',
                          '2026-01-01T00:00:00Z')
                """,
                (offline.READER_NAME,),
            )
        elif provenance == "unredeemed-identity":
            database.execute(
                """
                INSERT INTO agents (
                    id, name, description, host, created_at, credential_epoch
                ) VALUES ('reader-id', ?, ?, ?, '2026-01-01T00:00:00Z', 1)
                """,
                (offline.READER_NAME, offline.IDENTITY_MARKER, smoke.HOST_MARKER),
            )
        else:
            database.execute(
                """
                INSERT INTO agent_credentials (
                    id, agent_id, kind, secret_hash, status, creation_method,
                    creation_reason, issuance_request_id, created_at, pending_expires_at
                ) VALUES ('unproven-credential', 'writer-id', 'sb1', ?, 'pending',
                          'enrollment', 'unproven credential lineage', 'unproven-issuance',
                          '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')
                """,
                ("f" * 64,),
            )
    _assert_offline_cleanup_transaction_refused(path, "cleanup_refused")


@pytest.mark.parametrize("contamination", [
    "channel-purpose", "channel-owner", "malformed-metadata",
    "foreign-mention-recipient", "foreign-mention-message",
    "foreign-subscription", "foreign-cursor",
])
def test_offline_cleanup_artifact_refusal_preserves_state_and_recovers(tmp_path, contamination):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=16)
    binding = (*smoke._file_identity(path), 16)
    smoke._cleanup_transaction(
        path, namespace=offline.NAMESPACE, binding=binding, artifacts=False,
    )
    metadata = json.dumps(
        {"marker": smoke.MARKER_VERSION, "run": offline.NAMESPACE}, separators=(",", ":"),
    )
    mutation, recovery, recovery_values = {
        "channel-purpose": (
            "UPDATE channels SET purpose = 'foreign purpose' WHERE id = 'smoke-channel'",
            "UPDATE channels SET purpose = ? WHERE id = 'smoke-channel'",
            (offline.IDENTITY_MARKER,),
        ),
        "channel-owner": (
            "UPDATE channels SET created_by = 'existing-agent' WHERE id = 'smoke-channel'",
            "UPDATE channels SET created_by = 'writer-id' WHERE id = 'smoke-channel'",
            (),
        ),
        "malformed-metadata": (
            "UPDATE messages SET meta = '{' WHERE id = 'answer'",
            "UPDATE messages SET meta = ? WHERE id = 'answer'",
            (metadata,),
        ),
        "foreign-mention-recipient": (
            "INSERT INTO mentions SELECT seq, 'existing-agent' FROM messages WHERE id = 'question'",
            "DELETE FROM mentions WHERE agent_id = 'existing-agent' "
            "AND message_seq = (SELECT seq FROM messages WHERE id = 'question')",
            (),
        ),
        "foreign-mention-message": (
            "INSERT INTO mentions SELECT seq, 'reader-id' FROM messages WHERE id = 'existing-message'",
            "DELETE FROM mentions WHERE agent_id = 'reader-id' "
            "AND message_seq = (SELECT seq FROM messages WHERE id = 'existing-message')",
            (),
        ),
        "foreign-subscription": (
            "INSERT INTO subscriptions (agent_id, channel_id, created_at) "
            "VALUES ('writer-id', 'existing-channel', '2026-01-01T00:00:00Z')",
            "DELETE FROM subscriptions WHERE agent_id = 'writer-id' "
            "AND channel_id = 'existing-channel'",
            (),
        ),
        "foreign-cursor": (
            "INSERT INTO cursors (agent_id, channel_id, include_stale, last_seq, updated_at) "
            "VALUES ('writer-id', 'existing-channel', 0, 1, '2026-01-01T00:00:00Z')",
            "DELETE FROM cursors WHERE agent_id = 'writer-id' AND channel_id = 'existing-channel'",
            (),
        ),
    }[contamination]
    with closing(sqlite3.connect(path)) as database, database:
        database.execute("PRAGMA foreign_keys = ON")
        database.execute(mutation)
    _assert_offline_cleanup_transaction_refused(
        path, "artifact_cleanup_refused", artifacts=True,
    )
    with closing(sqlite3.connect(path)) as database, database:
        database.execute("PRAGMA foreign_keys = ON")
        database.execute(recovery, recovery_values)
    smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=binding)
    offline.assert_namespace_absent(path)
    with closing(sqlite3.connect(path)) as database:
        cleaned = list(database.iterdump())
    smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=binding)
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == cleaned


def test_offline_cleanup_of_partial_run_does_not_require_help_channel(tmp_path):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=16, partial=True)
    with closing(sqlite3.connect(path)) as database, database:
        database.execute("PRAGMA foreign_keys = ON")
        database.execute("DELETE FROM channels WHERE name = 'help'")
    binding = (*smoke._file_identity(path), 16)
    smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=binding)
    offline.assert_namespace_absent(path)
    with closing(sqlite3.connect(path)) as database:
        assert database.execute("SELECT 1 FROM channels WHERE name = 'help'").fetchone() is None
        cleaned = list(database.iterdump())
    smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=binding)
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == cleaned


def test_offline_cleanup_requires_containment_and_rolls_back_artifact_deletions(tmp_path):
    path = tmp_path / "fixture.db"
    offline.create_database(path, schema=16)
    _assert_offline_cleanup_transaction_refused(path, "cleanup_failed", artifacts=True)
    binding = (*smoke._file_identity(path), 16)
    smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=binding)
    offline.assert_namespace_absent(path)
    with closing(sqlite3.connect(path)) as database:
        assert database.execute(
            "SELECT COUNT(*) FROM messages WHERE agent_id IN ('writer-id', 'reader-id')"
        ).fetchone() == (0,)
        assert database.execute(
            "SELECT COUNT(*) FROM agent_lifecycle_audit WHERE action = 'retire'"
        ).fetchone() == (2,)
        cleaned = list(database.iterdump())
    smoke.cleanup_database(path, namespace=offline.NAMESPACE, binding=binding)
    with closing(sqlite3.connect(path)) as database:
        assert list(database.iterdump()) == cleaned
