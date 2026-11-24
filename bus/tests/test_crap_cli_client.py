"""The network-facing client commands: URL and key handling, identity proof, SSE tail."""

from __future__ import annotations

import io
import json
import os
import ssl
import time
import uuid
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError, URLError

import pytest

import strugglebus.cli as cli
from strugglebus.cli import (
    EXIT_AUTH,
    EXIT_CONFIG,
    EXIT_NETWORK,
    EXIT_OK,
    EXIT_SERVER,
    main,
)
from strugglebus.errors import ConfigurationError
from strugglebus.service import MAX_SEQUENCE

class _OsProxy:
    """The real ``os`` module with a few attributes replaced for one module."""

    def __init__(self, **overrides: object) -> None:
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        overrides = self.__dict__["_overrides"]
        if name in overrides:
            return overrides[name]
        return getattr(os, name)


class _Response(io.BytesIO):
    def __init__(self, body: bytes, *, content_type: str = "application/json") -> None:
        super().__init__(body)
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _stream(body: bytes) -> _Response:
    return _Response(body, content_type="text/event-stream")


def _http_error(code: int) -> HTTPError:
    return HTTPError("https://bus.lan/x", code, "synthetic", Message(), None)


def _config(url: str = "https://bus.lan") -> SimpleNamespace:
    return SimpleNamespace(public_base_url=url)


# --- Base URL -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://bus.lan", "https://bus.lan"),
        ("https://bus.lan/", "https://bus.lan"),
        ("https://bus.lan:8443/", "https://bus.lan:8443"),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://localhost/", "http://localhost"),
        ("http://[::1]:8080", "http://[::1]:8080"),
        ("https://[fd00::1]:65535", "https://[fd00::1]:65535"),
    ],
)
def test_base_url_accepts_bare_origins_and_strips_the_trailing_slash(value, expected):
    assert cli._base_url(_config("https://ignored.example"), value) == expected


def test_base_url_falls_back_to_the_configured_public_url():
    assert cli._base_url(_config("https://configured.lan/"), None) == "https://configured.lan"


@pytest.mark.parametrize(
    "value",
    ["https://bus.lan/é", "https://bus .lan", "https://bus.lan\n", "https://bus.lan\x7f", 5],
    ids=["non-ascii", "space", "newline", "delete", "not-text"],
)
def test_base_url_rejects_unsafe_text(value):
    with pytest.raises(ConfigurationError, match="URL must be a safe ASCII HTTP\\(S\\) origin"):
        cli._base_url(_config(), value)


@pytest.mark.parametrize(
    "value", ["https://[::1", "https://bus.lan:port", "https://bus.lan:99999"],
)
def test_base_url_rejects_unparseable_hosts_and_ports(value):
    with pytest.raises(ConfigurationError, match="URL must be a valid HTTP\\(S\\) origin"):
        cli._base_url(_config(), value)


@pytest.mark.parametrize(
    "value",
    [
        "ftp://bus.lan",
        "bus.lan",
        "https://",
        "https://:8443",
        "https://operator@bus.lan",
        "https://operator:secret@bus.lan",
        "https://bus.lan/api",
        "https://bus.lan?next=1",
        "https://bus.lan#fragment",
    ],
)
def test_base_url_rejects_anything_beyond_scheme_host_and_port(value):
    with pytest.raises(ConfigurationError, match="HTTP\\(S\\) origin without credentials") as raised:
        cli._base_url(_config(), value)
    assert "secret" not in str(raised.value)


def test_base_url_rejects_port_zero():
    with pytest.raises(ConfigurationError, match="URL port must be between 1 and 65535"):
        cli._base_url(_config(), "https://bus.lan:0")


@pytest.mark.parametrize(
    "value", ["http://bus.lan", "http://192.168.1.10:8080", "http://localhost.example"],
)
def test_base_url_requires_https_for_remote_hosts(value):
    with pytest.raises(ConfigurationError, match="remote URL must use HTTPS"):
        cli._base_url(_config(), value)


# --- TLS context and opener ---------------------------------------------------


def test_ssl_context_reports_missing_and_invalid_ca_files(monkeypatch, tmp_path):
    monkeypatch.delenv("STRUGGLEBUS_CA_FILE", raising=False)
    with pytest.raises(ConfigurationError, match="CA file is unavailable or invalid"):
        cli._ssl_context(tmp_path / "absent.pem")

    invalid = tmp_path / "invalid.pem"
    invalid.write_text("not a certificate", encoding="ascii")
    with pytest.raises(ConfigurationError, match="CA file is unavailable or invalid"):
        cli._ssl_context(invalid)

    monkeypatch.setenv("STRUGGLEBUS_CA_FILE", str(tmp_path / "absent-from-env.pem"))
    with pytest.raises(ConfigurationError, match="CA file is unavailable or invalid"):
        cli._ssl_context(None)


def test_ssl_context_defaults_to_verifying_system_trust(monkeypatch):
    monkeypatch.delenv("STRUGGLEBUS_CA_FILE", raising=False)

    context = cli._ssl_context(None)

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_open_ignores_proxies_and_never_follows_redirects(monkeypatch):
    built = []

    def build(*handlers):
        built.append(handlers)
        return SimpleNamespace(open=lambda request, timeout: ("opened", request, timeout))

    monkeypatch.setattr(cli, "build_opener", build)
    context = ssl.create_default_context()

    assert cli._open("request", timeout=3.5, context=context) == ("opened", "request", 3.5)

    (proxy, https, redirect), = built
    assert isinstance(proxy, cli.ProxyHandler)
    assert proxy.proxies == {}
    assert isinstance(https, cli.HTTPSHandler)
    assert isinstance(redirect, cli._NoRedirectHandler)


@pytest.mark.parametrize(
    "error",
    [URLError("unreachable"), TimeoutError("slow"), ConnectionResetError("reset"),
     ssl.SSLError("handshake")],
    ids=["url", "timeout", "reset", "tls"],
)
def test_open_reports_transport_failures_without_detail(monkeypatch, error):
    def fail(request, timeout):
        raise error

    monkeypatch.setattr(cli, "build_opener", lambda *handlers: SimpleNamespace(open=fail))

    with pytest.raises(cli._NetworkFailure, match="^network request failed$") as raised:
        cli._open("request", timeout=1, context=object())
    assert raised.value.__cause__ is error


def test_open_lets_http_status_errors_through_for_the_caller_to_classify(monkeypatch):
    error = _http_error(503)

    def fail(request, timeout):
        raise error

    monkeypatch.setattr(cli, "build_opener", lambda *handlers: SimpleNamespace(open=fail))

    with pytest.raises(HTTPError) as raised:
        cli._open("request", timeout=1, context=object())
    assert raised.value is error


# --- API key ------------------------------------------------------------------


def _key_file(tmp_path: Path, content: bytes) -> Path:
    path = tmp_path.resolve() / "agent.key"
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def test_api_key_comes_from_exactly_one_source(tmp_path):
    path = _key_file(tmp_path, b"file-key\n")

    with pytest.raises(ConfigurationError, match="configure exactly one of"):
        cli._read_api_key(
            {"STRUGGLEBUS_API_KEY": "value-key", "STRUGGLEBUS_API_KEY_FILE": str(path)}
        )
    assert cli._read_api_key({"STRUGGLEBUS_API_KEY": "value-key_1"}) == "value-key_1"
    assert cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(path)}) == "file-key"


@pytest.mark.parametrize("environment", [{}, {"STRUGGLEBUS_API_KEY": ""},
                                         {"STRUGGLEBUS_API_KEY": "k" * 4097}])
def test_api_key_value_must_be_present_and_bounded(environment):
    with pytest.raises(ConfigurationError, match="agent API key is not configured"):
        cli._read_api_key(environment)


@pytest.mark.parametrize("value", ["has space", "semi;colon", "café", "line\nbreak"])
def test_api_key_value_must_be_url_safe_text(value):
    with pytest.raises(ConfigurationError, match="agent API key has an invalid format") as raised:
        cli._read_api_key({"STRUGGLEBUS_API_KEY": value})
    assert value not in str(raised.value)


def test_api_key_accepts_the_longest_allowed_value():
    assert cli._read_api_key({"STRUGGLEBUS_API_KEY": "k" * 4096}) == "k" * 4096


def test_api_key_file_path_must_be_absolute_and_openable(tmp_path):
    with pytest.raises(ConfigurationError, match="file path must be absolute"):
        cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": "agent.key"})
    with pytest.raises(ConfigurationError, match="agent API key file is unavailable"):
        cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(tmp_path.resolve() / "absent")})


@pytest.mark.parametrize(
    ("content", "expected"),
    [(b"file-key", "file-key"), (b"file-key\n", "file-key"), (b"file-key\r\n", "file-key"),
     (b"k" * 4096 + b"\n", "k" * 4096)],
    ids=["bare", "newline", "crlf", "longest"],
)
def test_api_key_file_line_ending_is_not_part_of_the_key(tmp_path, content, expected):
    path = _key_file(tmp_path, content)

    assert cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(path)}) == expected


@pytest.mark.parametrize("content", [b"", b"\n", b"\r\n", b"k" * 4097, b"k" * 9000])
def test_api_key_file_must_hold_a_bounded_non_empty_key(tmp_path, content):
    path = _key_file(tmp_path, content)

    with pytest.raises(ConfigurationError, match="must contain between 1 and 4096 bytes"):
        cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(path)})


def test_api_key_file_must_be_utf8_and_url_safe(tmp_path):
    with pytest.raises(ConfigurationError, match="must contain UTF-8 text"):
        cli._read_api_key(
            {"STRUGGLEBUS_API_KEY_FILE": str(_key_file(tmp_path, b"\xff\xfe-key"))}
        )
    with pytest.raises(ConfigurationError, match="agent API key has an invalid format"):
        cli._read_api_key(
            {"STRUGGLEBUS_API_KEY_FILE": str(_key_file(tmp_path, b"two words\n"))}
        )


def test_api_key_path_must_be_a_regular_file(monkeypatch, tmp_path):
    path = _key_file(tmp_path, b"file-key\n")
    real_fstat = os.fstat
    closed = []
    real_close = os.close

    def directory_fstat(descriptor):
        metadata = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=(metadata.st_mode & 0o7777) | 0o040000, st_uid=metadata.st_uid,
        )

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(cli, "os", _OsProxy(fstat=directory_fstat, close=close))

    with pytest.raises(ConfigurationError, match="path must be a regular file"):
        cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(path)})
    assert len(closed) == 1


def test_api_key_file_read_faults_are_reported_and_the_file_closed(monkeypatch, tmp_path):
    path = _key_file(tmp_path, b"file-key\n")
    closed = []
    real_close = os.close

    def fail(descriptor, size):
        raise OSError("synthetic read fault")

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(cli, "os", _OsProxy(read=fail, close=close))

    with pytest.raises(ConfigurationError, match="agent API key file is unreadable"):
        cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(path)})
    assert len(closed) == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o700, 0o604])
def test_api_key_file_must_be_private_to_its_owner(tmp_path, mode):
    path = _key_file(tmp_path, b"file-key\n")
    path.chmod(mode)

    with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
        cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(path)})


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_api_key_file_may_be_read_only_but_not_a_symbolic_link(tmp_path):
    path = _key_file(tmp_path, b"file-key\n")
    path.chmod(0o400)
    assert cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(path)}) == "file-key"

    link = tmp_path.resolve() / "link.key"
    link.symlink_to(path)
    with pytest.raises(ConfigurationError, match="agent API key file is unavailable"):
        cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(link)})


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_api_key_file_owned_by_an_unrelated_account_is_rejected(monkeypatch, tmp_path):
    if os.getuid() == 0:
        pytest.skip("root-owned key files are always acceptable")
    path = _key_file(tmp_path, b"file-key\n")
    monkeypatch.setattr(cli, "os", _OsProxy(geteuid=lambda: os.getuid() + 4242))

    with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
        cli._read_api_key({"STRUGGLEBUS_API_KEY_FILE": str(path)})


# --- SSE parsing --------------------------------------------------------------


def _events(body: bytes) -> list[tuple[str | None, str, str]]:
    return list(cli._iter_sse(io.BytesIO(body)))


def test_sse_events_carry_id_type_and_joined_data():
    body = (
        b"id: 7\nevent: message\ndata: first\ndata:second\n\n"
        b"data: default type\r\n\r\n"
        b": keep-alive\n"
        b"event: notice\nretry: 10\nunknown\ndata:  two spaces\n\n"
    )

    assert _events(body) == [
        ("7", "message", "first\nsecond"),
        (None, "message", "default type"),
        (None, "_comment", ""),
        (None, "notice", " two spaces"),
    ]


def test_sse_blank_line_without_data_discards_the_pending_event():
    body = b"id: 3\nevent: notice\n\ndata: later\n\n"

    assert _events(body) == [(None, "message", "later")]


def test_sse_ignores_ids_containing_nul_and_unterminated_events():
    body = b"id: 4\nid: bad\x00id\ndata: kept\n\nid: 9\ndata: never dispatched\n"

    assert _events(body) == [("4", "message", "kept")]


def test_sse_rejects_invalid_utf8():
    with pytest.raises(cli._ServerFailure, match="SSE stream was not valid UTF-8"):
        _events(b"data: \xff\xfe\n\n")


def test_sse_bounds_single_lines_and_whole_events():
    limit = cli.MAX_SSE_LINE_BYTES
    with pytest.raises(cli._ServerFailure, match="SSE line exceeded the configured bound"):
        _events(b"data: " + b"x" * limit + b"\n\n")

    line = b"data: " + b"x" * (limit // 2) + b"\n"
    assert len(_events(line + b"\n")) == 1
    with pytest.raises(cli._ServerFailure, match="SSE event exceeded the configured bound"):
        _events(line + line + b"\n")


# --- Identity proof -----------------------------------------------------------


def _identity(monkeypatch, responses, **overrides):
    requests = []
    queue = iter(responses)

    def open_request(request, **options):
        requests.append((request, options))
        response = next(queue)
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr(cli, "_open", open_request)
    arguments = {
        "base_url": "https://bus.lan",
        "api_key": "secret-agent-key",
        "expected_agent_id": "agent-1",
        "expected_agent_name": "builder",
        "timeout": 4.0,
        "context": "tls-context",
    }
    arguments.update(overrides)
    return requests, lambda: cli._assert_expected_identity(**arguments)


def _whoami(*, agent=None, credential=None) -> _Response:
    payload = {
        "agent": {"id": "agent-1", "name": "builder", "credential_epoch": 3}
        if agent is None else agent,
        "credential": {"status": "active", "version": 5}
        if credential is None else credential,
    }
    return _Response(json.dumps(payload).encode("ascii"))


def test_identity_check_accepts_the_expected_agent_with_an_active_credential(monkeypatch):
    requests, check = _identity(monkeypatch, [_whoami()])

    check()

    ((request, options),) = requests
    assert request.full_url == "https://bus.lan/api/whoami"
    assert request.get_method() == "GET"
    assert request.get_header("Authorization") == "Bearer secret-agent-key"
    assert request.get_header("Accept") == "application/json"
    assert options == {"timeout": 4.0, "context": "tls-context"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"expected_agent_id": "a" * 129},
        {"expected_agent_name": "n" * 129},
        {"expected_agent_id": "agent\x001"},
        {"expected_agent_name": "build\x00er"},
    ],
    ids=["long-id", "long-name", "nul-id", "nul-name"],
)
def test_identity_check_rejects_implausible_expectations_before_any_request(
    monkeypatch, overrides,
):
    requests, check = _identity(monkeypatch, [], **overrides)

    with pytest.raises(ConfigurationError, match="expected agent identity is invalid"):
        check()
    assert requests == []


@pytest.mark.parametrize(
    ("failure", "error", "message"),
    [
        (_http_error(401), cli._AuthenticationFailure, "agent authentication failed"),
        (_http_error(403), cli._AuthenticationFailure, "agent authentication failed"),
        (_http_error(500), cli._ServerFailure, "identity endpoint returned an error"),
        (_http_error(404), cli._ServerFailure, "identity endpoint returned an error"),
        (URLError("down"), cli._NetworkFailure, "identity endpoint was unavailable"),
        (TimeoutError("slow"), cli._NetworkFailure, "identity endpoint was unavailable"),
        (ssl.SSLError("tls"), cli._NetworkFailure, "identity endpoint was unavailable"),
    ],
)
def test_identity_lookup_failures_are_classified_without_leaking_detail(
    monkeypatch, failure, error, message,
):
    requests, check = _identity(monkeypatch, [failure])

    with pytest.raises(error, match=f"^{message}$") as raised:
        check()
    assert raised.value.__cause__ is None
    assert len(requests) == 1


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b"null", b'{"agent":{}}', b'{"credential":{}}', b'"text"'],
)
def test_identity_lookup_rejects_malformed_responses(monkeypatch, body):
    _, check = _identity(monkeypatch, [_Response(body)])

    with pytest.raises(cli._ServerFailure, match="identity endpoint returned an invalid response"):
        check()


def test_identity_lookup_response_is_bounded(monkeypatch):
    body = b'{"agent":"' + b"x" * cli.MAX_IDENTITY_RESPONSE_BYTES + b'"}'
    _, check = _identity(monkeypatch, [_Response(body)])

    with pytest.raises(cli._ServerFailure, match="server response exceeded the configured bound"):
        check()


@pytest.mark.parametrize(
    "agent",
    [
        {"id": "agent-2", "name": "builder"},
        {"id": "agent-1", "name": "other"},
        {"name": "builder"},
        ["agent-1", "builder"],
        "agent-1",
    ],
    ids=["other-id", "other-name", "missing-id", "list", "text"],
)
def test_identity_mismatch_is_an_authentication_failure(monkeypatch, agent):
    requests, check = _identity(monkeypatch, [_whoami(agent=agent)])

    with pytest.raises(cli._AuthenticationFailure, match="authenticated agent identity mismatch"):
        check()
    assert len(requests) == 1


@pytest.mark.parametrize(
    "credential",
    [{"status": "revoked"}, {"status": "expired"}, {"version": 1}, ["active"], "active"],
    ids=["revoked", "expired", "no-status", "list", "text"],
)
def test_credentials_that_are_neither_active_nor_pending_are_refused(
    monkeypatch, credential,
):
    requests, check = _identity(monkeypatch, [_whoami(credential=credential)])

    with pytest.raises(cli._AuthenticationFailure, match="authenticated credential is inactive"):
        check()
    assert len(requests) == 1


def test_pending_credential_is_proved_against_the_pinned_identity(monkeypatch):
    requests, check = _identity(
        monkeypatch,
        [
            _whoami(credential={"status": "pending", "version": 5}),
            _Response(b'{"status":"active"}'),
        ],
    )

    check()

    (_, _), (proof, options) = requests
    assert proof.full_url == "https://bus.lan/api/credentials/prove"
    assert proof.get_method() == "POST"
    assert proof.get_header("Authorization") == "Bearer secret-agent-key"
    assert proof.get_header("Content-type") == "application/json"
    assert options == {"timeout": 4.0, "context": "tls-context"}
    body = json.loads(proof.data)
    assert uuid.UUID(body.pop("request_id")).version == 4
    assert body == {
        "expected_agent_id": "agent-1",
        "expected_agent_name": "builder",
        "expected_credential_epoch": 3,
        "expected_credential_version": 5,
    }
    assert b" " not in proof.data


@pytest.mark.parametrize(
    ("outcome", "error", "message"),
    [
        (_http_error(401), cli._AuthenticationFailure, "credential identity proof failed"),
        (_http_error(403), cli._AuthenticationFailure, "credential identity proof failed"),
        (_http_error(409), cli._AuthenticationFailure, "credential identity proof failed"),
        (_http_error(500), cli._ServerFailure, "identity proof endpoint returned an error"),
        (URLError("down"), cli._NetworkFailure, "identity proof endpoint was unavailable"),
        (OSError("reset"), cli._NetworkFailure, "identity proof endpoint was unavailable"),
        (_Response(b"<html>"), cli._ServerFailure,
         "identity proof endpoint returned invalid JSON"),
        (_Response(b'{"status":"pending"}'), cli._AuthenticationFailure,
         "credential identity proof failed"),
        (_Response(b'["active"]'), cli._AuthenticationFailure,
         "credential identity proof failed"),
    ],
    ids=["401", "403", "409", "500", "unreachable", "reset", "not-json", "still-pending",
         "not-object"],
)
def test_identity_proof_failures_are_classified(monkeypatch, outcome, error, message):
    if isinstance(outcome, _Response):
        outcome = _Response(outcome.getvalue())
    requests, check = _identity(
        monkeypatch,
        [_whoami(credential={"status": "pending", "version": 5}), outcome],
    )

    with pytest.raises(error, match=f"^{message}$") as raised:
        check()
    assert raised.value.__cause__ is None
    assert len(requests) == 2


# --- Tail ---------------------------------------------------------------------


@pytest.fixture
def tail(monkeypatch, tmp_path):
    """Run ``tail`` against scripted stream responses; identity is pre-approved."""
    values = {
        "STRUGGLEBUS_DATA_DIR": str(tmp_path),
        "STRUGGLEBUS_RUNTIME_DIR": str(tmp_path / "run"),
        "STRUGGLEBUS_BACKUP_DIR": str(tmp_path / "backups"),
        "STRUGGLEBUS_DATABASE_PATH": str(tmp_path / "strugglebus.db"),
        "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": str(tmp_path / "admin-token"),
        "STRUGGLEBUS_PUBLIC_BASE_URL": "https://bus.lan",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("STRUGGLEBUS_API_KEY", "secret-agent-key")
    monkeypatch.delenv("STRUGGLEBUS_API_KEY_FILE", raising=False)
    monkeypatch.setenv("STRUGGLEBUS_EXPECTED_AGENT_ID", "agent-1")
    monkeypatch.setenv("STRUGGLEBUS_EXPECTED_AGENT_NAME", "builder")
    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: "tls-context")
    identities = []
    monkeypatch.setattr(cli, "_assert_expected_identity", lambda **kw: identities.append(kw))
    sleeps: list[float] = []
    monkeypatch.setattr(
        cli, "time", SimpleNamespace(sleep=sleeps.append, monotonic=time.monotonic),
    )
    requests = []

    def run(responses, *arguments):
        queue = iter(responses)

        def open_stream(request, **options):
            requests.append(request)
            response = next(queue)
            if isinstance(response, BaseException):
                raise response
            return response

        monkeypatch.setattr(cli, "_open", open_stream)
        output, diagnostics = io.StringIO(), io.StringIO()
        code = main(["tail", *arguments], stdout=output, stderr=diagnostics)
        return code, output.getvalue(), diagnostics.getvalue()

    return SimpleNamespace(run=run, requests=requests, sleeps=sleeps, identities=identities)


def test_tail_requires_an_expected_identity_before_contacting_the_server(tail, monkeypatch):
    monkeypatch.delenv("STRUGGLEBUS_EXPECTED_AGENT_NAME")

    code, output, diagnostics = tail.run([])

    assert code == EXIT_CONFIG
    assert diagnostics == (
        "configuration error: tail requires expected agent ID and name via flags or "
        "environment\n"
    )
    assert tail.identities == [] and tail.requests == []

    code, _, _ = tail.run(
        [_stream(b'id: 1\ndata: {"seq":1}\n\n')],
        "--expected-agent-name", "from-flag", "--expected-agent-id", "flag-id",
        "--max-events", "1",
    )
    assert code == EXIT_OK
    assert tail.identities[0]["expected_agent_name"] == "from-flag"
    assert tail.identities[0]["expected_agent_id"] == "flag-id"
    assert tail.identities[0]["api_key"] == "secret-agent-key"
    assert tail.identities[0]["base_url"] == "https://bus.lan"


def test_tail_sends_since_and_the_cursor_and_emits_compact_json(tail):
    code, output, diagnostics = tail.run(
        [_stream(b'id: 6\ndata: {"seq": 6, "body": "caf\\u00e9"}\n\n')],
        "--since", "5", "--max-events", "1",
    )

    assert (code, diagnostics) == (EXIT_OK, "")
    assert output == '{"seq":6,"body":"caf\\u00e9"}\n'
    (request,) = tail.requests
    assert request.full_url == "https://bus.lan/api/stream?since=5"
    assert request.get_header("Last-event-id") == "5"
    assert request.get_header("Authorization") == "Bearer secret-agent-key"
    assert request.get_header("Accept") == "text/event-stream"
    assert tail.sleeps == []


def test_tail_skips_other_events_and_already_seen_messages(tail, tmp_path):
    resume = tmp_path.resolve() / "state" / "resume"
    body = (
        b"event: presence\ndata: {}\n\n"
        b'id: 2\ndata: {"seq":2}\n\n'
        b'id: 3\ndata: {"seq":3}\n\n'
        b'id: 4\ndata: {"seq":4}\n\n'
    )

    code, output, _ = tail.run(
        [_stream(body)], "--since", "3", "--max-events", "1", "--resume-file", str(resume),
    )

    assert code == EXIT_OK
    assert output == '{"seq":4}\n'
    assert resume.read_text(encoding="ascii") == "4\n"


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b'data: {"seq":1}\n\n', "message event did not include an ID"),
        (b'id: one\ndata: {"seq":1}\n\n', "message event ID was invalid"),
        (b'id: -1\ndata: {"seq":-1}\n\n', "message event ID was outside the valid range"),
        (f'id: {MAX_SEQUENCE + 1}\ndata: {{}}\n\n'.encode("ascii"),
         "message event ID was outside the valid range"),
        (b"id: 1\ndata: {not json\n\n", "message event contained invalid JSON"),
        (b'id: 1\ndata: [1]\n\n', "message event JSON was not an object"),
        (b'id: 1\ndata: {"seq":2}\n\n', "message event ID did not match its payload"),
        (b'id: 1\ndata: {"seq":"1"}\n\n', "message event ID did not match its payload"),
        (b"event: agent_access_frozen\ndata: {}\n\n",
         "access-freeze event contained an invalid payload"),
        (b"event: agent_access_unavailable\ndata: {}\n\n", "agent access is unavailable"),
    ],
)
def test_tail_stops_on_malformed_or_terminal_events(tail, tmp_path, body, message):
    resume = tmp_path.resolve() / "resume"
    resume.write_text("0\n", encoding="ascii")

    code, output, diagnostics = tail.run([_stream(body)], "--resume-file", str(resume))

    assert code == EXIT_SERVER
    assert diagnostics == f"server error: {message}\n"
    assert output == ""
    assert resume.read_text(encoding="ascii") == "0\n"
    assert len(tail.requests) == 1


def test_tail_rejects_a_stream_that_is_not_sse(tail):
    code, output, diagnostics = tail.run([_Response(b'{"seq":1}')])

    assert (code, output) == (EXIT_SERVER, "")
    assert diagnostics == "server error: stream endpoint did not return an SSE response\n"


@pytest.mark.parametrize(
    ("status", "code", "diagnostic"),
    [
        (401, EXIT_AUTH, "authentication error: agent authentication failed\n"),
        (403, EXIT_AUTH, "authentication error: agent authentication failed\n"),
        (500, EXIT_SERVER, "server error: stream endpoint returned an error\n"),
        (429, EXIT_SERVER, "server error: stream endpoint returned an error\n"),
    ],
)
def test_tail_does_not_retry_http_status_errors(tail, status, code, diagnostic):
    result, output, diagnostics = tail.run([_http_error(status)], "--retries", "3")

    assert (result, output, diagnostics) == (code, "", diagnostic)
    assert len(tail.requests) == 1
    assert tail.sleeps == []


def test_tail_backs_off_exponentially_up_to_five_seconds(tail):
    failures = [URLError("down"), cli._NetworkFailure("down"), TimeoutError("slow"),
                OSError("reset"), ssl.SSLError("tls"), URLError("down"), URLError("down")]

    code, output, diagnostics = tail.run(failures, "--retries", "6")

    assert (code, output) == (EXIT_NETWORK, "")
    assert diagnostics == "network error: SSE reconnect limit exceeded\n"
    assert len(tail.requests) == 7
    assert tail.sleeps == [0.25, 0.5, 1.0, 2.0, 4.0, 5.0]


def test_tail_progress_resets_the_backoff_and_the_retry_budget(tail):
    responses = [
        URLError("down"),
        URLError("down"),
        _stream(b": keep-alive\n"),
        URLError("down"),
        URLError("down"),
        _stream(b'id: 1\ndata: {"seq":1}\n\n'),
    ]

    code, output, _ = tail.run(responses, "--retries", "2", "--max-events", "1")

    assert code == EXIT_OK
    assert output == '{"seq":1}\n'
    assert tail.sleeps == [0.25, 0.5, 0.25, 0.5, 1.0]


def test_tail_reconnects_from_the_last_emitted_sequence(tail):
    responses = [
        _stream(b'id: 8\ndata: {"seq":8}\n\n'),
        _stream(b'id: 9\ndata: {"seq":9}\n\n'),
    ]

    code, output, _ = tail.run(responses, "--since", "2", "--max-events", "2")

    assert code == EXIT_OK
    assert output == '{"seq":8}\n{"seq":9}\n'
    first, second = tail.requests
    assert first.get_header("Last-event-id") == "2"
    assert second.get_header("Last-event-id") == "8"
    assert second.full_url == "https://bus.lan/api/stream?since=2"
    assert tail.sleeps == [0.25]


def test_tail_reports_an_unwritable_resume_file_after_emitting(tail, tmp_path):
    blocker = tmp_path.resolve() / "blocker"
    blocker.write_text("file", encoding="ascii")

    code, output, diagnostics = tail.run(
        [_stream(b'id: 1\ndata: {"seq":1}\n\n')],
        "--resume-file", str(blocker / "resume"),
    )

    assert code == EXIT_CONFIG
    assert output == '{"seq":1}\n'
    assert diagnostics == "configuration error: resume file could not be updated\n"


# --- Resume file --------------------------------------------------------------


def test_resume_file_round_trips_and_defaults_to_zero(tmp_path):
    path = tmp_path.resolve() / "nested" / "resume"

    assert cli._read_resume(None) == 0
    assert cli._read_resume(path) == 0
    cli._write_resume(None, 5)
    cli._write_resume(path, 41)
    cli._write_resume(path, 42)

    assert path.read_text(encoding="ascii") == "42\n"
    assert cli._read_resume(path) == 42
    assert [entry.name for entry in path.parent.iterdir()] == ["resume"]


def test_resume_file_paths_must_be_absolute():
    with pytest.raises(ConfigurationError, match="resume file path must be absolute"):
        cli._read_resume(Path("resume"))
    with pytest.raises(ConfigurationError, match="resume file path must be absolute"):
        cli._write_resume(Path("resume"), 1)


@pytest.mark.parametrize("content", [b"", b"seven", b"1.5", b"\xff\xfe", b"4 2"])
def test_resume_file_must_contain_one_integer(tmp_path, content):
    path = tmp_path.resolve() / "resume"
    path.write_bytes(content)

    with pytest.raises(ConfigurationError, match="does not contain a valid sequence"):
        cli._read_resume(path)


@pytest.mark.parametrize("value", [-1, MAX_SEQUENCE + 1])
def test_resume_sequence_must_be_in_range(tmp_path, value):
    path = tmp_path.resolve() / "resume"
    path.write_text(f"{value}\n", encoding="ascii")

    with pytest.raises(ConfigurationError, match="outside the supported range"):
        cli._read_resume(path)


# --- Health body --------------------------------------------------------------


def test_health_body_is_read_in_bounded_chunks():
    body = b"x" * (cli.MAX_HEALTH_RESPONSE_BYTES + 500)

    read = cli._read_health_body(io.BytesIO(body), time.monotonic() + 30)

    assert read == body[: cli.MAX_HEALTH_RESPONSE_BYTES + 1]


def test_health_body_read_applies_the_remaining_deadline_to_the_socket(monkeypatch):
    timeouts = []
    response = io.BytesIO(b'{"status":"ok"}')
    response.fp = SimpleNamespace(
        raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=timeouts.append)),
    )
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: 1000.0))

    assert cli._read_health_body(response, 1002.5) == b'{"status":"ok"}'
    assert timeouts == [2.5, 2.5]

    with pytest.raises(cli._NetworkFailure, match="health request timed out"):
        cli._read_health_body(io.BytesIO(b"{}"), 1000.0)
