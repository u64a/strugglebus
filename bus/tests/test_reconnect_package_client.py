import hashlib
import io
import json
import secrets
import ssl
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.request import Request
from uuid import uuid4

import pytest

from test_ca_anchor import chain
from strugglebus.auth import parse_credential
from strugglebus.cli import main
from strugglebus.config import AppConfig
from strugglebus.errors import ConfigurationError
from strugglebus.reconnect import (
    MAX_PACKAGE_BYTES,
    NoRedirectHandler,
    ReconnectError,
    _exchange,
    decode_package,
    encode_package,
    redeem_package,
)


@pytest.fixture
def package_data(chain):
    ca = (chain / "root.crt").read_bytes()
    return {
        "agent_id": str(uuid4()), "agent_name": "synthetic-recipient",
        "base_url": "https://bus.test", "ca_root": ca,
        "ca_sha256": hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(ca.decode("ascii"))
        ).hexdigest(),
        "expires_at": datetime.now(UTC) + timedelta(seconds=800),
        "grant": f"sbr1_{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}",
    }


@pytest.fixture
def package_file(tmp_path, package_data):
    tmp_path.chmod(0o700)
    path = tmp_path / "private-package.json"
    path.write_bytes(encode_package(**package_data))
    path.chmod(0o600)
    return path


def response_bytes(package_data, *, agent_name=None):
    secret = f"sb1_{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"
    parsed = parse_credential(secret)
    assert parsed is not None
    return json.dumps({
        "agent": {
            "id": package_data["agent_id"],
            "name": package_data["agent_name"] if agent_name is None else agent_name,
        },
        "credential": {
            "id": parsed[1], "agent_id": package_data["agent_id"],
            "kind": "sb1", "status": "pending",
        },
        "credential_secret": secret,
    }).encode("ascii"), secret


def test_package_is_bounded_versioned_private_and_exact_id(package_data):
    raw = encode_package(**package_data)
    package = decode_package(raw)
    assert package.agent_id == package_data["agent_id"]
    assert package_data["grant"] not in repr(package)
    assert len(raw) < MAX_PACKAGE_BYTES
    payload = json.loads(raw)
    for key, bad in (
        ("version", True), ("version", 2), ("agent_id", "../identity"),
        ("base_url", "http://bus.test"), ("base_url", "https://user@bus.test"),
        ("base_url", "https://bus.test/?query=secret"), ("ca_sha256", "0" * 64),
        ("agent_name", "UNTRUSTED NAME"), ("grant", "sb1_wrong"),
        ("expires_at", (datetime.now(UTC) - timedelta(seconds=1)).isoformat()),
    ):
        with pytest.raises(ConfigurationError):
            decode_package(json.dumps({**payload, key: bad}).encode("ascii"))
    with pytest.raises(ConfigurationError):
        decode_package(b" " * (MAX_PACKAGE_BYTES + 1))
    with pytest.raises(ConfigurationError):
        decode_package(raw[:-1] + b',"version":1}')


def test_client_reserves_output_before_redemption_and_saves_pending_key(
    package_file, package_data, tmp_path,
):
    output = tmp_path / "private-key"
    raw_response, secret = response_bytes(package_data)
    calls = []

    def exchange(request, context):
        assert output.exists()
        assert output.read_bytes() == b""
        assert request.full_url == "https://bus.test/api/reconnect/redeem"
        payload = json.loads(request.data)
        assert payload["expected_agent_id"] == package_data["agent_id"]
        assert payload["expected_agent_name"] == package_data["agent_name"]
        assert context.check_hostname
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert len(context.get_ca_certs()) == 1
        calls.append(request.method)
        return raw_response

    result = redeem_package(package_file, output, exchange=exchange)
    assert result.agent_id == package_data["agent_id"]
    assert output.read_bytes() == secret.encode("ascii") + b"\n"
    assert calls == ["POST"]
    assert secret != package_data["grant"]


def test_preexisting_output_causes_zero_redemption(package_file, tmp_path):
    output = tmp_path / "existing"
    output.write_bytes(b"do not overwrite")
    output.chmod(0o600)

    def exchange(*args):
        raise AssertionError("preflight failure contacted server")

    with pytest.raises(ConfigurationError):
        redeem_package(package_file, output, exchange=exchange)
    assert output.read_bytes() == b"do not overwrite"


@pytest.mark.parametrize("failure", ["lost-response", "wrong-identity", "malformed"])
def test_ambiguous_results_require_reissue_without_retry_or_partial_output(
    package_file, package_data, tmp_path, failure,
):
    output = tmp_path / "new-key"
    calls = []

    def exchange(*args):
        calls.append("request")
        if failure == "lost-response":
            raise OSError("synthetic lost response")
        if failure == "wrong-identity":
            return response_bytes(package_data, agent_name="foreign-identity")[0]
        return b"not-json"

    with pytest.raises(ReconnectError, match="operator reissue"):
        redeem_package(package_file, output, exchange=exchange)
    assert calls == ["request"]
    assert not output.exists()


def test_recipient_cli_does_not_load_server_configuration(
    monkeypatch, package_file, package_data, tmp_path,
):
    def no_config(*args, **kwargs):
        raise AssertionError("recipient attempted to read server configuration")

    package = decode_package(encode_package(**package_data))
    monkeypatch.setattr(AppConfig, "from_env", no_config)
    monkeypatch.setattr("strugglebus.reconnect.redeem_package", lambda *args: package)
    stdout = io.StringIO()
    stderr = io.StringIO()
    assert main([
        "reconnect", "redeem", "--package-file", str(package_file),
        "--credential-output", str(tmp_path / "private-key"),
    ], stdout=stdout, stderr=stderr) == 0
    assert json.loads(stdout.getvalue())["bootstrap_complete"] is False
    assert package.grant not in stdout.getvalue() + stderr.getvalue()


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (401, "grant_rejected"),
        (409, "state_changed"),
        (415, "media_type_rejected"),
        (429, "rate_limited"),
        (503, "access_unavailable"),
    ],
)
def test_http_rejections_are_definite_and_sanitized(monkeypatch, status, reason):
    class Opener:
        def open(self, request, timeout):
            del request, timeout
            raise HTTPError(
                "https://bus.test/api/reconnect/redeem",
                status,
                "untrusted upstream detail",
                {},
                io.BytesIO(b'{"detail":"untrusted response body"}'),
            )

    monkeypatch.setattr("strugglebus.reconnect.build_opener", lambda *args: Opener())
    with pytest.raises(ReconnectError) as caught:
        _exchange(Request("https://bus.test/api/reconnect/redeem"), ssl.create_default_context())
    assert caught.value.outcome == "rejected"
    assert caught.value.http_status == status
    assert reason in str(caught.value)
    assert "untrusted" not in str(caught.value)
    assert "do not retry" in str(caught.value)


def test_server_error_remains_ambiguous_and_sanitized(monkeypatch):
    class Opener:
        def open(self, request, timeout):
            del request, timeout
            raise HTTPError(
                "https://bus.test/api/reconnect/redeem",
                502,
                "untrusted proxy detail",
                {},
                io.BytesIO(b"untrusted response body"),
            )

    monkeypatch.setattr("strugglebus.reconnect.build_opener", lambda *args: Opener())
    with pytest.raises(ReconnectError) as caught:
        _exchange(Request("https://bus.test/api/reconnect/redeem"), ssl.create_default_context())
    assert caught.value.outcome == "unknown"
    assert caught.value.http_status == 502
    assert "result is uncertain" in str(caught.value)
    assert "untrusted" not in str(caught.value)


def test_redirect_handler_never_forwards_credentials():
    assert NoRedirectHandler().redirect_request(
        None, None, 307, None, None, "https://foreign.invalid",
    ) is None
