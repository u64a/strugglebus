from __future__ import annotations

import base64
import hashlib
import html
import io
import json
import re
import shutil
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from operator_test_support import operator_client
from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.ca import MAX_BUNDLE_BYTES, fingerprint_display, load_trust_anchor
from strugglebus.config import AppConfig
from strugglebus.dashboard import render_onboarding_package
from strugglebus.errors import ConfigurationError, TrustAnchorError
from strugglebus.integration import build_server_info
from strugglebus.store import SQLiteStore


def _digest(pem: bytes) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))).hexdigest()


@pytest.fixture(scope="module")
def chain(tmp_path_factory):
    executable = shutil.which("openssl")
    if executable is None:
        pytest.skip("openssl is required for real certificate tests")
    directory = tmp_path_factory.mktemp("lan-ca")

    def openssl(*arguments):
        return subprocess.run(  # nosec B603
            [executable, *map(str, arguments)], cwd=directory,
            check=True, capture_output=True,
        )

    (directory / "index.txt").write_text("", encoding="ascii")
    (directory / "serial").write_text("1000\n", encoding="ascii")
    (directory / "ca.cnf").write_text(
        "[ca]\ndefault_ca=test_ca\n"
        "[test_ca]\ndatabase=index.txt\nserial=serial\nnew_certs_dir=.\n"
        "default_md=sha256\npolicy=common_name\nunique_subject=no\n"
        "[common_name]\ncommonName=supplied\n"
        "[ca_extensions]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "[leaf_extensions]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:bus.test\n",
        encoding="ascii",
    )
    # Backdate fixtures, not verification, so host/WSL clock corrections cannot
    # make a freshly generated certificate transiently not-yet-valid.
    now = datetime.now(UTC)
    start = (now - timedelta(days=1)).strftime("%y%m%d%H%M%SZ")
    end = (now + timedelta(days=2)).strftime("%y%m%d%H%M%SZ")
    for name, issuer in (
        ("root", "root"), ("other-root", "other-root"),
        ("intermediate", "root"), ("leaf", "intermediate"),
    ):
        openssl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", f"{name}.key", "-out", f"{name}.csr",
            "-subj", f"/CN={name}",
        )
        issuer_certificate = f"{issuer}.crt"
        if issuer == name:
            issuer_certificate = f"{name}-bootstrap.crt"
            openssl(
                "req", "-x509", "-key", f"{name}.key", "-in", f"{name}.csr",
                "-out", issuer_certificate, "-days", "2",
                "-addext", "basicConstraints=critical,CA:TRUE",
            )
        openssl(
            "ca", "-batch", "-notext", "-config", "ca.cnf",
            "-cert", issuer_certificate, "-keyfile", f"{issuer}.key",
            "-in", f"{name}.csr", "-out", f"{name}.crt",
            "-startdate", start, "-enddate", end,
            "-extensions", "leaf_extensions" if name == "leaf" else "ca_extensions",
            *(["-selfsign"] if issuer == name else []),
        )
    for certificate in directory.glob("*.crt"):
        certificate.write_bytes(certificate.read_bytes().replace(b"\r\n", b"\n"))
    return directory


@pytest.fixture
def bundle(tmp_path: Path, chain: Path) -> Path:
    path = tmp_path / "ca-bundle.pem"
    path.write_bytes(
        (chain / "intermediate.crt").read_bytes() + (chain / "root.crt").read_bytes()
    )
    return path


def _client(config: AppConfig):
    service = AgentService(
        SQLiteStore(
            config.database_path,
            backup_dir=config.backup_dir,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
        )
    )
    return operator_client(create_app(config=config, agent_service=service))


def _configured(config: AppConfig, bundle: Path, chain: Path) -> AppConfig:
    return replace(
        config, ca_bundle_path=str(bundle),
        ca_root_sha256=_digest((chain / "root.crt").read_bytes()),
    )


def test_selects_and_canonicalizes_only_the_declared_anchor(bundle: Path, chain: Path):
    root = (chain / "root.crt").read_bytes()
    anchor = load_trust_anchor(str(bundle), _digest(root))
    assert anchor == root
    # Input formatting must not be interpolated into the generated package.
    bundle.write_bytes(root.replace(b"\n", b"\r\n\t"))
    assert load_trust_anchor(str(bundle), _digest(root)) == root
    intermediate = (chain / "intermediate.crt").read_bytes()
    bundle.write_bytes(intermediate + root)
    assert load_trust_anchor(str(bundle), _digest(intermediate)) == intermediate


def test_unknown_digest_is_an_explicit_publication_error(bundle: Path):
    with pytest.raises(TrustAnchorError):
        load_trust_anchor(str(bundle), "a" * 64)


@pytest.mark.parametrize(
    ("path", "digest"),
    [
        ("", "a" * 64), ("/absent", ""), ("relative/path.pem", "a" * 64),
        ("/absent/ca.pem", "a" * 64), ("/absent/ca.pem", "not-a-digest"),
        ("/absent/ca.pem", "A" * 64),
    ],
)
def test_unusable_configuration_never_looks_like_manual_mode(path: str, digest: str):
    with pytest.raises(TrustAnchorError):
        load_trust_anchor(path, digest)


def test_private_keys_and_fake_der_are_not_certificates(tmp_path: Path):
    path = tmp_path / "invalid.pem"
    path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n")
    with pytest.raises(TrustAnchorError):
        load_trust_anchor(str(path), "a" * 64)
    der = b"not-an-x509-certificate"
    path.write_bytes(ssl.DER_cert_to_PEM_cert(der).encode("ascii"))
    with pytest.raises(TrustAnchorError):
        load_trust_anchor(str(path), hashlib.sha256(der).hexdigest())


def test_leaf_is_not_published_as_a_ca(chain: Path):
    leaf = chain / "leaf.crt"
    with pytest.raises(TrustAnchorError):
        load_trust_anchor(str(leaf), _digest(leaf.read_bytes()))


@pytest.mark.parametrize("offset", [-3 * 86400, 3 * 86400])
def test_ca_outside_its_validity_window_is_a_publication_error(
    bundle: Path, chain: Path, monkeypatch: pytest.MonkeyPatch, offset: int,
):
    now = time.time()
    monkeypatch.setattr("strugglebus.ca.time.time", lambda: now + offset)
    with pytest.raises(TrustAnchorError):
        load_trust_anchor(str(bundle), _digest((chain / "root.crt").read_bytes()))


def test_symlinked_bundle_is_refused(tmp_path: Path, bundle: Path, chain: Path):
    link = tmp_path / "linked.pem"
    try:
        link.symlink_to(bundle)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable in this environment")
    with pytest.raises(TrustAnchorError):
        load_trust_anchor(str(link), _digest((chain / "root.crt").read_bytes()))


def test_actual_read_is_bounded_not_only_stat_size(
    bundle: Path, chain: Path, monkeypatch: pytest.MonkeyPatch
):
    root = (chain / "root.crt").read_bytes()
    huge = root + b"#" * MAX_BUNDLE_BYTES
    requested = []

    class BoundedFile(io.BytesIO):
        def read(self, size=-1):
            requested.append(size)
            assert size == MAX_BUNDLE_BYTES + 1
            return super().read(size)

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: BoundedFile(huge))
    with pytest.raises(TrustAnchorError):
        load_trust_anchor(str(bundle), _digest(root))
    assert requested == [MAX_BUNDLE_BYTES + 1]


def test_unreadable_bundle_error_is_sanitized(
    bundle: Path, chain: Path, monkeypatch: pytest.MonkeyPatch
):
    digest = _digest((chain / "root.crt").read_bytes())

    def unreadable(*args, **kwargs):
        raise PermissionError("private-path-and-secret-sentinel")

    monkeypatch.setattr(Path, "open", unreadable)
    with pytest.raises(TrustAnchorError) as error:
        load_trust_anchor(str(bundle), digest)
    assert "sentinel" not in str(error.value)
    assert str(bundle) not in str(error.value)


def test_fingerprint_display_matches_openssl_style(chain: Path):
    digest = _digest((chain / "root.crt").read_bytes())
    shown = fingerprint_display(digest)
    assert shown.count(":") == 31
    assert shown.replace(":", "").lower() == digest


def _package_root(package: str) -> bytes:
    text = html.unescape(package)
    encoded = text.split("CA PEM base64: ", 1)[1].splitlines()[0]
    return base64.b64decode(encoded, validate=True)


def test_download_and_package_embed_only_the_public_root(
    app_config: AppConfig, bundle: Path, chain: Path
):
    configured = _configured(app_config, bundle, chain)
    with _client(configured) as client:
        download = client.get("/ca-root.crt")
        assert download.status_code == 200
        assert download.content == (chain / "root.crt").read_bytes()
        assert "attachment" in download.headers["Content-Disposition"]
        assert download.headers["Cache-Control"] == "no-store"
        assert download.headers["Referrer-Policy"] == "no-referrer"
        package = client.register("review-reader")
        assert package.status_code == 201
        assert _package_root(package.text) == download.content
        assert fingerprint_display(configured.ca_root_sha256) in package.text
        assert "curl -k" not in package.text
        assert "--insecure" not in package.text
        assert "must match CA SHA-256" in package.text
        assert "PRIVATE KEY" not in package.text
        assert base64.b64encode((chain / "intermediate.crt").read_bytes()).decode() not in package.text


def test_unconfigured_anchor_explicitly_supports_manual_handoff(app_config: AppConfig):
    assert load_trust_anchor("", "") is None
    with _client(app_config) as client:
        assert client.get("/ca-root.crt").status_code == 404
        package = client.register("review-reader")
        assert package.status_code == 201
        assert "/ca-root.crt" not in package.text
        assert "No CA root is published" in package.text
        assert "Get ca-root.crt from your" in package.text
        assert "CA PEM base64:" not in package.text


@pytest.mark.parametrize("failure", ["missing", "mismatch", "invalid", "invalid-date"])
def test_configured_failure_is_visible_before_any_token_is_minted(
    app_config: AppConfig, bundle: Path, chain: Path,
    monkeypatch: pytest.MonkeyPatch, failure: str,
):
    configured = _configured(app_config, bundle, chain)
    if failure == "missing":
        bundle.unlink()
    elif failure == "mismatch":
        configured = replace(configured, ca_root_sha256="f" * 64)
    elif failure == "invalid":
        der = b"invalid-x509"
        bundle.write_bytes(ssl.DER_cert_to_PEM_cert(der).encode())
        configured = replace(configured, ca_root_sha256=hashlib.sha256(der).hexdigest())
    else:
        der = ssl.PEM_cert_to_DER_cert((chain / "root.crt").read_text())
        timestamp = re.search(rb"[0-9]{12}Z", der)
        assert timestamp is not None
        month = timestamp.start() + 2
        der = der[:month] + b"13" + der[month + 2:]
        bundle.write_bytes(ssl.DER_cert_to_PEM_cert(der).encode("ascii"))
        configured = replace(configured, ca_root_sha256=hashlib.sha256(der).hexdigest())

    def must_not_mint():
        pytest.fail("configured trust must be validated before token generation")

    monkeypatch.setattr("strugglebus.auth.mint_enrollment_token", must_not_mint)
    with _client(configured) as client:
        for response in (
            client.get("/ca-root.crt"),
            client.register("review-reader"),
        ):
            assert response.status_code == 503
            assert "Configured LAN CA publication is unavailable" in response.text
            assert str(bundle) not in response.text
            assert "sbe1_" not in response.text
        assert not client.app.state.agent_service.list_enrollments()


def test_anchor_download_survives_a_freeze(
    app_config: AppConfig, bundle: Path, chain: Path
):
    """The public root is trust material, not access.

    A freeze stops the agent plane. Handing the operator a public certificate
    grants nobody anything, and the operator may well need it mid-incident to
    verify what they are connecting to.
    """

    with _client(_configured(app_config, bundle, chain)) as client:
        assert client.get("/ca-root.crt").status_code == 200
        client.app.state.access_freeze_service.freeze("incident drill")
        assert client.get("/ca-root.crt").status_code == 200


@pytest.mark.parametrize(
    ("path", "digest"),
    [("relative/ca.pem", "a" * 64), ("", "a" * 64),
     ("", "not-a-digest"), ("", "A" * 64)],
)
def test_invalid_or_partial_configuration_is_refused(app_config, path, digest):
    with pytest.raises(ConfigurationError):
        replace(app_config, ca_bundle_path=path, ca_root_sha256=digest)


def test_path_without_digest_is_refused(app_config, tmp_path):
    with pytest.raises(ConfigurationError, match="both"):
        replace(app_config, ca_bundle_path=str(tmp_path / "ca.pem"))


@pytest.mark.parametrize("case", ["valid", "wrong-host", "wrong-root", "missing-intermediate"])
def test_package_root_verifies_real_tls_chain_and_hostname(
    app_config: AppConfig, bundle: Path, chain: Path, tmp_path: Path, case: str,
):
    with _client(_configured(app_config, bundle, chain)) as client:
        package = client.register("review-reader")
        assert package.status_code == 201
        root = _package_root(package.text)
    published = tmp_path / "package-root.crt"
    published.write_bytes(root)
    server_chain = tmp_path / "server-chain.crt"
    server_chain.write_bytes(
        (chain / "leaf.crt").read_bytes()
        + (b"" if case == "missing-intermediate" else (chain / "intermediate.crt").read_bytes())
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(server_chain, chain / "leaf.key")
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(
        cafile=(chain / "other-root.crt") if case == "wrong-root" else published
    )
    hostname = "different.test" if case == "wrong-host" else "bus.test"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)

        def serve():
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                try:
                    with server_context.wrap_socket(connection, server_side=True) as secured:
                        secured.sendall(b"verified")
                except (ssl.SSLError, ConnectionResetError):
                    if case == "valid":
                        raise

        with ThreadPoolExecutor(max_workers=1) as executor:
            serving = executor.submit(serve)
            with socket.create_connection(listener.getsockname(), timeout=5) as connection:
                if case == "valid":
                    with client_context.wrap_socket(connection, server_hostname=hostname) as secured:
                        assert secured.recv(8) == b"verified"
                else:
                    with pytest.raises(ssl.SSLCertVerificationError):
                        client_context.wrap_socket(connection, server_hostname=hostname)
            serving.result(timeout=5)


_SHELLS = {"powershell": "pwsh", "windows-powershell": "powershell", "linux": "bash"}


@pytest.mark.parametrize("platform", ["powershell", "windows-powershell", "linux"])
def test_package_root_save_recipe_round_trips_with_real_tooling(
    app_config: AppConfig, bundle: Path, chain: Path, tmp_path: Path, platform: str,
):
    executable = shutil.which(_SHELLS[platform])
    if executable is None:
        pytest.skip(f"{platform} is unavailable")
    configured = _configured(app_config, bundle, chain)
    with _client(configured) as client:
        text = html.unescape(client.register("review-reader").text)
    selected = tmp_path / "selected private directory"
    selected.mkdir()
    if platform != "linux":
        recipe = text.split("Windows PowerShell (", 1)[1].split("\n", 1)[1]
        # Everything up to the request body: save the root, print its
        # fingerprint. No openssl is stubbed, because stock Windows has none.
        line = "Set-Location -LiteralPath 'selected private directory'\n" + recipe.split(
            "$body =", 1
        )[0]
        assert "openssl" not in line
    else:
        line = "cd 'selected private directory'\n" + next(
            line for line in text.splitlines() if line.startswith("printf '%s'")
        )
    command = (
        [executable, "-NoProfile", "-NonInteractive", "-Command", line]
        if platform != "linux" else [executable, "-c", line]
    )
    result = subprocess.run(command, cwd=tmp_path, capture_output=True)  # nosec B603
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert (selected / "ca-root.crt").read_bytes() == _package_root(text)
    assert not (tmp_path / "ca-root.crt").exists()
    if platform != "linux":
        # The printed line is what the agent compares with CA SHA-256 in the
        # package, in the form the Linux recipe's openssl prints.
        expected = fingerprint_display(configured.ca_root_sha256)
        assert f"CA SHA-256  : {expected}" in text
        assert result.stdout.decode(errors="replace").split() == [
            "sha256", f"Fingerprint={expected}",
        ]


def test_windows_recipe_stops_before_redeeming_without_a_root(
    app_config: AppConfig, tmp_path: Path,
):
    """Manual handoff with no ca-root.crt saved must not spend the token."""

    executable = shutil.which("pwsh") or shutil.which("powershell")
    if executable is None:
        pytest.skip("PowerShell is unavailable")
    text = html.unescape(render_onboarding_package(
        build_server_info(app_config), generated_at=datetime.now(UTC),
        base_url="https://bus.test", agent_name="review-reader",
        token="test-enrollment", expires_at=datetime.now(UTC), enrollment_id="test",
    ))
    recipe = text.split("Windows PowerShell (", 1)[1].split("\n", 1)[1].split(
        "\n\n3.", 1
    )[0]
    prelude = "function curl.exe { Set-Content -LiteralPath redeemed.txt -Value 1 }\n"
    result = subprocess.run(  # nosec B603
        [executable, "-NoProfile", "-NonInteractive", "-Command", prelude + recipe],
        cwd=tmp_path, capture_output=True,
    )
    assert result.returncode != 0
    assert not (tmp_path / "redeemed.txt").exists()
    assert not (tmp_path / "redeem.json").exists()


@pytest.mark.parametrize("platform", ["powershell", "linux"])
def test_redemption_recipes_quote_url_and_generate_valid_json(
    app_config: AppConfig, chain: Path, tmp_path: Path, platform: str,
):
    executable = shutil.which("pwsh" if platform == "powershell" else "bash")
    if executable is None:
        pytest.skip(f"{platform} is unavailable")
    hostile_url = "https://bus.test'; touch OWNED; echo '"
    text = html.unescape(render_onboarding_package(
        build_server_info(app_config), generated_at=datetime.now(UTC),
        base_url=hostile_url, agent_name="review-reader", token="test-enrollment",
        expires_at=datetime.now(UTC), enrollment_id="test",
    ))
    selected = tmp_path / "selected private directory"
    selected.mkdir()
    # No root is published here, so the operator's manual handoff supplies it.
    shutil.copyfile(chain / "root.crt", selected / "ca-root.crt")
    if platform == "powershell":
        recipe = text.split("Windows PowerShell (", 1)[1].split("\n", 1)[1].split(
            "\n\n3.", 1
        )[0]
        # Test the literal command arguments without sending a network request.
        prelude = (
            "Set-Location -LiteralPath 'selected private directory'\n"
            "function curl.exe { $args | ConvertTo-Json | Set-Content args.json }\n"
        )
        command = [executable, "-NoProfile", "-NonInteractive", "-Command", prelude + recipe]
    else:
        recipe = text.split("Linux shell (", 1)[1].split("\n", 1)[1].split(
            "\n\nWindows PowerShell", 1
        )[0]
        prelude = (
            "cd 'selected private directory'\n"
            'openssl() { if [ "$1" = rand ]; then command openssl "$@"; fi; }\n'
            'curl() { printf "%s\\n" "$@" > args.txt; }\n'
        )
        command = [executable, "-c", prelude + recipe]
    result = subprocess.run(command, cwd=tmp_path, capture_output=True)  # nosec B603
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    payload = json.loads((selected / "redeem.json").read_text(encoding="utf-8"))
    assert payload["name"] == "review-reader"
    from uuid import UUID
    assert str(UUID(payload["request_id"])) == payload["request_id"]
    arguments = (
        json.loads((selected / "args.json").read_text(encoding="utf-8-sig"))
        if platform == "powershell"
        else (selected / "args.txt").read_text().splitlines()
    )
    assert arguments[arguments.index("--url") + 1] == hostile_url + "/api/enrollments/redeem"
    assert arguments[arguments.index("--header") + 1] == "Authorization: Bearer test-enrollment"
    assert not (selected / "OWNED").exists()
    assert not (tmp_path / "redeem.json").exists()
    if platform == "powershell":
        assert Path(arguments[arguments.index("--cacert") + 1]) == selected / "ca-root.crt"
        assert arguments[arguments.index("--data-binary") + 1] == "@" + str(selected / "redeem.json")
        assert Path(arguments[arguments.index("--output") + 1]) == selected / "credential-response.json"


def test_root_and_setup_link_are_offered_before_anyone_can_sign_in(
    app_config: AppConfig, bundle: Path, chain: Path
):
    """A PC needs the public root before its browser trusts the bus at all."""

    from fastapi.testclient import TestClient

    from strugglebus.app import create_app

    with TestClient(
        create_app(config=_configured(app_config, bundle, chain)),
        base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        download = client.get("/ca-root.crt")
        assert download.status_code == 200
        assert download.content == (chain / "root.crt").read_bytes()
        setup = client.get("/setup")
        assert setup.status_code == 200
        assert 'href="/ca-root.crt"' in setup.text
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        assert client.get("/ca-root.crt").status_code == 404
        assert 'href="/ca-root.crt"' not in client.get("/setup").text
