"""The satellite: a local proxy that carries agent traffic to the bus.

Agents on a remote machine talk plain HTTP to 127.0.0.1. Each connection is
forwarded, byte for byte, over TLS to the gateway, presenting this site's
certificate and trusting only the site CA from its bundle. It never parses
HTTP, so REST, MCP and SSE behave exactly as they do on the LAN. The same
process renews the site certificate and follows the bus's own release.
"""

from __future__ import annotations

import asyncio
import getpass
import hashlib
import json
import os
import platform
import shutil
import ssl
# Fixed argv only: uv, schtasks. Nothing untrusted reaches a command line.
import subprocess  # nosec B404
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from strugglebus import __version__
from strugglebus.errors import ConfigurationError
from strugglebus.satellite import encode_join_request, parse_site_bundle

DEFAULT_PORT = 8765
RENEW_WITHIN = timedelta(days=10)
CHECK_SECONDS = 3600
#: Exit status after installing an update, so the supervising loop restarts
#: into the new version.
UPDATED_EXIT = 75
TASK_NAME = "Strugglebus Satellite"


def state_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "Strugglebus" / "satellite"
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "strugglebus" / "satellite"


def _write_private(path: Path, data: bytes) -> None:
    """Write a 0600 file atomically. The per-user directory is 0700."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _new_key(directory: Path) -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Generate the next site key beside the current one and its join request."""

    key = ec.generate_private_key(ec.SECP256R1())
    _write_private(
        directory / "key.pending.pem",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "satellite")]))
        .sign(key, hashes.SHA256())
    )
    return key, encode_join_request(csr)


def accept_bundle(directory: Path, text: str) -> dict[str, object]:
    """Install a bundle issued for the pending key, then make that key current."""

    bundle = parse_site_bundle(text)
    pending = directory / "key.pending.pem"
    try:
        key = serialization.load_pem_private_key(pending.read_bytes(), password=None)
        certificate = x509.load_pem_x509_certificate(str(bundle["cert_pem"]).encode("ascii"))
        x509.load_pem_x509_certificate(str(bundle["ca_pem"]).encode("ascii"))
    except (OSError, ValueError):
        raise ConfigurationError("the bundle does not match a waiting join request") from None
    if certificate.public_key() != key.public_key():
        raise ConfigurationError("the bundle was issued for a different join request")
    _write_private(directory / "cert.pem", str(bundle["cert_pem"]).encode("ascii"))
    _write_private(directory / "ca.pem", str(bundle["ca_pem"]).encode("ascii"))
    _write_private(directory / "bundle.json", json.dumps(bundle).encode("ascii"))
    os.replace(pending, directory / "key.pem")
    return bundle


def load_site(directory: Path) -> dict[str, object]:
    try:
        return json.loads((directory / "bundle.json").read_text(encoding="ascii"))
    except (OSError, ValueError):
        raise ConfigurationError(
            "this machine has not joined; run: strugglebus satellite join"
        ) from None


def tls_context(directory: Path) -> ssl.SSLContext:
    """Trust only the site CA, check the gateway name, and present our certificate."""

    context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(directory / "cert.pem"), str(directory / "key.pem"))
    return context


def _expires(site: dict[str, object]) -> datetime:
    return datetime.fromisoformat(str(site["expires_at"]))


def _client(directory: Path, site: dict[str, object]) -> httpx.Client:
    return httpx.Client(
        base_url=f"https://{site['hostname']}:{site['port']}",
        verify=tls_context(directory),
        timeout=60,
    )


def renew(directory: Path) -> dict[str, object]:
    """Renew onto a fresh key. The old certificate stops working at once."""

    site = load_site(directory)
    _, join_request = _new_key(directory)
    with _client(directory, site) as client:
        response = client.post("/api/satellite/renew", json={"join_request": join_request})
    if response.status_code != 200:
        raise ConfigurationError(f"renewal was refused ({response.status_code})")
    return accept_bundle(directory, response.json()["bundle"])


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def update(directory: Path, *, uv: str | None = None) -> bool:
    """Install the bus's release when it differs. True means restart now."""

    site = load_site(directory)
    with _client(directory, site) as client:
        manifest = client.get("/api/satellite/release")
        if manifest.status_code != 200:
            return False
        release = manifest.json()
        if release.get("version") == __version__:
            return False
        uv = uv or shutil.which("uv")
        if uv is None:
            print("satellite: an update is available but uv is not on PATH", file=sys.stderr)
            return False
        with tempfile.TemporaryDirectory() as scratch:
            wheel = Path(scratch) / Path(str(release["wheel"]["name"])).name
            lock = Path(scratch) / "requirements.lock"
            for path, route, expected in (
                (wheel, "/api/satellite/release/wheel", release["wheel"]["sha256"]),
                (lock, "/api/satellite/release/requirements-lock",
                 release["requirements_lock"]["sha256"]),
            ):
                with client.stream("GET", route) as download, path.open("wb") as stream:
                    if download.status_code != 200:
                        return False
                    for chunk in download.iter_bytes():
                        stream.write(chunk)
                if _sha256(path) != expected:
                    print("satellite: a downloaded release file failed its check", file=sys.stderr)
                    return False
            result = subprocess.run(  # nosec B603
                [uv, "tool", "install", "--force", "--constraints", str(lock), str(wheel)],
                check=False,
            )
    return result.returncode == 0


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError, ssl.SSLError):
        pass
    finally:
        writer.close()


class Satellite:
    def __init__(self, directory: Path, port: int) -> None:
        self.directory = directory
        self.port = port
        self.site = load_site(directory)
        self.context = tls_context(directory)

    async def _connection(
        self, local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter,
    ) -> None:
        hostname = str(self.site["hostname"])
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    hostname, int(self.site["port"]),
                    ssl=self.context, server_hostname=hostname,
                ),
                timeout=20,
            )
        except (OSError, ssl.SSLError, TimeoutError) as error:
            print(f"satellite: gateway unavailable: {type(error).__name__}", file=sys.stderr)
            local_writer.close()
            return
        await asyncio.gather(
            _pipe(local_reader, remote_writer), _pipe(remote_reader, local_writer),
        )

    def _maintain(self) -> bool:
        if _expires(self.site) - datetime.now(UTC) < RENEW_WITHIN:
            self.site = renew(self.directory)
            self.context = tls_context(self.directory)
            print(f"satellite: renewed until {self.site['expires_at']}", file=sys.stderr)
        return update(self.directory)

    async def serve(self, *, check_seconds: int = CHECK_SECONDS) -> int:
        server = await asyncio.start_server(self._connection, "127.0.0.1", self.port)
        print(f"satellite: listening on 127.0.0.1:{self.port}", file=sys.stderr)
        async with server:
            while True:
                try:
                    if await asyncio.to_thread(self._maintain):
                        print("satellite: updated; restarting", file=sys.stderr)
                        return UPDATED_EXIT
                except (ConfigurationError, httpx.HTTPError, OSError, ValueError, KeyError) as error:
                    print(f"satellite: maintenance deferred: {error}", file=sys.stderr)
                await asyncio.sleep(check_seconds)


def join(directory: Path, *, read=input) -> dict[str, object]:
    _, join_request = _new_key(directory)
    print("Paste this join request into Satellite sites > Add a site on the bus:\n")
    print(join_request)
    print("\nThen paste the site bundle it returns, and press Enter:")
    bundle = accept_bundle(directory, read())
    print(f"Joined as {bundle['site']}. Certificate valid until {bundle['expires_at']}.")
    return bundle


def install_task(directory: Path, port: int) -> str:
    """Start the satellite at logon, restarting it whenever it exits."""

    program = shutil.which("strugglebus") or str(Path(sys.argv[0]).resolve())
    if os.name != "nt":
        unit = (
            "[Unit]\nDescription=Strugglebus satellite\n\n[Service]\n"
            f"ExecStart={program} satellite run --port {port}\n"
            "Restart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n"
        )
        print("Save as ~/.config/systemd/user/strugglebus-satellite.service, then run")
        print("  systemctl --user enable --now strugglebus-satellite\n")
        print(unit)
        return unit
    script = directory / "run.ps1"
    _write_private(
        script,
        (
            "while ($true) {\r\n"
            f"  & '{program}' satellite run --port {port}\r\n"
            "  Start-Sleep -Seconds 5\r\n"
            "}\r\n"
        ).encode("utf-8"),
    )
    command = (
        f'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{script}"'
    )
    result = subprocess.run(  # nosec B603 B607
        ["schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED",
         "/TN", TASK_NAME, "/TR", command],
        capture_output=True, text=True, check=False,
    )
    if result.returncode == 0:
        print(f"Registered the '{TASK_NAME}' logon task. It starts at your next logon;")
        print(f"to start it now, run: schtasks /Run /TN \"{TASK_NAME}\"")
        return command
    # Creating logon tasks can need elevation on managed machines; the user's
    # Startup folder needs none.
    startup = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup"
    launcher = startup / "strugglebus-satellite.cmd"
    launcher.write_text(f"@start \"\" /min {command}\r\n", encoding="ascii")
    print(f"Could not register a logon task; added {launcher} instead.")
    return command


def link_agent(
    name: str,
    *,
    port: int,
    token: str | None = None,
    description: str = "",
    write: Path | None = None,
) -> dict[str, object]:
    """Redeem an exact-name enrollment through the local proxy; emit MCP config."""

    token = token or getpass.getpass("Enrollment token from the bus's /register page: ")
    base = f"http://127.0.0.1:{port}"
    response = httpx.post(
        f"{base}/api/enrollments/redeem",
        headers={"Authorization": f"Bearer {token.strip()}"},
        json={
            "request_id": str(uuid.uuid4()),
            "name": name,
            "description": description,
            "host": platform.node()[:255],
        },
        timeout=30,
    )
    if response.status_code != 201:
        raise ConfigurationError(
            f"enrollment was refused ({response.status_code}): "
            f"{response.json().get('detail', '') if response.content else ''}"
        )
    redeemed = response.json()
    config = {
        "mcpServers": {
            "strugglebus": {
                "type": "http",
                "url": f"{base}/mcp",
                "headers": {"Authorization": f"Bearer {redeemed['credential_secret']}"},
            }
        }
    }
    text = json.dumps(config, indent=2)
    if write is not None:
        _write_private(write, text.encode("utf-8"))
        print(f"Wrote the MCP configuration for {name} to {write}.")
    else:
        print(text)
    print(
        f"\n{name} has a pending credential (agent id {redeemed['agent']['id']}). "
        "Its first session must follow the bus orientation: prove the credential "
        "and acknowledge the rules of engagement."
    )
    return config
