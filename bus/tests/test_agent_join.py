"""The quick-join block in an onboarding package, run for real against a TLS bus."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from live_test_support import trusted_https_server
from strugglebus.app import create_app
from strugglebus.ca import fingerprint_display
from strugglebus.config import AppConfig
from strugglebus.dashboard import onboarding_package_text

KIT = Path(__file__).resolve().parents[1] / "src" / "strugglebus" / "selfhost" / "agent"


def _bash() -> str | None:
    if sys.platform == "win32":
        # System32\bash.exe is the WSL launcher, which sees a different disk.
        git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
        return str(git_bash) if git_bash.is_file() else None
    return shutil.which("bash")


def _shell(platform: str) -> str:
    executable = _bash() if platform == "linux" else (
        shutil.which("powershell") if sys.platform == "win32" else None
    )
    if executable is None:
        pytest.skip(f"no {platform} shell on this machine")
    return executable


def _environment(home: Path, **extra: str) -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if key not in {"STRUGGLEBUS_ENROLLMENT", "STRUGGLEBUS_HOME", "NODE_EXTRA_CA_CERTS"}
    }
    environment.update({
        "HOME": home.as_posix(), "USERPROFILE": str(home),
        "HOMEDRIVE": home.drive, "HOMEPATH": str(home)[len(home.drive):],
    })
    environment.update(extra)
    return environment


def _run(platform: str, script: str, home: Path, **extra: str):
    executable = _shell(platform)
    command = (
        [executable, "-c", "set -e\n" + script] if platform == "linux"
        else [executable, "-NoProfile", "-NonInteractive", "-Command",
              "$ErrorActionPreference = 'Stop'\n" + script]
    )
    return subprocess.run(  # nosec B603
        command, cwd=home, env=_environment(home, **extra),
        capture_output=True, text=True, timeout=120,
    )


def _block(package: str, platform: str) -> str:
    if platform == "linux":
        return package.split("Linux or macOS shell:\n", 1)[1].split(
            "\n\nWindows PowerShell:", 1
        )[0]
    return package.split("Windows PowerShell:\n", 1)[1].split("\n\nBY HAND", 1)[0]


class _Bus:
    def __init__(self, application, base_url: str, trust: ssl.SSLContext, root: bytes):
        self.application = application
        self.base_url = base_url
        self.trust = trust
        self.root = root
        self.fingerprint = fingerprint_display(
            hashlib.sha256(ssl.PEM_cert_to_DER_cert(root.decode("ascii"))).hexdigest()
        )

    def package(self, name: str) -> tuple[str, str]:
        issued = self.application.state.agent_service.create_enrollment(
            name_prefix=name, name_match="exact",
        )
        text = onboarding_package_text(
            base_url=self.base_url, agent_name=name, token=issued.token,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            ca_root=self.root, ca_fingerprint=self.fingerprint,
        )
        return text, issued.token

    def whoami(self, key: str) -> dict:
        response = httpx.get(
            self.base_url + "/api/whoami", verify=self.trust, trust_env=False,
            headers={"Authorization": "Bearer " + key}, timeout=10,
        )
        assert response.status_code == 200, response.text
        return response.json()


@pytest.fixture
def bus(app_config: AppConfig, tmp_path: Path):
    server_files = tmp_path / "server"
    server_files.mkdir()

    def application_factory(base_url: str):
        root = (server_files / "live-test.crt").read_bytes().replace(b"\r\n", b"\n")
        bundle = server_files / "ca-bundle.pem"
        bundle.write_bytes(root)
        return create_app(config=replace(
            app_config, public_base_url=base_url, ca_bundle_path=str(bundle),
            ca_root_sha256=hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(root.decode("ascii"))
            ).hexdigest(),
        ))

    with trusted_https_server(application_factory, server_files) as running:
        application, base_url, trust, _server, _thread = running
        yield _Bus(
            application, base_url, trust, (server_files / "ca-bundle.pem").read_bytes(),
        )


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_quick_join_enrolls_proves_and_writes_the_copilot_launcher(
    bus: _Bus, tmp_path: Path, platform: str,
):
    _shell(platform)
    name = f"joiner-{platform}"
    package, token = bus.package(name)
    home = tmp_path / "home"
    home.mkdir()

    result = _run(platform, _block(package, platform), home)

    assert result.returncode == 0, result.stdout + result.stderr
    folder = home / ".strugglebus" / name
    key = (folder / "agent-key").read_text(encoding="ascii")
    assert key.startswith("sb1_") and key == key.strip()
    assert token not in result.stdout + result.stderr
    assert key not in result.stdout + result.stderr
    assert "Joined the bus." in result.stdout

    record = json.loads((folder / "agent.json").read_text(encoding="utf-8"))
    assert record["agent_name"] == name and record["proved"] is True
    assert record["endpoint"] == bus.base_url
    identity = bus.whoami(key)
    assert identity["agent"]["id"] == record["agent_id"]
    assert identity["credential"]["status"] == "active"

    # The key is in exactly one file; Copilot CLI gets it from the environment.
    config = json.loads((folder / "copilot-mcp.json").read_text(encoding="utf-8"))
    server = config["mcpServers"]["bus"]
    assert server["type"] == "http" and server["url"] == bus.base_url + "/mcp"
    assert server["headers"] == {"Authorization": "Bearer ${STRUGGLEBUS_AGENT_KEY}"}
    left = sorted(path.name for path in folder.iterdir())
    launchers = ["bus-copilot"] if platform == "linux" else ["bus-copilot.cmd", "bus-copilot.ps1"]
    assert left == sorted(
        ["agent-key", "agent.json", "ca-root.crt", "copilot-mcp.json", *launchers]
    )
    for path in folder.iterdir():
        if path.name != "agent-key":
            assert key not in path.read_text(encoding="utf-8", errors="replace"), path.name

    # Running the same block again must not spend anything or change the key.
    again = _run(platform, _block(package, platform), home)
    assert again.returncode == 0, again.stdout + again.stderr
    assert (folder / "agent-key").read_text(encoding="ascii") == key
    assert "enrolled as" not in again.stdout


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_join_stops_before_spending_the_enrollment_when_the_root_differs(
    bus: _Bus, tmp_path: Path, platform: str,
):
    _shell(platform)
    name = f"pinned-{platform}"
    package, _token = bus.package(name)
    home = tmp_path / "home"
    home.mkdir()
    wrong = ":".join(["00"] * 32)
    assert bus.fingerprint in package

    result = _run(platform, _block(package, platform).replace(bus.fingerprint, wrong), home)

    assert result.returncode != 0
    assert "does not match the onboarding package" in result.stderr
    folder = home / ".strugglebus" / name
    assert not (folder / "agent.json").exists()
    assert not (folder / "agent-key").exists()
    # The enrollment is still good: the untouched block then succeeds.
    assert _run(platform, _block(package, platform), home).returncode == 0


def test_join_reports_a_spent_enrollment_in_plain_words(bus: _Bus, tmp_path: Path):
    platform = "linux" if _bash() else "windows"
    _shell(platform)
    package, _token = bus.package("spent-token")
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    assert _run(platform, _block(package, platform), first).returncode == 0

    result = _run(platform, _block(package, platform), second)

    assert result.returncode != 0
    assert "Ask your operator" in result.stderr
    assert not (second / ".strugglebus" / "spent-token" / "agent-key").exists()


def test_linux_launcher_starts_copilot_with_the_key_and_both_certificate_roots(
    bus: _Bus, tmp_path: Path,
):
    _shell("linux")
    if sys.platform == "win32":
        pytest.skip("the launcher's fake copilot needs a POSIX PATH")
    package, _token = bus.package("launcher-linux")
    home = tmp_path / "home"
    home.mkdir()
    assert _run("linux", _block(package, "linux"), home).returncode == 0
    folder = home / ".strugglebus" / "launcher-linux"
    tools = tmp_path / "tools"
    tools.mkdir()
    fake = tools / "copilot"
    fake.write_text(
        "#!/bin/bash\n"
        'printf "%s\\n" "$@" > "$HOME/arguments"\n'
        'printf "%s" "$STRUGGLEBUS_AGENT_KEY" > "$HOME/key"\n'
        'cp "$NODE_EXTRA_CA_CERTS" "$HOME/roots"\n',
        encoding="ascii",
    )
    fake.chmod(0o700)
    company = tmp_path / "company-root.pem"
    company.write_text("company proxy root\n", encoding="ascii")

    result = subprocess.run(  # nosec B603
        [str(folder / "bus-copilot"), "--deny-tool", "shell"], cwd=tmp_path,
        env=_environment(
            home, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}",
            NODE_EXTRA_CA_CERTS=str(company),
        ),
        capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert (home / "arguments").read_text().splitlines() == [
        "--additional-mcp-config", f"@{folder}/copilot-mcp.json", "--deny-tool", "shell",
    ]
    assert (home / "key").read_text() == (folder / "agent-key").read_text()
    roots = (home / "roots").read_text()
    assert roots.startswith("company proxy root\n")
    assert (folder / "ca-root.crt").read_text() in roots


def test_join_scripts_are_served_without_a_credential(app_config: AppConfig):
    with TestClient(create_app(config=app_config), base_url="https://bus.lan") as client:
        for name in ("join.sh", "join.ps1"):
            response = client.get("/" + name, follow_redirects=False)
            assert response.status_code == 200, name
            assert response.content == (KIT / name).read_bytes()
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["x-content-type-options"] == "nosniff"
        assert client.get("/join.cmd", follow_redirects=False).status_code != 200


def test_package_offers_quick_join_only_when_it_carries_a_root():
    common = dict(
        base_url="https://bus.home.arpa", agent_name="review-reader",
        token="sbe1_example", expires_at=datetime.now(UTC),
    )
    manual = onboarding_package_text(**common)
    assert "QUICK JOIN" not in manual and "join.sh" not in manual

    root = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    package = onboarding_package_text(**common, ca_root=root, ca_fingerprint="AA:BB")
    assert package.index("QUICK JOIN") < package.index("BY HAND") < package.index("1. Check the CA")
    assert "--output join.sh https://bus.home.arpa/join.sh" in package
    assert "'https://bus.home.arpa/join.ps1'" in package
    # The token rides in an environment variable, not on a visible command line.
    assert "STRUGGLEBUS_ENROLLMENT=sbe1_example bash join.sh" in package
    assert "$env:STRUGGLEBUS_ENROLLMENT = 'sbe1_example'" in package
