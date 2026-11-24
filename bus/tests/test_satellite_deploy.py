"""Satellite deployment pieces: the PKI helper, the gateway template and script.

The helper's certificates must survive Python's strict verification, which is
what the satellite client uses, so the main test completes a real mutual-TLS
handshake with them.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from strugglebus.config import AppConfig
from strugglebus.satellite import BUNDLE_PREFIX, SiteAuthority, parse_join_request
from test_satellite_sites import _join_request

REPOSITORY = Path(__file__).resolve().parents[1]
HELPER = REPOSITORY / "deploy/roles/satellite/files/strugglebus-satellite-pki.sh"
GATEWAY = REPOSITORY / "deploy/gateway"
HOSTNAME = "sb-gw.example.cloudapp.azure.com"
BASH = shutil.which("bash")
OPENSSL = shutil.which("openssl")
needs_tools = pytest.mark.skipif(
    BASH is None or OPENSSL is None, reason="bash and openssl are required",
)


def _pki(tmp_path: Path, hostname: str = HOSTNAME) -> subprocess.CompletedProcess[str]:
    server_dir = tmp_path / "satellite"
    server_dir.mkdir(exist_ok=True)
    return subprocess.run(
        [
            BASH, str(HELPER), str(tmp_path / "ca.key"), str(tmp_path / "ca.crt"),
            str(server_dir), hostname, "",
        ],
        capture_output=True, text=True, check=False,
        # On Windows the MSYS layer would rewrite "-subj /CN=..." as a path.
        env={
            **os.environ, "OPENSSL_BIN": OPENSSL or "", "MSYS_NO_PATHCONV": "1",
            "MSYS2_ARG_CONV_EXCL": "*",
        },
    )


@needs_tools
def test_helper_certificates_pass_strict_mutual_tls(
    app_config: AppConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _pki(tmp_path)
    assert first.returncode == 0, first.stderr
    assert first.stdout.split() == ["ca:", "created", "server:", "issued"]
    assert "PRIVATE KEY" not in first.stdout + first.stderr

    # The bus signs a site certificate with the helper's CA.
    monkeypatch.setattr(
        AppConfig, "load_satellite_ca_key", lambda self: (tmp_path / "ca.key").read_bytes(),
    )
    config = replace(
        app_config, satellite_hostname=HOSTNAME, satellite_gateway_wg_address="10.99.0.1",
        satellite_ca_cert_path=tmp_path / "ca.crt",
        satellite_ca_key_path=tmp_path / "ca.key",
    )
    authority = SiteAuthority.load(config)
    site_key = ec.generate_private_key(ec.SECP256R1())
    issued = authority.issue("devbox-one", parse_join_request(_join_request(site_key)))
    encoded = issued.bundle[len(BUNDLE_PREFIX):]
    import base64

    bundle = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    (tmp_path / "client.crt").write_text(bundle["cert_pem"], encoding="ascii")
    (tmp_path / "client.key").write_bytes(
        site_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(
        tmp_path / "satellite/server.crt", tmp_path / "satellite/server.key",
    )
    server_context.load_verify_locations(tmp_path / "ca.crt")
    server_context.verify_mode = ssl.CERT_REQUIRED
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    seen: dict[str, object] = {}

    def serve() -> None:
        connection, _ = listener.accept()
        with server_context.wrap_socket(connection, server_side=True) as tls:
            seen["peer"] = dict(item[0] for item in tls.getpeercert()["subject"])
            tls.sendall(b"ok")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    # The client's default context: Python 3.13 enables strict X.509 checks.
    client_context = ssl.create_default_context(cafile=tmp_path / "ca.crt")
    client_context.load_cert_chain(tmp_path / "client.crt", tmp_path / "client.key")
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with client_context.wrap_socket(raw, server_hostname=HOSTNAME) as tls:
            assert tls.recv(2) == b"ok"
    thread.join(timeout=10)
    listener.close()
    assert seen["peer"] == {"commonName": "devbox-one"}

    again = _pki(tmp_path)
    assert again.returncode == 0, again.stderr
    assert again.stdout.split() == ["ca:", "present", "server:", "current"]
    renamed = _pki(tmp_path, "other.example.cloudapp.azure.com")
    assert renamed.stdout.split() == ["ca:", "present", "server:", "issued"]


@needs_tools
def test_helper_refuses_half_a_ca_and_bad_hostnames(tmp_path: Path) -> None:
    assert _pki(tmp_path).returncode == 0
    (tmp_path / "ca.key").unlink()
    refused = _pki(tmp_path)
    assert refused.returncode != 0
    assert "restore it" in refused.stderr
    assert _pki(tmp_path, "Not_A_Host").returncode != 0


def test_gateway_template_admits_only_satellites_and_the_bus() -> None:
    template = json.loads((GATEWAY / "gateway.json").read_text(encoding="utf-8"))
    resources = {resource["type"]: resource for resource in template["resources"]}
    rules = [
        rule["properties"]
        for rule in resources["Microsoft.Network/networkSecurityGroups"]["properties"]["securityRules"]
    ]
    assert [(r["protocol"], r["destinationPortRange"], r["sourceAddressPrefix"]) for r in rules] == [
        ("Tcp", "443", "Internet"),
        ("Udp", "51820", "[concat(parameters('homeIp'), '/32')]"),
    ]
    assert all(r["direction"] == "Inbound" and r["access"] == "Allow" for r in rules)
    assert template["parameters"]["vmSize"]["defaultValue"] == "Standard_B1s"
    vm = resources["Microsoft.Compute/virtualMachines"]["properties"]
    assert vm["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"] is True
    assert "customData" not in vm["osProfile"]
    assert resources["Microsoft.Network/networkInterfaces"]["properties"]["enableIPForwarding"]


def test_gateway_script_forwards_443_unopened_and_validates_input() -> None:
    script = (GATEWAY / "configure-gateway.sh").read_text(encoding="utf-8")
    assert script.startswith("#!/usr/bin/env bash\n") and "set -euo pipefail" in script
    assert "dnat ip to $bus_ip:8443" in script
    assert "tcp dport 8443 ct status dnat accept" in script
    assert "policy drop;" in script
    assert 'oifname "wg0" masquerade' in script
    for check in (
        "invalid bus public key", "invalid bus tunnel address", "invalid gateway tunnel CIDR",
        "invalid bus source address",
    ):
        assert check in script
    # Input admits only the bus's WireGuard packets beyond replies and loopback.
    assert "type filter hook input priority filter; policy drop;" in script
    assert 'iif "lo" accept' in script
    assert 'ip saddr $bus_source udp dport 51820 accept' in script
    # Only the owned sysctl file and the owned nftables table are touched.
    assert 'sysctl -q -p "$SYSCTL_FILE"' in script and "sysctl -q --system" not in script
    assert "flush ruleset" not in script
    assert "delete table inet strugglebus_gateway" in script
    # The candidate is checked before it is applied, and the tunnel comes up
    # only after the table loads, and reloads it at every start.
    order = [
        script.index('nft -c -f "$NFT_FILE.new"'),
        script.index('mv "$NFT_FILE.new" "$NFT_FILE"'),
        script.index('nft -f "$NFT_FILE"'),
        script.index("systemctl enable -q wg-quick@wg0"),
    ]
    assert order == sorted(order)
    assert "PreUp = nft -f $NFT_FILE" in script
    assert script.count("  require_forwarding\n") == 2
    # New connections are bounded per client address before the masquerade.
    meter = "ct state new add @new_by_source { ip saddr limit rate over 10/second burst 20 packets } drop"
    assert meter in script
    assert script.index(meter) < script.index("tcp dport 8443 ct status dnat accept")
    # Debian's nftables.service would flush the gateway's table on any restart.
    assert "systemctl mask -q nftables.service" in script
    # No TLS material ever lands on the gateway.
    assert "openssl" not in script and ".crt" not in script


@pytest.mark.skipif(BASH is None, reason="bash is required")
def test_deployment_scripts_parse() -> None:
    for script in (HELPER, GATEWAY / "configure-gateway.sh"):
        result = subprocess.run([BASH, "-n", str(script)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


@pytest.mark.skipif(BASH is None, reason="bash is required")
def test_gateway_peer_accepts_named_values_as_run_command_passes_them() -> None:
    # run-command exports any parameter containing '=', and a WireGuard key
    # always ends in '=', so the named form is the one that works there.
    import os

    env = {
        **os.environ,
        "BUS_PUBLIC_KEY": "not-a-wireguard-key",
        "BUS_TUNNEL_IP": "10.99.0.2",
        "GATEWAY_TUNNEL_CIDR": "10.99.0.1/30",
        "BUS_SOURCE_IP": "192.0.2.10",
    }
    result = subprocess.run(
        [BASH, str(GATEWAY / "configure-gateway.sh"), "peer"],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode != 0
    # The values reached validation rather than failing on the usage line.
    assert "invalid bus public key" in result.stderr
    assert "usage" not in result.stderr


def test_satellite_role_masks_debians_nftables_service() -> None:
    # Its flush ruleset would drop the tunnel firewall while the tunnel stays up.
    tasks = (REPOSITORY / "deploy/roles/satellite/tasks/main.yml").read_text(encoding="utf-8")
    assert "name: nftables.service\n    masked: true" in tasks
    assert tasks.index("masked: true") < tasks.index("wg-quick@sbsat0")
