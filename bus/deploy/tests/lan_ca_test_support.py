#!/usr/bin/env python3
"""Create and verify an isolated real step-ca test configuration."""

from __future__ import annotations

import argparse
import json
import socket
import ssl
from pathlib import Path


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def render_config(args: argparse.Namespace) -> None:
    provisioner = {
        "type": "JWK",
        "name": args.provisioner,
        "key": json.loads(Path(args.jwk_public).read_text(encoding="utf-8")),
        "encryptedKey": Path(args.jwk_private).read_text(encoding="utf-8").strip(),
        "claims": {
            "enableSSHCA": False,
            "defaultTLSCertDuration": "24h",
            "maxTLSCertDuration": "72h",
        },
        "options": {
            "x509": {
                "templateFile": str(Path(args.template).resolve()),
                "templateData": {"ServiceDNS": args.service_dns},
            }
        },
    }
    config = {
        "root": str(Path(args.root).resolve()),
        "federatedRoots": [],
        "crt": str(Path(args.intermediate).resolve()),
        "key": str(Path(args.intermediate_key).resolve()),
        "address": f"127.0.0.1:{args.port}",
        "insecureAddress": "",
        "dnsNames": [args.ca_dns],
        "logger": {"format": "text"},
        "db": {
            "type": "badgerv2",
            "dataSource": str(Path(args.database).resolve()),
            "badgerFileLoadingMode": "FileIO",
        },
        "authority": {
            "provisioners": [provisioner],
            "policy": {
                "x509": {
                    "allow": {"dns": [args.service_dns, args.ca_dns]},
                    "allowWildcardNames": False,
                }
            },
        },
        "tls": {
            "cipherSuites": [
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            ],
            "minVersion": 1.2,
        },
    }
    Path(args.output).write_text(
        json.dumps(config, indent=2) + "\n",
        encoding="utf-8",
    )


def tls_health(args: argparse.Namespace) -> None:
    context = ssl.create_default_context(cafile=args.root)
    context.check_hostname = True
    with socket.create_connection(("127.0.0.1", args.port), timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname=args.sni) as tls:
            request = (
                f"GET /health HTTP/1.1\r\nHost: {args.sni}\r\n"
                "Connection: close\r\n\r\n"
            )
            tls.sendall(request.encode("ascii"))
            response = tls.recv(4096)
    if not response.startswith(b"HTTP/1.1 200"):
        raise RuntimeError("step-ca health response was not HTTP 200")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    port = commands.add_parser("free-port")
    port.set_defaults(function=lambda _args: print(free_port()))

    render = commands.add_parser("render-config")
    for name in (
        "root",
        "intermediate",
        "intermediate-key",
        "jwk-public",
        "jwk-private",
        "template",
        "database",
        "ca-dns",
        "service-dns",
        "provisioner",
        "output",
    ):
        render.add_argument(f"--{name}", required=True)
    render.add_argument("--port", type=int, required=True)
    render.set_defaults(function=render_config)

    health = commands.add_parser("tls-health")
    health.add_argument("--port", type=int, required=True)
    health.add_argument("--sni", required=True)
    health.add_argument("--root", required=True)
    health.set_defaults(function=tls_health)
    return root


def main() -> int:
    args = parser().parse_args()
    args.function(args)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
