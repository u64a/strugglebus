"""Shared helpers for the live TLS updater tests."""

from contextlib import closing, contextmanager
from html.parser import HTMLParser
import html
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from uuid import uuid4

import pytest
import uvicorn

from strugglebus import __version__
from strugglebus.migrations import LATEST_SCHEMA_VERSION
from test_acceptance import _next_sse_message


def hidden(response):
    assert response.status_code == 200, response.text
    return {
        key: html.unescape(value)
        for key, value in re.findall(
            r'<input type="hidden" name="([^"]+)" value="([^"]*)">', response.text,
        )
    }


def stylesheet(response):
    return re.findall(r'<link rel="stylesheet" href="([^"]+)">', response.text)


class Forms(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.forms = []
        self.current = None
        self.feed(document)

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        if tag == "form":
            self.current = (values.get("action", ""), {})
            self.forms.append(self.current)
        if tag == "input" and self.current is not None and values.get("name"):
            name = values["name"]
            assert name not in self.current[1], "duplicate form field"
            self.current[1][name] = values.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None

    def fields(self, action):
        matching = [fields for target, fields in self.forms if target == action]
        assert len(matching) == 1, f"expected exactly one {action} form"
        return dict(matching[0])


def _certificate(directory: Path):
    executable = shutil.which("openssl")
    if executable is None:
        pytest.skip("OpenSSL is required for the real trusted-TLS transport test")
    certificate = directory / "live-test.crt"
    key = directory / "live-test.key"
    subprocess.run(
        [
            executable, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ],
        check=True, capture_output=True, timeout=30,
    )
    key.chmod(0o600)
    return certificate, key


@contextmanager
def trusted_https_server(application_factory, directory: Path):
    certificate, key = _certificate(directory)
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            base_url = f"https://127.0.0.1:{listener.getsockname()[1]}"
            application = application_factory(base_url)
            server = uvicorn.Server(uvicorn.Config(
                application, host="127.0.0.1", port=0,
                ssl_certfile=str(certificate), ssl_keyfile=str(key),
                log_level="error", access_log=False, proxy_headers=False,
                server_header=False, timeout_graceful_shutdown=2,
            ))
            thread = threading.Thread(
                target=server.run, kwargs={"sockets": [listener]}, daemon=True,
            )
            thread.start()
            try:
                deadline = time.monotonic() + 10
                while not server.started:
                    if not thread.is_alive() or time.monotonic() >= deadline:
                        pytest.fail("TLS server failed to start")
                    time.sleep(0.01)
                trust = ssl.create_default_context(cafile=str(certificate))
                assert trust.verify_mode == ssl.CERT_REQUIRED and trust.check_hostname
                yield application, base_url, trust, server, thread
            finally:
                server.should_exit = True
                thread.join(timeout=5)
                if thread.is_alive():
                    pytest.fail("TLS server did not stop")
    finally:
        certificate.unlink(missing_ok=True)
        key.unlink(missing_ok=True)


def _identity(application):
    uri = application.state.config.database_path.as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as database:
        schema = database.execute("PRAGMA user_version").fetchone()[0]
    assert schema == LATEST_SCHEMA_VERSION
    return {
        "pid": os.getpid(), "version": __version__,
        "release_id": application.state.config.release_id,
        "schema": schema,
    }


async def _prove(client):
    response = await client.get("/api/whoami")
    assert response.status_code == 200, response.text
    identity = response.json()
    agent = identity["agent"]
    proof = await client.post(
        "/api/credentials/prove",
        json={
            "request_id": str(uuid4()),
            "expected_agent_id": agent["id"],
            "expected_agent_name": agent["name"],
            "expected_credential_epoch": agent["credential_epoch"],
            "expected_credential_version": identity["credential"]["version"],
        },
    )
    assert proof.status_code == 200, proof.text


async def _consume(lines):
    return [await _next_sse_message(lines, index + 1) for index in range(100)]
