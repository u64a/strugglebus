"""Verify release readiness uses an explicit, working internal CA trust path."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import ssl
import subprocess  # nosec B404
import tempfile
import threading


DEPLOY_DIR = Path(__file__).resolve().parents[1]
ANSIBLE_PLAYBOOK = shutil.which("ansible-playbook")
OPENSSL = shutil.which("openssl")
if ANSIBLE_PLAYBOOK is None:
    raise RuntimeError("ansible-playbook is required for release HTTPS tests")
if OPENSSL is None:
    raise RuntimeError("openssl is required for release HTTPS tests")


class HealthHandler(BaseHTTPRequestHandler):
    failures_remaining = 0
    request_count = 0
    state_lock = threading.Lock()

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self.send_error(404)
            return
        with self.state_lock:
            type(self).request_count += 1
            unavailable = type(self).failures_remaining > 0
            if unavailable:
                type(self).failures_remaining -= 1
        if unavailable:
            self.send_error(503)
            return
        payload = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


def run_openssl(*arguments: str) -> None:
    subprocess.run(  # nosec B603
        [OPENSSL, *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def create_ca(directory: Path, name: str) -> tuple[Path, Path]:
    certificate = directory / f"{name}.crt"
    key = directory / f"{name}.key"
    run_openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(certificate),
        "-days",
        "1",
        "-sha256",
        "-subj",
        f"/CN={name}",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    return certificate, key


def create_server_certificate(
    directory: Path,
    ca_certificate: Path,
    ca_key: Path,
) -> tuple[Path, Path]:
    certificate = directory / "server.crt"
    request = directory / "server.csr"
    key = directory / "server.key"
    extensions = directory / "server.ext"
    extensions.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="ascii",
    )
    run_openssl(
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(request),
        "-subj",
        "/CN=localhost",
    )
    run_openssl(
        "x509",
        "-req",
        "-in",
        str(request),
        "-CA",
        str(ca_certificate),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(certificate),
        "-days",
        "1",
        "-sha256",
        "-extfile",
        str(extensions),
    )
    return certificate, key


def run_probe(url: str, ca_path: Path | None, *, expect_success: bool) -> None:
    command = [
        ANSIBLE_PLAYBOOK,
        "-i",
        "tests/inventory.yml",
        "tests/release_https_readiness.yml",
        "--extra-vars",
        json.dumps({"release_https_test_url": url}),
    ]
    if ca_path is not None:
        command.extend(
            [
                "--extra-vars",
                json.dumps({"release_https_test_ca_path": str(ca_path)}),
            ]
        )
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        result = subprocess.run(  # nosec B603
            command,
            cwd=DEPLOY_DIR,
            check=False,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output.seek(0)
        rendered_output = output.read()
    if (result.returncode == 0) is not expect_success:
        raise AssertionError(
            f"release HTTPS probe returned {result.returncode}:\n"
            f"{rendered_output}"
        )


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)
        ca_certificate, ca_key = create_ca(directory, "release-readiness-ca")
        wrong_ca, _ = create_ca(directory, "wrong-release-readiness-ca")
        server_certificate, server_key = create_server_certificate(
            directory,
            ca_certificate,
            ca_key,
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(server_certificate, server_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"https://localhost:{server.server_port}/healthz"
            run_probe(url, None, expect_success=False)
            run_probe(url, wrong_ca, expect_success=False)
            run_probe(url, ca_certificate, expect_success=True)
            before_retry_probe = HealthHandler.request_count
            HealthHandler.failures_remaining = 2
            run_probe(url, ca_certificate, expect_success=True)
            if HealthHandler.request_count - before_retry_probe != 3:
                raise AssertionError("release readiness did not use bounded retries")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
