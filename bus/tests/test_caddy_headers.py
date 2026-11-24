"""Application/edge referrer contract; real Caddy runs only when already installed."""

from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request

import pytest


TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "deploy/roles/caddy/templates/Caddyfile.j2"
).read_text(encoding="utf-8")
CADDY = shutil.which("caddy")


def test_edge_referrer_policy_is_only_a_default() -> None:
    assert re.findall(
        r'^\s*(\S*Referrer-Policy)\s+"([^"]+)"', TEMPLATE, re.MULTILINE,
    ) == [("?Referrer-Policy", "no-referrer")]


@pytest.mark.skipif(CADDY is None, reason="real Caddy is not installed")
def test_real_caddy_preserves_upstream_policy_and_defaults_missing_header(tmp_path) -> None:
    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            if self.path != "/absent":
                self.send_header(
                    "Referrer-Policy", "same-origin" if self.path == "/form" else "no-referrer",
                )
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    # Only the production service snippet is exercised; synthetic HTTP endpoints
    # stay on loopback and do not qualify certificate/HTTPS deployment behavior.
    with ThreadingHTTPServer(("127.0.0.1", 0), Upstream) as upstream:
        with closing(socket.socket()) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        snippet = TEMPLATE[TEMPLATE.index("(strugglebus_service)"):TEMPLATE.index("{% if")]
        snippet = snippet.replace("{{ strugglebus_bind_host }}", "127.0.0.1")
        snippet = snippet.replace("{{ strugglebus_bind_port }}", str(upstream.server_port))
        config = tmp_path / "Caddyfile"
        config.write_text(
            "{\n admin off\n auto_https off\n}\n" + snippet
            + f"\nhttp://127.0.0.1:{port} {{\n bind 127.0.0.1\n import strugglebus_service\n}}\n",
            encoding="utf-8",
        )
        # Keep Caddy's autosaved config and runtime data out of the caller's profile.
        environment = {
            **os.environ,
            "HOME": str(tmp_path),
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
            "XDG_DATA_HOME": str(tmp_path / "data"),
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
            "APPDATA": str(tmp_path / "config"),
            "LOCALAPPDATA": str(tmp_path / "data"),
        }
        adapted = subprocess.run(
            [CADDY, "adapt", "--config", str(config), "--adapter", "caddyfile"],
            capture_output=True, timeout=10, check=True, env=environment,
        )
        configuration = json.loads(adapted.stdout)
        assert [
            address
            for server in configuration["apps"]["http"]["servers"].values()
            for address in server["listen"]
        ] == [f"127.0.0.1:{port}"]

        def headers(value):
            if isinstance(value, dict):
                if value.get("handler") == "headers":
                    yield value
                for nested in value.values():
                    yield from headers(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from headers(nested)

        defaults = [
            handler["response"] for handler in headers(configuration)
            if "Referrer-Policy" in handler.get("response", {}).get("set", {})
        ]
        assert len(defaults) == 1
        assert defaults[0]["set"]["Referrer-Policy"] == ["no-referrer"]
        assert defaults[0]["require"]["headers"]["Referrer-Policy"] in (None, [])

        worker = threading.Thread(target=upstream.serve_forever, daemon=True)
        worker.start()
        try:
            with (tmp_path / "caddy.log").open("wb") as log:
                process = subprocess.Popen(
                    [CADDY, "run", "--config", str(config), "--adapter", "caddyfile"],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=environment,
                )
                try:
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    deadline = time.monotonic() + 5
                    while True:
                        assert process.poll() is None, "Caddy exited before readiness"
                        try:
                            response = opener.open(f"http://127.0.0.1:{port}/absent", timeout=.5)
                        except (urllib.error.URLError, TimeoutError):
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(.02)
                        else:
                            response.close()
                            break
                    for path, policy in (
                        ("/form", "same-origin"), ("/download", "no-referrer"),
                        ("/absent", "no-referrer"),
                    ):
                        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=1) as response:
                            assert response.headers.get_all("Referrer-Policy") == [policy]
                            assert "script-src 'none'" in response.headers["Content-Security-Policy"]
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
        finally:
            upstream.shutdown()
            worker.join(timeout=2)
            assert not worker.is_alive()
