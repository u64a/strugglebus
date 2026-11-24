"""The proxy watchdog restarts Caddy only when Caddy itself stops answering."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/roles/caddy/files/strugglebus-proxy-watchdog"
BASH = shutil.which("bash")

# Stubs: curl answers the client path with $CLIENT_CODE and the loopback path
# (--connect-to) with $LOCAL_CODE; systemctl records a restart.
CURL = """#!/bin/bash
for arg in "$@"; do
  if [ "$arg" = "--connect-to" ]; then printf '%s' "$LOCAL_CODE"; exit 0; fi
done
printf '000'; exit 28
"""
SYSTEMCTL = """#!/bin/bash
case "$1" in
  is-active) echo active ;;
  restart) touch "$RESTARTED" ;;
esac
"""


def _run(tmp_path: Path, local_code: str) -> tuple[subprocess.CompletedProcess[str], bool]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("curl", CURL), ("systemctl", SYSTEMCTL), ("sleep", "#!/bin/bash\n")):
        stub = bin_dir / name
        stub.write_bytes(body.encode())
        stub.chmod(0o755)
    restarted = tmp_path / "restarted"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "RUNTIME_DIRECTORY": str(tmp_path / "state"),
        "STRUGGLEBUS_WATCHDOG_THRESHOLD": "1",
        "LOCAL_CODE": local_code,
        "RESTARTED": str(restarted),
    }
    result = subprocess.run([BASH, str(SCRIPT)], capture_output=True, text=True, env=env)
    return result, restarted.exists()


@pytest.mark.skipif(BASH is None or os.name == "nt", reason="needs bash with POSIX stubs")
def test_network_loss_outside_the_guest_does_not_restart_a_healthy_caddy(tmp_path: Path) -> None:
    result, restarted = _run(tmp_path, local_code="200")
    assert result.returncode == 1
    assert "status=unreachable-outside-guest" in result.stdout
    assert not restarted


@pytest.mark.skipif(BASH is None or os.name == "nt", reason="needs bash with POSIX stubs")
def test_caddy_that_fails_on_loopback_too_is_restarted(tmp_path: Path) -> None:
    result, restarted = _run(tmp_path, local_code="000")
    assert "action=restarting-caddy" in result.stdout
    assert restarted
