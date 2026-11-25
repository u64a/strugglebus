"""Running a PowerShell script's pure functions from a test: dot-source the script, run `body`, return its JSON output.
Shared by the tests of the setup and tools scripts."""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


def ps(shell: str, script: Path, body: str):
    text = "$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest; . '" + str(script) + "'\n" + body
    with tempfile.TemporaryDirectory() as d:
        driver = Path(d) / "driver.ps1"
        driver.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
        r = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver)],
                           capture_output=True, timeout=120)
    out = r.stdout.decode("utf-8", "replace").strip()
    assert r.returncode == 0, (out, r.stderr.decode("utf-8", "replace"))
    return json.loads(out)
