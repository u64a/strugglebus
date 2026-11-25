"""tools/sign-config.ps1: the rules it enforces before the owner's YubiKey signs anything, and a real -Test run.

The -Test run uses a throwaway ed25519 key in a throwaway repository (never a YubiKey): it exercises the
byte-exact signing and verifying path the -Pr flow uses.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from workerhost import signing

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "sign-config.ps1"
PWSH = shutil.which("pwsh")

pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell 7 (pwsh) is not installed")

DRIVER = r"""
$ErrorActionPreference = 'Stop'
. '@SCRIPT@'
[ordered]@{
  files_ok = @(Test-PrFiles @('fleet.toml', 'fleet.toml.sig'))
  files_code = @(Test-PrFiles @('fleet.toml', 'workerhost/host.py', '.github/workflows/tests.yml'))
  serial = @(
    (Get-Serial "serial = 3`n[[coordinator]]`nserial = 9`n"),
    (Get-Serial "# c`nserial = 12 # note`n"),
    (Get-Serial "[[host]]`nserial = 4`n"),
    (Get-Serial "serial = '3'`n")
  )
  step = @(
    (Test-SerialStep 3 4), (Test-SerialStep 3 3), (Test-SerialStep 3 5), (Test-SerialStep 4 3),
    (Test-SerialStep $null 1), (Test-SerialStep $null 2), (Test-SerialStep 3 $null)
  )
  principals = (Get-SignerPrincipals "# who`nalice namespaces=`"x`" ssh-ed25519 AAAA a`n`nbob,alice ssh-ed25519 BBBB b`n*@example.com ssh-ed25519 CCCC c`n")
} | ConvertTo-Json -Depth 3
"""


@pytest.fixture(scope="module")
def ps(tmp_path_factory):
    script = tmp_path_factory.mktemp("sign") / "driver.ps1"
    script.write_text(DRIVER.replace("@SCRIPT@", str(SCRIPT)), encoding="utf-8")
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)], capture_output=True, text=True,
                       timeout=120, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_only_signed_files_may_ride_on_a_signature(ps):
    assert ps["files_ok"] == []
    assert ps["files_code"] == ["workerhost/host.py", ".github/workflows/tests.yml"]


def test_the_serial_is_the_top_level_one(ps):
    assert ps["serial"] == [3, 12, None, None]


def test_each_change_is_exactly_one_more_than_main(ps):
    assert ps["step"] == [True, False, False, False, True, False, False]


def test_the_principals_come_from_the_signers_file(ps):
    assert ps["principals"] == ["alice", "bob"]  # each once, in order; wildcard patterns skipped


def test_a_real_sign_and_verify_with_a_throwaway_key(tmp_path):
    keygen = next((k for k in signing.KEYGEN_CANDIDATES[:2] if os.path.isfile(k)), None)
    if keygen is None:
        pytest.skip("no Windows OpenSSH ssh-keygen")
    repo = tmp_path / "repo"
    (repo / "keys").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    key = tmp_path / "id_test"
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", str(key)], check=True,
                   capture_output=True)
    kind, blob = (tmp_path / "id_test.pub").read_text().split()[:2]
    # Any principal name: the signer is whoever the pinned list names, not one built into the code.
    (repo / "keys" / "allowed_signers").write_text(f'alice namespaces="strugglebus-fleet" {kind} {blob} test\n')
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(SCRIPT), "-Test", "-KeyFile", str(key)],
                       cwd=repo, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'Good "strugglebus-fleet" signature for alice with ED25519 key SHA256:' in r.stdout
    assert "this PC can sign" in r.stdout


def test_neither_or_both_modes_is_refused(tmp_path):
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(SCRIPT)], cwd=tmp_path,
                       capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    assert r.returncode != 0 and "either -Pr <number> or -Test" in (r.stdout + r.stderr)
