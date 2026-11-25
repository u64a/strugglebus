"""tools/grant-ssh.ps1: hand one public key to a host's SSH, with a remote script that parses and fits a command line.

Only pure functions are exercised (dot-sourced), in PowerShell 7 and Windows PowerShell 5.1: nothing here touches the
machine running the tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from pshelp import ps
from test_debloat import SHELLS

ROOT = Path(__file__).resolve().parent.parent
GRANT = ROOT / "tools" / "grant-ssh.ps1"
pytestmark = pytest.mark.skipif(not SHELLS, reason="no PowerShell")
GOOD = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGLR0m1Lnixt4tSHh2fSKTJotzibAUsbx1cqO2iFH agent-access"


@pytest.fixture(params=SHELLS)
def shell(request):
    return request.param


def test_grant_ssh_takes_one_public_key_and_sends_a_script_that_parses(shell):
    got = ps(shell, GRANT, r"""
$good = '""" + GOOD + r"""'
$checks = @(
  (Test-PublicKey $good), (Test-PublicKey 'ssh-ed25519 AAAA'), (Test-PublicKey '-----BEGIN OPENSSH PRIVATE KEY-----'),
  (Test-PublicKey ($good + "`nssh-ed25519 AAAA two")), (Test-PublicKey 'ssh-dss AAAAB3 old'), (Test-PublicKey '')
)
$script = New-RemoteScript $good $false
$errors = $null
[void][Management.Automation.Language.Parser]::ParseInput($script, [ref]$null, [ref]$errors)
$keep = New-RemoteScript $good $true
[ordered]@{
  checks = $checks; parse_errors = @($errors).Count
  has_key = $script.Contains([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($good)))
  turns_off = $script.Contains("'PasswordAuthentication no'"); keep_leaves = $keep.Contains('left as it is')
  encoded_len = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script)).Length
} | ConvertTo-Json -Depth 3
""")
    assert got["checks"] == [True, True, False, False, False, False]
    assert got["parse_errors"] == 0 and got["has_key"] and got["turns_off"] and got["keep_leaves"]
    assert got["encoded_len"] < 7000  # fits cmd.exe's 8,191-character command line on the host


def test_the_script_is_plain_ascii_for_windows_powershell():
    assert all(b < 128 for b in GRANT.read_bytes())
