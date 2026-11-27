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
  folder_ok = @(Test-PrFiles @('worker-host/release.toml', 'worker-host/release.toml.sig') 'worker-host/')
  folder_bad = @(Test-PrFiles @('worker-host/release.toml', 'release.toml', 'bus/release.toml', 'worker-host/wh.py') 'worker-host/')
  prefix = @((Get-Prefix ''), (Get-Prefix 'worker-host'), (Get-Prefix 'worker-host\'), (Get-Prefix '/a/b/'))
  prefix_bad = @('..', 'a/../b', 'a b', 'C:\x', './a' | ForEach-Object { try { Get-Prefix $_; 'accepted' } catch { 'refused' } })
  first = @(
    (Test-SerialStep $null 8 8), (Test-SerialStep $null 1 8), (Test-SerialStep $null 9 8),
    (Test-SerialStep 8 9 8), (Test-SerialStep 8 8 8)
  )
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


def test_in_a_shared_repository_only_the_hosts_own_signed_files_may_change(ps):
    assert ps["folder_ok"] == []
    # A top-level or another product's release.toml, or the host's code, never rides in on the host's signature.
    assert ps["folder_bad"] == ["release.toml", "bus/release.toml", "worker-host/wh.py"]


def test_the_folder_is_a_plain_relative_name(ps):
    assert ps["prefix"] == ["", "worker-host/", "worker-host/", "a/b/"]
    assert ps["prefix_bad"] == ["refused"] * 5


def test_a_continued_numbering_starts_where_asked_and_only_for_a_new_file(ps):
    # Hosts refuse a serial not above the installed one, so a release at a new place continues the old count.
    assert ps["first"] == [True, False, False, True, False]


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


def test_no_script_variable_is_a_parameter_under_another_case():
    """PowerShell names are case-insensitive: `$signers = ...` overwrote the -Signers parameter, and the first real
    run (27 Nov) failed copying a temp path onto itself. A script-level parameter is never assigned."""
    import re

    text = SCRIPT.read_text(encoding="utf-8")
    block = re.search(r"(?ms)^param\((.*?)^\)", text)
    params = {p.lower() for p in re.findall(r"\]\$(\w+)", block.group(1))}
    assert {"pr", "test", "keyfile", "nomerge", "path", "firstserial", "signers"} <= params
    assigned = [m.group(1) for m in re.finditer(r"\$(\w+)\s*=(?!=)", text[block.end():]) if m.group(1).lower() in params]
    assert assigned == []


def test_a_real_sign_and_verify_with_a_signers_file_given(tmp_path):
    """-Signers: the file given is the one checked against (the repository has none at keys/)."""
    keygen = next((k for k in signing.KEYGEN_CANDIDATES[:2] if os.path.isfile(k)), None)
    if keygen is None:
        pytest.skip("no Windows OpenSSH ssh-keygen")
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    key = tmp_path / "id_test"
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", str(key)], check=True,
                   capture_output=True)
    kind, blob = (tmp_path / "id_test.pub").read_text().split()[:2]
    signers = tmp_path / "elsewhere_signers"
    signers.write_text(f'bob namespaces="strugglebus-fleet" {kind} {blob} test\n')
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(SCRIPT), "-Test", "-KeyFile", str(key),
                        "-Signers", str(signers)], cwd=repo, capture_output=True, text=True, timeout=120,
                       stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'Good "strugglebus-fleet" signature for bob' in r.stdout


def test_neither_or_both_modes_is_refused(tmp_path):
    for extra in ([], ["-Test", "-File", "fleet.toml"]):
        r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(SCRIPT), *extra], cwd=tmp_path,
                           capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        assert r.returncode != 0 and "give one of -Pr <number>, -Test or -File <path>" in (r.stdout + r.stderr)


def run_ps(body: str):
    driver = f"$ErrorActionPreference = 'Stop'\n. '{SCRIPT}'\n{body}"
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", driver], capture_output=True, text=True,
                       timeout=60, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_a_loose_file_is_signed_in_the_namespace_its_name_gives():
    got = run_ps("ConvertTo-Json @(foreach ($p in 'fleet.toml', 'C:\\x\\release.toml', 'D:\\y\\baseline.toml', "
                 "'fleet.toml.txt', 'host.py', 'fleet') { try { Get-FileNamespace $p } catch { 'refused' } })")
    assert got == ["strugglebus-fleet", "strugglebus-release", "strugglebus-baseline", "refused", "refused", "refused"]


def _ssh_string(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _sshsig(key_type: str, flags: int | None) -> str:
    """A structurally real SSHSIG (made up key and signature bytes): what the flags check reads."""
    import base64

    inner = _ssh_string(key_type.encode()) + _ssh_string(b"\x01" * 64)
    if flags is not None:
        inner += bytes([flags]) + (7).to_bytes(4, "big")  # sk: flags, then the counter
    blob = (b"SSHSIG" + (1).to_bytes(4, "big") + _ssh_string(b"pubkey") + _ssh_string(b"strugglebus-fleet")
            + _ssh_string(b"") + _ssh_string(b"sha512") + _ssh_string(inner))
    return "-----BEGIN SSH SIGNATURE-----\n" + base64.b64encode(blob).decode() + "\n-----END SSH SIGNATURE-----\n"


def test_the_flags_are_read_from_the_signature_and_only_a_security_key_has_them():
    cases = {"pin": _sshsig("sk-ssh-ed25519@openssh.com", 5), "touch": _sshsig("sk-ssh-ed25519@openssh.com", 1),
             "plain": _sshsig("ssh-ed25519", None)}
    body = "; ".join(f"$r.{k} = Get-SigFlags '{v}'" for k, v in cases.items())
    got = run_ps(f"$r = [ordered]@{{}}; {body}; try {{ Get-SigFlags 'bm90IGEgc2ln' | Out-Null; $r.bad = 'read' }} "
                 "catch { $r.bad = 'refused' }; ConvertTo-Json $r")
    assert got == {"pin": 5, "touch": 1, "plain": None, "bad": "refused"}


def test_file_mode_refuses_a_signature_without_touch_and_pin_and_writes_nothing(tmp_path):
    """A plain (non-YubiKey) key verifies, but the hosts would refuse it: no .sig is written."""
    keygen = next((k for k in signing.KEYGEN_CANDIDATES[:2] if os.path.isfile(k)), None)
    if keygen is None:
        pytest.skip("no Windows OpenSSH ssh-keygen")
    key = tmp_path / "id_test"
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", str(key)], check=True,
                   capture_output=True)
    kind, blob = (tmp_path / "id_test.pub").read_text().split()[:2]
    signers = tmp_path / "signers"
    signers.write_text(f'chris namespaces="strugglebus-fleet" {kind} {blob} test\n')
    fleet = tmp_path / "fleet.toml"
    fleet.write_bytes(b'serial = 5\nowner = "x"\n')
    r = subprocess.run([PWSH, "-NoProfile", "-File", str(SCRIPT), "-File", str(fleet), "-KeyFile", str(key),
                        "-Signers", str(signers)], cwd=tmp_path, capture_output=True, text=True, timeout=120,
                       input="yes\n")
    out = r.stdout + r.stderr
    assert r.returncode != 0 and 'Good "strugglebus-fleet" signature for chris' in out
    assert "not 0x05" in out and not (tmp_path / "fleet.toml.sig").exists()
