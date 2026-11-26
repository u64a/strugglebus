"""tools/sign-bootstrap.ps1: bootstrap.ps1 is Authenticode-signed only when it is exactly what a signed release
approved, and a signed copy passes only as "the released bytes + one timestamped signature by a certificate the
release names" (docs/app-host-integration.md 2.1; security review: sign only what the release key approved; check
the thumbprint, not the name; require the timestamp; pin current and next thumbprints in the release)."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "sign-bootstrap.ps1"
PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell 7 (pwsh) is not installed")

PLAIN = b"# bootstrap\nparam([string]$DataFile)\nWrite-Host 'hello'\n"
SHA = hashlib.sha256(PLAIN).hexdigest()
THUMB = "3FF059FA28ED74ACB229CBA2E670CEA565015238"
BLOCK = ("\r\n# SIG # Begin signature block\r\n# MIIFpAYJKoZIhvcNAQcCoIIFlTCCBZECAQExDzANBglghkgBZQMEAgEFADB5Bgor\r\n"
         "# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG\r\n# SIG # End signature block\r\n")
RELEASE = (f'serial = 7\nversion = "2026.11.27"\nbootstrap_sha256 = "{SHA}"\n'
           f'authenticode_thumbprints = ["{THUMB}", "{"A" * 40}"]\n')


def run(body: str, tmp_path: Path):
    driver = tmp_path / "d.ps1"
    driver.write_text(f". '{SCRIPT}'\n{body}", encoding="utf-8")
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(driver)], capture_output=True, text=True,
                       timeout=120, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def bytes_literal(data: bytes) -> str:
    return "([byte[]](" + ",".join(str(b) for b in data) + "))" if data else "([byte[]]@())"


def facts_literal(text: str) -> str:
    return "(Get-ReleaseFacts '" + text.replace("'", "''") + "')"


def sig(status="Valid", thumb=THUMB, timestamp=True) -> str:
    stamp = "[pscustomobject]@{Subject='CN=Certum Timestamp'}" if timestamp else "$null"
    cert = f"[pscustomobject]@{{Thumbprint='{thumb}'}}" if thumb else "$null"
    return f"([pscustomobject]@{{Status='{status}'; SignerCertificate={cert}; TimeStamperCertificate={stamp}}})"


def test_the_release_facts_are_read_as_make_release_writes_them(tmp_path):
    got = run(f"ConvertTo-Json -Compress {facts_literal(RELEASE)}", tmp_path)
    assert got == {"bootstrap_sha256": SHA, "thumbprints": [THUMB, "A" * 40]}
    none = run(f"ConvertTo-Json -Compress {facts_literal('serial = 1')}", tmp_path)
    assert none["bootstrap_sha256"] == "" and none["thumbprints"] == []


def test_only_the_file_the_release_approved_is_signed(tmp_path):
    ok = run(f"ConvertTo-Json -Compress -InputObject (Test-UnsignedBootstrap {bytes_literal(PLAIN)} {facts_literal(RELEASE)})",
             tmp_path)
    assert ok == []
    doctored = run(f"ConvertTo-Json -Compress -InputObject (Test-UnsignedBootstrap {bytes_literal(PLAIN + b'#x')} "
                   f"{facts_literal(RELEASE)})", tmp_path)
    assert any("not the file this release approved" in p for p in doctored)
    already = run(f"ConvertTo-Json -Compress -InputObject (Test-UnsignedBootstrap {bytes_literal(PLAIN + BLOCK.encode())} "
                  f"{facts_literal(RELEASE)})", tmp_path)
    assert any("already signed" in p for p in already)
    nothumbs = run(f"ConvertTo-Json -Compress -InputObject (Test-UnsignedBootstrap {bytes_literal(PLAIN)} "
                   f"{facts_literal(RELEASE.split('authenticode')[0])})", tmp_path)
    assert any("authenticode_thumbprints" in p for p in nothumbs)


def problems(data: bytes, signature: str, tmp_path, release: str = RELEASE) -> list[str]:
    return run(f"ConvertTo-Json -Compress -InputObject (Test-SignedBootstrap {bytes_literal(data)} {facts_literal(release)} "
               f"{signature})", tmp_path)


def test_a_good_signed_copy_passes(tmp_path):
    assert problems(PLAIN + BLOCK.encode(), sig(), tmp_path) == []
    assert problems(PLAIN + BLOCK.encode(), sig(thumb="A" * 40), tmp_path) == []  # the next certificate, pinned


@pytest.mark.parametrize("data, signature, why", [
    (PLAIN + b"#x" + BLOCK.encode(), sig(), "not the released bootstrap.ps1"),
    (PLAIN, sig(), "no signature block"),
    (PLAIN + BLOCK.encode() + b"Write-Host 'evil'\r\n", sig(), "something follows"),
    (PLAIN + BLOCK.encode() + BLOCK.encode()[2:], sig(), "more than one"),
    (PLAIN + BLOCK.replace("# BgEE", "Write-Host evil #").encode(), sig(), "not signature data"),
    (PLAIN + BLOCK.encode(), sig(status="HashMismatch"), "signature status"),
    (PLAIN + BLOCK.encode(), sig(status="NotSigned", thumb=""), "thumbprint"),
    (PLAIN + BLOCK.encode(), sig(thumb="B" * 40), "is not one the release names"),  # same name, other certificate
    (PLAIN + BLOCK.encode(), sig(timestamp=False), "no timestamp"),
])
def test_anything_else_is_refused(data, signature, why, tmp_path):
    got = problems(data, signature, tmp_path)
    assert any(why in p for p in got), got


def test_the_release_must_verify_with_the_pinned_release_key(tmp_path):
    from workerhost import signing

    keygen = signing.find_ssh_keygen()
    if not keygen:
        pytest.skip("no ssh-keygen")
    for name in ("alice", "stranger"):
        subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(tmp_path / name)], check=True,
                       capture_output=True)
    kind, blob = (tmp_path / "alice.pub").read_text().split()[:2]
    signers = tmp_path / "allowed_signers"
    signers.write_text(f'alice namespaces="strugglebus-release" {kind} {blob}\n')
    release = tmp_path / "release.toml"
    release.write_bytes(RELEASE.encode())

    def signed_by(key: str, ns: str) -> Path:
        Path(str(release) + ".sig").unlink(missing_ok=True)
        subprocess.run([keygen, "-Y", "sign", "-f", str(tmp_path / key), "-n", ns, str(release)], check=True,
                       capture_output=True)
        return Path(str(release) + ".sig")

    alice_fp = signing.read_signers(signers)[0].fingerprint

    def verifies(data: bytes, sig: Path, pinned: str = alice_fp) -> str:
        lit = bytes_literal(data)
        pin = f"@('{pinned}')" if pinned else "$ReleaseKeyFingerprints"
        return run(f"ConvertTo-Json (Test-ReleaseSignature '{keygen}' '{signers}' {lit} '{sig}' {pin})", tmp_path)

    assert verifies(RELEASE.encode(), signed_by("alice", "strugglebus-release")) == alice_fp
    assert verifies(RELEASE.encode() + b"#", signed_by("alice", "strugglebus-release")) == ""  # changed bytes
    assert verifies(RELEASE.encode(), signed_by("alice", "strugglebus-fleet")) == ""  # another namespace
    assert verifies(RELEASE.encode(), signed_by("stranger", "strugglebus-release")) == ""
    # The security review's case: a good signature by a key that the -Signers file lists but this script does not
    # pin (an agent could add its key to that file). With the script's own pins (the owner's YubiKeys), refused.
    assert verifies(RELEASE.encode(), signed_by("alice", "strugglebus-release"), pinned="") == ""


def test_the_pinned_release_keys_are_the_owners_three_yubikeys(tmp_path):
    got = run("ConvertTo-Json -Compress -InputObject $ReleaseKeyFingerprints", tmp_path)
    assert len(got) == 3 and all(fp.startswith("SHA256:") and len(fp) == 50 for fp in got)


def test_signing_appends_and_changes_nothing_before_the_block(tmp_path):
    """What the design rests on: a real Set-AuthenticodeSignature keeps the original bytes as an exact prefix (a
    throwaway self-signed certificate, deleted afterwards; its status is untrusted, which is expected)."""
    target = tmp_path / "b.ps1"
    target.write_bytes(PLAIN)
    body = (f"$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=throwaway test' "
            f"-CertStoreLocation Cert:\\CurrentUser\\My -NotAfter (Get-Date).AddDays(1)\n"
            f"try {{ $null = Set-AuthenticodeSignature -LiteralPath '{target}' -Certificate $c -HashAlgorithm SHA256\n"
            f"  $b = [IO.File]::ReadAllBytes('{target}'); $p = Split-SignedScript $b\n"
            f"  ConvertTo-Json -Compress @{{ sha = (Get-Sha256Hex $p.Content) }} }}\n"
            f"finally {{ Remove-Item \"Cert:\\CurrentUser\\My\\$($c.Thumbprint)\" -Force }}")
    try:
        got = run(body, tmp_path)
    except AssertionError as e:
        pytest.skip(f"no certificate store here: {e}")
    assert got["sha"] == SHA
