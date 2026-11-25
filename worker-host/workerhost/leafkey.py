"""A new EC P-256 key and CSR for the host's leaf, made on this machine (S11 self-enrolment).

Python's standard library cannot make a CSR and the host ships only .py files, so this runs a fixed PowerShell 7
script (.NET's CertificateRequest, as setup/30-openbao.ps1 does) with -EncodedCommand. Nothing secret is on the
command line: the script carries only the leaf's name and the key's path. The key is written straight to that path
by PowerShell, owner-only by SID, and never passes through this process; the CSR comes back on stdout.
"""
from __future__ import annotations

import base64
import re
import shutil
import subprocess
from pathlib import Path

SAN_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+")  # a lowercase DNS name, two labels or more

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$san = '__SAN__'
$keyPath = '__KEY__'
function Pem([string]$label, [byte[]]$der) {
    $b = [Convert]::ToBase64String($der)
    $l = for ($i = 0; $i -lt $b.Length; $i += 64) { $b.Substring($i, [Math]::Min(64, $b.Length - $i)) }
    "-----BEGIN $label-----`n" + ($l -join "`n") + "`n-----END $label-----`n"
}
$ec = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$san", $ec,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$sans = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
$sans.AddDnsName($san)
$req.CertificateExtensions.Add($sans.Build($false))
[IO.File]::WriteAllText($keyPath, (Pem 'PRIVATE KEY' $ec.ExportPkcs8PrivateKey()), [Text.Encoding]::ASCII)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls $keyPath /inheritance:r /grant:r "*${sid}:F" | Out-Null
if ($LASTEXITCODE) { Remove-Item $keyPath -Force; throw 'icacls failed on the new key' }
[Console]::Out.Write((Pem 'CERTIFICATE REQUEST' $req.CreateSigningRequest()))
$ec.Dispose()
"""


def script_for(san: str, key_path: Path) -> str:
    if not SAN_RE.fullmatch(san):
        raise ValueError("bad leaf name")
    key = str(key_path)
    if "'" in key or "\n" in key or "\r" in key:
        raise ValueError("bad key path")
    return SCRIPT.replace("__SAN__", san).replace("__KEY__", key)


def new_key_and_csr(san: str, key_path: Path, pwsh: str = "pwsh", timeout: float = 120) -> str:
    """Write a new key to key_path (owner-only) and return the CSR PEM. Raises OSError on any failure."""
    exe = shutil.which(pwsh) or pwsh
    encoded = base64.b64encode(script_for(san, key_path).encode("utf-16-le")).decode("ascii")
    try:
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], capture_output=True,
                           text=True, stdin=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        raise OSError("pwsh could not run") from e
    csr = r.stdout
    if r.returncode != 0 or "BEGIN CERTIFICATE REQUEST" not in csr or not Path(key_path).is_file():
        raise OSError(f"key and CSR not made (pwsh exit {r.returncode})")
    return csr
