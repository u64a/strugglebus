#!/usr/bin/python3
"""Safely export Caddy's public root certificate to a protected directory."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import ssl
import stat
import subprocess  # nosec B404
import sys
from typing import Callable


CERTIFICATE_NAME = "strugglebus-caddy-root.crt"
INSTRUCTIONS_NAME = "strugglebus-caddy-root.sha256.txt"
TEMPORARY_PREFIX = ".strugglebus-ca-export."
WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")


class ExportError(Exception):
    """A deliberately non-sensitive export failure."""


def _powershell_executable() -> str:
    if os.name == "nt":
        return r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    return "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"


def _contained_by(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _wsl_windows_path(value: str) -> tuple[Path, str] | None:
    windows_value: str | None = None
    if WINDOWS_ABSOLUTE.match(value):
        if os.name == "nt":
            return Path(value), str(PureWindowsPath(value))
        windows_value = str(PureWindowsPath(value))
        result = subprocess.run(  # nosec B603
            ["/usr/bin/wslpath", "-u", windows_value],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ExportError("destination path conversion failed")
        linux_path = Path(result.stdout.strip())
    else:
        linux_path = Path(value)
        if not re.match(r"^/mnt/[A-Za-z](?:/|$)", value):
            return None
        if (
            "WSL_DISTRO_NAME" not in os.environ
            and not Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
        ):
            return None
        result = subprocess.run(  # nosec B603
            ["/usr/bin/wslpath", "-w", value],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ExportError("destination path conversion failed")
        windows_value = result.stdout.strip()
    return linux_path, windows_value


def _windows_move(source: str, destination: str) -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$inputValue = [Console]::In.ReadToEnd() | ConvertFrom-Json
[IO.File]::Move($inputValue.source, $inputValue.destination)
"""
    result = subprocess.run(  # nosec B603
        [
            _powershell_executable(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        input=json.dumps(
            {"source": source, "destination": destination},
            ensure_ascii=True,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ExportError("atomic Windows publication failed")


def _windows_security_details(path: str) -> dict[str, bool] | None:
    script = r"""
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1" -Force
$inputValue = [Console]::In.ReadToEnd() | ConvertFrom-Json
$item = Get-Item -LiteralPath $inputValue.path -Force
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$unsafe = @(
  'Everyone',
  'BUILTIN\Users',
  'NT AUTHORITY\Authenticated Users',
  'BUILTIN\Guests',
  'ANONYMOUS LOGON'
)
$reparse = $false
$cursor = $item
while ($null -ne $cursor) {
  if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    $reparse = $true
  }
  $cursor = $cursor.Parent
}
$acl = Get-Acl -LiteralPath $item.FullName
$ownerOk = $acl.Owner -eq $current
$unsafeWrite = $false
foreach ($rule in $acl.Access) {
  $rights = $rule.FileSystemRights
  $writes = ($rights -band (
    [Security.AccessControl.FileSystemRights]::Write -bor
    [Security.AccessControl.FileSystemRights]::Modify -bor
    [Security.AccessControl.FileSystemRights]::FullControl -bor
    [Security.AccessControl.FileSystemRights]::Delete
  )) -ne 0
  if (
    $rule.AccessControlType -eq
      [Security.AccessControl.AccessControlType]::Allow -and
    $writes -and
    $unsafe -contains $rule.IdentityReference.Value
  ) {
    $unsafeWrite = $true
  }
}
[ordered]@{
  exists = $true
  directory = $item.PSIsContainer
  reparse = $reparse
  owner_ok = $ownerOk
  unsafe_write = $unsafeWrite
} | ConvertTo-Json -Compress
"""
    result = subprocess.run(  # nosec B603
        [
            _powershell_executable(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        input=json.dumps({"path": path}, ensure_ascii=True),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _windows_security(path: str, *, expect_directory: bool) -> bool:
    value = _windows_security_details(path)
    return (
        value == {
            "exists": True,
            "directory": expect_directory,
            "reparse": False,
            "owner_ok": True,
            "unsafe_write": False,
        }
    )


def _validate_linux_destination(path: Path) -> None:
    effective_uid = getattr(os, "geteuid", lambda: path.stat().st_uid)()
    cursor = path
    while True:
        metadata = cursor.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ExportError("destination has a symbolic-link parent")
        if cursor == path and (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != effective_uid
            or metadata.st_mode & 0o077
        ):
            raise ExportError("destination ownership or mode is unsafe")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent


def resolve_destination(
    value: str,
    *,
    repository_root: Path,
    windows_security: Callable[..., bool] = _windows_security,
    wsl_resolver: Callable[[str], tuple[Path, str] | None] = _wsl_windows_path,
) -> tuple[Path, str | None]:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ExportError("destination is invalid")
    wsl_value = wsl_resolver(value)
    windows_path: str | None = None
    if wsl_value is not None:
        candidate, windows_path = wsl_value
    else:
        candidate = Path(value)
    if not candidate.is_absolute():
        raise ExportError("destination must be absolute")
    if windows_path is None:
        try:
            _validate_linux_destination(candidate)
        except OSError as error:
            raise ExportError("destination cannot be resolved") from error
    try:
        destination = candidate.resolve(strict=True)
        repository = repository_root.resolve(strict=True)
    except OSError as error:
        raise ExportError("destination cannot be resolved") from error
    if _contained_by(destination, repository):
        raise ExportError("destination must be outside the repository")
    if not destination.is_dir():
        raise ExportError("destination is not a directory")
    if windows_path is not None and not windows_security(
        windows_path, expect_directory=True
    ):
        raise ExportError("destination Windows ACL or reparse policy is unsafe")
    return destination, windows_path


def _certificate_outputs(certificate: bytes) -> tuple[bytes, bytes]:
    try:
        text = certificate.decode("ascii")
        der = ssl.PEM_cert_to_DER_cert(text)
    except (UnicodeDecodeError, ValueError) as error:
        raise ExportError("certificate is not valid public PEM") from error
    digest = hashlib.sha256(der).hexdigest().upper()
    fingerprint = ":".join(digest[index : index + 2] for index in range(0, 64, 2))
    instructions = (
        f"SHA-256 fingerprint: {fingerprint}\n"
        "Verify this fingerprint through an independent trusted channel before "
        "installing the certificate on an authorized client.\n"
        "Keep TLS certificate verification enabled.\n"
    ).encode("ascii")
    return certificate, instructions


def _safe_existing(
    path: Path,
    expected: bytes,
    *,
    windows_path: str | None,
    windows_security: Callable[..., bool],
) -> bool:
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            return False
        if path.read_bytes() != expected:
            return False
        if windows_path is not None:
            return windows_security(
                str(PureWindowsPath(windows_path) / path.name),
                expect_directory=False,
            )
        return (
            metadata.st_uid == os.geteuid()
            and metadata.st_mode & 0o777 == 0o644
        )
    except OSError:
        return False


def export_certificate(
    destination_value: str,
    certificate: bytes,
    *,
    repository_root: Path,
    windows_security: Callable[..., bool] = _windows_security,
    windows_move: Callable[[str, str], None] = _windows_move,
    wsl_resolver: Callable[[str], tuple[Path, str] | None] = _wsl_windows_path,
    publish: Callable[[Path, Path], None] | None = None,
) -> None:
    destination, windows_path = resolve_destination(
        destination_value,
        repository_root=repository_root,
        windows_security=windows_security,
        wsl_resolver=wsl_resolver,
    )
    outputs = dict(
        zip(
            (CERTIFICATE_NAME, INSTRUCTIONS_NAME),
            _certificate_outputs(certificate),
            strict=True,
        )
    )
    stale = [
        item
        for item in destination.iterdir()
        if item.name.startswith(TEMPORARY_PREFIX)
    ]
    if stale:
        raise ExportError("unexpected temporary export file exists")
    existing = {name: destination / name for name in outputs}
    existing_count = sum(path.exists() or path.is_symlink() for path in existing.values())
    if existing_count:
        if existing_count != len(outputs) or any(
            not _safe_existing(
                existing[name],
                outputs[name],
                windows_path=windows_path,
                windows_security=windows_security,
            )
            for name in outputs
        ):
            raise ExportError("unexpected existing export target")
        return
    temporary: dict[str, Path] = {}
    published: list[Path] = []
    try:
        for name, content in outputs.items():
            path = destination / (
                f"{TEMPORARY_PREFIX}{secrets.token_hex(8)}.{name}.tmp"
            )
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary[name] = path
        for name in outputs:
            target = existing[name]
            if publish is not None:
                publish(temporary[name], target)
            elif windows_path is not None:
                windows_move(
                    str(PureWindowsPath(windows_path) / temporary[name].name),
                    str(PureWindowsPath(windows_path) / target.name),
                )
            else:
                os.link(temporary[name], target)
            published.append(target)
            target.chmod(0o644)
        if windows_path is not None:
            for name in outputs:
                target_windows = str(PureWindowsPath(windows_path) / name)
                if not windows_security(target_windows, expect_directory=False):
                    raise ExportError("exported file Windows ACL is unsafe")
    except BaseException:
        for path in reversed(published):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        for path in temporary.values():
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def main() -> int:
    try:
        value = json.load(sys.stdin)
        if (
            not isinstance(value, dict)
            or set(value) != {"certificate_base64", "destination"}
            or not isinstance(value["certificate_base64"], str)
            or not isinstance(value["destination"], str)
        ):
            raise ExportError("input is invalid")
        certificate = base64.b64decode(
            value["certificate_base64"], validate=True
        )
        export_certificate(
            value["destination"],
            certificate,
            repository_root=Path(__file__).resolve().parents[2],
        )
    except (ExportError, OSError, binascii.Error):
        print(
            json.dumps(
                {"exported": False, "error_code": "export_refused"},
                separators=(",", ":"),
            )
        )
        return 1
    print(
        json.dumps(
            {"exported": True, "error_code": "none"},
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
