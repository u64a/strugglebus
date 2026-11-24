"""Private, no-overwrite local files for human setup and recipient handoff."""

from __future__ import annotations

import os
import stat
# The sole child is system PowerShell running the fixed ACL inspection script.
import subprocess  # nosec B404
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from strugglebus.errors import ConfigurationError


def _kernel32():
    import ctypes

    return ctypes.WinDLL("kernel32", use_last_error=True)


def windows_directory() -> Path:
    if os.name != "nt":
        raise ConfigurationError("this operator connection requires Windows")
    return _query_windows_directory(_kernel32())


def _query_windows_directory(kernel) -> Path:
    import ctypes
    from ctypes import wintypes

    get_directory = kernel.GetWindowsDirectoryW
    get_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32_768)
    size = get_directory(buffer, len(buffer))
    if size == 0 or size >= len(buffer):
        raise ConfigurationError("trusted Windows directory is unavailable")
    return Path(buffer.value)


def _windows_security(path: Path, *, directory: bool, private: bool = True) -> None:
    executable = (
        windows_directory() / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    literal = str(path).replace("'", "''")
    script = r"""
$ErrorActionPreference = 'Stop'
$path = '__PATH__'
$isDirectory = __DIRECTORY__
$private = __PRIVATE__
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# SYSTEM, Administrators, and TrustedInstaller are Windows administrative owners.
$trusted = @(
  'S-1-5-18', 'S-1-5-32-544',
  'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)
if ($private) { $trusted = @($sid) + $trusted }
if ($isDirectory) { $item = [IO.DirectoryInfo]::new($path) }
else { $item = [IO.FileInfo]::new($path) }
if (-not $item.Exists) { exit 1 }
$cursor = $item
$leaf = $true
while ($null -ne $cursor) {
  if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 1 }
  $acl = $cursor.GetAccessControl()
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($private -and $leaf -and $owner -ne $sid) { exit 1 }
  if ($trusted -notcontains $owner) { exit 1 }
  $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
  foreach ($rule in $rules) {
    if (($rule.PropagationFlags -band
        [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
      continue
    }
    # OWNER RIGHTS grants rights only to the already-validated owner.
    if ($trusted -contains $rule.IdentityReference.Value -or
        $rule.IdentityReference.Value -eq 'S-1-3-4') { continue }
    $dangerous = [Security.AccessControl.FileSystemRights]::Delete -bor
      [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
      [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
      [Security.AccessControl.FileSystemRights]::TakeOwnership
    $dangerous = $dangerous -bor 0x10000000
    if ($leaf) {
      $dangerous = $dangerous -bor [Security.AccessControl.FileSystemRights]::Write -bor 0x40000000
    }
    if (($private -and $leaf) -or (($rule.FileSystemRights -band $dangerous) -ne 0)) { exit 1 }
  }
  if ($cursor -is [IO.FileInfo]) { $cursor = $cursor.Directory }
  else { $cursor = $cursor.Parent }
  $leaf = $false
}
exit 0
""".replace("__PATH__", literal).replace(
        "__DIRECTORY__", "$true" if directory else "$false"
        ).replace(
            "__PRIVATE__", "$true" if private else "$false"
    )
    try:
        # Native Windows-directory path; only quote-escaped literal data enters the fixed script.
        result = subprocess.run(  # nosec B603
            [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-Command", script],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigurationError("Windows security inspection failed") from None
    if result.returncode != 0:
        raise ConfigurationError("private path has unsafe Windows ACLs or parents")


def _require_unlinked(path: Path, metadata: os.stat_result, *, directory: bool) -> None:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(metadata.st_mode)
        or path.resolve(strict=True) != path
        or (not directory and metadata.st_nlink != 1)
        or getattr(metadata, "st_file_attributes", 0) & 0x400
    ):
        raise ConfigurationError("private path must not be linked")


def _require_outside_repositories(path: Path, *, directory: bool) -> None:
    for ancestor in (path if directory else path.parent, *path.parents):
        if (ancestor / ".git").exists():
            raise ConfigurationError("private files must remain outside repositories")


def _posix_parent_is_unsafe(parent: os.stat_result) -> bool:
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid not in {0, os.geteuid()}:
        return True
    # Group/other-writable is tolerated only for root-owned sticky directories.
    root_sticky = parent.st_uid == 0 and bool(parent.st_mode & stat.S_ISVTX)
    return bool(stat.S_IMODE(parent.st_mode) & 0o022) and not root_sticky


def _require_posix_private(path: Path, metadata: os.stat_result) -> None:
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ConfigurationError("private path has unsafe ownership or permissions")
    for ancestor in path.parents:
        if _posix_parent_is_unsafe(ancestor.lstat()):
            raise ConfigurationError("private path has unsafe parent permissions")


def require_private_path(
    path: Path, *, directory: bool, outside_repository: bool = False,
) -> None:
    """Reject links and unsafe ownership/access, including writable ancestors."""
    if not path.is_absolute():
        raise ConfigurationError("private path must be absolute")
    try:
        metadata = path.lstat()
        _require_unlinked(path, metadata, directory=directory)
        if outside_repository:
            _require_outside_repositories(path, directory=directory)
        if os.name == "nt":
            _windows_security(path, directory=directory)
        else:
            _require_posix_private(path, metadata)
    except (OSError, RuntimeError):
        raise ConfigurationError("private path is unavailable") from None


def open_private_output(path: Path, *, outside_repository: bool = True) -> int:
    """Reserve the destination before any remote mutation; return an owned FD."""
    require_private_path(
        path.parent, directory=True, outside_repository=outside_repository,
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        raise ConfigurationError("private output must be a new file") from None
    try:
        require_private_path(
            path, directory=False, outside_repository=outside_repository,
        )
        metadata = os.fstat(descriptor)
        current = path.lstat()
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise ConfigurationError("private output changed")
    except (ConfigurationError, OSError):
        os.close(descriptor)
        # Do not unlink a potentially substituted path.
        raise
    return descriptor


def read_private_file(path: Path, *, maximum: int) -> bytes:
    require_private_path(path, directory=False, outside_repository=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ConfigurationError("private input changed")
            value = os.read(descriptor, maximum + 1)
            after = os.fstat(descriptor)
            if (
                opened.st_size != len(value)
                or len(value) > maximum
                or (opened.st_mtime_ns, opened.st_ctime_ns)
                != (after.st_mtime_ns, after.st_ctime_ns)
            ):
                raise ConfigurationError("private input is too large or changed")
        finally:
            os.close(descriptor)
    except OSError:
        raise ConfigurationError("private input is unavailable") from None
    return value


def require_trusted_windows_program(path: Path) -> None:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.resolve(strict=True) != path
            or getattr(metadata, "st_file_attributes", 0) & 0x400
        ):
            raise ConfigurationError("trusted Windows program is unavailable")
    except (OSError, RuntimeError):
        raise ConfigurationError("trusted Windows program is unavailable") from None
    _windows_security(path, directory=False, private=False)


def _open_windows_lease(kernel, path: Path):
    """Open a handle that blocks replacement; return it with its closer."""
    import ctypes
    from ctypes import wintypes

    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, OPEN_REPARSE_POINT.
    handle = create(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise ConfigurationError("private SSH file cannot be leased safely")
    return handle, close


@contextmanager
def _windows_read_lease(kernel, path: Path) -> Iterator[None]:
    handle, close = _open_windows_lease(kernel, path)
    try:
        require_private_path(path, directory=False, outside_repository=True)
        yield
    finally:
        if not close(handle):
            raise ConfigurationError("private SSH file lease could not be released")


@contextmanager
def private_read_lease(path: Path) -> Iterator[None]:
    """Pin private SSH files without reading key bytes or allowing replacement."""
    if os.name != "nt":
        require_private_path(path, directory=False, outside_repository=True)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            yield
        finally:
            os.close(descriptor)
        return
    with _windows_read_lease(_kernel32(), path):
        yield
