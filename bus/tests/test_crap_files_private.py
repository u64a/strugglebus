"""Platform-independent checks of the private-file guards.

The Windows-only paths reach the operating system through three seams: the
kernel32 handle, the PowerShell child process and ``os.name``. Each test here
replaces only those seams, so the decision logic runs on every platform.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import strugglebus.private_files as private_files
from strugglebus.errors import ConfigurationError
from strugglebus.private_files import (
    open_private_output,
    private_read_lease,
    read_private_file,
    require_private_path,
    require_trusted_windows_program,
    windows_directory,
)


class _OsProxy:
    """The real ``os`` module with a few attributes replaced for one module."""

    def __init__(self, **overrides: object) -> None:
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        overrides = self.__dict__["_overrides"]
        if name in overrides:
            return overrides[name]
        return getattr(os, name)


def _pretend_platform(monkeypatch, name: str, **overrides: object) -> None:
    monkeypatch.setattr(private_files, "os", _OsProxy(name=name, **overrides))


class _FakeFunction:
    def __init__(self, behaviour):
        self._behaviour = behaviour
        self.calls: list[tuple[object, ...]] = []
        self.argtypes = None
        self.restype = None

    def __call__(self, *arguments):
        self.calls.append(arguments)
        return self._behaviour(*arguments)


def _directory_kernel(value: str, *, size: int | None = None) -> SimpleNamespace:
    def get_directory(buffer, length):
        buffer.value = value
        return len(value) if size is None else size

    return SimpleNamespace(GetWindowsDirectoryW=_FakeFunction(get_directory))


def _lease_kernel(*, handle: object = 42, closes: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        CreateFileW=_FakeFunction(lambda *arguments: handle),
        CloseHandle=_FakeFunction(lambda opened: closes),
    )


def _private_file(tmp_path: Path) -> Path:
    directory = tmp_path.resolve()
    directory.chmod(0o700)
    path = directory / "synthetic-key"
    path.write_bytes(b"synthetic")
    path.chmod(0o600)
    return path


# --- Windows directory lookup -------------------------------------------------


def test_windows_directory_query_returns_the_reported_path_with_typed_call():
    kernel = _directory_kernel(r"C:\Windows")

    assert private_files._query_windows_directory(kernel) == Path(r"C:\Windows")

    function = kernel.GetWindowsDirectoryW
    assert function.argtypes == [ctypes.wintypes.LPWSTR, ctypes.wintypes.UINT]
    assert function.restype is ctypes.wintypes.UINT
    (buffer, length), = function.calls
    assert length == len(buffer) == 32_768


@pytest.mark.parametrize("size", [0, 32_768, 40_000])
def test_windows_directory_query_rejects_failed_or_truncated_results(size):
    kernel = _directory_kernel(r"C:\Windows", size=size)

    with pytest.raises(ConfigurationError, match="trusted Windows directory is unavailable"):
        private_files._query_windows_directory(kernel)


def test_windows_directory_uses_kernel32_only_on_windows(monkeypatch):
    kernel = _directory_kernel(r"D:\WinNT")
    monkeypatch.setattr(private_files, "_kernel32", lambda: kernel)

    _pretend_platform(monkeypatch, "posix")
    with pytest.raises(ConfigurationError, match="requires Windows"):
        windows_directory()
    assert kernel.GetWindowsDirectoryW.calls == []

    _pretend_platform(monkeypatch, "nt")
    assert windows_directory() == Path(r"D:\WinNT")


def test_kernel32_is_loaded_with_last_error_tracking(monkeypatch):
    loaded = []

    def load(name, **options):
        loaded.append((name, options))
        return "kernel-handle"

    monkeypatch.setattr(ctypes, "WinDLL", load, raising=False)

    assert private_files._kernel32() == "kernel-handle"
    assert loaded == [("kernel32", {"use_last_error": True})]


# --- PowerShell ACL inspection ------------------------------------------------


def _capture_powershell(monkeypatch, tmp_path, *, returncode=0, error=None):
    calls = []

    def run(command, **options):
        calls.append((command, options))
        if error is not None:
            raise error
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(private_files, "windows_directory", lambda: tmp_path)
    monkeypatch.setattr(
        private_files,
        "subprocess",
        SimpleNamespace(
            run=run,
            DEVNULL=subprocess.DEVNULL,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    return calls


def test_windows_security_runs_fixed_script_with_escaped_literal_path(
    monkeypatch, tmp_path,
):
    calls = _capture_powershell(monkeypatch, tmp_path)
    target = Path("C:/Users/o'brien/key'; throw 'not-code")

    private_files._windows_security(target, directory=False)

    (command, options), = calls
    executable = tmp_path / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    assert command[:5] == [
        str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
    ]
    script = command[5]
    assert len(command) == 6
    escaped = str(target).replace("'", "''")
    assert f"$path = '{escaped}'" in script
    assert "$isDirectory = $false" in script
    assert "$private = $true" in script
    assert "__PATH__" not in script
    assert "__DIRECTORY__" not in script
    assert "__PRIVATE__" not in script
    assert options == {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "timeout": 10,
        "check": False,
    }


def test_windows_security_passes_directory_and_shared_modes_to_the_script(
    monkeypatch, tmp_path,
):
    calls = _capture_powershell(monkeypatch, tmp_path)

    private_files._windows_security(tmp_path, directory=True, private=False)

    script = calls[0][0][5]
    assert "$isDirectory = $true" in script
    assert "$private = $false" in script


def test_windows_security_rejects_paths_the_script_refuses(monkeypatch, tmp_path):
    _capture_powershell(monkeypatch, tmp_path, returncode=1)

    with pytest.raises(ConfigurationError, match="unsafe Windows ACLs or parents"):
        private_files._windows_security(tmp_path / "key", directory=False)


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("powershell is missing"),
        PermissionError("blocked"),
        subprocess.TimeoutExpired("powershell.exe", 10),
    ],
    ids=["missing", "denied", "timeout"],
)
def test_windows_security_fails_closed_when_inspection_cannot_run(
    monkeypatch, tmp_path, error,
):
    _capture_powershell(monkeypatch, tmp_path, error=error)

    with pytest.raises(ConfigurationError, match="Windows security inspection failed") as raised:
        private_files._windows_security(tmp_path / "key", directory=False)
    assert raised.value.__cause__ is None


# --- Trusted Windows programs -------------------------------------------------


def _record_security(monkeypatch):
    inspected = []
    monkeypatch.setattr(
        private_files,
        "_windows_security",
        lambda path, **options: inspected.append((path, options)),
    )
    return inspected


def test_trusted_program_is_inspected_as_a_shared_administrative_file(
    monkeypatch, tmp_path,
):
    inspected = _record_security(monkeypatch)
    program = tmp_path.resolve() / "tool.exe"
    program.write_bytes(b"synthetic")

    require_trusted_windows_program(program)

    assert inspected == [(program, {"directory": False, "private": False})]


def test_trusted_program_rejects_missing_and_non_regular_paths_before_inspection(
    monkeypatch, tmp_path,
):
    inspected = _record_security(monkeypatch)
    directory = tmp_path.resolve()

    for candidate in (directory / "absent.exe", directory):
        with pytest.raises(ConfigurationError, match="trusted Windows program is unavailable"):
            require_trusted_windows_program(candidate)
    assert inspected == []


def test_trusted_program_rejects_non_canonical_paths_before_inspection(
    monkeypatch, tmp_path,
):
    inspected = _record_security(monkeypatch)
    directory = tmp_path.resolve()
    (directory / "bin").mkdir()
    program = directory / "bin" / "tool.exe"
    program.write_bytes(b"synthetic")

    with pytest.raises(ConfigurationError, match="trusted Windows program is unavailable"):
        require_trusted_windows_program(directory / "bin" / ".." / "bin" / "tool.exe")
    assert inspected == []


def test_trusted_program_rejects_reparse_points_before_inspection(monkeypatch):
    inspected = _record_security(monkeypatch)

    class ReparsePoint:
        def lstat(self):
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_file_attributes=0x400)

        def resolve(self, strict):
            assert strict is True
            return self

    with pytest.raises(ConfigurationError, match="trusted Windows program is unavailable"):
        require_trusted_windows_program(ReparsePoint())
    assert inspected == []


def test_trusted_program_propagates_acl_rejection(monkeypatch, tmp_path):
    def reject(path, **options):
        raise ConfigurationError("private path has unsafe Windows ACLs or parents")

    monkeypatch.setattr(private_files, "_windows_security", reject)
    program = tmp_path.resolve() / "tool.exe"
    program.write_bytes(b"synthetic")

    with pytest.raises(ConfigurationError, match="unsafe Windows ACLs"):
        require_trusted_windows_program(program)


# --- Private path checks ------------------------------------------------------


def test_private_path_must_be_absolute():
    with pytest.raises(ConfigurationError, match="must be absolute"):
        require_private_path(Path("relative-key"), directory=False)


def test_private_path_reports_missing_files_as_unavailable(tmp_path):
    with pytest.raises(ConfigurationError, match="private path is unavailable"):
        require_private_path(tmp_path.resolve() / "absent", directory=False)


def test_private_path_requires_the_expected_kind(monkeypatch, tmp_path):
    _record_security(monkeypatch)
    path = _private_file(tmp_path)

    with pytest.raises(ConfigurationError, match="must not be linked"):
        require_private_path(path, directory=True)
    with pytest.raises(ConfigurationError, match="must not be linked"):
        require_private_path(path.parent, directory=False)


def test_private_path_on_windows_defers_to_acl_inspection_after_link_checks(
    monkeypatch, tmp_path,
):
    inspected = _record_security(monkeypatch)
    _pretend_platform(monkeypatch, "nt")
    path = _private_file(tmp_path)

    require_private_path(path, directory=False)
    require_private_path(path.parent, directory=True)

    assert inspected == [
        (path, {"directory": False}),
        (path.parent, {"directory": True}),
    ]

    os.link(path, path.parent / "second-name")
    with pytest.raises(ConfigurationError, match="must not be linked"):
        require_private_path(path, directory=False)
    assert len(inspected) == 2


def test_repository_check_covers_the_directory_itself_and_runs_before_ownership(
    monkeypatch, tmp_path,
):
    inspected = _record_security(monkeypatch)
    _pretend_platform(monkeypatch, "nt")
    path = _private_file(tmp_path)
    (path.parent / ".git").mkdir()

    with pytest.raises(ConfigurationError, match="outside repositories"):
        require_private_path(path, directory=False, outside_repository=True)
    with pytest.raises(ConfigurationError, match="outside repositories"):
        require_private_path(path.parent, directory=True, outside_repository=True)
    assert inspected == []

    require_private_path(path, directory=False)
    assert inspected == [(path, {"directory": False})]


def _stat(mode: int, uid: int) -> SimpleNamespace:
    return SimpleNamespace(st_mode=mode, st_uid=uid)


@pytest.mark.parametrize(
    ("mode", "uid", "unsafe"),
    [
        (stat.S_IFDIR | 0o700, 1000, False),
        (stat.S_IFDIR | 0o755, 1000, False),
        (stat.S_IFDIR | 0o755, 0, False),
        (stat.S_IFDIR | stat.S_ISVTX | 0o777, 0, False),
        (stat.S_IFDIR | 0o777, 0, True),
        (stat.S_IFDIR | 0o775, 1000, True),
        (stat.S_IFDIR | 0o757, 1000, True),
        (stat.S_IFDIR | stat.S_ISVTX | 0o777, 1000, True),
        (stat.S_IFDIR | 0o700, 2000, True),
        (stat.S_IFREG | 0o600, 1000, True),
    ],
    ids=[
        "own-private", "own-readable", "root-readable", "root-sticky-shared",
        "root-shared-not-sticky", "own-group-writable", "own-other-writable",
        "own-sticky-shared", "foreign-owner", "not-a-directory",
    ],
)
def test_posix_parent_safety_rules(monkeypatch, mode, uid, unsafe):
    _pretend_platform(monkeypatch, "posix", geteuid=lambda: 1000)

    assert private_files._posix_parent_is_unsafe(_stat(mode, uid)) is unsafe


class _FakeAncestor:
    def __init__(self, metadata):
        self._metadata = metadata

    def lstat(self):
        return self._metadata


def test_posix_private_requires_own_unshared_leaf_and_safe_ancestors(monkeypatch):
    _pretend_platform(monkeypatch, "posix", geteuid=lambda: 1000)
    safe = _FakeAncestor(_stat(stat.S_IFDIR | 0o700, 1000))
    shared = _FakeAncestor(_stat(stat.S_IFDIR | 0o777, 1000))
    leaf = _stat(stat.S_IFREG | 0o600, 1000)

    private_files._require_posix_private(SimpleNamespace(parents=[safe, safe]), leaf)

    for mode, uid in ((0o640, 1000), (0o604, 1000), (0o600, 0), (0o600, 2000)):
        with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
            private_files._require_posix_private(
                SimpleNamespace(parents=[safe]), _stat(stat.S_IFREG | mode, uid),
            )
    with pytest.raises(ConfigurationError, match="unsafe parent permissions"):
        private_files._require_posix_private(
            SimpleNamespace(parents=[safe, shared]), leaf,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership/mode contract")
def test_posix_private_path_rejects_a_group_writable_ancestor(tmp_path):
    path = _private_file(tmp_path)
    require_private_path(path, directory=False)
    require_private_path(path.parent, directory=True)

    path.parent.chmod(0o770)
    with pytest.raises(ConfigurationError, match="unsafe parent permissions"):
        require_private_path(path, directory=False)
    with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
        require_private_path(path.parent, directory=True)


# --- Private output and input -------------------------------------------------


def test_private_output_is_closed_and_kept_when_the_new_file_fails_inspection(
    monkeypatch, tmp_path,
):
    directory = tmp_path.resolve()
    path = directory / "credential"
    closed = []
    real_close = os.close

    def check(candidate, **options):
        if candidate == path:
            raise ConfigurationError("private path has unsafe ownership or permissions")

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(private_files, "require_private_path", check)
    monkeypatch.setattr(private_files, "os", _OsProxy(close=close))

    with pytest.raises(ConfigurationError, match="unsafe ownership"):
        open_private_output(path)

    assert len(closed) == 1
    # A possibly substituted path is never unlinked.
    assert path.exists()


def test_private_output_detects_a_replaced_file(monkeypatch, tmp_path):
    directory = tmp_path.resolve()
    path = directory / "credential"
    monkeypatch.setattr(private_files, "require_private_path", lambda *a, **k: None)
    real_fstat = os.fstat

    def fstat(descriptor):
        metadata = real_fstat(descriptor)
        return SimpleNamespace(st_dev=metadata.st_dev, st_ino=metadata.st_ino + 1)

    monkeypatch.setattr(private_files, "os", _OsProxy(fstat=fstat))

    with pytest.raises(ConfigurationError, match="private output changed"):
        open_private_output(path)


def test_private_input_detects_replacement_between_check_and_open(
    monkeypatch, tmp_path,
):
    path = _private_file(tmp_path)
    monkeypatch.setattr(private_files, "require_private_path", lambda *a, **k: None)
    real_fstat = os.fstat
    closed = []
    real_close = os.close

    def fstat(descriptor):
        metadata = real_fstat(descriptor)
        return SimpleNamespace(st_dev=metadata.st_dev, st_ino=metadata.st_ino + 1)

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(private_files, "os", _OsProxy(fstat=fstat, close=close))

    with pytest.raises(ConfigurationError, match="private input changed"):
        read_private_file(path, maximum=64)
    assert len(closed) == 1


def test_private_input_detects_modification_while_reading(monkeypatch, tmp_path):
    path = _private_file(tmp_path)
    monkeypatch.setattr(private_files, "require_private_path", lambda *a, **k: None)
    real_fstat = os.fstat
    observations = []

    def fstat(descriptor):
        metadata = real_fstat(descriptor)
        observations.append(metadata)
        return SimpleNamespace(
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns + len(observations),
            st_ctime_ns=metadata.st_ctime_ns,
        )

    monkeypatch.setattr(private_files, "os", _OsProxy(fstat=fstat))

    with pytest.raises(ConfigurationError, match="too large or changed"):
        read_private_file(path, maximum=64)


def test_private_input_reports_open_failures_as_unavailable(monkeypatch, tmp_path):
    path = _private_file(tmp_path)
    monkeypatch.setattr(private_files, "require_private_path", lambda *a, **k: None)

    def refuse(*arguments):
        raise PermissionError("synthetic denial")

    monkeypatch.setattr(private_files, "os", _OsProxy(open=refuse))

    with pytest.raises(ConfigurationError, match="private input is unavailable") as raised:
        read_private_file(path, maximum=64)
    assert raised.value.__cause__ is None


# --- Read leases --------------------------------------------------------------


def test_windows_lease_opens_without_following_links_and_releases_the_handle(
    monkeypatch, tmp_path,
):
    kernel = _lease_kernel(handle=42)
    checked = []
    monkeypatch.setattr(
        private_files,
        "require_private_path",
        lambda path, **options: checked.append((path, options)),
    )
    path = tmp_path / "id_ed25519"

    with private_files._windows_read_lease(kernel, path):
        assert kernel.CloseHandle.calls == []
        assert checked == [(path, {"directory": False, "outside_repository": True})]

    # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT.
    assert kernel.CreateFileW.calls == [
        (str(path), 0x80000000, 1, None, 3, 0x00200000, None),
    ]
    assert kernel.CreateFileW.restype is ctypes.wintypes.HANDLE
    assert kernel.CloseHandle.argtypes == [ctypes.wintypes.HANDLE]
    assert kernel.CloseHandle.calls == [(42,)]


@pytest.mark.parametrize("handle", [None, ctypes.c_void_p(-1).value])
def test_windows_lease_refuses_an_invalid_handle_without_inspecting_the_path(
    monkeypatch, tmp_path, handle,
):
    kernel = _lease_kernel(handle=handle)
    checked = []
    monkeypatch.setattr(
        private_files, "require_private_path", lambda *a, **k: checked.append(a),
    )

    with pytest.raises(ConfigurationError, match="cannot be leased safely"):
        with private_files._windows_read_lease(kernel, tmp_path / "key"):
            pytest.fail("the lease body must not run")
    assert checked == []
    assert kernel.CloseHandle.calls == []


def test_windows_lease_releases_the_handle_when_the_path_is_unsafe(
    monkeypatch, tmp_path,
):
    kernel = _lease_kernel(handle=7)

    def reject(path, **options):
        raise ConfigurationError("private path has unsafe Windows ACLs or parents")

    monkeypatch.setattr(private_files, "require_private_path", reject)

    with pytest.raises(ConfigurationError, match="unsafe Windows ACLs"):
        with private_files._windows_read_lease(kernel, tmp_path / "key"):
            pytest.fail("the lease body must not run")
    assert kernel.CloseHandle.calls == [(7,)]


def test_windows_lease_reports_a_handle_that_cannot_be_released(
    monkeypatch, tmp_path,
):
    kernel = _lease_kernel(handle=7, closes=False)
    monkeypatch.setattr(private_files, "require_private_path", lambda *a, **k: None)
    entered = []

    with pytest.raises(ConfigurationError, match="lease could not be released"):
        with private_files._windows_read_lease(kernel, tmp_path / "key"):
            entered.append(True)
    assert entered == [True]


def test_read_lease_selects_the_windows_handle_lease_on_windows(
    monkeypatch, tmp_path,
):
    kernel = _lease_kernel(handle=9)
    monkeypatch.setattr(private_files, "_kernel32", lambda: kernel)
    monkeypatch.setattr(private_files, "require_private_path", lambda *a, **k: None)
    _pretend_platform(monkeypatch, "nt")
    path = tmp_path / "key"

    with private_read_lease(path):
        assert kernel.CreateFileW.calls[0][0] == str(path)
        assert kernel.CloseHandle.calls == []
    assert kernel.CloseHandle.calls == [(9,)]


def test_read_lease_holds_a_descriptor_open_on_posix(monkeypatch, tmp_path):
    path = _private_file(tmp_path)
    checked = []
    monkeypatch.setattr(
        private_files,
        "require_private_path",
        lambda candidate, **options: checked.append((candidate, options)),
    )
    opened = []
    closed = []
    real_open, real_close = os.open, os.close

    def open_file(*arguments):
        descriptor = real_open(*arguments)
        opened.append(descriptor)
        return descriptor

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(
        private_files, "os", _OsProxy(name="posix", open=open_file, close=close),
    )

    with pytest.raises(RuntimeError, match="synthetic failure"):
        with private_read_lease(path):
            assert checked == [(path, {"directory": False, "outside_repository": True})]
            assert len(opened) == 1
            assert closed == []
            raise RuntimeError("synthetic failure")
    assert closed == opened
