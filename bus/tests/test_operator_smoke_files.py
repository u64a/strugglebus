"""Real non-root Linux file checks; only root ownership observations are simulated."""

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import time
import warnings

import pytest


SPEC = importlib.util.spec_from_file_location(
    "operator_smoke_files",
    Path(__file__).resolve().parents[1] / "deploy" / "files" / "strugglebus_disposable_smoke.py",
)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)
pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux file descriptors and permissions")


@pytest.fixture
def private_session(tmp_path, monkeypatch):
    directory = tmp_path / "strugglebus-smoke-session-test"
    directory.mkdir(mode=0o700)
    path = directory / "session.json"
    value = {
        "version": 1, "origin": "https://bus.invalid", "ca_path": str(tmp_path / "root.crt"),
        "ca_sha256": "0" * 64, "token": "t" * 43, "csrf": "c" * 43,
        "actor_id": "operator:owner:" + "1" * 32,
        "issued_at": int(time.time()), "expires_at": int(time.time()) + 900,
    }
    smoke._atomic_json(path, value)
    owners = {"directory": 0, "file": 0}

    def metadata(original, owner):
        fields = {name: getattr(original, name) for name in (
            "st_uid", "st_mode", "st_nlink", "st_size", "st_dev", "st_ino",
        )}
        return SimpleNamespace(**{**fields, "st_uid": owner})

    original_lstat = Path.lstat

    def lstat(current, *args, **kwargs):
        result = original_lstat(current, *args, **kwargs)
        return metadata(result, owners["directory"]) if current == directory else result

    class ProcessOS:
        def __getattr__(self, name):
            return getattr(os, name)

        def fstat(self, descriptor):
            return metadata(os.fstat(descriptor), owners["file"])

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(smoke, "os", ProcessOS())
    monkeypatch.setattr(smoke, "SESSION_ROOT", tmp_path)
    return path, value, owners


def test_private_session_reads_the_exact_opened_inode(private_session):
    path, value, _ = private_session
    assert smoke._read_operator_session(path) == value


@pytest.mark.parametrize("corruption", [
    "directory_mode", "file_mode", "directory_owner", "file_owner",
    "symlink", "hardlink", "fifo", "size", "duplicate", "parent_alias", "inode",
])
def test_private_session_rejects_unsafe_projection(private_session, monkeypatch, corruption):
    path, _, owners = private_session
    if corruption == "directory_mode":
        path.parent.chmod(0o750)
    elif corruption == "file_mode":
        path.chmod(0o640)
    elif corruption == "directory_owner":
        owners["directory"] = 12345
    elif corruption == "file_owner":
        owners["file"] = 12345
    elif corruption == "symlink":
        original = path.with_name("original.json")
        path.rename(original)
        path.symlink_to(original)
    elif corruption == "hardlink":
        os.link(path, path.with_name("alias.json"))
    elif corruption == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    elif corruption == "size":
        path.write_bytes(b" " * 8193)
    elif corruption == "duplicate":
        path.write_text('{"version":1,"version":1}', encoding="ascii")
    elif corruption == "parent_alias":
        alias = path.parent.with_name("strugglebus-smoke-alias")
        alias.symlink_to(path.parent, target_is_directory=True)
        path = alias / path.name
    else:
        monkeypatch.setattr(smoke, "_file_identity", lambda _: (-1, -1))
    with pytest.raises((smoke.SmokeError, OSError)):
        smoke._read_operator_session(path)


def test_public_ca_read_rejects_writable_or_symlinked_inputs(tmp_path):
    path = tmp_path / "root.crt"
    path.write_bytes(b"public fixture")
    path.chmod(0o644)
    assert smoke._ca_bytes(path) == b"public fixture"
    path.chmod(0o664)
    with pytest.raises(smoke.SmokeError):
        smoke._ca_bytes(path)
    path.chmod(0o644)
    alias = path.with_name("alias.crt")
    alias.symlink_to(path)
    with pytest.raises(OSError):
        smoke._ca_bytes(alias)


def test_password_never_uses_echoing_getpass_fallback(monkeypatch):
    import getpass

    class ProcessOS:
        name = "posix"

        @staticmethod
        def geteuid():
            return 0

    monkeypatch.setattr(smoke, "os", ProcessOS())
    monkeypatch.setattr(smoke, "sys", SimpleNamespace(stderr=SimpleNamespace(isatty=lambda: True)))

    def fallback(*args, **kwargs):
        warnings.warn("no echo control", getpass.GetPassWarning)
        pytest.fail("echoing fallback must not read a password")

    monkeypatch.setattr(getpass, "getpass", fallback)
    with pytest.raises(smoke.SmokeError, match="authentication"):
        smoke._operator_password()
