"""Protected output files, receipts and exit-code mapping of the operator CLI."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import strugglebus.cli as cli
from strugglebus.cli import (
    EXIT_AUTH,
    EXIT_CONFIG,
    EXIT_INTERRUPTED,
    EXIT_NETWORK,
    EXIT_OK,
    EXIT_SERVER,
    main,
)
from strugglebus.errors import AgentNotFoundError, ConfigurationError, StrugglebusError


class _OsProxy:
    """The real ``os`` module with a few attributes replaced for one module."""

    def __init__(self, **overrides: object) -> None:
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        overrides = self.__dict__["_overrides"]
        if name in overrides:
            return overrides[name]
        return getattr(os, name)


def _directory(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


def _write(path: Path, content: bytes = b"secret\n", *, strict_parent: bool = True) -> None:
    cli._write_protected_file(
        path, content, description="credential output", strict_parent=strict_parent,
    )


def _track_close(monkeypatch, **overrides):
    closed: list[int] = []
    real_close = os.close

    def close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(cli, "os", _OsProxy(close=close, **overrides))
    return closed


# --- Protected output files ---------------------------------------------------


def test_protected_file_is_created_private_with_exact_content(tmp_path):
    path = _directory(tmp_path) / "credential"

    _write(path, b"secret-value\n")

    assert path.read_bytes() == b"secret-value\n"
    metadata = path.stat()
    assert metadata.st_nlink == 1
    if os.name == "posix":
        assert stat.S_IMODE(metadata.st_mode) == 0o600


def test_protected_file_path_and_parent_must_be_usable(tmp_path):
    directory = _directory(tmp_path)
    blocker = directory / "blocker"
    blocker.write_bytes(b"file")

    with pytest.raises(ConfigurationError, match="^credential output path must be absolute$"):
        _write(Path("credential"))
    with pytest.raises(ConfigurationError, match="^credential output parent directory must exist$"):
        _write(directory / "absent" / "credential")
    with pytest.raises(ConfigurationError, match="^credential output parent directory must exist$"):
        _write(blocker / "credential")
    assert sorted(entry.name for entry in directory.iterdir()) == ["blocker"]


def test_protected_file_never_replaces_an_existing_path(tmp_path):
    path = _directory(tmp_path) / "credential"
    path.write_bytes(b"earlier")

    with pytest.raises(ConfigurationError, match="^credential output path already exists$") as raised:
        _write(path)
    assert isinstance(raised.value.__cause__, FileExistsError)
    assert path.read_bytes() == b"earlier"


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
@pytest.mark.parametrize("mode", [0o720, 0o702, 0o777])
def test_strict_parent_must_not_be_writable_by_other_accounts(tmp_path, mode):
    directory = _directory(tmp_path)
    directory.chmod(mode)
    path = directory / "credential"

    with pytest.raises(ConfigurationError, match="parent directory is not protected"):
        _write(path)
    assert not path.exists()

    _write(path, strict_parent=False)
    assert path.read_bytes() == b"secret\n"


def test_strict_parent_must_belong_to_the_current_account(monkeypatch, tmp_path):
    path = _directory(tmp_path) / "credential"
    monkeypatch.setattr(cli, "_effective_uid", lambda: 424242)

    with pytest.raises(ConfigurationError, match="parent directory is not protected"):
        _write(path)
    assert not path.exists()


def test_file_created_under_another_owner_is_removed(monkeypatch, tmp_path):
    path = _directory(tmp_path) / "credential"
    monkeypatch.setattr(cli, "_effective_uid", lambda: 424242)
    closed = _track_close(monkeypatch)

    with pytest.raises(ConfigurationError, match="could not be created safely") as raised:
        _write(path, strict_parent=False)
    assert str(raised.value.__cause__) == "created output descriptor is unsafe"
    assert not path.exists()
    assert len(closed) == 1


def test_effective_uid_is_absent_only_where_the_platform_has_none(monkeypatch):
    if hasattr(os, "geteuid"):
        assert cli._effective_uid() == os.geteuid()

    class _NoGeteuid:
        def __getattr__(self, name):
            if name == "geteuid":
                raise AttributeError(name)
            return getattr(os, name)

    monkeypatch.setattr(cli, "os", _NoGeteuid())
    assert cli._effective_uid() is None


def test_short_writes_are_continued_until_everything_is_stored(monkeypatch, tmp_path):
    path = _directory(tmp_path) / "credential"
    sizes = []

    def trickle(descriptor, view):
        sizes.append(len(view))
        return os.write(descriptor, bytes(view[:3]))

    monkeypatch.setattr(cli, "os", _OsProxy(write=trickle))

    _write(path, b"0123456789")

    assert path.read_bytes() == b"0123456789"
    assert sizes == [10, 7, 4, 1]


def test_write_that_makes_no_progress_removes_the_partial_file(monkeypatch, tmp_path):
    path = _directory(tmp_path) / "credential"
    closed = _track_close(monkeypatch, write=lambda descriptor, view: 0)

    with pytest.raises(ConfigurationError, match="could not be created safely") as raised:
        _write(path)
    assert str(raised.value.__cause__) == "protected output write did not progress"
    assert not path.exists()
    assert len(closed) == 1


def test_interrupt_during_write_removes_the_partial_file(monkeypatch, tmp_path):
    path = _directory(tmp_path) / "credential"

    def interrupt(descriptor, view):
        raise KeyboardInterrupt

    closed = _track_close(monkeypatch, write=interrupt)

    with pytest.raises(KeyboardInterrupt):
        _write(path)
    assert not path.exists()
    assert len(closed) == 1


@pytest.mark.skipif(os.name == "nt", reason="an open file cannot be renamed away on Windows")
def test_file_replaced_during_creation_is_rejected_and_the_replacement_kept(
    monkeypatch, tmp_path,
):
    directory = _directory(tmp_path)
    path = directory / "credential"

    def swap_then_sync(descriptor):
        os.fsync(descriptor)
        path.rename(directory / "moved-away")
        path.write_bytes(b"substituted")

    monkeypatch.setattr(cli, "os", _OsProxy(fsync=swap_then_sync))

    with pytest.raises(ConfigurationError, match="could not be created safely") as raised:
        _write(path)
    assert str(raised.value.__cause__) == "protected output changed during creation"
    # Only the file this call created may be removed; the substitute is not ours.
    assert path.read_bytes() == b"substituted"


def test_unchanged_output_check_compares_descriptor_and_path_identity(tmp_path):
    path = _directory(tmp_path) / "credential"
    path.write_bytes(b"x")
    descriptor = os.open(path, os.O_RDONLY)
    try:
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        cli._require_unchanged_output(descriptor, path, identity)
        with pytest.raises(OSError, match="protected output changed during creation"):
            cli._require_unchanged_output(descriptor, path, (identity[0], identity[1] + 1))
        os.link(path, path.parent / "second-name")
        with pytest.raises(OSError, match="protected output changed during creation"):
            cli._require_unchanged_output(descriptor, path, identity)
    finally:
        os.close(descriptor)


def test_directory_sync_failure_removes_the_new_file(monkeypatch, tmp_path):
    path = _directory(tmp_path) / "credential"

    def fail(directory):
        raise OSError("synthetic directory sync fault")

    monkeypatch.setattr(cli, "_fsync_directory", fail)

    with pytest.raises(ConfigurationError, match="could not be created safely"):
        _write(path)
    assert not path.exists()


def test_unlink_if_same_file_only_removes_the_identified_file(tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"x")
    identity = cli._file_identity(path)

    cli._unlink_if_same_file(path, None)
    cli._unlink_if_same_file(path, (identity[0], identity[1] + 1))
    assert path.exists()

    cli._unlink_if_same_file(path, identity)
    assert not path.exists()
    cli._unlink_if_same_file(path, identity)
    assert cli._file_identity_or_none(path) is None


@pytest.mark.skipif(os.name == "nt", reason="directories are not synced on Windows")
def test_directory_sync_reports_a_missing_directory(tmp_path):
    cli._fsync_directory(tmp_path)
    with pytest.raises(OSError):
        cli._fsync_directory(tmp_path / "absent")


def test_directory_sync_is_skipped_on_windows_and_closes_elsewhere(monkeypatch, tmp_path):
    opened = []
    monkeypatch.setattr(
        cli, "os", _OsProxy(name="nt", open=lambda *a: opened.append(a)),
    )
    cli._fsync_directory(tmp_path)
    assert opened == []

    synced = []
    closed = []

    def fail_sync(descriptor):
        synced.append(descriptor)
        raise OSError("synthetic sync fault")

    monkeypatch.setattr(
        cli,
        "os",
        _OsProxy(
            name="posix",
            open=lambda path, flags: 77,
            fsync=fail_sync,
            close=closed.append,
        ),
    )
    with pytest.raises(OSError, match="synthetic sync fault"):
        cli._fsync_directory(tmp_path)
    assert synced == [77]
    assert closed == [77]


# --- Secret writers -----------------------------------------------------------


def test_enrollment_token_writer_validates_the_token_shape(tmp_path):
    directory = _directory(tmp_path)

    for token in ("sbe1_short", "not-a-token", "sbe1_" + "é" * 66):
        with pytest.raises(ConfigurationError, match="enrollment token has an invalid format"):
            cli._write_enrollment_token(directory / "token", token)
    assert list(directory.iterdir()) == []


def test_spn_credential_writer_validates_the_credential_shape(tmp_path):
    directory = _directory(tmp_path)

    for secret in ("spn1_short", "sb1_" + "a" * 22 + "_" + "b" * 43, "café"):
        with pytest.raises(ConfigurationError, match="SPN credential has an invalid format"):
            cli._write_spn_credential(directory / "spn", secret)
    assert list(directory.iterdir()) == []


def test_agent_credential_writer_rejects_non_ascii_secrets(tmp_path):
    directory = _directory(tmp_path)

    with pytest.raises(ConfigurationError, match="credential secret has an invalid format"):
        cli._write_credential_secret(directory / "credential", "sb1_é")
    assert list(directory.iterdir()) == []


# --- Receipts -----------------------------------------------------------------


def _temporaries(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir() if entry.name.endswith(".tmp"))


def test_receipt_is_published_atomically_without_leftovers(tmp_path):
    directory = _directory(tmp_path)
    path = directory / "receipt.json"

    cli._write_atomic_receipt(path, b'{"version":1}\n')

    assert path.read_bytes() == b'{"version":1}\n'
    assert [entry.name for entry in directory.iterdir()] == ["receipt.json"]
    metadata = path.stat()
    assert metadata.st_nlink == 1
    if os.name == "posix":
        assert stat.S_IMODE(metadata.st_mode) == 0o600


def test_receipt_path_must_be_absolute():
    with pytest.raises(ConfigurationError, match="^receipt path must be absolute$"):
        cli._write_atomic_receipt(Path("receipt.json"), b"{}\n")


def test_receipt_never_replaces_an_existing_file(tmp_path):
    directory = _directory(tmp_path)
    path = directory / "receipt.json"
    path.write_bytes(b"earlier")

    with pytest.raises(ConfigurationError, match="^receipt path already exists$"):
        cli._write_atomic_receipt(path, b"{}\n")

    assert path.read_bytes() == b"earlier"
    assert [entry.name for entry in directory.iterdir()] == ["receipt.json"]


def test_receipt_swapped_at_publication_is_rejected_and_the_substitute_kept(
    monkeypatch, tmp_path,
):
    directory = _directory(tmp_path)
    path = directory / "receipt.json"

    def substitute(source, destination, **options):
        Path(destination).write_bytes(b"substituted")

    monkeypatch.setattr(cli, "os", _OsProxy(link=substitute))

    with pytest.raises(ConfigurationError, match="^receipt could not be created safely$"):
        cli._write_atomic_receipt(path, b"{}\n")

    # The file at the path is not the one this call created, so it is left alone.
    assert path.read_bytes() == b"substituted"
    assert _temporaries(directory) == []


def test_receipt_that_keeps_a_second_name_is_withdrawn(monkeypatch, tmp_path):
    directory = _directory(tmp_path)
    path = directory / "receipt.json"
    real_unlink = cli._unlink_if_same_file
    calls = []

    def keep_first_temporary(candidate, identity):
        calls.append(candidate)
        if len(calls) > 1:
            real_unlink(candidate, identity)

    monkeypatch.setattr(cli, "_unlink_if_same_file", keep_first_temporary)

    with pytest.raises(ConfigurationError, match="^receipt could not be created safely$"):
        cli._write_atomic_receipt(path, b"{}\n")

    assert list(directory.iterdir()) == []


def test_receipt_owned_by_another_account_is_withdrawn(monkeypatch, tmp_path):
    directory = _directory(tmp_path)
    path = directory / "receipt.json"
    real = cli._effective_uid()
    answers = iter([real, 424242])
    monkeypatch.setattr(cli, "_effective_uid", lambda: next(answers))

    with pytest.raises(ConfigurationError, match="^receipt could not be created safely$"):
        cli._write_atomic_receipt(path, b"{}\n")

    assert list(directory.iterdir()) == []


def test_receipt_is_withdrawn_when_the_directory_cannot_be_synced(monkeypatch, tmp_path):
    directory = _directory(tmp_path)
    path = directory / "receipt.json"
    calls = []

    def fail_second(target):
        calls.append(target)
        if len(calls) == 2:
            raise OSError("synthetic directory sync fault")

    monkeypatch.setattr(cli, "_fsync_directory", fail_second)

    with pytest.raises(ConfigurationError, match="^receipt could not be created safely$") as raised:
        cli._write_atomic_receipt(path, b"{}\n")

    assert isinstance(raised.value.__cause__, OSError)
    assert list(directory.iterdir()) == []
    # Once for the temporary file, once for publication, once after withdrawal.
    assert calls == [directory, directory, directory]


def _credential(**overrides) -> SimpleNamespace:
    values = {
        "id": "cred_" + "a" * 22,
        "status": "active",
        "version": 2,
        "identity_verified_at": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        "revoked_at": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _receipt(tmp_path: Path, credential: SimpleNamespace) -> dict[str, object]:
    path = _directory(tmp_path) / "receipt.json"
    cli._write_credential_receipt(
        path,
        operation_id="rotate-2026",
        agent=SimpleNamespace(name="builder"),
        credential=credential,
    )
    raw = path.read_bytes()
    assert raw.endswith(b"\n") and b" " not in raw
    return json.loads(raw)


def test_proved_credential_receipt_records_the_proof_time_in_utc(tmp_path):
    assert _receipt(tmp_path, _credential()) == {
        "version": 1,
        "operation_id": "rotate-2026",
        "agent_name": "builder",
        "credential_id": "cred_" + "a" * 22,
        "outcome": "proved",
        "credential_status": "active",
        "credential_version": 2,
        "observed_at": "2026-01-02T03:04:05Z",
    }


def test_revoked_credential_receipt_records_the_revocation_time_in_utc(tmp_path):
    revoked_at = datetime(2026, 1, 2, 5, 4, 5, tzinfo=timezone(timedelta(hours=2)))

    receipt = _receipt(tmp_path, _credential(status="revoked", revoked_at=revoked_at, version=3))

    assert receipt["outcome"] == "revoked"
    assert receipt["credential_status"] == "revoked"
    assert receipt["credential_version"] == 3
    assert receipt["observed_at"] == "2026-01-02T03:04:05Z"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"version": 0}, "credential evidence version is stale"),
        ({"status": "pending"}, "credential evidence state is invalid"),
        ({"identity_verified_at": None}, "credential evidence time is unavailable"),
        ({"status": "revoked"}, "credential evidence time is unavailable"),
    ],
    ids=["stale", "pending", "unproved", "revoked-without-time"],
)
def test_receipt_is_not_written_for_incomplete_evidence(tmp_path, overrides, message):
    directory = _directory(tmp_path)

    with pytest.raises(ConfigurationError, match=f"^{message}$"):
        cli._write_credential_receipt(
            directory / "receipt.json",
            operation_id="rotate-2026",
            agent=SimpleNamespace(name="builder"),
            credential=_credential(**overrides),
        )
    assert list(directory.iterdir()) == []


# --- Exit codes ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "code", "diagnostic"),
    [
        (ConfigurationError("bad setting"), EXIT_CONFIG, "configuration error: bad setting\n"),
        (cli._AuthenticationFailure("denied"), EXIT_AUTH, "authentication error: denied\n"),
        (cli._NetworkFailure("unreachable"), EXIT_NETWORK, "network error: unreachable\n"),
        (cli._ServerFailure("broken"), EXIT_SERVER, "server error: broken\n"),
        (AgentNotFoundError("no such agent"), EXIT_SERVER, "server error: no such agent\n"),
        (StrugglebusError("refused"), EXIT_SERVER, "server error: refused\n"),
        (KeyboardInterrupt(), EXIT_INTERRUPTED, "interrupted\n"),
    ],
    ids=["config", "auth", "network", "server", "not-found", "domain", "interrupt"],
)
def test_expected_failures_map_to_stable_exit_codes(monkeypatch, error, code, diagnostic):
    def handler(args, *, stdout, stderr):
        raise error

    monkeypatch.setattr(cli, "_health", handler)
    output, diagnostics = io.StringIO(), io.StringIO()

    assert main(["health"], stdout=output, stderr=diagnostics) == code
    assert diagnostics.getvalue() == diagnostic
    assert output.getvalue() == ""


def test_unexpected_failures_are_not_swallowed(monkeypatch):
    def handler(args, *, stdout, stderr):
        raise RuntimeError("programming error")

    monkeypatch.setattr(cli, "_health", handler)

    with pytest.raises(RuntimeError, match="programming error"):
        main(["health"], stdout=io.StringIO(), stderr=io.StringIO())


def test_handler_result_and_default_streams_are_passed_through(monkeypatch, capsys):
    def handler(args, *, stdout, stderr):
        stdout.write("to stdout\n")
        stderr.write("to stderr\n")
        return 17

    monkeypatch.setattr(cli, "_health", handler)
    monkeypatch.setattr(sys, "argv", ["strugglebus", "health", "--timeout", "2"])

    assert main() == 17
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("to stdout\n", "to stderr\n")


def test_closed_output_pipe_ends_quietly(monkeypatch):
    silenced = []

    def handler(args, *, stdout, stderr):
        raise cli._OutputClosed

    monkeypatch.setattr(cli, "_health", handler)
    monkeypatch.setattr(cli, "_silence_broken_stdout", silenced.append)
    output, diagnostics = io.StringIO(), io.StringIO()

    assert main(["health"], stdout=output, stderr=diagnostics) == EXIT_OK
    assert silenced == [output]
    assert diagnostics.getvalue() == ""


def test_operator_password_argument_errors_are_redacted(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["operator", "password", "--credential-file"])
    assert raised.value.code == cli.EXIT_USAGE
    error = capsys.readouterr().err
    assert "invalid operator password arguments" in error
    assert "--credential-file" not in error.splitlines()[-1]

    with pytest.raises(SystemExit):
        main(["tail", "--max-events", "0"])
    assert "must be positive" in capsys.readouterr().err


def test_broken_stdout_is_redirected_to_the_null_device(monkeypatch, tmp_path):
    target = tmp_path / "stdout.txt"
    with open(target, "w", encoding="ascii") as stream:
        cli._silence_broken_stdout(stream)
        os.write(stream.fileno(), b"still attached\n")

        monkeypatch.setattr(sys, "stdout", stream)
        cli._silence_broken_stdout(stream)
        os.write(stream.fileno(), b"discarded\n")
    assert target.read_bytes() == b"still attached\n"


def test_broken_stdout_without_a_descriptor_is_left_alone(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)

    cli._silence_broken_stdout(stream)

    stream.write("usable")
    assert stream.getvalue() == "usable"


# --- Argument types -----------------------------------------------------------


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["health", "--timeout", "soon"], "must be a number"),
        (["health", "--timeout", "0.05"], "must be between 0.1 and 60 seconds"),
        (["health", "--timeout", "61"], "must be between 0.1 and 60 seconds"),
        (["tail", "--since", "-1"], "must be zero or greater"),
        (["tail", "--since", "many"], "must be an integer"),
        (["tail", "--since", str(cli.MAX_SEQUENCE + 1)], "must not exceed"),
        (["tail", "--retries", "-2"], "must be zero or greater"),
        (["access-freeze", "freeze", "--reason", "   "], "must not be empty"),
        (["agent", "credential-evidence", "verify", "builder", "--credential-id", "cred_x",
          "--operation-id", "op", "--receipt-path", "r"], "must be cred_ followed by 22"),
        (["agent", "credential-evidence", "verify", "builder", "--credential-id",
          "cred_" + "a" * 22, "--operation-id", "Not-Lowercase", "--receipt-path", "r"],
         "must start with lowercase alphanumeric text"),
    ],
)
def test_argument_values_are_validated_as_usage_errors(capsys, arguments, message):
    with pytest.raises(SystemExit) as raised:
        main(arguments)

    assert raised.value.code == cli.EXIT_USAGE
    assert message in capsys.readouterr().err


def test_backup_command_requires_absolute_paths(monkeypatch, tmp_path):
    values = {
        "STRUGGLEBUS_DATA_DIR": str(tmp_path),
        "STRUGGLEBUS_RUNTIME_DIR": str(tmp_path / "run"),
        "STRUGGLEBUS_BACKUP_DIR": str(tmp_path / "backups"),
        "STRUGGLEBUS_DATABASE_PATH": str(tmp_path / "strugglebus.db"),
        "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": str(tmp_path / "admin-token"),
        "STRUGGLEBUS_PUBLIC_BASE_URL": "https://bus.lan",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    for arguments in (["--database", "relative.db"], ["--destination", "relative-dir"]):
        diagnostics = io.StringIO()
        assert main(["backup", *arguments], stdout=io.StringIO(), stderr=diagnostics) == EXIT_CONFIG
        assert diagnostics.getvalue() == "configuration error: backup paths must be absolute\n"
    assert not (tmp_path / "backups").exists()
