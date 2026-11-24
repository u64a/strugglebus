import os

import pytest

from strugglebus.errors import ConfigurationError
from strugglebus.private_files import (
    open_private_output,
    read_private_file,
    require_private_path,
    require_trusted_windows_program,
    windows_directory,
)


def test_private_output_reserves_exclusively_and_reads_bounded(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "synthetic-key"
    descriptor = open_private_output(path)
    try:
        os.write(descriptor, b"synthetic-value\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    assert read_private_file(path, maximum=20) == b"synthetic-value\n"
    with pytest.raises(ConfigurationError):
        open_private_output(path)
    with pytest.raises(ConfigurationError):
        read_private_file(path, maximum=5)
    assert path.read_bytes() == b"synthetic-value\n"


def test_private_outputs_are_never_inside_a_repository(tmp_path):
    (tmp_path / ".git").write_text("gitdir: synthetic-worktree-reference")
    path = tmp_path / "credential"
    with pytest.raises(ConfigurationError, match="outside repositories"):
        open_private_output(path)
    assert not path.exists()


def test_private_inputs_reject_hard_links(tmp_path):
    path = tmp_path / "credential"
    path.write_bytes(b"synthetic")
    os.link(path, tmp_path / "linked")
    with pytest.raises(ConfigurationError, match="linked"):
        require_private_path(path, directory=False)


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership/mode contract")
def test_private_input_rejects_broad_permissions_and_symlinks(tmp_path):
    path = tmp_path / "credential"
    path.write_bytes(b"synthetic")
    path.chmod(0o644)
    with pytest.raises(ConfigurationError, match="permissions"):
        require_private_path(path, directory=False)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ConfigurationError, match="linked"):
        require_private_path(link, directory=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows protected executable ACLs")
def test_windows_program_requires_administrative_ownership(tmp_path):
    program = tmp_path / "untrusted-program.exe"
    program.write_bytes(b"synthetic non-executable")
    with pytest.raises(ConfigurationError):
        require_trusted_windows_program(program)
    trusted = (
        windows_directory() / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    require_trusted_windows_program(trusted)


@pytest.mark.skipif(os.name != "nt", reason="real Windows ACL script literal escaping")
def test_windows_acl_path_is_literal_not_powershell_code(tmp_path):
    path = tmp_path / "private'; throw 'synthetic-not-code"
    descriptor = open_private_output(path)
    try:
        os.write(descriptor, b"synthetic protected data")
    finally:
        os.close(descriptor)
    assert read_private_file(path, maximum=64) == b"synthetic protected data"
