"""Validate tracked Linux scripts as raw bytes and kernel executables."""

from __future__ import annotations

import os
from pathlib import Path
# Subprocess is limited to fixed isolated helper paths in this offline test.
import subprocess  # nosec B404
import sys
import tempfile


REPOSITORY = Path(__file__).resolve().parents[2]
SCRIPT_SUFFIXES = {".bash", ".j2", ".py", ".sh"}
SCRIPT_ROOTS = ("deploy", "scripts", "src", "tests")
EXCLUDED_PARTS = {".ansible", ".ansible-venv", ".venv", "__pycache__"}
PRODUCTION_HELPERS = {
    Path("deploy/roles/guest_base/files/strugglebus-release-lock.py"):
        b"#!/usr/bin/python3.13\n",
    Path("deploy/roles/guest_base/files/strugglebus-validate-backup.py"):
        b"#!/usr/bin/python3.13\n",
    Path("deploy/roles/guest_base/files/strugglebus-validate-release.py"):
        b"#!/usr/bin/python3.13\n",
    Path("deploy/roles/systemd/templates/sqlite_backup.py.j2"):
        b"#!/usr/bin/python3.13\n",
}
BOMS = (
    b"\xef\xbb\xbf",
    b"\xff\xfe",
    b"\xfe\xff",
    b"\xff\xfe\x00\x00",
    b"\x00\x00\xfe\xff",
)


def repository_scripts() -> list[Path]:
    return sorted(
        path.relative_to(REPOSITORY)
        for root in SCRIPT_ROOTS
        for path in (REPOSITORY / root).rglob("*")
        if not EXCLUDED_PARTS.intersection(path.parts)
        and path.is_file()
        and path.suffix in SCRIPT_SUFFIXES
    )


def validate_bytes() -> None:
    for relative in repository_scripts():
        content = (REPOSITORY / relative).read_bytes()
        if content.startswith(BOMS):
            raise AssertionError(f"{relative} starts with a byte-order mark")
        if b"\r\n" in content:
            raise AssertionError(f"{relative} contains CRLF line endings")

    for relative, shebang in PRODUCTION_HELPERS.items():
        first_line = (REPOSITORY / relative).read_bytes().splitlines(keepends=True)[0]
        if first_line != shebang:
            raise AssertionError(
                f"{relative} first line is {first_line!r}, expected {shebang!r}"
            )


def validate_kernel_execution() -> None:
    if os.name != "posix":
        return
    with tempfile.TemporaryDirectory(prefix="strugglebus-helper-exec-") as directory:
        root = Path(directory)
        for relative, shebang in PRODUCTION_HELPERS.items():
            executable = root / relative.name.removesuffix(".j2")
            content = (REPOSITORY / relative).read_bytes()
            if not Path("/usr/bin/python3.13").is_file():
                portable_shebang = f"#!{Path(sys.executable).absolute()}\n".encode()
                content = portable_shebang + content.removeprefix(shebang)
            executable.write_bytes(content)
            executable.chmod(0o700)
            # The executable is an isolated copy from the fixed helper inventory.
            result = subprocess.run(  # nosec B603
                [str(executable)],
                cwd=root,
                env={"LANG": "C", "PATH": "/usr/bin:/bin"},
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr
            if result.returncode in {0, 126, 127} or "usage:" not in output.lower():
                raise AssertionError(
                    f"{relative} did not reach its argument parser through execve: "
                    f"rc={result.returncode}, output={output!r}"
                )


def main() -> int:
    validate_bytes()
    validate_kernel_execution()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
