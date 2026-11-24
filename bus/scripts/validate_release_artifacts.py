"""Validate that release distributions contain only deployable application files."""

from __future__ import annotations

import argparse
from email.parser import BytesParser
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser


def _single(directory: Path, pattern: str) -> Path:
    matches = tuple(directory.glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one {pattern!r} artifact, found {len(matches)}"
        )
    return matches[0]


def _runtime_files(repository: Path) -> set[str]:
    source = repository / "src" / "strugglebus"
    return {
        (PurePosixPath("strugglebus") / path.relative_to(source)).as_posix()
        for path in source.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and ".egg-info" not in path.as_posix()
    }


def _assert_safe_names(names: set[str]) -> None:
    forbidden_parts = {
        ".git",
        ".github",
        ".pytest_cache",
        "__pycache__",
        "deploy",
        "inventory",
        "tests",
        "var",
    }
    forbidden_names = {".env", "admin-token"}
    forbidden_suffixes = (
        ".db",
        ".db-shm",
        ".db-wal",
        ".pyc",
        ".pyo",
        ".retry",
        ".vault",
    )
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name:
            raise RuntimeError(f"unsafe archive path: {name}")
        if forbidden_parts.intersection(path.parts):
            raise RuntimeError(f"forbidden release content: {name}")
        if path.name in forbidden_names or path.name.endswith(forbidden_suffixes):
            raise RuntimeError(f"forbidden release content: {name}")


def _validate_wheel(wheel: Path, runtime_files: set[str]) -> tuple[str, str]:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        _assert_safe_names(names)
        missing = runtime_files - names
        if missing:
            raise RuntimeError(f"wheel is missing runtime files: {sorted(missing)}")

        entry_points = [
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        ]
        if len(entry_points) != 1:
            raise RuntimeError("wheel must contain one entry_points.txt")
        entry_point_text = archive.read(entry_points[0]).decode("utf-8")
        if "strugglebus = strugglebus.cli:main" not in entry_point_text:
            raise RuntimeError("wheel does not expose the strugglebus CLI")

        metadata_files = [
            name
            for name in names
            if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_files) != 1:
            raise RuntimeError("wheel must contain one METADATA file")
        metadata = BytesParser().parsebytes(archive.read(metadata_files[0]))
        if metadata.get("Name") != "strugglebus":
            raise RuntimeError("wheel metadata has an unexpected package name")
        version = metadata.get("Version")
        if version is None:
            raise RuntimeError("wheel metadata is missing its version")
        if metadata.get("Requires-Python") != "<3.14,>=3.13":
            raise RuntimeError("wheel metadata has unexpected Python support")
        expected_name = f"strugglebus-{version}-py3-none-any.whl"
        if wheel.name != expected_name:
            raise RuntimeError("wheel does not use the canonical pure-Python filename")
        return version, metadata.get("Requires-Python")


def _validate_sdist(
    sdist: Path,
    runtime_files: set[str],
    version: str,
) -> None:
    with tarfile.open(sdist, mode="r:gz") as archive:
        names = {member.name for member in archive.getmembers()}
        _assert_safe_names(names)
        roots = {PurePosixPath(name).parts[0] for name in names if name}
        root = f"strugglebus-{version}"
        if roots != {root}:
            raise RuntimeError(f"unexpected sdist roots: {sorted(roots)}")
        expected = {
            f"{root}/LICENSE",
            f"{root}/MANIFEST.in",
            f"{root}/README.md",
            f"{root}/pyproject.toml",
            f"{root}/requirements.lock",
            *{
                f"{root}/src/{runtime_file}"
                for runtime_file in runtime_files
            },
        }
        missing = expected - names
        if missing:
            raise RuntimeError(f"sdist is missing release files: {sorted(missing)}")


def main() -> int:
    args = _parser().parse_args()
    repository = args.repository.resolve(strict=True)
    dist = args.dist.resolve(strict=True)
    runtime_files = _runtime_files(repository)
    if not runtime_files:
        raise RuntimeError("no runtime package files were found")
    version, _ = _validate_wheel(_single(dist, "*.whl"), runtime_files)
    sdists = tuple(dist.glob("*.tar.gz"))
    if len(sdists) > 1:
        raise RuntimeError(f"expected at most one sdist artifact, found {len(sdists)}")
    if sdists:
        _validate_sdist(sdists[0], runtime_files, version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
