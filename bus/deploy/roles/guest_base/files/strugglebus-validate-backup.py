#!/usr/bin/python3.13
"""Validate that an explicit rollback backup is confined and protected."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import sys
import re
import sqlite3


class BackupValidationError(RuntimeError):
    pass


TOKEN_PATTERN = re.compile(r"^[0-9a-f]{64}$")
STAGING_MARGIN_BYTES = 64 * 1024 * 1024


def require_integrity(path: Path) -> None:
    try:
        with sqlite3.connect(
            f"{path.as_uri()}?mode=ro&immutable=1",
            uri=True,
        ) as database:
            database.execute("PRAGMA query_only = ON")
            integrity = database.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error as error:
        raise BackupValidationError(
            "rollback backup failed read-only integrity validation"
        ) from error
    if integrity != ("ok",):
        raise BackupValidationError(
            "rollback backup failed read-only integrity validation"
        )


def validate_backup(
    configured_root: Path,
    configured_candidate: Path,
    service_user: str,
    stage_directory: Path | None = None,
    stage_token: str | None = None,
    check_integrity: bool = False,
) -> dict[str, str]:
    if not configured_root.is_absolute() or not configured_candidate.is_absolute():
        raise BackupValidationError("backup paths must be absolute")
    if ".." in configured_candidate.parts:
        raise BackupValidationError("backup path traversal is forbidden")
    try:
        service_uid = pwd.getpwnam(service_user).pw_uid
    except KeyError as error:
        raise BackupValidationError("configured service user does not exist") from error

    try:
        root_metadata = configured_root.lstat()
        root = configured_root.resolve(strict=True)
    except (FileNotFoundError, RuntimeError) as error:
        raise BackupValidationError("backup root is missing or unresolvable") from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root != configured_root.absolute()
        or root_metadata.st_uid != service_uid
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise BackupValidationError("backup root ownership or permissions are unsafe")

    if configured_candidate.parent != configured_root:
        raise BackupValidationError("rollback backup must be a direct backup-root child")

    root_descriptor = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    opened_root_metadata = os.fstat(root_descriptor)
    if (
        opened_root_metadata.st_dev != root_metadata.st_dev
        or opened_root_metadata.st_ino != root_metadata.st_ino
    ):
        os.close(root_descriptor)
        raise BackupValidationError("backup root changed during validation")
    candidate_descriptor = -1
    try:
        candidate_descriptor = os.open(
            configured_candidate.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        candidate_metadata = os.fstat(candidate_descriptor)
        candidate = Path(f"/proc/self/fd/{candidate_descriptor}").resolve(strict=True)
        try:
            relative = candidate.relative_to(root)
        except ValueError as error:
            raise BackupValidationError("rollback backup escapes the backup root") from error
        if (
            candidate != configured_candidate.absolute()
            or len(relative.parts) != 1
            or not stat.S_ISREG(candidate_metadata.st_mode)
            or candidate_metadata.st_uid != service_uid
            or stat.S_IMODE(candidate_metadata.st_mode) != 0o600
            or candidate_metadata.st_nlink != 1
        ):
            raise BackupValidationError(
                "rollback backup ownership or permissions are unsafe"
            )

        result = {"backup": str(candidate)}
        if (stage_directory is None) != (stage_token is None):
            raise BackupValidationError(
                "rollback staging directory and token must be supplied together"
            )
        if stage_directory is not None and stage_token is not None:
            if not TOKEN_PATTERN.fullmatch(stage_token):
                raise BackupValidationError("rollback staging token is invalid")
            try:
                stage_metadata = stage_directory.lstat()
                canonical_stage_directory = stage_directory.resolve(strict=True)
            except (FileNotFoundError, RuntimeError) as error:
                raise BackupValidationError(
                    "rollback staging directory is missing or unresolvable"
                ) from error
            if (
                not stat.S_ISDIR(stage_metadata.st_mode)
                or canonical_stage_directory != stage_directory.absolute()
                or stage_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(stage_metadata.st_mode) != 0o700
            ):
                raise BackupValidationError(
                    "rollback staging directory ownership or permissions are unsafe"
                )
            required_bytes = candidate_metadata.st_size + STAGING_MARGIN_BYTES
            if shutil.disk_usage(canonical_stage_directory).free < required_bytes:
                raise BackupValidationError(
                    "rollback staging filesystem has insufficient free capacity"
                )
            staged = (
                canonical_stage_directory
                / f"rollback-backup-{stage_token}.db"
            )
            try:
                staged_descriptor = os.open(
                    staged,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600,
                )
            except OSError as error:
                raise BackupValidationError(
                    "rollback staging file could not be created safely"
                ) from error
            try:
                os.fchmod(staged_descriptor, 0o600)
                with os.fdopen(os.dup(candidate_descriptor), "rb") as source:
                    with os.fdopen(staged_descriptor, "wb", closefd=False) as target:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                        target.flush()
                        os.fsync(target.fileno())
                result["staged_backup"] = str(staged)
            except BaseException:
                os.close(staged_descriptor)
                staged.unlink(missing_ok=True)
                raise
            os.close(staged_descriptor)
        try:
            if check_integrity:
                integrity_path = Path(
                    result.get(
                        "staged_backup",
                        f"/proc/self/fd/{candidate_descriptor}",
                    )
                )
                require_integrity(integrity_path)
        except BackupValidationError:
            if "staged_backup" in result:
                Path(result["staged_backup"]).unlink(missing_ok=True)
            raise
        return result
    except FileNotFoundError as error:
        raise BackupValidationError("rollback backup is missing") from error
    except OSError as error:
        raise BackupValidationError("rollback backup could not be opened safely") from error
    finally:
        if candidate_descriptor >= 0:
            os.close(candidate_descriptor)
        os.close(root_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("backup_root", type=Path)
    parser.add_argument("backup", type=Path)
    parser.add_argument("service_user")
    parser.add_argument("--stage-directory", type=Path)
    parser.add_argument("--stage-token")
    parser.add_argument("--check-integrity", action="store_true")
    args = parser.parse_args()
    try:
        result = validate_backup(
            args.backup_root,
            args.backup,
            args.service_user,
            args.stage_directory,
            args.stage_token,
            args.check_integrity,
        )
    except BackupValidationError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
