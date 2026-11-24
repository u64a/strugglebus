"""Trusted read-only canonical wheel validation shared by release tools."""
from __future__ import annotations
import base64
import calendar
import csv
import hashlib
import io
import re
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

CANONICAL_FILE_MODE = 0o644


CANONICAL_CREATE_SYSTEM = 3


CANONICAL_ZIP_VERSION = 20


CANONICAL_COMPRESS_LEVEL = 9


ZIP_MINIMUM_EPOCH = 315532800


ZIP_MAXIMUM_EPOCH = 4102444799


MAX_WHEEL_BYTES = 256 * 1024 * 1024


MAX_MEMBERS = 8192


MAX_MEMBER_BYTES = 64 * 1024 * 1024


MAX_NAME_LENGTH = 255


MAX_RECORD_BYTES = 4 * 1024 * 1024


MEMBER_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9._+-]*(?:/[A-Za-z0-9_][A-Za-z0-9._+-]*)*$"
)


RECORD_HASH_PATTERN = re.compile(r"^sha256=([A-Za-z0-9_-]{43})$")


class CanonicalWheelError(RuntimeError):
    """The wheel is unsafe, malformed, or not canonically normalized."""


def _safe_regular_file(path: Path, maximum: int = MAX_WHEEL_BYTES) -> int:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise CanonicalWheelError(f"missing wheel: {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CanonicalWheelError(f"wheel is not a regular file: {path.name}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise CanonicalWheelError(f"wheel size is outside its limit: {path.name}")
    return metadata.st_size


def canonical_date_time(timestamp: int) -> tuple[int, int, int, int, int, int]:
    """Return the ZIP-safe fixed date/time for one accepted build timestamp."""

    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise CanonicalWheelError("canonical wheel timestamp must be an integer")
    if not ZIP_MINIMUM_EPOCH <= timestamp <= ZIP_MAXIMUM_EPOCH:
        raise CanonicalWheelError(
            "canonical wheel timestamp is outside the safe ZIP range"
        )
    # ZIP stores two-second resolution, so only even seconds survive a round trip.
    parts = time.gmtime(timestamp - timestamp % 2)
    return (
        parts.tm_year,
        parts.tm_mon,
        parts.tm_mday,
        parts.tm_hour,
        parts.tm_min,
        parts.tm_sec,
    )


def _date_time_epoch(date_time: tuple[int, ...]) -> int:
    if len(date_time) != 6:
        raise CanonicalWheelError("wheel member has an invalid timestamp")
    try:
        return calendar.timegm((*date_time, 0, 0, 0))
    except (OverflowError, ValueError) as error:
        raise CanonicalWheelError("wheel member has an invalid timestamp") from error


def _require_safe_name(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > MAX_NAME_LENGTH:
        raise CanonicalWheelError("wheel member name is not a bounded string")
    _require_ascii_file_name(name)
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise CanonicalWheelError(f"wheel member name traverses: {name!r}")
    if MEMBER_NAME_PATTERN.fullmatch(name) is None:
        raise CanonicalWheelError(f"wheel member name is unsafe: {name!r}")
    return name


def _require_ascii_file_name(name: str) -> None:
    if not name.isascii():
        raise CanonicalWheelError(f"wheel member name is not ASCII: {name!r}")
    if name.endswith("/"):
        raise CanonicalWheelError(f"wheel contains a directory entry: {name}")
    if "\\" in name:
        raise CanonicalWheelError(f"wheel member name is unsafe: {name!r}")


def _require_regular_member(info: zipfile.ZipInfo) -> None:
    if info.is_dir():
        raise CanonicalWheelError(f"wheel contains a directory entry: {info.filename}")
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        raise CanonicalWheelError(
            f"wheel member uses an unsupported compression: {info.filename}"
        )
    if info.file_size > MAX_MEMBER_BYTES:
        raise CanonicalWheelError(f"wheel member exceeds its size limit: {info.filename}")
    mode = info.external_attr >> 16
    if info.create_system == 0:
        if info.external_attr & 0x10:
            raise CanonicalWheelError(
                f"wheel contains a directory entry: {info.filename}"
            )
        return
    file_type = stat.S_IFMT(mode)
    if file_type not in {0, stat.S_IFREG}:
        raise CanonicalWheelError(
            f"wheel member is not a regular file: {info.filename}"
        )
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise CanonicalWheelError(
            f"wheel member requests a special mode: {info.filename}"
        )


def _read_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    if not members or len(members) > MAX_MEMBERS:
        raise CanonicalWheelError("wheel member count is outside its limit")
    seen: set[str] = set()
    for info in members:
        name = _require_safe_name(info.filename)
        if name in seen:
            raise CanonicalWheelError(f"wheel contains a duplicate member: {name}")
        seen.add(name)
        _require_regular_member(info)
    if archive.comment:
        raise CanonicalWheelError("wheel archive comment must be empty")
    return members


def _record_name(names: list[str]) -> str:
    records = [
        name
        for name in names
        if name.endswith(".dist-info/RECORD") and name.count("/") == 1
    ]
    if len(records) != 1:
        raise CanonicalWheelError("wheel must contain exactly one dist-info RECORD")
    return records[0]


def _record_digest(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
    return f"sha256={encoded.rstrip(b'=').decode('ascii')}"


def _validate_record(payloads: dict[str, bytes], names: list[str]) -> str:
    record_name = _record_name(names)
    content = payloads[record_name]
    if len(content) > MAX_RECORD_BYTES:
        raise CanonicalWheelError("wheel RECORD exceeds its size limit")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CanonicalWheelError("wheel RECORD is not valid UTF-8") from error
    if "\x00" in text:
        raise CanonicalWheelError("wheel RECORD contains a null byte")
    rows = [row for row in csv.reader(io.StringIO(text, newline="")) if row]
    listed: set[str] = set()
    for row in rows:
        name = _validate_record_row(row, listed, payloads, record_name)
        listed.add(name)
    if listed != set(payloads):
        raise CanonicalWheelError("wheel RECORD does not list every wheel member")
    return record_name


def _validate_record_row(row: list[str], listed: set[str],
                         payloads: dict[str, bytes], record_name: str) -> str:
    if len(row) != 3:
        raise CanonicalWheelError("wheel RECORD row is malformed")
    name, digest, size = row
    _require_safe_name(name)
    if name in listed:
        raise CanonicalWheelError(f"wheel RECORD lists a duplicate member: {name}")
    if name not in payloads:
        raise CanonicalWheelError(f"wheel RECORD lists a missing member: {name}")
    if name == record_name:
        if digest or size:
            raise CanonicalWheelError("wheel RECORD must not hash itself")
    else:
        _validate_record_hash(name, digest, size, payloads[name])
    return name


def _validate_record_hash(name: str, digest: str, size: str, payload: bytes) -> None:
    if RECORD_HASH_PATTERN.fullmatch(digest) is None:
        raise CanonicalWheelError(f"wheel RECORD hash is not SHA-256: {name}")
    if digest != _record_digest(payload):
        raise CanonicalWheelError(f"wheel RECORD hash mismatch: {name}")
    if not size.isdecimal() or int(size) != len(payload):
        raise CanonicalWheelError(f"wheel RECORD size mismatch: {name}")


def _load(path: Path) -> tuple[list[zipfile.ZipInfo], dict[str, bytes]]:
    _safe_regular_file(path)
    try:
        with zipfile.ZipFile(path) as archive:
            members = _read_members(archive)
            payloads: dict[str, bytes] = {}
            total = 0
            for info in members:
                with archive.open(info) as stream:
                    payload = stream.read(MAX_MEMBER_BYTES + 1)
                if len(payload) > MAX_MEMBER_BYTES or len(payload) != info.file_size:
                    raise CanonicalWheelError(
                        f"wheel member payload is invalid: {info.filename}"
                    )
                total += len(payload)
                if total > MAX_WHEEL_BYTES:
                    raise CanonicalWheelError("wheel payload exceeds its total limit")
                payloads[info.filename] = payload
    except (zipfile.BadZipFile, OSError) as error:
        raise CanonicalWheelError(f"wheel is not a readable ZIP archive: {path.name}") from error
    _validate_record(payloads, [info.filename for info in members])
    return members, payloads


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_info(name: str, date_time: tuple[int, ...]) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=date_time)  # type: ignore[arg-type]
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = CANONICAL_CREATE_SYSTEM
    info.create_version = CANONICAL_ZIP_VERSION
    info.extract_version = CANONICAL_ZIP_VERSION
    info.external_attr = (stat.S_IFREG | CANONICAL_FILE_MODE) << 16
    info.internal_attr = 0
    info.flag_bits = 0
    info.comment = b""
    info.extra = b""
    return info


def verify_canonical_wheel(
    wheel: Path,
    *,
    timestamp: int | None = None,
) -> dict[str, Any]:
    """Fail closed unless ``wheel`` is already canonical and RECORD-consistent."""

    members, payloads = _load(wheel)
    expected_date_time = (
        None if timestamp is None else canonical_date_time(timestamp)
    )
    observed: set[tuple[int, ...]] = set()
    for info in members:
        _verify_member_metadata(info)
        observed.add(tuple(info.date_time))
    if len(observed) != 1:
        raise CanonicalWheelError("wheel members do not share one fixed timestamp")
    date_time = next(iter(observed))
    if expected_date_time is not None and date_time != expected_date_time:
        raise CanonicalWheelError("wheel timestamp is not the accepted build timestamp")
    epoch = _date_time_epoch(date_time)
    if not ZIP_MINIMUM_EPOCH <= epoch <= ZIP_MAXIMUM_EPOCH or epoch % 2:
        raise CanonicalWheelError("wheel timestamp is not ZIP-safe")
    names = [info.filename for info in members]
    return {
        "members": names,
        "record": _validate_record(payloads, names),
        "sha256": _sha256(wheel),
        "size_bytes": wheel.stat().st_size,
        "source_date_epoch": epoch,
        "wheel": wheel.name,
    }


def _verify_member_origin(info: zipfile.ZipInfo) -> None:
    """The mode, host system and ZIP version the canonical builder stamps on each member."""
    name = info.filename
    if info.external_attr != (stat.S_IFREG | CANONICAL_FILE_MODE) << 16:
        raise CanonicalWheelError(f"wheel member mode is not canonical: {name}")
    if info.create_system != CANONICAL_CREATE_SYSTEM:
        raise CanonicalWheelError(f"wheel member host system is not canonical: {name}")
    if (info.create_version != CANONICAL_ZIP_VERSION
            or info.extract_version != CANONICAL_ZIP_VERSION):
        raise CanonicalWheelError(f"wheel member ZIP version is not canonical: {name}")


def _verify_member_metadata(info: zipfile.ZipInfo) -> None:
    _verify_member_origin(info)
    name = info.filename
    if info.flag_bits != 0 or info.internal_attr != 0:
        raise CanonicalWheelError(f"wheel member flags are not canonical: {name}")
    if info.extra or info.comment:
        raise CanonicalWheelError(f"wheel member carries extra metadata: {name}")
    if info.compress_type != zipfile.ZIP_DEFLATED:
        raise CanonicalWheelError(f"wheel member compression is not canonical: {name}")
