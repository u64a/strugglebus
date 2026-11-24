"""Normalize and verify byte-canonical wheels without adding dependencies.

The helper rewrites an already-built wheel into one canonical byte sequence that
depends only on the accepted commit timestamp and the exact uncompressed member
payloads. Member order, member names, and payload bytes are preserved exactly;
only ZIP metadata that a builder may vary (timestamps, modes, host system,
version fields, extra fields, comments) is replaced with fixed safe values. The
wheel ``RECORD`` is validated before and after normalization so a rewrite can
never silently alter, drop, or add packaged content.
"""

from __future__ import annotations

import argparse
import base64
import calendar
import csv
import hashlib
import io
import json
import os
import re
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

# Build/controller entry points use their qualified tree, not another install.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from strugglebus.release_wheel import (
    CANONICAL_COMPRESS_LEVEL,
    CANONICAL_CREATE_SYSTEM,
    CANONICAL_FILE_MODE,
    CANONICAL_ZIP_VERSION,
    CanonicalWheelError,
    MAX_MEMBERS,
    MAX_MEMBER_BYTES,
    MAX_NAME_LENGTH,
    MAX_RECORD_BYTES,
    MAX_WHEEL_BYTES,
    MEMBER_NAME_PATTERN,
    RECORD_HASH_PATTERN,
    ZIP_MAXIMUM_EPOCH,
    ZIP_MINIMUM_EPOCH,
    _canonical_info,
    _date_time_epoch,
    _load,
    _read_members,
    _record_digest,
    _record_name,
    _require_regular_member,
    _require_safe_name,
    _safe_regular_file,
    _sha256,
    _validate_record,
    canonical_date_time,
    verify_canonical_wheel,
)


def normalize_wheel(source: Path, destination: Path, *, timestamp: int) -> dict[str, Any]:
    """Write one canonical copy of ``source`` and return its verified identity."""

    date_time = canonical_date_time(timestamp)
    members, payloads = _load(source)
    if destination.exists() or destination.is_symlink():
        raise CanonicalWheelError(
            f"canonical wheel destination already exists: {destination.name}"
        )
    with zipfile.ZipFile(
        destination,
        mode="x",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=CANONICAL_COMPRESS_LEVEL,
    ) as archive:
        for info in members:
            archive.writestr(
                _canonical_info(info.filename, date_time),
                payloads[info.filename],
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=CANONICAL_COMPRESS_LEVEL,
            )
    result = verify_canonical_wheel(destination, timestamp=timestamp)
    if result["members"] != [info.filename for info in members]:
        raise CanonicalWheelError("canonical wheel member order or names changed")
    _, normalized_payloads = _load(destination)
    if normalized_payloads != payloads:
        raise CanonicalWheelError("canonical wheel payload bytes changed")
    return result


def resolve_source_date_epoch(value: str | None) -> int:
    """Resolve an accepted build timestamp from an argument or the environment."""

    text = value if value is not None else os.environ.get("SOURCE_DATE_EPOCH")
    if text is None or not text.strip():
        raise CanonicalWheelError("SOURCE_DATE_EPOCH is required and was not provided")
    text = text.strip()
    if not text.isdecimal() or len(text) > 12:
        raise CanonicalWheelError("SOURCE_DATE_EPOCH must be a decimal UTC timestamp")
    return int(text)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    normalize = subparsers.add_parser("normalize")
    normalize.add_argument("source", type=Path)
    normalize.add_argument("destination", type=Path)
    normalize.add_argument("--source-date-epoch")
    verify = subparsers.add_parser("verify")
    verify.add_argument("wheel", type=Path)
    verify.add_argument("--source-date-epoch")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if args.command == "normalize":
        result = normalize_wheel(
            args.source,
            args.destination,
            timestamp=resolve_source_date_epoch(args.source_date_epoch),
        )
    else:
        timestamp = (
            None
            if args.source_date_epoch is None
            else resolve_source_date_epoch(args.source_date_epoch)
        )
        result = verify_canonical_wheel(args.wheel, timestamp=timestamp)
    print(
        json.dumps(
            {
                "member_count": len(result["members"]),
                "record": result["record"],
                "sha256": result["sha256"],
                "size_bytes": result["size_bytes"],
                "source_date_epoch": result["source_date_epoch"],
                "wheel": result["wheel"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
