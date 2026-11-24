"""Validate a deployment wheel filename with packaging's canonical parser."""

from __future__ import annotations

import argparse
from pathlib import Path

from packaging.utils import InvalidWheelFilename, parse_wheel_filename


def validate_wheel_filename(path: Path) -> str:
    filename = path.name
    try:
        distribution, _, _, _ = parse_wheel_filename(filename)
    except InvalidWheelFilename as error:
        raise RuntimeError(f"invalid wheel filename: {filename}") from error
    if distribution != "strugglebus":
        raise RuntimeError("deployment wheel distribution must be strugglebus")
    return filename


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    validate_wheel_filename(args.wheel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
