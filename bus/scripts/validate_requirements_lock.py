"""Validate a bounded, hash-pinned, index-resolved requirements file."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

# Controller/build entry points use the reviewed source tree, not another install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from strugglebus.release_lock import HASH, MAX_LOCK_BYTES, REQUIREMENT, validate_requirements_lock


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", type=Path)
    args = parser.parse_args()
    validate_requirements_lock(args.lock)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
