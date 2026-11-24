"""Validate exact Environment assignments in a rendered systemd unit."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path


def assignments(items: list[str], source: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise AssertionError(f"{source} assignment lacks '=': {item!r}")
        name, value = item.split("=", 1)
        if not name or name in parsed:
            raise AssertionError(f"{source} assignment is invalid or duplicated: {name!r}")
        parsed[name] = value
    return parsed


def validate(unit_path: Path, expected_items: list[str]) -> None:
    lines = unit_path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, start=1):
        if line.count("Environment=") > 1:
            raise AssertionError(
                f"{unit_path}:{line_number} contains multiple Environment= tokens"
            )

    rendered_items = [
        line.removeprefix("Environment=")
        for line in lines
        if line.startswith("Environment=")
    ]
    names = [item.split("=", 1)[0] for item in rendered_items]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise AssertionError(
            f"{unit_path} duplicates environment variables: {duplicates!r}"
        )

    rendered = assignments(rendered_items, "rendered")
    expected = assignments(expected_items, "expected")
    missing = sorted(expected.keys() - rendered.keys())
    extra = sorted(rendered.keys() - expected.keys())
    differing = {
        name: {"expected": expected[name], "rendered": rendered[name]}
        for name in sorted(expected.keys() & rendered.keys())
        if expected[name] != rendered[name]
    }
    if missing or extra or differing:
        raise AssertionError(
            f"{unit_path} environment mismatch: "
            f"missing={missing!r}, extra={extra!r}, differing={differing!r}"
        )


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit(
            f"usage: {Path(sys.argv[0]).name} UNIT NAME=VALUE [NAME=VALUE ...]"
        )
    validate(Path(sys.argv[1]), sys.argv[2:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
