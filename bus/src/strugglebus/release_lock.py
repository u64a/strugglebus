"""Validate a bounded, hash-pinned, index-resolved requirements file."""

from __future__ import annotations

import re
from pathlib import Path


MAX_LOCK_BYTES = 10 * 1024 * 1024
REQUIREMENT = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:\[[A-Za-z0-9,._-]+\])?"
    r"==[^\s]+"
)
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")


def validate_requirements_lock(path: Path) -> int:
    lock = path.resolve(strict=True)
    if lock.stat().st_size > MAX_LOCK_BYTES:
        raise RuntimeError("requirements lock exceeds the validation size limit")
    content = lock.read_text(encoding="utf-8")
    if "\x00" in content:
        raise RuntimeError("requirements lock contains NUL")

    lowered = f"\n{content.lower()}"
    blocked = (
        "\n-e ",
        "\n--editable ",
        "\nfile:",
        "\n./",
        "\n../",
        " @ ",
        "://",
    )
    if any(fragment in lowered for fragment in blocked):
        raise RuntimeError("requirements lock contains a local, editable, or URL dependency")

    blocks = _blocks(content)
    for block in blocks:
        _validate_block(block)
    return len(blocks)


def _blocks(content: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] = []
    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw_line[:1].isspace():
            if not current:
                raise RuntimeError("requirements lock has an orphan continuation")
            current.append(stripped)
            continue
        if current:
            blocks.append(current)
        current = [stripped]
    if current:
        blocks.append(current)
    if not blocks:
        raise RuntimeError("requirements lock does not contain dependencies")
    return blocks


def _validate_block(block: list[str]) -> None:
    requirement = block[0].removesuffix("\\").strip().split(";", 1)[0].strip()
    if REQUIREMENT.fullmatch(requirement) is None:
        raise RuntimeError(f"requirement is not exactly pinned: {requirement!r}")
    joined = " ".join(block)
    hash_options = re.findall(r"--hash=\S+", joined)
    if any(HASH.fullmatch(option.removesuffix("\\")) is None for option in hash_options):
        raise RuntimeError(f"requirement has an invalid hash: {requirement!r}")
    if not hash_options:
        raise RuntimeError(f"requirement is missing a SHA-256 hash: {requirement!r}")
