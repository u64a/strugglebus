#!/usr/bin/env python3
"""Prints the statement the owner signs for a release: its version and the hash of every file.

    python scripts/release_statement.py BUNDLE_DIR --tag v0.2.72 > release-statement.txt
    ssh-keygen -Y sign -f <release key> -n strugglebus-bus-release release-statement.txt

The signature (release-statement.txt.sig) is then given to publish_public_release.py, which
puts the statement and the signature in the release's tag. Installed buses refuse a release
whose files are not the ones in a statement signed by a release key.

The statement is written as exact bytes with LF line ends. Redirect it to a file from a shell
that does not rewrite line ends, or use --output.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from strugglebus.release_signature import release_statement
from strugglebus.release_validation import TAG_PATTERN


def statement_for(directory: Path, tag: str) -> str:
    if TAG_PATTERN.fullmatch(tag) is None:
        raise SystemExit(f"error: {tag!r} is not a release tag such as v0.2.72")
    files = sorted(path for path in directory.iterdir() if path.is_file())
    if not files:
        raise SystemExit(f"error: {directory} holds no release files")
    return release_statement(
        tag.removeprefix("v"), {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
    )


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directory", type=Path, help="the folder holding the release's files, and nothing else")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", type=Path, help="write the statement here instead of printing it")
    options = parser.parse_args(arguments)
    statement = statement_for(options.directory, options.tag)
    if options.output is None:
        sys.stdout.buffer.write(statement.encode())
    else:
        options.output.write_bytes(statement.encode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
