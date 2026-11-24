"""Copy the install guide and the manual into a checkout of the public repository.

    python scripts/publish_public_docs.py <checkout of strugglebus-releases>

It writes files only: review the result with `git status` there, then commit
and push it yourself. Run it from the commit the release was made from, so
the public pages match the released version.

Layout written in the public repository:

    INSTALL.md            the install guide, where existing links expect it
    SECURITY.md           the security policy
    docs/INSTALL.md       the same guide, where the manual's links expect it
    docs/manual/*.md      the manual
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "src" / "strugglebus" / "selfhost"


def plan(root: Path) -> dict[str, Path]:
    """Public path -> source file."""
    kit = root / "src" / "strugglebus" / "selfhost"
    pages = sorted((kit / "manual").glob("*.md"))
    if not pages:
        raise FileNotFoundError(f"no manual pages under {kit / 'manual'}")
    files = {
        "INSTALL.md": kit / "INSTALL.md",
        "SECURITY.md": root / "SECURITY.md",
        "docs/INSTALL.md": kit / "INSTALL.md",
    }
    files.update({f"docs/manual/{page.name}": page for page in pages})
    return files


def publish(root: Path, target: Path) -> list[str]:
    if not (target / ".git").exists():
        raise NotADirectoryError(f"{target} is not a git checkout")
    files = plan(root)
    # A page removed from the manual must not linger in the public copy.
    manual = target / "docs" / "manual"
    if manual.is_dir():
        for stale in manual.glob("*.md"):
            if f"docs/manual/{stale.name}" not in files:
                stale.unlink()
    for public, source in files.items():
        destination = target / public
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    # The guide links to the manual beside it; from the repository root the
    # manual is one folder further down.
    guide = target / "INSTALL.md"
    guide.write_bytes(guide.read_bytes().replace(b"](manual/", b"](docs/manual/"))
    return sorted(files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", type=Path, help="checkout of the public releases repository")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    for name in publish(options.root, options.target.resolve()):
        print(name)
    print(f"written to {options.target.resolve()}; review, commit and push it there")
    return 0


if __name__ == "__main__":
    sys.exit(main())
