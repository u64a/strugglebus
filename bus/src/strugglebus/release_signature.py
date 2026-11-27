"""The publisher's signature on a release, for the server's own update path and the publisher.

A release's files are named, by SHA-256, in a short statement the project owner signs with a
hardware key. The statement and signature travel in the release's annotated tag. Everything that
decides whether a signature is good lives in one place, ``selfhost/fetch_release.py``, because
that file must also run alone, on the standard library, inside the self-hosted updaters. This
module loads that same code, so there is one implementation, and hands the final Ed25519 check
to the ``cryptography`` library, which is available here.
"""

from __future__ import annotations

import hashlib
import importlib.util
from collections.abc import Iterable
from functools import cache
from pathlib import Path
from types import ModuleType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

STATEMENT_FILE = "release-statement.txt"


class ReleaseSignatureError(Exception):
    """The release is not, verifiably, the one its publisher signed."""


@cache
def _fetcher() -> ModuleType:
    path = Path(__file__).resolve().parent / "selfhost" / "fetch_release.py"
    spec = importlib.util.spec_from_file_location("strugglebus._release_fetcher", path)
    if spec is None or spec.loader is None:  # pragma: no cover - the file ships with the package
        raise ReleaseSignatureError("the release verifier is missing from this installation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def library_verifies(public: bytes, message: bytes, signature: bytes) -> bool:
    """Ed25519 verification by the cryptography library."""
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def release_statement(version: str, digests: dict[str, str]) -> str:
    """The exact text the owner signs: the version and the SHA-256 of every release file."""
    return str(_fetcher().release_statement(version, digests))


def signed_digests(
    tag_message: str, version: str, *, keys: tuple[str, ...] | None = None,
) -> dict[str, str]:
    """
    The file hashes the publisher signed for ``version``, from the release tag's message.
    Raises unless a pinned release key signed exactly that statement for exactly that version.
    """
    fetcher = _fetcher()
    try:
        return dict(fetcher.signed_digests(tag_message, version, keys=keys, verifies=library_verifies))
    except fetcher.Problem as problem:
        raise ReleaseSignatureError(str(problem)) from None


def signer_of(signature: str, statement: str, *, keys: tuple[str, ...] | None = None) -> str | None:
    """The fingerprint of the pinned release key that signed ``statement``, or None."""
    result = _fetcher().signer_of(signature, statement.encode(), keys=keys, verifies=library_verifies)
    return None if result is None else str(result)


def verify_files(
    tag_message: str, version: str, files: Iterable[Path], *, keys: tuple[str, ...] | None = None,
) -> None:
    """
    Raises unless ``files`` are exactly the release the publisher signed for ``version``: every
    file named in the statement is there with the signed hash, and there is no file besides.
    """
    digests = signed_digests(tag_message, version, keys=keys)
    present = {path.name: path for path in files}
    if set(present) != set(digests):
        odd = sorted(set(present) ^ set(digests))[0]
        raise ReleaseSignatureError(f"{odd} is not in both the release and its signed statement")
    for name, path in present.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != digests[name]:
            raise ReleaseSignatureError(f"{name} is not the file the publisher signed")
