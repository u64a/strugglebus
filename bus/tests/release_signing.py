"""A stand-in for the owner's hardware release key, for tests.

A real release is signed with a FIDO security key, which a test cannot touch. This makes
signatures of exactly the same shape with an ordinary Ed25519 key held in memory, so the
verifier runs its whole path: the OpenSSH wrapper, the hardware key's flags and counter, and
the Ed25519 check. Tests then tell the code under test to trust ``TEST_KEY.blob`` in place of
the real pinned keys.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_TYPE = b"sk-ssh-ed25519@openssh.com"
NAMESPACE = "strugglebus-bus-release"
TOUCHED_AND_PIN_VERIFIED = 0x05


def packed(*fields: bytes) -> bytes:
    return b"".join(len(field).to_bytes(4, "big") + field for field in fields)


class ReleaseKey:
    def __init__(self, application: bytes = b"ssh:strugglebus-test") -> None:
        self._private = Ed25519PrivateKey.generate()
        self.application = application
        self.public = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.key_blob = packed(KEY_TYPE, self.public, application)
        self.blob = base64.b64encode(self.key_blob).decode()

    def sign(
        self, message: bytes, *, namespace: str = NAMESPACE, flags: int = TOUCHED_AND_PIN_VERIFIED,
        counter: int = 7, algorithm: bytes = b"sha512", signature_type: bytes = KEY_TYPE,
        key_blob: bytes | None = None, trailing: bytes = b"", reserved: bytes = b"",
    ) -> str:
        """An armoured SSH signature of ``message``. The options make deliberately wrong ones."""
        digest = hashlib.new(algorithm.decode(), message).digest()
        wrapped = b"SSHSIG" + packed(namespace.encode(), reserved, algorithm, digest)
        device = bytes([flags]) + counter.to_bytes(4, "big")
        raw = self._private.sign(
            hashlib.sha256(self.application).digest() + device + hashlib.sha256(wrapped).digest(),
        )
        blob = (
            b"SSHSIG" + (1).to_bytes(4, "big")
            + packed(
                key_blob or self.key_blob, namespace.encode(), reserved, algorithm,
                packed(signature_type, raw) + device,
            )
            + trailing
        )
        text = base64.b64encode(blob).decode()
        lines = [text[index:index + 70] for index in range(0, len(text), 70)]
        return "\n".join(["-----BEGIN SSH SIGNATURE-----", *lines, "-----END SSH SIGNATURE-----"])

    def tag_message(self, statement: str, **options: object) -> str:
        """An annotated tag's message as a published release carries it."""
        return (
            "Strugglebus public release mirror v1\n{}\n"
            + statement
            + self.sign(statement.encode(), **options)  # type: ignore[arg-type]
            + "\n"
        )


def statement_for(version: str, files: dict[str, bytes]) -> str:
    lines = ["strugglebus-bus-release 1", f"version {version}"]
    lines += [f"{hashlib.sha256(files[name]).hexdigest()}  {name}" for name in sorted(files)]
    return "\n".join(lines) + "\n"


TEST_KEY = ReleaseKey()
