"""Fail-closed OpenSSH public key validation for guest provisioning."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any


_PUBLIC_KEY = re.compile(
    r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|"
    r"sk-ssh-ed25519@openssh\.com) ([A-Za-z0-9+/]+={0,3})"
    r"(?: [ -~]{1,128})?"
)


def _ssh_strings(blob: bytes) -> list[bytes]:
    fields: list[bytes] = []
    offset = 0
    while offset < len(blob):
        if len(blob) - offset < 4:
            raise ValueError("truncated SSH string length")
        length = int.from_bytes(blob[offset : offset + 4], "big")
        offset += 4
        if length > len(blob) - offset:
            raise ValueError("truncated SSH string")
        fields.append(blob[offset : offset + length])
        offset += length
    return fields


def public_key_errors(value: Any) -> list[str]:
    if not isinstance(value, str):
        return ["public key is invalid"]
    match = _PUBLIC_KEY.fullmatch(value.strip())
    if match is None:
        return ["public key is not an allowed OpenSSH key"]
    declared_type, encoded = match.groups()
    try:
        blob = base64.b64decode(encoded, validate=True)
        fields = _ssh_strings(blob)
    except (binascii.Error, ValueError):
        return ["public key wire data is malformed"]
    if not fields or fields[0] != declared_type.encode("ascii"):
        return ["public key type does not match its wire data"]
    if declared_type == "ssh-ed25519":
        valid = len(fields) == 2 and len(fields[1]) == 32
    elif declared_type == "ssh-rsa":
        valid = (
            len(fields) == 3
            and 0 < len(fields[1]) <= 8
            and len(fields[2]) >= 128
        )
    elif declared_type.startswith("ecdsa-sha2-"):
        curve = declared_type.removeprefix("ecdsa-sha2-")
        point_sizes = {"nistp256": 65, "nistp384": 97, "nistp521": 133}
        valid = (
            len(fields) == 3
            and fields[1] == curve.encode("ascii")
            and len(fields[2]) == point_sizes[curve]
            and fields[2].startswith(b"\x04")
        )
    else:
        valid = (
            len(fields) == 3
            and len(fields[1]) == 32
            and 0 < len(fields[2]) <= 1024
        )
    return [] if valid else ["public key wire data is incomplete"]


class FilterModule:
    def filters(self) -> dict[str, Any]:
        return {"strugglebus_public_key_errors": public_key_errors}
