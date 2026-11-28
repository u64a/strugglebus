"""The Claude token, sealed by the App to one host's key, and opened by that host (docs/app-host-integration.md 4a).

The bus only ever relays ciphertext. The scheme, exactly (the App's side must make the same bytes; the shared vector
is contracts/claude-token/):

  shared = X25519(the App's one-off private key, the host's public key)      refused if all zero
  key    = HKDF-SHA256(ikm = shared, salt = epk || host public key,           32 bytes
                       info = "strugglebus-claude-token v1")
  aad    = UTF-8 of "<host agent name>\\n<command nonce>"                    so it opens for no other host or command
  ct     = base64(IV (12) || AES-256-GCM(key, IV, token, aad) || tag (16))
  epk    = base64(the App's one-off public key)

HKDF is RFC 5869 written over hmac and hashlib (standard library), not CNG's KDF, whose availability and layout vary
by Windows build (u64-security, #humans 29172). X25519 and AES-GCM are the operating system's (workerhost/cng.py).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os

from . import cng

INFO = b"strugglebus-claude-token v1"
MAX_TOKEN = 512  # a Claude setup-token is about 108 characters


class SealError(Exception):
    """Can't be opened: malformed, or the wrong key, or changed bytes (the status says `decrypt`)."""


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with SHA-256."""
    if length > 255 * 32:
        raise ValueError("HKDF output too long")
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, block = b"", b""
    for i in range(1, -(-length // 32) + 1):
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
    return out[:length]


def aad(agent: str, nonce: str) -> bytes:
    return f"{agent}\n{nonce}".encode("utf-8")


def _key(shared: bytes, epk: bytes, host_public: bytes) -> bytes:
    return hkdf_sha256(shared, epk + host_public, INFO, 32)


def seal(token: str, host_public: bytes, agent: str, nonce: str, *, ephemeral: bytes | None = None,
         iv: bytes | None = None) -> tuple[str, str]:
    """(epk, ct), both base64: what the App puts in a sign-in-claude command. `ephemeral` and `iv` are for the
    fixed test vector only; left out, they come from the OS."""
    data = token.encode("utf-8")
    if not data or len(data) > MAX_TOKEN:
        raise ValueError("token length")
    eph = ephemeral if ephemeral is not None else cng.x25519_generate()[0]
    epk = cng.x25519_public(eph)
    key = _key(cng.x25519(eph, host_public), epk, host_public)
    iv = iv if iv is not None else os.urandom(cng.IV)
    ct, tag = cng.aes256gcm_encrypt(key, iv, data, aad(agent, nonce))
    return base64.b64encode(epk).decode("ascii"), base64.b64encode(iv + ct + tag).decode("ascii")


def open_sealed(epk_b64: str, ct_b64: str, host_private: bytes, host_public: bytes, agent: str, nonce: str) -> str:
    """The token, or SealError for anything that isn't exactly a token sealed to this host for this command."""
    try:
        epk = base64.b64decode(epk_b64, validate=True)
        blob = base64.b64decode(ct_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise SealError("not base64") from None
    if len(epk) != 32 or not cng.IV + cng.TAG < len(blob) <= cng.IV + MAX_TOKEN + cng.TAG:
        raise SealError("length")
    iv, ct, tag = blob[:cng.IV], blob[cng.IV:-cng.TAG], blob[-cng.TAG:]
    try:
        key = _key(cng.x25519(host_private, epk), epk, host_public)
        token = cng.aes256gcm_decrypt(key, iv, ct, tag, aad(agent, nonce))
    except cng.CryptoError:
        raise SealError("decrypt") from None
    try:
        return token.decode("utf-8")
    except UnicodeDecodeError:
        raise SealError("not UTF-8") from None
