"""Windows' own cryptography (CNG, bcrypt.dll) through ctypes: X25519 and AES-256-GCM, nothing else.

The host is standard-library Python only, and Python's standard library has neither primitive, so the host calls the
operating system's implementation the way it already calls DPAPI (docs/app-host-integration.md 4a). No
cryptographic arithmetic is written here: only the calls and CNG's byte orders, which are pinned by tests against
RFC 7748 6.1 (X25519) and the GCM specification's test case 16 (AES-256-GCM).

CNG's curve25519, as measured against RFC 7748 (28 Nov 2026):
- a private key is the RFC's little-endian scalar, stored CLAMPED (CNG refuses an unclamped one; clamping is what
  X25519 does to a scalar anyway, so the result is the same);
- a public key is the RFC's bytes, unreversed;
- the raw shared secret (BCRYPT_KDF_RAW_SECRET) comes out REVERSED: it is reversed back here, before anything uses it
  (u64-security, #humans 29172).
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

KEY = 32
_PUBLIC_MAGIC, _PRIVATE_MAGIC = 0x504B4345, 0x564B4345  # BCRYPT_ECDH_PUBLIC/PRIVATE_GENERIC_MAGIC
_AUTH_TAG_MISMATCH = 0xC000A002


class CryptoError(Exception):
    pass


class AuthenticationFailed(CryptoError):
    """AES-GCM's tag didn't match: the wrong key, or changed bytes."""


def _lib():
    if sys.platform != "win32":
        raise CryptoError("CNG is Windows only")
    return ctypes.WinDLL("bcrypt.dll")


def _ok(status: int, what: str) -> None:
    if status != 0:
        code = status & 0xFFFFFFFF
        if code == _AUTH_TAG_MISMATCH:
            raise AuthenticationFailed(what)
        raise CryptoError(f"{what}: NTSTATUS 0x{code:08X}")


class _Provider:
    def __init__(self, algorithm: str, prop: tuple[str, str] | None):
        self.b = _lib()
        self.h = ctypes.c_void_p()
        _ok(self.b.BCryptOpenAlgorithmProvider(ctypes.byref(self.h), ctypes.c_wchar_p(algorithm), None, 0), "open")
        if prop:
            value = ctypes.create_unicode_buffer(prop[1])
            _ok(self.b.BCryptSetProperty(self.h, ctypes.c_wchar_p(prop[0]), value, ctypes.sizeof(value), 0), prop[0])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.b.BCryptCloseAlgorithmProvider(self.h, 0)


def _blob(magic: int, *parts: bytes) -> bytes:
    return magic.to_bytes(4, "little") + KEY.to_bytes(4, "little") + b"".join(parts)


def _import(p: _Provider, kind: str, data: bytes):
    key = ctypes.c_void_p()
    _ok(p.b.BCryptImportKeyPair(p.h, None, ctypes.c_wchar_p(kind), ctypes.byref(key), data, len(data), 0), kind)
    return key


def _export(p: _Provider, key, kind: str) -> bytes:
    n = wintypes.ULONG()
    _ok(p.b.BCryptExportKey(key, None, ctypes.c_wchar_p(kind), None, 0, ctypes.byref(n), 0), kind)
    out = ctypes.create_string_buffer(n.value)
    _ok(p.b.BCryptExportKey(key, None, ctypes.c_wchar_p(kind), out, n, ctypes.byref(n), 0), kind)
    return out.raw[:n.value]


def clamp(scalar: bytes) -> bytes:
    """RFC 7748's clamping of a little-endian X25519 scalar (what X25519 applies to any scalar)."""
    if len(scalar) != KEY:
        raise ValueError("an X25519 private key is 32 bytes")
    b = bytearray(scalar)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def _ecdh() -> _Provider:
    return _Provider("ECDH", ("ECCCurveName", "curve25519"))


def x25519_generate() -> tuple[bytes, bytes]:
    """A new key pair from the OS's generator: (private, public), each 32 bytes in RFC 7748's form."""
    with _ecdh() as p:
        key = ctypes.c_void_p()
        _ok(p.b.BCryptGenerateKeyPair(p.h, ctypes.byref(key), 255, 0), "generate")
        try:
            _ok(p.b.BCryptFinalizeKeyPair(key, 0), "finalize")
            blob = _export(p, key, "ECCPRIVATEBLOB")
        finally:
            p.b.BCryptDestroyKey(key)
    return blob[8 + 2 * KEY:8 + 3 * KEY], blob[8:8 + KEY]


def x25519_public(private: bytes) -> bytes:
    """The public key for a private key (RFC 7748's X25519(k, 9))."""
    with _ecdh() as p:
        key = _import(p, "ECCPRIVATEBLOB", _blob(_PRIVATE_MAGIC, bytes(KEY), bytes(KEY), clamp(private)))
        try:
            return _export(p, key, "ECCPUBLICBLOB")[8:8 + KEY]
        finally:
            p.b.BCryptDestroyKey(key)


def x25519(private: bytes, peer_public: bytes) -> bytes:
    """The shared secret, in RFC 7748's byte order. Refuses an all-zero result (a low-order peer key)."""
    if len(peer_public) != KEY:
        raise ValueError("an X25519 public key is 32 bytes")
    with _ecdh() as p:
        mine = _import(p, "ECCPRIVATEBLOB", _blob(_PRIVATE_MAGIC, bytes(KEY), bytes(KEY), clamp(private)))
        theirs = _import(p, "ECCPUBLICBLOB", _blob(_PUBLIC_MAGIC, peer_public, bytes(KEY)))
        secret = ctypes.c_void_p()
        try:
            _ok(p.b.BCryptSecretAgreement(mine, theirs, ctypes.byref(secret), 0), "agree")
            n = wintypes.ULONG()
            raw = ctypes.c_wchar_p("TRUNCATE")  # BCRYPT_KDF_RAW_SECRET
            _ok(p.b.BCryptDeriveKey(secret, raw, None, None, 0, ctypes.byref(n), 0), "derive")
            out = ctypes.create_string_buffer(n.value)
            _ok(p.b.BCryptDeriveKey(secret, raw, None, out, n, ctypes.byref(n), 0), "derive")
            shared = out.raw[:n.value][::-1]  # CNG gives it reversed
        finally:
            if secret:
                p.b.BCryptDestroySecret(secret)
            p.b.BCryptDestroyKey(mine)
            p.b.BCryptDestroyKey(theirs)
    if shared == bytes(len(shared)):
        raise CryptoError("all-zero shared secret (a low-order public key)")
    return shared


class _AuthInfo(ctypes.Structure):
    """BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO."""
    _fields_ = [("cbSize", wintypes.ULONG), ("dwInfoVersion", wintypes.ULONG),
                ("pbNonce", ctypes.c_void_p), ("cbNonce", wintypes.ULONG),
                ("pbAuthData", ctypes.c_void_p), ("cbAuthData", wintypes.ULONG),
                ("pbTag", ctypes.c_void_p), ("cbTag", wintypes.ULONG),
                ("pbMacContext", ctypes.c_void_p), ("cbMacContext", wintypes.ULONG),
                ("cbAAD", wintypes.ULONG), ("cbData", ctypes.c_ulonglong), ("dwFlags", wintypes.ULONG)]


IV, TAG = 12, 16


def _gcm(encrypt: bool, key: bytes, iv: bytes, data: bytes, aad: bytes, tag: bytes | None) -> tuple[bytes, bytes]:
    if len(key) != 32 or len(iv) != IV:
        raise ValueError("AES-256-GCM takes a 32-byte key and a 12-byte IV")
    with _Provider("AES", ("ChainingMode", "ChainingModeGCM")) as p:
        handle = ctypes.c_void_p()
        _ok(p.b.BCryptGenerateSymmetricKey(p.h, ctypes.byref(handle), None, 0, key, len(key), 0), "key")
        try:
            nonce_buf = ctypes.create_string_buffer(iv, IV)
            aad_buf = ctypes.create_string_buffer(aad, max(len(aad), 1))
            tag_buf = ctypes.create_string_buffer(tag or bytes(TAG), TAG)
            info = _AuthInfo(cbSize=ctypes.sizeof(_AuthInfo), dwInfoVersion=1,
                             pbNonce=ctypes.addressof(nonce_buf), cbNonce=IV,
                             pbAuthData=ctypes.addressof(aad_buf) if aad else None, cbAuthData=len(aad),
                             pbTag=ctypes.addressof(tag_buf), cbTag=TAG)
            src = ctypes.create_string_buffer(data, max(len(data), 1))
            out = ctypes.create_string_buffer(max(len(data), 1))
            n = wintypes.ULONG()
            fn = p.b.BCryptEncrypt if encrypt else p.b.BCryptDecrypt
            _ok(fn(handle, src, len(data), ctypes.byref(info), None, 0, out, len(data), ctypes.byref(n), 0),
                "encrypt" if encrypt else "decrypt")
            return out.raw[:n.value], tag_buf.raw
        finally:
            p.b.BCryptDestroyKey(handle)


def aes256gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """(ciphertext, 16-byte tag)."""
    return _gcm(True, key, iv, plaintext, aad, None)


def aes256gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """The plaintext, or AuthenticationFailed."""
    if len(tag) != TAG:
        raise AuthenticationFailed("tag length")
    return _gcm(False, key, iv, ciphertext, aad, tag)[0]
