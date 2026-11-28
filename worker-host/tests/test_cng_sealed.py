"""workerhost/cng.py and workerhost/sealed.py against the published test vectors (u64-security, #humans 29172):
RFC 7748 6.1 (X25519, so CNG's byte orders are pinned), RFC 5869 test case 1 (HKDF-SHA256), and the GCM
specification's test case 16 (AES-256-GCM with associated data). Then the sealed token itself, both ways, and an
independent X25519 (RFC 7748's ladder, in this test only) that agrees with CNG on fresh keys."""
from __future__ import annotations

import base64
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="CNG is Windows only")

from workerhost import cng, sealed  # noqa: E402

ALICE_PRIV = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUB = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PRIV = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUB = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
SHARED = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


def test_x25519_matches_rfc_7748_section_6_1():
    assert cng.x25519_public(ALICE_PRIV) == ALICE_PUB
    assert cng.x25519_public(BOB_PRIV) == BOB_PUB
    assert cng.x25519(ALICE_PRIV, BOB_PUB) == SHARED  # CNG's reversed secret is put back in RFC order
    assert cng.x25519(BOB_PRIV, ALICE_PUB) == SHARED


def test_a_low_order_public_key_is_refused_not_used():
    with pytest.raises(cng.CryptoError):
        cng.x25519(ALICE_PRIV, bytes(32))  # the all-zero point gives an all-zero secret (or CNG refuses it)


def test_hkdf_matches_rfc_5869_test_case_1():
    okm = sealed.hkdf_sha256(bytes([0x0B] * 22), bytes(range(0x0D)), bytes(range(0xF0, 0xFA)), 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


GCM_K = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
GCM_IV = bytes.fromhex("cafebabefacedbaddecaf888")
GCM_P = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
                      "b16aedf5aa0de657ba637b39")
GCM_A = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
GCM_C = bytes.fromhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
                      "c5f61e6393ba7a0abcc9f662")
GCM_T = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")


def test_aes_256_gcm_matches_the_gcm_specification_test_case_16():
    assert cng.aes256gcm_encrypt(GCM_K, GCM_IV, GCM_P, GCM_A) == (GCM_C, GCM_T)
    assert cng.aes256gcm_decrypt(GCM_K, GCM_IV, GCM_C, GCM_T, GCM_A) == GCM_P


@pytest.mark.parametrize("change", ["tag", "ciphertext", "aad", "key"])
def test_any_changed_byte_fails_the_tag(change):
    k, c, t, a = GCM_K, GCM_C, GCM_T, GCM_A
    if change == "tag":
        t = bytes([t[0] ^ 1]) + t[1:]
    elif change == "ciphertext":
        c = bytes([c[0] ^ 1]) + c[1:]
    elif change == "aad":
        a = a + b"x"
    else:
        k = bytes([k[0] ^ 1]) + k[1:]
    with pytest.raises(cng.AuthenticationFailed):
        cng.aes256gcm_decrypt(k, GCM_IV, c, t, a)


# --- the sealed token -----------------------------------------------------------------------------------------------

AGENT, NONCE = "host-office1-host", "0123456789abcdef0123456789abcdef"
TOKEN = "example-setup-" + "claudecode" * 9 + "end"  # a Claude setup token's length, made up (not key-shaped)


def test_a_sealed_token_opens_for_its_host_and_command_only():
    host_priv, host_pub = cng.x25519_generate()
    epk, ct = sealed.seal(TOKEN, host_pub, AGENT, NONCE)
    assert sealed.open_sealed(epk, ct, host_priv, host_pub, AGENT, NONCE) == TOKEN
    other_priv, other_pub = cng.x25519_generate()
    for args in [(epk, ct, other_priv, other_pub, AGENT, NONCE),        # another host's key
                 (epk, ct, host_priv, host_pub, "host-office2-host", NONCE),  # another host's name
                 (epk, ct, host_priv, host_pub, AGENT, "f" * 32)]:     # another command
        with pytest.raises(sealed.SealError):
            sealed.open_sealed(*args)


@pytest.mark.parametrize("epk, ct", [
    ("not base64!", "AAAA"), (base64.b64encode(bytes(31)).decode(), base64.b64encode(bytes(40)).decode()),
    (base64.b64encode(bytes(32)).decode(), base64.b64encode(bytes(28)).decode()),  # IV + tag, no ciphertext
])
def test_malformed_input_is_refused(epk, ct):
    priv, pub = cng.x25519_generate()
    with pytest.raises(sealed.SealError):
        sealed.open_sealed(epk, ct, priv, pub, AGENT, NONCE)


def test_the_ciphertext_never_contains_the_token():
    _, pub = cng.x25519_generate()
    _, ct = sealed.seal(TOKEN, pub, AGENT, NONCE)
    assert TOKEN.encode() not in base64.b64decode(ct)


# --- an independent X25519, in this test only: RFC 7748's Montgomery ladder -------------------------------------------

P = 2**255 - 19
A24 = 121665


def _x25519_reference(k: bytes, u: bytes) -> bytes:
    k_int = int.from_bytes(cng.clamp(k), "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (k_int >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def test_the_reference_ladder_itself_matches_rfc_7748():
    assert _x25519_reference(ALICE_PRIV, (9).to_bytes(32, "little")) == ALICE_PUB
    assert _x25519_reference(ALICE_PRIV, BOB_PUB) == SHARED


def test_the_shared_vector_both_ways():
    """contracts/sealed-signin/vector.json: the App's tests must reproduce the same epk and ct from the same inputs."""
    import json

    import vectors

    v = json.loads(vectors.path("sealed-signin", "vector.json").read_bytes())
    scalar, public = bytes.fromhex(v["host_scalar_hex"]), bytes.fromhex(v["host_public_hex"])
    assert cng.x25519_public(scalar) == public
    epk, ct = sealed.seal(v["plaintext"], public, v["agent"], v["nonce"],
                          ephemeral=bytes.fromhex(v["ephemeral_scalar_hex"]), iv=bytes.fromhex(v["iv_hex"]))
    assert (epk, ct) == (v["epk"], v["ct"])
    assert sealed.open_sealed(v["epk"], v["ct"], scalar, public, v["agent"], v["nonce"]) == v["plaintext"]


@pytest.mark.parametrize("round_", range(5))
def test_cng_agrees_with_an_independent_x25519_on_fresh_keys(round_):
    a_priv, a_pub = cng.x25519_generate()
    b_priv, b_pub = cng.x25519_generate()
    assert _x25519_reference(a_priv, (9).to_bytes(32, "little")) == a_pub
    assert cng.x25519(a_priv, b_pub) == _x25519_reference(a_priv, b_pub) == cng.x25519(b_priv, a_pub)
