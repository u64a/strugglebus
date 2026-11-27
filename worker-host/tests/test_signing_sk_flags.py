"""A security key's signature must carry both the touch and the PIN flag (workerhost/signing.py, touch_and_pin).

OpenSSH's allowed_signers has no verify-required option, so ssh-keygen alone accepts a touch-only signature; the host
reads the flags itself once ssh-keygen has verified the signature."""
from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

import pytest

from workerhost import signing

ROOT = Path(__file__).resolve().parent.parent


def s(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def armour(blob: bytes) -> bytes:
    b64 = base64.b64encode(blob).decode()
    body = "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70))
    return f"-----BEGIN SSH SIGNATURE-----\n{body}\n-----END SSH SIGNATURE-----\n".encode()


def sshsig(sig_type: bytes, tail: bytes = b"") -> bytes:
    """An SSHSIG in the real layout: magic, version, public key, namespace, reserved, hash, then the signature field
    (type, signature bytes and, for a security key, flags and counter)."""
    pub = s(sig_type) + s(b"\x00" * 32) + (s(b"ssh:strugglebus-signing") if sig_type.startswith(b"sk-") else b"")
    inner = s(sig_type) + s(b"\x11" * 64) + tail
    return armour(b"SSHSIG" + (1).to_bytes(4, "big") + s(pub) + s(b"strugglebus-release") + s(b"") + s(b"sha512")
                  + s(inner))


SK = b"sk-ssh-ed25519@openssh.com"


@pytest.mark.parametrize("flags, ok", [(0x05, True), (0x01, False), (0x04, False), (0x00, False), (0x25, True)])
def test_a_security_key_signature_needs_both_touch_and_pin(flags, ok):
    sig = sshsig(SK, bytes([flags]) + (319).to_bytes(4, "big"))
    assert signing.sk_flags(sig) == flags
    assert signing.touch_and_pin(sig) is ok


def test_other_key_types_have_no_flags_and_are_not_held_to_them():
    sig = sshsig(b"rsa-sha2-512")
    assert signing.sk_flags(sig) is None and signing.touch_and_pin(sig)


@pytest.mark.parametrize("sig", [
    b"-----BEGIN SSH SIGNATURE-----\nnot base64!\n-----END SSH SIGNATURE-----\n",
    armour(b"NOTSIG" + b"\x00" * 40),
    sshsig(SK),            # no flags at all
    armour(b"SSHSIG\x00\x00\x00\x01" + s(b"short")),
])
def test_a_signature_that_cannot_be_taken_apart_is_refused(sig):
    assert signing.touch_and_pin(sig) is False


def test_the_real_release_signature_here_carries_touch_and_pin():
    """This repository's own release.toml.sig, made with the project's YubiKey (where the release lives here)."""
    real = ROOT / "release.toml.sig"
    if not real.is_file():
        pytest.skip("no release.toml.sig in this layout")
    assert signing.sk_flags(real.read_bytes()) == 0x05


def test_verify_refuses_a_touch_only_signature_that_ssh_keygen_accepted(tmp_path, monkeypatch):
    signers = tmp_path / "allowed_signers"
    signers.write_text('alice namespaces="strugglebus-release" sk-ssh-ed25519@openssh.com AAAA x\n')
    monkeypatch.setattr(signing, "_verify_as", lambda *a: 'Good "strugglebus-release" signature for alice with '
                                                          "ED25519-SK key SHA256:abc")
    touch_only = sshsig(SK, b"\x01" + (5).to_bytes(4, "big"))
    with_pin = sshsig(SK, b"\x05" + (6).to_bytes(4, "big"))
    v = signing.verify(b"data", touch_only, signing.NS_RELEASE, signers, "ssh-keygen", tmp_path / "w")
    assert (v.ok, v.reason, v.principal) == (False, "sk-no-pin", "alice")
    v = signing.verify(b"data", with_pin, signing.NS_RELEASE, signers, "ssh-keygen", tmp_path / "w")
    assert (v.ok, v.reason) == (True, "good")


def test_a_plain_ed25519_key_still_verifies_end_to_end(tmp_path):
    """The usual throwaway-key path (as the other signing tests): no flags, so nothing changes for it."""
    keygen = next((k for k in signing.KEYGEN_CANDIDATES[:2] if os.path.isfile(k)), None)
    if keygen is None:
        pytest.skip("no Windows OpenSSH ssh-keygen")
    key = tmp_path / "id"
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True, capture_output=True)
    kind, blob = (tmp_path / "id.pub").read_text().split()[:2]
    signers = tmp_path / "allowed_signers"
    signers.write_text(f'bob namespaces="strugglebus-fleet" {kind} {blob} t\n')
    data = tmp_path / "doc"
    data.write_bytes(b"serial = 1\n")
    subprocess.run([keygen, "-Y", "sign", "-f", str(key), "-n", "strugglebus-fleet", str(data)], check=True,
                   capture_output=True)
    v = signing.verify(data.read_bytes(), (tmp_path / "doc.sig").read_bytes(), signing.NS_FLEET, signers, keygen,
                       tmp_path / "w")
    assert v.ok and v.principal == "bob"
