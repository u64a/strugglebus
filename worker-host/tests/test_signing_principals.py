"""signing.verify trusts whichever principal the pinned allowed_signers names for the namespace, not a name built into
the code: a real ssh-keygen and throwaway keys."""
from __future__ import annotations

import os
import subprocess

import pytest

from workerhost import signing

KEYGEN = next((k for k in signing.KEYGEN_CANDIDATES if os.path.isfile(k)), None)
needs_keygen = pytest.mark.skipif(KEYGEN is None, reason="no ssh-keygen")


def test_principals_for_a_namespace(tmp_path):
    f = tmp_path / "allowed_signers"
    f.write_text("# pinned\n"
                 'alice namespaces="strugglebus-fleet,strugglebus-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== a\n'
                 'bob namespaces="strugglebus-baseline" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== b\n'
                 "carol,alice ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== c\n"
                 "*@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== d\n", encoding="utf-8")
    assert signing.principals_for(f, "strugglebus-fleet") == ["alice", "carol"]  # carol's line has no restriction
    assert signing.principals_for(f, "strugglebus-baseline") == ["bob", "carol", "alice"]


def key_pair(tmp_path, name):
    key = tmp_path / name
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True,
                   capture_output=True, stdin=subprocess.DEVNULL)
    return key, " ".join((tmp_path / f"{name}.pub").read_text().split()[:2])


def sign(key, data_file, namespace):
    subprocess.run([KEYGEN, "-Y", "sign", "-f", str(key), "-n", namespace, str(data_file)], check=True,
                   capture_output=True, stdin=subprocess.DEVNULL)
    return data_file.with_name(data_file.name + ".sig").read_bytes()


@needs_keygen
def test_a_signature_by_any_pinned_principal_verifies_and_names_it(tmp_path):
    ka, pub_a = key_pair(tmp_path, "a")
    kb, pub_b = key_pair(tmp_path, "b")
    signers = tmp_path / "allowed_signers"
    signers.write_text(f'alice namespaces="strugglebus-fleet" {pub_a}\nbob namespaces="strugglebus-fleet" {pub_b}\n',
                       encoding="utf-8")
    data = tmp_path / "fleet.toml"
    data.write_bytes(b"serial = 1\n")
    v = signing.verify(data.read_bytes(), sign(kb, data, "strugglebus-fleet"), "strugglebus-fleet", signers, KEYGEN,
                       tmp_path / "work")
    assert v.ok and v.principal == "bob" and v.fingerprint.startswith("SHA256:")


@needs_keygen
def test_a_key_not_pinned_for_the_namespace_does_not_verify(tmp_path):
    ka, pub_a = key_pair(tmp_path, "a")
    signers = tmp_path / "allowed_signers"
    signers.write_text(f'alice namespaces="strugglebus-baseline" {pub_a}\n', encoding="utf-8")
    data = tmp_path / "release.toml"
    data.write_bytes(b"serial = 1\n")
    sig = sign(ka, data, "strugglebus-release")
    assert signing.verify(data.read_bytes(), sig, "strugglebus-release", signers, KEYGEN, tmp_path / "w").reason == \
        "no-signers"  # nobody may sign releases


@needs_keygen
def test_a_stranger_key_is_refused(tmp_path):
    ka, pub_a = key_pair(tmp_path, "a")
    kx, _ = key_pair(tmp_path, "x")
    signers = tmp_path / "allowed_signers"
    signers.write_text(f'alice namespaces="strugglebus-fleet" {pub_a}\n', encoding="utf-8")
    data = tmp_path / "fleet.toml"
    data.write_bytes(b"serial = 1\n")
    v = signing.verify(data.read_bytes(), sign(kx, data, "strugglebus-fleet"), "strugglebus-fleet", signers, KEYGEN,
                       tmp_path / "w")
    assert not v.ok and v.reason == "bad-signature"
