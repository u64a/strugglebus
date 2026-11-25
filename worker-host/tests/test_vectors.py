"""The shared contract vectors (docs/app-host-integration.md; tests/vectors.py finds them): the files the App is built and
tested against. A throwaway RSA-2048 key made them (private half discarded), as a Windows Hello key would: SSHSIG,
rsa-sha2-512. Here: every fleet vector and every command signature gives the result expected.json names, through the
host's own verifier. The command CONTENT rules (host, times, nonce, verb) are tests/test_commands.py, against the
same vectors."""
from __future__ import annotations

import json
import os

import pytest

import vectors
from workerhost import fleet, signing

FLEET = json.loads(vectors.path("fleet", "expected.json").read_text(encoding="utf-8"))
COMMANDS = json.loads(vectors.path("host-command", "expected.json").read_text(encoding="utf-8"))
KEYGEN = next((k for k in signing.KEYGEN_CANDIDATES if os.path.isfile(k)), None)
needs_keygen = pytest.mark.skipif(KEYGEN is None, reason="no ssh-keygen")


def verify(contract: str, name: str, namespace: str, tmp_path) -> signing.Verified:
    return signing.verify(vectors.path(contract, name).read_bytes(), vectors.path(contract, f"{name}.sig").read_bytes(),
                          namespace, vectors.path(contract, "allowed_signers"), KEYGEN, tmp_path)


@pytest.mark.parametrize("contract", ["fleet", "host-command"])
def test_the_vectors_are_signed_by_an_rsa_key_and_ship_no_private_key(contract):
    signers = vectors.path(contract, "allowed_signers")
    assert "ssh-rsa" in signers.read_text(encoding="utf-8")
    assert not any(b"PRIVATE KEY" in p.read_bytes() for p in signers.parent.iterdir() if p.is_file())


@pytest.mark.parametrize("contract", ["fleet", "host-command", "host-enrol"])
def test_the_vectors_on_disk_are_byte_for_byte_what_git_stores(contract):
    """A checkout must never change a vector's bytes (core.autocrlf on Windows would): each file must hash to the
    blob git has for it (security review: a Windows clone without `-text` rewrote 23 of them)."""
    import hashlib
    import subprocess

    folder = vectors.path(contract, "expected.json" if contract != "host-enrol" else "sbhost-enrol.json").parent
    r = subprocess.run(["git", "ls-files", "-s", "-z", "--", "."], cwd=folder, capture_output=True)
    if r.returncode != 0 or not r.stdout:
        pytest.skip("not a git checkout")
    for entry in r.stdout.split(b"\0"):
        if not entry:
            continue
        meta, _, name = entry.partition(b"\t")
        sha = meta.split()[1].decode("ascii")
        data = (folder / name.decode("utf-8")).read_bytes()
        if (folder / name.decode("utf-8")).parent != folder:
            continue
        assert hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest() == sha, name.decode("utf-8")


@needs_keygen
@pytest.mark.parametrize("name", sorted(FLEET["fleet"]))
def test_fleet_vectors(name, tmp_path):
    v = verify("fleet", name, signing.NS_FLEET, tmp_path)
    assert v.ok is (FLEET["fleet"][name] == "accept"), (name, v.reason)


def test_the_good_fleet_vector_is_a_valid_fleet():
    f = fleet.parse(vectors.path("fleet", "fleet.toml").read_bytes())
    assert (f.serial, f.owner, [h.agent_name for h in f.hosts]) == (5, "Alex", [FLEET["this_host"]])


@needs_keygen
@pytest.mark.parametrize("name", COMMANDS["command_order"])
def test_command_signatures(name, tmp_path):
    # Only a command signed under the command namespace verifies; content checks are tests/test_commands.py.
    v = verify("host-command", name, "strugglebus-host-command", tmp_path)
    assert v.ok is (COMMANDS["commands"][name] != "bad-signature"), (name, v.reason)
