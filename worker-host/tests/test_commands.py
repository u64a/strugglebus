"""Signed host commands (workerhost/commands.py; docs/app-host-integration.md section 4): every vector in
the shared vectors (tests/vectors.py) gives the result expected.json names, through the real verifier, in the order given (the replayed
command reuses an accepted one's nonce); and the edges the vectors do not cover."""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

import vectors
from workerhost import commands, signing

EXPECTED = json.loads(vectors.path("host-command", "expected.json").read_text(encoding="utf-8"))
NOW = dt.datetime.strptime(EXPECTED["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()
HOST = EXPECTED["this_host"]
KEYGEN = next((k for k in signing.KEYGEN_CANDIDATES if os.path.isfile(k)), None)


@pytest.mark.skipif(KEYGEN is None, reason="no ssh-keygen")
def test_every_command_vector_gives_the_expected_result(tmp_path):
    nonces = commands.NonceStore(tmp_path / "nonces.json")
    verify = commands.verifier(vectors.path("host-command", "allowed_signers"), KEYGEN, tmp_path / "tmp")
    got = {}
    for name in EXPECTED["command_order"]:
        try:
            cmd = commands.check(vectors.path("host-command", name).read_bytes(),
                                 vectors.path("host-command", f"{name}.sig").read_bytes(), host=HOST, now=NOW,
                                 nonces=nonces, verify=verify)
            got[name] = "accept"
            assert cmd.signer.startswith("SHA256:")
        except commands.Refused as e:
            got[name] = e.reason
    assert got == EXPECTED["commands"]


# --- the edges, with a stand-in verifier ----------------------------------------------------------------------------

def ok(doc, sig):
    return NS(ok=True, fingerprint="SHA256:test", reason="")


def bad(doc, sig):
    return NS(ok=False, fingerprint="", reason="bad-signature")


def stamp(t: float) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def doc(**over) -> bytes:
    d = {"v": 1, "type": "sb-host-command", "host": HOST, "verb": "pause", "nonce": "a" * 32,
         "issued_at": stamp(NOW - 30), "expires_at": stamp(NOW + 270)}
    d.update(over)
    return json.dumps({k: v for k, v in d.items() if v is not ...}).encode()


def reason(raw: bytes, tmp_path, verify=ok) -> str:
    try:
        commands.check(raw, b"sig", host=HOST, now=NOW, nonces=commands.NonceStore(tmp_path / "n.json"),
                       verify=verify)
        return "accept"
    except commands.Refused as e:
        return e.reason


@pytest.mark.parametrize("raw, why", [
    (doc(), "accept"),
    (doc(verb="drain"), "accept"),
    (doc(verb="resume"), "accept"),
    (b"not json", "bad-document"),
    (b"[1, 2]", "bad-document"),
    (doc(v=2), "bad-document"),
    (doc(type="sb-fleet"), "bad-document"),
    (doc(host=...), "bad-document"),
    (doc(nonce="short"), "bad-document"),
    (doc(nonce=...), "bad-document"),
    (doc(host="host-other-host"), "not-this-host"),
    (doc(issued_at="2026-11-24 14:02:11"), "bad-time"),
    (doc(expires_at=stamp(NOW - 1)), "expired"),
    (doc(issued_at=stamp(NOW + 200), expires_at=stamp(NOW + 300)), "bad-time"),   # more than 2 minutes ahead
    (doc(issued_at=stamp(NOW - 400), expires_at=stamp(NOW + 300)), "bad-time"),   # over 10 minutes long
    (doc(issued_at=stamp(NOW + 60), expires_at=stamp(NOW + 30)), "bad-time"),     # ends before it starts
    (doc(verb="stop"), "bad-verb"),
    (doc(verb=["pause"]), "bad-verb"),
    (doc(version="2026.11.24"), "unknown-field"),
    (doc().replace(b'"verb": "pause"', b'"verb": "pause", "verb": "update"'), "duplicate-key"),
])
def test_each_rule(raw, why, tmp_path):
    assert reason(raw, tmp_path) == why


def test_the_signature_comes_before_anything_in_the_document(tmp_path):
    assert reason(b"not even json", tmp_path, verify=bad) == "bad-signature"
    assert reason(doc(host="host-other-host"), tmp_path, verify=bad) == "bad-signature"


def test_a_nonce_is_kept_across_restarts_for_24_hours(tmp_path):
    store = commands.NonceStore(tmp_path / "n.json")
    commands.check(doc(), b"s", host=HOST, now=NOW, nonces=store, verify=ok)
    again = commands.NonceStore(tmp_path / "n.json")  # a restart reads the same file
    with pytest.raises(commands.Refused, match="replayed"):
        commands.check(doc(), b"s", host=HOST, now=NOW + 10, nonces=again, verify=ok)
    assert again.seen("a" * 32, NOW + 86000) and not again.seen("a" * 32, NOW + 86500)


def test_a_refused_command_does_not_use_up_its_nonce(tmp_path):
    store = commands.NonceStore(tmp_path / "n.json")
    with pytest.raises(commands.Refused):
        commands.check(doc(verb="stop"), b"s", host=HOST, now=NOW, nonces=store, verify=ok)
    assert not store.seen("a" * 32, NOW)


def test_the_store_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(commands.NonceStore, "LIMIT", 3)
    store = commands.NonceStore(tmp_path / "n.json")
    for i in range(5):
        store.add(f"{i:032x}", NOW + i)
    assert not store.seen(f"{0:032x}", NOW + 5) and store.seen(f"{4:032x}", NOW + 5)


def test_a_damaged_store_reads_as_empty(tmp_path):
    (tmp_path / "n.json").write_text("[not, a, dict", encoding="utf-8")
    assert not commands.NonceStore(tmp_path / "n.json").seen("a" * 32, NOW)


@pytest.mark.parametrize("meta, result", [
    (None, None),
    ({"other": 1}, None),
    ({"sb_host_command": "text"}, "bad-document"),
    ({"sb_host_command": {"doc": "!!!", "sig": "x"}}, "bad-document"),
    ({"sb_host_command": {"doc": base64.b64encode(b"x" * 1100).decode(), "sig": "x"}}, "bad-document"),
    ({"sb_host_command": {"doc": base64.b64encode(b"{}").decode(), "sig": "x" * 5000}}, "bad-document"),
    ({"sb_host_command": {"doc": base64.b64encode(b"{}").decode(), "sig": "armored"}}, (b"{}", b"armored")),
])
def test_what_a_message_carries(meta, result):
    try:
        assert commands.carried(meta) == result
    except commands.Refused as e:
        assert e.reason == result
