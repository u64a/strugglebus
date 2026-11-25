"""S11 self-enrolment: the host asks for a token, enrols with the one token-minter drops, and deletes it."""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import pytest

from conftest import HOST_A, FakeVault
from test_openbao import FakeBao, client
from workerhost import leafkey, openbao, resources
from workerhost.config import Config, OpenBao
from workerhost.host import Host

CERT = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
TOKEN = "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"  # a fake token: its parts decode to '{"alg":', '{"sub":', 'signature'  # gitleaks:allow


class Bus:
    def __init__(self):
        self.posts, self.calls = [], []

    def post(self, channel, kind, text, reply_to=None):
        self.posts.append((channel, kind, text))
        return len(self.posts)

    def call(self, method, path, **kw):
        self.calls.append((method, path))
        return 200, None


@pytest.fixture
def h(tmp_path, monkeypatch):
    monkeypatch.setattr(resources, "sample", lambda root: None)
    monkeypatch.setattr("workerhost.host.openbao_client", lambda c: client(FakeBao()))
    drop = tmp_path / "bootstrap"
    drop.mkdir()
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", home=tmp_path / "home", workers_root=tmp_path / "w",
                 openbao=OpenBao(enabled=True, bootstrap_dir=str(drop), san_domain="example.lan",
                                 leaf_authority="token-minter"))
    host = Host(cfg, bus=Bus(), vault=FakeVault())
    host.pins = {"host": HOST_A}
    host.drop = drop
    return host


def test_no_leaf_asks_prox_manager_once_an_hour_in_security(h):
    now = time.time()
    h.bootstrap_tick(now)
    h.bootstrap_tick(now + 60)
    assert h.bus.posts == [("security", "status", "@token-minter leaf-needed san=host-alpha.example.lan")]
    assert ("PUT", "/api/subscriptions/security") in h.bus.calls
    h.bootstrap_tick(now + 3601)
    assert len(h.bus.posts) == 2


def test_a_healthy_leaf_asks_nothing(h, monkeypatch):
    monkeypatch.setattr(h, "leaf_hours_left", lambda: 50.0)
    h.bootstrap_tick(time.time())
    monkeypatch.setattr(h, "leaf_hours_left", lambda: 5.0)  # low, but renewal is not failing: it will renew
    h.bootstrap_tick(time.time())
    assert h.bus.posts == []
    h.leaf_renew_failing = True
    h.bootstrap_tick(time.time())
    assert h.bus.posts[-1][2].endswith("leaf-needed san=host-alpha.example.lan")


def test_a_dropped_token_is_used_once_deleted_and_the_leaf_replaced(h, monkeypatch):
    leaf = h.cfg.leaf_dir
    leaf.mkdir(parents=True)
    (leaf / "leaf.key").write_text("OLD KEY", encoding="ascii")
    (h.drop / "host-alpha.example.lan.token").write_text(TOKEN + "\n", encoding="ascii")
    got = {}

    def fake_key(san, key_path):
        Path(key_path).write_text("NEW KEY", encoding="ascii")
        got["san"] = san
        return "CSR"

    def fake_sign(url, ca, csr, token, not_after):
        got.update(csr=csr, token=token, not_after=not_after, token_file_gone=not (h.drop / "host-alpha.example.lan.token").exists())
        return CERT

    monkeypatch.setattr(leafkey, "new_key_and_csr", fake_key)
    monkeypatch.setattr(openbao, "sign_leaf", fake_sign)
    h.bootstrap_tick(time.time())
    assert got == {"san": "host-alpha.example.lan", "csr": "CSR", "token": TOKEN, "not_after": "72h", "token_file_gone": True}
    assert (leaf / "leaf.key").read_text(encoding="ascii") == "NEW KEY" and not (leaf / "leaf.key.new").exists()
    assert (leaf / "leaf.crt").read_text(encoding="ascii") == CERT
    assert h.bus.posts == [("security", "status", "leaf-issued san=host-alpha.example.lan")]
    log = "".join(p.read_text(encoding="utf-8") for p in h.cfg.logs_dir.glob("host-*.log"))
    assert "leaf-token-arrived" in log and "leaf-token-deleted" in log and TOKEN not in log


def test_a_refused_token_keeps_the_old_key_and_leaf(h, monkeypatch):
    leaf = h.cfg.leaf_dir
    leaf.mkdir(parents=True)
    (leaf / "leaf.key").write_text("OLD KEY", encoding="ascii")
    (leaf / "leaf.crt").write_text("OLD CRT", encoding="ascii")
    (h.drop / "host-alpha.example.lan.token").write_text(TOKEN, encoding="ascii")
    monkeypatch.setattr(leafkey, "new_key_and_csr", lambda san, p: Path(p).write_text("NEW", encoding="ascii") or "CSR")

    def refuse(*a):
        raise openbao.OpenBaoError(401, "ca sign")

    monkeypatch.setattr(openbao, "sign_leaf", refuse)
    h.bootstrap_tick(time.time())
    assert (leaf / "leaf.key").read_text(encoding="ascii") == "OLD KEY"
    assert (leaf / "leaf.crt").read_text(encoding="ascii") == "OLD CRT"
    assert not (leaf / "leaf.key.new").exists() and not (h.drop / "host-alpha.example.lan.token").exists()
    assert not any("leaf-issued" in p[2] for p in h.bus.posts)


def test_a_file_that_is_not_a_token_is_deleted_and_not_sent(h, monkeypatch):
    (h.drop / "host-alpha.example.lan.token").write_text("hello", encoding="ascii")
    monkeypatch.setattr(openbao, "sign_leaf", lambda *a: pytest.fail("must not be sent"))
    h.bootstrap_tick(time.time())
    assert not (h.drop / "host-alpha.example.lan.token").exists()


def test_another_hosts_token_is_left_alone(h):
    (h.drop / "host-other.example.lan.token").write_text(TOKEN, encoding="ascii")
    h.bootstrap_tick(time.time())
    assert (h.drop / "host-other.example.lan.token").exists()


def test_the_script_takes_only_a_checked_name_and_path(tmp_path):
    s = leafkey.script_for("host-alpha.example.lan", tmp_path / "leaf.key.new")
    assert "CN=$san" in s and "host-alpha.example.lan" in s
    for bad in ("Host.example.lan", "nodomain", "a';evil;'.example.lan", "x.lan\nevil"):
        with pytest.raises(ValueError):
            leafkey.script_for(bad, tmp_path / "k")
    with pytest.raises(ValueError):
        leafkey.script_for("host-alpha.example.lan", Path("C:/it's/k"))


@pytest.mark.skipif(not shutil.which("pwsh"), reason="needs PowerShell 7")
def test_a_real_key_and_csr(tmp_path):
    key = tmp_path / "leaf.key.new"
    csr = leafkey.new_key_and_csr("host-alpha.example.lan", key)
    assert csr.startswith("-----BEGIN CERTIFICATE REQUEST-----")
    assert key.read_text(encoding="ascii").startswith("-----BEGIN PRIVATE KEY-----")


def test_needed_file_exists_exactly_while_there_is_no_valid_leaf(h, monkeypatch):
    needed = h.drop / "host-alpha.example.lan.needed"
    h.bus = None  # a rebuilt host: no bus yet, so it can only ask by file
    h.bootstrap_tick(time.time())
    assert needed.is_file() and needed.read_text(encoding="ascii").strip()[:4].isdigit()  # a timestamp only
    first = needed.read_text(encoding="ascii")
    h.bootstrap_tick(time.time() + 120)
    assert needed.read_text(encoding="ascii") == first  # written once, not every minute
    monkeypatch.setattr(h, "leaf_hours_left", lambda: 71.0)
    h.bootstrap_tick(time.time() + 240)
    assert not needed.exists()  # never present while the host holds a valid leaf


def test_enrol_by_file_removes_the_request_and_posts_issued_once_connected(h, monkeypatch):
    (h.drop / "host-alpha.example.lan.needed").write_text("2026-11-04T23:00:00+1300\n", encoding="ascii")
    (h.drop / "host-alpha.example.lan.token").write_text(TOKEN, encoding="ascii")
    monkeypatch.setattr(leafkey, "new_key_and_csr", lambda san, p: Path(p).write_text("K", encoding="ascii") or "CSR")
    monkeypatch.setattr(openbao, "sign_leaf", lambda *a: CERT)
    bus, h.bus = h.bus, None
    h.bootstrap_tick(time.time())
    assert not (h.drop / "host-alpha.example.lan.needed").exists() and not (h.drop / "host-alpha.example.lan.token").exists()
    assert h.leaf_issued_unposted
    h.bus = bus  # connected: the host's identity came from OpenBao with the new leaf
    monkeypatch.setattr(h, "leaf_hours_left", lambda: 72.0)
    h.bootstrap_tick(time.time() + 60)
    assert bus.posts == [("security", "status", "leaf-issued san=host-alpha.example.lan")] and not h.leaf_issued_unposted


def test_a_connected_host_asks_on_the_bus_and_writes_no_file(h):
    h.bootstrap_tick(time.time())
    assert not (h.drop / "host-alpha.example.lan.needed").exists()
    assert h.bus.posts == [("security", "status", "@token-minter leaf-needed san=host-alpha.example.lan")]


def test_the_name_on_a_held_leaf_wins_over_the_configured_domain(h, monkeypatch):
    # An expired leaf still names the host: a renewal or re-issue asks for that same name.
    monkeypatch.setattr(openbao, "leaf_san", lambda path: ["host-alpha.home.lan"])
    h.bootstrap_tick(time.time())
    assert h.bus.posts == [("security", "status", "@token-minter leaf-needed san=host-alpha.home.lan")]


def test_with_no_leaf_authority_the_host_asks_by_file_only(h):
    # A site where nobody on the bus mints tokens: the request is the <san>.needed file, even while connected.
    h.cfg.openbao.leaf_authority = ""
    h.bootstrap_tick(time.time())
    assert h.bus.posts == [] and (h.drop / "host-alpha.example.lan.needed").is_file()


def test_no_leaf_and_no_domain_asks_for_nothing(h, monkeypatch):
    h.cfg.openbao.san_domain = ""
    logged = []
    monkeypatch.setattr(h, "log", lambda event, **kw: logged.append(event))
    h.bootstrap_tick(time.time())
    h.bootstrap_tick(time.time() + 7200)
    assert h.bus.posts == [] and not list(h.drop.iterdir())
    assert logged == ["leaf-no-name"]  # said once, not every loop
