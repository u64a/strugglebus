"""sign-in-claude (docs/app-host-integration.md 4a): the host's key, the sealed token, and where the token goes.

The store is a stand-in for the DPAPI one (same calls); the crypto is the real CNG (workerhost/cng.py)."""
from __future__ import annotations

import base64
import datetime as dt
import json
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="CNG is Windows only")

from workerhost import claudesignin, commands, engines, hoststatus, launcher, sealed  # noqa: E402

AGENT, NONCE = "host-box1-host", "0123456789abcdef0123456789abcdef"
TOKEN = "example-setup-" + "claudecode" * 9 + "end"
TODAY = dt.date(2026, 11, 28)


class FakeStore:
    def __init__(self):
        self.items = {}

    def has(self, name):
        return name in self.items

    def save(self, name, record):
        self.items[name] = json.loads(json.dumps(record))

    def load(self, name):
        if name not in self.items:
            raise LookupError(name)
        return self.items[name]


def sealed_for(store, agent=AGENT, nonce=NONCE, token=TOKEN):
    _, public = claudesignin.ensure_key(store)
    return sealed.seal(token, public, agent, nonce)


def test_the_key_is_made_once_kept_and_reported_without_its_private_half():
    store = FakeStore()
    assert claudesignin.key_status(store) is None  # never made just to report it
    private, public = claudesignin.ensure_key(store)
    assert claudesignin.ensure_key(store) == (private, public)
    st = claudesignin.key_status(store)
    assert base64.b64decode(st["x25519"]) == public
    assert st["fingerprint"] == claudesignin.fingerprint(public) and st["fingerprint"].startswith("SHA256:")
    assert private.hex() not in json.dumps(st)


def test_a_token_sealed_to_this_host_for_this_command_is_kept_with_its_date():
    store = FakeStore()
    epk, ct = sealed_for(store)
    claudesignin.receive(store, epk, ct, AGENT, NONCE, TODAY)
    assert claudesignin.token(store) == TOKEN and claudesignin.since(store) == "2026-11-28"


@pytest.mark.parametrize("agent, nonce", [("host-other-host", NONCE), (AGENT, "f" * 32)])
def test_a_token_for_another_host_or_command_is_refused_and_nothing_kept(agent, nonce):
    store = FakeStore()
    epk, ct = sealed_for(store, agent=agent, nonce=nonce)
    with pytest.raises(sealed.SealError):
        claudesignin.receive(store, epk, ct, AGENT, NONCE, TODAY)
    assert claudesignin.token(store) is None


def test_no_key_means_nothing_can_be_opened():
    with pytest.raises(sealed.SealError):
        claudesignin.receive(FakeStore(), "AAAA", "AAAA", AGENT, NONCE, TODAY)


@pytest.mark.parametrize("since, old", [("2025-12-28", True), ("2025-12-29", False), (None, False), ("bad", False)])
def test_a_token_is_old_after_335_days(since, old):
    assert claudesignin.is_old(since, TODAY) is old


def test_the_verb_requires_exactly_its_two_fields():
    base = {"v": 1, "type": "sb-host-command", "host": AGENT, "verb": "sign-in-claude", "nonce": NONCE,
            "issued_at": "2026-11-28T10:00:00Z", "expires_at": "2026-11-28T10:05:00Z"}

    class Nonces:
        def seen(self, n, now):
            return False

    now = dt.datetime(2026, 11, 28, 10, 1, tzinfo=dt.timezone.utc).timestamp()
    ok = commands._content({**base, "epk": "QUJD", "ct": "REVGR0g="}, AGENT, now, Nonces())
    assert ok.verb == "sign-in-claude" and dict(ok.extra) == {"ct": "REVGR0g=", "epk": "QUJD"}
    for doc, reason in [({**base, "epk": "QUJD"}, "bad-document"),                       # one missing
                        ({**base, "epk": "QUJD", "ct": "not base64!"}, "bad-document"),
                        ({**base, "epk": "QUJD", "ct": "REVG", "x": "1"}, "unknown-field"),
                        ({**base, "verb": "pause", "epk": "QUJD", "ct": "REVG"}, "unknown-field")]:  # not for others
        with pytest.raises(commands.Refused) as e:
            commands._content(doc, AGENT, now, Nonces())
        assert e.value.reason == reason


def test_claude_counts_as_signed_in_with_a_sealed_token(monkeypatch, tmp_path):
    monkeypatch.setattr(engines, "resolve", lambda name: "C:\\bin\\x.exe")
    eng = engines.Engines("ghcp", engines.Claude())
    assert "claude" not in engines.available("copilot", eng, home=tmp_path)
    assert "claude" in engines.available("copilot", eng, home=tmp_path, token=True)


def test_an_inherited_token_never_reaches_a_worker():
    env = launcher.worker_env({"CLAUDE_CODE_OAUTH_TOKEN": "inherited", "PATH": "C:\\x"}, bus_ca="ca", bus_url="u",
                              store=None, token="bus", temp="C:\\t", gh_exe="gh", wait_timeout=60)
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env


def test_the_status_carries_the_key_and_the_date_admin_only_and_never_the_token():
    store = FakeStore()
    epk, ct = sealed_for(store)
    claudesignin.receive(store, epk, ct, AGENT, NONCE, TODAY)
    f = hoststatus.Facts(host="h", agent=AGENT, version="v", serial=1, started_at=0, interval_s=60,
                         reported_state="idle", account="x", dedicated=True, engines=[], busy=0, max_workers=1,
                         claiming=0, held_clones=0, outbox=0, fleet={}, listed_in_fleet=True,
                         sign_in_key=claudesignin.key_status(store), claude_token_since=claudesignin.since(store),
                         claude_token_old=True)
    snap = hoststatus.build_v2(f)
    assert snap["sign_in_key"] == claudesignin.key_status(store) and snap["claude_token_since"] == "2026-11-28"
    assert "claude-token-old" in snap["warnings"]
    dev = hoststatus.for_device(snap)
    assert "sign_in_key" not in dev and "claude_token_since" not in dev
    assert TOKEN not in json.dumps(snap) and "sign_in_key" not in hoststatus.build(f)


@pytest.fixture
def host(tmp_path, monkeypatch):
    from conftest import HOST_A, FakeVault, SharedBus
    from workerhost import engines as engines_mod
    from workerhost import resources
    from workerhost.config import Config
    from workerhost.host import Host

    monkeypatch.setattr(resources, "sample", lambda root: None)
    monkeypatch.setattr(engines_mod, "resolve", lambda name: "C:\\bin\\copilot.exe")
    h = Host(Config(host_name="box1", agent_prefix="host-box1", home=tmp_path / "home", workers_root=tmp_path / "w"),
             bus=SharedBus().client(HOST_A), vault=FakeVault())
    lines = []
    h.signins.log = lambda event, **f: lines.append((event, f))
    h.log = lambda event, **f: lines.append((event, f))
    return h, lines


def test_a_sign_in_claude_command_keeps_the_token_and_logs_only_that_it_did(host):
    h, lines = host
    _, public = claudesignin.ensure_key(h.signin_store)  # the real DPAPI store, as this test's user
    epk, ct = sealed.seal(TOKEN, public, h.cfg.host_agent, NONCE)
    h.run_command("sign-in-claude", NONCE, {"epk": epk, "ct": ct})
    assert claudesignin.token(h.signin_store) == TOKEN
    assert h.signins.status() == {"nonce": NONCE, "tool": "claude", "state": "done"}
    assert [e for e, _ in lines] == ["claude-token-stored", "sign-in-requested", "sign-in-done"]
    assert TOKEN not in json.dumps(lines)


def test_a_token_that_will_not_open_is_sign_in_failed_decrypt_and_nothing_is_kept(host):
    h, lines = host
    _, public = claudesignin.ensure_key(h.signin_store)
    epk, ct = sealed.seal(TOKEN, public, "host-other-host", NONCE)  # sealed for another host's name
    h.run_command("sign-in-claude", NONCE, {"epk": epk, "ct": ct})
    assert claudesignin.token(h.signin_store) is None
    assert h.signins.status() == {"nonce": NONCE, "tool": "claude", "state": "failed", "reason": "decrypt"}


def test_the_bootstrap_prints_the_key_fingerprint_before_the_lock_down():
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "tools" / "bootstrap.ps1").read_text(encoding="ascii")
    main = text.split("InvocationName -eq '.') { return }")[1]
    block = main.split("try {")[1].split("} finally {")[0]
    assert block.index("Invoke-Enrol") < block.index("Show-SignInKey") < block.index("Invoke-SignIn")
