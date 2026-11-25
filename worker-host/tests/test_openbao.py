"""Host secrets in OpenBao (docs/openbao-design.md, phase 1)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import HOST_A, FakeVault
from workerhost import busclient, launcher, openbao, resources
from workerhost import config as config_mod
from workerhost.config import Config, OpenBao
from workerhost.host import OPENBAO_DOWN, OPENBAO_UP, Host
from workerhost.validate import REPLY_KIND

TOKEN = "s.tok-0123456789"  # a fake test value  # gitleaks:allow
SECRET = "sb1_worker-secret-value"
SPN = "sbsp1_spn-secret-value"


class FakeBao:
    """KV v2 under agents/, cert login, revoke-self. Records every call (without secrets in assertions)."""

    def __init__(self, login_status=200, up=True):
        self.kv: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.login_status = login_status
        self.up = up
        self.live_tokens: set[str] = set()
        self.logins = 0
        self.login_bodies: list[dict] = []

    def __call__(self, method, path, token, body):
        if not self.up:
            raise openbao.OpenBaoError(0, "unreachable")
        self.calls.append((method, path))
        if path == "/v1/sys/health":
            return 200, {"initialized": True, "sealed": False}
        if path == "/v1/auth/cert/login":
            self.login_bodies.append(body)
            if self.login_status != 200:
                return self.login_status, None
            self.logins += 1
            tok = f"{TOKEN}-{self.logins}"
            self.live_tokens.add(tok)
            return 200, {"auth": {"client_token": tok}}
        if token not in self.live_tokens:
            return 403, None
        if path == "/v1/auth/token/revoke-self":
            self.live_tokens.discard(token)
            return 204, None
        if path.startswith("/v1/agents/data/"):
            key = path[len("/v1/agents/data/"):]
            if method == "GET":
                return (200, {"data": {"data": self.kv[key], "metadata": {}}}) if key in self.kv else (404, None)
            if method == "POST":
                self.kv[key] = dict(body["data"])
                return 200, {"data": {"version": 1}}
        if path.startswith("/v1/agents/metadata/") and method == "DELETE":
            self.kv.pop(path[len("/v1/agents/metadata/"):], None)
            return 204, None
        return 405, None


def client(bao: FakeBao) -> openbao.Client:
    return openbao.Client(bao, "host-alpha", "agents", "host-alpha")


# --- the client -------------------------------------------------------------------------------------------


def test_session_logs_in_with_the_role_and_revokes_its_token():
    bao = FakeBao()
    with client(bao).session() as s:
        s.write("selftest", {"x": "1"})
        assert s.read("selftest") == {"x": "1"}
        s.destroy("selftest")
        assert s.read("selftest") is None
    assert bao.login_bodies == [{"name": "host-alpha"}]
    assert bao.live_tokens == set()
    assert ("DELETE", "/v1/agents/metadata/host-alpha/selftest") in bao.calls  # destroy, not soft delete


def test_token_is_revoked_even_when_a_call_fails():
    bao = FakeBao()
    with pytest.raises(openbao.OpenBaoError):
        with client(bao).session() as s:
            s.client.transport = lambda m, p, t, b: (500, None) if "/data/" in p else bao(m, p, t, b)
            s.read("x")
    assert bao.live_tokens == set()


@pytest.mark.parametrize("status", [400, 403, 500])
def test_failed_login_raises_and_never_falls_back(status):
    bao = FakeBao(login_status=status)
    store = openbao.Store(client(bao), "host-alpha-host")
    with pytest.raises(openbao.OpenBaoError) as e:
        store.load_spn()
    assert e.value.status == status and isinstance(e.value, OSError)


def test_errors_carry_no_secret():
    bao = FakeBao()
    store = openbao.Store(client(bao), "host-alpha-host")
    store.save("host-alpha-core14", {"secret": SECRET})
    bao.up = False
    with pytest.raises(OSError) as e:
        store.load("host-alpha-core14")
    assert SECRET not in str(e.value) and TOKEN not in str(e.value)


def test_bad_path_segments_are_refused():
    store = openbao.Store(client(FakeBao()), "host-alpha-host")
    for bad in ("../x", "a/b", "UPPER", "", "x" * 200):
        with pytest.raises(ValueError):
            store.save(bad, {})
    with pytest.raises(ValueError):
        openbao.Client(FakeBao(), "../other")


def test_missing_leaf_fails_each_call_and_health_is_false(tmp_path):
    t = openbao.https_transport("https://vault.invalid:8200", "", str(tmp_path / "leaf.crt"), str(tmp_path / "leaf.key"))
    with pytest.raises(openbao.OpenBaoError) as e:
        t("GET", "/v1/sys/health", None, None)
    assert e.value.what == "leaf missing"
    assert openbao.Client(t, "host-alpha").health() is False


# --- the store --------------------------------------------------------------------------------------------


def test_store_paths_spn_host_and_workers():
    bao = FakeBao()
    store = openbao.Store(client(bao), "host-alpha-host")
    store.save_spn(SPN + "\n")
    store.save("host-alpha-host", {"agent_name": "host-alpha-host", "secret": "h"})
    store.save("host-alpha-core14", {"agent_name": "host-alpha-core14", "secret": SECRET})
    assert set(bao.kv) == {"host-alpha/strugglebus-spn", "host-alpha/strugglebus", "host-alpha/workers/host-alpha-core14"}
    assert store.load_spn() == SPN
    assert store.load("host-alpha-core14")["secret"] == SECRET
    assert store.has("host-alpha-core14") and not store.has("host-alpha-core15")
    with pytest.raises(LookupError):
        store.load("host-alpha-core15")
    store.remove("host-alpha-core14")
    assert not store.has("host-alpha-core14")
    assert bao.live_tokens == set()  # every operation revoked its own token


def test_no_spn_is_a_lookup_error():
    with pytest.raises(LookupError):
        openbao.Store(client(FakeBao()), "host-alpha-host").load_spn()


# --- the worker's environment and bus client --------------------------------------------------------------


def test_worker_env_with_a_token_names_no_store_and_drops_inherited_ones(tmp_path):
    base = {"PATH": "x", "SB_BUS_STORE": "C:\\old", "SB_BUS_TOKEN": "inherited"}
    env = launcher.worker_env(base, bus_ca="ca", bus_url="u", store=None, token=SECRET, temp=tmp_path, gh_exe="gh",
                              wait_timeout=60)
    assert env["SB_BUS_TOKEN"] == SECRET
    assert "SB_BUS_STORE" not in env
    dpapi = launcher.worker_env(base, bus_ca="ca", bus_url="u", store=tmp_path, temp=tmp_path, gh_exe="gh",
                                wait_timeout=60)
    assert dpapi["SB_BUS_STORE"] == str(tmp_path) and "SB_BUS_TOKEN" not in dpapi


def test_worker_env_needs_exactly_one_credential_source(tmp_path):
    for store, token in ((None, None), (tmp_path, SECRET)):
        with pytest.raises(ValueError):
            launcher.worker_env({}, bus_ca="ca", bus_url="u", store=store, token=token, temp=tmp_path, gh_exe="gh",
                                wait_timeout=60)


def test_busclient_uses_the_token_and_never_a_store(tmp_path):
    bus = busclient.client_for("host-alpha-core14", env={"SB_BUS_TOKEN": SECRET, "SB_BUS_STORE": str(tmp_path),
                                                         "SB_BUS_URL": "https://bus.test", "SB_BUS_CA": "ca"})
    assert bus.token == SECRET and bus.base == "https://bus.test"


def test_busclient_without_any_credential_fails_closed():
    with pytest.raises(LookupError):
        busclient.client_for("host-alpha-core14", env={})


# --- the host ---------------------------------------------------------------------------------------------


@pytest.fixture
def bao_host(tmp_path, shared_bus, monkeypatch):
    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(
        100 * resources.GB, 10 * resources.GB, 100 * resources.GB, 128 * resources.GB, 500 * resources.GB, set()))
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", poll_seconds=0, settle_seconds=0,
                 workers_root=tmp_path / "w", home=tmp_path / "home", openbao=OpenBao(enabled=True))
    bao = FakeBao()
    monkeypatch.setattr("workerhost.host.openbao_client", lambda c: client(bao))
    h = Host(cfg, bus=shared_bus.client(HOST_A), vault=FakeVault())
    h.pins = {"host": HOST_A}
    h.fake_bao = bao
    return h


def test_host_with_openbao_uses_it_and_no_dpapi_store(bao_host):
    assert isinstance(bao_host.store, openbao.Store)
    assert not (bao_host.cfg.home / "creds").exists()


def test_ensure_identity_mints_once_into_openbao_then_reuses_it(bao_host, monkeypatch):
    bao = bao_host.fake_bao
    bao_host.store.save_spn(SPN)
    minted = []

    def fake_onboard(bus, spn, agent, description, identity_ttl_seconds=None):
        assert identity_ttl_seconds is None  # phase 1: durable
        assert spn == SPN
        minted.append(agent)
        return {"agent_id": "id", "agent_name": agent, "secret": SECRET, "credential_id": "c", "credential_version": 0,
                "credential_epoch": 1, "base_url": "u"}

    monkeypatch.setattr("workerhost.host.onboard", fake_onboard)
    monkeypatch.setattr("workerhost.host.bootstrap", lambda bus, rec, channels: [])
    first = bao_host.ensure_identity("host-alpha-core14")
    again = bao_host.ensure_identity("host-alpha-core14")  # a later task or a resume
    assert minted == ["host-alpha-core14"]
    assert first["secret"] == again["secret"] == SECRET
    assert json.loads(json.dumps(bao.kv["host-alpha/workers/host-alpha-core14"]))["secret"] == SECRET
    assert bao.live_tokens == set()


def test_unreachable_openbao_refuses_new_tasks_and_posts_the_fixed_wording_once(bao_host, shared_bus):
    bao_host.fake_bao.up = False
    bao_host.openbao_tick(force=True)
    bao_host.openbao_tick(force=True)
    assert bao_host.resource_verdict() == ("openbao", {})
    assert "openbao=unreachable" in bao_host.heartbeat_line()
    bao_host.fake_bao.up = True
    bao_host.openbao_tick(force=True)
    assert bao_host.resource_verdict() is None
    assert "openbao=ok" in bao_host.heartbeat_line()
    texts = [m["body"] for m in shared_bus.messages]
    assert texts == [f"host=alpha {OPENBAO_DOWN}", f"host=alpha {OPENBAO_UP}"]


def test_a_queued_vault_line_is_superseded_by_the_next_one(bao_host, shared_bus):
    bus, bao_host.bus = bao_host.bus, None  # no bus: posts go to the outbox
    bao_host.fake_bao.up = False
    bao_host.openbao_tick(force=True)
    bao_host.fake_bao.up = True
    bao_host.openbao_tick(force=True)
    assert [i["text"] for i in bao_host.st.data["outbox"]] == [f"host=alpha {OPENBAO_UP}"]
    bao_host.bus = bus
    bao_host.flush_outbox()
    assert [m["body"] for m in shared_bus.messages] == [f"host=alpha {OPENBAO_UP}"]


def test_a_vault_line_from_before_a_restart_is_dropped_when_untrue(bao_host, shared_bus):
    # The dev host rebuild: a probe run with no leaf queued "unreachable"; the real start an hour later had a leaf.
    bus, bao_host.bus = bao_host.bus, None
    bao_host.fake_bao.up = False
    bao_host.openbao_tick(force=True)
    bao_host.openbao_ok = True  # what a restarted host starts with; its own check posts any change
    bao_host.bus = bus
    bao_host.flush_outbox()
    assert shared_bus.messages == [] and bao_host.st.data["outbox"] == []


def test_a_late_status_event_says_so_and_a_task_reply_is_never_altered(bao_host, shared_bus):
    bus, bao_host.bus = bao_host.bus, None
    bao_host.post("status", "host=alpha spn-rotated")
    bao_host.post(REPLY_KIND, "reply body", reply_to=7)
    for item in bao_host.st.data["outbox"]:
        item["queued_at"] -= 3600
    bao_host.post("status", "host=alpha fresh")
    bao_host.bus = bus
    bao_host.flush_outbox()
    bodies = [m["body"] for m in shared_bus.messages]
    assert bodies[0].startswith("host=alpha spn-rotated (queued ") and bodies[0].endswith(", sent late)")
    assert bodies[1:] == ["reply body", "host=alpha fresh"]


def test_wording_is_what_the_siem_rule_matches():
    assert OPENBAO_DOWN == "vault unreachable, no new tasks"
    assert OPENBAO_UP == "vault reachable, taking tasks"


def test_host_without_openbao_has_no_openbao_field(tmp_path, shared_bus, monkeypatch):
    monkeypatch.setattr(resources, "sample", lambda root: None)
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", home=tmp_path / "home", workers_root=tmp_path / "w")
    h = Host(cfg, bus=shared_bus.client(HOST_A), vault=FakeVault())
    h.pins = {"host": HOST_A}
    assert h.openbao is None and "openbao=" not in h.heartbeat_line()


# --- config -----------------------------------------------------------------------------------------------


def write_config(tmp_path: Path, extra: str) -> Path:
    p = tmp_path / "config.toml"
    p.write_text('host_name = "alpha"\nagent_prefix = "host-alpha"\n' + extra, encoding="utf-8")
    return p


def test_config_reads_the_openbao_section(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "home_dir", lambda: tmp_path)
    cfg = config_mod.load(write_config(tmp_path, '[openbao]\nenabled = true\nurl = "https://vault.example.lan:8200"\n'
                                                 'ca_url = "https://ca.example.lan"\n'))
    assert cfg.openbao.enabled is True and cfg.openbao_prefix == "host-alpha"
    assert cfg.leaf_dir == tmp_path / "leaf"
    assert config_mod.load(write_config(tmp_path, "")).openbao.enabled is False
    with pytest.raises(ValueError, match="ca_url"):  # once on, both URLs are needed: there is no site default
        config_mod.load(write_config(tmp_path, '[openbao]\nenabled = true\nurl = "https://vault.example.lan:8200"\n'))


@pytest.mark.parametrize("extra", ['[openbao]\nurl = "http://vault:8200"\n', '[openbao]\nprefix = "../x"\n',
                                   '[openbao]\nenabled = "yes"\n', '[openbao]\nsurprise = 1\n',
                                   '[openbao]\ncheck_minutes = 0\n'])
def test_config_refuses_bad_openbao_values(tmp_path, monkeypatch, extra):
    monkeypatch.setattr(config_mod, "home_dir", lambda: tmp_path)
    with pytest.raises(ValueError):
        config_mod.load(write_config(tmp_path, extra))
