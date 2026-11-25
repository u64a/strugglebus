"""Enrol with the App's one-time code (workerhost/hostenrol.py, `wh enrol --code-stdin`; docs/app-host-integration.md
section 2.2 step 8): the redeem contract agreed with the bus, the kept request id, the M1 confirmation code, and that
neither the code nor the credential is ever printed."""
from __future__ import annotations

import hashlib
import io
import json
from types import SimpleNamespace as NS

import pytest

from workerhost import cli, config, creds, hostenrol

CODE = "sbhe1_" + "A" * 22 + "_" + "b" * 43
SECRET = "sbsp1_" + "7f3e" * 10
RID = "0b9e6f3a-2c1d-4e5f-8a7b-6c5d4e3f2a1b"
AGENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


class Bus:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def call(self, method, path, *, body=None, query=None, token=None):
        self.calls.append((method, path, body, token))
        return self.answers.pop(0)


def ok(status=201, **over):
    body = {"name": "host-box1", "credential": SECRET, "request_id": RID}
    body.update(over)
    return status, body


def test_a_redeem_sends_the_code_as_bearer_and_only_the_request_id_in_the_body():
    bus = Bus(ok())
    assert hostenrol.redeem(bus, CODE, RID, "host-box1") == SECRET
    assert bus.calls == [("POST", hostenrol.REDEEM_PATH, {"request_id": RID}, CODE)]  # the code is the bearer, not in the body
    assert hostenrol.redeem(Bus(ok(200)), CODE, RID, "host-box1") == SECRET  # a replay with the same request id


@pytest.mark.parametrize("status, code", [(400, "bad-request"), (422, "bad-request"), (401, "unknown-or-used-code"), (404, "unknown-or-used-code"), (410, "expired"),
                                          (409, "name-taken"), (503, "unavailable"), (500, "unexpected")])
def test_every_refusal_has_a_fixed_message_and_nothing_from_the_bus_is_shown(status, code):
    with pytest.raises(hostenrol.EnrolError) as e:
        hostenrol.redeem(Bus((status, {"detail": "ZZ-from-the-bus-ZZ"})), CODE, RID, "host-box1")
    assert e.value.code == code and "ZZ-from-the-bus-ZZ" not in str(e.value)


def test_a_rate_limit_is_retried_then_given_up():
    slept = []
    assert hostenrol.redeem(Bus((429, {}), ok()), CODE, RID, "host-box1", sleep=slept.append) == SECRET
    with pytest.raises(hostenrol.EnrolError) as e:
        hostenrol.redeem(Bus((429, {}), (429, {}), (429, {})), CODE, RID, "host-box1", sleep=slept.append)
    assert e.value.code == "rate-limited" and slept == [30, 30, 60]


@pytest.mark.parametrize("answer, code", [
    (ok(name="host-other"), "wrong-name"),           # a credential for another host is refused
    (ok(request_id="ffffffff-ffff-4fff-8fff-ffffffffffff"), "bad-reply"),
    (ok(credential="not-an-spn"), "bad-reply"),
    ((201, ["not", "an", "object"]), "bad-reply"),
])
def test_a_reply_that_is_not_for_this_host_is_refused(answer, code):
    with pytest.raises(hostenrol.EnrolError) as e:
        hostenrol.redeem(Bus(answer), CODE, RID, "host-box1")
    assert e.value.code == code


def test_a_code_of_the_wrong_shape_is_never_sent():
    bus = Bus()
    with pytest.raises(hostenrol.EnrolError) as e:
        hostenrol.redeem(bus, "sbhe1_short", RID, "host-box1")
    assert e.value.code == "bad-code" and bus.calls == []


def test_the_request_id_is_made_once_and_kept(tmp_path):
    rid = hostenrol.request_id(tmp_path)
    assert hostenrol.UUID_RE.fullmatch(rid) and hostenrol.request_id(tmp_path) == rid
    (tmp_path / hostenrol.STATE_FILE).write_text("not json", encoding="utf-8")
    assert hostenrol.request_id(tmp_path) != rid  # a damaged file gets a fresh id


def test_the_confirmation_code_is_the_agreed_bytes():
    expected = hashlib.sha256(f"{AGENT_ID}\n{RID}".encode("utf-8")).hexdigest()[:8]
    assert hostenrol.confirmation_code(AGENT_ID, RID) == expected
    assert hostenrol.confirmation_code(AGENT_ID.upper(), RID.upper()) == expected  # lowercase on both sides
    # the vector the App and the bus pin too (agreed with the bus)
    assert hostenrol.confirmation_code("3b283d99-7521-4216-aceb-d39e6b5d5402",
                                       "11111111-2222-4333-8444-555555555555") == "6be98e36"


# --- wh enrol --code-stdin ------------------------------------------------------------------------------------------

class Store:
    saved, spn = {}, None

    def __init__(self, folder=None):
        pass

    def has(self, name):
        return name in Store.saved

    def save(self, name, record):
        Store.saved[name] = record

    def save_spn(self, spn):
        Store.spn = spn


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('host_name = "box1"\nagent_prefix = "host-box1"\nscheduled_task = ""\n'
                                      'bus_url = "https://bus.example.lan"\n', encoding="utf-8")
    monkeypatch.setenv("WORKERHOST_HOME", str(home))
    Store.saved, Store.spn = {}, None
    monkeypatch.setattr(creds, "Store", Store)
    return config.load()


def test_enrol_with_a_code_prints_the_confirmation_code_and_never_a_secret(cfg, monkeypatch, capsys):
    bus = Bus(ok())
    monkeypatch.setattr(cli, "Bus", lambda *a, **k: bus)
    monkeypatch.setattr(hostenrol, "request_id", lambda state_dir: RID)
    record = {"agent_id": AGENT_ID, "agent_name": "host-box1-host", "secret": "sbse1_" + "9" * 30}
    onboarded = []
    monkeypatch.setattr(cli, "onboard", lambda b, spn, name, desc: onboarded.append((spn, name)) or record)
    monkeypatch.setattr(cli, "bootstrap", lambda b, rec, channels: ["subscribe worker-hosts 200"])
    monkeypatch.setattr("sys.stdin", io.StringIO(CODE + "\n"))
    assert cli.cmd_enrol(cfg, NS(code_stdin=True, import_identity=None)) == 0
    out = capsys.readouterr().out
    assert Store.spn == SECRET and onboarded == [(SECRET, "host-box1-host")]
    assert f"CONFIRMATION CODE {hostenrol.confirmation_code(AGENT_ID, RID)}" in out
    assert SECRET not in out and CODE not in out and record["secret"] not in out
    assert json.loads((cfg.state_dir / "pins.json").read_text(encoding="utf-8"))["host"]["agent_id"] == AGENT_ID


def test_enrol_with_a_refused_code_stores_nothing(cfg, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Bus", lambda *a, **k: Bus((404, {"detail": "unknown-or-used-code"})))
    monkeypatch.setattr("sys.stdin", io.StringIO(CODE + "\n"))
    assert cli.cmd_enrol(cfg, NS(code_stdin=True, import_identity=None)) == 1
    assert Store.spn is None and Store.saved == {}
    assert "ask the App for a new script" in capsys.readouterr().out


def test_enrol_with_a_code_refuses_to_re_enrol(cfg, capsys):
    Store.saved[cfg.host_agent] = {"secret": "x"}
    assert cli.cmd_enrol(cfg, NS(code_stdin=True, import_identity=None)) == 1
    assert "refusing to re-enrol" in capsys.readouterr().out
