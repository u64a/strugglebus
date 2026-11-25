"""setup/30-openbao.ps1 (pure functions, dot-sourced), the leaf helpers in openbao.py, and `wh openbao`.

Nothing here reaches step-ca or OpenBao: the CA calls and OpenBao are faked.
"""
from __future__ import annotations

import io
import json
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from pshelp import ps
from test_debloat import SHELLS
from test_openbao import SPN, FakeBao, client

from workerhost import cli, creds, openbao, winapi
from workerhost.config import Config, OpenBao

ROOT = Path(__file__).resolve().parent.parent
SETUP = ROOT / "setup" / "30-openbao.ps1"
PWSH = [s for s in SHELLS if "pwsh" in s.lower()]


@pytest.fixture(params=SHELLS)
def shell(request):
    return request.param


def test_plan_is_empty_for_a_valid_leaf_and_complete_for_none(shell):
    got = ps(shell, SETUP, r"""
$good = [pscustomobject]@{ Folder = 'x'; FolderOwnerOnly = $true; LeafSans = @('host-box2.example.lan'); HoursLeft = 50 }
$none = [pscustomobject]@{ Folder = 'x'; FolderOwnerOnly = $false; LeafSans = @(); HoursLeft = 0 }
$wrong = [pscustomobject]@{ Folder = 'x'; FolderOwnerOnly = $true; LeafSans = @('host-box1.example.lan'); HoursLeft = 50 }
$late = [pscustomobject]@{ Folder = 'x'; FolderOwnerOnly = $true; LeafSans = @('host-box2.example.lan'); HoursLeft = 1 }
[ordered]@{
  good = @(Get-LeafPlan $good 'host-box2.example.lan' $false | ForEach-Object Id)
  force = @(Get-LeafPlan $good 'host-box2.example.lan' $true | ForEach-Object Id)
  none = @(Get-LeafPlan $none 'host-box2.example.lan' $false | ForEach-Object Id)
  wrong = @(Get-LeafPlan $wrong 'host-box2.example.lan' $false | ForEach-Object Id)
  late = @(Get-LeafPlan $late 'host-box2.example.lan' $false | ForEach-Object Id)
  names = @('host-box2.example.lan', 'Host-X.example.lan', 'x.example.com', 'a.b.example.lan', '-x.example.lan', 'nodomain', 'x.home.lan;evil' | ForEach-Object { Test-SanName $_ })
  san = Get-DefaultSan "agent_prefix = `"host-a`"`n[openbao]`nenabled = true`nsan_domain = `"home.lan`"`n"
  nodomain = Get-DefaultSan "agent_prefix = `"host-a`"`n[openbao]`nenabled = true`n[update]`nsan_domain = `"x.lan`"`n"
  noprefix = Get-DefaultSan "[openbao]`nsan_domain = `"home.lan`"`n"
} | ConvertTo-Json -Depth 3
""")
    assert got["good"] == []
    assert got["force"] == ["key", "enrol"]
    assert got["none"] == ["folder", "key", "enrol"]
    assert got["wrong"] == ["key", "enrol"] and got["late"] == ["key", "enrol"]
    # Any lowercase DNS name of two labels or more: the LAN domain is a setting, not this repository's own.
    assert got["names"] == [True, False, True, True, False, False, False]
    assert got["san"] == "host-a.home.lan"
    assert got["nodomain"] is None and got["noprefix"] is None  # san_domain only counts inside [openbao]


@pytest.mark.skipif(not PWSH, reason="needs PowerShell 7")
def test_key_and_csr_are_what_step_ca_and_python_ssl_accept(tmp_path):
    # The CSR names the SAN; the PKCS#8 key loads in Python's ssl (what the host uses for mTLS).
    out = ps(PWSH[0], SETUP, r"""
$r = New-LeafRequest 'host-box2.example.lan'
$self = $r.Request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(72))
[IO.File]::WriteAllText('""" + str(tmp_path / "leaf.key") + r"""', $r.Key)
[IO.File]::WriteAllText('""" + str(tmp_path / "leaf.crt") + r"""', (ConvertTo-Pem 'CERTIFICATE' $self.RawData))
$csr = [System.Security.Cryptography.X509Certificates.CertificateRequest]::LoadSigningRequestPem($r.Csr,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]::UnsafeLoadCertificateExtensions)
$sanExt = $csr.CertificateExtensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
[ordered]@{
  subject = $csr.SubjectName.Name
  sans = @($sanExt.EnumerateDnsNames())
  csr = $r.Csr.StartsWith('-----BEGIN CERTIFICATE REQUEST-----')
  key = $r.Key.StartsWith('-----BEGIN PRIVATE KEY-----')
} | ConvertTo-Json -Depth 3
""")
    assert out == {"subject": "CN=host-box2.example.lan", "sans": ["host-box2.example.lan"], "csr": True, "key": True}
    ctx = ssl.create_default_context()
    ctx.load_cert_chain(str(tmp_path / "leaf.crt"), str(tmp_path / "leaf.key"))
    assert openbao.leaf_san(tmp_path / "leaf.crt") == ["host-box2.example.lan"]
    left = (openbao.leaf_not_after(tmp_path / "leaf.crt") - time.time()) / 3600
    assert 71 < left <= 72


def test_leaf_helpers_on_missing_files(tmp_path):
    assert openbao.leaf_not_after(tmp_path / "none.crt") is None
    assert openbao.leaf_san(tmp_path / "none.crt") == []


CERT = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"


def test_sign_sends_the_token_in_the_body_and_returns_the_chain(monkeypatch):
    seen = {}

    def fake_post(ca_url, ca_file, path, body, cert=None, timeout=30):
        seen.update(path=path, body=body, cert=cert)
        return {"crt": CERT, "ca": CERT.replace("AAAA", "BBBB")}

    monkeypatch.setattr(openbao, "_ca_post", fake_post)
    chain = openbao.sign_leaf("https://ca.example.lan", "root.crt", "CSR", "a.b.c", "72h")
    assert seen == {"path": "/1.0/sign", "body": {"csr": "CSR", "ott": "a.b.c", "notAfter": "72h"}, "cert": None}
    assert chain.count("BEGIN CERTIFICATE") == 2 and "BBBB" in chain


def test_renew_uses_the_leaf_and_rejects_an_odd_answer(monkeypatch, tmp_path):
    monkeypatch.setattr(openbao, "_ca_post", lambda *a, **k: {"certChain": [CERT]})
    assert openbao.renew_leaf("https://ca", "root", tmp_path) == CERT
    monkeypatch.setattr(openbao, "_ca_post", lambda *a, **k: {"crt": "not a cert"})
    with pytest.raises(openbao.OpenBaoError):
        openbao.renew_leaf("https://ca", "root", tmp_path)


def test_ca_errors_carry_the_status_only(monkeypatch):
    import urllib.error

    def boom(req, timeout, context):
        raise urllib.error.HTTPError(req.full_url, 401, "no", {}, io.BytesIO(b'{"message":"token a.b.c used"}'))

    monkeypatch.setattr(openbao.urllib.request, "urlopen", boom)
    with pytest.raises(openbao.OpenBaoError) as e:
        openbao.sign_leaf("https://ca.example.lan", "", "CSR", "a.b.c")
    assert e.value.status == 401 and "a.b.c" not in str(e.value)


# --- the host renews --------------------------------------------------------------------------------------


def test_host_renews_only_under_48_hours_and_only_hourly(tmp_path, monkeypatch):
    from conftest import HOST_A, FakeVault, SharedBus
    from workerhost import resources
    from workerhost.host import Host

    monkeypatch.setattr(resources, "sample", lambda root: None)
    monkeypatch.setattr("workerhost.host.openbao_client", lambda c: client(FakeBao()))
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", home=tmp_path / "home", workers_root=tmp_path / "w",
                 openbao=OpenBao(enabled=True))
    h = Host(cfg, bus=SharedBus().client(HOST_A), vault=FakeVault())
    h.pins = {"host": HOST_A}
    left = {"h": 60.0}
    monkeypatch.setattr(h, "leaf_hours_left", lambda: left["h"])
    renewed = []
    monkeypatch.setattr(openbao, "renew_leaf", lambda *a: renewed.append(a) or CERT)
    monkeypatch.setattr(openbao, "write_leaf", lambda d, c: None)
    now = time.time()
    h.renew_leaf_if_due(now)
    assert renewed == []
    left["h"] = 47.0
    h.renew_leaf_if_due(now + 60)  # within the hour: not checked again
    assert renewed == []
    h.renew_leaf_if_due(now + 3601)
    assert len(renewed) == 1
    assert "leaf=47h" in h.heartbeat_line()


# --- wh openbao -------------------------------------------------------------------------------------------


@pytest.fixture
def wh(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('host_name = "alpha"\nagent_prefix = "host-alpha"\n[openbao]\nenabled = true\n'
                                      'url = "https://vault.example.lan:8200"\nca_url = "https://ca.example.lan"\n',
                                      encoding="utf-8")
    monkeypatch.setenv("WORKERHOST_HOME", str(home))
    bao = FakeBao()
    monkeypatch.setattr("workerhost.host.openbao_client", lambda c: client(bao))

    def run(*argv, stdin=""):
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
        return cli.main(["--home", str(home), *argv])

    return run, bao, home


def test_seed_spn_from_stdin_stores_and_reads_back(wh, capsys):
    run, bao, _ = wh
    assert run("openbao", "seed-spn", "--spn-stdin", stdin=SPN + "\n") == 0
    assert bao.kv["host-alpha/strugglebus-spn"] == {"secret": SPN}
    out = capsys.readouterr().out
    assert "stored and read back" in out and SPN not in out


def test_seed_spn_refuses_something_that_is_not_an_spn(wh, capsys):
    run, bao, _ = wh
    assert run("openbao", "seed-spn", "--spn-stdin", stdin="sb1_not-an-spn-at-all\n") == 1
    assert bao.kv == {}


def test_status_logs_in_and_cleans_up_its_selftest(wh, capsys):
    run, bao, _ = wh
    assert run("openbao", "status") == 0
    out = capsys.readouterr().out
    assert "login and own-prefix write/read/destroy: ok" in out and "SPN: missing" in out
    assert "host-alpha/selftest" not in bao.kv and bao.live_tokens == set()


def test_status_reports_a_failed_login_without_secrets(wh, capsys):
    run, bao, _ = wh
    bao.login_status = 403
    assert run("openbao", "status") == 1
    assert "failed (login, HTTP 403)" in capsys.readouterr().out


@pytest.mark.skipif(not winapi.IS_WINDOWS, reason="DPAPI")
def test_migrate_copies_spn_and_every_identity_then_deletes_only_when_asked(wh, capsys):
    run, bao, home = wh
    dpapi = creds.Store(home / "creds")
    dpapi.save_spn(SPN)
    dpapi.save("host-alpha-host", {"agent_name": "host-alpha-host", "secret": "sb1_host"})
    dpapi.save("host-alpha-core14", {"agent_name": "host-alpha-core14", "secret": "sb1_core14"})
    dpapi.save("someone-else", {"agent_name": "someone-else", "secret": "sb1_x"})
    assert run("openbao", "migrate") == 0
    assert bao.kv["host-alpha/strugglebus-spn"] == {"secret": SPN}
    assert bao.kv["host-alpha/strugglebus"]["secret"] == "sb1_host"
    assert bao.kv["host-alpha/workers/host-alpha-core14"]["secret"] == "sb1_core14"
    assert not any("someone-else" in k for k in bao.kv)
    assert (home / "creds").is_dir()  # kept until asked
    out = capsys.readouterr().out
    assert "2 of 3 identities copied" in out and "sb1_" not in out
    assert run("openbao", "migrate", "--delete-dpapi") == 0
    assert not (home / "creds").exists()


def test_enrol_refuses_without_a_key_and_csr(wh, capsys):
    run, _, home = wh
    assert run("openbao", "enrol", "--token-stdin", stdin="a.b.c\n") == 1
    assert "no key and CSR" in capsys.readouterr().out


def test_enrol_writes_the_leaf_and_removes_the_csr(wh, capsys, monkeypatch):
    run, _, home = wh
    leaf = home / "leaf"
    leaf.mkdir()
    (leaf / "leaf.key").write_text("KEY", encoding="ascii")
    (leaf / "leaf.csr").write_text("CSR", encoding="ascii")
    got = {}
    monkeypatch.setattr(openbao, "sign_leaf", lambda url, ca, csr, token, na: got.update(csr=csr, token=token, na=na)
                        or CERT)
    assert run("openbao", "enrol", "--token-stdin", stdin="h.p.s\n") == 0
    assert got == {"csr": "CSR", "token": "h.p.s", "na": "72h"}
    assert (leaf / "leaf.crt").read_text(encoding="ascii") == CERT and not (leaf / "leaf.csr").exists()
    assert "h.p.s" not in capsys.readouterr().out
