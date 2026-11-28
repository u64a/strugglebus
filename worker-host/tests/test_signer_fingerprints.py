"""The status's `signers` (u64-security, #humans 29197 item 4): the keys this host pins, so the App can warn when its
own signer set and a host's differ. Admin-only; the fingerprint, key type and namespaces, never the key or its name."""
from __future__ import annotations

import json

from workerhost import hoststatus, signing

LINES = (
    'chris-yubikey-A namespaces="strugglebus-fleet,strugglebus-host-command" sk-ssh-ed25519@openssh.com '
    "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIN56hk/clV5r0XsK7JkOlTLz0Zyri/QEhaIqCnmd+5yOAAAAF3NzaDpzdHJ1Z2dsZWJ1cy1zaWduaW5n"
    " backup-A\n"
    'release namespaces="strugglebus-release" sk-ssh-ed25519@openssh.com '
    "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIMLHD9G3fCyGMJ8RlHGYzaB7P3efJFqoQoQZ1AxivmUFAAAAF3NzaDpzdHJ1Z2dsZWJ1cy1zaWduaW5n\n"
    "# a comment\n"
    "not a signer line at all\n"
)


def facts(**over):
    base = dict(host="h", agent="host-h-host", version="v", serial=1, started_at=0, interval_s=60,
                reported_state="idle", account="x", dedicated=True, engines=[], busy=0, max_workers=1, claiming=0,
                held_clones=0, outbox=0, fleet={}, listed_in_fleet=True)
    return hoststatus.Facts(**{**base, **over})


def pinned(tmp_path):
    p = tmp_path / "allowed_signers"
    p.write_text(LINES, encoding="ascii")
    return [{"fingerprint": s.fingerprint, "key_type": s.key_type, "namespaces": s.namespaces}
            for s in signing.read_signers(p)]


def test_each_pinned_line_is_reported_by_fingerprint_only(tmp_path):
    snap = hoststatus.build_v2(facts(signers=pinned(tmp_path)))
    assert snap["signers"] == [
        {"fingerprint": "SHA256:xh5bC1DWKRzjLykESi8D5Qha6izhRNwkMJUyVMC2q2A", "key_type": "sk-ssh-ed25519@openssh.com",
         "namespaces": "strugglebus-fleet,strugglebus-host-command"},
        {"fingerprint": "SHA256:I621GOi+pKy3XIbahS6mmqKCn7pVnQaubqPigdMTzus", "key_type": "sk-ssh-ed25519@openssh.com",
         "namespaces": "strugglebus-release"},
    ]
    text = json.dumps(snap["signers"])
    assert "chris-yubikey-A" not in text and "backup-A" not in text and "AAAAGnNr" not in text  # no name, no key


def test_it_is_admin_only_and_not_in_the_v1_status_or_a_sample(tmp_path):
    f = facts(signers=pinned(tmp_path))
    snap = hoststatus.build_v2(f)
    assert "signers" not in hoststatus.for_device(snap)
    assert "signers" not in hoststatus.build(f)
    assert "signers" not in hoststatus.sample(snap, "2026-11-28T00:00:00Z")


def test_absent_when_unknown_and_empty_when_nothing_is_pinned():
    assert "signers" not in hoststatus.build_v2(facts())
    assert hoststatus.build_v2(facts(signers=[]))["signers"] == []


def test_malformed_values_never_go_out_and_the_list_is_capped():
    bad = [{"fingerprint": "SHA256:" + "x" * 43, "key_type": "ssh-ed25519", "namespaces": 'a",b'},  # a quote
           {"fingerprint": "not-a-fingerprint", "key_type": "ssh-ed25519", "namespaces": ""}]
    good = {"fingerprint": "SHA256:" + "A" * 43, "key_type": "ssh-ed25519", "namespaces": "strugglebus-fleet"}
    out = hoststatus.build_v2(facts(signers=bad + [good] * 20))["signers"]
    assert out == [good] * (hoststatus.MAX_SIGNERS - 2)


def test_the_total_counts_every_line_ssh_keygen_may_trust_so_an_extra_key_never_looks_identical(tmp_path):
    p = tmp_path / "allowed_signers"
    p.write_text(LINES, encoding="ascii")  # 2 parsed signers, a comment, and one line read_signers can't parse
    assert signing.count_signer_lines(p) == 3
    snap = hoststatus.build_v2(facts(signers=pinned(tmp_path), signers_total=signing.count_signer_lines(p)))
    assert len(snap["signers"]) == 2 and snap["signers_total"] == 3  # the App sees the difference and warns
    assert "signers_total" not in hoststatus.for_device(snap)
    assert signing.count_signer_lines(tmp_path / "missing") is None


def test_the_host_reports_its_own_pinned_file(tmp_path, monkeypatch):
    from conftest import HOST_A, FakeVault, SharedBus
    from workerhost import engines as engines_mod
    from workerhost import resources
    from workerhost.config import Config
    from workerhost.host import Host

    monkeypatch.setattr(resources, "sample", lambda root: None)
    monkeypatch.setattr(engines_mod, "resolve", lambda name: "C:\\bin\\copilot.exe")
    signers = tmp_path / "allowed_signers"
    signers.write_text(LINES, encoding="ascii")
    h = Host(Config(host_name="box1", agent_prefix="host-box1", home=tmp_path / "home", workers_root=tmp_path / "w"),
             bus=SharedBus().client(HOST_A), vault=FakeVault(), signers=signers)
    snap = hoststatus.build_v2(h.status_facts())
    assert [s["fingerprint"] for s in snap["signers"]] == ["SHA256:xh5bC1DWKRzjLykESi8D5Qha6izhRNwkMJUyVMC2q2A",
                                                           "SHA256:I621GOi+pKy3XIbahS6mmqKCn7pVnQaubqPigdMTzus"]
    assert snap["signers_total"] == 3
