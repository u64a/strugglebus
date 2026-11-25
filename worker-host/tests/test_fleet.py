"""fleet.toml (agent-host-build.md section 7.2, signing-keys.md): signed, serial-checked, last good kept.

Real ssh-keygen and real (local) git: test keys are plain ed25519 made here, never the owner's YubiKey keys.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from conftest import COORD, HOST_A, HOST_B, STRANGER, git, message, task_body
from workerhost import fleet, signing
from workerhost.validate import Pin, validate_task

pytestmark = pytest.mark.fleet

TEST = Pin("44444444-4444-4444-8444-444444444444", "sb-test-coordinator")
NAMESPACES = "strugglebus-fleet,strugglebus-baseline,strugglebus-release"


def fleet_text(serial: int = 1, extra: str = "", coordinators=(COORD, TEST), hosts=(HOST_A, HOST_B)) -> bytes:
    out = [f"serial = {serial}", extra, ""]
    for c in coordinators:
        project = "app" if c == COORD else "test"
        out += ["[[coordinator]]", f'agent_name = "{c.agent_name}"', f'agent_id = "{c.agent_id}"',
                f'project = "{project}"', 'notes_repo = "https://github.com/acme/team-notes"',
                'notes_channel = "Notes"', 'repos = ["https://github.com/acme/"]', ""]
    for h in hosts:
        out += ["[[host]]", f'agent_name = "{h.agent_name}"', f'agent_id = "{h.agent_id}"', ""]
    return "\n".join(out).encode()


# --- keys and signatures ----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keygen() -> str:
    found = signing.find_ssh_keygen()
    if not found:
        pytest.skip("no ssh-keygen on this machine")
    return found


@pytest.fixture(scope="module")
def keys(tmp_path_factory, keygen):
    d = tmp_path_factory.mktemp("keys")
    for name in ("alice", "stranger"):
        subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(d / name)], check=True,
                       capture_output=True)
    kind, blob = (d / "alice.pub").read_text().split()[:2]
    (d / "allowed_signers").write_text(f'alice namespaces="{NAMESPACES}" {kind} {blob} alice-test-key\n')
    return d


def sign(keys: Path, keygen: str, data: bytes, key: str = "alice", ns: str = signing.NS_FLEET) -> bytes:
    target = keys / f"payload-{abs(hash((data, key, ns)))}"
    target.write_bytes(data)
    Path(str(target) + ".sig").unlink(missing_ok=True)
    subprocess.run([keygen, "-Y", "sign", "-f", str(keys / key), "-n", ns, str(target)], check=True,
                   capture_output=True)
    return Path(str(target) + ".sig").read_bytes()


def test_a_good_signature_and_everything_that_is_not(keys, keygen, tmp_path):
    data = fleet_text()
    good = sign(keys, keygen, data)

    def check(d, s, ns=signing.NS_FLEET, signers=keys / "allowed_signers"):
        return signing.verify(d, s, ns, signers, keygen, tmp_path)

    v = check(data, good)
    assert v.ok and v.fingerprint.startswith("SHA256:")
    assert v.fingerprint == signing.read_signers(keys / "allowed_signers")[0].fingerprint
    assert check(data + b" ", good).reason == "bad-signature"                      # one byte more
    assert check(data, sign(keys, keygen, data, ns=signing.NS_BASELINE)).reason == "bad-signature"  # other namespace
    assert check(data, good, ns=signing.NS_BASELINE).reason == "bad-signature"
    assert check(data, sign(keys, keygen, data, key="stranger")).reason == "bad-signature"   # not a pinned key
    assert check(data, b"not a signature").reason == "sig-shape"
    assert check(data, good, signers=tmp_path / "missing").reason == "no-signers"
    assert signing.verify(data, good, signing.NS_FLEET, keys / "allowed_signers", None, tmp_path).reason == \
        "no-ssh-keygen"


def test_verify_hands_ssh_keygen_a_file_not_a_pipe_and_leaves_nothing_behind(keys, keygen, tmp_path, monkeypatch):
    # Windows' ssh-keygen hangs on a piped stdin when the caller is in an SSH session (a test host, 4 Nov 2026).
    data = fleet_text()
    good = sign(keys, keygen, data)
    seen = {}
    real_run = signing.subprocess.run

    def run(cmd, **kw):
        seen["stdin"], seen["input"] = kw.get("stdin"), kw.get("input")
        seen["bytes"] = Path(kw["stdin"].name).read_bytes()
        return real_run(cmd, **kw)

    monkeypatch.setattr(signing.subprocess, "run", run)
    work = tmp_path / "work"
    assert signing.verify(data, good, signing.NS_FLEET, keys / "allowed_signers", keygen, work).ok
    assert seen["input"] is None and hasattr(seen["stdin"], "fileno") and seen["bytes"] == data
    assert list(work.iterdir()) == []


def test_a_signer_list_reads_as_written():
    signers = signing.read_signers(Path(__file__).resolve().parent / "data" / "allowed_signers")
    assert [s.comment for s in signers] == ["test-key-A", "test-key-B"]
    assert all(s.principal == "alice" and s.key_type == "ssh-ed25519" and s.fingerprint.startswith("SHA256:")
               for s in signers)
    assert all(set(s.namespaces.split(",")) == set(NAMESPACES.split(",")) for s in signers)


# --- the file ----------------------------------------------------------------------------------------

def test_a_valid_fleet_parses():
    f = fleet.parse(fleet_text(serial=7))
    assert f.serial == 7 and [c.pin for c in f.coordinators] == [COORD, TEST]
    assert list(f.hosts) == [HOST_A, HOST_B]
    assert f.coordinator(TEST).project == "test" and f.coordinators[0].default_engine == "ghcp"


@pytest.mark.parametrize("text", [
    b"",                                                          # no serial
    b"serial = 0",
    b"serial = true",
    b'serial = "1"',
    b"serial = 1\n[[coordinator]]\nagent_name = \"x-y\"",        # incomplete
    fleet_text().replace(COORD.agent_id.encode(), b"NOT-A-UUID"),
    fleet_text().replace(b"https://github.com/acme/team-notes", b"http://github.com/a/b"),
    fleet_text().replace(b'repos = ["https://github.com/acme/"]', b"repos = []"),
    fleet_text().replace(b'repos = ["https://github.com/acme/"]', b'repos = ["https://github.com/a/b/c/"]'),
    fleet_text(coordinators=(COORD, COORD)),                      # the same agent twice
    fleet_text(hosts=(HOST_A, Pin(COORD.agent_id, "host-x"))),     # a host with a coordinator's id
    fleet_text(extra='[[coordinator]]\nagent_name = "a-b"'),
    b"serial = 1\ndefault_engine = ",                             # not TOML
])
def test_invalid_fleets_are_refused(text):
    with pytest.raises(fleet.FleetError) as e:
        fleet.parse(text)
    assert e.value.reason == "fleet-invalid"


def test_unknown_keys_are_ignored_and_listed_so_a_newer_file_does_not_stop_an_older_host():
    f = fleet.parse(fleet_text(extra='maintenance = "03:00"').replace(
        b'notes_channel = "Notes"', b'notes_channel = "Notes"\nbudget = 5', 1))
    assert f.ignored_keys == ("maintenance", "coordinator[0].budget")


@pytest.mark.parametrize("url,prefix,ok", [
    ("https://github.com/acme-labs/thing", "https://github.com/acme-labs/", True),
    ("https://github.com/acme-labs-evil/thing", "https://github.com/acme-labs/", False),
    ("https://github.com/acme-labs/thing.git", "https://github.com/acme-labs/thing", True),
    ("https://github.com/acme-labs/thing", "https://github.com/acme-labs/other", False),
    ("https://git.example.lan/alice/x", "https://git.example.lan/", True),
    ("https://git.example.lan/alice/x", "https://github.com/", False),
    ("http://github.com/acme-labs/thing", "https://github.com/acme-labs/", False),
    ("https://user@github.com/acme-labs/thing", "https://github.com/acme-labs/", False),
    ("https://github.com:443/acme-labs/thing", "https://github.com/acme-labs/", False),
    ("https://GitHub.com/acme-labs/thing", "https://github.com/acme-labs/", False),
    ("https://github.com/acme-labs/thing?x=1", "https://github.com/acme-labs/", False),
    ("https://github.com/acme-labs/..", "https://github.com/acme-labs/", False),
    ("https://github.com/acme-labs/a/b", "https://github.com/acme-labs/", False),
    ("ext::sh -c calc", "https://github.com/acme-labs/", False),
    ("file:///c:/x/y", "https://github.com/acme-labs/", False),
])
def test_repository_urls_match_whole_segments_only(url, prefix, ok):
    assert fleet.url_matches(url, prefix) is ok


# --- fetch, check, keep -------------------------------------------------------------------------------

@pytest.fixture
def origin(tmp_path):
    """A bare 'GitHub' repository with main, and a working clone to publish fleet.toml changes from."""
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", "-q", "-b", "main", str(bare)], check=True)
    work = tmp_path / "work"
    subprocess.run(["git", "clone", "-q", str(bare), str(work)], check=True, capture_output=True)
    for k, v in (("user.email", "t@example.invalid"), ("user.name", "test"), ("commit.gpgsign", "false"),
                 ("core.autocrlf", "true")):
        git(work, "config", k, v)
    (work / ".gitattributes").write_bytes(b"fleet.toml -text\n*.sig -text\n")
    (work / "README.md").write_text("x\n")
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "init")
    git(work, "push", "-q", "origin", "HEAD:main")
    return bare, work


def publish(work: Path, data: bytes | None, sig: bytes | None) -> str:
    for name, content in (("fleet.toml", data), ("fleet.toml.sig", sig)):
        if content is None:
            (work / name).unlink(missing_ok=True)
        else:
            (work / name).write_bytes(content)
    git(work, "add", "-A")
    git(work, "commit", "-q", "--allow-empty", "-m", "fleet")
    git(work, "push", "-q", "origin", "HEAD:main")
    return git(work, "rev-parse", "HEAD")


@pytest.fixture
def sync(origin, keys, keygen, tmp_path):
    bare, _ = origin
    return fleet.FleetSync(tmp_path / "home" / "fleet.git", tmp_path / "home" / "state" / "fleet", str(bare), "git",
                           keygen, keys / "allowed_signers")


def test_missing_then_unsigned_then_accepted_then_unchanged(sync, origin, keys, keygen):
    _, work = origin
    assert sync.refresh(None).status == "fleet-missing"
    publish(work, fleet_text(), None)
    assert sync.refresh(None).status == "fleet-unsigned"
    commit = publish(work, fleet_text(), sign(keys, keygen, fleet_text()))
    out = sync.refresh(None)
    assert out.status == "fleet-accepted" and out.fleet.serial == 1 and out.fleet.commit == commit
    assert out.detail == signing.read_signers(keys / "allowed_signers")[0].fingerprint
    assert sync.refresh(out.fleet).status == "unchanged"
    kept = sync.load_last_good()
    assert kept == out.fleet and sync.accepted()["serial"] == 1


def test_the_signed_bytes_survive_a_windows_checkout(sync, origin, keys, keygen):
    """CRLF in the file: -text keeps git from touching it, so the bytes read back are the bytes signed."""
    _, work = origin
    data = fleet_text().replace(b"\n", b"\r\n")
    publish(work, data, sign(keys, keygen, data))
    assert sync.refresh(None).status == "fleet-accepted"


@pytest.mark.parametrize("signed_by,ns,status", [
    ("stranger", signing.NS_FLEET, "fleet-bad-signature"),
    ("alice", signing.NS_BASELINE, "fleet-bad-signature"),
])
def test_a_signature_by_another_key_or_for_another_file_is_refused(sync, origin, keys, keygen, signed_by, ns,
                                                                   status):
    _, work = origin
    publish(work, fleet_text(), sign(keys, keygen, fleet_text(), key=signed_by, ns=ns))
    assert sync.refresh(None).status == status
    assert sync.load_last_good() is None and not sync.accepted()


def test_an_invalid_file_is_refused_even_when_signed(sync, origin, keys, keygen):
    _, work = origin
    bad = b"serial = 1\n[[coordinator]]\nagent_name = \"oops\"\n"
    publish(work, bad, sign(keys, keygen, bad))
    out = sync.refresh(None)
    assert out.status == "fleet-invalid" and "coordinator[0]" in out.detail


def test_serials_only_go_up(sync, origin, keys, keygen):
    _, work = origin
    two = fleet_text(serial=2)
    publish(work, two, sign(keys, keygen, two))
    current = sync.refresh(None).fleet
    # an older signed file put back
    one = fleet_text(serial=1)
    publish(work, one, sign(keys, keygen, one))
    assert sync.refresh(current).status == "fleet-old"
    # the same serial with different content (a serial used twice)
    two_b = fleet_text(serial=2, hosts=(HOST_A,))
    publish(work, two_b, sign(keys, keygen, two_b))
    assert sync.refresh(current).status == "fleet-old"
    # a host that lost its in-memory copy still remembers the serial
    assert sync.refresh(None).status == "fleet-old"
    three = fleet_text(serial=3, hosts=(HOST_A,))
    publish(work, three, sign(keys, keygen, three))
    out = sync.refresh(current)
    assert out.status == "fleet-accepted" and list(out.fleet.hosts) == [HOST_A]


def test_a_tampered_kept_copy_is_not_loaded(sync, origin, keys, keygen):
    _, work = origin
    publish(work, fleet_text(), sign(keys, keygen, fleet_text()))
    sync.refresh(None)
    kept = sync.store / "fleet.toml"
    kept.write_bytes(kept.read_bytes().replace(TEST.agent_id.encode(), STRANGER.agent_id.encode()))
    assert sync.load_last_good() is None


def test_fetch_failure_keeps_what_the_host_has(keys, keygen, tmp_path):
    s = fleet.FleetSync(tmp_path / "m.git", tmp_path / "store", str(tmp_path / "no-such-origin.git"), "git", keygen,
                        keys / "allowed_signers")
    assert s.refresh(None).status == "fetch-failed"


# --- the host ----------------------------------------------------------------------------------------

def test_a_task_from_any_fleet_coordinator_is_accepted_and_says_who_sent_it(ctx):
    ctx.coordinators = [COORD, TEST]
    d = validate_task(message(task_body(), sender=TEST), ctx)
    assert d.accepted and d.coordinator == TEST
    assert validate_task(message(task_body(), sender=STRANGER), ctx).reason == "sender"


@pytest.fixture
def host(tmp_path, keys, monkeypatch):
    from conftest import FakeVault
    from workerhost import resources
    from workerhost.config import Config
    from workerhost.host import Host

    monkeypatch.setattr(resources, "sample", lambda root: None)
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", poll_seconds=0, settle_seconds=0,
                 workers_root=tmp_path / "w", home=tmp_path / "home",
                 hosts=[{"agent_name": HOST_B.agent_name, "agent_id": HOST_B.agent_id}])
    h = Host(cfg, vault=FakeVault(), signers=keys / "allowed_signers")
    h.pins = {"coordinator": COORD, "host": HOST_A}
    h.posts = []
    h.post = lambda kind, text, reply_to=None, queue=True: h.posts.append(text)
    return h


def test_before_the_first_signed_fleet_the_host_uses_config_toml(host):
    assert host.fleet is None and host.fleet_status == "legacy"
    assert host.coordinators() == [COORD] and host.pinned_hosts() == [HOST_B, HOST_A]
    assert "fleet=legacy" in host.heartbeat_line()


def test_an_accepted_fleet_replaces_the_legacy_pins_and_is_announced(host, origin, keys, keygen):
    bare, work = origin
    host.fleet_sync.remote = str(bare)
    publish(work, fleet_text(coordinators=(TEST,), hosts=(HOST_A,)),
            sign(keys, keygen, fleet_text(coordinators=(TEST,), hosts=(HOST_A,))))
    assert host.refresh_fleet(force=True).status == "fleet-accepted"
    assert host.coordinators() == [TEST]  # coord-main is no longer in the list
    assert host.pinned_hosts() == [HOST_A]
    assert "fleet=1:" in host.heartbeat_line() and "fleet-accepted" in host.posts[-1]


def test_a_bad_file_on_main_is_posted_once_and_the_last_good_list_kept(host, origin, keys, keygen):
    bare, work = origin
    host.fleet_sync.remote = str(bare)
    publish(work, fleet_text(), sign(keys, keygen, fleet_text()))
    host.refresh_fleet(force=True)
    good = host.fleet
    publish(work, fleet_text(serial=2), sign(keys, keygen, fleet_text(serial=2), key="stranger"))
    host.refresh_fleet(force=True)
    host.refresh_fleet(force=True)
    problems = [p for p in host.posts if "fleet-bad-signature" in p]
    assert len(problems) == 1 and "keeping=1:" in problems[0]
    assert host.fleet == good


def test_once_a_fleet_was_accepted_a_lost_copy_means_trust_nobody(host, origin, keys, keygen, tmp_path):
    from workerhost.host import Host

    bare, work = origin
    host.fleet_sync.remote = str(bare)
    publish(work, fleet_text(), sign(keys, keygen, fleet_text()))
    host.refresh_fleet(force=True)
    (host.cfg.fleet_store_dir / "fleet.toml.sig").write_bytes(b"-----BEGIN SSH SIGNATURE-----\nbroken\n")
    again = Host(host.cfg, vault=host.vault, signers=keys / "allowed_signers")
    again.pins = {"coordinator": COORD, "host": HOST_A}
    assert again.fleet is None and again.fleet_status == "unavailable"
    assert again.coordinators() == []  # not the legacy pin


def test_only_the_coordinator_that_posted_a_task_can_cancel_it(host):
    from types import SimpleNamespace

    from workerhost.host import Pending

    host.fleet = fleet.parse(fleet_text())
    yielded = []
    session = SimpleNamespace(claim_seq=None, yield_=lambda r: yielded.append(r))
    host.pending["t1"] = Pending(session, {"worker": "core14"}, 500, None, 0.0, coordinator=COORD)
    host.st.set_task("t1", status="claiming")
    host.cancel(500, 501, TEST)
    assert "t1" in host.pending
    host.cancel(500, 502, COORD)
    assert "t1" not in host.pending and host.st.data["tasks"]["t1"]["status"] == "cancelled"
