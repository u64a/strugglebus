"""The signed fleet read from the bus's site-document store (fleet_source "bus" / "either";
docs/app-host-integration.md section 3): the same signature, parse and serial checks as a copy from the repository,
so where a copy came from never decides whether it is trusted."""
from __future__ import annotations

import base64

import pytest

from test_fleet import fleet_text, host, keygen, keys, origin, publish, sign, sync  # noqa: F401 (fixtures)
from workerhost import config, fleet

pytestmark = pytest.mark.fleet


class Bus:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def call(self, method, path, *, body=None, query=None, token=None):
        self.calls.append((method, path))
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, Exception):
            raise a
        return a


def doc(data: bytes, sig: bytes, **over):
    d = {"name": "fleet", "serial": 1, "body": base64.b64encode(data).decode(), "signature": sig.decode(),
         "stored_at": "2026-11-25T01:00:00Z"}
    d.update(over)
    return 200, d


def test_a_signed_fleet_from_the_bus_is_accepted_then_unchanged(sync, keys, keygen):  # noqa: F811
    data = fleet_text(serial=3)
    bus = Bus(doc(data, sign(keys, keygen, data)))
    out = sync.refresh(None, bus=bus, source="bus")
    assert out.status == "fleet-accepted" and out.fleet.serial == 3 and out.commit == ""
    assert bus.calls == [("GET", fleet.BUS_PATH)]
    assert sync.refresh(out.fleet, bus=bus, source="bus").status == "unchanged"
    assert sync.load_last_good() == out.fleet  # kept and re-checked like any other copy


def test_the_signed_bytes_decide_not_the_bus(sync, keys, keygen):  # noqa: F811
    data = fleet_text(serial=2)
    out = sync.refresh(None, bus=Bus(doc(data, sign(keys, keygen, data), serial=99)), source="bus")
    assert out.status == "fleet-accepted" and out.fleet.serial == 2  # the bus's serial is only a hint


@pytest.mark.parametrize("make, status", [
    (lambda k, g, d: doc(d, sign(k, g, d, key="stranger")), "fleet-bad-signature"),
    (lambda k, g, d: doc(d, sign(k, g, d, ns="strugglebus-release")), "fleet-bad-signature"),
    (lambda k, g, d: doc(d + b"\n# changed\n", sign(k, g, d)), "fleet-bad-signature"),
    (lambda k, g, d: doc(b"serial = 0\n", sign(k, g, b"serial = 0\n")), "fleet-invalid"),
])
def test_a_bus_copy_that_is_not_right_is_refused(sync, keys, keygen, make, status):  # noqa: F811
    out = sync.refresh(None, bus=Bus(make(keys, keygen, fleet_text())), source="bus")
    assert out.status == status
    assert sync.load_last_good() is None


@pytest.mark.parametrize("answer, status", [
    ((404, {"detail": "not found"}), "fleet-missing"),
    ((500, {}), "fetch-failed"),
    ((200, ["not", "a", "document"]), "fetch-failed"),
    ((200, {"name": "baseline", "body": "", "signature": ""}), "fetch-failed"),
    ((200, {"name": "fleet", "body": "not base64!", "signature": "x"}), "fetch-failed"),
    ((200, {"name": "fleet", "body": base64.b64encode(b"x" * 70000).decode(), "signature": "x"}), "fleet-invalid"),
    (OSError("unreachable"), "fetch-failed"),
])
def test_what_the_bus_answers_otherwise(sync, answer, status):  # noqa: F811
    assert sync.refresh(None, bus=Bus(answer), source="bus").status == status


def test_without_a_bus_connection_the_bus_source_says_so(sync):  # noqa: F811
    out = sync.refresh(None, bus=None, source="bus")
    assert (out.status, out.detail) == ("fetch-failed", "no bus connection")


def test_an_older_fleet_on_the_bus_cannot_roll_back_one_from_git(sync, origin, keys, keygen):  # noqa: F811
    _, work = origin
    newer = fleet_text(serial=5)
    publish(work, newer, sign(keys, keygen, newer))
    current = sync.refresh(None).fleet
    older = fleet_text(serial=4)
    out = sync.refresh(current, bus=Bus(doc(older, sign(keys, keygen, older))), source="bus")
    assert out.status == "fleet-old"


def test_either_takes_the_bus_first_and_the_repository_when_the_bus_has_nothing(sync, origin, keys, keygen):  # noqa: F811
    _, work = origin
    data = fleet_text(serial=1)
    publish(work, data, sign(keys, keygen, data))
    out = sync.refresh(None, bus=Bus((404, {})), source="either")
    assert out.status == "fleet-accepted" and out.commit  # from the repository
    newer = fleet_text(serial=2)
    out = sync.refresh(out.fleet, bus=Bus(doc(newer, sign(keys, keygen, newer))), source="either")
    assert out.status == "fleet-accepted" and out.commit == "" and out.fleet.serial == 2  # from the bus


def test_either_takes_the_higher_verified_serial_even_when_the_bus_is_unchanged(sync, origin, keys, keygen):  # noqa: F811
    _, work = origin
    old = fleet_text(serial=1)
    bus = Bus(doc(old, sign(keys, keygen, old)))
    current = sync.refresh(None, bus=bus, source="either").fleet
    newer = fleet_text(serial=2)
    publish(work, newer, sign(keys, keygen, newer))
    out = sync.refresh(current, bus=bus, source="either")  # the bus is unchanged; the repository is ahead
    assert out.status == "fleet-accepted" and out.fleet.serial == 2 and out.commit


def test_either_reports_the_answer_that_says_most():
    O = fleet.Outcome
    accepted, unchanged, old, bad = O("fleet-accepted"), O("unchanged"), O("fleet-old"), O("fleet-bad-signature")
    assert fleet.pick(unchanged, accepted) is accepted       # the repository is ahead
    assert fleet.pick(accepted, old) is accepted             # the repository is merely behind the bus: no problem
    assert fleet.pick(unchanged, old) is unchanged
    assert fleet.pick(unchanged, bad) is bad                 # a forged or broken copy is worth saying anyway
    assert fleet.pick(bad, O("fetch-failed")) is bad
    assert fleet.pick(O("fleet-missing"), O("fetch-failed")).status == "fleet-missing"


def test_the_host_reads_its_fleet_from_the_bus_and_retries_soon_before_it_is_connected(host, keys, keygen):  # noqa: F811
    host.cfg.fleet_source = "bus"
    host.bus = None
    t0 = __import__("time").time()
    assert host.refresh_fleet(force=True).detail == "no bus connection"
    assert host.next_fleet < t0 + 120  # not fleet_refresh_minutes away
    data = fleet_text(serial=7)
    host.bus = Bus(doc(data, sign(keys, keygen, data)))
    assert host.refresh_fleet(force=True).status == "fleet-accepted" and host.fleet.serial == 7
    assert "fleet-accepted" in host.posts[-1]


def test_in_bus_mode_the_update_check_still_fetches_the_release_mirror(host, monkeypatch):  # noqa: F811
    host.cfg.fleet_source = "bus"
    host.bus = None
    fetched = []
    monkeypatch.setattr(host.fleet_sync, "fetch_mirror", lambda: fetched.append(1) or True)
    monkeypatch.setattr(host.release_source, "read", lambda: (None, "release-missing"))
    host.update_check(announce=False)
    assert fetched == [1]


def test_fleet_source_is_checked(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('host_name = "box1"\nagent_prefix = "host-box1"\nscheduled_task = ""\n'
                                      'bus_url = "https://bus.example.lan"\nfleet_source = "anywhere"\n',
                                      encoding="utf-8")
    monkeypatch.setenv("WORKERHOST_HOME", str(home))
    with pytest.raises(ValueError, match="fleet_source"):
        config.check(config.load())
