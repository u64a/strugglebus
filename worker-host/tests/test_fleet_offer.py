"""A host offers the fleet it accepted while the bus holds none (bus 0.2.75; bus-dev #humans 29304, u64-security
29303): the App then publishes it unchanged, with no file. The offer is only a carrier: the App checks the signature
and the serial itself, so these tests are about what the host sends, when, and how it reacts."""
from __future__ import annotations

import base64

import pytest

from workerhost import fleet

DATA = b'serial = 4\nowner = "Alex"\n'
SIG = b"-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n"


def stored(sync: fleet.FleetSync, data: bytes = DATA, sig: bytes = SIG) -> fleet.Fleet:
    sync.store.mkdir(parents=True, exist_ok=True)
    (sync.store / fleet.FILE).write_bytes(data)
    (sync.store / fleet.SIG).write_bytes(sig)
    return fleet.parse(data)


@pytest.fixture
def sync(tmp_path):
    return fleet.FleetSync(tmp_path / "mirror", tmp_path / "store", "", "git", None, tmp_path / "signers")


def test_the_offer_is_the_exact_accepted_bytes_and_signature(sync):
    current = stored(sync)
    body = sync.offer_body(current)
    assert set(body) == {"serial", "fleet", "sig"}  # exact keys, nothing else (the bus refuses unknown ones)
    assert body["serial"] == 4 and base64.b64decode(body["fleet"]) == DATA and body["sig"] == SIG.decode("ascii")


def test_nothing_is_offered_without_an_accepted_fleet_or_with_a_stored_copy_that_is_not_it(sync):
    assert sync.offer_body(None) is None
    current = stored(sync)
    (sync.store / fleet.FILE).write_bytes(DATA + b"# changed\n")  # the folder is the host user's to write
    assert sync.offer_body(current) is None
    stored(sync, sig=b"not a signature")
    assert sync.offer_body(current) is None
    stored(sync, sig=SIG[:30] + b"A" * fleet.OFFER_SIG_MAX + SIG[30:])  # over the bus's cap
    assert sync.offer_body(current) is None
    (sync.store / fleet.SIG).unlink()
    assert sync.offer_body(current) is None


class Bus:
    def __init__(self, code, doc=None):
        self.code, self.doc = code, doc

    def call(self, method, path, body=None, **k):
        return self.code, self.doc


def test_the_bus_answering_404_is_what_marks_it_as_holding_none(sync):
    assert sync.refresh_from_bus(None, Bus(404)).status == "fleet-missing" and sync.bus_holds_none
    sync.refresh_from_bus(None, Bus(200, {"name": "fleet", "body": base64.b64encode(DATA).decode(), "signature": "x"}))
    assert not sync.bus_holds_none  # the bus holds a document (whatever its check says): stop offering
    sync.bus_holds_none = True
    sync.refresh_from_bus(None, Bus(503))
    assert sync.bus_holds_none  # a bus that's down says nothing either way


@pytest.fixture
def offering(tmp_path, monkeypatch):
    """A real Host on fleet_source either, holding an accepted fleet, whose bus holds none."""
    from conftest import HOST_A, FakeVault, SharedBus
    from workerhost import engines as engines_mod
    from workerhost import resources
    from workerhost.config import Config
    from workerhost.host import Host

    monkeypatch.setattr(resources, "sample", lambda root: None)
    monkeypatch.setattr(engines_mod, "resolve", lambda name: "C:\\bin\\copilot.exe")
    bus = SharedBus().client(HOST_A)
    h = Host(Config(host_name="box1", agent_prefix="host-box1", home=tmp_path / "home", workers_root=tmp_path / "w",
                    fleet_source="either"), bus=bus, vault=FakeVault())
    h.fleet = stored(h.fleet_sync)
    h.fleet_sync.bus_holds_none = True
    posts, logged, answer = [], [], {"code": 204}

    def call(method, path, body=None, **k):
        if isinstance(answer["code"], Exception):
            raise answer["code"]
        posts.append((method, path, body))
        return answer["code"], None

    bus.call = call
    h.log = lambda event, **k: logged.append((event, k))
    clock = {"t": 1_800_000_000.0}
    monkeypatch.setattr("workerhost.host.time.time", lambda: clock["t"])
    return h, posts, logged, answer, clock


def test_a_host_offers_its_fleet_on_each_refresh_while_the_bus_holds_none(offering):
    h, posts, logged, answer, clock = offering
    h.offer_fleet_if_due()
    assert [(m, p) for m, p, _ in posts] == [("POST", "/api/hosts/fleet-offer")]
    assert posts[0][2]["serial"] == 4 and logged == [("fleet-offered", {"serial": 4})]
    h.offer_fleet_if_due()
    assert len(posts) == 1  # not again before the next fleet refresh
    clock["t"] += 60 * h.cfg.fleet_refresh_minutes
    h.offer_fleet_if_due()
    assert len(posts) == 2 and len(logged) == 1  # offered again (the newest replaces the last); logged once


def test_409_means_the_bus_holds_a_fleet_now_so_the_host_stops(offering):
    h, posts, logged, answer, clock = offering
    answer["code"] = 409
    h.offer_fleet_if_due()
    assert logged == [("fleet-offer-held", {})] and not h.fleet_sync.bus_holds_none
    clock["t"] += 7200
    h.offer_fleet_if_due()
    assert len(posts) == 1


@pytest.mark.parametrize("code", [404, 403, 400, 413])
def test_a_refusal_is_logged_once_and_retried_hourly(offering, code):
    """404: a bus older than 0.2.75; 403: not marked as a host yet; 400 or 413: a contract mismatch."""
    h, posts, logged, answer, clock = offering
    answer["code"] = code
    h.offer_fleet_if_due()
    clock["t"] += 3599
    h.offer_fleet_if_due()
    assert len(posts) == 1
    clock["t"] += 2
    h.offer_fleet_if_due()
    assert len(posts) == 2 and logged == [("fleet-offer-refused", {"status": code})]


def test_a_busy_bus_waits_a_minute_and_an_unreachable_one_is_not_a_refusal(offering):
    h, posts, logged, answer, clock = offering
    answer["code"] = 429
    h.offer_fleet_if_due()
    clock["t"] += 61
    h.offer_fleet_if_due()
    assert len(posts) == 2 and not logged
    answer["code"] = OSError("unreachable")
    clock["t"] += 3600
    h.offer_fleet_if_due()
    assert logged == [("fleet-offer-failed", {"error": "OSError"})]


def test_no_offer_from_a_git_host_or_while_the_bus_holds_a_fleet_or_with_nothing_accepted(offering):
    h, posts, logged, answer, clock = offering
    h.cfg.fleet_source = "git"
    h.offer_fleet_if_due()
    h.cfg.fleet_source = "either"
    h.fleet_sync.bus_holds_none = False
    h.offer_fleet_if_due()
    h.fleet_sync.bus_holds_none, h.fleet = True, None
    h.offer_fleet_if_due()
    assert posts == [] and logged == []
