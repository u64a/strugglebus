"""A worker host offers the fleet it accepts, so an operator can take it over with no file."""

from __future__ import annotations

import base64
import json

import pytest

from strugglebus import fleet_offers
from test_host_status import HOST, Clock, agent_id, mark
from test_mobile_write_path import _auth, _grant, surface  # noqa: F401
from test_site_documents import BODY, SIGNATURE, _agent_key, _publish

OFFER = "/api/hosts/fleet-offer"
OFFERS = "/api/mobile/admin/hosts/fleet-offers"
FLEET_BYTES = b'serial = 4\nowner = "Alex"\n'
SIG = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"


def offer_body(**changed) -> dict:
    return {"serial": 4, "fleet": base64.b64encode(FLEET_BYTES).decode("ascii"), "sig": SIG, **changed}


def send(client, key: str, body: object = None, **changed):
    payload = offer_body(**changed) if body is None else body
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return client.post(OFFER, content=data, headers={**_auth(key), "Content-Type": "application/json"})


def read(client, secret, grant):
    return client.post(OFFERS, json={"grant_secret": grant}, headers=_auth(secret))


@pytest.fixture
def offering(surface):  # noqa: F811
    """A bus with one marked host, no fleet, a clock the test moves, and the device's grant."""
    client, secret, agents, store = surface
    clock = Clock()
    client.app.state.fleet_offer_service = fleet_offers.FleetOfferService(
        store, client.app.state.site_document_service, clock=clock,
    )
    key = _agent_key(agents, HOST)
    grant = _grant(client, secret)
    assert mark(client, secret, grant, agent_id(store, HOST), HOST).status_code == 200
    return client, secret, grant, key, clock, agents, store


def test_a_marked_host_offers_its_fleet_and_an_administrator_reads_it_back_exactly(offering) -> None:
    client, secret, grant, key, _, _, store = offering

    sent = send(client, key)
    assert sent.status_code == 204, sent.text
    assert sent.content == b""

    answer = read(client, secret, grant)
    assert answer.status_code == 200, answer.text
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert body["held"] is False
    (only,) = body["offers"]
    assert (only["agent"], only["agent_id"], only["serial"], only["sig"]) == (HOST, agent_id(store, HOST), 4, SIG)
    assert base64.b64decode(only["fleet"]) == FLEET_BYTES
    assert only["received_at"] == "2026-11-27T04:00:00Z"


def test_the_newest_offer_replaces_the_last_and_one_a_minute_is_the_limit(offering) -> None:
    client, secret, grant, key, clock, *_ = offering
    assert send(client, key).status_code == 204

    clock.forward(59)
    early = send(client, key, serial=5)
    assert (early.status_code, early.json()["detail"], early.headers["retry-after"]) == (429, "too-soon", "1")

    clock.forward(1)
    assert send(client, key, serial=5).status_code == 204
    (only,) = read(client, secret, grant).json()["offers"]
    assert only["serial"] == 5


def test_only_a_marked_host_may_offer_and_only_with_the_grant_may_offers_be_read(offering) -> None:
    client, secret, grant, key, _, agents, _ = offering

    other = send(client, _agent_key(agents, "coord-main"))
    assert (other.status_code, other.json()["detail"]) == (403, "not-a-host")
    assert client.post(OFFER, content=b"{}").status_code == 401
    assert send(client, secret).status_code in {401, 403}

    assert client.post(OFFERS, json={"grant_secret": grant}).status_code == 401
    assert client.post(OFFERS, json={"grant_secret": "wrong"}, headers=_auth(secret)).status_code == 401
    assert client.post(OFFERS, json={"grant_secret": grant}, headers=_auth(key)).status_code in {401, 403}
    assert read(client, secret, grant).json()["offers"] == []


def test_once_the_bus_holds_a_fleet_offers_are_refused_and_the_stored_ones_are_dropped(offering) -> None:
    client, secret, grant, key, clock, *_ = offering
    assert send(client, key).status_code == 204
    assert _publish(client, secret, grant, serial=4, body=BODY, signature=SIGNATURE).status_code == 201

    assert read(client, secret, grant).json() == {"held": True, "offers": []}
    clock.forward(120)
    held = send(client, key)
    assert (held.status_code, held.json()["detail"]) == (409, "fleet-held")
    assert client.app.state.fleet_offer_service._offers == {}


def test_a_host_that_is_no_longer_marked_has_its_offer_left_out(offering) -> None:
    client, secret, grant, key, _, _, store = offering
    assert send(client, key).status_code == 204

    assert mark(client, secret, grant, agent_id(store, HOST), HOST, action="unmark").status_code == 200

    assert read(client, secret, grant).json() == {"held": False, "offers": []}


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"not json", "bad-json"),
        ([], "bad-offer"),
        ("text", "bad-offer"),
        ({"serial": 4, "fleet": "QQ=="}, "missing-field:sig"),
        ({"fleet": "QQ==", "sig": SIG}, "missing-field:serial"),
        ({"serial": 4, "sig": SIG}, "missing-field:fleet"),
        (offer_body(owner="x"), "unknown-field"),
        (offer_body(serial=0), "bad-offer"),
        (offer_body(serial="4"), "bad-offer"),
        (offer_body(serial=True), "bad-offer"),
        (offer_body(serial=2_000_000_001), "bad-offer"),
        (offer_body(fleet=""), "bad-offer"),
        (offer_body(fleet="not base64!"), "bad-offer"),
        (offer_body(fleet=7), "bad-offer"),
        (offer_body(fleet=base64.b64encode(b"x" * (fleet_offers.MAX_FLEET_BYTES + 1)).decode()), "bad-offer"),
        (offer_body(sig="a signature"), "bad-offer"),
        (offer_body(sig=SIG + "x" * fleet_offers.MAX_SIGNATURE_CHARS), "bad-offer"),
        (offer_body(sig=fleet_offers.SIGNATURE_START + "\né"), "bad-offer"),
        (offer_body(sig=None), "bad-offer"),
    ],
)
def test_an_offer_that_does_not_fit_is_refused_in_fixed_words(offering, body, reason) -> None:
    client, _, _, key, *_ = offering

    answer = send(client, key, body)

    assert (answer.status_code, answer.json()["detail"]) == (400, reason)
    assert client.app.state.fleet_offer_service._offers == {}


def test_a_fleet_of_the_largest_size_is_kept_and_a_request_over_the_cap_is_too_large(offering) -> None:
    client, secret, grant, key, clock, *_ = offering
    largest = base64.b64encode(b"x" * fleet_offers.MAX_FLEET_BYTES).decode()

    assert send(client, key, fleet=largest).status_code == 204
    (only,) = read(client, secret, grant).json()["offers"]
    assert len(base64.b64decode(only["fleet"])) == fleet_offers.MAX_FLEET_BYTES

    clock.forward(120)
    over = send(client, key, b"{" + b" " * fleet_offers.MAX_BYTES + b"}")
    assert over.status_code == 413


def test_only_so_many_hosts_offers_are_kept_and_the_oldest_goes() -> None:
    class Hosts:
        def host_statuses(self):
            return [(f"id-{number}", f"host-{number}-host", "x", None, None) for number in range(fleet_offers.MAX_HOSTS + 1)]

    class Documents:
        def read(self, name):
            return None

    service = fleet_offers.FleetOfferService(Hosts(), Documents(), clock=Clock())
    body = json.dumps(offer_body()).encode()
    for number in range(fleet_offers.MAX_HOSTS + 1):
        service.offer(f"id-{number}", f"host-{number}-host", body)

    held, offers = service.offers()
    assert held is False
    assert len(offers) == fleet_offers.MAX_HOSTS
    assert "id-0" not in {offer.agent_id for offer in offers}


def test_a_bus_with_no_document_store_configured_is_not_holding_a_fleet() -> None:
    from strugglebus.errors import ConfigurationError

    class Hosts:
        def host_statuses(self):
            return [("id-1", HOST, "x", None, None)]

    class Documents:
        def read(self, name):
            raise ConfigurationError("not configured")

    service = fleet_offers.FleetOfferService(Hosts(), Documents(), clock=Clock())
    service.offer("id-1", HOST, json.dumps(offer_body()).encode())

    assert service.offers()[0] is False


def test_the_bus_does_not_judge_the_offer_it_only_carries_it(offering) -> None:
    """A serial that disagrees with the bytes, and a signature that verifies nothing, are still kept: the App decides."""
    client, secret, grant, key, *_ = offering

    assert send(client, key, serial=999).status_code == 204
    (only,) = read(client, secret, grant).json()["offers"]
    assert only["serial"] == 999
    assert base64.b64decode(only["fleet"]) == FLEET_BYTES


def test_each_offer_stored_or_refused_writes_one_audit_line_with_who_and_how_large(offering, caplog) -> None:
    client, _, _, key, *_ = offering
    caplog.set_level("INFO")

    send(client, key)
    send(client, key, offer_body(owner="x"))

    lines = [json.loads(record.getMessage().split(" ", 1)[1]) for record in caplog.records if record.name == "strugglebus.audit"]
    lines = [line for line in lines if line["event"] == f"POST {OFFER}"]
    assert [(line["outcome"], line["status"], line["agent_name"]) for line in lines] == [("ok", 204, HOST), ("refused", 400, HOST)]
    assert all(line["request_bytes"] > 100 for line in lines)
    lines = [json.dumps(line) for line in lines]
    assert FLEET_BYTES.decode() not in "".join(lines)
