"""A host the signed fleet does not list takes no work (docs/app-host-integration.md section 3): the other hosts would
ignore its claims, so the same task could run twice."""
from __future__ import annotations

from types import SimpleNamespace

from conftest import HOST_A, HOST_B
from workerhost.host import Host


def host(fleet_hosts, me=HOST_A, draining=False):
    h = object.__new__(Host)
    h.fleet = None if fleet_hosts is None else SimpleNamespace(hosts=tuple(fleet_hosts))
    h.pins = {"host": me}
    h.st = SimpleNamespace(data={"draining": draining, "paused": False})
    return h


def test_an_unlisted_host_refuses_with_needs_fleet():
    h = host([HOST_B])
    assert not h.listed_in_fleet()
    assert h.resource_verdict() == ("needs-fleet", {})


def test_a_listed_host_and_a_host_before_any_fleet_go_on_to_the_other_checks():
    assert host([HOST_B, HOST_A], draining=True).resource_verdict() == ("draining", {})
    assert host(None, draining=True).resource_verdict() == ("draining", {})  # config.toml pins: no fleet rule
    assert host([HOST_A]).listed_in_fleet() and host(None).listed_in_fleet()


def test_matching_is_by_agent_id():
    from workerhost.validate import Pin

    renamed = Pin(HOST_A.agent_id, "some-other-name")
    assert host([renamed]).listed_in_fleet()
    assert not host([Pin("cccccccc-cccc-4ccc-8ccc-cccccccccccc", HOST_A.agent_name)]).listed_in_fleet()
