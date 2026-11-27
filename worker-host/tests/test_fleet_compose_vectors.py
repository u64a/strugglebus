"""contracts/fleet/compose/: the Windows App's step 10 (spec 2.2 step 10; bus-dev #humans 29130, u64-security 29131).

The App reads the bus's current fleet STRICTLY, adds one [[host]] and raises the serial, changing no other byte; the
YubiKey signs those exact bytes outside the App. This file holds a small reference of the App's rules and checks the
vectors against it, and checks that what it composes is a fleet the host's own parser accepts (and lists the new
host in). The App is stricter than the host on purpose: an unknown key is refused, where the host ignores it.
"""
from __future__ import annotations

import base64
import json
import re
import tomllib
from pathlib import Path

import pytest

import vectors
from workerhost import fleet

if not (vectors.CONTRACTS / "fleet" / "compose").is_dir():
    pytest.skip("contracts/fleet/compose/ is in the monorepo only", allow_module_level=True)
NAMES = sorted(k.split("/", 2)[2] for k in vectors.PINNED if k.startswith("fleet/compose/"))


def read(name: str) -> bytes:
    """A compose vector, checked against its pinned hash first (vectors.path)."""
    return vectors.path("fleet", f"compose/{name}").read_bytes()


EXPECTED = json.loads(read("expected.json"))
TOP_KEYS = {"serial", "owner", "coordinator", "host"}
HOST_KEYS = {"agent_name", "agent_id"}
SERIAL_LINE = re.compile(r"(?m)^serial = ([0-9]{1,9})\n")


class Refused(Exception):
    pass


def compose(text: str, name: str, agent_id: str, bus_serial: int, reported: list[int]) -> str:
    """The App's step 10, as a reference: the next fleet's exact text, or Refused(reason)."""
    if len(SERIAL_LINE.findall(text)) != 1 or len(re.findall(r"(?m)^\s*serial\s*=", text)) != 1:
        raise Refused("serial-line")
    raw = tomllib.loads(text)
    if set(raw) - TOP_KEYS:
        raise Refused("unknown-key")
    for h in raw.get("host", []):
        if set(h) - HOST_KEYS:
            raise Refused("unknown-key")
    for c in raw.get("coordinator", []):
        if set(c) - fleet.COORDINATOR_KEYS:
            raise Refused("unknown-key")
    agents = raw.get("coordinator", []) + raw.get("host", [])
    names, ids = [a.get("agent_name") for a in agents], [a.get("agent_id") for a in agents]
    if len(set(names)) != len(names) or len(set(ids)) != len(ids):
        raise Refused("duplicate-agent")
    if name in names or agent_id in ids:
        raise Refused("host-listed")
    if raw["serial"] != bus_serial:
        raise Refused("serial-mismatch")  # the bus's stored serial must be the document's own
    if any(r > bus_serial for r in reported):
        raise Refused("serial-ahead")  # never jump to a host's report: stop and show it (u64-security, 29131)
    new = SERIAL_LINE.sub(f"serial = {bus_serial + 1}\n", text, count=1)
    return new + f'\n[[host]]\nagent_name = "{name}"\nagent_id   = "{agent_id}"\n'


@pytest.mark.parametrize("case", EXPECTED["cases"], ids=lambda c: c["name"])
def test_each_compose_case_gives_its_expected_bytes_or_refusal(case):
    text = read(case["current"]).decode("utf-8")
    add = case["add"]
    try:
        got = compose(text, add["agent_name"], add["agent_id"], case["bus_serial"], case["reported"])
    except Refused as e:
        got = f"refuse:{e}"
    if case["result"].startswith("refuse:"):
        assert got == case["result"]
    else:
        assert got.encode("utf-8") == read(case["result"])


def test_every_vector_file_is_pinned_and_utf8_lf_without_a_bom():
    on_disk = sorted(p.name for p in (vectors.CONTRACTS / "fleet" / "compose").iterdir())
    assert on_disk == NAMES  # a new vector is pinned in tests/vectors.py in the same change
    for name in NAMES:
        raw = read(name)
        assert b"\r" not in raw and not raw.startswith(b"\xef\xbb\xbf") and raw.endswith(b"\n"), name


def test_what_the_app_composes_is_a_fleet_the_host_accepts_and_lists_the_new_host_in():
    doc = fleet.parse(read("after.toml"))
    assert doc.serial == 6
    assert [h.agent_name for h in doc.hosts] == ["host-office1-host", "host-office2-host"]
    assert fleet.parse(read("before.toml")).serial == 5


def test_the_host_also_refuses_the_duplicates_the_app_refuses():
    for name in ("duplicate-id.toml", "duplicate-name.toml"):
        with pytest.raises(fleet.FleetError):
            fleet.parse(read(name))


def _flags(armored: str):
    """The reference flags reader (the same layout as sign-config.ps1's Get-SigFlags)."""
    b = base64.b64decode("".join(ln for ln in armored.splitlines() if not ln.startswith("-----")))
    assert b[:6] == b"SSHSIG"
    pos = 10

    def string(buf, p):
        n = int.from_bytes(buf[p:p + 4], "big")
        return buf[p + 4:p + 4 + n], p + 4 + n

    for _ in range(4):
        _, pos = string(b, pos)
    sig, _ = string(b, pos)
    kind, p = string(sig, 0)
    if not kind.startswith(b"sk-"):
        return None
    _, p = string(sig, p)
    return sig[p]


@pytest.mark.parametrize("name, want", [(k, v) for k, v in EXPECTED["flags"].items() if not k.startswith("_")])
def test_the_flags_vectors(name, want):
    assert _flags(read(name).decode("ascii")) == want
