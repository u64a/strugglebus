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


# --- the coordinator allow list (coordinators.json): add or remove a coordinator, remove a host -----------------------

from workerhost import urls  # noqa: E402

UNSAFE = set('"\\\n\r#[]')
ENTRY_ORDER = ("agent_name", "agent_id", "project", "notes_repo", "notes_channel", "repos", "default_engine")
HEADER_RE = re.compile(r"^\[\[?([a-z_]+)\]\]?\s*$")


def _read_strict(text: str) -> dict:
    """The current fleet, as strictly as compose() reads it (the step 10 rules), plus the serial line."""
    if len(SERIAL_LINE.findall(text)) != 1 or len(re.findall(r"(?m)^\s*serial\s*=", text)) != 1:
        raise Refused("serial-line")
    raw = tomllib.loads(text)
    if set(raw) - TOP_KEYS or any(set(h) - HOST_KEYS for h in raw.get("host", [])) \
            or any(set(c) - fleet.COORDINATOR_KEYS for c in raw.get("coordinator", [])):
        raise Refused("unknown-key")
    agents = raw.get("coordinator", []) + raw.get("host", [])
    names, ids = [a.get("agent_name") for a in agents], [a.get("agent_id") for a in agents]
    if len(set(names)) != len(names) or len(set(ids)) != len(ids):
        raise Refused("duplicate-agent")
    return raw


def _serial(raw: dict, bus_serial: int, reported: list[int]) -> int:
    if raw["serial"] != bus_serial:
        raise Refused("serial-mismatch")
    if any(r > bus_serial for r in reported):
        raise Refused("serial-ahead")
    return bus_serial + 1


def _within(url: str, remote: str) -> bool:
    """A repos prefix or repository URL inside one allowed remote, by whole path segments, never wider than it."""
    if not url.endswith("/"):
        return urls.url_matches(url, remote)
    u, r = urls.split_url(url), urls.split_url(remote)
    if not u or not r or u[0] != r[0]:
        return False
    u_segs, r_segs = [s for s in u[1] if s], [s for s in r[1] if s]
    return len(u_segs) >= len(r_segs) and u_segs[:len(r_segs)] == r_segs


def compose_add_coordinator(text: str, e: dict, bus_serial: int, reported: list[int], remotes: list[str]):
    """(the next fleet's exact text, confirm-screen warnings), or Refused("<reason>[:<field>]")."""
    for name in ("notes_repo", "repos"):
        values = e[name] if isinstance(e[name], list) else [e[name]]
        if any(UNSAFE & set(v) for v in values):
            raise Refused(f"unsafe-char:{name}")
    # default_engine is optional and the App leaves it out (bus-dev 29301): a task picks its engine, then the host's
    # default applies; the coordinator's key chooses nothing, and a missing one reads as ghcp.
    order = [k for k in ENTRY_ORDER if k != "default_engine" or "default_engine" in e]
    checks = {"agent_name": fleet.AGENT_RE.fullmatch(e["agent_name"]), "agent_id": fleet.UUID_RE.fullmatch(e["agent_id"]),
              "project": fleet.PROJECT_RE.fullmatch(e["project"]),
              "notes_repo": urls.repo_url(e["notes_repo"]), "notes_channel": fleet.CHANNEL_RE.fullmatch(e["notes_channel"]),
              "repos": e["repos"] and all(urls.prefix_ok(r) for r in e["repos"]),
              "default_engine": e.get("default_engine") in fleet.ENGINES}
    for name in order:
        if not checks[name]:
            raise Refused(f"bad-value:{name}")
    for r in e["repos"]:
        if not any(_within(r, remote) for remote in remotes):
            raise Refused("outside-remotes:repos")
    if not any(_within(e["notes_repo"], remote) for remote in remotes):
        raise Refused("outside-remotes:notes_repo")
    raw = _read_strict(text)
    agents = raw.get("coordinator", []) + raw.get("host", [])
    if any(a.get("agent_name") == e["agent_name"] or a.get("agent_id") == e["agent_id"] for a in agents):
        raise Refused("duplicate-agent")
    serial = _serial(raw, bus_serial, reported)
    values = {k: (("[" + ", ".join(f'"{r}"' for r in e[k]) + "]") if k == "repos" else f'"{e[k]}"') for k in order}
    block = "\n[[coordinator]]\n" + "".join(f"{k:<14} = {values[k]}\n" for k in order)
    warnings = [f"broad-prefix:{r}" for r in e["repos"] if r.endswith("/")]
    return SERIAL_LINE.sub(f"serial = {serial}\n", text, count=1) + block, warnings


def compose_remove(text: str, kind: str, agent_name: str, bus_serial: int, reported: list[int]) -> str:
    """The next fleet without one [[coordinator]] or [[host]] block (and the blank line before it), or Refused."""
    raw = _read_strict(text)
    if kind == "coordinator" and len(raw.get("coordinator", [])) == 1 and \
            raw["coordinator"][0].get("agent_name") == agent_name:
        raise Refused("last-coordinator")
    lines = text.split("\n")
    headers = [i for i, ln in enumerate(lines) if HEADER_RE.match(ln)]
    for n, h in enumerate(headers):
        if lines[h] != f"[[{kind}]]":
            continue
        end = (headers[n + 1] if n + 1 < len(headers) else len(lines))
        body = lines[h + 1:end]
        while body and not body[-1].strip():
            body.pop()
        if f'agent_name = "{agent_name}"' not in [re.sub(r"\s+=\s+", " = ", ln) for ln in body]:
            continue
        if any(not ln.strip() or ln.lstrip().startswith("#") for ln in body):
            raise Refused("hand-edited")  # never guess a block's boundary (u64-security, 29174)
        start = h - 1 if h > 0 and not lines[h - 1].strip() else h
        kept = lines[:start] + lines[h + 1 + len(body):]
        new = "\n".join(kept)
        serial = _serial(raw, bus_serial, reported)
        return SERIAL_LINE.sub(f"serial = {serial}\n", new, count=1)
    raise Refused("not-listed")


COORDS = json.loads(read("coordinators.json"))


@pytest.mark.parametrize("case", COORDS["cases"], ids=lambda c: c["name"])
def test_each_allow_list_case_gives_its_expected_bytes_or_refusal(case):
    text = read(case["current"]).decode("utf-8")
    warnings = []
    try:
        if case["op"] == "add-coordinator":
            got, warnings = compose_add_coordinator(text, case["entry"], case["bus_serial"], case["reported"],
                                                    COORDS["remotes"])
        else:
            got = compose_remove(text, case["op"].removeprefix("remove-"), case["agent_name"], case["bus_serial"],
                                 case["reported"])
    except Refused as e:
        got = f"refuse:{e}"
    if case["result"].startswith("refuse:"):
        assert got == case["result"]
    else:
        assert got.encode("utf-8") == read(case["result"])
        assert warnings == case.get("warnings", [])
        doc = fleet.parse(got.encode("utf-8"))  # and the host's own parser accepts it
        assert doc.serial == case["bus_serial"] + 1


# --- starting a fleet in the App (start.json; bus-dev 29301, u64-security 29299/29303) ----------------------------------

from workerhost import config  # noqa: E402  (OWNER_RE: the schema's owner pattern)


def compose_start(owner: str, bus_serial: int | None, reported: list[int]) -> str:
    """A first fleet: `serial = 1` and the owner, nothing else; hosts and coordinators are then added one signed
    change at a time. Only when the bus holds no fleet AND no host reports one: otherwise a fleet exists somewhere,
    and a fresh one would un-list everything it names (that's the takeover from the hosts' offers instead)."""
    if bus_serial is not None or reported:
        raise Refused("fleet-exists")
    if not owner:
        return "serial = 1\n"
    if not config.OWNER_RE.fullmatch(owner):
        raise Refused("bad-value:owner")
    return f'serial = 1\nowner = "{owner}"\n'


START = json.loads(read("start.json"))


@pytest.mark.parametrize("case", START["cases"], ids=lambda c: c["name"])
def test_each_start_case_gives_its_expected_bytes_or_refusal(case):
    try:
        got = compose_start(case["owner"], case["bus_serial"], case["reported"])
    except Refused as e:
        got = f"refuse:{e}"
    if case["result"].startswith("refuse:"):
        assert got == case["result"]
    else:
        assert got.encode("utf-8") == read(case["result"])
        doc = fleet.parse(got.encode("utf-8"))  # a host accepts it: no hosts, no coordinators
        assert (doc.serial, doc.owner, doc.hosts, doc.coordinators) == (1, case["owner"], (), ())


def test_a_started_fleet_is_then_built_by_the_usual_one_at_a_time_changes():
    """The first coordinator and the first host go onto a started fleet through the composers that exist."""
    first = next(c for c in COORDS["cases"] if c["name"] == "add-the-first-coordinator-to-a-started-fleet")
    host = next(c for c in EXPECTED["cases"] if c["name"] == "add-the-first-host-to-a-started-fleet")
    assert first["current"] in [c["result"] for c in START["cases"]]
    assert host["current"] in [c["result"] for c in START["cases"]]
    assert fleet.parse(read(first["result"])).coordinators[0].default_engine == "ghcp"  # left out: reads as ghcp


NOT_A_FLEET = json.loads(read("not-a-fleet.json"))


@pytest.mark.parametrize("case", NOT_A_FLEET["cases"], ids=lambda c: c["name"])
def test_a_release_or_a_statement_is_never_read_as_a_fleet(case):
    """u64-security 29197 condition 1: what isn't a fleet never reaches the YubiKey as one."""
    text = read(case["input"]).decode("utf-8")
    try:
        _read_strict(text)
        got = "accepted"
    except Refused as e:
        got = f"refuse:{e}"
    assert got == case["result"]
    assert NOT_A_FLEET["sign_namespace"] == "strugglebus-fleet"
    assert "strugglebus-release" in NOT_A_FLEET["never_sign_namespaces"]


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


def _string(buf: bytes, p: int):
    n = int.from_bytes(buf[p:p + 4], "big")
    assert p + 4 + n <= len(buf), "cut short"
    return buf[p + 4:p + 4 + n], p + 4 + n


def _flags(armored: str):
    """The reference flags reader (the same layout as sign-config.ps1's Get-SigFlags), as strict as the App's: the
    public key must be a real key blob whose type matches the signature's (bus-dev, #humans 29156)."""
    b = base64.b64decode("".join(ln for ln in armored.splitlines() if not ln.startswith("-----")))
    assert b[:6] == b"SSHSIG"
    pub, pos = _string(b, 10)
    key_type, k = _string(pub, 0)
    key, k = _string(pub, k)
    assert len(key) == 32  # an ed25519 public key
    if key_type.startswith(b"sk-"):
        application, k = _string(pub, k)
        assert application.startswith(b"ssh:")
    assert k == len(pub)
    for _ in range(3):  # namespace, reserved, hash algorithm
        _, pos = _string(b, pos)
    sig, _ = _string(b, pos)
    kind, p = _string(sig, 0)
    assert kind == key_type
    if not kind.startswith(b"sk-"):
        return None
    _, p = _string(sig, p)
    return sig[p]


@pytest.mark.parametrize("name, want", [(k, v) for k, v in EXPECTED["flags"].items() if not k.startswith("_")])
def test_the_flags_vectors(name, want):
    assert _flags(read(name).decode("ascii")) == want
