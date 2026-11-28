"""The host's status for the StruggleBus App (docs/app-host-integration.md sections 1 and 1a).

v1 (build): one JSON object sent in the heartbeat's metadata as `sb_host_status`, with the readable heartbeat line
kept as the message body. The heartbeat stays exactly as it is: coordinators read it.

v2 (build_v2): the same object plus what the desktop panel shows, POSTed to the bus's own status API for the App's
Hosts dashboard (section 1a). for_device() and sample() are what the BUS does with it, written here as the reference the
contract vectors (contracts/host-status/) are made from.

All pure: Host gathers the facts (Host.status_facts) and this turns them into the contract. Nothing here is a token,
credential, path or message text: the App shows it as untrusted plain text.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

V = 1
METADATA_KEY = "sb_host_status"
MAX_BYTES = 16 * 1024  # the bus's metadata cap

STATES = ("online", "paused", "draining", "needs-sign-in", "needs-fleet", "updating", "error")
PROBLEMS = {  # code -> the one plain sentence the App shows
    "channel-missing": "The host's channel is missing on the bus, so no tasks can arrive.",
    "fleet-unavailable": "The kept signed fleet list failed its check: no coordinator is trusted until it refreshes.",
    "bus-unreachable": "The host cannot reach StruggleBus; running workers carry on.",
    "engine-missing": "No agent engine (Copilot CLI or Claude Code) is installed and usable on this host.",
    "sign-in-needed": "An agent engine needs signing in as the host's account.",
    "rolled-back": "The last update failed its checks and was rolled back; the previous version is running.",
    "update-failed": "The last update could not be applied.",
    "release-source-unreachable": "The host cannot reach its release source, so it stays on its current version.",
    "release-redirect-refused": "The installed release names a release source outside this host's allowed remotes; "
                                "the host ignores it and updates from its fleet repository.",
    "openbao-unreachable": "The host cannot reach OpenBao for its secrets; it takes no new tasks until it can.",
    "leaf-expiring": "The host's leaf certificate is close to expiring and its renewal is failing.",
    "disk-low": "Disk space on the workers' drive is below the safe limit.",
    "memory-high": "Committed memory is above the safe limit; no new tasks until it drops.",
}
WARNINGS = ("not-dedicated", "isolation-weak", "claude-token-old")  # the last: rotate it (section 4a, 335 days)
# v2: how each task this host process has ended so far ended (state.TERMINAL), always all seven, in this order.
TASK_OUTCOMES = ("finished", "failed", "timed-out", "interrupted", "refused", "yielded", "cancelled")
# v2 fields the bus returns to an admin (operator grant) only (u64-security, #humans 28828; bus-dev 28832): the
# Windows account and its weaknesses map the weakest machine, and a host's channel may be private.
ADMIN_ONLY = (("account",), ("dedicated",), ("warnings",), ("bus", "channel"), ("bus", "channel_state"),
              ("sign_in",), ("sign_in_key",), ("claude_token_since",))  # section 4a


@dataclass
class Facts:
    """What the host knows about itself right now, gathered by Host.status_facts()."""
    host: str
    agent: str
    version: str
    serial: int
    started_at: float
    interval_s: int
    reported_state: str            # Host.reported_state(): idle, running, claimed, paused(...), draining, maintenance, stopped
    account: str
    dedicated: bool
    engines: list[dict]            # name, version, signed_in (bool or None), default (bool)
    busy: int
    max_workers: int
    claiming: int
    held_clones: int
    outbox: int
    fleet: dict                    # source, serial, coordinators, state
    listed_in_fleet: bool          # False only when a signed fleet is in use and does not list this host
    update: dict | None = None     # version, when
    last_command: dict | None = None
    bus_ok: bool = True
    channel_ok: bool = True
    openbao_ok: bool | None = None  # None: OpenBao not used
    leaf_expiring: bool = False
    rolled_back: bool = False
    resource_problem: str | None = None  # "disk-low", "memory-high", or None
    isolation_weak: bool = False
    extra_warnings: list[str] = field(default_factory=list)
    release_source: str = "fleet"      # update.Where.label(): "fleet", or the release repository#folder
    release_unreachable: bool = False
    release_redirect_refused: bool = False
    # v2 only (the Hosts dashboard): what the desktop panel shows.
    running: list[dict] = field(default_factory=list)  # per worker: slot, engine, model, minutes (never a task id)
    machine: dict = field(default_factory=dict)        # cpu_pct, ram_free_gb, disk_free_gb, commit_pct (None: unmeasured)
    bus_state: str = "unknown"                         # ok, down, unknown
    channel: str = ""
    channel_state: str = "unknown"                     # ok, missing, unknown
    model: str = ""                                    # the default model
    ghcp_ok: bool | None = None                        # the last Copilot CLI update worked (None: not tried)
    tasks: dict = field(default_factory=dict)          # outcome -> count since started_at (TASK_OUTCOMES)
    pwsh: str | None = None                            # PowerShell 7's version (a zip install Wazuh can't see)
    sign_in: dict | None = None                        # section 4a: the sign-in in progress or just ended (signin.py)
    sign_in_key: dict | None = None                    # section 4a: this host's X25519 public key and its fingerprint
    claude_token_since: str | None = None              # section 4a: the date the sealed Claude token arrived
    claude_token_old: bool = False                     # ... 335 days or more ago: rotate it


def state_of(f: Facts) -> str:
    """The App's one-word state; the first that applies wins."""
    if f.reported_state == "maintenance" or (f.update or {}).get("applying"):
        return "updating"
    if f.fleet.get("state") == "unavailable" or not f.channel_ok:
        return "error"
    if not any(e.get("usable", True) for e in f.engines) or not f.engines:
        return "needs-sign-in"
    if not f.listed_in_fleet:
        return "needs-fleet"
    if f.reported_state == "draining":
        return "draining"
    if f.reported_state.startswith("paused"):
        return "paused"
    return "online"


def problem_of(f: Facts) -> str | None:
    """The most important current problem's code, or None."""
    if not f.channel_ok:
        return "channel-missing"
    if f.fleet.get("state") == "unavailable":
        return "fleet-unavailable"
    if not f.bus_ok:
        return "bus-unreachable"
    if not f.engines:
        return "engine-missing"
    if not any(e.get("usable", True) for e in f.engines):
        return "sign-in-needed"
    if f.rolled_back:
        return "rolled-back"
    if f.release_redirect_refused:
        return "release-redirect-refused"
    if f.release_unreachable:
        return "release-source-unreachable"
    if f.openbao_ok is False:
        return "openbao-unreachable"
    if f.leaf_expiring:
        return "leaf-expiring"
    return f.resource_problem


def warnings_of(f: Facts) -> list[str]:
    out = []
    if not f.dedicated:
        out.append("not-dedicated")
    if f.isolation_weak:
        out.append("isolation-weak")
    if f.claude_token_old:
        out.append("claude-token-old")
    return out + [w for w in f.extra_warnings if w in WARNINGS and w not in out]


def iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def build(f: Facts) -> dict:
    """The v1 status object (docs/app-host-integration.md section 1)."""
    problem = problem_of(f)
    return {
        "v": V,
        "host": f.host,
        "agent": f.agent,
        "version": f.version,
        "serial": f.serial,
        "started_at": iso(f.started_at),
        "interval_s": int(f.interval_s),
        "state": state_of(f),
        "account": f.account,
        "dedicated": bool(f.dedicated),
        "engines": [{k: e.get(k) for k in ("name", "version", "signed_in", "default")} for e in f.engines],
        "workers": {"busy": f.busy, "max": f.max_workers, "claiming": f.claiming},
        "held_clones": f.held_clones,
        "outbox": f.outbox,
        "fleet": {k: f.fleet.get(k) for k in ("source", "serial", "coordinators", "state")},
        "update": f.update and {k: f.update.get(k) for k in ("version", "when")},
        "release": {"source": f.release_source, "serial": f.serial},  # security review rule (e): a source change is alerted
        "last_command": f.last_command,
        "problem": None if problem is None else {"code": problem, "text": PROBLEMS[problem]},
        "warnings": warnings_of(f),
    }


MACHINE = ("cpu_pct", "ram_free_gb", "disk_free_gb", "commit_pct")
PWSH_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}(?:[-.][0-9A-Za-z.]{1,16})?")  # at most 32


def build_v2(f: Facts) -> dict:
    """The v2 snapshot for the bus's status API (section 1a): v1, plus worker rows, machine, bus and task totals."""
    s = build(f)
    s["v"] = 2
    s["workers"]["running"] = [{"slot": str(r.get("slot", "?")), "engine": str(r.get("engine", "?")),
                                "model": str(r.get("model", "?")), "minutes": int(r.get("minutes", 0))}
                               for r in f.running]
    s["machine"] = {k: (None if f.machine.get(k) is None else round(float(f.machine[k]), 1)) for k in MACHINE}
    s["bus"] = {"state": f.bus_state, "channel": f.channel, "channel_state": f.channel_state}
    s["model"] = f.model
    s["ghcp_ok"] = f.ghcp_ok
    s["tasks"] = {k: int(f.tasks.get(k, 0)) for k in TASK_OUTCOMES}
    # pwsh: added after v2 was agreed (u64-security, #humans 28927; bus-dev 28936): the bus accepts it with or
    # without, so hosts and buses can be updated in either order. Not in the history sample.
    s["pwsh"] = f.pwsh if f.pwsh and PWSH_RE.fullmatch(f.pwsh) else None
    # sign_in (section 4a): admin-only, and ABSENT unless a sign-in was asked for, so a bus that doesn't know it yet
    # sees nothing new until an App sends a sign-in command. Never in the v1 status, the heartbeat or a history sample.
    if f.sign_in:
        s["sign_in"] = sign_in_field(f.sign_in)
    # sign_in_key and claude_token_since (section 4a): admin-only, present once there is a key / a token. Unlike
    # sign_in they are sent routinely, so a host release carrying them waits for a bus that accepts them.
    key = f.sign_in_key or {}
    if B64_KEY_RE.fullmatch(str(key.get("x25519", ""))) and FINGERPRINT_RE.fullmatch(str(key.get("fingerprint", ""))):
        s["sign_in_key"] = {"x25519": key["x25519"], "fingerprint": key["fingerprint"]}
    if f.claude_token_since and DATE_RE.fullmatch(f.claude_token_since):
        s["claude_token_since"] = f.claude_token_since
    return s


B64_KEY_RE = re.compile(r"[A-Za-z0-9+/]{43}=")             # base64 of 32 bytes
FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")   # unpadded base64 of SHA-256
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


SIGN_IN_STATES = ("starting", "code", "done", "failed")
SIGN_IN_CODE_RE = re.compile(r"[A-Z0-9]{4}-[A-Z0-9]{4}")


def sign_in_field(raw: dict) -> dict:
    """The status's sign_in, built from known keys only: a code only in state "code" and only in GitHub's form."""
    out = {"nonce": str(raw.get("nonce", "")), "tool": str(raw.get("tool", "")), "state": raw.get("state")}
    if out["state"] not in SIGN_IN_STATES:
        out["state"] = "failed"
    if out["state"] == "code" and SIGN_IN_CODE_RE.fullmatch(str(raw.get("code", ""))):
        out["code"], out["expires_at"] = raw["code"], str(raw.get("expires_at", ""))
    if out["state"] == "failed":
        out["reason"] = raw.get("reason")
    return out


def for_device(snapshot: dict) -> dict:
    """What the bus returns to a signed-in App device without the operator grant: the snapshot less ADMIN_ONLY."""
    out = json.loads(json.dumps(snapshot))
    for path in ADMIN_ONLY:
        parent = out
        for key in path[:-1]:
            parent = parent.get(key) or {}
        parent.pop(path[-1], None)
    return out


def sample(snapshot: dict, received_at: str) -> dict:
    """One point of the bus's 12-hour history (bus-dev, 28832): only the figures a chart needs, about 200 bytes.
    received_at is the bus's own clock, never the host's."""
    return {"received_at": received_at, "state": snapshot["state"],
            "workers": {"busy": snapshot["workers"]["busy"], "max": snapshot["workers"]["max"]},
            "machine": dict(snapshot["machine"]), "outbox": snapshot["outbox"],
            "held_clones": snapshot["held_clones"], "tasks": dict(snapshot["tasks"])}


def body(snapshot: dict) -> dict:
    """The POST body, refused (ValueError) past 16 KB, the bus's cap."""
    if len(json.dumps(snapshot, separators=(",", ":")).encode()) > MAX_BYTES:
        raise ValueError("status snapshot over 16 KB")
    return snapshot


def metadata(status: dict) -> dict:
    """The message metadata: {"sb_host_status": status}, refused (ValueError) past the bus's 16 KB cap."""
    meta = {METADATA_KEY: status}
    if len(json.dumps(meta, separators=(",", ":")).encode()) > MAX_BYTES:
        raise ValueError("status metadata over 16 KB")
    return meta


def change_key(status: dict) -> tuple:
    """What, when it changes, is posted at once rather than at the next heartbeat."""
    return (status["state"], tuple(status["warnings"]), (status["problem"] or {}).get("code"),
            (status["update"] or {}).get("version"), json.dumps(status["last_command"], sort_keys=True),
            tuple((e["name"], e["signed_in"]) for e in status["engines"]), status["fleet"].get("serial"),
            status["release"]["source"], json.dumps(status.get("sign_in"), sort_keys=True))
