"""The host's status for the StruggleBus App's hosts page (docs/app-host-integration.md section 1): one JSON object,
sent in the heartbeat's metadata as `sb_host_status`, with the readable heartbeat line kept as the message body.

build() is pure: Host gathers the facts (Host.status_facts) and this turns them into the v1 contract. Nothing here is a
token, credential, path or message text: the App shows it as untrusted plain text.
"""
from __future__ import annotations

import json
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
WARNINGS = ("not-dedicated", "isolation-weak")


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
            status["release"]["source"])
