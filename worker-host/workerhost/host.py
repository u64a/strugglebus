"""The host loop (design sections 4 to 7, 10, 11, 13 and 14).

poll the bus -> validate (validate.py) -> claim (claim.py) -> launch (launcher.py) -> supervise ->
clean up -> heartbeat. Local commands arrive as control files; the bus offers no remote stop, drain,
update or shell. Every post is a fixed-shape JSON reply built by this module; no message text is
ever logged, executed or placed in a prompt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from . import cleanup, creds, fleet as fleet_mod, ghcp, launcher, prompt, resources, signing, urls, usage, winapi
from . import hoststatus
from . import commands as commands_mod
from . import engines as engines_mod
from . import models as models_mod
from . import openbao as openbao_mod
from . import update as update_mod
from .config import INSTALL_DIR
from .busclient import Bus, BusError, bootstrap, onboard
from .busclient import retire as retire_identity
from .claim import ClaimSession, from_pinned, parse_reply, reply_text
from .config import Config
from . import hostevents
from .hostevents import EventLog
from .logs import HostLog
from .state import StateStore, atomic_write_json, take_controls
from .validate import (REPLY_KIND, TASK_KIND, UUID_RE, WORKER_RE, Context, Decision, Pin, Policy, classify,
                       digest_of, parse_body, sender_is, sender_of, validate_task)

# Refresh outcomes that are posted on the bus (once per commit): the file on main is not one the host accepts.
FLEET_PROBLEMS = {"fleet-unsigned", "fleet-bad-signature", "fleet-cannot-verify", "fleet-invalid", "fleet-old"}
from .vault import GitVault, remove_tree

TERMINAL_REPLIES = {"finished", "failed", "timed-out", "interrupted"}
# Every worker identity is subscribed to these when it is created; the task's own notes channel (fleet.toml
# notes_channel, or config.toml's [coordinator] notes_channel before the first signed fleet) is added before each
# launch (Host.ensure_channel).
WORKER_CHANNELS = ("Humans",)
WIP_PROTECTED = {"develop", "main", "master"}
# The App's Hosts dashboard (docs/app-host-integration.md section 1a): the bus's status API, as this host.
STATUS_PUSH_PATH = "/api/hosts/status"
STATUS_PUSH_SECONDS = 60     # at least this often
STATUS_PUSH_MIN_GAP = 10     # at most this often (the bus refuses more than one push per 10 s)
STATUS_PUSH_BACKOFF = 3600   # after a refusal (an older bus, or not marked as a host yet)
PWSH_PATHS = (r"C:\Program Files\PowerShell\7\pwsh.exe",)  # the bootstrap's pinned install, if not on PATH
# Host events for the bus's event log (section 1b).
EVENTS_PATH = "/api/hosts/events"
EVENTS_MIN_GAP = 5           # the bus takes one call per 5 s per host
WIP_PUSH_TIMEOUT = 120


# Fixed wording: security monitoring may match it. Keep it stable.
OPENBAO_DOWN = "vault unreachable, no new tasks"
OPENBAO_UP = "vault reachable, taking tasks"

# A status event that waited in the outbox longer than this is marked late when it is finally sent. (Seen on the
# a rebuilt host: "vault unreachable" queued by a 13:17 probe run went out at 14:15, when it was untrue.)
OUTBOX_LATE_SECONDS = 600


def read_json_file(path: Path) -> dict | None:
    """A small JSON state file written by the host or its installer, or None if missing or unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def vault_state_of(text: str) -> bool | None:
    """True/False for a queued vault-state line (OPENBAO_UP / OPENBAO_DOWN), None for anything else."""
    if text.endswith(OPENBAO_UP):
        return True
    if text.endswith(OPENBAO_DOWN):
        return False
    return None


def openbao_client(cfg: Config) -> openbao_mod.Client:
    ob = cfg.openbao
    leaf = cfg.leaf_dir
    transport = openbao_mod.https_transport(ob.url, ob.ca or cfg.bus_ca, str(leaf / "leaf.crt"), str(leaf / "leaf.key"))
    return openbao_mod.Client(transport, cfg.openbao_prefix, ob.mount, ob.role or cfg.openbao_prefix)


def rotate_spn_now(cfg: Config, store, log, sleep=time.sleep, clock=time.monotonic) -> str:
    """Rotate this host's SPN (bus 0.2.61) and store the successor in OpenBao inside the 60 s overlap.
    Returns "rotated", "replayed" or "lost". "lost" means the bus issued a successor that could not be stored: the old
    SPN stops working after 60 s and the operator must rotate it from the console. Nothing secret is logged."""
    from .busclient import rotate_spn

    spn = store.load_spn()
    new = rotate_spn(Bus(cfg.bus_url, cfg.bus_ca), spn, str(uuid.uuid4()))
    del spn
    if new is None:
        log("spn-rotate-replayed")
        return "replayed"
    deadline = clock() + 50
    while True:
        try:
            store.save_spn(new, rotated_at=time.time())
            if store.load_spn() == new:
                break
        except OSError as e:
            log("spn-rotate-store-retry", error=type(e).__name__)
        if clock() >= deadline:
            del new
            log("spn-rotate-lost")
            return "lost"
        sleep(5)
    del new
    log("spn-rotated")
    return "rotated"


def load_pins(cfg: Config) -> dict:
    path = cfg.state_dir / "pins.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    coord = data.get("coordinator") or {}
    host = data.get("host") or {}
    return {
        "coordinator": Pin(str(coord.get("agent_id", "")), cfg.coordinator_name)
        if coord.get("agent_name", cfg.coordinator_name) == cfg.coordinator_name else Pin("", cfg.coordinator_name),
        "host": Pin(str(host.get("agent_id", "")), str(host.get("agent_name", cfg.host_agent))),
    }


def save_pins(cfg: Config, coordinator: Pin | None = None, host: Pin | None = None) -> None:
    path = cfg.state_dir / "pins.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if coordinator:
        data["coordinator"] = {"agent_id": coordinator.agent_id, "agent_name": coordinator.agent_name}
    if host:
        data["host"] = {"agent_id": host.agent_id, "agent_name": host.agent_name}
    atomic_write_json(path, data)
    creds.owner_only(path)


@dataclass
class Pending:
    session: ClaimSession
    task: dict
    msg_seq: int
    brief: object
    claim_at: float
    resume: bool = False
    coordinator: Pin | None = None  # the coordinator that sent this task (it alone may cancel it)
    policy: Policy | None = None  # that coordinator's project: notes repository, channel, preamble rules
    repo_url: str = ""  # the task's repository, checked (validate.resolve_repo)


@dataclass
class Host:
    cfg: Config
    bus: Bus | None = None
    vault: GitVault | None = None
    store: creds.Store | None = None
    log: HostLog | None = None
    echo: bool = False
    # The pinned signer list. Not a config.toml key on purpose: only setup (elevated) decides it. Tests pass one.
    signers: Path | None = None
    # The installed code (self-update writes here). Tests pass a temporary folder; never the repository.
    app_dir: Path | None = None
    runs: dict = field(default_factory=dict)
    pending: dict = field(default_factory=dict)
    resumes: list = field(default_factory=list)
    cancelled_seqs: set = field(default_factory=set)
    # Class defaults (not dataclass fields): OpenBao off. __post_init__ sets them per host.
    openbao = None
    openbao_ok = True
    next_openbao_check = 0.0
    restart_pending: bool | None = None   # Windows will restart at [update] windows_restart (workerhost/winupdate.py)
    next_restart_check = 0.0
    next_leaf_renew = 0.0
    next_leaf_ask = 0.0
    leaf_renew_failing = False
    leaf_subscribed = False
    leaf_issued_unposted = False
    next_spn_check = 0.0

    def __post_init__(self):
        cfg = self.cfg
        for d in (cfg.home, cfg.state_dir, cfg.logs_dir, cfg.briefs_dir, cfg.control_dir):
            d.mkdir(parents=True, exist_ok=True)
        # EventLog: the host log, plus a few lines queued as events for the bus's event log (section 1b). The local
        # log files are unchanged and stay the full record.
        self.log = self.log or EventLog(cfg.logs_dir, cfg.state_dir, echo=self.echo)
        # Host secrets: OpenBao when [openbao] enabled (docs/openbao-design.md), else the DPAPI store as before.
        self.openbao: openbao_mod.Client | None = None
        self.openbao_ok = True
        self.next_openbao_check = 0.0
        if self.store is None and cfg.openbao.enabled:
            self.openbao = openbao_client(cfg)
            self.store = openbao_mod.Store(self.openbao, cfg.host_agent)
        self.store = self.store or creds.Store(cfg.creds_dir)
        self.vault = self.vault or GitVault(cfg.vault_dir, cfg.vault_remote(), cfg.git_exe)
        self.vaults: dict[str, GitVault] = {}  # notes repository URL -> its mirror (fleet coordinators)
        self.st = StateStore(cfg.state_dir)
        self.st.load()
        self.pins = load_pins(cfg)
        self.guard = resources.Guard(cfg.resources)
        self.sample: resources.Sample | None = None
        self.next_sample = 0.0
        self.next_poll = 0.0
        self.next_heartbeat = time.time() + 60 * cfg.heartbeat_idle_minutes
        self.channel_state = "unknown"
        self.bus_state = "unknown"
        # The Hosts dashboard push (push_status_if_due): when, what was last accepted, and a refusal being backed off.
        self.push_at, self.push_after, self.push_key = 0.0, 0.0, None
        self.push_refused: int | None = None
        # Host events (section 1b): the problem code last seen, and the sender's timing.
        self.problem_checked, self.problem_code = 0.0, None
        self.events_at, self.events_after = 0.0, 0.0
        self.events_refused: int | None = None
        self.game_paused = False
        self.pressure_posted = False
        self.maintenance = False
        self.update_when_idle = False
        self.exit_code: int | None = None
        self.ghcp_version: str | None = None
        self.ghcp_ok: bool | None = None  # False after a failed update until the next good version read
        self.last_disk_cleanup = 0.0
        self._warned_no_pin = False
        self.signers = Path(self.signers) if self.signers else signing.pinned_path()
        self.ssh_keygen = signing.find_ssh_keygen(cfg.ssh_keygen_exe)
        self.nonces = commands_mod.NonceStore(cfg.state_dir / "command-nonces.json")  # signed commands (stage D)
        self.fleet_sync = fleet_mod.FleetSync(cfg.fleet_mirror_dir, cfg.fleet_store_dir, cfg.fleet_remote(),
                                              cfg.git_exe, self.ssh_keygen, self.signers)
        self.fleet: fleet_mod.Fleet | None = self.fleet_sync.load_last_good()
        # Once any signed fleet was accepted, config.toml's [coordinator]/[[hosts]] are never used again: if the
        # kept copy cannot be checked, the host trusts nobody until a refresh succeeds (fail closed).
        self.fleet_required = bool(self.fleet_sync.accepted())
        self.next_fleet = 0.0
        self.fleet_status = "accepted" if self.fleet else ("unavailable" if self.fleet_required else "legacy")
        self.fleet_posted: set[str] = set()
        self.log("fleet-loaded", state=self.fleet_status, fleet=self.fleet.label if self.fleet else "-")
        # Self-update (workerhost/update.py): release.toml is read from the same mirror as fleet.toml.
        self.app_dir = Path(self.app_dir) if self.app_dir else INSTALL_DIR
        self.update_file = cfg.state_dir / "update.json"
        self.ustate = update_mod.load_state(self.update_file)
        # Where releases come from: config.toml, else the installed release's signed
        # redirect, else the fleet mirror. The same pinned project release key checks them, wherever they are.
        self.release_where = update_mod.where(cfg, update_mod.installed(self.app_dir))
        self.release_unreachable = False
        self.release_source = update_mod.ReleaseSource(
            cfg.fleet_mirror_dir if self.release_where.origin == "fleet"
            else update_mod.mirror_for(cfg.release_mirrors_dir, self.release_where.url),
            cfg.git_exe, self.ssh_keygen, self.signers, cfg.state_dir / "release-tmp", path=self.release_where.path)
        self.started_at = time.time()
        self.metadata_refused = False  # set when the bus refuses message metadata (an older bus): see post()
        self.update_now = False
        self.models_sig = self._config_signature()  # [models] hot reload: the file as loaded at start
        self.cpu_times: tuple[int, int, int] | None = None  # the previous GetSystemTimes reading
        self.cpu_at = 0.0
        self.cpu_now: float | None = None
        self.cpu_window: list[float] = []  # readings since the last heartbeat

    # --- identities ---------------------------------------------------------------------------
    @property
    def me(self) -> Pin:
        return self.pins["host"]

    def coordinators(self) -> list[Pin]:
        """Who may task this host: fleet.toml's coordinators, or before the first signed fleet the one coordinator
        pinned by `wh enrol` (config.toml [coordinator]), or nobody."""
        if self.fleet is not None:
            return [c.pin for c in self.fleet.coordinators]
        if self.fleet_required:
            return []
        legacy = self.pins["coordinator"]
        return [legacy] if legacy.agent_id else []

    def pinned_hosts(self) -> list[Pin]:
        if self.fleet is not None:
            hosts = list(self.fleet.hosts)
        else:
            hosts = [Pin(h["agent_id"], h["agent_name"]) for h in self.cfg.hosts]
        if self.me.agent_id and all(h.agent_id != self.me.agent_id for h in hosts):
            hosts.append(self.me)
        return hosts

    def vault_for(self, notes_repo: str) -> GitVault:
        """The mirror of a coordinator's notes repository. The legacy vault_repo keeps the existing mirror."""
        if urls.canonical(notes_repo) == urls.canonical(self.cfg.vault_remote()):
            return self.vault
        key = urls.canonical(notes_repo)
        if key not in self.vaults:
            self.vaults[key] = GitVault(self.cfg.notes_vault_dir(key), key + ".git", self.cfg.git_exe)
        return self.vaults[key]

    def policy_for(self, pin: Pin) -> Policy | None:
        """The sending coordinator's project, from the signed fleet; before the first one, the legacy policy for the
        one pinned coordinator (short repo names, config's vault_repo, and config.toml's [coordinator] project,
        notes_channel and owner)."""
        if self.fleet is not None:
            c = self.fleet.coordinator(pin)
            if c is None:
                return None
            return Policy(vault=self.vault_for(c.notes_repo), project=c.project, coordinator_name=c.agent_name,
                          notes_channel=c.notes_channel, repos=tuple(c.repos), repo_instructions=c.repo_instructions,
                          worker_rules=c.worker_rules, legacy=False, owner=getattr(self.fleet, "owner", ""))
        if self.fleet_required:
            return None
        return Policy(vault=self.vault, coordinator_name=pin.agent_name,
                      project=getattr(self.cfg, "coordinator_project", "default"),
                      notes_channel=getattr(self.cfg, "coordinator_notes_channel", "") or self.cfg.channel,
                      owner=getattr(self.cfg, "owner", ""))

    def all_vaults(self) -> list[GitVault]:
        return [self.vault, *self.vaults.values()]

    def task_coordinator(self, task_id: str) -> Pin | None:
        """The coordinator recorded when the task was claimed (records from before fleet.toml have none)."""
        rec = self.st.data["tasks"].get(task_id, {}).get("coordinator")
        if isinstance(rec, dict) and isinstance(rec.get("agent_id"), str) and isinstance(rec.get("agent_name"), str):
            return Pin(rec["agent_id"], rec["agent_name"])
        return None

    # --- fleet.toml -----------------------------------------------------------------------------
    def refresh_fleet(self, force: bool = False) -> fleet_mod.Outcome | None:
        now = time.time()
        if not force and now < self.next_fleet:
            return None
        self.next_fleet = now + 60 * self.cfg.fleet_refresh_minutes
        out = self.fleet_sync.refresh(self.fleet, bus=self.bus, source=self.cfg.fleet_source)
        if out.detail == "no bus connection":
            self.next_fleet = now + 60  # not connected yet: try again soon rather than in fleet_refresh_minutes
        if out.status == "fleet-accepted":
            old = self.fleet.label if self.fleet else self.fleet_status
            self.fleet, self.fleet_status, self.fleet_required = out.fleet, "accepted", True
            self.log("fleet-accepted", fleet=out.fleet.label, was=old, signer=out.detail,
                     coordinators=len(out.fleet.coordinators), hosts=len(out.fleet.hosts),
                     ignored=",".join(out.fleet.ignored_keys) or "-")
            self.post("status", f"host={self.cfg.host_name} fleet-accepted fleet={out.fleet.label} "
                                f"coordinators={len(out.fleet.coordinators)} hosts={len(out.fleet.hosts)}", queue=False)
            return out
        if out.status == "unchanged":
            return out
        key = f"{out.status}:{out.commit or out.detail}"  # a copy from the bus has no commit
        if key not in self.fleet_posted:
            self.fleet_posted.add(key)
            self.log(out.status, commit=out.commit[:12] or "-", detail=out.detail or "-",
                     keeping=self.fleet.label if self.fleet else self.fleet_status)
            if out.status in FLEET_PROBLEMS:
                self.post("status", f"host={self.cfg.host_name} {out.status} commit={out.commit[:7]} "
                                    f"detail={out.detail or '-'} keeping="
                                    f"{self.fleet.label if self.fleet else self.fleet_status}", queue=False)
        return out

    def connect(self) -> None:
        if self.bus is not None:
            return
        try:
            rec = self.store.load(self.cfg.host_agent)
        except (LookupError, OSError, ValueError):
            self.log("no-credential", identity=self.cfg.host_agent)
            return
        self.bus = Bus(self.cfg.bus_url, self.cfg.bus_ca, rec["secret"])
        if not self.me.agent_id:
            self.pins["host"] = Pin(rec["agent_id"], rec["agent_name"])

    # --- posting ------------------------------------------------------------------------------
    def bus_is_ok(self) -> None:
        """The bus answered. After an outage, one `bus-back` line (and event, section 1b) marks its end."""
        if self.bus_state == "down":
            self.log("bus-back")
        self.bus_state = "ok"

    def post(self, kind: str, text: str, reply_to: int | None = None, queue: bool = True,
             metadata: dict | None = None) -> int | None:
        """metadata goes only with a direct post (the status object); a queued post is sent later without it. A bus
        that refuses metadata (an older bus) gets the post again without it, and no metadata until the host restarts,
        so a heartbeat is never lost to it."""
        if self.bus is not None:
            try:
                if metadata and not self.metadata_refused:
                    try:
                        seq = self.bus.post(self.cfg.channel, kind, text, reply_to, metadata=metadata)
                    except BusError as e:
                        if e.status not in (400, 413, 422):
                            raise
                        self.metadata_refused = True
                        self.log("metadata-refused", status=e.status, action="posting-without-it-until-restart")
                        seq = self.bus.post(self.cfg.channel, kind, text, reply_to)
                else:
                    seq = self.bus.post(self.cfg.channel, kind, text, reply_to)
                self.bus_is_ok()
                return seq
            except (BusError, OSError, ValueError):
                self.bus_state = "down"
        if queue:
            box = self.st.data["outbox"]
            if kind == "status" and vault_state_of(text) is not None:
                # Only the latest vault state means anything: it supersedes any earlier one still waiting.
                box[:] = [i for i in box if not (i.get("kind") == "status" and vault_state_of(i.get("text", "")) is not None)]
            box.append({"kind": kind, "text": text, "reply_to": reply_to, "queued_at": time.time()})
            self.st.save()
        return None

    def reply(self, kind: str, task_id: str | None, digest: str, reply_to: int, queue: bool = True, **extra):
        return self.post(REPLY_KIND, reply_text(kind, task_id, digest, self.cfg.host_name, **extra), reply_to, queue)

    def flush_outbox(self) -> None:
        box = self.st.data["outbox"]
        if not box or self.bus is None:
            return
        while box:
            item = box[0]
            text = item["text"]
            if item["kind"] == "status":
                was = vault_state_of(text)
                if was is not None and (self.openbao is None or was != self.openbao_ok):
                    # Superseded: the host's vault state has changed since (or a restart re-checks it and posts any
                    # change itself). Sending it now would announce something untrue.
                    box.pop(0)
                    self.log("outbox-dropped", why="superseded", text=text)
                    continue
                queued = item.get("queued_at")
                if queued and time.time() - queued > OUTBOX_LATE_SECONDS:
                    # Appended, so the fixed wording at the front (SIEM rules match it) is unchanged.
                    text = f"{text} (queued {datetime.fromtimestamp(queued).strftime('%H:%M')}, sent late)"
            try:
                self.bus.post(self.cfg.channel, item["kind"], text, item.get("reply_to"))
            except (BusError, OSError, ValueError):
                self.bus_state = "down"
                break
            box.pop(0)
        self.st.save()

    # --- state of the host --------------------------------------------------------------------
    def active(self) -> int:
        return len(self.runs) + len(self.pending)

    def reported_state(self) -> str:
        if self.exit_code is not None:
            return "stopped"
        if self.st.data["draining"] or (self.st.data.get("drain_to_pause") and self.active()):
            return "draining"
        if self.maintenance:
            return "maintenance"
        base = "running" if self.runs else "claimed" if self.pending else "idle"
        if self.st.data["paused"] or self.game_paused:
            return f"paused({base})"
        return base

    def model_allowed(self, model: object) -> bool:
        return models_mod.is_allowed(model, self.cfg.allowed_models, self.cfg.denied_models)

    def default_model(self) -> str:
        """A set-model choice while it is still allowed (a reload may have narrowed the list), else the config's."""
        m = self.st.data.get("default_model")
        return m if m and self.model_allowed(m) else self.cfg.default_model

    def _config_signature(self) -> tuple[int, int] | None:
        try:
            s = (self.cfg.home / "config.toml").stat()
            return (s.st_mtime_ns, s.st_size)
        except OSError:
            return None

    def reload_models(self) -> None:
        """Hot reload of config.toml [models] only. Checked every loop (one stat); on a change the table is parsed and
        validated as a whole, and applied only if valid. A bad edit is logged and the previous models stay in force:
        never a half-applied list, and never a fallback to "anything"."""
        sig = self._config_signature()
        if sig is None or sig == self.models_sig:
            return
        self.models_sig = sig
        path = self.cfg.home / "config.toml"
        old = self.current_models()
        try:
            m = models_mod.read(path)
        except (OSError, ValueError) as e:  # tomllib.TOMLDecodeError is a ValueError
            reason = " ".join(str(e).split())[:200]
            self.log("models-reload-failed", reason=reason, kept=",".join(self.cfg.allowed_models))
            self.audit_models("models-reload-failed", f"error={reason} kept: {models_mod.summary(old)}",
                              models_mod.file_sha256(path))
            return
        if m == old:
            return
        self.cfg.default_model, self.cfg.allowed_models, self.cfg.denied_models = m.default, list(m.allowed), list(m.denied)
        self.log("models-reloaded", default=m.default, allowed=",".join(m.allowed), denied=",".join(m.denied) or "-")
        self.audit_models("models-reloaded", f"old: {models_mod.summary(old)} new: {models_mod.summary(m)}",
                          models_mod.file_sha256(path))
        self.heartbeat()  # coordinators see the new list (the heartbeat carries it) without waiting for the next one

    def available_engines(self) -> list[str]:
        """Engines a task may use here now (engines.available): checked when a task is validated and in the heartbeat,
        so signing Claude Code in or out takes effect without a restart. Cached for a minute: status.json rebuilds
        the heartbeat line every second."""
        now = time.monotonic()
        cached = getattr(self, "_engines_cache", None)
        if cached is None or now - cached[0] > 60:
            cached = (now, engines_mod.available(self.cfg.copilot_exe,
                                                 engines_mod.Engines(self.cfg.default_engine, self.cfg.claude)))
            self._engines_cache = cached
        return list(cached[1])

    def current_models(self) -> models_mod.Models:
        return models_mod.Models(self.cfg.default_model, tuple(self.cfg.allowed_models), tuple(self.cfg.denied_models))

    def audit_models(self, event: str, detail: str, sha: str) -> None:
        """A model-policy change in force, posted to the security channel (the SIEM reads it) and remembered, so a
        restart with an edited file is caught too (check_models_at_start). A failed post is logged and also put on the
        host channel: the change is never silent."""
        text = f"{event} host={self.cfg.host_name} sha256={sha} {detail}"
        if event != "models-reload-failed":
            self.st.data["models_applied"] = models_mod.summary(self.current_models())
            self.st.save()
        channel = models_mod.AUDIT_CHANNEL
        posted = False
        if self.bus is not None:
            try:
                if not self.st.data.get("audit_subscribed"):
                    self.bus.call("PUT", "/api/subscriptions/" + channel)
                    self.st.data["audit_subscribed"] = True
                self.bus.post(channel, "status", text)
                posted = True
            except Exception as e:  # noqa: BLE001 - an audit post must never stop the host; it falls back below
                self.log("models-audit-failed", channel=channel, error=getattr(e, "status", type(e).__name__))
        if not posted:
            self.post("status", text)  # queued if the bus is down: delivered when it is back

    def check_models_at_start(self) -> None:
        """config.toml read at start may differ from the last list in force (edited while the host was stopped): that
        is a change too, audited like a reload. The first start with this code records the list (models-loaded)."""
        now = models_mod.summary(self.current_models())
        last = self.st.data.get("models_applied")
        if last == now:
            return
        event = "models-loaded" if last is None else "models-changed-at-start"
        self.log(event, models=now)
        self.audit_models(event, f"old: {last or 'none'} new: {now}", models_mod.file_sha256(self.cfg.home / "config.toml"))

    def sample_cpu(self) -> None:
        """CPU busy % over the last ~30 s, for monitoring only (to size max_workers):
        it never refuses a task. The heartbeat reports the average and peak since the previous heartbeat."""
        if self.cpu_times is not None and time.monotonic() - self.cpu_at < 5:
            return  # a forced sample seconds after the last: too short a span to mean anything
        try:
            now = winapi.system_times()
        except (OSError, NotImplementedError, AttributeError):
            return
        self.cpu_at = time.monotonic()
        if self.cpu_times is not None:
            pct = winapi.cpu_busy_pct(self.cpu_times, now)
            if pct is not None:
                self.cpu_now = pct
                self.cpu_window.append(pct)
        self.cpu_times = now

    def cpu_fields(self) -> list[str]:
        """cpu=<avg>% cpu_max=<peak>% since the last heartbeat (or the latest reading if none yet)."""
        if self.cpu_window:
            return [f"cpu={sum(self.cpu_window) / len(self.cpu_window):.0f}%", f"cpu_max={max(self.cpu_window):.0f}%"]
        if self.cpu_now is not None:
            return [f"cpu={self.cpu_now:.0f}%"]
        return []

    def refresh_sample(self, force: bool = False) -> None:
        now = time.time()
        if not force and now < self.next_sample:
            return
        self.next_sample = now + 30
        self.sample_cpu()
        try:
            self.sample = resources.sample(self.cfg.workers_root)
        except (OSError, NotImplementedError):
            self.sample = None
            return
        was_game = self.game_paused
        self.game_paused = resources.game_running(self.sample, self.cfg.pause_while_running)
        if self.game_paused != was_game:
            self.log("game-pause" if self.game_paused else "game-resume")
        if self.guard.update(self.sample):
            if not self.pressure_posted:
                self.post("status", f"host={self.cfg.host_name} pressure commit={self.sample.commit_pct:.0f}% "
                                    f"ram_free={self.sample.free_phys / resources.GB:.1f}GB", queue=False)
                self.log("pressure")
                self.pressure_posted = True
        else:
            self.pressure_posted = False

    def listed_in_fleet(self) -> bool:
        """False only while a signed fleet is in use that does not list this host. Hosts settle claims only against
        the hosts their fleet lists, so an unlisted host's claims would be ignored by the others and the same task
        could run twice: it takes no work until the fleet lists it (docs/app-host-integration.md section 3)."""
        if self.fleet is None:
            return True
        return any(h.agent_id == self.me.agent_id for h in self.fleet.hosts)

    def resource_verdict(self) -> tuple[str, dict] | None:
        d = self.st.data
        if not self.listed_in_fleet():
            return "needs-fleet", {}
        if d["draining"]:
            return "draining", {}
        if self.maintenance or self.update_when_idle or self.ustate.get("phase") == "announced":
            return "maintenance", {}  # (an announced self-update: no new tasks until it is applied)
        if self.openbao is not None and not self.openbao_ok:
            return "openbao", {}  # fail closed: no new tasks while OpenBao is unreachable; running workers carry on
        if self.restart_blocks_claims():
            return "restart", {}  # updates will restart Windows before a task started now could finish
        if d["paused"]:
            return "paused", {}
        self.refresh_sample(force=True)
        if self.game_paused:
            return "game", {}
        if self.guard.tripped:
            return "pressure", {}
        if self.sample is None:
            return "resources", {}
        verdict = resources.check(self.sample, self.cfg.resources, self.active())
        if verdict and verdict[0] == "disk" and time.time() - self.last_disk_cleanup > 3600:
            self.last_disk_cleanup = time.time()
            self.run_cleanup(disk_pressure=True)
            self.refresh_sample(force=True)
            verdict = resources.check(self.sample, self.cfg.resources, self.active()) if self.sample else verdict
        return verdict

    def uniqueness(self, worker: str, task_id: str) -> str | None:
        if worker in {r.worker for r in self.runs.values()} or worker in {p.task["worker"] for p in self.pending.values()}:
            return "busy"
        cutoff = time.time() - 86400
        replies = [r for r in self.st.data["host_replies"] if r.get("ts", 0) >= cutoff]
        for r in replies:
            if r["type"] != "started" or (r.get("worker") != worker and r.get("task_id") != task_id):
                continue
            ended = any(t["type"] in TERMINAL_REPLIES and t.get("task_id") == r.get("task_id")
                        and t.get("agent_id") == r.get("agent_id") and t["seq"] > r["seq"] for t in replies)
            if not ended:
                return "duplicate"
        return None

    def context(self) -> Context:
        copilot = self.cfg.copilot_exe
        return Context(
            host_name=self.cfg.host_name, coordinators=self.coordinators(), repos=self.cfg.repos,
            allowed_models=list(self.cfg.allowed_models), denied_models=list(self.cfg.denied_models),
            default_engine=self.cfg.default_engine, engines=tuple(self.available_engines()), claude=self.cfg.claude,
            tags=self.cfg.tags, vault=self.vault,
            remotes=list(self.cfg.remotes), policy=self.policy_for,
            handled_seqs=self.st.handled_seqs(), terminal_task_ids=self.st.terminal_task_ids(),
            max_age=timedelta(hours=self.cfg.max_task_age_hours), resources=self.resource_verdict,
            uniqueness=self.uniqueness, git_exe=self.cfg.git_exe,
            fits_command_line=lambda text, policy=None: prompt.fits(text, str(self.cfg.busclient_path), copilot,
                                                                    str(self.cfg.export_dir), policy))

    # --- bus polling --------------------------------------------------------------------------
    def poll(self) -> None:
        now = time.time()
        if now < self.next_poll:
            return
        self.next_poll = now + self.cfg.poll_seconds
        self.connect()
        if self.bus is None:
            self.next_poll = now + 300
            return
        if not self.coordinators() and not self._warned_no_pin:
            # every task will be ignored as the wrong sender: fail closed
            self.log("no-coordinator-pin", fleet=self.fleet_status)
            self._warned_no_pin = True
        try:
            if self.st.data["cursor"] is None:
                newest = self.bus.newest_seq(self.cfg.channel)
                self.backfill(newest)
                self.st.data["cursor"] = newest
                self.st.save()
                self.log("cursor-start", seq=newest)
                self.channel_state = "ok"
                return
            msgs = self.bus.read_all(self.cfg.channel, int(self.st.data["cursor"]))
            self.channel_state = "ok"
            self.bus_is_ok()
        except BusError as e:
            if e.status == 404:
                if self.channel_state != "missing":
                    self.log("channel-missing", channel=self.cfg.channel, action="not-polling-any-other-channel")
                self.channel_state = "missing"
                self.next_poll = now + 300
            else:
                self.log("bus-error", status=e.status)
                self.bus_state = "down"
                self.next_poll = now + 60
            return
        except (OSError, ValueError):
            self.log("bus-unreachable")
            self.bus_state = "down"
            self.next_poll = now + 60
            return
        for m in sorted(msgs, key=lambda x: x["seq"]):
            if m["seq"] <= int(self.st.data["cursor"]):
                continue
            try:
                self.handle(m)
            finally:
                self.st.data["cursor"] = m["seq"]
                self.st.save()

    def backfill(self, newest: int) -> None:
        """Index host replies from the last day so the uniqueness check (step 6) works after a restart."""
        try:
            msgs = self.bus.read_all(self.cfg.channel, max(0, newest - 5000))
        except (BusError, OSError, ValueError):
            return
        for m in msgs:
            self.index_reply(m)

    def index_reply(self, m: dict) -> None:
        if not from_pinned(m, self.pinned_hosts()) or m.get("kind") != REPLY_KIND:
            return
        body = parse_reply(m)
        if not body or body.get("type") not in TERMINAL_REPLIES | {"started"}:
            return
        task_id, worker = body.get("task_id"), body.get("worker")
        if not isinstance(task_id, str) or not UUID_RE.fullmatch(task_id):
            return
        if worker is not None and (not isinstance(worker, str) or not WORKER_RE.fullmatch(worker)):
            return
        if any(r["seq"] == m["seq"] for r in self.st.data["host_replies"]):
            return
        self.st.data["host_replies"].append({"seq": m["seq"], "agent_id": m["agent_id"], "type": body["type"],
                                              "task_id": task_id, "worker": worker, "ts": time.time()})

    def handle(self, m: dict) -> None:
        seq = m["seq"]
        sender = m.get("agent_name", "?")
        if self.handle_command(m):
            return
        if from_pinned(m, self.pinned_hosts()):
            if m.get("kind") == TASK_KIND:
                self.log("ignored", seq=seq, sender=sender, reason="sender")  # a host is never the coordinator
            self.index_reply(m)
            return
        ctx = self.context()
        kind, obj, digest = classify(m, ctx)
        if kind == "ignore":
            reason = "sender" if sender_of(m, ctx.coordinators) is None else "kind-or-shape"
            self.log("ignored", seq=seq, sender=sender, reason=reason)
            return
        if kind == "cancel":
            self.cancel(obj["task"], seq, sender_of(m, ctx.coordinators))
            return
        if kind == "set-model":
            self.st.data["default_model"] = obj["model"]
            self.st.save()
            self.log("set-model", seq=seq, model=obj["model"])
            return
        if kind == "status":
            self.heartbeat(reply_to=seq)
            return
        self.consider(m, ctx)

    # --- signed commands from the App (stage D) -----------------------------------------------------------------------
    def handle_command(self, m: dict) -> bool:
        """A message carrying a signed host command (docs/app-host-integration.md section 4). True when it carried
        one, whatever became of it: such a message is never also read as a task. The signature is the authority, so
        the sender is not checked; a command for another host is only logged, never shown as this host's."""
        try:
            got = commands_mod.carried(m.get("metadata"))
            if got is None:
                return False
            cmd = commands_mod.check(*got, host=self.cfg.host_agent, now=time.time(), nonces=self.nonces,
                                     verify=commands_mod.verifier(self.signers, self.ssh_keygen,
                                                                  self.cfg.state_dir / "tmp"))
        except commands_mod.Refused as e:
            self.log("command-refused", seq=m["seq"], reason=e.reason, verb=e.verb or "-", nonce=e.nonce or "-")
            if e.reason != "not-this-host":
                self.set_last_command(e.nonce, e.verb, "refused", e.reason)
            return True
        self.log("command", seq=m["seq"], verb=cmd.verb, nonce=cmd.nonce, signer=cmd.signer)
        self.run_command(cmd.verb)
        self.set_last_command(cmd.nonce, cmd.verb, "done", None)
        return True

    def run_command(self, verb: str) -> None:
        """The fixed verbs, mapped to the existing control paths. A remote drain leaves the host running and paused
        (unlike a local drain, which stops it), so the App can resume it."""
        d = self.st.data
        if verb == "pause":
            d["paused"] = True
        elif verb == "resume":
            d["paused"], d["drain_to_pause"] = False, False
        elif verb == "drain":
            d["paused"], d["drain_to_pause"] = True, True
            for task_id, p in list(self.pending.items()):
                if p.session.claim_seq is not None:
                    p.session.yield_("draining")
                self.drop_pending(task_id, "yielded")
        elif verb == "update":
            self.update_now = True
            self.update_check(announce=True)
        self.st.save()

    def set_last_command(self, nonce: str | None, verb: str | None, result: str, reason: str | None) -> None:
        self.st.data["last_command"] = {"nonce": nonce, "verb": verb, "result": result, "reason": reason}
        self.st.save()

    def consider(self, m: dict, ctx: Context) -> None:
        seq = m["seq"]
        decision = validate_task(m, ctx)
        task_id = decision.task["task_id"] if decision.task else None
        self.log("task", seq=seq, sender=m.get("agent_name"), decision=decision.action,
                 reason=decision.reason or "-", field=decision.field or "-", task_id=task_id or "-")
        if decision.action != "ignore" or decision.reason != "replay":
            self.st.mark_handled(seq)
        if decision.action == "ignore":
            return
        if decision.action == "refuse":
            extra = {"reason": decision.reason, **decision.numbers}
            if decision.field:
                extra["field"] = decision.field
            if task_id:
                self.st.mark_terminal(task_id, "refused", seq=seq, reason=decision.reason)
                self.log("task-refused", reason=decision.reason)  # the reason code only (section 1b)
            self.reply("refuse", task_id, decision.digest, seq, queue=False, **extra)
            return
        self.reserve(m, decision)

    def reserve(self, m: dict, decision: Decision, resume: bool = False) -> None:
        task = decision.task
        brief = decision.brief
        copy = self.cfg.briefs_dir / f"{brief.blob_sha}.txt"
        if not copy.exists():
            copy.write_text(brief.text, encoding="utf-8")
        coord = decision.coordinator
        session = ClaimSession(self.bus, self.cfg.channel, self.cfg.host_name, m["seq"], task["task_id"],
                               decision.digest, self.pinned_hosts(), coord, self.cfg.settle_seconds,
                               clock=time.time)
        delay = 0.0 if task["host"] == self.cfg.host_name else 2.0 * len(self.runs)
        policy = decision.policy or Policy(vault=self.vault)
        self.pending[task["task_id"]] = Pending(session, task, m["seq"], brief, time.time() + delay, resume, coord,
                                                policy, decision.repo_url)
        self.st.set_task(task["task_id"], status="claiming", seq=m["seq"], worker=task["worker"],
                         digest=decision.digest, project=policy.project, repo_url=decision.repo_url,
                         coordinator={"agent_id": coord.agent_id, "agent_name": coord.agent_name} if coord else None)

    def cancel(self, task_seq: int, seq: int, by: Pin | None) -> None:
        """Only the coordinator that posted a task can cancel it."""
        if by is None:
            return
        self.cancelled_seqs.add((task_seq, by.agent_id))
        self.log("cancel", seq=seq, task=task_seq, by=by.agent_name)
        for task_id, p in list(self.pending.items()):
            if p.msg_seq == task_seq and p.coordinator == by:
                if p.session.claim_seq is not None:
                    p.session.yield_("cancelled")
                self.drop_pending(task_id, "cancelled")
        # A started worker is not killed by a bus message: there is no remote stop (design section 3).

    def drop_pending(self, task_id: str, status: str) -> None:
        self.pending.pop(task_id, None)
        self.st.set_task(task_id, status=status)

    # --- claims -------------------------------------------------------------------------------
    def advance_claims(self) -> None:
        now = time.time()
        for task_id, p in list(self.pending.items()):
            s = p.session
            if p.coordinator is not None and (p.msg_seq, p.coordinator.agent_id) in self.cancelled_seqs:
                if s.claim_seq is not None:
                    s.yield_("cancelled")
                self.drop_pending(task_id, "cancelled")
                continue
            if s.claim_seq is None:
                if now < p.claim_at:
                    continue
                if self.st.data["draining"]:
                    self.drop_pending(task_id, "yielded")
                    continue
                if not s.post_claim():
                    self.log("claim-failed", task_id=task_id)
                    self.drop_pending(task_id, "yielded")
                    continue
                self.log("claimed", task_id=task_id, claim=s.claim_seq)
                self.st.set_task(task_id, status="claimed", claim_seq=s.claim_seq)
                continue
            if not s.ready():
                continue
            outcome = s.decide()
            self.log("settled", task_id=task_id, outcome=outcome)
            if outcome != "win":
                s.yield_(outcome)
                self.drop_pending(task_id, "yielded")
                continue
            self.pending.pop(task_id)
            verdict = self.resource_verdict_excluding_self()
            if verdict:
                self.st.mark_terminal(task_id, "refused", reason=verdict[0])
                self.log("task-refused", reason=verdict[0])
                s.post("refuse", reason=verdict[0], **verdict[1])
                continue
            if self.cfg.messages_mutable and not self.still_same(p):
                s.yield_("changed")
                self.st.set_task(task_id, status="yielded", reason="changed")
                continue
            self.start(p)

    def resource_verdict_excluding_self(self):
        return self.resource_verdict()

    def still_same(self, p: Pending) -> bool:
        """Messages may be mutable: the body we start must be the body we validated (digest)."""
        try:
            msgs = self.bus.read(self.cfg.channel, p.msg_seq - 1, 1)
        except (BusError, OSError, ValueError):
            return False
        m = next((x for x in msgs if x["seq"] == p.msg_seq), None)
        if m is None or p.coordinator is None or not sender_is(m, p.coordinator):
            return False
        try:
            return digest_of(parse_body(m.get("body"))) == p.session.digest
        except Exception:  # noqa: BLE001
            return False

    # --- launching ----------------------------------------------------------------------------
    # --- phase 2: one TTL identity per task attempt (docs/openbao-design.md section 3) ------------------------
    @property
    def ttl_identities(self) -> bool:
        return self.openbao is not None and bool(self.cfg.openbao.ttl_identities)

    def identity_ttl(self) -> int:
        """max_runtime_hours + 1 h, capped at the bus's 12 h (it refuses more rather than clamping)."""
        return int(min(self.cfg.runtime.max_runtime_hours * 3600 + 3600, 43200))

    def task_agent(self, task_id: str, worker: str) -> str:
        """The bus identity for this task attempt. Phase 1: the worker name's durable identity. Phase 2: a new
        <prefix>-<worker>-<yymmdd><n> every attempt, a resume included (the previous one is retired)."""
        stable = self.cfg.worker_agent(worker)
        if not self.ttl_identities:
            return stable
        day = datetime.now().strftime("%y%m%d")
        counters = {k: v for k, v in self.st.data.get("identity_counters", {}).items() if k.endswith("-" + day)}
        key = f"{worker}-{day}"
        counters[key] = int(counters.get(key, 0)) + 1
        self.st.data["identity_counters"] = counters
        prev = self.st.data["tasks"].get(task_id, {}).get("bus_agent")
        if prev and prev != stable:
            self.release_identity(prev)
        return f"{stable}-{day}{counters[key]}"

    def release_identity(self, agent: str) -> None:
        """Retire a TTL identity with the SPN and destroy its OpenBao entry. Never fatal: an identity left behind
        still expires at its TTL and the bus retires it then. Durable (phase 1) identities are never touched."""
        if (not self.ttl_identities or not agent or agent == self.cfg.host_agent
                or not re.fullmatch(re.escape(self.cfg.agent_prefix) + r"-[a-z0-9-]+-[0-9]{6}[0-9]{1,4}", agent)):
            return
        try:
            spn = self.store.load_spn()
            status = retire_identity(Bus(self.cfg.bus_url, self.cfg.bus_ca), spn, agent)
            del spn
        except (LookupError, BusError, OSError, ValueError) as e:
            self.log("identity-retire-failed", agent=agent, error=type(e).__name__)
            return
        try:
            self.store.remove(agent)
        except (OSError, ValueError) as e:
            self.log("identity-entry-destroy-failed", agent=agent, error=type(e).__name__)
        self.st.data.get("worker_channels", {}).pop(agent, None)
        self.log("identity-retired", agent=agent, status=status)

    def release_task_identity(self, task_id: str) -> None:
        agent = self.st.data["tasks"].get(task_id, {}).get("bus_agent")
        if agent:
            self.release_identity(agent)

    def ensure_identity(self, agent: str, ttl: int | None = None) -> dict:
        """The worker's identity record (holds its secret; never log it), minted with the SPN on first use.
        With OpenBao the SPN is read into memory for this call only and the record lives at
        agents/<prefix>/workers/<agent>; a resume reads the same record again (phase 1). With `ttl` (phase 2) the
        identity is new for this task attempt and expires after ttl seconds."""
        try:
            try:
                return self.store.load(agent)
            except LookupError:
                pass
            spn = self.store.load_spn()
            bus = Bus(self.cfg.bus_url, self.cfg.bus_ca)
            record = onboard(bus, spn, agent, "worker (strugglebus worker host)", identity_ttl_seconds=ttl)
            del spn
            self.store.save(agent, record)
            bootstrap(Bus(self.cfg.bus_url, self.cfg.bus_ca, record["secret"]), record, WORKER_CHANNELS)
            return record
        except (LookupError, BusError, OSError, KeyError, ValueError) as e:
            raise launcher.LaunchError("identity") from e

    def ensure_channel(self, agent: str, channel: str, record: dict | None = None) -> None:
        """Subscribe a worker identity to its task's notes channel, once per (identity, channel). Worker names are
        host-wide, so one identity can serve several projects over time. A failure is logged, never fatal: the
        worker's status posts may then be refused by the bus, which the coordinator sees as silence."""
        done = self.st.data.setdefault("worker_channels", {})
        if channel in done.get(agent, []):
            return
        try:
            rec = record or self.store.load(agent)
            status, _ = Bus(self.cfg.bus_url, self.cfg.bus_ca, rec["secret"]).call(
                "PUT", "/api/subscriptions/" + channel)
        except Exception as e:  # noqa: BLE001 - never stops a launch
            self.log("subscribe-failed", agent=agent, channel=channel, error=type(e).__name__)
            return
        if status in (200, 201, 204):
            done.setdefault(agent, []).append(channel)
            self.st.save()
        else:
            self.log("subscribe-failed", agent=agent, channel=channel, status=status)

    def start(self, p: Pending, session_id: str | None = None) -> None:
        """Launch the worker for a claimed task: post "started", then prepare its identity, clone and command and
        start it. Any launch failure is posted as "failed" with its reason, and the task's identity is released."""
        task, s = p.task, p.session
        worker, task_id = task["worker"], task["task_id"]
        plan = self._launch_plan(p, session_id)
        try:
            agent = self.task_agent(task_id, worker)
        except ValueError:
            agent = ""
        # Phase 2: the started reply names the bus identity minted for this attempt (so monitoring can alert on a name
        # no task asked for), and coordinators can see which name the worker posts as.
        named = {"agent": agent} if self.ttl_identities and agent else {}
        s.post("started", worker=worker, model=plan.model, engine=plan.engine, resume=plan.resume,
               repo_instructions=plan.repo_instructions, project=plan.project, **named)
        self.st.set_task(task_id, status="started", seq=p.msg_seq, worker=worker, model=plan.model,
                         session_id=plan.session_id, commit=task["vault_commit"], brief=task["brief"],
                         blob=p.brief.blob_sha, launched_at=time.time(),
                         resumed=self.st.data["tasks"].get(task_id, {}).get("resumed", 0) + (1 if p.resume else 0),
                         by_stop=False, project=plan.project, repo_url=plan.repo_url, bus_agent=agent,
                         engine=plan.engine)
        self.log("started", task_id=task_id, worker=worker, model=plan.model, engine=plan.engine,
                 resume=plan.resume, project=plan.project, **named)
        try:
            run, log = self._launch(p, plan, agent)
        except launcher.LaunchError as e:
            self._launch_failed(task_id, s, worker, plan.project, e.reason, e.reason)
            return
        except (OSError, KeyError, ValueError) as e:
            self._launch_failed(task_id, s, worker, plan.project, "launch", type(e).__name__)
            return
        run.session = s
        run.project = plan.project
        run.model = plan.model
        run.engine = plan.engine
        run.warned = run.stalled = False
        self.runs[task_id] = run
        self.st.set_task(task_id, pid=run.proc.pid, proc_id=winapi.process_identity(run.proc.pid),
                         boot=winapi.boot_time(), log=str(log))

    def _launch_plan(self, p: Pending, session_id: str | None) -> SimpleNamespace:
        """What start() will launch: engine, model, policy, repository, and the session to start or resume."""
        task = p.task
        claude_cfg = getattr(self.cfg, "claude", None)  # getattr: minimal stand-in configs (tests) predate engines
        engine = task.get("engine") or getattr(self.cfg, "default_engine", "ghcp")
        claude = engine == "claude"
        if claude and claude_cfg is None:
            engine, claude = "ghcp", False  # unreachable after validation; never launch an unconfigured engine
        policy = getattr(p, "policy", None) or Policy(vault=self.vault)
        session_id, resume = self._session_for(task["task_id"], task["worker"], engine, claude,
                                               bool(p.resume or task.get("resume")), session_id)
        return SimpleNamespace(
            engine=engine, claude=claude, claude_cfg=claude_cfg, policy=policy, project=policy.project,
            model=task.get("model") or (claude_cfg.default_model if claude else self.default_model()),
            # A pending task from before this release has no checked URL: its short name still maps through [repos].
            repo_url=getattr(p, "repo_url", "") or f"https://github.com/{self.cfg.repos[task['repo']]}",
            repo_instructions=task.get("repo_instructions", policy.repo_instructions) is not False,
            session_id=session_id, resume=resume)

    def _session_for(self, task_id: str, worker: str, engine: str, claude: bool, resume: bool,
                     session_id: str | None) -> tuple[str, bool]:
        """(session id, resume). A resume uses the given session, else the task's last one from the same engine;
        with neither usable it starts a new session instead."""
        clone = Path(self.cfg.workers_root) / worker
        session_ok = engines_mod.claude_session_ok if claude else launcher.session_ok
        if resume and not (session_id and session_ok(session_id, clone)):
            prev = self.st.data["tasks"].get(task_id, {}).get("session_id")
            # A session from the other engine can never be resumed by this one.
            same = self.st.data["tasks"].get(task_id, {}).get("engine", "ghcp") == engine
            session_id = prev if prev and same and session_ok(prev, clone) else None
            resume = session_id is not None
        return session_id or str(uuid.uuid4()), resume

    def _worker_token(self, agent: str, notes_channel: str) -> str | None:
        """Make sure the worker's bus identity exists and can read its notes channel. With OpenBao, return its
        credential (passed in SB_BUS_TOKEN, its process environment only); with DPAPI, None (it gets the store
        folder). Not isolation while workers share a user: a dedicated account is."""
        if not agent:
            raise launcher.LaunchError("identity")
        record = (self.ensure_identity(agent, self.identity_ttl()) if self.ttl_identities
                  else self.ensure_identity(agent))
        self.ensure_channel(agent, notes_channel, record if isinstance(record, dict) else None)
        token = record.get("secret") if self.openbao is not None and isinstance(record, dict) else None
        if self.openbao is not None and not token:
            raise launcher.LaunchError("identity")
        return token

    def _launch(self, p: Pending, plan: SimpleNamespace, agent: str):
        """(run, log path): identity, clone, .ds-worker.json, the engine's command and environment, then launch."""
        task, worker = p.task, p.task["worker"]
        token = self._worker_token(agent, plan.policy.notes_channel)
        clone = launcher.prepare_clone(self.cfg.workers_root, worker, plan.repo_url, task["branch"],
                                       self.cfg.gh_exe, self.cfg.git_exe, require_clean=not plan.resume)
        meta = {"name": worker, "agent": agent, "project": plan.project, "repo": plan.repo_url, "clone": str(clone),
                "branch": task["branch"]}
        vault = plan.policy.vault
        if vault.referenced_files(task["vault_commit"], p.brief.text, task["brief"]):
            export = vault.export(task["vault_commit"], self.cfg.export_dir)
            if export is None:
                raise launcher.LaunchError("vault-export")
            meta["vault_export"] = str(export)
        launcher.write_meta(clone, meta)
        cmd, stdin_text = self._command(p, plan, meta.get("vault_export"))
        temp = Path(self.cfg.workers_root) / "tmp" / f"{worker}-{p.msg_seq}"
        own_name = self.cfg.worker_agent(worker)
        env = launcher.worker_env(dict(os.environ), bus_ca=self.cfg.bus_ca, bus_url=self.cfg.bus_url,
                                  store=None if token else self.cfg.creds_dir, token=token, temp=temp,
                                  gh_exe=self.cfg.gh_exe, wait_timeout=self.cfg.runtime.task_wait_timeout_seconds,
                                  task_seq=p.msg_seq, coordinator=p.coordinator,
                                  notes_channel=plan.policy.notes_channel, project=plan.project,
                                  notes_name=own_name if agent != own_name else "")
        if plan.claude:
            env.update(engines_mod.CLAUDE_ENV)
        log = Path(self.cfg.workers_root) / f"{worker}.log"
        head = launcher.header({"seq": p.msg_seq, "task_id": task["task_id"], "project": plan.project,
                                "repo": plan.repo_url, "brief": task["brief"], "vault_commit": task["vault_commit"],
                                "blob": p.brief.blob_sha, "model": plan.model, "engine": plan.engine,
                                "ghcp": self.ghcp_version or "?", "host": self.cfg.host_name,
                                "resume": plan.resume, "repo_instructions": plan.repo_instructions,
                                "at": time.strftime("%Y-%m-%dT%H:%M:%S")})
        run = launcher.launch(cmd, clone, env, log, temp, worker, task["task_id"], head, stdin_text=stdin_text)
        return run, log

    def _command(self, p: Pending, plan: SimpleNamespace, vault_export: str | None) -> tuple[list[str], str | None]:
        """(command, stdin text) for the task's engine: Claude Code takes the prompt on stdin, Copilot CLI in -p."""
        if plan.claude:
            return launcher.build_claude(plan.claude_cfg.exe, p.brief.text, str(self.cfg.busclient_path), plan.model,
                                         plan.session_id, plan.resume, vault_export, plan.repo_instructions,
                                         plan.policy)
        return launcher.build(self.cfg.copilot_exe, p.brief.text, str(self.cfg.busclient_path), plan.model,
                              plan.session_id, plan.resume, vault_export, plan.repo_instructions, plan.policy), None

    def _launch_failed(self, task_id: str, s, worker: str, project: str, reason: str, log_reason: str) -> None:
        self.st.mark_terminal(task_id, "failed", reason=reason)
        s.post("failed", reason=reason, worker=worker, project=project)
        self.log("launch-failed", task_id=task_id, reason=log_reason)
        self.release_task_identity(task_id)

    # --- supervision --------------------------------------------------------------------------
    def supervise(self) -> None:
        now = time.time()
        rt = self.cfg.runtime
        for task_id, run in list(self.runs.items()):
            code = run.poll()
            if code is not None:
                self.finish(task_id, run, code)
                continue
            elapsed = now - run.started
            limit = rt.max_runtime_hours * 3600
            if elapsed >= limit:
                run.kill()
                run.poll()
                wip = self.save_wip(task_id, run, "timeout") or {}
                self.st.mark_terminal(task_id, "timed-out", exit_code=-1)
                run.session.post("timed-out", worker=run.worker, minutes=round(elapsed / 60),
                                 project=getattr(run, "project", "") or "-", **wip)
                self.end(task_id, run, "timed-out", -1)
                continue
            if elapsed >= 0.8 * limit and not run.warned:
                run.warned = True
                run.session.post("warning", worker=run.worker, minutes=round(elapsed / 60),
                                 limit_minutes=round(limit / 60))
            quiet = now - max(run.last_output, _mtime(run.log))
            if quiet >= rt.stall_minutes * 60 and not run.stalled:
                run.stalled = True
                run.session.post("stalled", worker=run.worker, quiet_minutes=round(quiet / 60))
            elif quiet < rt.stall_minutes * 60:
                run.stalled = False

    def finish(self, task_id: str, run, code: int) -> None:
        clone = Path(self.cfg.workers_root) / run.worker
        try:
            ahead = cleanup.unpushed(clone, self.cfg.git_exe)
        except (OSError, subprocess.TimeoutExpired):
            ahead = None
        pushed = "yes" if ahead == "" else "no"
        # `pushed` above counts commits only; uncommitted edits are unsaved work too, so always inspect.
        extra = self.save_wip(task_id, run, "exit") or {}
        pushed = extra.pop("pushed", pushed)
        kind = "finished" if code == 0 else "failed"
        self.st.mark_terminal(task_id, kind, exit_code=code)
        spent = self.read_spent(task_id)
        run.session.post(kind, worker=run.worker, exit_code=code, minutes=round((time.time() - run.started) / 60),
                         model=run.model, engine=getattr(run, "engine", "ghcp"), ghcp=self.ghcp_version or "?",
                         pushed=pushed, project=getattr(run, "project", "") or "-", **extra, **spent)
        self.end(task_id, run, kind, code, spent)

    def save_wip(self, task_id: str, run, why: str) -> dict | None:
        """Commit and push what a worker left behind (timeout, kill, or exit without a push).

        Returns envelope keys: {"pushed": "wip", "wip_branch": b} when saved, {"pushed": "no"} when
        it was skipped or failed, or None when there was nothing to save (or the clone is not this
        task's). Runs before the terminal post, while the clone is still there; never raises."""
        try:
            return self._save_wip(task_id, run, why)
        except Exception as e:  # noqa: BLE001 - the finish must always post
            self.log.error("wip-failed", e, task_id=task_id, worker=run.worker)
            return {"pushed": "no"}

    def _save_wip(self, task_id: str, run, why: str) -> dict | None:
        worker = run.worker
        clone = Path(self.cfg.workers_root) / worker
        try:
            meta = json.loads((clone / launcher.META).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            meta = {}
        same_clone = (isinstance(meta, dict) and meta.get("name") == worker
                      and os.path.normcase(os.path.abspath(str(meta.get("clone", ""))))
                      == os.path.normcase(os.path.abspath(clone)))
        if (not (clone / ".git").exists() or not same_clone
                or self.st.data["tasks"].get(task_id, {}).get("worker") != worker):
            self.log("wip-skipped", task_id=task_id, worker=worker, reason="not-host-clone")
            return None
        # The WIP commit is the host's own, so it carries the host's identity explicitly. Before 18 Nov it used whatever
        # git config held, and a fresh host account has none at any level: every WIP save that needed a commit failed
        # ("wip-failed step=commit"), leaving the worker's last changes uncommitted in its clone. The environment
        # variables beat every config level, so the result is the same on every machine.
        who = f"{self.cfg.host_agent} (worker host)"
        email = f"{self.cfg.host_agent}@worker-host.invalid"
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": who, "GIT_AUTHOR_EMAIL": email,
               "GIT_COMMITTER_NAME": who, "GIT_COMMITTER_EMAIL": email}

        def git(*args: str, timeout: float = 60) -> subprocess.CompletedProcess:
            return subprocess.run([self.cfg.git_exe, "-C", str(clone), *args], capture_output=True, timeout=timeout,
                                  stdin=subprocess.DEVNULL, env=env)

        head = git("symbolic-ref", "--quiet", "--short", "HEAD")
        branch = head.stdout.decode("utf-8", "replace").strip() if head.returncode == 0 else ""
        if not branch or branch in WIP_PROTECTED:
            self.log("wip-skipped", task_id=task_id, worker=worker,
                     reason=f"on-{branch}" if branch else "detached-head")
            return {"pushed": "no"}
        # Line-ending-only changes are not work: without this every worker of a repository like that
        # that exited on a branch pushed a WIP commit renormalising one vendored file.
        dirty = cleanup.uncommitted(clone, self.cfg.git_exe)
        if dirty is None:
            self.log("wip-failed", task_id=task_id, worker=worker, step="status")
            return {"pushed": "no"}
        ahead = git("rev-list", "HEAD", "--not", "--remotes=origin")
        if ahead.returncode != 0:
            self.log("wip-failed", task_id=task_id, worker=worker, step="rev-list")
            return {"pushed": "no"}
        if not dirty and not ahead.stdout.strip():
            return None
        if dirty:
            if git("add", "-A").returncode != 0:
                self.log("wip-failed", task_id=task_id, worker=worker, step="add")
                return {"pushed": "no"}
            label = "timeout" if why == "timeout" else "exit"
            message = f"WIP ({label}): {worker} {task_id}\n\nWorker-Host: wip\n"
            if git("-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m", message).returncode != 0:
                self.log("wip-failed", task_id=task_id, worker=worker, step="commit")
                return {"pushed": "no"}
        try:
            push = git("push", "-q", "origin", f"HEAD:refs/heads/{branch}", timeout=WIP_PUSH_TIMEOUT)
            ok = push.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        if not ok:
            self.log("wip-push-failed", task_id=task_id, worker=worker, branch=branch)
            return {"pushed": "no"}
        self.log("wip-pushed", task_id=task_id, worker=worker, branch=branch, why=why, committed=bool(dirty))
        return {"pushed": "wip", "wip_branch": branch}

    def read_spent(self, task_id: str) -> dict:
        """Envelope keys for what the session spent; empty (and one `usage-missing` line) on any log problem.
        GHCP: AIC from its session log. Claude Code: US dollars from the `result` line in the worker log, under their
        own keys (usd, by_model_usd), never added to AIC."""
        rec = self.st.data["tasks"].get(task_id, {})
        if rec.get("engine") == "claude":
            try:
                u = engines_mod.read_claude_usage(Path(rec.get("log") or ""), task_id)
            except Exception:  # noqa: BLE001
                u = None
            if u is None:
                self.log("usage-missing", task_id=task_id, engine="claude")
                return {}
            spent = {"usd": u["usd"], "calls": u["calls"], "by_model_usd": u["by_model_usd"]}
            if u.get("model_observed"):
                spent["model_observed"] = u["model_observed"]
            return spent
        try:
            u = usage.read_usage(self.st.data["tasks"][task_id]["session_id"])
        except Exception:  # noqa: BLE001
            u = None
        if u is None:
            self.log("usage-missing", task_id=task_id)
            return {}
        spent = {"aic": u["aic"], "calls": u["calls"], "by_model": u["by_model"]}
        if u.get("model_observed"):
            spent["model_observed"] = u["model_observed"]
        return spent

    def end(self, task_id: str, run, status: str, code: int, spent: dict | None = None) -> None:
        self.runs.pop(task_id, None)
        self.release_task_identity(task_id)  # phase 2: retired by the SPN as soon as its task is over
        try:
            run.job.close()
        except Exception:  # noqa: BLE001
            pass
        if run.temp.exists() and not remove_tree(run.temp):
            self.log("temp-delete-failed", task_id=task_id, worker=run.worker)  # the sweep retries it
        clone = Path(self.cfg.workers_root) / run.worker
        cleaned, reason, names = (cleanup.clean_after_finish(clone, code, self.cfg.salvage_dir,
                                                             f"{run.worker}-{task_id}", self.cfg.cleanup.salvage_cap_mb,
                                                             self.cfg.git_exe)
                                  if status == "finished" else (False, status, []))
        held = self.held_reasons()
        if cleaned:
            held.pop(run.worker, None)
        else:
            held[run.worker] = reason
        self.st.data["held_reasons"] = held
        self.st.data["held_clones"] = sorted(held)
        if clone.exists():
            os.utime(clone)
        self.st.set_task(task_id, status=status, exit_code=code, cleaned=cleaned)
        self.log("ended", task_id=task_id, status=status, exit_code=code, clean=reason, salvaged=len(names),
                 **{k: v for k, v in (spent or {}).items() if k in ("aic", "usd", "model_observed")})
        for n in names:
            self.log("salvaged", task_id=task_id, file=n)

    # --- restart recovery (section 14) --------------------------------------------------------
    def recover(self) -> None:
        """Start-up sweep. Only tasks the state file records as running (`started`) or as accepted but not
        started (`claiming`, `claimed`) are looked at; a
        terminal task (finished, failed, timed-out, interrupted, refused, ...) is never re-reported.

        A running task's worker is matched by recorded pid and process start time. Normally it is already
        dead: its job object has KILL_ON_JOB_CLOSE and the job handle died with the previous host process.
        If it is somehow still alive it is killed, not adopted (this process holds no job handle, pipe or
        timer for it, so it cannot be supervised); its work stays in the clone. Only once the worker is
        gone is the task marked `interrupted` (state first) and the reply posted, exactly once.

        A task the previous process accepted or claimed but never started (`claiming`, `claimed`) is
        marked `yielded` (state first) and reported with a `yield` reply (reason `restart`), so the
        coordinator knows to re-post it; it is never silently dropped."""
        boot = winapi.boot_time()
        for task_id, rec in list(self.st.data["tasks"].items()):
            if rec.get("status") in ("claiming", "claimed"):
                claimed = rec.get("status") == "claimed"
                self.st.mark_terminal(task_id, "yielded", reason="restart")
                self.post(REPLY_KIND, reply_text("yield", task_id, rec.get("digest", ""), self.cfg.host_name,
                                                 reason="restart", worker=rec.get("worker")),
                          reply_to=rec.get("seq"))
                self.log("yielded", task_id=task_id, reason="restart", claimed=claimed)
        for task_id in self.st.running_task_ids():
            rec = self.st.data["tasks"][task_id]
            pid, ident = int(rec.get("pid") or 0), rec.get("proc_id")
            if pid and ident and winapi.process_identity(pid) == ident and not winapi.terminate_pid(pid):
                self.log("orphan-alive", task_id=task_id, pid=pid)
                continue
            cause = ("update" if rec.get("update_stop") else
                     "reboot" if boot > float(rec.get("launched_at", 0)) else "restart")
            self.st.mark_terminal(task_id, "interrupted", cause=cause, exit_code=-1)
            self.post(REPLY_KIND, reply_text("interrupted", task_id, rec.get("digest", ""), self.cfg.host_name,
                                             worker=rec.get("worker"), cause=cause),
                      reply_to=rec.get("seq"))
            # A worker stopped for a self-update (its work pushed first) resumes once, as after a reboot.
            if (cause in ("reboot", "update") and self.cfg.runtime.resume_after_reboot and not rec.get("by_stop")
                    and int(rec.get("resumed", 0)) < 1):
                self.resumes.append(task_id)
            self.log("interrupted", task_id=task_id, cause=cause)

    def do_resumes(self) -> None:
        """Resume once after a reboot: task re-read from the bus, brief re-read from the vault."""
        if not self.resumes or self.bus is None or self.channel_state != "ok":
            return
        task_id = self.resumes.pop(0)
        rec = self.st.data["tasks"].get(task_id, {})
        seq = rec.get("seq")
        try:
            msgs = self.bus.read(self.cfg.channel, int(seq) - 1, 1)
        except (BusError, OSError, ValueError, TypeError):
            self.log("resume-skipped", task_id=task_id, reason="bus")
            return
        m = next((x for x in msgs if x["seq"] == seq), None)
        if m is None:
            self.log("resume-skipped", task_id=task_id, reason="message")
            return
        decision = validate_task(m, self.context(), resume=True)
        if not decision.accepted or decision.task["task_id"] != task_id:
            self.log("resume-skipped", task_id=task_id, reason=decision.reason or "task_id")
            return
        recorded = self.task_coordinator(task_id)
        if recorded is not None and recorded != decision.coordinator:
            self.log("resume-skipped", task_id=task_id, reason="coordinator")
            return
        session = ClaimSession(self.bus, self.cfg.channel, self.cfg.host_name, seq, task_id, decision.digest,
                               self.pinned_hosts(), decision.coordinator, self.cfg.settle_seconds)
        self.start(Pending(session, decision.task, seq, decision.brief, time.time(), resume=True,
                           coordinator=decision.coordinator), session_id=rec.get("session_id"))

    # --- heartbeat, maintenance, control ------------------------------------------------------
    def heartbeat_line(self) -> str:
        s = self.sample
        parts = [f"host={self.cfg.host_name}", f"state={self.reported_state()}",
                 f"workers={len(self.runs)}/{self.cfg.resources.max_workers}"]
        if s:
            parts += [f"commit={s.commit_pct:.0f}%", f"ram_free={s.free_phys / resources.GB:.1f}GB",
                      f"disk_free={s.free_disk / resources.GB:.0f}GB"]
        parts += self.cpu_fields()
        root = Path(self.cfg.workers_root)
        held = [w for w in self.st.data.get("held_clones", []) if (root / w).exists()]
        # engines= lists what a task may use here now; the default is marked with *.
        parts.append("engines=" + (",".join(e + ("*" if e == self.cfg.default_engine else "")
                                            for e in self.available_engines()) or "none"))
        parts += [f"ghcp={self.ghcp_version or '?'}", f"model={self.default_model()}",
                  f"models={','.join(self.cfg.allowed_models)}"]
        if self.cfg.claude is not None:
            parts.append(f"claude_models={','.join(self.cfg.claude.allowed)}")
        if self.cfg.denied_models:
            parts.append(f"denied={','.join(self.cfg.denied_models)}")
        parts += [f"clones={self.clones_on_disk()}", f"held_clones={len(held)}"]
        if self.st.data.get("strays"):
            parts.append(f"strays={len(self.st.data['strays'])}")
        parts.append(f"fleet={self.fleet.label if self.fleet else self.fleet_status}")
        parts.append(f"release={update_mod.installed(self.app_dir)['version']}")
        # user=: the Windows account the host (and so every worker) runs as. Mid-line on purpose: the line's start
        # (host= state= workers= commit=) and its optional trailing flags are parsed by others. Monitoring can alert on
        # Claude workers under any account but a dedicated one.
        parts.append(f"user={os.environ.get('USERNAME', '?')}")
        if self.ustate.get("phase") == "announced":
            parts.append(f"update={self.ustate.get('version', '?')}@{self.cfg.update.window}")
        if self.ghcp_ok is False:
            parts.append("ghcp_ok=False")
        if self.restart_pending:
            parts.append(f"restart-pending@{self.cfg.update.windows_restart}")
        if any(getattr(v, "last_fetch_ok", None) is False for v in self.all_vaults()):
            parts.append("vault=failing")  # any coordinator's notes mirror whose last fetch failed
        if self.openbao is not None:
            parts.append(f"openbao={'ok' if self.openbao_ok else 'unreachable'}")
            left = self.leaf_hours_left()
            parts.append(f"leaf={'none' if left is None else f'{max(left, 0):.0f}h'}")
        return " ".join(parts)

    def heartbeat(self, reply_to: int | None = None) -> None:
        self.refresh_sample(force=True)
        status = self.status_json()
        self.post("status", self.heartbeat_line(), reply_to=reply_to, queue=False,
                  metadata=hoststatus.metadata(status))
        self.status_key, self.status_posted_at = hoststatus.change_key(status), time.time()
        self.cpu_window = []  # the next heartbeat reports the CPU since this one
        minutes =self.cfg.heartbeat_running_minutes if self.runs else self.cfg.heartbeat_idle_minutes
        self.next_heartbeat = time.time() + 60 * minutes

    def status_facts(self) -> hoststatus.Facts:
        """What the App's hosts page needs (docs/app-host-integration.md section 1), from what the host already has."""
        inst = update_mod.installed(self.app_dir)
        usable = set(self.available_engines())
        engines = [{"name": "ghcp", "version": self.ghcp_version, "signed_in": None, "usable": "ghcp" in usable,
                    "default": self.cfg.default_engine == "ghcp", "installed": bool(engines_mod.resolve(
                        self.cfg.copilot_exe))}]
        if self.cfg.claude is not None:
            engines.append({"name": "claude", "version": None, "signed_in": engines_mod.claude_signed_in(),
                            "usable": "claude" in usable, "default": self.cfg.default_engine == "claude",
                            "installed": bool(engines_mod.resolve(self.cfg.claude.exe))})
        engines = [e for e in engines if e["installed"]]
        s = self.sample
        verdict = resources.check(s, self.cfg.resources, self.active()) if s is not None else None
        left = self.leaf_hours_left() if self.openbao is not None else None
        listed = self.listed_in_fleet()
        return hoststatus.Facts(
            host=self.cfg.host_name, agent=self.cfg.host_agent, version=inst["version"], serial=inst["serial"],
            started_at=self.started_at,
            interval_s=60 * (self.cfg.heartbeat_running_minutes if self.runs else self.cfg.heartbeat_idle_minutes),
            reported_state=self.reported_state(), account=os.environ.get("USERNAME", "?"),
            dedicated=bool(getattr(self.cfg, "dedicated_account", False)), engines=engines, busy=len(self.runs),
            max_workers=self.cfg.resources.max_workers, claiming=len(self.pending),
            held_clones=len(self.st.data.get("held_clones", [])), outbox=len(self.st.data["outbox"]),
            fleet={"source": ("git" if self.fleet.commit else "bus") if self.fleet is not None else "config",
                   "serial": self.fleet.serial if self.fleet else None,
                   "coordinators": [p.agent_name for p in self.coordinators()], "state": self.fleet_status},
            listed_in_fleet=listed,
            update=({"version": self.ustate.get("version", "?"),
                     "when": "idle" if self.update_now else self.cfg.update.window}
                    if self.ustate.get("phase") == "announced" else None),
            bus_ok=self.bus_state != "down", channel_ok=self.channel_state != "missing",
            openbao_ok=None if self.openbao is None else bool(self.openbao_ok),
            leaf_expiring=left is not None and left < self.cfg.openbao.ask_below_hours and self.leaf_renew_failing,
            rolled_back=self.ustate.get("phase") == "rolled-back",
            resource_problem={"disk": "disk-low", "commit": "memory-high", "ram": "memory-high"}.get(
                verdict[0] if verdict else ""),
            isolation_weak=bool((read_json_file(self.cfg.state_dir / "isolation.json") or {}).get("exec_hits")),
            last_command=self.st.data.get("last_command"),
            release_source=self.release_where.label(), release_unreachable=self.release_unreachable,
            release_redirect_refused=bool(self.release_where.refused), **self.dashboard_facts())

    def dashboard_facts(self) -> dict:
        """The v2-only facts (section 1a): what the desktop panel shows, never a task id, path or repository name."""
        now, s = time.time(), self.sample
        since = self.started_at
        tasks = {k: 0 for k in hoststatus.TASK_OUTCOMES}
        for rec in self.st.data["tasks"].values():
            if rec.get("status") in tasks and float(rec.get("updated", 0) or 0) >= since:
                tasks[rec["status"]] += 1
        return {
            "running": [{"slot": r.worker, "engine": getattr(r, "engine", "ghcp"), "model": getattr(r, "model", "?"),
                         "minutes": round((now - r.started) / 60)} for r in self.runs.values()],
            "machine": {} if s is None else {"cpu_pct": self.cpu_now, "commit_pct": s.commit_pct,
                                             "ram_free_gb": s.free_phys / resources.GB,
                                             "disk_free_gb": s.free_disk / resources.GB},
            "bus_state": self.bus_state, "channel": self.cfg.channel, "channel_state": self.channel_state,
            "model": self.default_model(), "ghcp_ok": self.ghcp_ok, "tasks": tasks, "pwsh": self.pwsh_version(),
        }

    def pwsh_version(self) -> str | None:
        """PowerShell 7's version, for the status (a zip install that Wazuh can't see, so monitoring needs it here).
        Asked once an hour; None if pwsh can't be found or run."""
        now = time.time()
        cached = getattr(self, "_pwsh", None)
        if cached is not None and now - cached[0] < 3600:
            return cached[1]
        # The bootstrap's pinned install first: a pwsh earlier on the account's PATH (a folder it can write) would
        # otherwise be run instead and make this field, which monitoring alerts on, report the wrong version
        # (u64-security, #humans 28988). PATH only when the pinned one is absent.
        exe = next((p for p in PWSH_PATHS if os.path.isfile(p)), None) or shutil.which("pwsh")
        version = None
        if exe:
            try:
                r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command",
                                    "$PSVersionTable.PSVersion.ToString()"], capture_output=True, text=True,
                                   timeout=60, stdin=subprocess.DEVNULL)
                out = r.stdout.strip()
                version = out if r.returncode == 0 and hoststatus.PWSH_RE.fullmatch(out) else None
            except (OSError, subprocess.TimeoutExpired):
                version = None
        self._pwsh = (now, version)
        return version

    def status_json(self) -> dict:
        return hoststatus.build(self.status_facts())

    def push_status_if_due(self) -> None:
        """The App's Hosts dashboard (section 1a): POST the v2 snapshot to the bus as this host, every minute and on a
        change (at most every 10 s). The heartbeat message is separate and unchanged. A refusal (404: an older bus;
        403: not yet marked as a host on the bus; another code: a contract mismatch) is logged once and retried hourly,
        so a host is ready before its bus is."""
        now = time.time()
        call = getattr(self.bus, "call", None)  # None: no bus, or a test's bus without raw calls (tests/conftest.py)
        if call is None or now < self.push_after or now - self.push_at < STATUS_PUSH_MIN_GAP:
            return
        snap = hoststatus.build_v2(self.status_facts())
        key = hoststatus.change_key(snap)
        if key == self.push_key and now - self.push_at < STATUS_PUSH_SECONDS:
            return
        self.push_at = now
        try:
            code, _ = call("POST", STATUS_PUSH_PATH, body=hoststatus.body(snap))
        except (BusError, OSError, ValueError) as e:  # the bus unreachable (shown by bus_state anyway), or over the cap
            self.log("status-push-failed", error=type(e).__name__)
            return
        if code in (200, 201, 204):
            self.push_key = key
            if self.push_refused is not None:
                self.log("status-push-ok", after=self.push_refused)
                self.push_refused = None
        elif code == 429:
            self.push_after = now + 60
        else:
            if self.push_refused != code:
                self.log("status-push-refused", status=code)
                self.push_refused = code
            self.push_after = now + STATUS_PUSH_BACKOFF

    def track_problem(self) -> None:
        """A `problem-raised` / `problem-cleared` line (and event, section 1b) when the status's problem code changes.
        Checked at most every 10 s, whatever the bus says."""
        now = time.time()
        if now - self.problem_checked < STATUS_PUSH_MIN_GAP:
            return
        self.problem_checked = now
        code = hoststatus.problem_of(self.status_facts())
        if code == self.problem_code:
            return
        if self.problem_code:
            self.log("problem-cleared", code=self.problem_code)
        if code:
            self.log("problem-raised", code=code)
        self.problem_code = code

    def push_events_if_due(self) -> None:
        """Send queued host events (section 1b) to the bus, up to 20 a call, at most every 5 s. The queue is on disk,
        so nothing is lost while the bus is away. A 400 means the batch can never be stored (a contract mismatch):
        it is dropped and logged, so it can't block the queue. 403 or 404 (an older bus, or not marked as a host
        yet): kept, retried hourly. 429: a minute."""
        queue = getattr(self.log, "events", None)
        call = getattr(self.bus, "call", None)
        now = time.time()
        if queue is None or call is None or now < self.events_after or now - self.events_at < EVENTS_MIN_GAP:
            return
        batch = queue.first(self.cfg.host_agent)
        if not batch:
            return
        self.events_at = now
        try:
            code, _ = call("POST", EVENTS_PATH, body=hostevents.body(self.cfg.host_agent, batch))
        except (BusError, OSError, ValueError) as e:
            self.log("host-events-failed", error=type(e).__name__)
            return
        if code in (200, 201, 204):
            queue.remove({e["id"] for e in batch})
            self.events_refused = None
        elif code in (400, 413):
            queue.remove({e["id"] for e in batch})
            self.log("host-events-dropped", status=code, events=len(batch))
        elif code == 429:
            self.events_after = now + 60
        else:
            if self.events_refused != code:
                self.log("host-events-refused", status=code)
                self.events_refused = code
            self.events_after = now + STATUS_PUSH_BACKOFF

    def status_if_changed(self) -> None:
        """Post the status at once when something the App shows changes (state, warnings, problem, update, engines'
        sign-in, fleet), at most every 30 seconds; otherwise it goes with the next heartbeat."""
        if self.bus is None or getattr(self, "status_key", None) is None:
            return  # nothing posted yet: the first status goes with the first heartbeat
        if time.time() - getattr(self, "status_posted_at", 0.0) < 30:
            return
        if hoststatus.change_key(self.status_json()) != getattr(self, "status_key", None):
            self.heartbeat()

    def heartbeat_if_due(self) -> None:
        if time.time() >= self.next_heartbeat:
            self.heartbeat()
        elif self.runs:
            # a worker started since the last beat: shorten the interval to the running cadence
            self.next_heartbeat = min(self.next_heartbeat, time.time() + 60 * self.cfg.heartbeat_running_minutes)

    def in_window(self) -> bool:
        now = datetime.now().strftime("%H:%M")
        return self.cfg.ghcp.window_start <= now < self.cfg.ghcp.window_end

    def update_ghcp(self) -> None:
        self.maintenance = True
        self.write_status()
        try:
            result = ghcp.update(self.cfg.copilot_exe, self.cfg.ghcp_backup_dir, self.cfg.ghcp.winget_id)
        finally:
            self.maintenance = False
        self.ghcp_version = result.after or self.ghcp_version
        self.ghcp_ok = result.ok
        self.st.data["last_ghcp_day"] = datetime.now().strftime("%Y-%m-%d")
        self.st.save()
        self.post("status", f"host={self.cfg.host_name} {result.line}")
        self.log("ghcp-update", ok=result.ok, before=result.before, after=result.after)

    def openbao_tick(self, force: bool = False) -> None:
        """Unauthenticated health check every [openbao] check_minutes. A change of state is logged and posted once,
        in fixed wording that security monitoring may match."""
        if self.openbao is None:
            return
        now = time.time()
        if not force and now < self.next_openbao_check:
            return
        self.next_openbao_check = now + 60 * self.cfg.openbao.check_minutes
        self.renew_leaf_if_due(now)
        try:
            self.bootstrap_tick(now)
        except Exception as e:  # noqa: BLE001 - self-enrolment never stops the host
            self.log.error("leaf-bootstrap-error", e)
        ok = self.openbao.health()
        if ok == self.openbao_ok:
            return
        self.openbao_ok = ok
        self.log("openbao-reachable" if ok else "openbao-unreachable")
        self.post("status", f"host={self.cfg.host_name} {OPENBAO_UP if ok else OPENBAO_DOWN}")

    def leaf_hours_left(self) -> float | None:
        end = openbao_mod.leaf_not_after(self.cfg.leaf_dir / openbao_mod.LEAF_CRT)
        return None if end is None else (end - time.time()) / 3600

    def renew_leaf_if_due(self, now: float) -> None:
        """Hourly; renews over mTLS when under 48 h are left. A failure is logged and retried next hour: the leaf
        lasts 72 h, so a long CA outage shows first as leaf=<hours> falling in the heartbeat."""
        if now < self.next_leaf_renew:
            return
        self.next_leaf_renew = now + 3600
        left = self.leaf_hours_left()
        if left is None or left >= openbao_mod.RENEW_BELOW_HOURS:
            return
        ob = self.cfg.openbao
        try:
            chain = openbao_mod.renew_leaf(ob.ca_url, ob.ca or self.cfg.bus_ca, self.cfg.leaf_dir)
            openbao_mod.write_leaf(self.cfg.leaf_dir, chain)
            self.leaf_renew_failing = False
            self.log("leaf-renewed", hours_left=round(self.leaf_hours_left() or 0))
        except OSError as e:
            self.leaf_renew_failing = True
            self.log("leaf-renew-failed", status=getattr(e, "status", 0), what=getattr(e, "what", type(e).__name__),
                     hours_left=round(left))

    # --- S11 self-enrolment: ask for a token, enrol with the one that arrives in the drop -------------------
    @property
    def leaf_san(self) -> str:
        """This host's leaf name: the one on the leaf it holds (an expired leaf still names it), else
        <prefix>.<openbao.san_domain>, else "" (no leaf and no domain: it cannot ask for one)."""
        held = openbao_mod.leaf_san(self.cfg.leaf_dir / openbao_mod.LEAF_CRT)
        if held:
            return held[0]
        domain = getattr(self.cfg.openbao, "san_domain", "")
        return f"{self.cfg.openbao_prefix}.{domain}" if domain else ""

    def post_leaf(self, text: str) -> bool:
        """One line in the leaf channel (subscribed once). Fixed wording; security monitoring may pair these."""
        if self.bus is None:
            return False
        ch = self.cfg.openbao.leaf_channel
        try:
            if not self.leaf_subscribed:
                self.bus.call("PUT", "/api/subscriptions/" + ch)
                self.leaf_subscribed = True
            self.bus.post(ch, "status", text)
            return True
        except (BusError, OSError, ValueError) as e:
            self.log("leaf-post-failed", status=getattr(e, "status", 0))
            return False

    def bootstrap_tick(self, now: float) -> None:
        if not self.leaf_san:
            if not getattr(self, "_warned_no_san", False):
                self._warned_no_san = True
                self.log("leaf-no-name", hint="no leaf and no [openbao] san_domain: run setup\\30-openbao.ps1 -San")
            return
        drop = Path(self.cfg.openbao.bootstrap_dir)
        token_file = drop / f"{self.leaf_san}.token"
        if self.leaf_issued_unposted and self.post_leaf(f"leaf-issued san={self.leaf_san}"):
            self.leaf_issued_unposted = False
        if token_file.is_file():
            self.enrol_from_drop(token_file)
            return
        left = self.leaf_hours_left()
        self.sync_needed_file(drop, valid=left is not None and left > 0)
        need = left is None or left <= 0 or (left < self.cfg.openbao.ask_below_hours and self.leaf_renew_failing)
        # No leaf_authority: nobody on the bus mints tokens at this site, so the host asks by file only.
        if need and now >= self.next_leaf_ask and self.cfg.openbao.leaf_authority:
            ob = self.cfg.openbao
            if self.post_leaf(f"@{ob.leaf_authority} leaf-needed san={self.leaf_san}"):
                self.next_leaf_ask = now + 3600  # a token minter gives at most one per SAN per hour anyway
                self.log("leaf-needed", san=self.leaf_san, hours_left=-1 if left is None else round(left))

    def sync_needed_file(self, drop: Path, valid: bool) -> None:
        """<san>.needed asks the token minter by file when the host cannot ask on the bus (a rebuild, or a leaf that
        lapsed while the host was off: no leaf means no bus identity from OpenBao). It exists exactly while the host
        holds no valid leaf; its content is a timestamp only."""
        needed = drop / f"{self.leaf_san}.needed"
        try:
            if valid and needed.exists():
                needed.unlink()
                self.log("leaf-needed-file-removed", san=self.leaf_san)
            elif (not valid and (self.bus is None or not self.cfg.openbao.leaf_authority) and not needed.exists()
                  and drop.is_dir()):
                # Only when it cannot (or, with no leaf_authority, does not) ask on the bus: one request per lapse,
                # so the token minter's hourly limit never sees the same need twice.
                needed.write_text(datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z") + "\n", encoding="ascii")
                self.log("leaf-needed-file", san=self.leaf_san)
        except OSError as e:
            self.log("leaf-needed-file-failed", error=type(e).__name__)

    def enrol_from_drop(self, token_file: Path) -> None:
        """A new key and CSR, the token from the drop (read, then deleted at once), /1.0/sign, then the new key and
        leaf replace the old ones together. On any failure the old key and leaf stay; the next ask is an hour on."""
        from . import leafkey

        arrived = datetime.fromtimestamp(token_file.stat().st_mtime).strftime("%Y-%m-%dT%H:%M:%S")
        self.log("leaf-token-arrived", san=self.leaf_san, at=arrived)
        try:
            token = token_file.read_text(encoding="ascii").strip().splitlines()[0].strip()
        except (OSError, UnicodeDecodeError, IndexError):
            token = ""
        finally:
            try:
                token_file.unlink()
                self.log("leaf-token-deleted", san=self.leaf_san)
            except OSError as e:
                self.log("leaf-token-delete-failed", error=type(e).__name__)
        if token.count(".") != 2:
            self.log("leaf-token-unusable", san=self.leaf_san)
            return
        leaf = self.cfg.leaf_dir
        leaf.mkdir(parents=True, exist_ok=True)
        new_key = leaf / (openbao_mod.LEAF_KEY + ".new")
        ob = self.cfg.openbao
        try:
            csr = leafkey.new_key_and_csr(self.leaf_san, new_key)
            chain = openbao_mod.sign_leaf(ob.ca_url, ob.ca or self.cfg.bus_ca, csr, token, f"{ob.leaf_hours}h")
        except OSError as e:
            new_key.unlink(missing_ok=True)
            self.log("leaf-enrol-failed", status=getattr(e, "status", 0), what=getattr(e, "what", type(e).__name__))
            return
        finally:
            del token
        os.replace(new_key, leaf / openbao_mod.LEAF_KEY)
        openbao_mod.write_leaf(leaf, chain)
        self.leaf_renew_failing = False
        self.next_leaf_renew = 0.0
        self.log("leaf-issued", san=self.leaf_san, hours_left=round(self.leaf_hours_left() or 0))
        self.sync_needed_file(token_file.parent, valid=True)
        if not self.post_leaf(f"leaf-issued san={self.leaf_san}"):
            self.leaf_issued_unposted = True  # no bus yet (a rebuild): posted once the host is connected

    def spn_rotate_tick(self, now: float) -> None:
        """Hourly; in the hour after [update] window (local), rotate the SPN when spn_rotate_days have passed. With
        no rotation on record the clock starts now (a first deployment never rotates at once)."""
        days = self.cfg.openbao.spn_rotate_days
        if self.openbao is None or not days or now < self.next_spn_check:
            return
        self.next_spn_check = now + 3600
        store = self.store
        last = store.spn_rotated_at()
        if last is None:
            store.save_spn(store.load_spn(), rotated_at=now)
            self.log("spn-rotation-clock-started", days=days)
            return
        local = datetime.now()
        start = datetime.strptime(self.cfg.update.window, "%H:%M").replace(year=local.year, month=local.month,
                                                                           day=local.day)
        if not (start <= local < start + timedelta(hours=1)) or now - last < days * 86400:
            return
        result = rotate_spn_now(self.cfg, store, self.log)
        if result == "lost":
            self.post("status", f"host={self.cfg.host_name} spn-rotation-failed: the successor could not be stored; "
                                f"the SPN must be rotated from the operator console")
        elif result == "rotated":
            self.post("status", f"host={self.cfg.host_name} spn-rotated")

    def next_windows_restart(self, local: datetime) -> datetime:
        """When Windows may next restart for updates: [update] windows_restart today, or tomorrow once today's restart
        window (it runs to 08:00 with 20-policy's active hours) is over. Inside the window: now."""
        at = datetime.strptime(self.cfg.update.windows_restart, "%H:%M").replace(
            year=local.year, month=local.month, day=local.day)
        if local < at:
            return at
        if local < at + timedelta(hours=5):
            return local
        return at + timedelta(days=1)

    def restart_blocks_claims(self, local: datetime | None = None) -> bool:
        """While a restart is expected, refuse a task that could still be running at it (now + max_runtime_hours).
        Unknown (None) does not block: a failed Windows Update query must not stop the host taking work."""
        if not self.restart_pending:
            return False
        local = local or datetime.now()
        return local + timedelta(hours=self.cfg.runtime.max_runtime_hours) > self.next_windows_restart(local)

    def restart_tick(self, force: bool = False) -> None:
        """Hourly: ask Windows whether it will restart for updates. A change is logged; the heartbeat carries it."""
        now = time.time()
        if not force and now < self.next_restart_check:
            return
        self.next_restart_check = now + 3600
        from . import winupdate
        expected = winupdate.restart_expected()
        if expected is None and self.restart_pending is not None:
            return  # one failed query: keep the last answer
        if expected != self.restart_pending:
            self.log("restart-pending" if expected else "restart-clear" if expected is False else "restart-unknown")
        self.restart_pending = expected

    def maintain(self) -> None:
        try:
            self.spn_rotate_tick(time.time())
        except Exception as e:  # noqa: BLE001 - a failed rotation check never stops the host
            self.log.error("spn-rotate-error", e)
        try:
            self.restart_tick()
        except Exception as e:  # noqa: BLE001 - a failed Windows Update query never stops the host
            self.log.error("restart-check-error", e)
        self.openbao_tick()
        self.refresh_fleet()
        try:
            self.update_tick()
        except Exception as e:  # noqa: BLE001 - a failed update step never stops the host
            self.log.error("update-error", e)
        now = time.time()
        idle = not self.runs and not self.pending
        if self.update_when_idle and idle:
            self.update_when_idle = False
            self.update_ghcp()
        today = datetime.now().strftime("%Y-%m-%d")
        if (self.in_window() and self.st.data.get("last_ghcp_day") != today
                and now - self.st.data.get("ghcp_attempt", 0) >= 60 * self.cfg.ghcp.retry_minutes):
            self.st.data["ghcp_attempt"] = now
            if idle:
                self.update_ghcp()
            else:
                self.log("ghcp-deferred", reason="workers-running")
        if now - self.st.data.get("last_cleanup", 0) >= 3600 * self.cfg.cleanup.sweep_hours:
            self.st.data["last_cleanup"] = now
            self.run_cleanup()

    # --- self-update (workerhost/update.py; design.md section 10a) -----------------------------------------
    HEALTHY_SECONDS = 180  # the new code has run this long with the bus reachable: the update is done

    def save_update_state(self) -> None:
        update_mod.save_state(self.update_file, self.ustate)

    def mentions(self) -> str:
        return " ".join(f"@{p.agent_name}" for p in self.coordinators())

    def announce(self, text: str) -> None:
        """On the announce channel, which every coordinator watches, and as status on the host channel."""
        channel = self.cfg.update.announce_channel
        if self.bus is not None:
            try:
                if not self.st.data.get("announce_subscribed"):
                    self.bus.call("PUT", "/api/subscriptions/" + channel)
                    self.st.data["announce_subscribed"] = True
                self.bus.post(channel, "announce", text)
            except (BusError, OSError, ValueError) as e:
                self.log("announce-failed", channel=channel, error=getattr(e, "status", type(e).__name__))
        self.post("status", f"host={self.cfg.host_name} {text}", queue=False)

    def fetch_release_source(self) -> bool:
        """Bring the release source up to date. The fleet mirror is fetched by the fleet refresh (and again in bus
        mode, where the fleet came from the bus). A release repository of its own is fetched here; if it cannot be
        reached the host stays on what it has and says so, never falling back to the old source (security review, rule d)."""
        self.refresh_fleet(force=True)
        w = self.release_where
        if w.origin == "fleet":
            if self.cfg.fleet_source == "bus":
                self.fleet_sync.fetch_mirror()
            self.release_unreachable = False
            return True
        ok = update_mod.fetch_release_mirror(self.cfg.git_exe, update_mod.mirror_for(self.cfg.release_mirrors_dir, w.url),
                                             w.url)
        if not ok and not self.release_unreachable:
            self.log("release-source-unreachable", source=w.label(), origin=w.origin)
        self.release_unreachable = not ok
        return ok

    def update_check(self, announce: bool = True):
        """Fetch, read and verify release.toml; when it is newer than what is installed (and not a release this host
        rolled back from), announce it and stop taking tasks (phase "announced")."""
        if not self.fetch_release_source():
            return None
        rel, status = self.release_source.read()
        inst = update_mod.installed(self.app_dir)
        if rel is None:
            self.log("update-check", status=status, installed=inst["version"])
            return None
        if not update_mod.redirect_allowed(rel, self.cfg.remotes):
            # A signed redirect outside this host's [remotes] fence: not applied, so never recorded.
            self.log("update-check", status="release-redirect-refused", release=rel.version, serial=rel.serial,
                     to=rel.moved_to[0])
            return None
        newer = update_mod.is_newer(rel, inst)
        rejected = rel.serial in self.ustate.get("rejected", [])
        self.log("update-check", status=status, release=rel.version, serial=rel.serial, installed=inst["version"],
                 newer=newer, rejected=rejected)
        if not (newer and announce and self.cfg.update.enabled) or rejected:
            return rel
        if rel.needs_install:
            if self.ustate.get("manual_posted") != rel.serial:
                self.ustate["manual_posted"] = rel.serial
                self.save_update_state()
                self.announce(f"{self.mentions()} release {rel.version} needs install.ps1 run by hand on host "
                              f"{self.cfg.host_name}: it is not applied automatically.".strip())
            return rel
        self.ustate.update(phase="announced", serial=rel.serial, version=rel.version, commit=rel.commit,
                           from_version=inst["version"], announced_at=time.time())
        self.save_update_state()
        u = self.cfg.update
        if self.update_now:
            self.announce(f"{self.mentions()} host {self.cfg.host_name} updates from {inst['version']} to "
                          f"{rel.version} as soon as no worker is running (started by hand); no new tasks until "
                          f"then.".strip())
        else:
            self.announce(update_mod.announcement(self.cfg.host_name, rel, inst["version"], u.window, u.grace_minutes,
                                                  [p.agent_name for p in self.coordinators()]))
        return rel

    def update_tick(self) -> None:
        u = self.cfg.update
        phase = self.ustate.get("phase", "")
        if phase == "applied" and time.time() - self.started_at >= self.HEALTHY_SECONDS and self.bus_state == "ok":
            self.ustate.update(phase="done", done_at=time.time())
            self.save_update_state()
            self.log("update-done", version=self.ustate.get("version"))
            self.announce(f"{self.mentions()} host {self.cfg.host_name} updated from "
                          f"{self.ustate.get('from_version', '?')} to {self.ustate.get('version', '?')}; taking tasks "
                          f"again.".strip())
            return
        if phase == "rolled-back" and not self.ustate.get("reported"):
            self.ustate["reported"] = True
            self.save_update_state()
            self.announce(f"{self.mentions()} host {self.cfg.host_name}: the update to {self.ustate.get('version')} "
                          f"failed (the new code kept stopping) and was rolled back to "
                          f"{self.ustate.get('from_version', '?')}; that release is not retried here.".strip())
            return
        if phase == "announced" and not u.enabled:
            self.ustate["phase"] = "cancelled"
            self.save_update_state()
            return
        busy = bool(self.runs or self.pending)
        if self.update_now and phase == "announced":
            if not busy:
                self.apply_update()
            return
        if not u.enabled:
            return
        now = update_mod.now_local()
        action = update_mod.decide(now, u.check_at, u.window, u.grace_minutes, self.ustate, busy)
        if action == "check":
            self.ustate["checked_for"] = update_mod.window_key(now, u.check_at, u.window)
            self.save_update_state()
            self.update_check(announce=True)
        elif action == "apply":
            self.apply_update()
        elif action == "stop-and-apply":
            self.stop_for_update()
            self.apply_update()
        elif action == "give-up":
            self.ustate["phase"] = "missed"
            self.save_update_state()
            self.log("update-missed", version=self.ustate.get("version"))
            self.post("status", f"host={self.cfg.host_name} update to {self.ustate.get('version')} missed tonight's "
                                f"window; taking tasks again (the next check announces it again)", queue=False)

    def stop_for_update(self) -> None:
        """Workers still running at the end of the grace period: push their work to their branch (as a timeout does),
        stop them, and mark them to be resumed once after the restart (recover() sees update_stop)."""
        for task_id, run in list(self.runs.items()):
            run.kill()
            run.poll()
            wip = self.save_wip(task_id, run, "update") or {}
            self.st.set_task(task_id, update_stop=True)
            self.log("update-stopped-worker", task_id=task_id, worker=run.worker, pushed=wip.get("pushed", "-"))
            self.runs.pop(task_id, None)
            try:
                run.job.close()
            except Exception:  # noqa: BLE001
                pass
        self.st.save()

    def apply_update(self) -> None:
        rel, status = self.release_source.read()  # read and verified again, now
        inst = update_mod.installed(self.app_dir)
        if rel is None or not update_mod.is_newer(rel, inst) or rel.needs_install:
            self.update_failed(rel, status if rel is None else "not-newer")
            return
        try:
            files = self.release_source.files(rel)
        except update_mod.ReleaseError as e:
            self.update_failed(rel, e.reason, e.detail)
            return
        staging = self.cfg.home / "app.new"
        if staging.exists():
            remove_tree(staging)
        update_mod.write_files(files, staging)
        python = self.cfg.python_exe or sys.executable
        ok, detail = update_mod.run_selftest(python, staging, self.cfg.home)
        if not ok:
            self.update_failed(rel, "selftest", detail)
            return
        for task_id, p in list(self.pending.items()):
            if p.session.claim_seq is not None:
                p.session.yield_("update")
            self.drop_pending(task_id, "yielded")
        update_mod.apply_files(files, self.app_dir, self.cfg.home / "app.prev", rel)
        remove_tree(staging)
        self.ustate.update(phase="applied", serial=rel.serial, version=rel.version, commit=rel.commit,
                           from_version=inst["version"], applied_at=time.time(), failures=0)
        self.save_update_state()
        self.log("update-applied", version=rel.version, previous=inst["version"])
        self.post("status", f"host={self.cfg.host_name} updating from {inst['version']} to {rel.version}; "
                            f"restarting now", queue=False)
        self.exit_code = update_mod.EXIT_UPDATE

    def update_failed(self, rel, reason: str, detail: str = "") -> None:
        version = rel.version if rel is not None else self.ustate.get("version", "?")
        self.log("update-failed", version=version, reason=reason, detail=detail[:200] or "-")
        if rel is not None and reason not in ("not-newer",):
            rejected = self.ustate.setdefault("rejected", [])
            if rel.serial not in rejected:
                rejected.append(rel.serial)
        self.ustate["phase"] = "failed"
        self.save_update_state()
        if reason != "not-newer":
            self.announce(f"{self.mentions()} host {self.cfg.host_name}: the update to {version} was not applied "
                          f"({reason}); still on {update_mod.installed(self.app_dir)['version']}, taking tasks "
                          f"again.".strip())
        if any(rec.get("update_stop") for rec in self.st.data["tasks"].values()
               if rec.get("status") == "started"):
            self.recover()  # workers stopped for this update: report them and resume them now

    def finished_workers(self) -> set[str]:
        """Workers whose most recent task finished with exit 0 and whose clone was cleaned after it."""
        latest: dict[str, dict] = {}
        for rec in self.st.data["tasks"].values():
            w = rec.get("worker")
            if isinstance(w, str) and rec.get("updated", 0) >= latest.get(w, {}).get("updated", 0):
                latest[w] = rec
        return {w for w, rec in latest.items() if rec.get("status") == "finished" and rec.get("cleaned") is True}

    def run_cleanup(self, dry_run: bool = False, disk_pressure: bool = False, budget: bool = True) -> dict:
        """budget=False only when no host loop is waiting on it (`wh cleanup` with the host not running)."""
        in_use = {r.worker for r in self.runs.values()} | {p.task["worker"] for p in self.pending.values()}
        retry = set(self.st.data.get("delete_failed", []))
        report = cleanup.daily(Path(self.cfg.workers_root), self.cfg.logs_dir, self.cfg.salvage_dir, self.cfg.cleanup,
                               in_use, self.cfg.git_exe, self.cfg.gh_exe, dry_run=dry_run, disk_pressure=disk_pressure,
                               finished=self.finished_workers(), retry=retry,
                               budget_seconds=60 * self.cfg.cleanup.sweep_budget_minutes if budget else None)
        if report["deferred"] and not dry_run:
            # Out of time with candidates left (a backlog): the next sweep comes in 15 minutes, not sweep_hours.
            self.st.data["last_cleanup"] = time.time() - 3600 * self.cfg.cleanup.sweep_hours + 900
        if not dry_run:
            root = Path(self.cfg.workers_root)

            def names(key: str) -> set[str]:
                return {i.split(":", 1)[1] for i in report[key] if i.startswith("clone:")}
            swept = dict(h.split(":", 1) for h in report["held"])
            # Clones the sweep did not look at (not idle long enough) keep the reason end() gave them.
            held = {w: r for w, r in self.held_reasons().items()
                    if w not in swept and w not in names("deleted") and (root / w).exists()}
            held.update(swept)
            self.st.data["held_reasons"] = held
            self.st.data["held_clones"] = sorted(held)
            self.st.data["delete_failed"] = sorted(w for w in (retry - names("deleted")) | names("failed")
                                                   if (root / w).exists())
            self.st.data["strays"] = report["strays"]
            self.st.save()
        for key in ("deleted", "held", "would_delete", "failed"):
            for item in report[key]:
                self.log("cleanup", action=key, item=item)
        self.log("cleanup-done", clones=report["clones"], held=len(report["held"]), deleted=len(report["deleted"]),
                 failed=len(report["failed"]), strays=len(report["strays"]), deferred=report["deferred"],
                 dry_run=dry_run)
        return report

    def held_reasons(self) -> dict[str, str]:
        """{worker: why its clone is held}; state from before reasons were kept has only the names."""
        reasons = self.st.data.get("held_reasons")
        if isinstance(reasons, dict):
            return dict(reasons)
        return {w: "held" for w in self.st.data.get("held_clones", [])}

    def clones_on_disk(self) -> int:
        """Folders under the workers root with `.git`, counted fresh (the count is what is on disk,
        not what the ledger remembers)."""
        try:
            return len(cleanup.worker_dirs(Path(self.cfg.workers_root))[0])
        except OSError:
            return -1

    def handle_control(self, c: dict) -> None:
        cmd, args = c["cmd"], c.get("args", {})
        self.log("control", cmd=cmd)
        d = self.st.data
        if cmd == "stop":
            self.stop_now()
        elif cmd == "drain":
            d["draining"] = True
            for task_id, p in list(self.pending.items()):
                if p.session.claim_seq is not None:
                    p.session.yield_("draining")
                self.drop_pending(task_id, "yielded")
        elif cmd == "pause":
            d["paused"] = True
        elif cmd == "resume":
            d["paused"] = False
        elif cmd == "status":
            self.heartbeat()
        elif cmd == "set-model" and self.model_allowed(args.get("model")):
            d["default_model"] = args["model"]
        elif cmd == "cleanup":
            self.run_cleanup(dry_run=bool(args.get("dry_run")))
        elif cmd == "fleet-refresh":
            out = self.refresh_fleet(force=True)
            self.log("fleet-refresh", status=out.status if out else "-")
        elif cmd == "update-check":
            self.update_check(announce=False)
        elif cmd == "update-now":
            # "update now": a newer signed release is announced and applied as soon as no worker runs.
            self.update_now = True
            self.update_check(announce=True)
        elif cmd == "update-ghcp":
            if args.get("when_idle"):
                self.update_when_idle = True
            elif self.runs or self.pending:
                self.log("ghcp-refused", reason="workers-running")
            else:
                self.update_ghcp()
        self.st.save()

    def stop_now(self) -> None:
        for task_id, run in list(self.runs.items()):
            run.kill()
            run.poll()
            wip = self.save_wip(task_id, run, "kill") or {}
            self.st.mark_terminal(task_id, "interrupted", by_stop=True, cause="stop", exit_code=-1)
            run.session.post("interrupted", worker=run.worker, cause="stop", **wip)
            self.end(task_id, run, "interrupted", -1)
        for task_id, p in list(self.pending.items()):
            if p.session.claim_seq is not None:
                p.session.yield_("stopping")
            self.drop_pending(task_id, "yielded")
        self.stopped("stop")

    def stopped(self, why: str) -> None:
        self.st.data["enabled"] = False
        self.st.data["draining"] = False
        self.st.save()
        self.post("status", f"host={self.cfg.host_name} stopped ({why})", queue=False)
        self.log("stopped", why=why)
        self.exit_code = 0

    def _release_status(self) -> dict:
        """The installed release, and a newer one this host has announced (waiting for its window or for idle)."""
        inst = update_mod.installed(self.app_dir)
        out = {"release": {"version": inst["version"], "serial": inst["serial"]}}
        if self.ustate.get("phase") == "announced":
            out["update"] = {"version": self.ustate.get("version", "?"),
                             "when": "as soon as idle" if self.update_now else self.cfg.update.window}
        return out

    def write_status(self) -> None:
        now = time.time()
        workers = [{"worker": r.worker, "task_id": t, "model": getattr(r, "model", "?"),
                    "minutes": round((now - r.started) / 60), "log": str(r.log)} for t, r in self.runs.items()]
        s = self.sample
        status = {
            "pid": os.getpid(), "updated": now, "state": self.reported_state(), "workers": workers,
            "claims": [p.task["worker"] for p in self.pending.values()],
            "paused": bool(self.st.data["paused"]), "game_paused": self.game_paused,
            "draining": bool(self.st.data["draining"]), "channel": self.cfg.channel, "channel_state": self.channel_state,
            "bus_state": self.bus_state, "model": self.default_model(), "ghcp": self.ghcp_version,
            "models": {"default": self.cfg.default_model, "allowed": list(self.cfg.allowed_models),
                       "denied": list(self.cfg.denied_models)},
            "ghcp_ok": self.ghcp_ok,
            "held_clones": self.st.data.get("held_clones", []), "held_reasons": self.held_reasons(),
            "strays": self.st.data.get("strays", []), "outbox": len(self.st.data["outbox"]),
            "cpu_pct": None if self.cpu_now is None else round(self.cpu_now, 1),
            "resources": None if s is None else {"commit_pct": round(s.commit_pct, 1),
                                                 "ram_free_gb": round(s.free_phys / resources.GB, 1),
                                                 "disk_free_gb": round(s.free_disk / resources.GB, 1)},
            "heartbeat_line": self.heartbeat_line(),
            **self._release_status(),
            "fleet": {"state": self.fleet_status, "label": self.fleet.label if self.fleet else None,
                      "coordinators": [c.agent_name for c in self.fleet.coordinators] if self.fleet else
                      [p.agent_name for p in self.coordinators()],
                      "hosts": [h.agent_name for h in self.pinned_hosts()]},
        }
        atomic_write_json(self.cfg.state_dir / "status.json", status)

    # --- main loop ----------------------------------------------------------------------------
    def tick(self) -> None:
        for c in take_controls(self.cfg.control_dir):
            self.handle_control(c)
            if self.exit_code is not None:
                return
        self.reload_models()
        self.refresh_sample()
        self.poll()
        self.do_resumes()
        self.advance_claims()
        self.supervise()
        self.flush_outbox()
        self.heartbeat_if_due()
        self.status_if_changed()
        self.push_status_if_due()
        self.track_problem()
        self.push_events_if_due()
        self.maintain()
        if self.st.data["draining"] and not self.runs and not self.pending:
            self.stopped("drain")
        if self.st.data.get("drain_to_pause") and not self.runs and not self.pending:
            self.st.data["drain_to_pause"] = False  # drained: stays running and paused (a remote drain)
            self.st.save()
            self.log("drained", left="paused")

    def run(self, max_seconds: float | None = None) -> int:
        """The main loop. A caught error is logged with its type, message and traceback (errors file);
        anything that escapes is logged the same way as `fatal` before the process exits non-zero,
        which is what makes `wh supervise` restart it."""
        try:
            return self._serve(max_seconds)
        except BaseException as e:  # noqa: BLE001 - logged, then re-raised: never a silent exit
            self.log.error("fatal", e)
            raise

    def _serve(self, max_seconds: float | None) -> int:
        name = "StrugglebusWorkerHost-" + hashlib.sha256(str(self.cfg.home).lower().encode()).hexdigest()[:12]
        mutex = None
        for prefix in ("Global\\", "Local\\"):
            try:
                mutex = winapi.single_instance(prefix + name)
                break
            except OSError:
                continue
        if mutex is None:
            self.log("already-running")
            return 3
        if not self.st.data.get("enabled", True):
            self.log("disabled", hint="wh start")
            return 0
        self.ghcp_version = ghcp.version(self.cfg.copilot_exe)
        self.ghcp_ok = None if self.ghcp_version else False
        self.log("host-start", host=self.cfg.host_name, channel=self.cfg.channel, ghcp=self.ghcp_version or "?")
        if self.release_where.refused:
            self.log("release-redirect-refused", to=self.release_where.refused, using="fleet",
                     reason="outside-remotes-allowed")
        self.connect()
        self.check_models_at_start()
        self.recover()
        deadline = time.time() + max_seconds if max_seconds else None
        while self.exit_code is None:
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001 - one bad loop must not kill supervision
                self.log.error("loop-error", e)
            self.write_status_safely()
            if deadline and time.time() >= deadline:
                self.log("host-exit", why="max-seconds")
                break
            time.sleep(1)
        self.write_status_safely()
        return self.exit_code or 0

    def write_status_safely(self) -> None:
        """status.json is a convenience for `wh status`; failing to write it (the file held open by a
        reader past the retries) is logged and the loop goes on."""
        try:
            self.write_status()
        except Exception as e:  # noqa: BLE001
            self.log.error("status-error", e)


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0
