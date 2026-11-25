"""Configuration: one TOML file in the host's home folder (read with the standard library's tomllib).

The home folder is %LOCALAPPDATA%\\strugglebus-worker-host unless WORKERHOST_HOME points elsewhere
(the installer's -Home switch, used for dry runs into a temporary folder).
"""
from __future__ import annotations

import os
import re
import socket
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import engines as engines_mod
from . import models as models_mod
from . import urls

INSTALL_DIR = Path(__file__).resolve().parent.parent

NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
# The bus lets an SPN create only agents named <SPN name>-*, so agent_prefix must equal the SPN's name.
PREFIX_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,30}")
HOST_SUFFIX = "host"
# The owner's name as workers' preamble says it ("run by <coordinator> for <owner>"): fleet.toml's signed `owner`, or,
# before the first signed fleet, config.toml's [coordinator] owner. Plain text only, never a "{placeholder}".
OWNER_RE = re.compile(r"[A-Za-z][A-Za-z0-9 .'-]{0,39}")
# A release's folder in its repository ("" = the top level): relative, plain segments, never "." or "..".
RELEASE_PATH_RE = re.compile(r"(?:(?!\.\.?(?:/|$))[A-Za-z0-9_.-]{1,64}(?:/(?!\.\.?(?:/|$))[A-Za-z0-9_.-]{1,64}){0,7})?")
CHANNEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def agent_name(prefix: str, short: str) -> str:
    """The one place bus identity names are derived: <agent_prefix>-host, <agent_prefix>-<worker>."""
    if not PREFIX_RE.fullmatch(prefix or ""):
        raise ValueError("agent_prefix must match [a-z0-9][a-z0-9-]{1,30} (the SPN's name)")
    return f"{prefix}-{short}"


def home_dir() -> Path:
    override = os.environ.get("WORKERHOST_HOME")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "strugglebus-worker-host"


def default_host_name() -> str:
    raw = (os.environ.get("COMPUTERNAME") or socket.gethostname() or "host").lower()
    name = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")[:31] or "host"
    return name if NAME_RE.fullmatch(name) else "host"


@dataclass
class Resources:
    max_workers: int = 2
    max_commit_pct: float = 80.0
    min_free_ram_gb: float = 6.0
    worker_commit_gb: float = 8.0
    min_free_disk_gb: float = 40.0
    guard_commit_pct: float = 85.0
    guard_free_gb: float = 6.0


@dataclass
class Runtime:
    max_runtime_hours: float = 6.0
    stall_minutes: float = 45.0
    resume_after_reboot: bool = True
    task_wait_timeout_seconds: int = 3600


@dataclass
class Cleanup:
    log_retention_days: int = 14
    host_log_days: int = 30
    idle_clone_days: float = 7
    finished_clone_hours: float = 12
    sweep_hours: float = 6
    sweep_budget_minutes: float = 5
    salvage_days: int = 30
    salvage_cap_mb: int = 50
    pytest_temp_days: int = 2


@dataclass
class Ghcp:
    window_start: str = "04:00"
    window_end: str = "06:00"
    winget_id: str = "GitHub.Copilot"
    retry_minutes: int = 30


@dataclass
class Update:
    # Self-update from signed releases (workerhost/update.py). Local times. These move to the signed baseline.toml
    # once it exists (agent-host-build.md section 9).
    enabled: bool = True
    check_at: str = "01:00"       # fetch, announce a newer release, stop taking tasks
    window: str = "03:00"         # apply when no worker is running
    grace_minutes: float = 30     # then save running workers' work, stop them, apply, resume them after
    announce_channel: str = "announce"
    # When Windows installs updates and restarts (setup\20-policy: daily at 03:00). While updates that need a restart
    # are waiting, the host takes no task that could still be running then (agent-host-build.md 9.2).
    windows_restart: str = "03:00"


@dataclass
class OpenBao:
    # Host secrets in OpenBao (docs/openbao-design.md). Off: the DPAPI creds store, exactly as before.
    enabled: bool = False
    url: str = ""                 # https://<host>[:port]; needed once enabled (site.toml [openbao])
    mount: str = "agents"         # KV v2
    prefix: str = ""              # default: agent_prefix (= the leaf SAN's host part and the SPN's name)
    role: str = ""                # cert auth role; default: the prefix
    ca: str = ""                  # default: bus_ca (the LAN root)
    leaf_dir: str = ""            # default: <home>\leaf (leaf.crt, leaf.key; owner-only)
    check_minutes: float = 1.0    # how often an unauthenticated health check runs
    ca_url: str = ""              # step-ca: first issue (one-time token) and hourly renewal (mTLS); needed once enabled
    leaf_hours: int = 72          # the validity asked for at first issue (the provisioner's maximum); renewals keep it
    # The DNS domain of the host's leaf, <prefix>.<san_domain>. Only needed while the host holds no leaf at all (its
    # first one, or after the leaf folder is lost): otherwise the name on the leaf it holds is used.
    san_domain: str = ""
    # Self-enrolment (S11): with no leaf, or under ask_below_hours left and renewal failing, the host asks
    # leaf_authority in leaf_channel for a one-time token, at most hourly; the token arrives over SFTP (user sbdrop,
    # setup 25-access -HostUser) as <bootstrap_dir>\<san>.token, and the host enrols with it and deletes it.
    bootstrap_dir: str = r"C:\ProgramData\strugglebus\bootstrap"
    leaf_channel: str = "security"
    leaf_authority: str = ""      # the agent that mints one-time tokens; "": ask only by file (<san>.needed)
    ask_below_hours: float = 6.0
    # Phase 2 (bus 0.2.61; docs/openbao-design.md section 3): one bus identity per task attempt,
    # <prefix>-<worker>-<yymmdd><n>, with a TTL of max_runtime_hours + 1 h (cap 12 h), retired by the SPN when the task
    # ends. Off: one durable identity per worker name (phase 1).
    ttl_identities: bool = False
    # SPN self-rotation in the nightly window ([update] window, local time), every spn_rotate_days; 0 turns it off.
    # The successor is written to OpenBao inside the bus's 60 s overlap, then read back.
    spn_rotate_days: int = 30


@dataclass
class Config:
    host_name: str
    # Required in config.toml (load() refuses a file without it); "" here is never a valid prefix.
    agent_prefix: str = ""
    channel: str = "worker-hosts"
    poll_seconds: float = 10.0
    settle_seconds: float = 20.0
    workers_root: Path = Path(r"C:\sb-workers")
    bus_url: str = ""  # the site's StruggleBus (site.toml); `wh probe` fails while it is unset
    bus_ca: str = ""
    copilot_exe: str = "copilot"
    gh_exe: str = "gh"
    git_exe: str = "git"
    python_exe: str = ""
    vault_repo: str = ""  # before the first signed fleet only: the pinned coordinator's notes repository (owner/repo)
    vault_url: str = ""
    # fleet.toml (signed): fetched from this repository's main every fleet_refresh_minutes. "": no fleet, no
    # self-update (both come from it); the host runs on config.toml's [coordinator] pin alone.
    fleet_repo: str = ""
    fleet_url: str = ""
    fleet_refresh_minutes: float = 15.0
    # Where the signed fleet comes from: "git" (fleet_repo), "bus" (the bus's site-document store, published by the
    # App) or "either" (the bus first). Every copy is checked the same way, so the source never decides trust.
    fleet_source: str = "git"
    # Where self-update reads release.toml and the code. Empty: the fleet mirror, as
    # before, unless the installed release recorded a signed redirect (moved_to). release_path: the code's folder in
    # that repository ("" = its top level). Set by hand only to override; the signed redirect is the normal way.
    release_repo: str = ""
    release_url: str = ""
    release_path: str = ""
    ssh_keygen_exe: str = ""  # empty: Win32-OpenSSH, then Windows' own, then Git's (signing.KEYGEN_CANDIDATES)
    messages_mutable: bool = False
    # True when the host runs under a Windows account made for it alone (install.ps1 / the App's bootstrap). False: it
    # runs as a person's own account, and the App shows a standing "not-dedicated" warning (workers can reach
    # everything that account can).
    dedicated_account: bool = False
    logon_type: str = "Password"
    scheduled_task: str = "StrugglebusWorkerHost"
    tags: list[str] = field(default_factory=list)
    max_task_age_hours: float = 2.0
    pause_while_running: list[str] = field(default_factory=list)
    heartbeat_running_minutes: float = 10.0
    heartbeat_idle_minutes: float = 60.0
    coordinator_name: str = ""  # [coordinator] agent_name: before the first signed fleet, the one coordinator trusted
    # Before the first signed fleet only ([coordinator] project, notes_channel, owner): what the one pinned
    # coordinator's workers are told. A signed fleet.toml replaces all three.
    coordinator_project: str = "default"
    coordinator_notes_channel: str = ""  # "": the host's own channel
    owner: str = ""
    default_model: str = "claude-opus-5.5"
    allowed_models: list[str] = field(default_factory=lambda: ["claude-opus-5.5"])  # exact ids or families (models.py)
    denied_models: list[str] = field(default_factory=list)
    # [engines] (workerhost/engines.py): the engine for a task that names none, and Claude Code's own settings.
    default_engine: str = "ghcp"
    claude: "engines_mod.Claude | None" = None
    repos: dict[str, str] = field(default_factory=dict)
    hosts: list[dict] = field(default_factory=list)
    # [remotes] allowed: the outer fence on clone URLs (section 7.3). A task's repo must match a prefix here AND
    # in its coordinator's fleet.toml `repos`, so even a signed mistake cannot point this host anywhere else.
    remotes: list[str] = field(default_factory=lambda: list(urls.DEFAULT_REMOTES))
    resources: Resources = field(default_factory=Resources)
    runtime: Runtime = field(default_factory=Runtime)
    cleanup: Cleanup = field(default_factory=Cleanup)
    ghcp: Ghcp = field(default_factory=Ghcp)
    update: Update = field(default_factory=Update)
    openbao: OpenBao = field(default_factory=OpenBao)
    home: Path = field(default_factory=home_dir)

    @property
    def openbao_prefix(self) -> str:
        return self.openbao.prefix or self.agent_prefix

    @property
    def leaf_dir(self) -> Path:
        return Path(self.openbao.leaf_dir) if self.openbao.leaf_dir else self.home / "leaf"

    @property
    def host_agent(self) -> str:
        return agent_name(self.agent_prefix, HOST_SUFFIX)

    def worker_agent(self, worker: str) -> str:
        # A worker called "host" would be given this host's own identity and credential.
        if worker == HOST_SUFFIX:
            raise ValueError("worker name 'host' is reserved for the host identity")
        return agent_name(self.agent_prefix, worker)

    @property
    def state_dir(self) -> Path:
        return self.home / "state"

    @property
    def creds_dir(self) -> Path:
        return self.home / "creds"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    @property
    def vault_dir(self) -> Path:
        return self.home / "vault.git"

    @property
    def briefs_dir(self) -> Path:
        return self.state_dir / "briefs"

    @property
    def salvage_dir(self) -> Path:
        return self.home / "salvage"

    @property
    def ghcp_backup_dir(self) -> Path:
        return self.home / "ghcp-backup"

    @property
    def export_dir(self) -> Path:
        return self.home / "vault-export"

    @property
    def control_dir(self) -> Path:
        return self.state_dir / "control"

    @property
    def busclient_path(self) -> Path:
        return INSTALL_DIR / "workerhost" / "busclient.py"

    def vault_remote(self) -> str:
        """The legacy notes repository's clone URL, or "" when none is set."""
        if self.vault_url:
            return self.vault_url
        return f"https://github.com/{self.vault_repo}.git" if self.vault_repo else ""

    def notes_vault_dir(self, notes_repo: str) -> Path:
        """The mirror for a coordinator's notes repository. The legacy vault_repo keeps <home>\\vault.git (no
        second fetch of it); any other gets <home>\\vaults\\<host>--<owner>--<repo>.git."""
        if urls.canonical(notes_repo) == urls.canonical(self.vault_remote()):
            return self.vault_dir
        host, owner, repo = urls.repo_url(notes_repo)
        return self.home / "vaults" / f"{host}--{owner}--{repo}.git"

    def repo_url(self, short: str) -> str:
        """A short name from [repos] (the old task form, kept for one release) as its clone URL."""
        return f"https://github.com/{self.repos[short]}"

    @property
    def fleet_mirror_dir(self) -> Path:
        return self.home / "fleet.git"

    @property
    def fleet_store_dir(self) -> Path:
        return self.state_dir / "fleet"

    def fleet_remote(self) -> str:
        """The fleet repository's clone URL, or "" when none is set (no fleet, no self-update)."""
        if self.fleet_url:
            return self.fleet_url
        return f"https://github.com/{self.fleet_repo}.git" if self.fleet_repo else ""

    def release_remote(self) -> str:
        """The release repository set in config.toml, or "" (then a recorded redirect, else the fleet mirror)."""
        if self.release_url:
            return self.release_url
        return f"https://github.com/{self.release_repo}.git" if self.release_repo else ""

    @property
    def release_mirrors_dir(self) -> Path:
        return self.home / "release-mirrors"


def _section(raw: dict, key: str, cls):
    data = raw.get(key, {}) or {}
    known = {f for f in cls.__dataclass_fields__}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"unknown keys in [{key}]: {sorted(unknown)}")
    return cls(**data)


def load(path: Path | None = None) -> Config:
    home = home_dir()
    path = path or (home / "config.toml")
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    models = raw.pop("models", {}) or {}
    eng = engines_mod.parse(raw.pop("engines", None))
    coordinator = raw.pop("coordinator", {}) or {}
    sections = {k: raw.pop(k, {}) for k in ("resources", "runtime", "cleanup", "ghcp", "update", "openbao")}
    repos = raw.pop("repos", {}) or {}
    hosts = raw.pop("hosts", []) or []
    remotes = raw.pop("remotes", {}) or {}
    if not isinstance(remotes, dict) or set(remotes) - {"allowed"}:
        raise ValueError("[remotes] takes one key: allowed = [\"https://<host>/<owner>/\", ...]")
    known = set(Config.__dataclass_fields__) - {"resources", "runtime", "cleanup", "ghcp", "update", "openbao", "home",
                                                "repos", "hosts",
                                                "default_model", "allowed_models", "denied_models",
                                                "default_engine", "claude", "coordinator_name", "remotes"}
    unknown = set(raw) - known
    if unknown:
        raise ValueError(f"unknown keys in config: {sorted(unknown)}")
    if "workers_root" in raw:
        raw["workers_root"] = Path(raw["workers_root"])
    raw.setdefault("host_name", default_host_name())
    if "agent_prefix" not in raw:
        raise ValueError("agent_prefix missing from config.toml: re-run install.ps1 -AgentPrefix <the SPN's name>")
    m = models_mod.parse(models)
    cfg = Config(
        **raw,
        coordinator_name=coordinator.get("agent_name", ""),
        coordinator_project=coordinator.get("project", "default"),
        coordinator_notes_channel=coordinator.get("notes_channel", ""),
        owner=coordinator.get("owner", ""),
        default_model=m.default,
        allowed_models=list(m.allowed),
        denied_models=list(m.denied),
        default_engine=eng.default,
        claude=eng.claude,
        repos=dict(repos),
        hosts=list(hosts),
        remotes=list(remotes.get("allowed", urls.DEFAULT_REMOTES)),
        resources=_section(sections, "resources", Resources),
        runtime=_section(sections, "runtime", Runtime),
        cleanup=_section(sections, "cleanup", Cleanup),
        ghcp=_section(sections, "ghcp", Ghcp),
        update=_section(sections, "update", Update),
        openbao=_section(sections, "openbao", OpenBao),
        home=home,
    )
    check(cfg)
    return cfg


def check(cfg: Config) -> None:
    """Raise ValueError naming the first setting that is wrong. The checks run section by section, in file order."""
    _check_identity(cfg)
    _check_engines_and_timing(cfg)
    _check_repos(cfg.repos)
    _check_update(cfg.update)
    if not cfg.remotes or not all(isinstance(p, str) and p.endswith("/") and urls.prefix_ok(p) for p in cfg.remotes):
        raise ValueError("remotes.allowed entries must be https://<host>/ or https://<host>/<owner>/ prefixes")
    _check_openbao(cfg.openbao)
    for h in cfg.hosts:
        if set(h) - {"agent_name", "agent_id"} or not h.get("agent_id") or not h.get("agent_name"):
            raise ValueError("each [[hosts]] entry needs agent_name and agent_id only")


def _check_identity(cfg: Config) -> None:
    if not NAME_RE.fullmatch(cfg.host_name):
        raise ValueError("host_name must match [a-z0-9][a-z0-9-]{0,30}")
    if not isinstance(cfg.agent_prefix, str) or not PREFIX_RE.fullmatch(cfg.agent_prefix):
        raise ValueError("agent_prefix must match [a-z0-9][a-z0-9-]{1,30} and equal the SPN's name")
    if not isinstance(cfg.coordinator_project, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}",
                                                                        cfg.coordinator_project):
        raise ValueError("coordinator.project must match [a-z0-9][a-z0-9-]{0,30}")
    if cfg.coordinator_notes_channel and not (isinstance(cfg.coordinator_notes_channel, str)
                                              and CHANNEL_RE.fullmatch(cfg.coordinator_notes_channel)):
        raise ValueError("coordinator.notes_channel must be a channel name")
    if cfg.owner and not (isinstance(cfg.owner, str) and OWNER_RE.fullmatch(cfg.owner)):
        raise ValueError("coordinator.owner must be a plain name: letters, digits, spaces and . ' - (40 at most)")


def _check_engines_and_timing(cfg: Config) -> None:
    models_mod.parse({"default": cfg.default_model, "allowed": list(cfg.allowed_models),
                      "denied": list(cfg.denied_models)})
    if cfg.default_engine not in engines_mod.ENGINES:
        raise ValueError(f"engines.default must be one of {', '.join(engines_mod.ENGINES)}")
    if cfg.default_engine == "claude" and cfg.claude is None:
        raise ValueError('engines.default = "claude" needs an [engines.claude] table')
    if cfg.settle_seconds < 2 * cfg.poll_seconds:
        raise ValueError("settle_seconds must be at least twice poll_seconds")
    if not isinstance(cfg.dedicated_account, bool):
        raise ValueError("dedicated_account must be true or false")
    if cfg.fleet_source not in ("git", "bus", "either"):
        raise ValueError('fleet_source must be "git", "bus" or "either"')
    if not RELEASE_PATH_RE.fullmatch(cfg.release_path):
        raise ValueError("release_path must be a relative folder (letters, digits, . _ -, separated by /), no ..")
    if cfg.release_repo and not re.fullmatch(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}", cfg.release_repo):
        raise ValueError("release_repo must be owner/repo")
    if cfg.logon_type not in ("Password", "S4U", "Interactive"):
        raise ValueError("logon_type must be Password, S4U or Interactive")


def _check_repos(repos: dict) -> None:
    for short, full in repos.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", short) or not re.fullmatch(
                r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}", full):
            raise ValueError("repos entries must be short-name = \"owner/repo\"")


def _check_update(u: Update) -> None:
    for name in ("check_at", "window"):
        if not re.fullmatch(r"([01][0-9]|2[0-3]):[0-5][0-9]", str(getattr(u, name))):
            raise ValueError(f"update.{name} must be HH:MM (24-hour, local time)")
    if not 0 <= float(u.grace_minutes) <= 240:
        raise ValueError("update.grace_minutes must be between 0 and 240")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", str(u.announce_channel)):
        raise ValueError("update.announce_channel must be a channel name")


def _check_openbao(ob: OpenBao) -> None:
    if not isinstance(ob.enabled, bool):
        raise ValueError("openbao.enabled must be true or false")
    _check_openbao_addresses(ob)
    _check_openbao_names(ob)
    _check_openbao_numbers(ob)


HTTPS_HOST_RE = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?")


def _check_openbao_addresses(ob: OpenBao) -> None:
    """url and ca_url may stay empty while OpenBao is off; once it is on, both must be set. san_domain is optional."""
    for name in ("url", "ca_url"):
        value = str(getattr(ob, name))
        if (value or ob.enabled) and not HTTPS_HOST_RE.fullmatch(value):
            raise ValueError(f"openbao.{name} must be https://<host>[:port]")
    if ob.san_domain and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+",
                                          str(ob.san_domain)):
        raise ValueError("openbao.san_domain must be a lowercase DNS domain, e.g. home.lan")


def _check_openbao_names(ob: OpenBao) -> None:
    for name in ("mount", "prefix", "role"):
        value = str(getattr(ob, name))
        if value and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value):
            raise ValueError(f"openbao.{name} must match [a-z0-9][a-z0-9-]*")
    if not ob.mount:
        raise ValueError("openbao.mount must be set")
    for name in ("leaf_channel", "leaf_authority"):  # leaf_authority may be empty: ask by file only
        value = str(getattr(ob, name))
        if (value or name == "leaf_channel") and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
            raise ValueError(f"openbao.{name} must be a channel or agent name")


def _check_openbao_numbers(ob: OpenBao) -> None:
    if not 0.1 <= float(ob.check_minutes) <= 60:
        raise ValueError("openbao.check_minutes must be between 0.1 and 60")
    if not isinstance(ob.leaf_hours, int) or not 2 <= ob.leaf_hours <= 72:
        raise ValueError("openbao.leaf_hours must be a whole number from 2 to 72")
    if not 1 <= float(ob.ask_below_hours) <= 48:
        raise ValueError("openbao.ask_below_hours must be between 1 and 48")
    if not isinstance(ob.spn_rotate_days, int) or not 0 <= ob.spn_rotate_days <= 365:
        raise ValueError("openbao.spn_rotate_days must be a whole number from 0 (off) to 365")
