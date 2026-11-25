"""Validation of coordinator messages (design section 3), in the order the design gives.

1. sender  2. shape  3. age and replay  4. vault  5. resources  6. uniqueness

Every field is checked with a full-string pattern or an allowlist. Nothing here executes text from a
message; the only process started is `git check-ref-format --branch` with an argument list, and only
after the branch has already passed its pattern (so it cannot start with "-").
A refusal names the field and a fixed reason code; it never carries the rejected value.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from . import models as models_mod
from . import urls

MAX_BODY_BYTES = 4096
MAX_BRIEF_BYTES = 24 * 1024
TASK_KIND = "question"
REPLY_KIND = "answer"

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HOST_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
WORKER_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,30}")
BRANCH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
BRIEF_RE = re.compile(r"tooling/briefs/[A-Za-z0-9_./-]+\.(?:txt|md)")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
MODEL_RE = models_mod.MODEL_RE
TAG_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
REPO_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")

PROTECTED_BRANCHES = {"main", "master", "develop", "head"}
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)), *(f"lpt{i}" for i in range(10))}

TASK_REQUIRED = ("v", "type", "task_id", "host", "worker", "repo", "branch", "brief", "vault_commit")
TASK_OPTIONAL = ("model", "resume", "needs", "repo_instructions", "engine")
ENGINES = ("ghcp", "claude")  # workerhost/engines.py


class ShapeError(Exception):
    """A field failed its rule. Carries the field name only, never the value."""

    def __init__(self, field_name: str):
        super().__init__(field_name)
        self.field = field_name


@dataclass
class Pin:
    agent_id: str
    agent_name: str


@dataclass
class BriefBlob:
    path: str
    blob_sha: str
    text: str


@dataclass
class Decision:
    action: str  # accept | ignore | refuse
    reason: str = ""
    field: str = ""
    numbers: dict = dc_field(default_factory=dict)
    task: dict | None = None
    digest: str = ""
    brief: BriefBlob | None = None
    coordinator: Pin | None = None  # which trusted coordinator sent it (fleet.toml may list several)
    policy: "Policy | None" = None  # that coordinator's project rules (below)
    repo_url: str = ""  # the task's repository as a checked clone URL (a short name is mapped through [repos])

    @property
    def accepted(self) -> bool:
        return self.action == "accept"


class Vault(Protocol):
    def fetch(self) -> bool: ...
    def resolve_commit(self, commit: str) -> str | None: ...
    def on_main(self, commit: str) -> bool: ...
    def brief_entry(self, commit: str, path: str) -> tuple[str, str, str, int] | None: ...
    def read_blob(self, sha: str) -> bytes: ...


@dataclass
class Policy:
    """What a task from one coordinator may do and how its worker is briefed: its fleet.toml entry, or, before the
    first signed fleet, the legacy single-coordinator setup (config.toml's [coordinator], short repo names, config's
    vault_repo)."""
    vault: Vault  # the coordinator's notes repository: briefs are read from here
    project: str = "default"
    coordinator_name: str = ""
    notes_channel: str = "worker-hosts"
    repos: tuple[str, ...] | None = None  # URL prefixes it may task; None (legacy): [repos] short names only
    repo_instructions: bool = True  # the default when a task does not say
    worker_rules: str = ""
    legacy: bool = True  # True: trusted from config.toml's pin, not a signed fleet
    owner: str = ""  # named in the worker's preamble; "" = "the owner"


@dataclass
class Context:
    """Everything validation needs, injected so the rules are testable without a bus or a vault."""
    host_name: str
    coordinators: list[Pin]
    repos: dict[str, str]
    allowed_models: list[str]  # exact ids or families ('*'): workerhost/models.py
    tags: list[str]
    vault: Vault  # the legacy notes repository (config.toml vault_repo)
    remotes: list[str] = dc_field(default_factory=lambda: list(urls.DEFAULT_REMOTES))
    policy: Callable[[Pin], Policy | None] | None = None  # None: every coordinator gets the legacy policy
    handled_seqs: set[int] = dc_field(default_factory=set)
    terminal_task_ids: set[str] = dc_field(default_factory=set)
    max_age: timedelta = timedelta(hours=2)
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    resources: Callable[[], tuple[str, dict] | None] = lambda: None
    uniqueness: Callable[[str, str], str | None] = lambda worker, task_id: None
    fits_command_line: Callable[..., bool] = lambda text, policy=None: True
    git_exe: str = "git"
    denied_models: list[str] = dc_field(default_factory=list)  # checked before allowed_models
    # Engines (workerhost/engines.py): the default for a task that names none, the engines usable here now, and Claude
    # Code's own model list (its ids differ from Copilot's: claude-opus-5-5 / opus, not claude-opus-5.5).
    default_engine: str = "ghcp"
    engines: tuple[str, ...] = ("ghcp",)
    claude: Any = None

    def model_allowed(self, model: str, engine: str = "ghcp") -> bool:
        if engine == "claude":
            return self.claude is not None and self.claude.allows(model)
        return models_mod.is_allowed(model, self.allowed_models, self.denied_models)

    def policy_for(self, pin: Pin) -> Policy | None:
        return self.policy(pin) if self.policy is not None else Policy(vault=self.vault)


# --- canonical form -----------------------------------------------------------------------------

def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_of(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("ascii")).hexdigest()


def raw_digest(body: Any) -> str:
    data = body.encode("utf-8", "replace") if isinstance(body, str) else repr(body).encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


# --- step 1: sender -----------------------------------------------------------------------------

def sender_is(msg: dict, pin: Pin) -> bool:
    """The bus-authenticated sender, never anything the body claims."""
    return (bool(pin.agent_id) and isinstance(msg.get("agent_id"), str) and isinstance(msg.get("agent_name"), str)
            and msg["agent_id"] == pin.agent_id and msg["agent_name"] == pin.agent_name)


def sender_of(msg: dict, pins: list[Pin]) -> Pin | None:
    """Which of `pins` sent this message (bus-authenticated), or None."""
    return next((p for p in pins if sender_is(msg, p)), None)


# --- step 2: shape ------------------------------------------------------------------------------

def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ShapeError("body")
        out[k] = v
    return out


def parse_body(body: Any) -> dict:
    if not isinstance(body, str):
        raise ShapeError("body")
    if len(body.encode("utf-8", "replace")) > MAX_BODY_BYTES:
        raise ShapeError("size")
    try:
        obj = json.loads(body, object_pairs_hook=_no_duplicates,
                         parse_constant=lambda c: (_ for _ in ()).throw(ShapeError("body")))
    except ShapeError:
        raise
    except (ValueError, RecursionError):
        raise ShapeError("body") from None
    if not isinstance(obj, dict):
        raise ShapeError("body")
    if obj.get("v") != 1 or type(obj.get("v")) is not int:
        raise ShapeError("v")
    if not isinstance(obj.get("type"), str):
        raise ShapeError("type")
    return obj


def _str(obj: dict, key: str, pattern: re.Pattern) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.isascii() or not pattern.fullmatch(value):
        raise ShapeError(key)
    return value


def branch_ok_locally(branch: str) -> bool:
    """The rules of git check-ref-format, as far as they apply after BRANCH_RE."""
    if ".." in branch or "//" in branch or "@{" in branch:
        return False
    if branch.endswith(("/", ".", ".lock")) or branch.lower() in PROTECTED_BRANCHES:
        return False
    if branch.lower().startswith(("refs/", "origin/", "heads/", "remotes/")):
        return False
    for part in branch.split("/"):
        if not part or part.startswith(".") or part.endswith(".lock"):
            return False
    return True


def git_check_ref_format(branch: str, git_exe: str = "git") -> bool:
    try:
        r = subprocess.run([git_exe, "check-ref-format", "--branch", branch], capture_output=True, timeout=20,
                           stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def brief_ok(path: str) -> bool:
    if ".." in path or "//" in path or "\\" in path:
        return False
    parts = path.split("/")
    return all(p and p != "." and not p.startswith(".") for p in parts)


def resolve_repo(value: Any, ctx: Context, policy: Policy) -> str:
    """The task's `repo` as a canonical clone URL, or ShapeError("repo").

    A short name in config.toml [repos] (the old form, kept for one release) maps to https://github.com/<owner/repo>.
    A full URL is accepted only from a fleet.toml coordinator. Either way the URL must pass the URL rules, sit under a
    prefix in the host's [remotes] allowed fence and, for a fleet coordinator, under one of its own `repos`."""
    if not isinstance(value, str):
        raise ShapeError("repo")
    if REPO_KEY_RE.fullmatch(value) and value in ctx.repos:
        url = f"https://github.com/{ctx.repos[value]}"
    elif policy.repos is not None and value.startswith("https://"):
        url = value
    else:
        raise ShapeError("repo")
    clean = urls.canonical(url)
    if clean is None or not urls.allowed(clean, ctx.remotes):
        raise ShapeError("repo")
    if policy.repos is not None and not urls.allowed(clean, policy.repos):
        raise ShapeError("repo")
    return clean


def check_task_fields(obj: dict, ctx: Context, git_check: bool = True, policy: Policy | None = None) -> dict:
    """Return the task with defaults filled, or raise ShapeError(field)."""
    policy = policy or Policy(vault=ctx.vault)
    _check_task_keys(obj)
    _check_task_who(obj)
    resolve_repo(obj.get("repo"), ctx, policy)
    branch = _check_task_what(obj)
    _check_task_engine_and_model(obj, ctx)
    _check_task_flags(obj)
    if git_check and not git_check_ref_format(branch, ctx.git_exe):
        raise ShapeError("branch")
    return dict(obj)


def _check_task_keys(obj: dict) -> None:
    for k in TASK_REQUIRED:
        if k not in obj:
            raise ShapeError(k)
    if set(obj) - set(TASK_REQUIRED) - set(TASK_OPTIONAL):
        raise ShapeError("unknown-key")
    if obj["type"] != "task":
        raise ShapeError("type")


def _check_task_who(obj: dict) -> None:
    """task_id, host and worker."""
    _str(obj, "task_id", UUID_RE)
    if obj.get("host") != "any":
        _str(obj, "host", HOST_RE)
    worker = _str(obj, "worker", WORKER_RE)
    if worker in WINDOWS_RESERVED or worker == "host":  # "host" would be <agent_prefix>-host: the host's own identity
        raise ShapeError("worker")


def _check_task_what(obj: dict) -> str:
    """branch, brief and vault_commit; returns the branch."""
    branch = _str(obj, "branch", BRANCH_RE)
    if not branch_ok_locally(branch):
        raise ShapeError("branch")
    brief = _str(obj, "brief", BRIEF_RE)
    if not brief_ok(brief):
        raise ShapeError("brief")
    _str(obj, "vault_commit", COMMIT_RE)
    return branch


def _check_task_engine_and_model(obj: dict, ctx: Context) -> None:
    if "engine" in obj and (not isinstance(obj["engine"], str) or obj["engine"] not in ENGINES):
        raise ShapeError("engine")
    engine = obj.get("engine") or ctx.default_engine
    if "model" in obj:
        model = _str(obj, "model", MODEL_RE)
        # Checked against the task's engine's list; a host without that engine refuses it as "engine" later, and a
        # model valid only for an engine this host lacks is that refusal too, not a shape error.
        if engine in ctx.engines and not ctx.model_allowed(model, engine):
            raise ShapeError("model")


def _check_task_flags(obj: dict) -> None:
    """resume, repo_instructions and needs."""
    if "resume" in obj and type(obj["resume"]) is not bool:
        raise ShapeError("resume")
    if "repo_instructions" in obj and type(obj["repo_instructions"]) is not bool:
        raise ShapeError("repo_instructions")  # JSON true/false only: "false" or 0 is refused, never guessed
    if "needs" in obj:
        needs = obj["needs"]
        if not isinstance(needs, list) or len(needs) > 8 or len(set(map(str, needs))) != len(needs):
            raise ShapeError("needs")
        if not all(isinstance(tag, str) and TAG_RE.fullmatch(tag) for tag in needs):
            raise ShapeError("needs")


def check_control_fields(obj: dict, ctx: Context) -> dict:
    kind = obj["type"]
    allowed = {"cancel": {"v", "type", "task"}, "set-model": {"v", "type", "model"}, "status": {"v", "type"}}
    if kind not in allowed:
        raise ShapeError("type")
    if set(obj) != allowed[kind]:
        raise ShapeError("unknown-key")
    if kind == "cancel":
        task = obj["task"]
        if type(task) is not int or task <= 0:
            raise ShapeError("task")
    if kind == "set-model":
        model = _str(obj, "model", MODEL_RE)
        if not ctx.model_allowed(model):
            raise ShapeError("model")
    return dict(obj)


# --- the pipeline -------------------------------------------------------------------------------

def parse_created(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def validate_task(msg: dict, ctx: Context, *, resume: bool = False, git_check: bool = True) -> Decision:
    # 1. Sender: one of the trusted coordinators. A stranger gets no answer at all (no oracle).
    coordinator = sender_of(msg, ctx.coordinators)
    if coordinator is None:
        return Decision("ignore", "sender")
    policy = ctx.policy_for(coordinator)
    if policy is None:
        return Decision("ignore", "sender")
    decision = _validate_task(msg, ctx, policy, resume=resume, git_check=git_check)
    decision.coordinator = coordinator
    decision.policy = policy
    return decision


def _validate_task(msg: dict, ctx: Context, policy: Policy, *, resume: bool, git_check: bool) -> Decision:
    if msg.get("kind") != TASK_KIND:
        return Decision("ignore", "kind")
    body = msg.get("body")
    # 2. Shape.
    try:
        obj = parse_body(body)
    except ShapeError as e:
        return Decision("refuse", "size" if e.field == "size" else "shape", field=e.field, digest=raw_digest(body))
    digest = digest_of(obj)
    if obj.get("type") != "task":
        return Decision("ignore", "not-task", digest=digest)
    try:
        task = check_task_fields(obj, ctx, git_check=git_check, policy=policy)
        repo_url = resolve_repo(task["repo"], ctx, policy)
    except ShapeError as e:
        return Decision("refuse", "shape", field=e.field, digest=digest)
    task.setdefault("resume", False)
    task.setdefault("needs", [])
    task.setdefault("repo_instructions", policy.repo_instructions)  # the project's default (fleet.toml)
    if task["host"] not in ("any", ctx.host_name):
        return Decision("ignore", "other-host", task=task, digest=digest)
    if not set(task["needs"]) <= set(ctx.tags):
        return Decision("ignore", "tags", task=task, digest=digest)
    # An engine this host does not have (not configured, not installed, or not signed in): refused, so the coordinator
    # sees why and another host may take it (docs/agent-host-build.md 7.6).
    task.setdefault("engine", ctx.default_engine)
    if task["engine"] not in ctx.engines:
        return Decision("refuse", "engine", field="engine", task=task, digest=digest)
    # 3. Age and replay (a resume re-validates everything except this step).
    if not resume:
        seq = msg.get("seq")
        if seq in ctx.handled_seqs:
            return Decision("ignore", "replay", task=task, digest=digest)
        created = parse_created(msg.get("created_at"))
        now = ctx.now()
        if created is None or now - created > ctx.max_age or created - now > timedelta(minutes=5):
            return Decision("refuse", "age", field="created_at", task=task, digest=digest)
        if task["task_id"] in ctx.terminal_task_ids:
            return Decision("refuse", "replay", field="task_id", task=task, digest=digest)
    # 4. Vault (the sending coordinator's notes repository): fresh fetch, commit on main, bounded UTF-8 blob.
    brief = check_vault(task, ctx, policy)
    if isinstance(brief, Decision):
        brief.task, brief.digest = task, digest
        return brief
    # 5. Resources.
    verdict = ctx.resources()
    if verdict is not None:
        reason, numbers = verdict
        return Decision("refuse", reason, numbers=dict(numbers), task=task, digest=digest)
    # 6. Uniqueness.
    clash = ctx.uniqueness(task["worker"], task["task_id"])
    if clash:
        return Decision("refuse", clash, field="worker", task=task, digest=digest)
    return Decision("accept", task=task, digest=digest, brief=brief, repo_url=repo_url)


def check_vault(task: dict, ctx: Context, policy: Policy | None = None) -> BriefBlob | Decision:
    policy = policy or Policy(vault=ctx.vault)
    vault = policy.vault
    commit, path = task["vault_commit"], task["brief"]
    if not vault.fetch():
        return Decision("refuse", "vault")
    if vault.resolve_commit(commit) != commit:
        return Decision("refuse", "vault_commit", field="vault_commit")
    if not vault.on_main(commit):
        return Decision("refuse", "vault_commit", field="vault_commit")
    entry = vault.brief_entry(commit, path)
    if entry is None:
        return Decision("refuse", "brief", field="brief")
    mode, kind, sha, size = entry
    if mode != "100644" or kind != "blob" or size > MAX_BRIEF_BYTES or not COMMIT_RE.fullmatch(sha):
        return Decision("refuse", "brief", field="brief")
    data = vault.read_blob(sha)
    if len(data) != size or len(data) > MAX_BRIEF_BYTES:
        return Decision("refuse", "brief", field="brief")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return Decision("refuse", "brief", field="brief")
    # Claude Code gets the prompt on stdin, so the command-line limit applies only to GHCP.
    if "\x00" in text or (task.get("engine", "ghcp") != "claude" and not ctx.fits_command_line(text, policy)):
        return Decision("refuse", "brief", field="brief")
    return BriefBlob(path=path, blob_sha=sha, text=text)


def classify(msg: dict, ctx: Context) -> tuple[str, dict | None, str]:
    """For the host loop: which kind of coordinator message is this? Returns (type, obj, digest).

    type is "ignore" (not from the coordinator, wrong kind, unparseable control), "task" (hand the
    message to validate_task), or a validated control type: "cancel", "set-model", "status".
    """
    if sender_of(msg, ctx.coordinators) is None or msg.get("kind") != TASK_KIND:
        return "ignore", None, ""
    try:
        obj = parse_body(msg.get("body"))
    except ShapeError:
        return "task", None, ""  # validate_task produces the refusal
    if obj["type"] == "task":
        return "task", obj, digest_of(obj)
    try:
        return obj["type"], check_control_fields(obj, ctx), digest_of(obj)
    except ShapeError:
        return "ignore", None, digest_of(obj)
