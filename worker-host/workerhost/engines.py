"""Worker engines (docs/agent-host-build.md 7.6): GHCP CLI (`ghcp`, the original) and Claude Code (`claude`).

config.toml:

    [engines]
    default = "ghcp"                 # the engine for a task that names none ("ghcp" or "claude")

    [engines.claude]                 # present = Claude Code may be used on this host
    exe = "claude"
    default_model = "opus"           # Claude Code ids: aliases (opus, sonnet, fable, haiku) or full ids (claude-opus-5-5)
    allowed = ["opus", "sonnet", "fable", "haiku", "claude-*"]
    denied = []

A task may say "engine": "ghcp" | "claude". A task for an engine this host does not have (not configured, not
installed, or not signed in) is refused with reason "engine", so another host may take it. Each engine has its own
model list: Copilot ids use dots (claude-opus-5.5), Claude Code ids use dashes or aliases (claude-opus-5-5, opus).

The Claude Code launch follows the GHCP rules:
- headless (`claude -p`), an argument list, never a shell; the prompt (the same fixed preamble plus the brief blob)
  goes on stdin, so the 32,767-character command line is not a limit;
- the tool set matches GHCP's --allow-all-tools with the path fence: --permission-mode acceptEdits (file edits only
  inside the clone and the --add-dir folders) plus Bash, WebFetch and WebSearch allowed; nothing is ever
  --dangerously-skip-permissions or bypassPermissions;
- --setting-sources "" (none) and --strict-mcp-config: no settings file is loaded at all - not the host account's
  (it may also be a person's interactive account), and not the repository's .claude/settings.json or settings.local.json.
  A repository's settings act without the model choosing anything (env such as ANTHROPIC_BASE_URL would send the
  subscription token elsewhere; apiKeyHelper runs a command; hooks, permissions.allow, additionalDirectories) and
  -p skips the trust prompt (security review). Proven live: a repo settings.local.json env
  value reached the worker's shell with "project,local" and did not with "". The repository's instructions still
  arrive, as text the worker reads (CLAUDE_REPO_NOTE);
- --output-format stream-json --verbose: the log keeps moving while the worker runs (the stall check reads it), and
  the final `result` line carries the cost;
- the session id is the host's (--session-id, or --resume for a resume), so `resume` works the same way;
- DISABLE_AUTOUPDATER=1: the CLI never updates itself under a running worker.

Usage: Claude Code's cost is reported in US dollars under its own keys (usd, by_model_usd), never added to AIC.
"""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import models as models_mod

ENGINES = ("ghcp", "claude")
CLAUDE_ALLOWED_TOOLS = "Bash,WebFetch,WebSearch"
CLAUDE_DEFAULTS = {"exe": "claude", "default_model": "opus",
                   "allowed": ["opus", "sonnet", "fable", "haiku", "claude-*"], "denied": []}
CLAUDE_KEYS = {"exe", "default_model", "allowed", "denied"}
# Claude Code reads CLAUDE.md, not AGENTS.md or .github/copilot-instructions.md, which is where repositories built for
# GHCP keep their rules (for example "never write to an assessed tenant"). With repo_instructions on, say so.
CLAUDE_REPO_NOTE = """Repository instructions: before anything else, read the repository's own instruction files if they exist:
AGENTS.md, CLAUDE.md and .github/copilot-instructions.md. Follow them, except where they conflict with the rules above.
"""
CLAUDE_ENV = {"DISABLE_AUTOUPDATER": "1"}


@dataclass(frozen=True)
class Claude:
    exe: str = "claude"
    default_model: str = "opus"
    allowed: tuple[str, ...] = tuple(CLAUDE_DEFAULTS["allowed"])
    denied: tuple[str, ...] = ()

    def allows(self, model: object) -> bool:
        return models_mod.is_allowed(model, self.allowed, self.denied)


@dataclass(frozen=True)
class Engines:
    default: str = "ghcp"
    claude: Claude | None = None  # None: [engines.claude] absent, Claude Code is not used on this host


def parse(table: object) -> Engines:
    if table is None:
        return Engines()
    if not isinstance(table, dict):
        raise ValueError("[engines] must be a table")
    unknown = set(table) - {"default", "claude"}
    if unknown:
        raise ValueError(f"unknown keys in [engines]: {sorted(unknown)}")
    default = table.get("default", "ghcp")
    if default not in ENGINES:
        raise ValueError(f"engines.default must be one of {', '.join(ENGINES)}")
    claude = None
    if "claude" in table:
        t = table["claude"]
        if not isinstance(t, dict):
            raise ValueError("[engines.claude] must be a table")
        unknown = set(t) - CLAUDE_KEYS
        if unknown:
            raise ValueError(f"unknown keys in [engines.claude]: {sorted(unknown)}")
        exe = t.get("exe", CLAUDE_DEFAULTS["exe"])
        if not isinstance(exe, str) or not exe.strip():
            raise ValueError("engines.claude.exe must be a path or command name")
        try:
            m = models_mod.parse({"default": t.get("default_model", CLAUDE_DEFAULTS["default_model"]),
                                  "allowed": t.get("allowed", CLAUDE_DEFAULTS["allowed"]),
                                  "denied": t.get("denied", CLAUDE_DEFAULTS["denied"])})
        except ValueError as e:
            raise ValueError(f"[engines.claude] {str(e).replace('models.', '')}") from None
        claude = Claude(exe, m.default, m.allowed, m.denied)
    if default == "claude" and claude is None:
        raise ValueError('engines.default = "claude" needs an [engines.claude] table')
    return Engines(default, claude)


def resolve(name: str) -> str | None:
    """An absolute path to a real executable (never a .cmd/.bat: a shell would re-parse arguments), or None."""
    path = shutil.which(name) if not os.path.isabs(name) else (name if os.path.isfile(name) else None)
    if not path or not os.path.isabs(path) or Path(path).suffix.lower() in (".cmd", ".bat"):
        return None
    return path


def claude_signed_in(home: Path | None = None) -> bool:
    """Claude Code keeps its sign-in in ~/.claude/.credentials.json. Only its presence is checked; never read."""
    return (Path(home or Path.home()) / ".claude" / ".credentials.json").is_file()


def available(copilot_exe: str, eng: Engines, home: Path | None = None, token: bool = False) -> list[str]:
    """The engines a task may use here now. GHCP: its CLI is installed (whether the licence is current cannot be
    told without spending a request). Claude: configured, installed and signed in, by its own /login or by a token
    the App sealed to this host (`token`, docs/app-host-integration.md 4a)."""
    out = []
    if resolve(copilot_exe):
        out.append("ghcp")
    if eng.claude is not None and resolve(eng.claude.exe) and (token or claude_signed_in(home)):
        out.append("claude")
    return out


def claude_command(exe: str, model: str, session_id: str, resume: bool, install_dir: str,
                   vault_export: str | None = None) -> list[str]:
    """The Claude Code argument list. The prompt is NOT in it: it goes on stdin."""
    cmd = [exe, "-p", "--output-format", "stream-json", "--verbose", "--model", model,
           "--permission-mode", "acceptEdits", "--allowedTools", CLAUDE_ALLOWED_TOOLS,
           "--setting-sources", "", "--strict-mcp-config", "--add-dir", str(install_dir)]
    if vault_export:
        cmd += ["--add-dir", str(vault_export)]
    cmd += ["--resume", session_id] if resume else ["--session-id", session_id]
    return cmd


def claude_session_ok(session_id: str, clone: Path, home: Path | None = None) -> bool:
    """Resume only a Claude Code session whose own record says it ran in this worker's clone. Sessions are
    ~/.claude/projects/<folder>/<session_id>.jsonl; each record carries the cwd it ran in."""
    root = Path(home or Path.home()) / ".claude" / "projects"
    try:
        hits = list(root.glob(f"*/{session_id}.jsonl"))
    except (OSError, ValueError):
        return False
    want = os.path.normcase(os.path.abspath(clone))
    for path in hits:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for _, line in zip(range(50), fh):
                    try:
                        cwd = json.loads(line).get("cwd")
                    except (ValueError, AttributeError):
                        continue
                    if isinstance(cwd, str):
                        return os.path.normcase(os.path.abspath(cwd)) == want
        except OSError:
            continue
    return False


def _num(v) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0


def read_claude_usage(log: Path, task_id: str) -> dict | None:
    """What a Claude Code worker spent, from the last `result` line of ITS attempt in the worker log (the log is per
    worker name and holds earlier tasks too: only lines after this task's header count). None if there is none."""
    marker = f"task_id={task_id} "
    result = None
    mine = False  # inside this task's part of the log (after its header, before another task's)
    try:
        with open(log, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("===== worker host task "):
                    mine = marker in line
                    continue
                if not mine or '"type":"result"' not in line.replace(" ", ""):
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict) and obj.get("type") == "result":
                    result = obj  # the last one wins: a resumed attempt appends a second header and result
    except OSError:
        return None
    if result is None:
        return None
    usage = result.get("usage") if isinstance(result.get("usage"), dict) else {}
    by_model = {}
    mu = result.get("modelUsage")
    if isinstance(mu, dict):
        for name, v in mu.items():
            if isinstance(name, str) and isinstance(v, dict):
                by_model[name] = round(_num(v.get("costUSD")), 4)
    out = {"usd": round(_num(result.get("total_cost_usd")), 4), "calls": int(_num(result.get("num_turns"))),
           "input_tokens": int(_num(usage.get("input_tokens")) + _num(usage.get("cache_read_input_tokens"))
                               + _num(usage.get("cache_creation_input_tokens"))),
           "output_tokens": int(_num(usage.get("output_tokens"))), "by_model_usd": by_model}
    if by_model:
        out["model_observed"] = max(by_model, key=by_model.get)
    return out
