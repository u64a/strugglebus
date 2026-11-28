r"""The machine's engine updater, as a dedicated host sees it (setup\Update-Engines.ps1; #humans 29443-29445).

On a host with its own standard account, the agent programs (Copilot CLI, Claude Code) are machine-wide and the
account can't update them, by design. A SYSTEM scheduled task does it in the window, from an admin-only folder:
C:\ProgramData\strugglebus\engine-update. The host only READS two files there:

- updating.json: present while the task works, and kept fresh as a heartbeat. Admission is CLOSED while it EXISTS,
  however old: only a run that finishes safely removes it (fail closed; prox-manager #humans 29453, u64-security
  29455). A stale heartbeat means the run that wrote it died mid-update: the host reports the problem
  engine-update-interrupted and stays closed until the updater runs again and recovers (no installer left running,
  every tool checked or restored from its backup).
- result.json: what the last run did, per tool. The host logs each new outcome once (tool-updated, or
  tool-update-failed with a reason), which become host events, and reports Copilot's state as ghcp_ok.

Both files are written only by administrators and SYSTEM, so a host can't fake its own update.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

STALE_SECONDS = 300  # the script beats every 30 s (setup\Update-Engines.ps1 $BeatSeconds); 10 missed beats = died
TOOLS = ("ghcp", "claude")
OUTCOMES = ("updated", "current", "failed", "not-installed")
TOOL_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.]+)?")
REASON_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def folder() -> Path:
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "strugglebus" / "engine-update"


def marker_present(path: Path | None = None) -> bool:
    """Is the machine updating the engines, or did a run stop part-way? Either way admission is closed."""
    return (path or folder() / "updating.json").exists()


def marker_interrupted(path: Path | None = None, now: float | None = None) -> bool:
    """A marker whose heartbeat has stopped: the run that wrote it died before every tool was checked."""
    p = path or folder() / "updating.json"
    try:
        age = (time.time() if now is None else now) - p.stat().st_mtime
    except OSError:
        return False
    return age > STALE_SECONDS


def _version(value) -> str | None:
    return value if isinstance(value, str) and len(value) <= 32 and TOOL_VERSION_RE.fullmatch(value) else None


def read_result(path: Path | None = None) -> dict | None:
    """The last run, as {"written_at": int, "results": [{tool, outcome, before, after, reason}]}, keeping only what
    fits the contract; None when there is no finished run to read."""
    p = path or folder() / "result.json"
    try:
        raw = json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("state") != "done" or type(raw.get("written_at")) is not int:
        return None
    results = []
    for r in raw.get("results") or []:
        if not isinstance(r, dict) or r.get("tool") not in TOOLS or r.get("outcome") not in OUTCOMES:
            continue
        reason = r.get("reason")
        results.append({"tool": r["tool"], "outcome": r["outcome"], "before": _version(r.get("before")),
                        "after": _version(r.get("after")),
                        "reason": reason if isinstance(reason, str) and len(reason) <= 64 and REASON_RE.fullmatch(reason)
                        else ("unknown" if r["outcome"] == "failed" else None)})
    return {"written_at": raw["written_at"], "results": results}
