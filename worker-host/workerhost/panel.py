"""`wh panel`: a small desktop window showing what the host is doing, so nobody has to type `wh status`.

The host runs as a scheduled task with no desktop (logged on or not), so the panel is a separate program in
the signed-in session. It only reads <home>\\state\\status.json, which the host rewrites every loop, and checks
that the process that wrote it is alive. It never talks to the bus. Its buttons run the same `wh` commands
the owner would type (pause, resume, drain, start), so they behave exactly as documented.

install.ps1 puts a shortcut in the user's Startup folder, so it opens at every sign-in (RDP included).
One panel per home folder: a second start just exits.

`summarize()` turns the status into what the window shows; it is pure, so it is tested without a screen.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import signing, winapi
from .config import INSTALL_DIR, Config

REFRESH_MS = 3000
STALE_SECONDS = 120
STARTING_SECONDS = 300   # after boot: "Starting", not "Not running" (the task's delay is 2 minutes)
COLOURS = {"ok": "#2e9d4f", "warn": "#d99a00", "bad": "#c8372d", "off": "#8a8a8a"}


@dataclass
class View:
    level: str                       # ok | warn | bad | off
    title: str                       # Online, Paused, ...
    detail: str                      # one plain sentence
    facts: list[tuple[str, str]] = field(default_factory=list)
    workers: list[tuple[str, str, str, str]] = field(default_factory=list)  # worker, task, model, minutes
    can_start: bool = False
    paused: bool = False


def _gb(value) -> str:
    return "?" if value is None else f"{value:.0f} GB" if value >= 10 else f"{value:.1f} GB"


def summarize(status: dict | None, alive: bool, now: float, state: dict | None = None,
              booted: float | None = None) -> View:
    """What the window shows. status: status.json (or None); alive: its writer's process exists;
    state: state.json, for the enabled/paused flags when the host is not running; booted: when Windows started."""
    if status is None or not alive:
        return _not_running(state or {}, now, booted)
    age = now - float(status.get("updated", 0) or 0)
    workers = [(w.get("worker", "?"), str(w.get("task_id", "?"))[:8], w.get("model", "?"), f"{w.get('minutes', 0)} min")
               for w in status.get("workers", [])]
    host_state = str(status.get("state", "?"))
    view = View("ok", "", "", _facts(status, len(workers), age), workers, paused=host_state.startswith("paused"))
    view.level, view.title, view.detail, view.can_start = _headline(status, host_state, age, len(workers),
                                                                    view.paused)
    return view


def _not_running(state: dict, now: float, booted: float | None) -> View:
    if state.get("enabled") is False:
        return View("off", "Stopped", "The host is switched off (wh stop or wh drain). Press Start to run it.",
                    can_start=True)
    if booted and 0 <= now - booted < STARTING_SECONDS:
        # The scheduled task starts the host 2 minutes after boot; with automatic sign-in this window opens first
        # (seen on a host with automatic sign-in), so "Not running" here would be a false alarm.
        return View("warn", "Starting", "Windows started a moment ago; the host starts 2 minutes after boot.")
    return View("bad", "Not running", "The host process is not running. It may be starting (up to 2 minutes "
                "after boot), or its scheduled task is off. Press Start, or look at the logs.", can_start=True)


def _headline(status: dict, host_state: str, age: float, n_workers: int, paused: bool) -> tuple[str, str, str, bool]:
    """(level, title, detail, can_start) for a host whose process is alive: the first problem wins."""
    fleet = status.get("fleet") or {}
    if age > STALE_SECONDS:
        return ("warn", "Not responding",
                f"The host has not updated its status for {int(age // 60)} minutes. It may be busy or stuck.", False)
    if host_state == "stopped":
        return "off", "Stopping", "The host is shutting down.", True
    if status.get("channel_state") == "missing":
        return ("bad", "Channel missing",
                f"The bus has no '{status.get('channel')}' channel, so no tasks can arrive.", False)
    if fleet.get("state") == "unavailable":
        return ("bad", "Trusts nobody",
                "The kept signed fleet list failed its check: no coordinator is trusted until it refreshes.", False)
    if status.get("bus_state") == "down":
        return ("warn", "Bus unreachable",
                "Cannot reach StruggleBus. Running workers carry on; the host keeps retrying.", False)
    if status.get("draining"):
        return "warn", "Draining", "Taking no new tasks; it switches off when the running workers finish.", False
    if paused:
        return ("warn", "Paused", "Paused while a game runs." if status.get("game_paused") else
                "Taking no new tasks; running workers carry on. Press Resume to take tasks again.", False)
    if host_state == "maintenance":
        return "warn", "Maintenance", "Updating; tasks resume afterwards.", False
    return ("ok", "Online",
            f"Connected to StruggleBus. {n_workers} worker{'s' if n_workers != 1 else ''} at work." if n_workers
            else "Connected to StruggleBus and waiting for tasks.", False)


def _release(status: dict) -> str:
    """The host code's version: "2026.11.24 (serial 3)", "manual" for a hand install, plus an announced update. A
    host from before this field: the release= token of its heartbeat line."""
    rel = status.get("release") or {}
    version = rel.get("version") or next((p.split("=", 1)[1] for p in status.get("heartbeat_line", "").split()
                                          if p.startswith("release=")), "?")
    text = f"{version} (serial {rel['serial']})" if rel.get("serial") else str(version)
    update = status.get("update") or {}
    if update.get("version"):
        text += f"; {update['version']} announced, applied {update.get('when', 'in the window')}"
    return text


def _facts(status: dict, n_workers: int, age: float) -> list[tuple[str, str]]:
    fleet = status.get("fleet") or {}
    res = status.get("resources") or {}
    line = status.get("heartbeat_line", "")
    max_workers = next((p.split("/")[1] for p in line.split() if p.startswith("workers=") and "/" in p), "?")
    held = status.get("held_clones") or []
    return [
        ("StruggleBus", {"ok": "connected", "down": "unreachable, retrying"}.get(status.get("bus_state"), "connecting")
         + f" (channel {status.get('channel', '?')}"
         + (", MISSING)" if status.get("channel_state") == "missing" else ")")),
        ("Workers", f"{n_workers} of {max_workers} busy" + (f", {len(status.get('claims', []))} being claimed"
                                                            if status.get("claims") else "")),
        ("Model", f"{status.get('model', '?')}   (Copilot CLI {status.get('ghcp') or '?'}"
                  + (", last update FAILED)" if status.get("ghcp_ok") is False else ")")),
        ("Release", _release(status)),
        ("Fleet", (f"signed list {fleet['label']}" if fleet.get("label") else
                   {"legacy": "config.toml pins (no signed fleet.toml yet)",
                    "unavailable": "NONE: the signed list failed its check"}.get(fleet.get("state"), "?"))
         + (f"; coordinators: {', '.join(fleet.get('coordinators', [])) or 'none'}" if fleet else "")),
        ("Machine", f"RAM free {_gb(res.get('ram_free_gb'))}, disk free {_gb(res.get('disk_free_gb'))}, "
                    f"memory committed {res.get('commit_pct', '?')}%" if res else "measuring"),
        ("Clones", f"{len(held)} held for unsaved work" + (f": {', '.join(held[:6])}" + (" ..." if len(held) > 6 else "")
                                                          if held else "")),
        ("Updated", f"{int(age)} s ago"),
    ]


# --- reading the host's files -------------------------------------------------------------------------

def read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def load(cfg: Config, now: float | None = None) -> View:
    status = read_json(cfg.state_dir / "status.json")
    pid = int((status or {}).get("pid") or 0)
    # pid_alive: the window runs in the signed-in session and may not open the host's process (session 0).
    # A stale status.json still shows "Not responding" below.
    alive = bool(pid) and winapi.IS_WINDOWS and winapi.pid_alive(pid)
    return summarize(status, alive, now or time.time(), read_json(cfg.state_dir / "state.json"),
                     booted=winapi.boot_time() if winapi.IS_WINDOWS else None)


def wh_command(cfg: Config, *args: str) -> tuple[int, str]:
    """Run `wh <args>` exactly as the owner would, with no console window. python.exe, not pythonw.exe, so the
    output can be shown."""
    exe = Path(sys.executable)
    if exe.name.lower() == "pythonw.exe" and (exe.parent / "python.exe").exists():
        exe = exe.parent / "python.exe"
    try:
        r = subprocess.run([str(exe), str(INSTALL_DIR / "wh.py"), "--home", str(cfg.home), *args],
                           capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, f"wh {' '.join(args)}: {type(e).__name__}"
    text = (r.stdout or r.stderr or "").strip().splitlines()
    return r.returncode, text[-1] if text else f"wh {' '.join(args)}: exit {r.returncode}"


# --- the window ---------------------------------------------------------------------------------------

def run(cfg: Config) -> int:
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except ImportError:
        print("the panel needs tkinter (part of the python.org installer: tick 'tcl/tk and IDLE')")
        return 2
    mutex = None
    if winapi.IS_WINDOWS:
        name = "Local\\StrugglebusHostPanel-" + hashlib.sha256(str(cfg.home).lower().encode()).hexdigest()[:12]
        mutex = winapi.single_instance(name)
        if mutex is None:
            return 0  # already open

    root = tk.Tk()
    root.title(f"Strugglebus host - {cfg.host_name}")
    root.geometry("640x470")
    root.minsize(520, 380)
    big = ("Segoe UI", 16, "bold")
    normal = ("Segoe UI", 10)

    head = tk.Frame(root, padx=14, pady=10)
    head.pack(fill="x")
    dot = tk.Canvas(head, width=28, height=28, highlightthickness=0)
    dot.pack(side="left")
    light = dot.create_oval(3, 3, 25, 25, fill=COLOURS["off"], outline="")
    titles = tk.Frame(head, padx=10)
    titles.pack(side="left", fill="x", expand=True)
    title = tk.Label(titles, text="...", font=big, anchor="w")
    title.pack(fill="x")
    detail = tk.Label(titles, text="", font=normal, anchor="w", justify="left", wraplength=540)
    detail.pack(fill="x")

    grid = tk.Frame(root, padx=14)
    grid.pack(fill="x")
    rows: dict[str, tk.Label] = {}

    table = ttk.Treeview(root, columns=("worker", "task", "model", "time"), show="headings", height=6)
    for col, text, width in (("worker", "Worker", 140), ("task", "Task", 90), ("model", "Model", 200),
                             ("time", "Running", 90)):
        table.heading(col, text=text)
        table.column(col, width=width, anchor="w")
    table.pack(fill="both", expand=True, padx=14, pady=8)

    bar = tk.Frame(root, padx=14, pady=8)
    bar.pack(fill="x")
    message = tk.Label(root, text="", font=("Segoe UI", 9), anchor="w", padx=14, fg="#555555")
    message.pack(fill="x", pady=(0, 6))

    def act(*args: str, confirm: str = ""):
        if confirm and not messagebox.askyesno("Strugglebus host", confirm):
            return
        message.config(text=f"wh {' '.join(args)} ...")
        root.update_idletasks()
        code, out = wh_command(cfg, *args)
        message.config(text=out)
        refresh(reschedule=False)

    pause_btn = ttk.Button(bar, text="Pause", command=lambda: act("resume" if state["paused"] else "pause"))
    pause_btn.pack(side="left")
    ttk.Button(bar, text="Drain", command=lambda: act(
        "drain", confirm="Drain: take no new tasks, let running workers finish, then switch the host off?")).pack(
        side="left", padx=6)
    start_btn = ttk.Button(bar, text="Start", command=lambda: act("start"))
    start_btn.pack(side="left")
    ttk.Button(bar, text="Open logs", command=lambda: os.startfile(cfg.logs_dir)).pack(side="right")  # noqa: S606
    ttk.Button(bar, text="Workers folder", command=lambda: os.startfile(cfg.workers_root)).pack(side="right", padx=6)

    state = {"paused": False, "icon_level": ""}
    icons: dict[str, tk.PhotoImage] = {}

    def icon(level: str) -> tk.PhotoImage:
        """A filled circle in the state's colour: the taskbar shows the state with the window minimised."""
        if level not in icons:
            img = tk.PhotoImage(width=32, height=32)
            colour = COLOURS[level]
            for y in range(32):
                span = [x for x in range(32) if (x - 15.5) ** 2 + (y - 15.5) ** 2 <= 14.5 ** 2]
                if span:
                    img.put(colour, to=(span[0], y, span[-1] + 1, y + 1))
            icons[level] = img
        return icons[level]

    def refresh(reschedule: bool = True):
        view = load(cfg)
        dot.itemconfig(light, fill=COLOURS[view.level])
        if state["icon_level"] != view.level:
            root.iconphoto(True, icon(view.level))
            state["icon_level"] = view.level
        title.config(text=view.title)
        detail.config(text=view.detail)
        root.title(f"{view.title} - Strugglebus host {cfg.host_name}")
        shown = set()
        for i, (name, value) in enumerate(view.facts):
            if name not in rows:
                tk.Label(grid, text=name, font=("Segoe UI", 10, "bold"), anchor="w", width=12).grid(
                    row=i, column=0, sticky="w")
                rows[name] = tk.Label(grid, text="", font=normal, anchor="w", justify="left", wraplength=500)
                rows[name].grid(row=i, column=1, sticky="w")
            rows[name].config(text=value)
            shown.add(name)
        for name, label in rows.items():
            if name not in shown:
                label.config(text="")
        table.delete(*table.get_children())
        for w in view.workers:
            table.insert("", "end", values=w)
        state["paused"] = view.paused
        pause_btn.config(text="Resume" if view.paused else "Pause")
        start_btn.state(["!disabled"] if view.can_start else ["disabled"])
        if reschedule:
            root.after(REFRESH_MS, refresh)

    signers = signing.read_signers(signing.pinned_path())
    message.config(text=f"Signing keys pinned: {len(signers)}" if signers else
                   "Signing keys not pinned yet (install.ps1 -PinSigners, elevated)")
    refresh()
    root.mainloop()
    return 0  # the single-instance mutex goes with the process
