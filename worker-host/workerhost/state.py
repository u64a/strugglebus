"""state.json (design section 6) and the local control files (section 7).

state.json is written atomically (temp file, then replace) under an inter-process file lock.
`wh` drops one JSON file per command into state\\control\\; the host consumes them in order and writes
state\\status.json after every loop, which is what `wh status` reads.
"""
from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
from pathlib import Path

TERMINAL = {"finished", "failed", "timed-out", "interrupted", "refused", "yielded", "cancelled"}
RUNNING = "started"
RETENTION_SECONDS = 30 * 86400
CONTROL_COMMANDS = {"stop", "drain", "pause", "resume", "status", "set-model", "cleanup", "update-ghcp",
                    "fleet-refresh", "update-check", "update-now"}


def _empty() -> dict:
    return {"version": 1, "cursor": None, "enabled": True, "draining": False, "paused": False, "default_model": None,
            "tasks": {}, "handled": {}, "outbox": [], "host_replies": [], "last_cleanup": 0, "last_ghcp_day": "",
            "ghcp_attempt": 0}


@contextlib.contextmanager
def file_lock(path: Path, timeout: float = 30.0):
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a+b")
    deadline = time.monotonic() + timeout
    try:
        if os.name == "nt":
            import msvcrt
            while True:
                try:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise TimeoutError("state lock busy") from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def atomic_write_json(path: Path, data, attempts: int = 10, wait: float = 0.05) -> None:
    """Write a temp file, then replace. On Windows the replace fails with PermissionError while any
    other process holds the target open without delete sharing (`wh status` reading status.json, an
    antivirus scan, the indexer): retried briefly, then raised to the caller."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    for attempt in range(attempts):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt + 1 >= attempts:
                with contextlib.suppress(OSError):
                    tmp.unlink()
                raise
            time.sleep(wait)


class StateStore:
    def __init__(self, folder: Path):
        self.folder = Path(folder)
        self.path = self.folder / "state.json"
        self.lock_path = self.folder / "state.lock"
        self.data = _empty()

    def load(self) -> dict:
        with file_lock(self.lock_path):
            self.data = self._read()
        return self.data

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return _empty()
        base = _empty()
        base.update(data if isinstance(data, dict) else {})
        return base

    def save(self) -> None:
        self.prune()
        with file_lock(self.lock_path):
            atomic_write_json(self.path, self.data)

    def update(self, fn) -> dict:
        """Read-modify-write under the lock (for `wh` when the host is not running)."""
        with file_lock(self.lock_path):
            self.data = self._read()
            fn(self.data)
            atomic_write_json(self.path, self.data)
        return self.data

    def prune(self, now: float | None = None) -> None:
        now = now or time.time()
        self.data["handled"] = {k: v for k, v in self.data["handled"].items() if now - v < RETENTION_SECONDS}
        self.data["tasks"] = {k: v for k, v in self.data["tasks"].items()
                              if v.get("status") not in TERMINAL or now - v.get("updated", now) < RETENTION_SECONDS}
        self.data["host_replies"] = [r for r in self.data["host_replies"] if now - r.get("ts", 0) < 86400]

    # convenience
    def handled_seqs(self) -> set[int]:
        return {int(k) for k in self.data["handled"]}

    def terminal_task_ids(self) -> set[str]:
        return {k for k, v in self.data["tasks"].items() if v.get("status") in TERMINAL - {"refused", "yielded"}}

    def mark_handled(self, seq: int) -> None:
        self.data["handled"][str(seq)] = time.time()

    def set_task(self, task_id: str, **fields) -> dict:
        rec = self.data["tasks"].setdefault(task_id, {})
        rec.update(fields)
        rec["updated"] = time.time()
        self.save()
        return rec

    def mark_terminal(self, task_id: str, status: str, **fields) -> dict:
        """Persist a terminal status. Called before the matching reply is posted, so a crash between the
        two leaves the task terminal (never `started`) and the start-up sweep cannot re-report it."""
        if status not in TERMINAL:
            raise ValueError(f"not a terminal status: {status}")
        return self.set_task(task_id, status=status, **fields)

    def running_task_ids(self) -> list[str]:
        return [k for k, v in self.data["tasks"].items() if v.get("status") == RUNNING]


# --- control files ------------------------------------------------------------------------------

def send_control(control_dir: Path, cmd: str, **args) -> Path:
    if cmd not in CONTROL_COMMANDS:
        raise ValueError("unknown command")
    control_dir.mkdir(parents=True, exist_ok=True)
    name = f"{time.time_ns():020d}-{uuid.uuid4().hex[:8]}.json"
    path = control_dir / name
    atomic_write_json(path, {"cmd": cmd, "args": args})
    return path


def take_controls(control_dir: Path) -> list[dict]:
    if not control_dir.exists():
        return []
    out = []
    for path in sorted(control_dir.glob("*.json")):
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            obj = None
        with contextlib.suppress(OSError):
            path.unlink()
        if isinstance(obj, dict) and obj.get("cmd") in CONTROL_COMMANDS and isinstance(obj.get("args", {}), dict):
            out.append(obj)
    return out
