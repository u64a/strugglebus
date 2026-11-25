"""Resources (design section 5): checked before claiming and again before starting.

check() returns None or (reason, numbers). The numbers are this host's own measurements and limits;
nothing from a message is ever part of a refusal.
"""
from __future__ import annotations

import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import winapi
from .config import Resources

GB = 1024 ** 3


@dataclass
class Sample:
    commit_limit: int
    committed: int
    free_phys: int
    total_phys: int
    free_disk: int
    processes: set[str] = field(default_factory=set)

    @property
    def commit_pct(self) -> float:
        return 100.0 * self.committed / self.commit_limit if self.commit_limit else 100.0


def sample(workers_root: Path) -> Sample:
    mem = winapi.memory()
    root = Path(workers_root)
    probe = root if root.exists() else Path(root.anchor or ".")
    disk = shutil.disk_usage(probe)
    return Sample(mem["commit_limit"], mem["committed"], mem["free_phys"], mem["total_phys"], disk.free,
                  winapi.process_names())


def check(s: Sample, r: Resources, active: int) -> tuple[str, dict] | None:
    """active = running workers plus reservations (claims in flight) on this host."""
    if active >= r.max_workers:
        return "workers", {"workers": active, "limit": r.max_workers}
    worker = r.worker_commit_gb * GB
    pct = round(100.0 * (s.committed + worker) / s.commit_limit, 1) if s.commit_limit else 100.0
    if pct > r.max_commit_pct:
        return "commit", {"commit_pct": pct, "limit": r.max_commit_pct}
    ram = round((s.free_phys - worker) / GB, 1)
    if ram < r.min_free_ram_gb:
        return "ram", {"ram_free_gb": ram, "limit": r.min_free_ram_gb}
    disk = round(s.free_disk / GB, 1)
    if disk < r.min_free_disk_gb:
        return "disk", {"disk_free_gb": disk, "limit": r.min_free_disk_gb}
    return None


def game_running(s: Sample, names: list[str]) -> bool:
    wanted = {n.lower() if n.lower().endswith(".exe") else n.lower() + ".exe" for n in names}
    return bool(wanted & s.processes)


class Guard:
    """As memory_guard.ps1: two samples at least a minute apart over the line trip it; one under resets."""

    def __init__(self, r: Resources, clock=time.monotonic):
        self.r = r
        self.clock = clock
        self.first_over: float | None = None
        self.tripped = False

    def update(self, s: Sample) -> bool:
        over = s.commit_pct >= self.r.guard_commit_pct or s.free_phys / GB < self.r.guard_free_gb
        now = self.clock()
        if not over:
            self.first_over, self.tripped = None, False
        elif self.first_over is None:
            self.first_over = now
        elif now - self.first_over >= 60:
            self.tripped = True
        return self.tripped
