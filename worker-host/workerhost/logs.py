"""Host log (design section 13): logs\\host-YYYYMMDD.log, one line per event.

Lines hold fixed event names and key=value pairs. Values are sanitised to a safe character set and
truncated, so no message free text and no secret reaches the log.

Errors: HostLog.error() writes the usual line with the exception type and (sanitised)
message, and appends the redacted traceback as one timestamped block to logs\\host-YYYYMMDD.errors.log.
Writing a log never raises: a full disk or a locked file must not turn into a host crash.
"""
from __future__ import annotations

import re
import time
import traceback
from pathlib import Path

from .redact import redact

SAFE = re.compile(r"[^A-Za-z0-9_.:/@%+=-]")


def clean(value) -> str:
    return SAFE.sub("_", redact(str(value)))[:120]


class HostLog:
    def __init__(self, folder: Path, echo: bool = False):
        self.folder = Path(folder)
        self.echo = echo

    def _append(self, name: str, text: str) -> None:
        try:
            self.folder.mkdir(parents=True, exist_ok=True)
            with open(self.folder / name, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(text)
        except Exception:  # noqa: BLE001 - logging runs inside error handlers and must never raise
            pass

    def __call__(self, event: str, **fields) -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        line = f"{stamp} {clean(event)} " + " ".join(f"{clean(k)}={clean(v)}" for k, v in fields.items())
        self._append(f"host-{time.strftime('%Y%m%d')}.log", line.rstrip() + "\n")
        if self.echo:
            try:
                print(line, flush=True)
            except (OSError, ValueError):
                pass

    def error(self, event: str, exc: BaseException, **fields) -> None:
        """One log line (type and message), one traceback block in the errors file."""
        self(event, error=type(exc).__name__, message=str(exc) or "-", **fields)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        try:
            trace = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        except Exception:  # noqa: BLE001 - formatting must not hide the original error
            trace = f"{type(exc).__name__}: (traceback unavailable)\n"
        block = f"===== {stamp} {clean(event)} {clean(type(exc).__name__)} =====\n{redact(trace).rstrip()}\n\n"
        self._append(f"host-{time.strftime('%Y%m%d')}.errors.log", block)
