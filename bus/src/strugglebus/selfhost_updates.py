"""The automatic-update on/off switch of a self-hosted install.

The bus never updates itself and makes no outbound connection. A root-owned
updater outside the service (a systemd timer, or a script on the Docker host)
checks the public release page, and before installing anything reads one word,
``on`` or ``off``, from a file the bus owns. This module writes that word for
the operator and shows what the updater last reported.

There is no setting for this. The self-host installers create the switch file;
its presence is what tells the bus that an updater exists.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path

from strugglebus import __version__
from strugglebus.operator_lifecycle_rendering import facts, hidden, panel

TOGGLE_PATH = "/operator/updates/automatic"
SWITCH_FILE = Path("selfhost") / "auto-update"
STATUS_FILE = Path("selfhost") / "update-status.json"
_MAXIMUM_STATUS_BYTES = 16 * 1024
_RESULTS = {
    "current": "Up to date",
    "updated": "Updated",
    "off": "Not checked: automatic updates are off",
    "unreachable": "The release page could not be reached",
    "invalid": "The newest release did not pass its checks; nothing was installed",
    "failed": "The update could not be installed; the previous version is running",
}


@dataclass(frozen=True)
class LastCheck:
    checked_at: datetime
    result: str
    latest_version: str
    detail: str


@dataclass(frozen=True)
class SelfHostUpdates:
    status_path: Path
    switch_path: Path

    @classmethod
    def for_install(cls, data_dir: Path) -> SelfHostUpdates:
        return cls(status_path=data_dir / STATUS_FILE, switch_path=data_dir / SWITCH_FILE)

    def available(self) -> bool:
        """True on an install whose installer set up an updater."""
        return self.switch_path.is_file()

    def enabled(self) -> bool:
        """On unless the operator turned it off; the updater reads it the same way."""
        try:
            return self.switch_path.read_bytes()[:8].strip() != b"off"
        except OSError:
            return True

    def set_enabled(self, enabled: bool) -> None:
        temporary = self.switch_path.with_name(self.switch_path.name + ".new")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            stream.write("on\n" if enabled else "off\n")
        os.replace(temporary, self.switch_path)

    def last_check(self) -> LastCheck | None:
        """What the updater last wrote, or None if it has not run or wrote nonsense."""
        try:
            with self.status_path.open("rb") as stream:
                raw = stream.read(_MAXIMUM_STATUS_BYTES + 1)
            if len(raw) > _MAXIMUM_STATUS_BYTES:
                return None
            record = json.loads(raw)
            return LastCheck(
                checked_at=datetime.fromtimestamp(int(record["checked_at"]), UTC),
                result=str(record["result"])[:32],
                latest_version=str(record.get("latest_version", ""))[:32],
                detail=str(record.get("detail", ""))[:500],
            )
        except (OSError, ValueError, KeyError, TypeError, OverflowError):
            return None


def render(updates: SelfHostUpdates, csrf: str) -> str:
    enabled = updates.enabled()
    check = updates.last_check()
    values: dict[str, object] = {
        "Automatic updates": "On" if enabled else "Off",
        "Installed version": __version__,
    }
    if check is None:
        values["Last check"] = "No check has been recorded yet"
    else:
        values["Last check"] = check.checked_at.strftime("%Y-%m-%d %H:%M UTC")
        values["Result"] = _RESULTS.get(check.result, "Unknown")
        if check.latest_version:
            values["Newest release"] = check.latest_version
        if check.detail:
            values["Detail"] = check.detail
    label = "Turn automatic updates off" if enabled else "Turn automatic updates on"
    explanation = (
        "<p>When on, the bus machine checks the public release page once a day and "
        "installs a newer release by itself. It backs up the database first, the "
        "bus is unavailable for about a minute, and if the new version does not "
        "start the previous one is put back.</p>"
        "<p>When off, nothing is checked or installed. To update by hand, follow "
        "<q>Updating</q> in the install guide.</p>"
    )
    if check is None:
        explanation += (
            "<p>No check has run yet. A Proxmox or Debian install checks by itself. "
            "On a Docker host the daily check has to be scheduled once; see "
            "<q>Updating</q> in the install guide.</p>"
        )
    form = (
        f'<form method="post" action="{escape(TOGGLE_PATH, quote=True)}" class="form-stack">'
        f'{hidden("csrf", csrf)}{hidden("enabled", "false" if enabled else "true")}'
        f'<div class="form-actions"><button type="submit">{label}</button></div></form>'
    )
    return panel(
        "Automatic updates", facts(values) + explanation + form,
        description="Whether this bus installs new releases by itself.",
    )
