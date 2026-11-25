"""GHCP update (#18): never deletes in the shared Links folder, skips when the live CLI is newer than
winget, keeps a binary that still answers and restores a missing one by copy-back."""
from __future__ import annotations

from pathlib import Path

import pytest

from workerhost import ghcp

LIVE = "1.0.95-3"
WINGET_ID = "GitHub.Copilot"
# The dev box's real `winget list --id GitHub.Copilot --exact`: v-prefixed versions, a Name with a space.
REAL_WINGET_LIST = ("Name        Id             Version Available Source\r\n"
                    "--------------------------------------------------\r\n"
                    "Copilot CLI GitHub.Copilot v1.0.80 v1.0.94 winget\r\n")


def winget_list(installed: str, available: str | None) -> str:
    if available is None:
        return ("\r-\r\\\rName           Id             Version Source\r\n"
                "---------------------------------------------\r\n"
                f"GitHub Copilot {WINGET_ID} {installed}  winget\r\n")
    return ("\r-\r\\\rName           Id             Version Available Source\r\n"
            "-------------------------------------------------------\r\n"
            f"GitHub Copilot {WINGET_ID} {installed}  {available}    winget\r\n")


@pytest.fixture
def links(tmp_path) -> Path:
    d = tmp_path / "Links"
    d.mkdir()
    (d / "copilot.exe").write_bytes(b"copilot " + LIVE.encode())
    (d / "copilot.exe.old-1-1").write_bytes(b"old copilot")
    (d / ".copilot-update-1").write_bytes(b"marker")
    (d / "terraform.exe").write_bytes(b"terraform")
    return d


class FakeRunner:
    """copilot answers while copilot.exe exists (its content holds the version); winget is scripted."""

    def __init__(self, exe: Path, available: str | None, upgrade_code: int, remove_on_upgrade: bool,
                 new_version: str | None = None, list_output: str | None = None):
        self.exe, self.available, self.upgrade_code = exe, available, upgrade_code
        self.remove_on_upgrade, self.new_version = remove_on_upgrade, new_version
        self.list_output = list_output
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], timeout: float) -> tuple[int, str]:
        self.calls.append(cmd)
        if cmd[0] == "winget" and cmd[1] == "list":
            if self.list_output is not None:
                return 0, self.list_output
            return 0, winget_list("1.0.80", self.available)
        if cmd[0] == "winget" and cmd[1] == "upgrade":
            if self.remove_on_upgrade:
                self.exe.unlink()
            elif self.new_version:
                self.exe.write_bytes(b"copilot " + self.new_version.encode())
            return self.upgrade_code, ""
        if not self.exe.is_file():
            return 1, ""
        if cmd[1] == "--version":
            return 0, self.exe.read_bytes().decode().split()[1] + "\n"
        if cmd[1] == "--help":
            return 0, "usage: copilot -p, --prompt <text>\n"
        return 1, ""

    def upgraded(self) -> bool:
        return any(c[:2] == ["winget", "upgrade"] for c in self.calls)


def snapshot(d: Path) -> dict[str, tuple[bytes, int]]:
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in d.iterdir()}


def test_failed_winget_that_removes_the_binary_is_restored_by_copy_back(links, tmp_path):
    before = snapshot(links)
    run = FakeRunner(links / "copilot.exe", available="1.0.96", upgrade_code=2316632151, remove_on_upgrade=True)
    result = ghcp.update(str(links / "copilot.exe"), tmp_path / "backup", WINGET_ID, run)
    assert not result.ok
    assert result.line == f"ghcp update: failed (exit 2316632151), kept {LIVE}"
    assert (links / "copilot.exe").read_bytes() == before["copilot.exe"][0]
    after = snapshot(links)
    for name in ("terraform.exe", "copilot.exe.old-1-1", ".copilot-update-1"):
        assert after[name] == before[name]
    assert sorted(p.name for p in (tmp_path / "backup" / LIVE).iterdir()) == ["copilot.exe"]


def test_winget_older_than_live_is_skipped_and_nothing_is_touched(links, tmp_path):
    before = snapshot(links)
    run = FakeRunner(links / "copilot.exe", available="1.0.94", upgrade_code=0, remove_on_upgrade=True)
    result = ghcp.update(str(links / "copilot.exe"), tmp_path / "backup", WINGET_ID, run)
    assert result.ok and result.after == LIVE
    assert result.line == f"ghcp update: {LIVE} newer than winget 1.0.94, skipped"
    assert not run.upgraded()
    assert snapshot(links) == before
    assert not (tmp_path / "backup").exists()


def test_failed_winget_with_a_working_binary_keeps_it_without_copy_back(links, tmp_path, monkeypatch):
    before = snapshot(links)
    run = FakeRunner(links / "copilot.exe", available="1.0.96", upgrade_code=1, remove_on_upgrade=False)
    copies: list[tuple[str, str]] = []
    real_copy2 = ghcp.shutil.copy2
    monkeypatch.setattr(ghcp.shutil, "copy2", lambda s, d: copies.append((str(s), str(d))) or real_copy2(s, d))
    result = ghcp.update(str(links / "copilot.exe"), tmp_path / "backup", WINGET_ID, run)
    assert not result.ok and result.line == f"ghcp update: failed (exit 1), kept {LIVE}"
    assert run.upgraded()
    assert all(Path(d).parent != links for _, d in copies)  # only the backup was written
    assert snapshot(links) == before


def test_successful_upgrade_reports_the_new_version(links, tmp_path):
    run = FakeRunner(links / "copilot.exe", available="1.0.96", upgrade_code=0, remove_on_upgrade=False,
                     new_version="1.0.96")
    result = ghcp.update(str(links / "copilot.exe"), tmp_path / "backup", WINGET_ID, run)
    assert result.ok and result.line == f"ghcp update: {LIVE} -> 1.0.96 ok"
    assert (links / "terraform.exe").read_bytes() == b"terraform"


@pytest.mark.parametrize("out,expected", [
    (winget_list("1.0.80", "1.0.94"), "1.0.94"),
    (winget_list("1.0.80", None), None),
    ("No installed package found matching input criteria.\r\n", None),
    (REAL_WINGET_LIST, "1.0.94"),
    (REAL_WINGET_LIST.replace(" v1.0.80 v1.0.94 ", " V1.0.80 V1.0.94 "), "1.0.94"),
])
def test_winget_available_parses_the_available_column(out, expected):
    assert ghcp.winget_available(WINGET_ID, lambda cmd, t: (0, out)) == expected


def test_real_v_prefixed_winget_line_with_newer_live_cli_skips_the_upgrade(links, tmp_path):
    before = snapshot(links)
    run = FakeRunner(links / "copilot.exe", available=None, upgrade_code=0, remove_on_upgrade=True,
                     list_output=REAL_WINGET_LIST)
    result = ghcp.update(str(links / "copilot.exe"), tmp_path / "backup", WINGET_ID, run)
    assert result.ok and result.after == LIVE
    assert result.line == f"ghcp update: {LIVE} newer than winget 1.0.94, skipped"
    assert not run.upgraded()
    assert snapshot(links) == before


def test_version_key_orders_self_update_builds_above_their_base():
    assert ghcp.version_key("1.0.95-3") > ghcp.version_key("1.0.94")
    assert ghcp.version_key("1.0.95-3") > ghcp.version_key("1.0.95")
    assert ghcp.version_key("1.0.100") > ghcp.version_key("1.0.95-3")
