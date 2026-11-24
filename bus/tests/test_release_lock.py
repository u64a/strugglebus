from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="the production lock helper uses Linux flock and /proc identity",
)
REPOSITORY = Path(__file__).resolve().parents[1]
HELPER = (
    REPOSITORY
    / "deploy/roles/guest_base/files/strugglebus-release-lock.py"
)


def write_metadata(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="ascii")
    path.chmod(0o600)


def run_helper(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HELPER), *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def acquire(root: Path, *, wait: int = 1, lease: int = 10) -> dict[str, object]:
    root.chmod(0o700)
    result = run_helper(
        "acquire",
        "--lock-path",
        str(root / "release.lock"),
        "--metadata-path",
        str(root / "release.json"),
        "--wait-seconds",
        str(wait),
        "--lease-seconds",
        str(lease),
    )
    return json.loads(result.stdout)


def release(root: Path, token: object) -> None:
    run_helper(
        "release",
        "--metadata-path",
        str(root / "release.json"),
        "--token",
        str(token),
    )


def renew(root: Path, token: object, lease: int) -> None:
    run_helper(
        "renew",
        "--metadata-path",
        str(root / "release.json"),
        "--token",
        str(token),
        "--lease-seconds",
        str(lease),
    )


def test_live_owner_contention_times_out_without_takeover(tmp_path: Path) -> None:
    owner = acquire(tmp_path)
    try:
        contender = run_helper(
            "acquire",
            "--lock-path",
            str(tmp_path / "release.lock"),
            "--metadata-path",
            str(tmp_path / "release.json"),
            "--wait-seconds",
            "1",
            "--lease-seconds",
            "10",
            check=False,
        )
        assert contender.returncode == 1
        assert "timed out" in contender.stderr
        assert json.loads((tmp_path / "release.json").read_text()) == owner
    finally:
        release(tmp_path, owner["token"])


def test_valid_stale_owner_metadata_is_recovered(tmp_path: Path) -> None:
    stale = {
        "version": 1,
        "pid": 99999999,
        "start_ticks": 1,
        "token": "a" * 64,
        "lease_seconds": 10,
        "heartbeat_ns": time.monotonic_ns(),
    }
    tmp_path.chmod(0o700)
    write_metadata(tmp_path / "release.json", stale)
    owner = acquire(tmp_path)
    try:
        assert owner["token"] != stale["token"]
    finally:
        release(tmp_path, owner["token"])


@pytest.mark.parametrize(
    "metadata",
    [
        "{",
        json.dumps({"version": 1}),
        json.dumps(
            {
                "version": 1,
                "pid": os.getpid(),
                "start_ticks": "invalid",
                "token": "b" * 64,
                "lease_seconds": 10,
                "heartbeat_ns": time.monotonic_ns(),
            }
        ),
    ],
    ids=["invalid-json", "missing-fields", "invalid-start-ticks"],
)
def test_malformed_metadata_fails_closed(tmp_path: Path, metadata: str) -> None:
    tmp_path.chmod(0o700)
    (tmp_path / "release.json").write_text(metadata, encoding="ascii")
    (tmp_path / "release.json").chmod(0o600)
    result = run_helper(
        "acquire",
        "--lock-path",
        str(tmp_path / "release.lock"),
        "--metadata-path",
        str(tmp_path / "release.json"),
        "--wait-seconds",
        "1",
        "--lease-seconds",
        "10",
        check=False,
    )
    assert result.returncode == 1
    assert (tmp_path / "release.json").read_text(encoding="ascii") == metadata


def test_non_private_metadata_fails_closed(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    write_metadata(
        tmp_path / "release.json",
        {
            "version": 1,
            "pid": 99999999,
            "start_ticks": 1,
            "token": "c" * 64,
            "lease_seconds": 10,
            "heartbeat_ns": time.monotonic_ns(),
        },
    )
    (tmp_path / "release.json").chmod(0o644)
    result = run_helper(
        "acquire",
        "--lock-path",
        str(tmp_path / "release.lock"),
        "--metadata-path",
        str(tmp_path / "release.json"),
        "--wait-seconds",
        "1",
        "--lease-seconds",
        "10",
        check=False,
    )
    assert result.returncode == 1
    assert "owner-only" in result.stderr


def test_lease_releases_lock_after_controller_loss(tmp_path: Path) -> None:
    first = acquire(tmp_path, lease=1)
    deadline = time.monotonic() + 3
    while (tmp_path / "release.json").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not (tmp_path / "release.json").exists()
    second = acquire(tmp_path)
    try:
        assert second["token"] != first["token"]
    finally:
        release(tmp_path, second["token"])


def test_expired_owner_cannot_be_renewed(tmp_path: Path) -> None:
    owner = acquire(tmp_path, lease=1)
    deadline = time.monotonic() + 3
    while (tmp_path / "release.json").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    result = run_helper(
        "renew",
        "--metadata-path",
        str(tmp_path / "release.json"),
        "--token",
        str(owner["token"]),
        "--lease-seconds",
        "1",
        check=False,
    )
    assert result.returncode == 1


def test_stale_releaser_cannot_remove_new_owner_metadata(tmp_path: Path) -> None:
    old_owner = acquire(tmp_path, lease=1)
    deadline = time.monotonic() + 3
    while (tmp_path / "release.json").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    new_owner = acquire(tmp_path)
    try:
        stale_release = run_helper(
            "release",
            "--metadata-path",
            str(tmp_path / "release.json"),
            "--token",
            str(old_owner["token"]),
            check=False,
        )
        assert stale_release.returncode == 1
        assert json.loads((tmp_path / "release.json").read_text()) == new_owner
    finally:
        release(tmp_path, new_owner["token"])


def test_heartbeat_keeps_an_active_owner_live(tmp_path: Path) -> None:
    owner = acquire(tmp_path, lease=3)
    try:
        time.sleep(1.5)
        renew(tmp_path, owner["token"], 3)
        time.sleep(1.0)
        assert (tmp_path / "release.json").exists()
        contender = run_helper(
            "acquire",
            "--lock-path",
            str(tmp_path / "release.lock"),
            "--metadata-path",
            str(tmp_path / "release.json"),
            "--wait-seconds",
            "1",
            "--lease-seconds",
            "10",
            check=False,
        )
        assert contender.returncode == 1
    finally:
        release(tmp_path, owner["token"])


def test_wrong_owner_cannot_release_live_lock(tmp_path: Path) -> None:
    owner = acquire(tmp_path)
    try:
        result = run_helper(
            "release",
            "--metadata-path",
            str(tmp_path / "release.json"),
            "--token",
            "f" * 64,
            check=False,
        )
        assert result.returncode == 1
        assert (tmp_path / "release.json").exists()
    finally:
        release(tmp_path, owner["token"])
