from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

import pytest


if sys.platform != "linux":
    pytest.skip(
        "the production validator enforces Linux ownership and mode semantics",
        allow_module_level=True,
    )

import pwd


REPOSITORY = Path(__file__).resolve().parents[1]
HELPER = (
    REPOSITORY
    / "deploy/roles/guest_base/files/strugglebus-validate-release.py"
)
SPEC = importlib.util.spec_from_file_location("release_validator", HELPER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the release validator")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ReleaseValidationError = MODULE.ReleaseValidationError
validate_release = MODULE.validate_release


WHEEL_NAME = "strugglebus-0.2.0-py3-none-any.whl"


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def create_valid_release(root: Path, name: str = "valid") -> Path:
    root.chmod(0o750)
    release = root / name
    (release / "venv/bin").mkdir(parents=True)
    release.chmod(0o750)
    (release / "venv").chmod(0o750)
    (release / "venv/bin").chmod(0o750)
    wheel_content = b"offline wheel"
    lock_content = b"offline lock"
    (release / WHEEL_NAME).write_bytes(wheel_content)
    (release / "requirements.lock").write_bytes(lock_content)
    (release / "release.env").write_text(
        f"STRUGGLEBUS_RELEASE_ID={name}\n",
        encoding="ascii",
    )
    (release / WHEEL_NAME).chmod(0o640)
    (release / "requirements.lock").chmod(0o640)
    (release / "release.env").chmod(0o640)
    (release / "venv/bin/python").symlink_to("/usr/bin/python3")
    service_entry_point = release / "venv/bin/strugglebus"
    service_entry_point.write_text("#!/bin/sh\n", encoding="ascii")
    service_entry_point.chmod(0o750)
    (release / ".installed").write_text(
        f"wheel_filename={WHEEL_NAME}\n"
        f"wheel_sha256={digest(wheel_content)}\n"
        f"requirements_lock_sha256={digest(lock_content)}\n",
        encoding="ascii",
    )
    (release / ".installed").chmod(0o640)
    return release


def test_valid_rollback_target_is_accepted(tmp_path: Path) -> None:
    create_valid_release(tmp_path)
    marker = validate_release(tmp_path, "valid")
    assert marker["wheel_filename"] == WHEEL_NAME
    assert "agent_access_freeze" not in marker


def test_capable_marker_requires_matching_runtime_capability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release = create_valid_release(tmp_path)
    marker_path = release / ".installed"
    marker_path.write_text(
        marker_path.read_text(encoding="ascii")
        + "agent_access_freeze=global-v1\n",
        encoding="ascii",
    )
    monkeypatch.setattr(
        MODULE,
        "probe_service_access",
        lambda *args, **kwargs: "global-v1",
    )

    marker = validate_release(tmp_path, "valid")

    assert marker["agent_access_freeze"] == "global-v1"


def test_capable_marker_runtime_mismatch_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release = create_valid_release(tmp_path)
    marker_path = release / ".installed"
    marker_path.write_text(
        marker_path.read_text(encoding="ascii")
        + "agent_access_freeze=global-v1\n",
        encoding="ascii",
    )
    monkeypatch.setattr(MODULE, "probe_service_access", lambda *args, **kwargs: None)

    with pytest.raises(ReleaseValidationError, match="does not match"):
        validate_release(tmp_path, "valid")


@pytest.mark.parametrize(
    "capability_line",
    [
        "agent_access_freeze=unknown\n",
        "agent_access_freeze=global-v1\nagent_access_freeze=global-v1\n",
    ],
)
def test_unknown_or_duplicate_marker_capability_is_rejected(
    tmp_path: Path,
    capability_line: str,
) -> None:
    release = create_valid_release(tmp_path)
    marker_path = release / ".installed"
    marker_path.write_text(
        marker_path.read_text(encoding="ascii") + capability_line,
        encoding="ascii",
    )

    with pytest.raises(ReleaseValidationError):
        validate_release(tmp_path, "valid")


def test_legacy_rollback_target_without_release_identity_is_accepted(
    tmp_path: Path,
) -> None:
    release = create_valid_release(tmp_path)
    (release / "release.env").unlink()

    marker = validate_release(tmp_path, "valid")

    assert marker["wheel_filename"] == WHEEL_NAME
    with pytest.raises(ReleaseValidationError, match="release environment is missing"):
        validate_release(tmp_path, "valid", require_release_id=True)


def test_current_live_partial_shape_is_rejected(tmp_path: Path) -> None:
    release = tmp_path / "partial"
    (release / "venv/bin").mkdir(parents=True)
    (release / "application.whl").write_bytes(b"failed upload")
    (release / "requirements.lock").write_bytes(b"offline lock")
    (release / "venv/bin/strugglebus").write_text("", encoding="ascii")
    with pytest.raises(ReleaseValidationError):
        validate_release(tmp_path, "partial")


@pytest.mark.parametrize(
    "artifact",
    [WHEEL_NAME, "requirements.lock", "release.env", ".installed"],
)
def test_tampered_artifact_or_marker_is_rejected(
    tmp_path: Path,
    artifact: str,
) -> None:
    release = create_valid_release(tmp_path)
    with (release / artifact).open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ReleaseValidationError):
        validate_release(tmp_path, "valid")


def test_extra_conflicting_wheel_is_rejected(tmp_path: Path) -> None:
    release = create_valid_release(tmp_path)
    (release / "other-1.0-py3-none-any.whl").write_bytes(b"other")
    with pytest.raises(ReleaseValidationError):
        validate_release(tmp_path, "valid")


def test_invalid_wheel_filename_is_rejected(tmp_path: Path) -> None:
    release = create_valid_release(tmp_path)
    original = release / WHEEL_NAME
    invalid = release / "application.whl"
    original.rename(invalid)
    marker = release / ".installed"
    marker.write_text(
        marker.read_text(encoding="ascii").replace(WHEEL_NAME, invalid.name),
        encoding="ascii",
    )
    with pytest.raises(ReleaseValidationError):
        validate_release(tmp_path, "valid")


def test_symlink_release_target_is_rejected(tmp_path: Path) -> None:
    create_valid_release(tmp_path, "real")
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(ReleaseValidationError):
        validate_release(tmp_path, "linked")


@pytest.mark.parametrize(
    "artifact",
    [WHEEL_NAME, "requirements.lock", "release.env", ".installed"],
)
def test_symlink_release_artifact_is_rejected(
    tmp_path: Path,
    artifact: str,
) -> None:
    release = create_valid_release(tmp_path)
    target = release / artifact
    content = target.read_bytes()
    target.unlink()
    replacement = tmp_path / f"{artifact}.target"
    replacement.write_bytes(content)
    target.symlink_to(replacement)
    with pytest.raises(ReleaseValidationError):
        validate_release(tmp_path, "valid")


def test_symlink_venv_executable_is_rejected(tmp_path: Path) -> None:
    release = create_valid_release(tmp_path)
    service_entry_point = release / "venv/bin/strugglebus"
    service_entry_point.unlink()
    service_entry_point.symlink_to(Path(os.devnull))
    with pytest.raises(ReleaseValidationError):
        validate_release(tmp_path, "valid")


def test_missing_release_interpreter_is_rejected(tmp_path: Path) -> None:
    release = create_valid_release(tmp_path)
    (release / "venv/bin/python").unlink()
    with pytest.raises(ReleaseValidationError):
        validate_release(tmp_path, "valid")


def create_nobody_accessible_release() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    temporary = tempfile.TemporaryDirectory(prefix="strugglebus-validator-", dir="/tmp")
    root = Path(temporary.name)
    release = create_valid_release(root)
    (release / "venv/bin/python").unlink()
    (release / "venv/bin/python").symlink_to("/usr/bin/python3")
    for directory in (root, release, release / "venv", release / "venv/bin"):
        directory.chmod(0o755)
    for artifact in (WHEEL_NAME, "requirements.lock", "release.env", ".installed"):
        (release / artifact).chmod(0o644)
    (release / "venv/bin/strugglebus").chmod(0o755)
    return temporary, release


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a distinct service UID")
def test_accessible_release_is_accepted_for_distinct_service_identity() -> None:
    service_user = "nobody"
    try:
        pwd.getpwnam(service_user)
    except KeyError:
        pytest.skip("nobody service identity is unavailable")
    temporary, release = create_nobody_accessible_release()
    try:
        validate_release(release.parent, release.name, service_user, "json")
    finally:
        temporary.cleanup()


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a distinct service UID")
@pytest.mark.parametrize(
    "relative_path",
    [".", "valid", "valid/venv", "valid/venv/bin"],
)
def test_root_only_directory_is_rejected_for_service_identity(
    relative_path: str,
) -> None:
    service_user = "nobody"
    try:
        pwd.getpwnam(service_user)
    except KeyError:
        pytest.skip("nobody service identity is unavailable")
    temporary, release = create_nobody_accessible_release()
    try:
        target = (
            release.parent
            if relative_path == "."
            else release.parent / relative_path
        )
        target.chmod(0o700)
        with pytest.raises(ReleaseValidationError, match="service identity"):
            validate_release(release.parent, release.name, service_user, "json")
    finally:
        temporary.cleanup()


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a distinct service UID")
def test_inaccessible_group_path_is_rejected_for_service_identity(
) -> None:
    service_user = "nobody"
    try:
        pwd.getpwnam(service_user)
    except KeyError:
        pytest.skip("nobody service identity is unavailable")
    temporary, release = create_nobody_accessible_release()
    try:
        release.chmod(0o750)
        with pytest.raises(ReleaseValidationError, match="service identity"):
            validate_release(release.parent, release.name, service_user, "json")
    finally:
        temporary.cleanup()


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a distinct service UID")
def test_root_only_service_entry_point_is_rejected_for_service_identity() -> None:
    service_user = "nobody"
    try:
        pwd.getpwnam(service_user)
    except KeyError:
        pytest.skip("nobody service identity is unavailable")
    temporary, release = create_nobody_accessible_release()
    try:
        (release / "venv/bin/strugglebus").chmod(0o700)
        with pytest.raises(ReleaseValidationError, match="service identity"):
            validate_release(release.parent, release.name, service_user, "json")
    finally:
        temporary.cleanup()
