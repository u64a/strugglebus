from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest


REPOSITORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_clean_install",
    REPOSITORY / "scripts/validate_clean_install.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the clean-install validator")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize(
    ("major", "minor", "expected"),
    [
        pytest.param(3, 13, "3.13", id="system-python-3.13"),
    ],
)
def test_clean_install_validator_accepts_requested_supported_interpreter(
    monkeypatch: pytest.MonkeyPatch,
    major: int,
    minor: int,
    expected: str,
) -> None:
    monkeypatch.setattr(
        MODULE.sys,
        "version_info",
        SimpleNamespace(major=major, minor=minor),
    )

    MODULE._validate_python_version(expected)


def test_clean_install_validator_rejects_wrong_actual_interpreter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(MODULE.sys, "version_info", SimpleNamespace(major=3, minor=13))

    with pytest.raises(
        RuntimeError,
        match=r"wrong Python version: expected 3\.12, found 3\.13",
    ):
        MODULE._validate_python_version("3.12")


def test_clean_install_validator_rejects_unsupported_interpreter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        MODULE.sys,
        "version_info",
        SimpleNamespace(major=3, minor=12),
    )

    with pytest.raises(RuntimeError, match="requires Python 3.13"):
        MODULE._validate_python_version("3.13")


def test_clean_install_validator_requires_expected_python_argument() -> None:
    with pytest.raises(SystemExit):
        MODULE._parser().parse_args(
            [
                "--wheel",
                "strugglebus.whl",
                "--requirements",
                "requirements.lock",
            ]
        )


def test_expected_schema_version_matches_every_declaration() -> None:
    """The wheel, the release manifest, and this validator must agree.

    A version bump that moved only one of these previously failed late, inside
    the deployment-validation job, instead of in the test suite.
    """
    from strugglebus.migrations import LATEST_SCHEMA_VERSION
    from strugglebus.integration import GUIDE_VERSION

    # Read the installed verifier policy without importing any candidate code.
    source = (REPOSITORY / "src/strugglebus/release_validation.py").read_text(encoding="utf-8")
    declared = {
        name: int(re.search(rf"^{name} = ([0-9]+)$", source, re.MULTILINE).group(1))
        for name in ("CURRENT_SCHEMA", "ROLLBACK_PREVIOUS_SCHEMA")
    }
    declared_guide = re.search(
        r'^GUIDE_VERSION = "([0-9.]+)"$', source, re.MULTILINE
    ).group(1)

    assert MODULE.EXPECTED_SCHEMA_VERSION == LATEST_SCHEMA_VERSION
    assert declared["CURRENT_SCHEMA"] == LATEST_SCHEMA_VERSION
    assert declared["ROLLBACK_PREVIOUS_SCHEMA"] == LATEST_SCHEMA_VERSION - 1
    assert MODULE.EXPECTED_GUIDE_VERSION == GUIDE_VERSION
    assert declared_guide == GUIDE_VERSION


def test_release_role_expected_schema_tracks_the_package() -> None:
    """The deployment role validates the release manifest's declared schema.

    This literal previously lagged a schema bump and only failed during a live
    deployment, after the release had already been published.
    """
    from strugglebus.migrations import LATEST_SCHEMA_VERSION

    resolver = (
        REPOSITORY / "deploy/roles/release/tasks/resolve_release_assets.yml"
    ).read_text(encoding="utf-8")
    declared = re.search(
        r'- --expected-current-schema\s*\n\s*- "([0-9]+)"', resolver
    )
    assert declared is not None
    assert int(declared.group(1)) == LATEST_SCHEMA_VERSION


def test_minimal_database_operation_tracks_the_default_channels() -> None:
    """The installed-service check pins the default channel list by name."""
    from strugglebus.service import DEFAULT_CHANNELS

    source = (REPOSITORY / "scripts/validate_clean_install.py").read_text(
        encoding="utf-8"
    )
    pinned = re.search(
        r'for channel in channels\] != \[(.*?)\]', source, re.DOTALL
    )
    assert pinned is not None
    assert re.findall(r'"([^"]+)"', pinned.group(1)) == sorted(
        name for name, _ in DEFAULT_CHANNELS
    )