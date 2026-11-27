import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tomllib

import pytest

from strugglebus import __version__


REPOSITORY = Path(__file__).resolve().parents[1]
VALID_HASH = "a" * 64
SPEC = importlib.util.spec_from_file_location(
    "validate_requirements_lock",
    REPOSITORY / "scripts/validate_requirements_lock.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the requirements lock validator")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
validate_requirements_lock = MODULE.validate_requirements_lock


def test_tracked_production_lock_is_fully_hashed_and_pinned() -> None:
    assert validate_requirements_lock(REPOSITORY / "requirements.lock") > 0


def test_package_version_has_one_canonical_source() -> None:
    with (REPOSITORY / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)

    assert __version__ == "0.2.74"
    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "strugglebus.__version__"
    }
    assert project["tool"]["uv"]["cache-keys"] == [
        {"file": "pyproject.toml"},
        {"file": "src/strugglebus/__init__.py"},
    ]


def test_application_exports_release_freeze_capability() -> None:
    module = ast.parse(
        (REPOSITORY / "src/strugglebus/app.py").read_text(encoding="utf-8")
    )
    access_imports = {
        alias.name
        for node in module.body
        if isinstance(node, ast.ImportFrom) and node.module == "strugglebus.access"
        for alias in node.names
    }

    assert "ACCESS_FREEZE_CAPABILITY" in access_imports


def test_application_import_prints_only_the_freeze_capability() -> None:
    # Deployed updaters run exactly this probe and read stdout and stderr
    # together; any warning printed on import makes them refuse the release.
    environment = {"LANG": "C", "PYTHONNOUSERSITE": "1"}
    if "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import importlib,sys;"
                "module=importlib.import_module(sys.argv[1]);"
                "value=getattr(module,'ACCESS_FREEZE_CAPABILITY',None);"
                "print('' if value is None else value)"
            ),
            "strugglebus.app",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.decode().strip() == "global-v1"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("example==1.0\n", "missing a SHA-256 hash"),
        (f"example>=1.0 \\\n    --hash=sha256:{VALID_HASH}\n", "not exactly pinned"),
        (f"-e . \\\n    --hash=sha256:{VALID_HASH}\n", "local, editable, or URL"),
        (
            f"example @ file:///tmp/example.whl \\\n"
            f"    --hash=sha256:{VALID_HASH}\n",
            "local, editable, or URL",
        ),
        ("example==1.0 \\\n    --hash=sha256:not-a-hash\n", "invalid hash"),
    ],
)
def test_dependency_lock_validator_rejects_unsafe_entries(
    tmp_path: Path,
    content: str,
    message: str,
) -> None:
    lock = tmp_path / "requirements.lock"
    lock.write_text(content, encoding="utf-8")

    with pytest.raises(RuntimeError, match=message):
        validate_requirements_lock(lock)
