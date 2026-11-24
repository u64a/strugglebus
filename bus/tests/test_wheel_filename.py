import importlib.util
from pathlib import Path

import pytest


REPOSITORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_wheel_filename",
    REPOSITORY / "scripts/validate_wheel_filename.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the wheel filename validator")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
validate_wheel_filename = MODULE.validate_wheel_filename


def test_wheel_filename_validator_accepts_distribution_filename() -> None:
    filename = "strugglebus-0.2.0-py3-none-any.whl"
    assert validate_wheel_filename(Path(filename)) == filename


@pytest.mark.parametrize(
    "filename",
    [
        "application.whl",
        "struggle-bus-0.1.0-py3-none-any.whl",
        "other-0.1.0-py3-none-any.whl",
        "strugglebus-0.1.0-py3-none-any-extra.whl",
    ],
)
def test_wheel_filename_validator_rejects_unsafe_names(filename: str) -> None:
    with pytest.raises(RuntimeError):
        validate_wheel_filename(Path(filename))
