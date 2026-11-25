"""Every shipped Python file compiles with no warnings.

An invalid escape such as "\\R" in a docstring is only a SyntaxWarning today, so the tests stay green, but a later
Python makes it a SyntaxError and the module would no longer load. winupdate.py had one (fixed with this test).
"""
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = sorted([*(ROOT / "workerhost").glob("*.py"), *(ROOT / "tools").glob("*.py"), ROOT / "wh.py"])


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_compiles_without_warnings(path):
    source = path.read_text(encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        compile(source, str(path), "exec")
