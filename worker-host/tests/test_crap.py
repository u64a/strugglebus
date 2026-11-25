"""tools/crap.py: the score, the gate's rules, and per-function coverage from a coverage.py JSON report."""
import importlib.util
import json
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("crap", ROOT / "tools" / "crap.py")
crap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(crap)


def test_the_score():
    assert crap.crap(1, 1.0) == 1  # simple and tested
    assert crap.crap(10, 0.0) == 110  # complex and untested
    assert crap.crap(10, 1.0) == 10  # complexity alone, when fully tested
    assert crap.crap(6, 0.5) == pytest.approx(6 * 6 * 0.125 + 6)


def s(score, complexity=10, coverage=0.0, line=1):
    return {"crap": score, "complexity": complexity, "coverage": coverage, "line": line}


def test_a_new_function_over_the_threshold_fails():
    failures, _ = crap.gate({"a.py::f": s(31.0), "a.py::g": s(30.0)}, {})
    assert len(failures) == 1 and failures[0].startswith("NEW") and "a.py::f" in failures[0]


def test_a_baselined_function_may_stay_but_not_get_worse():
    base = {"a.py::f": 100.0}
    assert crap.gate({"a.py::f": s(100.0)}, base) == ([], [])
    assert crap.gate({"a.py::f": s(109.0)}, base)[0] == []  # within the margin
    failures, _ = crap.gate({"a.py::f": s(111.0)}, base)
    assert len(failures) == 1 and failures[0].startswith("WORSE")


def test_a_baselined_function_back_under_the_threshold_is_reported_as_improved():
    failures, improved = crap.gate({"a.py::f": s(12.0)}, {"a.py::f": 80.0, "gone.py::h": 50.0})
    assert failures == [] and improved == ["a.py::f: 80.0 -> 12.0"]


def test_scores_use_each_functions_own_lines_and_branches(tmp_path):
    pytest.importorskip("radon")
    (tmp_path / "workerhost").mkdir()
    (tmp_path / "tools").mkdir()
    (tmp_path / "wh.py").write_text("", encoding="utf-8")
    code = textwrap.dedent("""\
        def outer(x):
            if x:
                return 1

            def inner(y):
                if y:
                    return 2
                return 3

            return inner


        class K:
            def m(self):
                return 4
        """)
    (tmp_path / "workerhost" / "mod.py").write_text(code, encoding="utf-8")
    report = {"files": {"workerhost/mod.py": {
        "executed_lines": [1, 2, 3, 5, 10, 13, 14],
        "missing_lines": [6, 7, 8, 15],
        "executed_branches": [[2, 3], [2, 5]],
        "missing_branches": [[6, 7], [6, 8]]}}}
    got = crap.scores(report, tmp_path)
    assert got["workerhost/mod.py::outer"]["coverage"] == 100.0  # inner's lines are not outer's
    # inner: its def line ran (defining it is part of outer's run); its 3 body lines and 2 branches did not: 1 of 6
    assert got["workerhost/mod.py::outer.inner"]["coverage"] == 16.7
    assert got["workerhost/mod.py::outer.inner"]["crap"] == round(crap.crap(2, 1 / 6), 1)
    assert got["workerhost/mod.py::K.m"]["coverage"] == 50.0


def test_a_module_the_tests_never_import_counts_as_untested(tmp_path):
    pytest.importorskip("radon")
    for d in ("workerhost", "tools"):
        (tmp_path / d).mkdir()
    (tmp_path / "wh.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    assert crap.scores({"files": {}}, tmp_path)["wh.py::main"]["coverage"] == 0.0


def test_main_check_report_and_baseline(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(crap, "scores", lambda data: {"a.py::f": s(50.0), "a.py::g": s(5.0, 5, 100.0)})
    cov = tmp_path / "coverage.json"
    cov.write_text("{}", encoding="utf-8")
    base = tmp_path / "baseline.json"
    assert crap.main(["check", str(cov), "--baseline", str(base)]) == 1
    assert "NEW" in capsys.readouterr().out
    assert crap.main(["baseline", str(cov), "--baseline", str(base)]) == 0
    assert json.loads(base.read_text(encoding="utf-8"))["functions"] == {"a.py::f": 50.0}
    assert crap.main(["check", str(cov), "--baseline", str(base)]) == 0
    assert "CRAP gate: ok" in capsys.readouterr().out
    assert crap.main(["report", str(cov)]) == 0
    assert "2 functions; 1 over 30" in capsys.readouterr().out
