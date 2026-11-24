from __future__ import annotations

import json
import textwrap

import pytest

from release_fixtures import load_script


GATE = load_script("quality_gate")

SOURCE = textwrap.dedent("""\
    def simple():
        return 1


    def branchy(a, b, c, d):
        if a:
            return 1
        if b:
            return 2
        if c:
            return 3
        if d:
            return 4
        return 5


    class Thing:
        def method(self, flag):
            if flag:
                return 1
            return 2
""")


def _repo(tmp_path, report_files):
    package = tmp_path / "src" / "strugglebus"
    package.mkdir(parents=True)
    (package / "sample.py").write_text(SOURCE, encoding="utf-8")
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"files": report_files}), encoding="utf-8")
    return report


def _lines(executed, missing):
    return {"executed_lines": executed, "missing_lines": missing}


def test_crap_is_complexity_when_fully_covered_and_grows_when_not():
    assert GATE.crap(5, 1.0) == 5
    assert GATE.crap(5, 0.0) == 30
    assert GATE.crap(10, 0.5) == 22.5


def test_functions_and_methods_are_each_measured_once():
    rows = GATE.measure_file(SOURCE, "src/strugglebus/sample.py", _lines(list(range(1, 22)), []))

    assert [(row.name, row.complexity, row.coverage) for row in rows] == [
        ("simple", 1, 1.0), ("branchy", 5, 1.0), ("Thing.method", 2, 1.0),
    ]


def test_coverage_is_the_share_of_a_functions_own_measured_lines():
    rows = GATE.measure_file(SOURCE, "src/strugglebus/sample.py", _lines([5, 6, 7, 8], [9, 10, 11, 12, 13, 14]))
    branchy = next(row for row in rows if row.name == "branchy")

    assert branchy.coverage == pytest.approx(0.4)
    assert branchy.crap == pytest.approx(25 * 0.6**3 + 5)
    # A function with no measured lines of its own has nothing left to cover.
    assert next(row for row in rows if row.name == "simple").coverage == 1.0


def test_a_file_missing_from_the_report_counts_as_not_run():
    rows = GATE.measure_file(SOURCE, "src/strugglebus/sample.py", None)

    assert {row.coverage for row in rows} == {0.0}


def test_a_covered_codebase_passes(tmp_path, capsys):
    report = _repo(tmp_path, {"src\\strugglebus\\sample.py": _lines(list(range(1, 22)), [])})

    assert GATE.main([str(report), "--root", str(tmp_path)]) == 0
    assert "passed" in capsys.readouterr().out


def test_an_untested_complex_function_fails_and_is_named(tmp_path, capsys):
    report = _repo(tmp_path, {"src/strugglebus/sample.py": _lines([1, 2, 17, 18, 19, 20, 21], list(range(5, 15)))})

    assert GATE.main([str(report), "--root", str(tmp_path)]) == 1
    error = capsys.readouterr().err
    assert "src/strugglebus/sample.py:5 branchy: CRAP 30.0 (complexity 5, coverage 0%)" in error
    assert "line coverage is 41.2%, below 85%" in error


def test_low_total_coverage_fails_even_when_every_function_is_simple(tmp_path, capsys):
    report = _repo(tmp_path, {"src/strugglebus/sample.py": _lines([1, 2], [18, 19, 20, 21])})

    assert GATE.main([str(report), "--root", str(tmp_path), "--max-crap", "100"]) == 1
    assert "line coverage is 33.3%" in capsys.readouterr().err


def test_limits_can_be_changed_from_the_command_line(tmp_path):
    report = _repo(tmp_path, {"src/strugglebus/sample.py": _lines([1, 2, 17, 18, 19, 20, 21], list(range(5, 15)))})

    assert GATE.main([str(report), "--root", str(tmp_path), "--max-crap", "31", "--min-coverage", "40"]) == 0


def test_an_empty_package_or_report_is_an_error_not_a_pass(tmp_path):
    report = _repo(tmp_path, {})
    with pytest.raises(ValueError, match="measured no lines"):
        GATE.measure(tmp_path, json.loads(report.read_text(encoding="utf-8")))
    (tmp_path / "src" / "strugglebus" / "sample.py").unlink()
    with pytest.raises(ValueError, match="no functions"):
        GATE.measure(tmp_path, {"files": {}})
