from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from release_fixtures import load_script


METRICS = load_script("quality_baseline")


@pytest.mark.parametrize(
    ("complexity", "coverage", "expected"),
    [(10, 0, 110), (10, 1, 10), (10, 0.5, 22.5), (1, 0, 2)],
)
def test_crap_known_values(complexity, coverage, expected):
    assert METRICS.crap(complexity, coverage) == expected


@pytest.mark.parametrize("coverage", [-0.01, 1.01, float("nan"), float("inf")])
def test_crap_rejects_invalid_coverage(coverage):
    with pytest.raises(ValueError):
        METRICS.crap(1, coverage)


def test_crap_rejects_invalid_complexity():
    with pytest.raises(ValueError):
        METRICS.crap(0, 1)


SOURCE = textwrap.dedent("""\
    def outer(value):
        def inner(flag):
            if flag:
                return 1
            return 2
        return inner(value)

    class Box:
        @property
        def value(self):
            return 1

        @value.setter
        def value(self, new):
            self.new = new

    async def asynchronous(flag):
        return 1 if flag else 2

    def branchless():
        return 3

    def unused():
        return 4

    if False:
        def conditional():
            return 5
    else:
        def alternative():
            return 6

    def decorated(flag):
        @((lambda fn: fn) if flag else (lambda fn: fn))
        def child():
            return 7
        return child()

    def local_class():
        class Local:
            def method(self):
                return 8
        return Local().method()
""")


@pytest.fixture
def measured(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(SOURCE, encoding="utf-8")
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import sample\n"
        "import asyncio\n"
        "sample.outer(True)\n"
        "box = sample.Box()\n"
        "box.value\n"
        "asyncio.run(sample.asynchronous(True))\n"
        "sample.branchless()\n"
        "sample.alternative()\n"
        "sample.decorated(True)\n"
        "sample.local_class()\n",
        encoding="utf-8",
    )
    output = tmp_path / "coverage.json"
    env = {**os.environ, "COVERAGE_FILE": str(tmp_path / ".coverage")}
    subprocess.run(
        [sys.executable, "-m", "coverage", "run", "--rcfile=", "--branch",
         f"--source={tmp_path}", str(driver)],
        cwd=tmp_path, env=env, check=True, capture_output=True, text=True,
    )
    subprocess.run(
        [sys.executable, "-m", "coverage", "json", "--rcfile=", "-o", str(output)],
        cwd=tmp_path, env=env, check=True, capture_output=True, text=True,
    )
    report = json.loads(output.read_text(encoding="utf-8"))
    return METRICS.measure_file(SOURCE, report["files"]["sample.py"])


def test_real_coverage_maps_closures_without_double_counting(measured):
    by_name = {row["name"]: row for row in measured}
    outer = by_name["outer"]
    inner = by_name["outer.inner"]
    assert (outer["complexity"], outer["coverage"], outer["crap"]) == (1, 1, 1)
    assert outer["statements"] == 2
    assert inner["complexity"] == 2
    assert inner["branches"] == 2
    assert inner["covered_branches"] == 1
    assert inner["coverage"] == 0.5
    assert inner["crap"] == 2.5
    assert inner["missing_lines"] == [5]
    assert inner["missing_branches"] == [(3, 5)]


def test_real_coverage_distinguishes_repeated_method_names(measured):
    getter, setter = [row for row in measured if row["name"] == "Box.value"]
    assert getter["line"] != setter["line"]
    assert getter["coverage"] == 1
    assert setter["coverage"] == 0
    assert setter["crap"] == 2


def test_branchless_async_and_unexecuted_regions(measured):
    by_name = {row["name"]: row for row in measured}
    assert by_name["branchless"]["basis"] == "statement"
    assert by_name["branchless"]["coverage"] == 1
    assert by_name["unused"]["coverage"] == 0
    assert by_name["asynchronous"]["complexity"] == 2
    assert by_name["asynchronous"]["basis"] == "statement"
    assert by_name["alternative"]["coverage"] == 1
    assert by_name["conditional"]["status"] == "no_executable_body"
    assert by_name["conditional"]["crap"] is None


def test_nested_class_and_decorated_function_mapping(measured):
    by_name = {row["name"]: row for row in measured}
    assert by_name["local_class"]["statements"] == 2
    assert by_name["local_class.Local.method"]["statements"] == 1
    assert by_name["decorated.child"]["statements"] == 1
    assert by_name["decorated.child"]["complexity"] == 1
    regions = METRICS.function_regions(SOURCE)
    owned = [line for region in regions for line in region["lines"]]
    assert len(owned) == len(set(owned))


def test_missing_measurements_are_not_zero_risk():
    rows = METRICS.measure_file("def unmeasured():\n    return 1\n", None)
    assert rows[0]["coverage"] is None
    assert rows[0]["crap"] is None
    assert rows[0]["status"] == "missing_file_coverage"
    assert METRICS.distribution(rows)["unavailable"] == 1


def test_distribution_keeps_policy_boundaries_and_missing_data():
    rows = [
        {"complexity": 10, "crap": 15, "coverage": 0.9, "basis": "branch-exit"},
        {"complexity": 11, "crap": 29.9, "coverage": 0.89, "basis": "branch-exit"},
        {"complexity": 21, "crap": 30, "coverage": 0, "basis": "statement"},
        {"complexity": 1, "crap": None, "coverage": None, "basis": "unavailable"},
    ]
    counts = METRICS.distribution(rows)
    assert counts["functions"] == 4
    assert counts["unavailable"] == 1
    assert counts["crap_le_15"] == counts["crap_gt_15_lt_30"] == counts["crap_ge_30"] == 1
    assert counts["branched_below_90"] == 1
    assert counts["complexity_le_10"] == 2


@pytest.fixture
def snapshot_inputs(tmp_path, monkeypatch):
    root = tmp_path / "source with spaces ; not a command"
    root.mkdir()
    source = root / "source.py"
    source.write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr(METRICS, "inventory", lambda root: ([source], [source]))
    git_binary = tmp_path / "tools with spaces" / "git"
    monkeypatch.setattr(METRICS.shutil, "which", lambda name: str(git_binary) if name == "git" else None)
    return root, tmp_path / "report", git_binary


def test_snapshot_uses_resolved_fixed_bounded_git_commands(snapshot_inputs, monkeypatch):
    root, directory, git_binary = snapshot_inputs
    calls = []
    outputs = iter(["a" * 40 + "\n", " M source.py\n"])
    real_check_output = subprocess.check_output

    def check_output(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return next(outputs)

    monkeypatch.setattr(METRICS, "subprocess", SimpleNamespace(check_output=check_output))
    assert subprocess.check_output is real_check_output
    METRICS.snapshot(root, directory)
    options = {"cwd": root, "text": True, "shell": False, "timeout": 30}
    assert calls == [
        ([str(git_binary.resolve()), "rev-parse", "HEAD"], options),
        ([str(git_binary.resolve()), "status", "--short"], options),
    ]
    record = json.loads((directory / "source.json").read_text(encoding="utf-8"))
    assert record["head"] == "a" * 40
    assert record["worktree"] == " M source.py\n"
    assert record["sha256"] == METRICS.fingerprint(root, [root / "source.py"])


def test_snapshot_rejects_missing_git_before_running_commands(snapshot_inputs, monkeypatch):
    root, directory, _ = snapshot_inputs
    monkeypatch.setattr(METRICS.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        METRICS, "subprocess",
        SimpleNamespace(check_output=lambda *a, **kw: pytest.fail("Git must not run")),
    )
    with pytest.raises(FileNotFoundError, match="Git is required"):
        METRICS.snapshot(root, directory)
    assert not directory.exists()


@pytest.mark.parametrize("command_index", [0, 1])
@pytest.mark.parametrize("failure", ["exit", "timeout"])
def test_snapshot_preserves_previous_identity_on_git_failure(
    snapshot_inputs, monkeypatch, command_index, failure,
):
    root, directory, _ = snapshot_inputs
    directory.mkdir()
    previous = directory / "source.json"
    previous.write_bytes(b"previous snapshot")
    calls = []
    error_type = subprocess.CalledProcessError if failure == "exit" else subprocess.TimeoutExpired

    def check_output(arguments, **kwargs):
        calls.append(arguments)
        if len(calls) - 1 == command_index:
            if failure == "exit":
                raise subprocess.CalledProcessError(1, arguments)
            raise subprocess.TimeoutExpired(arguments, kwargs["timeout"])
        return "a" * 40 + "\n"

    monkeypatch.setattr(METRICS, "subprocess", SimpleNamespace(check_output=check_output))
    with pytest.raises(error_type):
        METRICS.snapshot(root, directory)
    assert len(calls) == command_index + 1
    assert previous.read_bytes() == b"previous snapshot"


def test_report_rejects_source_drift(tmp_path, monkeypatch):
    source = tmp_path / "source.py"
    source.write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr(METRICS, "inventory", lambda root: ([source], [source]))
    monkeypatch.setattr(METRICS, "subprocess", SimpleNamespace(check_output=lambda *a, **kw: "test"))
    METRICS.snapshot(tmp_path, tmp_path)
    source.write_text("raise RuntimeError\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed since snapshot"):
        METRICS.report(tmp_path, tmp_path)


@pytest.fixture
def report_inputs(tmp_path, monkeypatch):
    source = tmp_path / "source.py"
    source.write_text("def example():\n    return 1\n", encoding="utf-8")
    monkeypatch.setattr(METRICS, "inventory", lambda root: ([source], [source]))
    monkeypatch.setattr(METRICS, "subprocess", SimpleNamespace(check_output=lambda *a, **kw: "test"))
    METRICS.snapshot(tmp_path, tmp_path)
    coverage = {
        "meta": {
            "branch_coverage": True,
            "version": METRICS.environment()["tools"]["coverage"],
        },
        "totals": {},
        "files": {
            "source.py": {
                "executed_lines": [1, 2],
                "missing_lines": [],
                "executed_branches": [],
                "missing_branches": [],
            },
        },
    }
    (tmp_path / ".coverage").write_bytes(b"synthetic freshness fixture")
    return tmp_path, coverage


def write_report_input(directory, coverage):
    path = directory / "coverage.json"
    path.write_text(json.dumps(coverage), encoding="utf-8")
    return path


def test_report_writes_calculated_rows_and_fingerprint(report_inputs):
    directory, coverage = report_inputs
    write_report_input(directory, coverage)
    assert METRICS.report(directory, directory) == 0
    result = json.loads((directory / "baseline.json").read_text(encoding="utf-8"))
    assert result["functions"][0]["crap"] == 1
    assert result["distribution"]["functions"] == 1
    assert len(result["coverage_sha256"]) == 64
    assert result["source"]["sha256"]["source.py"]


def test_report_returns_incomplete_for_missing_file(report_inputs):
    directory, coverage = report_inputs
    coverage["files"] = {}
    write_report_input(directory, coverage)
    assert METRICS.report(directory, directory) == 2
    result = json.loads((directory / "baseline.json").read_text(encoding="utf-8"))
    assert result["missing_files"] == ["source.py"]
    assert result["distribution"]["unavailable"] == 1
    assert result["functions"][0]["crap"] is None


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [("branch_coverage", False, "branch-enabled"), ("version", "0", "version")],
)
def test_report_rejects_incompatible_coverage(report_inputs, key, value, message):
    directory, coverage = report_inputs
    coverage["meta"][key] = value
    write_report_input(directory, coverage)
    with pytest.raises(ValueError, match=message):
        METRICS.report(directory, directory)


def test_report_rejects_stale_data_even_if_json_is_new(report_inputs):
    directory, coverage = report_inputs
    write_report_input(directory, coverage)
    os.utime(directory / ".coverage", (1, 1))
    with pytest.raises(ValueError, match="predates snapshot"):
        METRICS.report(directory, directory)


def test_inventory_includes_unimported_sources_and_excludes_reporting_glue(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "unimported.py").touch()
    (tmp_path / "scripts" / "quality_baseline.py").touch()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.coverage.run]\nsource = ["scripts"]\n'
        'omit = ["scripts/quality_baseline.py"]\n',
        encoding="utf-8",
    )
    sources, inputs = METRICS.inventory(tmp_path)
    assert sources == [tmp_path / "scripts" / "unimported.py"]
    assert tmp_path / "scripts" / "quality_baseline.py" in inputs
