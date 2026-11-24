"""CI gate: every function in src/strugglebus under CRAP 10, line coverage at least 85%.

CRAP = complexity^2 * (1 - coverage)^3 + complexity. Complexity is radon's
cyclomatic complexity of a top-level function or a method; coverage is the
share of that function's measured lines the test suite ran. A function passes
by being simple, by being tested, or both.

    python scripts/quality_gate.py .metrics/coverage-gate.json

The report is the JSON written by `pytest --cov=src/strugglebus
--cov-report=json:<path>`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NamedTuple

from radon.complexity import cc_visit


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "src/strugglebus"
MAX_CRAP = 10.0
MIN_COVERAGE = 85.0


class Row(NamedTuple):
    crap: float
    complexity: int
    coverage: float
    file: str
    line: int
    name: str


def crap(complexity: int, coverage: float) -> float:
    return complexity**2 * (1 - coverage) ** 3 + complexity


def _functions(source: str) -> list:
    """Top-level functions and methods, each once."""
    found, seen = [], set()
    for block in cc_visit(source):
        for item in getattr(block, "methods", None) or [block]:
            key = (item.lineno, item.name)
            if key not in seen and not hasattr(item, "methods"):
                seen.add(key)
                found.append(item)
    return found


def measure_file(source: str, relative: str, measured: dict | None) -> list[Row]:
    """A file the report does not mention counts as not run at all."""
    executed = set(measured["executed_lines"]) if measured else set()
    missing = set(measured["missing_lines"]) if measured else set()
    rows = []
    for item in _functions(source):
        lines = range(item.lineno, item.endline + 1)
        hit = sum(1 for number in lines if number in executed)
        miss = sum(1 for number in lines if number in missing)
        if measured is None:
            coverage = 0.0
        elif hit + miss == 0:
            coverage = 1.0
        else:
            coverage = hit / (hit + miss)
        owner = getattr(item, "classname", None)
        name = f"{owner}.{item.name}" if owner else item.name
        rows.append(Row(crap(item.complexity, coverage), item.complexity, coverage, relative, item.lineno, name))
    return rows


def measure(root: Path, report: dict) -> tuple[list[Row], float]:
    files = {name.replace("\\", "/"): data for name, data in report["files"].items()}
    rows: list[Row] = []
    executed = missing = 0
    for path in sorted((root / PACKAGE).rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        measured = files.get(relative)
        rows.extend(measure_file(path.read_text(encoding="utf-8"), relative, measured))
        if measured:
            executed += len(measured["executed_lines"])
            missing += len(measured["missing_lines"])
    if not rows:
        raise ValueError(f"no functions found under {root / PACKAGE}")
    if executed + missing == 0:
        raise ValueError("the coverage report measured no lines of the package")
    return rows, 100.0 * executed / (executed + missing)


def failures(rows: list[Row], line_coverage: float, max_crap: float, min_coverage: float) -> list[str]:
    problems = [
        f"{row.file}:{row.line} {row.name}: CRAP {row.crap:.1f} "
        f"(complexity {row.complexity}, coverage {row.coverage:.0%})"
        for row in sorted(rows, reverse=True)
        if row.crap >= max_crap
    ]
    if line_coverage < min_coverage:
        problems.append(f"line coverage is {line_coverage:.1f}%, below {min_coverage:g}%")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path, help="coverage JSON report")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--max-crap", type=float, default=MAX_CRAP)
    parser.add_argument("--min-coverage", type=float, default=MIN_COVERAGE)
    options = parser.parse_args(argv)

    rows, line_coverage = measure(options.root, json.loads(options.report.read_text(encoding="utf-8")))
    problems = failures(rows, line_coverage, options.max_crap, options.min_coverage)
    worst = max(rows)
    print(
        f"quality gate: {len(rows)} functions, line coverage {line_coverage:.1f}%, "
        f"highest CRAP {worst.crap:.1f} ({worst.file}:{worst.line} {worst.name})"
    )
    if not problems:
        print(f"passed: every function is under CRAP {options.max_crap:g} and coverage is at least {options.min_coverage:g}%")
        return 0
    print(f"FAILED: {len(problems)} problem(s). Simplify the function or test more of it.", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
