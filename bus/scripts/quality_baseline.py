"""Local, non-gating Python complexity/coverage/CRAP baseline."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import json
import math
import platform
import shutil
# Git metadata uses fixed argv, a resolved executable, no shell and a bounded wait.
import subprocess  # nosec B404
import sys
import tokenize
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from radon.complexity import cc_visit_ast


ROOT = Path(__file__).resolve().parents[1]


def crap(complexity: int, coverage: float) -> float:
    if complexity < 1 or not math.isfinite(coverage) or not 0 <= coverage <= 1:
        raise ValueError("CRAP requires positive complexity and coverage in [0, 1]")
    return complexity**2 * (1 - coverage) ** 3 + complexity


def function_regions(source: str) -> list[dict]:
    """Assign body lines exclusively; declarations remain in their caller."""
    regions = []

    def visit(node: ast.AST, parents: tuple[str, ...]) -> None:
        scope = parents
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = (*parents, node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lines = set(range(node.body[0].lineno, node.end_lineno + 1))
            for child in ast.walk(node):
                if child is not node and isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    lines.difference_update(
                        range(child.body[0].lineno, child.end_lineno + 1)
                    )
            regions.append({
                "name": ".".join(scope),
                "line": node.lineno,
                "end_line": node.end_lineno,
                "complexity": cc_visit_ast(node)[0].complexity,
                "lines": lines,
            })
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(ast.parse(source), ())
    return regions


def measure_file(source: str, coverage: dict | None) -> list[dict]:
    rows = []
    for region in function_regions(source):
        lines = region.pop("lines")
        row = {
            **region,
            "coverage": None,
            "crap": None,
            "basis": "unavailable",
            "status": "missing_file_coverage",
        }
        if coverage is not None:
            executed = lines.intersection(coverage["executed_lines"])
            missing = lines.intersection(coverage["missing_lines"])
            covered_arcs = {
                tuple(arc) for arc in coverage["executed_branches"] if arc[0] in lines
            }
            missing_arcs = {
                tuple(arc) for arc in coverage["missing_branches"] if arc[0] in lines
            }
            statements = len(executed) + len(missing)
            branches = len(covered_arcs) + len(missing_arcs)
            row.update(
                statements=statements,
                covered_statements=len(executed),
                branches=branches,
                covered_branches=len(covered_arcs),
                missing_lines=sorted(missing),
                missing_branches=sorted(missing_arcs),
                status="no_executable_body",
            )
            if statements:
                fraction = (
                    len(covered_arcs) / branches if branches else len(executed) / statements
                )
                row.update(
                    coverage=fraction,
                    crap=crap(region["complexity"], fraction),
                    basis="branch-exit" if branches else "statement",
                    status="measured",
                )
        rows.append(row)
    return rows


def inventory(root: Path) -> tuple[list[Path], list[Path]]:
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    run = config["tool"]["coverage"]["run"]
    excluded = set(run["omit"])
    sources = sorted({
        path
        for directory in run["source"]
        for path in (root / directory).rglob("*.py")
        if "__pycache__" not in path.parts
        and path.relative_to(root).as_posix() not in excluded
    })
    if not sources:
        raise ValueError("no Python sources in configured measurement scope")
    inputs = sorted({
        *sources,
        *(root / "tests").rglob("*.py"),
        root / "pyproject.toml",
        root / "uv.lock",
        root / "scripts" / "quality_baseline.py",
    })
    return sources, inputs


def fingerprint(root: Path, inputs: list[Path]) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in inputs
    }


def environment() -> dict:
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "tools": {
            name: importlib.metadata.version(name)
            for name in ("coverage", "radon", "pytest", "pytest-asyncio")
        },
    }


def snapshot(root: Path, directory: Path) -> None:
    sources, inputs = inventory(root)
    git_path = shutil.which("git")
    if git_path is None:
        raise FileNotFoundError("Git is required to record the baseline source identity")
    git_binary = str(Path(git_path).resolve())
    head = subprocess.check_output(  # nosec B603
        [git_binary, "rev-parse", "HEAD"], cwd=root, text=True, shell=False, timeout=30,
    )
    worktree = subprocess.check_output(  # nosec B603
        [git_binary, "status", "--short"], cwd=root, text=True, shell=False, timeout=30,
    )
    record = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "environment": environment(),
        "head": head.strip(),
        "worktree": worktree,
        "sources": [path.relative_to(root).as_posix() for path in sources],
        "sha256": fingerprint(root, inputs),
    }
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "source.json").write_text(json.dumps(record, indent=2), encoding="utf-8")


def distribution(rows: list[dict]) -> dict:
    measured = [row for row in rows if row["crap"] is not None]
    branched = [row for row in measured if row["basis"] == "branch-exit"]
    return {
        "functions": len(rows),
        "unavailable": len(rows) - len(measured),
        "complexity_le_10": sum(row["complexity"] <= 10 for row in rows),
        "complexity_11_20": sum(10 < row["complexity"] <= 20 for row in rows),
        "complexity_gt_20": sum(row["complexity"] > 20 for row in rows),
        "crap_le_15": sum(row["crap"] <= 15 for row in measured),
        "crap_gt_15_lt_30": sum(15 < row["crap"] < 30 for row in measured),
        "crap_ge_30": sum(row["crap"] >= 30 for row in measured),
        "branched_functions": len(branched),
        "branched_below_90": sum(row["coverage"] < 0.9 for row in branched),
        "branchless_functions": len(measured) - len(branched),
        "zero_coverage_functions": sum(row["coverage"] == 0 for row in measured),
    }


def report(root: Path, directory: Path) -> int:
    sources, inputs = inventory(root)
    saved = json.loads((directory / "source.json").read_text(encoding="utf-8"))
    if saved["sha256"] != fingerprint(root, inputs) or saved["environment"] != environment():
        raise ValueError("inputs/environment changed since snapshot; rerun measurement")
    coverage_path = directory / "coverage.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    if not coverage["meta"]["branch_coverage"]:
        raise ValueError("branch-enabled coverage is required")
    if coverage["meta"]["version"] != saved["environment"]["tools"]["coverage"]:
        raise ValueError("coverage report version does not match measured environment")
    started = (directory / "source.json").stat().st_mtime
    data_path = directory / ".coverage"
    if min(data_path.stat().st_mtime, coverage_path.stat().st_mtime) < started:
        raise ValueError("coverage predates snapshot; rerun measurement")
    files = {(root / name).resolve(): data for name, data in coverage["files"].items()}
    rows = []
    for path in sources:
        with tokenize.open(path) as stream:
            source = stream.read()
        rows.extend(
            {"file": path.relative_to(root).as_posix(), **row}
            for row in measure_file(source, files.get(path.resolve()))
        )
    missing_files = [
        path.relative_to(root).as_posix() for path in sources if path.resolve() not in files
    ]
    rows.sort(key=lambda row: (-(row["crap"] or 0), row["file"], row["line"]))
    result = {
        "policy": "M0 observation only; no pass/merge gate",
        "basis": "branch-exit CRAP adaptation; branchless statement fallback",
        "source": saved,
        "coverage_sha256": hashlib.sha256(coverage_path.read_bytes()).hexdigest(),
        "missing_files": missing_files,
        "coverage_totals": coverage["totals"],
        "distribution": distribution(rows),
        "application_distribution": distribution([
            row for row in rows if row["file"].startswith("src/")
        ]),
        "functions": rows,
    }
    (directory / "baseline.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key not in {
        "source", "functions"
    }}, indent=2))
    print("\nTop 20 measured functions (file:line, name, C, T, adapted CRAP):")
    for row in [row for row in rows if row["crap"] is not None][:20]:
        print(
            f"{row['file']}:{row['line']} {row['name']} "
            f"C={row['complexity']} T={row['coverage']:.2%} "
            f"CRAP={row['crap']:.2f} ({row['basis']})"
        )
    return 2 if missing_files or result["distribution"]["unavailable"] else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("snapshot", "report"))
    parser.add_argument("--directory", type=Path, default=ROOT / ".metrics")
    args = parser.parse_args()
    if args.action == "snapshot":
        snapshot(ROOT, args.directory)
        return 0
    return report(ROOT, args.directory)


if __name__ == "__main__":
    raise SystemExit(main())
