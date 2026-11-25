"""CRAP (Change Risk Anti-Patterns) per function, and the CI gate that keeps it from growing.

    CRAP = complexity^2 * (1 - coverage)^3 + complexity

Complexity is a function's cyclomatic complexity (radon); coverage is the share of its own statements and branches
the test suite runs (coverage.py, with branches). Nested functions and classes are scored on their own. A function
scoring over 30 is hard to change safely: too complex for the tests it has.

    python -m coverage run --branch --source=workerhost,tools -m pytest tests -q -p no:cacheprovider
    python -m coverage json -o coverage.json
    python tools/crap.py check coverage.json      # the gate: exit 1 if a function newly passes 30, or one that was
                                                  # already over 30 got worse
    python tools/crap.py report coverage.json     # every function, worst first
    python tools/crap.py baseline coverage.json   # rewrite tools/crap-baseline.json: only after making things better,
                                                  # or with a reason in the PR

tools/crap-baseline.json lists the functions already over 30 when the gate started, with their scores then. The gate
allows those to stay, never to get worse (beyond a small margin: coverage of the same code differs a little between
Python versions). A function that gets back under 30 drops off the list at the next `baseline`.

Development only: radon and coverage are not needed on a host.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tools" / "crap-baseline.json"
THRESHOLD = 30.0
MARGIN = 1.10  # a baselined function may score up to 10% above its baseline before the gate fails


def source_files(root: Path = ROOT) -> list[Path]:
    return sorted([*(root / "workerhost").glob("*.py"), *(root / "tools").glob("*.py"), root / "wh.py"])


def _blocks(code: str):
    """(qualified name, block) for every function and method, nested ones included."""
    from radon.visitors import Class, ComplexityVisitor

    def walk(blocks, prefix=""):
        for b in blocks:
            if isinstance(b, Class):
                yield from walk(b.methods, prefix + b.name + ".")
                yield from walk(getattr(b, "inner_classes", []), prefix + b.name + ".")
            else:
                yield prefix + b.name, b
                yield from walk(b.closures, prefix + b.name + ".")

    v = ComplexityVisitor.from_code(code)
    yield from walk(v.functions + v.classes)


def crap(complexity: int, covered: float) -> float:
    return complexity * complexity * (1 - covered) ** 3 + complexity


def scores(coverage_json: dict, root: Path = ROOT) -> dict[str, dict]:
    """{"<file>::<function>": {"crap", "complexity", "coverage", "line"}} for every function in source_files()."""
    files = {str(Path(k)).replace("\\", "/").lower(): v for k, v in coverage_json["files"].items()}
    out: dict[str, dict] = {}
    for f in source_files(root):
        rel = f.relative_to(root).as_posix()
        data = files.get(rel.lower())
        executed = set(data["executed_lines"]) if data else set()
        missing = set(data["missing_lines"]) if data else set()
        arcs = ([tuple(a) for a in data.get("executed_branches", [])], [tuple(a) for a in data.get("missing_branches", [])]
                ) if data else ([], [])
        for name, b in _blocks(f.read_text(encoding="utf-8")):
            holes = [(c.lineno, c.endline) for c in [*getattr(b, "closures", []), *getattr(b, "inner_classes", [])]]

            def mine(line, b=b, holes=holes):
                return b.lineno <= line <= b.endline and not any(s <= line <= e for s, e in holes)

            if data:
                stmts = [ln for ln in executed | missing if mine(ln)]
                hit = sum(ln in executed for ln in stmts) + sum(mine(s) for s, _ in arcs[0])
                total = len(stmts) + sum(mine(s) for s, _ in arcs[0] + arcs[1])
                covered = hit / total if total else 1.0
            else:
                covered = 0.0  # never imported by the tests
            key = f"{rel}::{name}"
            score = round(crap(b.complexity, covered), 1)
            if key not in out or score > out[key]["crap"]:
                out[key] = {"crap": score, "complexity": b.complexity, "coverage": round(100 * covered, 1),
                            "line": b.lineno}
    return out


def gate(current: dict[str, dict], baseline: dict[str, float]) -> tuple[list[str], list[str]]:
    """(failures, improvements). A failure: a function over the threshold that is not in the baseline, or one in it
    that scores more than MARGIN times its baseline. An improvement: a baselined function now at or under the
    threshold (run `baseline` to drop it)."""
    failures, improved = [], []
    for key, s in sorted(current.items(), key=lambda kv: -kv[1]["crap"]):
        was = baseline.get(key)
        if s["crap"] > THRESHOLD and was is None:
            failures.append(f"NEW   {s['crap']:7.1f}  {key}:{s['line']}  (complexity {s['complexity']}, "
                            f"covered {s['coverage']}%)")
        elif was is not None and s["crap"] > max(THRESHOLD, was * MARGIN):
            failures.append(f"WORSE {s['crap']:7.1f}  {key}:{s['line']}  (baseline {was}; complexity "
                            f"{s['complexity']}, covered {s['coverage']}%)")
    for key, was in sorted(baseline.items()):
        if key in current and current[key]["crap"] <= THRESHOLD:
            improved.append(f"{key}: {was} -> {current[key]['crap']}")
    return failures, improved


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("action", choices=["check", "report", "baseline"])
    p.add_argument("coverage_json")
    p.add_argument("--baseline", default=str(BASELINE))
    args = p.parse_args(argv)
    current = scores(json.loads(Path(args.coverage_json).read_text(encoding="utf-8")))
    over = {k: v for k, v in current.items() if v["crap"] > THRESHOLD}
    if args.action == "report":
        for key, s in sorted(current.items(), key=lambda kv: -kv[1]["crap"]):
            print(f"{s['crap']:7.1f}  complexity {s['complexity']:3}  covered {s['coverage']:5.1f}%  {key}:{s['line']}")
        print(f"{len(current)} functions; {len(over)} over {THRESHOLD:g}")
        return 0
    if args.action == "baseline":
        data = {"threshold": THRESHOLD, "functions": {k: v["crap"] for k, v in sorted(over.items())}}
        Path(args.baseline).write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
        print(f"baseline: {len(over)} functions over {THRESHOLD:g} written to {args.baseline}")
        return 0
    path = Path(args.baseline)
    baseline = json.loads(path.read_text(encoding="utf-8"))["functions"] if path.exists() else {}
    failures, improved = gate(current, baseline)
    print(f"CRAP gate: {len(current)} functions, {len(over)} over {THRESHOLD:g}, {len(baseline)} in the baseline")
    for line in improved:
        print(f"  improved (drop it from the baseline with `tools/crap.py baseline`): {line}")
    for line in failures:
        print("  " + line)
    if failures:
        print("Split the function or test it more. A deliberate exception: `tools/crap.py baseline`, and say why in "
              "the PR.")
        return 1
    print("CRAP gate: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
