#!/usr/bin/env python3
"""Line coverage for the test suite, in the standard library.

A coverage tool is a strange thing to write when a good one exists. The reason
is the same one that shapes the rest of this project: the promise is that
running bluerayscan pulls nothing into your environment, and that promise is
worth more than the fifty lines this costs. A contributor with no network, or
with a policy about what may be installed to run a security tool's own tests,
can still check the floor.

It is a *line* coverage tool and nothing more. There are no branch counts, no
HTML, no exclusions beyond ``# pragma: no cover``. Anything more would be
competing with coverage.py, which is not the point.

Usage::

    python3 tools/coverage.py            # report, and enforce the floor
    python3 tools/coverage.py --min 85   # a different floor
    python3 tools/coverage.py --show-missing
"""

from __future__ import annotations

import argparse
import dis
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "src")
TESTS = os.path.join(ROOT, "tests")

#: The floor. Raise it when the suite earns it; never lower it to make a build
#: pass, which is the one thing a coverage gate exists to prevent.
DEFAULT_MINIMUM = 94.0


def executable_lines(path: str) -> "set[int]":
    """Lines that can run: every statement start the compiler emits.

    Derived from the compiled code rather than from the text, so a continuation
    line, a docstring and a blank line are all correctly absent, and a line
    carrying ``# pragma: no cover`` is removed afterwards.
    """
    with open(path, encoding="utf-8") as handle:
        source = handle.read()
    code = compile(source, path, "exec")

    lines: "set[int]" = set()
    stack = [code]
    while stack:
        current = stack.pop()
        lines.update(
            lineno for _, lineno in dis.findlinestarts(current) if lineno is not None
        )
        stack.extend(
            const for const in current.co_consts if hasattr(const, "co_code")
        )

    text = source.splitlines()
    return {
        line
        for line in lines
        if 0 < line <= len(text) and "pragma: no cover" not in text[line - 1]
    }


def _make_tracer(executed: "set[tuple[str, int]]", prefix: str):
    def tracer(frame, event, arg):
        if frame.f_code.co_filename.startswith(prefix):
            if event == "line":
                executed.add((frame.f_code.co_filename, frame.f_lineno))
            return tracer
        return None

    return tracer


def run_suite(executed: "set[tuple[str, int]]") -> bool:
    """Run the whole suite under the tracer. Returns True if it passed.

    A caveat worth knowing when a number here drops without explanation:
    CPython silently clears the trace function if a RecursionError is raised
    while tracing, so everything after that test runs unmeasured. If coverage
    falls by fifteen points and no code changed, look for a test that recurses
    deeply rather than for a test that stopped running.
    """
    sys.path[:0] = [SOURCE, TESTS]
    runner = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, "w"))

    # Tracing starts before discovery, not after. Discovery is what imports the
    # package, and a module's import-time lines -- every rule in the catalogue,
    # every compiled pattern -- run exactly once, then. Starting the tracer
    # afterwards reports all of them as dead code.
    sys.settrace(_make_tracer(executed, SOURCE))
    try:
        suite = unittest.defaultTestLoader.discover(TESTS, top_level_dir=TESTS)
        result = runner.run(suite)
    finally:
        sys.settrace(None)
    return result.wasSuccessful()


def source_files() -> "list[str]":
    found = []
    for directory, _, names in os.walk(SOURCE):
        found.extend(
            os.path.join(directory, name)
            for name in sorted(names)
            if name.endswith(".py")
        )
    return sorted(found)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--min", type=float, default=DEFAULT_MINIMUM, dest="minimum")
    parser.add_argument("--show-missing", action="store_true")
    args = parser.parse_args(argv)

    executed: "set[tuple[str, int]]" = set()
    passed = run_suite(executed)
    if not passed:
        print("coverage: the suite failed; fix that before reading these numbers")
        return 2

    total_runnable = total_covered = 0
    rows = []
    for path in source_files():
        runnable = executable_lines(path)
        covered = {line for line in runnable if (path, line) in executed}
        total_runnable += len(runnable)
        total_covered += len(covered)
        missing = sorted(runnable - covered)
        rows.append((os.path.relpath(path, ROOT), len(runnable), len(covered), missing))

    width = max(len(row[0]) for row in rows)
    for name, runnable, covered, missing in rows:
        percent = 100.0 if not runnable else covered * 100.0 / runnable
        line = f"{name:<{width}}  {covered:>4}/{runnable:<4}  {percent:6.1f}%"
        if args.show_missing and missing:
            line += "  missing: " + _ranges(missing)
        print(line)

    overall = 100.0 if not total_runnable else total_covered * 100.0 / total_runnable
    print(f"{'TOTAL':<{width}}  {total_covered:>4}/{total_runnable:<4}  {overall:6.1f}%")

    if overall + 0.05 < args.minimum:
        print(f"coverage {overall:.1f}% is below the floor of {args.minimum:.1f}%")
        return 1
    return 0


def _ranges(numbers: "list[int]") -> str:
    """Compress [1,2,3,7] to "1-3, 7" -- a list of ninety line numbers is noise."""
    spans = []
    start = previous = numbers[0]
    for number in numbers[1:]:
        if number == previous + 1:
            previous = number
            continue
        spans.append((start, previous))
        start = previous = number
    spans.append((start, previous))
    return ", ".join(str(low) if low == high else f"{low}-{high}" for low, high in spans)


if __name__ == "__main__":
    raise SystemExit(main())
