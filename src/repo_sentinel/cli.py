"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .baseline import Baseline, BaselineError, serialise
from .discovery import DEFAULT_EXCLUDES, iter_files
from .findings import Finding, Severity
from .scanners import secrets, workflows

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_COLOURS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"


def scan_path(
    path: str,
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES,
    *,
    allow_examples: bool = True,
    use_gitignore: bool = True,
) -> list[Finding]:
    """Run every scanner over ``path`` and return findings worst-first."""
    files = list(iter_files(path, excludes=excludes, use_gitignore=use_gitignore))
    found = secrets.scan_files(files, allow_examples=allow_examples)
    found += workflows.scan_files(files)
    return sorted(found, key=lambda finding: finding.sort_key)


def _baseline_note(suppressed: int, stale: int) -> str:
    """One line describing what a baseline hid, and what it no longer covers."""
    note = f"{suppressed} finding(s) hidden by the baseline"
    if stale:
        note += (
            f"; {stale} baseline entry(s) matched nothing and can be pruned "
            "with --write-baseline"
        )
    return note + "."


def format_text(
    findings: Sequence[Finding], *, colour: bool, baseline_note: str = ""
) -> str:
    if not findings:
        clean = "No findings. That is not proof of safety, but it is a good sign."
        return f"{clean}\n{baseline_note}" if baseline_note else clean

    lines: list[str] = []
    for finding in findings:
        label = finding.severity.value.upper()
        if colour:
            label = f"{_COLOURS[finding.severity]}{label}{_RESET}"
        lines.append(f"{label} {finding.rule_id}  {finding.path}:{finding.line}")
        lines.append(f"    {finding.title}")
        if finding.evidence:
            lines.append(f"    evidence: {finding.evidence}")
        if finding.remediation:
            lines.append(f"    fix: {finding.remediation}")
        lines.append("")

    counts: dict[Severity, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(
        f"{counts[severity]} {severity.value}"
        for severity in sorted(counts, key=lambda s: -s.rank)
    )
    lines.append(f"{len(findings)} finding(s): {summary}")
    if baseline_note:
        lines.append(baseline_note)
    return "\n".join(lines)


def format_json(findings: Sequence[Finding], *, baseline: dict | None = None) -> str:
    payload = {
        "version": __version__,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    if baseline is not None:
        payload["baseline"] = baseline
    return json.dumps(payload, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-sentinel",
        description="Audit a repository for leaked secrets and insecure configuration.",
    )
    parser.add_argument("--version", action="version", version=f"repo-sentinel {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a directory or file")
    scan.add_argument("path", nargs="?", default=".", help="path to scan (default: .)")
    scan.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    scan.add_argument(
        "--min-severity",
        default="low",
        help="hide findings below this severity (low, medium, high, critical)",
    )
    scan.add_argument(
        "--fail-on",
        default="medium",
        help="exit non-zero when a finding reaches this severity (default: medium)",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="extra file or directory glob to skip (repeatable)",
    )
    recording = scan.add_mutually_exclusive_group()
    recording.add_argument(
        "--baseline",
        metavar="FILE",
        help="hide findings recorded in FILE, so CI only fails on new ones",
    )
    recording.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="record the current findings in FILE and exit without reporting them",
    )
    scan.add_argument(
        "--no-gitignore",
        action="store_true",
        help="also scan files git was told to ignore",
    )
    scan.add_argument(
        "--no-example-allowlist",
        action="store_true",
        help="also report credentials published as vendor or RFC examples",
    )
    scan.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        min_severity = Severity.parse(args.min_severity)
        fail_on = Severity.parse(args.fail_on)
    except ValueError as error:
        parser.error(str(error))
        return EXIT_ERROR  # pragma: no cover - argparse exits first

    scanned = scan_path(
        args.path,
        DEFAULT_EXCLUDES + tuple(args.exclude),
        allow_examples=not args.no_example_allowlist,
        use_gitignore=not args.no_gitignore,
    )

    # Written before --min-severity is applied: a baseline records what the scan
    # saw, not what this invocation chose to show. Otherwise a file recorded
    # under --min-severity high would quietly stop covering its own low findings
    # the next time someone ran the scan without that flag.
    if args.write_baseline:
        try:
            with open(args.write_baseline, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(serialise(scanned))
        except OSError as error:
            print(f"cannot write baseline file: {error}", file=sys.stderr)
            return EXIT_ERROR
        print(f"Recorded {len(scanned)} finding(s) in {args.write_baseline}.")
        return EXIT_OK

    note = ""
    baseline_report = None
    if args.baseline:
        try:
            recorded = Baseline.load(args.baseline)
        except BaselineError as error:
            print(str(error), file=sys.stderr)
            return EXIT_ERROR
        remaining = recorded.filter(scanned)
        suppressed = len(scanned) - len(remaining)
        note = _baseline_note(suppressed, recorded.stale_count)
        baseline_report = {
            "path": args.baseline,
            "suppressed": suppressed,
            "stale_entries": recorded.stale_count,
        }
        scanned = remaining

    findings = [finding for finding in scanned if finding.severity >= min_severity]

    if args.format == "json":
        print(format_json(findings, baseline=baseline_report))
    else:
        colour = not args.no_color and sys.stdout.isatty()
        print(format_text(findings, colour=colour, baseline_note=note))

    if any(finding.severity >= fail_on for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
