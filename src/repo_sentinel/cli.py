"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
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


def format_text(findings: Sequence[Finding], *, colour: bool) -> str:
    if not findings:
        return "No findings. That is not proof of safety, but it is a good sign."

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
    return "\n".join(lines)


def format_json(findings: Sequence[Finding]) -> str:
    return json.dumps(
        {
            "version": __version__,
            "finding_count": len(findings),
            "findings": [finding.to_dict() for finding in findings],
        },
        indent=2,
    )


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

    findings = [
        finding
        for finding in scan_path(
            args.path,
            DEFAULT_EXCLUDES + tuple(args.exclude),
            allow_examples=not args.no_example_allowlist,
            use_gitignore=not args.no_gitignore,
        )
        if finding.severity >= min_severity
    ]

    if args.format == "json":
        print(format_json(findings))
    else:
        colour = not args.no_color and sys.stdout.isatty()
        print(format_text(findings, colour=colour))

    if any(finding.severity >= fail_on for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
