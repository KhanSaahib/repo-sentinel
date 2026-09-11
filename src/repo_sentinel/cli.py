"""Command line entry point: argument handling, and nothing else.

Scanning lives in :mod:`.engine`, formatting in :mod:`.report`. What is left
here is the part that has to decide what the user asked for and what the exit
code should be -- which, for a tool whose whole job is to fail a build at the
right moment, is worth keeping unmixed with anything else.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from . import __version__, baseline as baseline_module, config as config_module, report
from .discovery import DEFAULT_EXCLUDES
from .engine import scan, scan_path  # noqa: F401  (scan_path is public API)
from .findings import Confidence, Finding, Severity
from .rules import RULES

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-sentinel",
        description="Audit a repository for leaked secrets and insecure configuration.",
    )
    parser.add_argument("--version", action="version", version=f"repo-sentinel {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a directory or file")
    scan_parser.add_argument("path", nargs="?", default=".", help="path to scan (default: .)")
    scan_parser.add_argument(
        "--format",
        choices=("text", "json", "sarif", "markdown"),
        default="text",
        help="output format",
    )
    scan_parser.add_argument(
        "--output",
        metavar="FILE",
        help="write the report to FILE instead of stdout (SARIF uploads want a file)",
    )
    scan_parser.add_argument(
        "--min-severity",
        default="low",
        help="hide findings below this severity (low, medium, high, critical)",
    )
    scan_parser.add_argument(
        "--min-confidence",
        default="low",
        help="hide findings below this confidence (low, medium, high)",
    )
    scan_parser.add_argument(
        "--fail-on",
        default="medium",
        help="exit non-zero when a finding reaches this severity (default: medium)",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="extra file or directory glob to skip (repeatable)",
    )
    scan_parser.add_argument(
        "--baseline",
        nargs="?",
        const=baseline_module.DEFAULT_PATH,
        metavar="FILE",
        help=(
            "treat findings recorded in FILE as accepted and fail only on new ones "
            f"(default file: {baseline_module.DEFAULT_PATH})"
        ),
    )
    scan_parser.add_argument(
        "--write-baseline",
        nargs="?",
        const=baseline_module.DEFAULT_PATH,
        metavar="FILE",
        help="record the current findings as accepted, then exit without failing",
    )
    scan_parser.add_argument(
        "--config",
        metavar="FILE",
        help=(
            "project defaults, as JSON "
            f"(default: {config_module.DEFAULT_PATH} beside the scanned tree, if present)"
        ),
    )
    scan_parser.add_argument(
        "--disable",
        action="append",
        default=[],
        metavar="RULE",
        help="switch off a rule or a family ('K8S004', 'DC*'); repeatable",
    )
    scan_parser.add_argument(
        "--paths-from",
        metavar="FILE",
        help=(
            "scan only the files listed in FILE, one per line ('-' for stdin). "
            "Pipe in `git diff --name-only origin/main` for a fast pull request run"
        ),
    )
    scan_parser.add_argument(
        "--sort",
        choices=("severity", "path"),
        default="severity",
        help="order findings worst-first (default) or by file",
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only the summary, not each finding",
    )
    scan_parser.add_argument(
        "--no-gitignore",
        action="store_true",
        help="also scan files git was told to ignore",
    )
    scan_parser.add_argument(
        "--no-example-allowlist",
        action="store_true",
        help="also report credentials published as vendor or RFC examples",
    )
    scan_parser.add_argument("--no-color", action="store_true", help="disable coloured output")

    rules_parser = subparsers.add_parser("rules", help="list every rule the scanner knows")
    rules_parser.add_argument("--format", choices=("text", "json"), default="text")
    # Kept for the second parse in main(), where a config file supplies
    # defaults that explicit flags then override.
    parser.scan_parser = scan_parser  # type: ignore[attr-defined]
    return parser


def _emit(text: str, destination: "str | None") -> int:
    """Print a report, or write it to a file. Returns an exit code."""
    if destination is None:
        print(text)
        return EXIT_OK
    try:
        os.makedirs(os.path.dirname(os.path.abspath(destination)), exist_ok=True)
        with open(destination, "w", encoding="utf-8") as handle:
            handle.write(text if text.endswith("\n") else text + "\n")
    except OSError as error:
        print(f"repo-sentinel: could not write {destination!r}: {error}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


#: Config key -> the argparse destination it supplies a default for. The two
#: booleans are inverted because the flags are phrased as opt-outs.
_CONFIG_TO_DEST = {
    "exclude": ("exclude", False),
    "fail_on": ("fail_on", False),
    "min_severity": ("min_severity", False),
    "min_confidence": ("min_confidence", False),
    "baseline": ("baseline", False),
    "sort": ("sort", False),
    "disable": ("disable", False),
    "gitignore": ("no_gitignore", True),
    "example_allowlist": ("no_example_allowlist", True),
}


#: Filled in by :func:`_apply_config` and read by :func:`_apply_disabled`.
#: Per-path rules have no command line form -- a glob table does not belong on
#: a command line -- so unlike every other setting they live only in the file.
_PATH_SCOPES: "list[config_module.PathScope]" = []


def _apply_config(parser: argparse.ArgumentParser, argv: "Sequence[str] | None") -> argparse.Namespace:
    """Parse twice: once to find the config file, once with it as defaults.

    Parsing again is cheaper than working out whether each flag was passed
    explicitly, and it gets the precedence right by construction -- argparse
    already prefers what is on the command line to whatever the defaults say.
    """
    args = parser.parse_args(argv)
    if args.command != "scan":
        return args

    path = config_module.find(args.path, args.config)
    if path is None:
        return args

    settings = config_module.load(path)
    _PATH_SCOPES[:] = config_module.path_scopes(settings)
    defaults = {}
    for key, value in settings.items():
        mapping = _CONFIG_TO_DEST.get(key)
        if mapping is None:
            continue  # a setting with no flag, like the paths table
        dest, inverted = mapping
        defaults[dest] = (not value) if inverted else value
    parser.scan_parser.set_defaults(**defaults)  # type: ignore[attr-defined]
    reparsed = parser.parse_args(argv)
    reparsed.config = path
    return reparsed


def _apply_disabled(
    findings: "list[Finding]", patterns: "Sequence[str]", notes: "list[str]"
) -> "list[Finding]":
    """Drop the rules a project has switched off, and say that it did.

    Two ways to switch one off: everywhere, through ``disable``, and under one
    glob, through the ``paths`` table. Both are counted rather than silently
    applied -- silence that nobody can see is the failure mode this whole tool
    is built to avoid. An unknown rule id is called out too: a typo there
    quietly leaves the rule switched on, which is the safe direction but not
    the intended one.
    """
    if not patterns and not _PATH_SCOPES:
        return findings

    disabled = config_module.disabled_matcher(patterns)
    scoped = [
        (scope, config_module.disabled_matcher(scope.disable)) for scope in _PATH_SCOPES
    ]
    kept = [
        finding
        for finding in findings
        if not disabled(finding.rule_id)
        and not any(
            scope.covers(finding.path) and matches(finding.rule_id) for scope, matches in scoped
        )
    ]
    hidden = len(findings) - len(kept)
    if hidden:
        where = ", ".join(patterns) if patterns else "the paths table"
        notes.append(f"{hidden} finding(s) hidden by disabled rules: {where}.")
    unknown = [
        pattern
        for pattern in patterns
        if not pattern.endswith("*") and pattern.upper() not in RULES
    ]
    if unknown:
        notes.append(f"No such rule: {', '.join(unknown)}. Check 'repo-sentinel rules'.")
    return kept


def _run_scan(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        min_severity = Severity.parse(args.min_severity)
        min_confidence = Confidence.parse(args.min_confidence)
        fail_on = Severity.parse(args.fail_on)
    except ValueError as error:
        parser.error(str(error))
        return EXIT_ERROR  # pragma: no cover - argparse exits first

    try:
        only_paths = _listed_paths(args.paths_from)
    except OSError as error:
        print(f"repo-sentinel: could not read {args.paths_from!r}: {error}", file=sys.stderr)
        return EXIT_ERROR

    result = scan(
        args.path,
        DEFAULT_EXCLUDES + tuple(args.exclude),
        allow_examples=not args.no_example_allowlist,
        use_gitignore=not args.no_gitignore,
        only_paths=only_paths,
    )
    findings: "list[Finding]" = [
        finding
        for finding in result.findings
        if finding.severity >= min_severity and finding.confidence >= min_confidence
    ]

    notes: "list[str]" = []
    findings = _apply_disabled(findings, args.disable, notes)

    if args.write_baseline:
        return _write_baseline(args.write_baseline, findings)

    if args.baseline:
        try:
            recorded = baseline_module.load(args.baseline)
        except baseline_module.BaselineError as error:
            print(f"repo-sentinel: {error}", file=sys.stderr)
            return EXIT_ERROR
        findings, accepted, stale = recorded.partition(findings)
        if accepted:
            notes.append(f"{len(accepted)} finding(s) accepted by {args.baseline}.")
        if stale:
            notes.append(
                f"{len(stale)} baseline entr{'y' if len(stale) == 1 else 'ies'} "
                "no longer match anything: prune with --write-baseline."
            )

    if args.sort == "path":
        findings.sort(key=lambda finding: (finding.path, finding.line, finding.rule_id))

    if args.format in ("text", "markdown"):
        notes.append(_scan_note(result))

    exit_code = _emit(_render(args, findings, notes), args.output)
    if exit_code != EXIT_OK:
        return exit_code
    if any(finding.severity >= fail_on for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def _render(
    args: argparse.Namespace, findings: "list[Finding]", notes: "list[str]"
) -> str:
    if args.format == "json":
        return report.format_json(findings, version=__version__, notes=notes)
    if args.format == "sarif":
        return report.format_sarif(findings, version=__version__)
    if args.format == "markdown":
        return report.format_markdown(findings, notes=notes)
    colour = not args.no_color and args.output is None and sys.stdout.isatty()
    if args.quiet:
        return report.format_summary(findings, notes=notes)
    return report.format_text(findings, colour=colour, notes=notes)


def _listed_paths(source: "str | None") -> "list[str] | None":
    """Read a file list from a file or from stdin, or None when not asked."""
    if source is None:
        return None
    if source == "-":
        return sys.stdin.read().splitlines()
    with open(source, encoding="utf-8") as handle:
        return handle.read().splitlines()


def _scan_note(result) -> str:
    if result.file_count == 0:
        return "Scanned 0 files. Check the path, the excludes and your .gitignore."
    return f"Scanned {result.file_count} file(s) in {result.duration:.2f}s."


def _write_baseline(path: str, findings: "list[Finding]") -> int:
    try:
        count = baseline_module.write(path, findings, version=__version__)
    except baseline_module.BaselineError as error:
        print(f"repo-sentinel: {error}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Recorded {count} finding(s) as accepted in {path}.")
    print("Commit it, then fix them: a baseline is a list of debts, not exemptions.")
    return EXIT_OK


def main(argv: "Sequence[str] | None" = None) -> int:
    parser = build_parser()
    try:
        args = _apply_config(parser, argv)
    except config_module.ConfigError as error:
        print(f"repo-sentinel: {error}", file=sys.stderr)
        return EXIT_ERROR

    if args.command == "rules":
        return _emit(report.format_rule_catalogue(as_json=args.format == "json"), None)
    return _run_scan(args, parser)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
