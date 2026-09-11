"""What each subcommand actually does.

Separated from :mod:`.cli`, which is the parser and the dispatch, so that
neither file has to be read to understand the other. The split follows the one
rule that matters for a tool whose whole job is to fail a build at the right
moment: the code deciding *what* to report should not be tangled with the code
deciding *whether* an argument was spelled correctly.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence

from . import __version__, baseline as baseline_module, config as config_module, report
from .discovery import DEFAULT_EXCLUDES
from .engine import scan
from .findings import Confidence, Finding, Severity
from .rules import RULES

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


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


def _apply_disabled(
    findings: "list[Finding]",
    patterns: "Sequence[str]",
    scopes: "Sequence[config_module.PathScope]",
    notes: "list[str]",
) -> "list[Finding]":
    """Drop the rules a project has switched off, and say that it did.

    Two ways to switch one off: everywhere, through ``disable``, and under one
    glob, through the ``paths`` table. Both are counted rather than silently
    applied -- silence that nobody can see is the failure mode this whole tool
    is built to avoid. An unknown rule id is called out too: a typo there
    quietly leaves the rule switched on, which is the safe direction but not
    the intended one.
    """
    if not patterns and not scopes:
        return findings

    disabled = config_module.disabled_matcher(patterns)
    scoped = [(scope, config_module.disabled_matcher(scope.disable)) for scope in scopes]
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


def scan_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
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
        honour_markers=not args.no_suppression,
    )
    findings: "list[Finding]" = [
        finding
        for finding in result.findings
        if finding.severity >= min_severity and finding.confidence >= min_confidence
    ]

    notes: "list[str]" = []
    findings = _apply_disabled(
        findings, args.disable, getattr(args, "path_scopes", ()), notes
    )

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

    if args.format in ("text", "markdown", "github"):
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
    if args.format == "github":
        return report.format_github(findings, notes=notes)
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
    note = f"Scanned {result.file_count} file(s) in {result.duration:.2f}s."
    if result.suppressed_lines:
        note += (
            f" {result.suppressed_lines} line(s) in {result.suppressed_files} file(s) "
            "carry a suppression marker; --no-suppression reads past them."
        )
    return note


def _write_baseline(path: str, findings: "list[Finding]") -> int:
    try:
        count = baseline_module.write(path, findings, version=__version__)
    except baseline_module.BaselineError as error:
        print(f"repo-sentinel: {error}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Recorded {count} finding(s) as accepted in {path}.")
    print("Commit it, then fix them: a baseline is a list of debts, not exemptions.")
    return EXIT_OK


#: Both snippets use a git reference rather than a package index, because that
#: is what actually works today, and both say to pin -- a tool whose own
#: getting-started copy trips WF001 has a credibility problem.
_ACTIONS_SNIPPET = """\
# .github/workflows/repo-sentinel.yml
name: repo-sentinel
on: [push, pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      # Pin both of these to a full commit SHA before you rely on them.
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: KhanSaahib/repo-sentinel@main
"""

_GITLAB_SNIPPET = """\
# .gitlab-ci.yml
repo-sentinel:
  image: python:3.13
  script:
    - pip install git+https://github.com/KhanSaahib/repo-sentinel@main
    - repo-sentinel scan .
"""


def init_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Set a repository up, and say what was found on the way.

    Three things, in the order someone actually needs them: what is in the
    repository now, a config file recording the decisions that answer implies,
    and a baseline holding whatever is already there so the first pipeline run
    is green and every later one is about new work.

    Nothing is overwritten without --force. Silently replacing a config
    somebody tuned would be a poor introduction.
    """
    try:
        fail_on = Severity.parse(args.fail_on)
    except ValueError as error:
        parser.error(str(error))
        return EXIT_ERROR  # pragma: no cover - argparse exits first

    root = args.path
    result = scan(root, DEFAULT_EXCLUDES)
    findings = result.findings
    print(
        f"Scanned {result.file_count} file(s) in {result.duration:.2f}s: "
        f"{report.summarise(findings) if findings else 'no findings'}."
    )

    config_path = os.path.join(root, config_module.DEFAULT_PATH)
    baseline_path = os.path.join(root, baseline_module.DEFAULT_PATH)
    at_or_above = [finding for finding in findings if finding.severity >= fail_on]

    settings: "dict[str, object]" = {"fail_on": fail_on.value}
    if at_or_above and not args.no_baseline:
        if os.path.exists(baseline_path) and not args.force:
            print(f"{baseline_module.DEFAULT_PATH} exists already; left alone.")
        else:
            baseline_module.write(baseline_path, at_or_above, version=__version__)
            settings["baseline"] = baseline_module.DEFAULT_PATH
            print(
                f"Recorded {len(at_or_above)} finding(s) in "
                f"{baseline_module.DEFAULT_PATH}. It is a list of debts: shrink it."
            )

    if os.path.exists(config_path) and not args.force:
        print(f"{config_module.DEFAULT_PATH} exists already; left alone.")
    else:
        with open(config_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(settings, indent=2) + "\n")
        print(f"Wrote {config_module.DEFAULT_PATH}.")

    print("\nAdd this to your pipeline:\n")
    print(_GITLAB_SNIPPET if _uses_gitlab(root) else _ACTIONS_SNIPPET)
    return EXIT_OK


def _uses_gitlab(root: str) -> bool:
    """Suggest the CI system the repository already has, not the popular one."""
    return os.path.exists(os.path.join(root, ".gitlab-ci.yml")) and not os.path.isdir(
        os.path.join(root, ".github", "workflows")
    )


def rules_command(args: argparse.Namespace) -> int:
    """Print the catalogue, or the part of it somebody asked about."""
    return _emit(
        report.format_rule_catalogue(args.pattern, as_json=args.format == "json"), None
    )
