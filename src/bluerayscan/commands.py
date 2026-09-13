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
from typing import TextIO

from . import (
    __version__,
    baseline as baseline_module,
    config as config_module,
    explain as explain_module,
    history,
    report,
    rules as rules_module,
)
from .discovery import DEFAULT_EXCLUDES, MAX_FILE_BYTES
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
        print(f"bluerayscan: could not write {destination!r}: {error}", file=sys.stderr)
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
        notes.append(f"No such rule: {', '.join(unknown)}. Check 'bluerayscan rules'.")
    return kept


def scan_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    # A path that is not there is a typo, not a clean repository. Scanning it
    # would print "no findings", which is the one answer this tool must never
    # give for a tree it did not read.
    if not os.path.exists(args.path):
        print(f"bluerayscan: no such file or directory: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    try:
        min_severity = Severity.parse(args.min_severity)
        min_confidence = Confidence.parse(args.min_confidence)
        fail_on = _fail_threshold(args.fail_on)
        max_bytes = _file_size_limit(getattr(args, "max_file_size", None))
    except ValueError as error:
        parser.error(str(error))
        return EXIT_ERROR  # pragma: no cover - argparse exits first

    try:
        only_paths = _listed_paths(args.paths_from)
    except OSError as error:
        print(f"bluerayscan: could not read {args.paths_from!r}: {error}", file=sys.stderr)
        return EXIT_ERROR

    result = scan(
        args.path,
        DEFAULT_EXCLUDES + tuple(args.exclude),
        allow_examples=not args.no_example_allowlist,
        use_gitignore=not args.no_gitignore,
        only_paths=only_paths,
        honour_markers=not args.no_suppression,
        max_bytes=max_bytes,
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

    if args.prune_baseline:
        return _prune_baseline(args.prune_baseline, findings)

    if args.baseline:
        try:
            recorded = baseline_module.load(args.baseline)
        except baseline_module.BaselineError as error:
            print(f"bluerayscan: {error}", file=sys.stderr)
            return EXIT_ERROR
        findings, accepted, stale = recorded.partition(findings)
        if accepted:
            notes.append(
                f"{len(accepted)} finding(s) accepted by "
                f"{_as_written(args.baseline, args.path)}."
            )
        if stale:
            notes.append(
                f"{len(stale)} baseline entr{'y' if len(stale) == 1 else 'ies'} "
                "no longer match anything: remove them with --prune-baseline."
            )

    if args.sort == "path":
        findings.sort(key=lambda finding: (finding.path, finding.line, finding.rule_id))

    # Every format that carries prose gets the summary sentence. json and
    # sarif carry the same facts as structure instead, which is what a machine
    # can act on.
    if args.format in ("text", "markdown", "github", "junit"):
        notes.append(_scan_note(result))

    exit_code = _emit(
        _render(args, findings, notes, result.duration, _scan_facts(result)),
        args.output,
    )
    if exit_code != EXIT_OK:
        return exit_code
    if fail_on is not None and any(finding.severity >= fail_on for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def history_command(args: argparse.Namespace) -> int:
    """Report the credentials a diff stream's commits introduced.

    The stream is read line by line rather than swallowed whole: a repository's
    history is a great deal larger than its working tree, and ``git log -p``
    over a decade of it is not something to hold in memory to answer a question
    about a few lines of it.
    """
    try:
        min_severity = Severity.parse(args.min_severity)
        min_confidence = Confidence.parse(args.min_confidence)
        fail_on = _fail_threshold(args.fail_on)
    except ValueError as error:
        print(f"bluerayscan: {error}", file=sys.stderr)
        return EXIT_ERROR

    try:
        handle, opened = _history_stream(args.file)
    except OSError as error:
        print(f"bluerayscan: could not read {args.file!r}: {error}", file=sys.stderr)
        return EXIT_ERROR

    try:
        result = history.scan_stream(
            handle, allow_examples=not args.no_example_allowlist
        )
    finally:
        if opened:
            handle.close()

    findings = [
        finding
        for finding in result.findings
        if finding.severity >= min_severity and finding.confidence >= min_confidence
    ]

    notes = []
    if args.format in ("text", "markdown", "github", "junit"):
        notes.append(result.summary)
        if result.commit_count == 0:
            # Nothing read looks exactly like nothing found, and this is the
            # command most likely to be handed an empty pipe by accident.
            notes.append(
                "No commits in the input. `git log -p` is what this reads; "
                "`git log` alone has no diffs in it."
            )
        elif findings:
            notes.append(
                "A credential in history is on every clone, fork and CI cache "
                "made since. Deleting the file does not take it back: rotate it."
            )

    facts = {
        "commits": result.commit_count,
        "file_revisions": result.file_count,
    }
    exit_code = _emit(_render(args, findings, notes, 0.0, facts), args.output)
    if exit_code != EXIT_OK:
        return exit_code
    if fail_on is not None and any(finding.severity >= fail_on for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def explain_command(args: argparse.Namespace) -> int:
    """Say what the heuristic rules make of one value.

    Exit code follows the answer rather than the run: 1 when the value would
    be reported, 0 when it would not, so a shell can ask the question without
    reading the prose.
    """
    value = sys.stdin.readline() if args.value == "-" else args.value
    answer = explain_module.explain(value, args.name)
    print(answer.render())
    return EXIT_FINDINGS if answer.reported else EXIT_OK


def _history_stream(name: str) -> "tuple[TextIO, bool]":
    """The lines to read, and whether this opened a file that must be closed."""
    if name == "-":
        return sys.stdin, False
    return open(name, encoding="utf-8", errors="replace"), True


def _scan_facts(result) -> "dict":
    """What the run looked at, as data rather than as a sentence."""
    return {
        "files": result.file_count,
        "duration_seconds": round(result.duration, 3),
        "unreadable": list(result.unreadable),
        "oversized": list(result.oversized),
        "suppressed_lines": result.suppressed_lines,
        "suppressed_files": result.suppressed_files,
    }


def _render(
    args: argparse.Namespace,
    findings: "list[Finding]",
    notes: "list[str]",
    duration: float = 0.0,
    scan: "dict | None" = None,
) -> str:
    if args.format == "json":
        return report.format_json(
            findings, version=__version__, notes=notes, scan=scan
        )
    if args.format == "sarif":
        return report.format_sarif(findings, version=__version__, scan=scan)
    if args.format == "markdown":
        return report.format_markdown(findings, notes=notes)
    if args.format == "github":
        return report.format_github(findings, notes=notes)
    if args.format == "junit":
        return report.format_junit(findings, notes=notes, duration=duration)
    colour = not args.no_color and args.output is None and sys.stdout.isatty()
    if args.quiet:
        return report.format_summary(findings, notes=notes)
    return report.format_text(
        findings, colour=colour, notes=notes, by_file=args.sort == "path"
    )


_SIZE_SUFFIXES = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}


def _file_size_limit(value: "str | None") -> int:
    """Bytes from "2M", "500k" or a plain number; the default when unset."""
    if value is None:
        return MAX_FILE_BYTES
    text = value.strip().lower().rstrip("b")
    scale = _SIZE_SUFFIXES.get(text[-1:], 1)
    digits = text[:-1] if scale > 1 else text
    if not digits.isdigit() or int(digits) <= 0:
        raise ValueError(f"unreadable size {value!r} (try 2M, 500k, or a number of bytes)")
    return int(digits) * scale


def _as_written(path: str, root: str) -> str:
    """A path the way the rest of the report writes them: relative to the scan.

    The baseline's location arrives absolute when it came from a config file,
    which resolves it against the config's own directory. Printing that in a
    sentence otherwise full of repository-relative paths reads as a different
    kind of thing, which it is not.
    """
    try:
        relative = os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(root))
    except ValueError:  # pragma: no cover - different drives on Windows
        return path
    return path if relative.startswith("..") else relative.replace(os.sep, "/")


def _fail_threshold(value: str) -> "Severity | None":
    """The severity that fails the run, or None for "report, never fail".

    A reporting job -- the one that uploads SARIF, posts the comment, writes
    the JUnit file -- must not stop at the first finding, and every CI system
    has its own word for that: continue-on-error, allow_failure,
    continueOnError, catchError. Saying it here instead means the gate and the
    report are the same command with one flag between them, and the flag is
    readable from the pipeline.
    """
    if value.strip().lower() == "none":
        return None
    return Severity.parse(value)


def _listed_paths(source: "str | None") -> "list[str] | None":
    """Read a file list from a file or from stdin, or None when not asked."""
    if source is None:
        return None
    if source == "-":
        return sys.stdin.read().splitlines()
    with open(source, encoding="utf-8") as handle:
        return handle.read().splitlines()


def _scan_note(result) -> str:
    # The unreadable count is appended in both branches on purpose. A tree
    # nothing could be read from scans zero files, which is precisely when
    # "no findings" is most misleading and the reason is most worth saying.
    if result.unreadable:
        unread = (
            f" {len(result.unreadable)} path(s) could not be opened and were not "
            f"scanned, starting with {result.unreadable[0]!r}."
        )
    else:
        unread = ""
    if result.file_count == 0:
        return (
            "Scanned 0 files. Check the path, the excludes and your .gitignore."
            + unread
        )
    note = f"Scanned {result.file_count} file(s) in {result.duration:.2f}s." + unread
    if result.oversized:
        note += (
            f" {len(result.oversized)} file(s) were larger than the size limit "
            f"and were not read, starting with {result.oversized[0]!r}; "
            "--max-file-size raises it."
        )
    if result.suppressed_lines:
        note += (
            f" {result.suppressed_lines} line(s) in {result.suppressed_files} file(s) "
            "carry a suppression marker; --no-suppression reads past them."
        )
    return note


def _prune_baseline(path: str, findings: "list[Finding]") -> int:
    """Remove the entries that match nothing, and add nothing.

    The difference from ``--write-baseline`` is the whole point of having both.
    Rewriting a baseline accepts everything the scan just found, which is
    exactly what somebody tidying up a stale file does not want to do by
    accident; this keeps the entries that still match and drops the rest.
    """
    try:
        recorded = baseline_module.load(path)
    except baseline_module.BaselineError as error:
        print(f"bluerayscan: {error}", file=sys.stderr)
        return EXIT_ERROR

    _, accepted, stale = recorded.partition(findings)
    if not stale:
        print(f"Nothing to prune: every entry in {path} still matches.")
        return EXIT_OK

    try:
        kept = baseline_module.write(path, accepted, version=__version__)
    except baseline_module.BaselineError as error:
        print(f"bluerayscan: {error}", file=sys.stderr)
        return EXIT_ERROR

    print(
        f"Pruned {len(stale)} entr{'y' if len(stale) == 1 else 'ies'} from {path}; "
        f"{kept} left. Nothing new was accepted."
    )
    for entry in stale:
        print(f"  gone: {entry.rule_id}  {entry.path}  {entry.title[:60]}")
    return EXIT_OK


def _write_baseline(path: str, findings: "list[Finding]") -> int:
    try:
        count = baseline_module.write(path, findings, version=__version__)
    except baseline_module.BaselineError as error:
        print(f"bluerayscan: {error}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Recorded {count} finding(s) as accepted in {path}.")
    print("Commit it, then fix them: a baseline is a list of debts, not exemptions.")
    return EXIT_OK


#: The GitHub snippet uses the repository's composite action; the other four
#: install the immutable PyPI release and ask for JUnit, because those CI
#: systems draw it natively.
_ACTIONS_SNIPPET = """\
# .github/workflows/bluerayscan.yml
name: bluerayscan
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
      - uses: KhanSaahib/bluerayscan@main
"""

_GITLAB_SNIPPET = """\
# .gitlab-ci.yml
bluerayscan:
  image: python:3.13
  script:
    - python -m pip install bluerayscan==0.4.0
    - bluerayscan scan . --format junit --output bluerayscan.xml
  artifacts:
    when: always
    reports:
      junit: bluerayscan.xml
"""

_INSTALL = "python -m pip install bluerayscan==0.4.0"

_AZURE_SNIPPET = f"""\
# azure-pipelines.yml
steps:
  - script: |
      {_INSTALL}
      bluerayscan scan . --format junit --output bluerayscan.xml
    displayName: bluerayscan
  - task: PublishTestResults@2
    condition: always()
    inputs:
      testResultsFiles: bluerayscan.xml
"""

_CIRCLECI_SNIPPET = f"""\
# .circleci/config.yml
jobs:
  bluerayscan:
    docker:
      - image: cimg/python:3.13
    steps:
      - checkout
      - run: {_INSTALL}
      - run: mkdir -p test-results
      - run: bluerayscan scan . --format junit --output test-results/bluerayscan.xml
      - store_test_results:
          path: test-results
"""

_JENKINS_SNIPPET = f"""\
// Jenkinsfile
stage('bluerayscan') {{
  steps {{
    sh '{_INSTALL}'
    sh 'bluerayscan scan . --format junit --output bluerayscan.xml'
  }}
  post {{
    always {{
      junit 'bluerayscan.xml'
    }}
  }}
}}
"""

#: Which file says a repository uses which CI, worst-guess last. GitHub is at
#: the end because .github/ exists in repositories that run their pipelines
#: somewhere else entirely, and because it is the fallback anyway.
_CI_SYSTEMS = (
    (os.path.join(".github", "workflows"), _ACTIONS_SNIPPET),
    (".gitlab-ci.yml", _GITLAB_SNIPPET),
    ("azure-pipelines.yml", _AZURE_SNIPPET),
    (os.path.join(".circleci", "config.yml"), _CIRCLECI_SNIPPET),
    ("Jenkinsfile", _JENKINS_SNIPPET),
)


def _ci_snippet(root: str) -> str:
    """The snippet for the CI system this repository already has.

    Suggesting GitHub Actions to a project that runs GitLab is how a
    getting-started section gets skipped. GitHub wins a tie only because it is
    also the fallback: a repository with both has a .github directory that may
    hold nothing but issue templates.
    """
    for marker, snippet in _CI_SYSTEMS:
        if os.path.exists(os.path.join(root, marker)):
            return snippet
    return _ACTIONS_SNIPPET


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
    for line in report.loudest_rules(findings):
        print(line)

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
            # A baseline makes what is already committed invisible, which is
            # what it is for and also its one danger: a credential in the
            # working tree is usually in history too, and one that is in
            # history is public whatever the working tree says later. This is
            # the moment to say so -- the person running init is the person
            # who has not looked yet.
            if any(finding.rule_id.startswith("SEC") for finding in at_or_above):
                print(
                    "\nSome of those are credentials. A baseline hides them from "
                    "the pipeline; it does not take them back. Check whether they "
                    "are already public:\n\n"
                    "  git log -p --date=iso | bluerayscan history"
                )

    if os.path.exists(config_path) and not args.force:
        print(f"{config_module.DEFAULT_PATH} exists already; left alone.")
    else:
        with open(config_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(settings, indent=2) + "\n")
        print(f"Wrote {config_module.DEFAULT_PATH}.")

    print("\nAdd this to your pipeline:\n")
    print(_ci_snippet(root))
    return EXIT_OK


def rules_command(args: argparse.Namespace) -> int:
    """Print the catalogue, or the part of it somebody asked about."""
    return _emit(
        report.format_rule_catalogue(args.pattern, as_json=args.format == "json"), None
    )
