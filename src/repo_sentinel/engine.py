"""Running every scanner over a tree and collecting the result."""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Iterable

from .discovery import DEFAULT_EXCLUDES, Entry, read_listed, walk
from . import suppression
from .findings import Finding
from .scanners import (
    ansible,
    azure,
    circleci,
    cloudformation,
    compose,
    dependencies,
    dockerfiles,
    filenames,
    gitlab,
    jenkins,
    kubernetes,
    secrets,
    shell,
    terraform,
    workflows,
)


#: Every scanner that reads whole files and filters by format. Named here
#: rather than inline so a test can assert it holds every scanner the package
#: has -- a new one missing from this tuple is a scanner that runs in its own
#: unit tests and nowhere else, which is the kind of gap nothing else notices.
#:
#: :mod:`.scanners.secrets` is called separately because it reads every file
#: rather than filtering, and :mod:`.scanners.filenames` because it takes paths
#: rather than contents.
FORMAT_SCANNERS = (
    ansible,
    azure,
    circleci,
    cloudformation,
    compose,
    dependencies,
    dockerfiles,
    gitlab,
    jenkins,
    kubernetes,
    shell,
    terraform,
    workflows,
)


@dataclasses.dataclass(frozen=True)
class ScanReport:
    """Everything one run learned, including what it looked at.

    The file count is part of the result rather than a debug detail: a run that
    scanned nothing looks exactly like a clean repository in the output, and
    "no findings" from a mistyped path is the most dangerous answer this tool
    can give.
    """

    findings: "list[Finding]"
    file_count: int
    duration: float
    #: How many lines carry a suppression directive, and in how many files.
    #: Reported rather than merely obeyed: a scanner that can be switched off
    #: invisibly is worse than no scanner.
    suppressed_lines: int = 0
    suppressed_files: int = 0
    #: Paths the walk could not open. Skipped, as they have to be, but counted,
    #: because "no findings" from a tree that was never read is the most
    #: dangerous answer this tool can give.
    unreadable: "tuple[str, ...]" = ()


def scan(
    path: str,
    excludes: "tuple[str, ...]" = DEFAULT_EXCLUDES,
    *,
    allow_examples: bool = True,
    use_gitignore: bool = True,
    only_paths: "Iterable[str] | None" = None,
    honour_markers: bool = True,
) -> ScanReport:
    """Run every scanner over ``path``, worst findings first.

    With ``only_paths``, the walk is replaced by that explicit list -- the files
    a pull request touched, usually. Everything downstream is identical, so a
    fast per-PR run and a full audit produce the same findings for the same
    file.
    """
    started = time.monotonic()
    unreadable: "list[str]" = []
    if only_paths is None:
        entries = list(
            walk(path, excludes=excludes, use_gitignore=use_gitignore, unreadable=unreadable)
        )
    else:
        entries = [
            walk_entry
            for walk_entry in _entries_for(path, only_paths, excludes)
        ]
    files = [(entry.path, entry.text) for entry in entries if entry.text is not None]

    found = filenames.scan_paths(
        [(entry.path, entry.text) for entry in entries], honour_markers=honour_markers
    )
    found += secrets.scan_files(
        files, allow_examples=allow_examples, honour_markers=honour_markers
    )
    for scanner in FORMAT_SCANNERS:
        found += scanner.scan_files(files, honour_markers=honour_markers)

    marked = [_count_markers(text) for _, text in files]

    return ScanReport(
        findings=sorted(collapse(found), key=lambda finding: finding.sort_key),
        file_count=len(entries),
        duration=time.monotonic() - started,
        suppressed_lines=sum(marked),
        suppressed_files=sum(1 for count in marked if count),
        unreadable=tuple(unreadable),
    )


def _count_markers(text: str) -> int:
    """How many lines carry a suppression directive.

    The directives themselves, not the lines a block covers -- that is what
    the number in the report claims, and a count that means something else is
    worse than no count. The substring test in front skips the whole per-line
    pass for the files that have no marker at all, which is almost all of them.
    """
    if "repo-sentinel" not in text:
        return 0
    return sum(1 for line in text.splitlines() if suppression.marker(line) is not None)


def _entries_for(
    path: str, only_paths: "Iterable[str]", excludes: "tuple[str, ...]"
) -> "list[Entry]":
    """Explicit paths as walk entries, so the name rules see them too."""
    return [Entry(name, text) for name, text in read_listed(path, only_paths, excludes=excludes)]


def collapse(findings: "Iterable[Finding]") -> "list[Finding]":
    """Drop the second report of one problem.

    Scanners overlap on purpose -- a credential inside a Kubernetes Secret is
    both a manifest problem and a secret, and each rule says something the
    other cannot. What nobody needs is that one value listed twice.

    Only findings that name a ``subject`` take part, and the subject is the
    redacted credential itself. Collapsing on anything vaguer loses real
    findings: two Dockerfile rules can report the same line with the same
    evidence and mean entirely different things, and an unpinned base image is
    not the same problem as a container running as root.

    Where subjects do match, the more severe finding wins; on a tie the rule
    whose id sorts first does, which keeps the format-specific rule over the
    generic one, since every format prefix sorts ahead of SEC.
    """
    best: "dict[tuple[str, int, str], Finding]" = {}
    kept: "list[Finding]" = []
    for finding in findings:
        if not finding.subject:
            kept.append(finding)
            continue
        key = (finding.path, finding.line, finding.subject)
        current = best.get(key)
        if current is None or (
            (-finding.severity.rank, -finding.confidence.rank, finding.rule_id)
            < (-current.severity.rank, -current.confidence.rank, current.rule_id)
        ):
            best[key] = finding
    return kept + list(best.values())


def scan_path(
    path: str,
    excludes: "tuple[str, ...]" = DEFAULT_EXCLUDES,
    *,
    allow_examples: bool = True,
    use_gitignore: bool = True,
    only_paths: "Iterable[str] | None" = None,
) -> "list[Finding]":
    """Just the findings, for callers that do not care how the run went."""
    return scan(
        path,
        excludes,
        allow_examples=allow_examples,
        use_gitignore=use_gitignore,
        only_paths=only_paths,
    ).findings
