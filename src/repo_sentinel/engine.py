"""Running every scanner over a tree and collecting the result."""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Iterable

from .discovery import DEFAULT_EXCLUDES, Entry, read_listed, walk
from .findings import Finding
from .scanners import (
    cloudformation,
    compose,
    dependencies,
    dockerfiles,
    filenames,
    gitlab,
    kubernetes,
    secrets,
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


def scan(
    path: str,
    excludes: "tuple[str, ...]" = DEFAULT_EXCLUDES,
    *,
    allow_examples: bool = True,
    use_gitignore: bool = True,
    only_paths: "Iterable[str] | None" = None,
) -> ScanReport:
    """Run every scanner over ``path``, worst findings first.

    With ``only_paths``, the walk is replaced by that explicit list -- the files
    a pull request touched, usually. Everything downstream is identical, so a
    fast per-PR run and a full audit produce the same findings for the same
    file.
    """
    started = time.monotonic()
    if only_paths is None:
        entries = list(walk(path, excludes=excludes, use_gitignore=use_gitignore))
    else:
        entries = [
            walk_entry
            for walk_entry in _entries_for(path, only_paths, excludes)
        ]
    files = [(entry.path, entry.text) for entry in entries if entry.text is not None]

    found = filenames.scan_paths([(entry.path, entry.text) for entry in entries])
    found += secrets.scan_files(files, allow_examples=allow_examples)
    found += workflows.scan_files(files)
    found += dockerfiles.scan_files(files)
    found += terraform.scan_files(files)
    found += kubernetes.scan_files(files)
    found += compose.scan_files(files)
    found += gitlab.scan_files(files)
    found += cloudformation.scan_files(files)
    found += dependencies.scan_files(files)

    return ScanReport(
        findings=sorted(collapse(found), key=lambda finding: finding.sort_key),
        file_count=len(entries),
        duration=time.monotonic() - started,
    )


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
