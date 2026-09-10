"""Running every scanner over a tree and collecting the result."""

from __future__ import annotations

import dataclasses
import time

from .discovery import DEFAULT_EXCLUDES, iter_files
from .findings import Finding
from .scanners import dockerfiles, secrets, workflows


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
) -> ScanReport:
    """Run every scanner over ``path``, worst findings first."""
    started = time.monotonic()
    files = list(iter_files(path, excludes=excludes, use_gitignore=use_gitignore))

    found = secrets.scan_files(files, allow_examples=allow_examples)
    found += workflows.scan_files(files)
    found += dockerfiles.scan_files(files)

    return ScanReport(
        findings=sorted(found, key=lambda finding: finding.sort_key),
        file_count=len(files),
        duration=time.monotonic() - started,
    )


def scan_path(
    path: str,
    excludes: "tuple[str, ...]" = DEFAULT_EXCLUDES,
    *,
    allow_examples: bool = True,
    use_gitignore: bool = True,
) -> "list[Finding]":
    """Just the findings, for callers that do not care how the run went."""
    return scan(
        path, excludes, allow_examples=allow_examples, use_gitignore=use_gitignore
    ).findings
