"""Audit GitHub Actions workflow files for well-known footguns.

These checks are deliberately pattern-based rather than YAML-aware: the whole
tool is standard library only, and a linter that reads the file the way a
reviewer skims it catches the mistakes that actually get shipped. The trade-off
is that exotic formatting can slip past, which is why every rule here reports
what it saw rather than asserting the file is clean.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from ..findings import Finding, Severity

_WORKFLOW_DIR = ".github/workflows"
_WORKFLOW_SUFFIXES = (".yml", ".yaml")

_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?(?P<ref>[^\s'\"#]+)")
_SHA_PIN = re.compile(r"^[0-9a-f]{40}$")
_LOCAL_ACTION = re.compile(r"^(?:\./|docker://)")
_RUN_START = re.compile(r"^(?P<indent>\s*)(?:-\s*)?run:\s*(?P<inline>.*)$")
_TOP_LEVEL_PERMISSIONS = re.compile(r"^permissions:")
_PULL_REQUEST_TARGET = re.compile(r"^\s*(?:-\s*)?pull_request_target\b")
_CHECKOUT_WITH_REF = re.compile(r"^\s*ref:\s*\S")

#: Contexts an outside contributor can write to. Interpolating any of these
#: into a shell command hands them the runner.
_UNTRUSTED = re.compile(
    r"""\$\{\{\s*
    (?P<expr>
        github\.head_ref
      | github\.event\.(?:issue|pull_request|comment|review|discussion
                        |head_commit|commits|workflow_run|pages)\b[^}]*
    )
    \s*\}\}""",
    re.VERBOSE,
)


def is_workflow_path(path: str) -> bool:
    """True for files GitHub will actually execute as workflows."""
    normalised = path.replace("\\", "/")
    return (
        posixpath.dirname(normalised).endswith(_WORKFLOW_DIR)
        and normalised.endswith(_WORKFLOW_SUFFIXES)
    )


def _iter_run_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, text)`` for every line inside a ``run:`` block."""
    index = 0
    while index < len(lines):
        match = _RUN_START.match(lines[index])
        if not match:
            index += 1
            continue

        inline = match.group("inline").strip()
        if inline and not inline.startswith(("|", ">")):
            yield index + 1, lines[index]
            index += 1
            continue

        # Block scalar: everything indented deeper than `run:` belongs to it.
        base_indent = len(match.group("indent"))
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and (len(line) - len(line.lstrip())) <= base_indent:
                break
            yield index + 1, line
            index += 1


def scan_workflow(path: str, text: str) -> list[Finding]:
    """Run every workflow rule against one workflow file."""
    lines = text.splitlines()
    findings: list[Finding] = []

    for number, line in enumerate(lines, start=1):
        match = _USES.match(line)
        if not match:
            continue
        ref = match.group("ref")
        if _LOCAL_ACTION.match(ref):
            continue
        _, _, version = ref.partition("@")
        if not version:
            findings.append(
                Finding(
                    rule_id="WF001",
                    severity=Severity.MEDIUM,
                    title=f"Action {ref!r} has no version reference",
                    path=path,
                    line=number,
                    evidence=line.strip(),
                    remediation="Pin the action to a full 40-character commit SHA.",
                )
            )
        elif not _SHA_PIN.match(version):
            findings.append(
                Finding(
                    rule_id="WF001",
                    severity=Severity.MEDIUM,
                    title=f"Action {ref!r} is pinned to a mutable tag",
                    path=path,
                    line=number,
                    evidence=line.strip(),
                    remediation=(
                        "Tags can be moved to point at new code. Pin to a full commit "
                        "SHA and let Dependabot propose upgrades."
                    ),
                )
            )

    for number, line in _iter_run_lines(lines):
        for match in _UNTRUSTED.finditer(line):
            findings.append(
                Finding(
                    rule_id="WF003",
                    severity=Severity.CRITICAL,
                    title=f"Untrusted input {match.group('expr')} interpolated into a shell command",
                    path=path,
                    line=number,
                    evidence=line.strip(),
                    remediation=(
                        "Pass the value through an env: block and reference it as "
                        '"$VAR" so the shell never parses attacker-controlled text.'
                    ),
                )
            )

    if not any(_TOP_LEVEL_PERMISSIONS.match(line) for line in lines):
        findings.append(
            Finding(
                rule_id="WF002",
                severity=Severity.MEDIUM,
                title="Workflow does not declare GITHUB_TOKEN permissions",
                path=path,
                line=1,
                evidence="no top-level 'permissions:' block",
                remediation=(
                    "Add a top-level 'permissions: contents: read' block and widen it "
                    "per job only where a job needs more."
                ),
            )
        )

    uses_prt = any(_PULL_REQUEST_TARGET.match(line) for line in lines)
    if uses_prt:
        for number, line in enumerate(lines, start=1):
            if _CHECKOUT_WITH_REF.match(line):
                findings.append(
                    Finding(
                        rule_id="WF004",
                        severity=Severity.CRITICAL,
                        title="pull_request_target checks out untrusted code",
                        path=path,
                        line=number,
                        evidence=line.strip(),
                        remediation=(
                            "pull_request_target runs with repository secrets. Checking "
                            "out the pull request head lets a fork execute code with "
                            "those secrets. Use pull_request, or check out the base ref."
                        ),
                    )
                )
                break

    return findings


def scan_files(files: Iterable[tuple[str, str]]) -> list[Finding]:
    """Scan ``(path, text)`` pairs, ignoring anything that is not a workflow."""
    return [
        finding
        for path, text in files
        if is_workflow_path(path)
        for finding in scan_workflow(path, text)
    ]
