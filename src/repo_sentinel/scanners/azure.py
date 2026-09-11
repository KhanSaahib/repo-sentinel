"""Audit Azure Pipelines definitions.

The third CI system, and the third appearance of the same bug. Azure expands
``$(Build.SourceVersionMessage)`` into the shell before the shell runs, exactly
as Actions expands ``${{ github.event.issue.title }}`` and GitLab expands
``$CI_COMMIT_TITLE``, and exactly as those two, some of the variables it
expands carry text a stranger wrote: a commit message, a pull request title, a
source branch name on a fork.

Three more: a pipeline that runs on a self-hosted pool, which outlives the job
that ran on it; a container image the pipeline pulls without pinning; and
``system.debug``, which prints every variable the job can see into a log that
is often readable by anyone who can see the project.

Pipelines are recognised by name (``azure-pipelines.yml``) or by shape -- a
document with ``steps``, ``jobs`` or ``stages`` and a ``pool`` or a ``trigger``
-- because a template can live in any file and be included from anywhere.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown, yamlish
from . import ci
from ..findings import Confidence, Finding, Severity

_YAML_SUFFIXES = (".yaml", ".yml")
_PIPELINE_NAMES = ("azure-pipelines.yml", "azure-pipelines.yaml", "vsts-ci.yml")

#: Keys that only a pipeline has.
_PIPELINE_KEYS = ("steps", "jobs", "stages")
_SUPPORTING_KEYS = ("pool", "trigger", "pr", "variables", "extends", "resources")

#: Variables whose value an outside contributor writes. Azure expands these
#: into the command line before the shell parses it.
_UNTRUSTED_VARIABLES = (
    "Build.SourceVersionMessage",
    "Build.SourceBranchName",
    "Build.SourceBranch",
    "Build.RequestedFor",
    "Build.RequestedForEmail",
    "System.PullRequest.SourceBranch",
    "System.PullRequest.SourceCommitId",
    "System.PullRequest.SourceRepositoryURI",
    "System.PullRequest.PullRequestId",
)
_UNTRUSTED = re.compile(
    r"\$\(\s*(?P<name>" + "|".join(re.escape(name) for name in _UNTRUSTED_VARIABLES) + r")\s*\)",
    re.IGNORECASE,
)

_SCRIPT_KEYS = ("script", "bash", "powershell", "pwsh")
_IMAGE_TAG = re.compile(r"^(?P<image>[^\s@]+?)(?::(?P<tag>[^:/@]+))?(?:@(?P<digest>sha256:\w+))?$")


def is_yaml_path(path: str) -> bool:
    return posixpath.basename(path.replace("\\", "/")).lower().endswith(_YAML_SUFFIXES)


def is_named_pipeline(path: str) -> bool:
    name = posixpath.basename(path.replace("\\", "/")).lower()
    return name.endswith(_PIPELINE_NAMES) or name.startswith("azure-pipelines")


def is_pipeline(path: str, document: "yamlish.Node") -> bool:
    """True for a document Azure would run, by name or by shape."""
    if not document.is_map or document.get("apiVersion") is not None:
        return False
    if is_named_pipeline(path):
        return True
    keys = {key for key, _ in document.items()}
    return bool(keys & set(_PIPELINE_KEYS)) and bool(keys & set(_SUPPORTING_KEYS))


def _steps(document: "yamlish.Node") -> "Iterator[yamlish.Node]":
    """Every step, at whatever depth the pipeline's shape puts it."""
    for key, node in document.walk():
        if key != "steps" or not node.is_list:
            continue
        for step in node.entries():
            if step.is_map:
                yield step


def _describe(step: "yamlish.Node") -> str:
    for key in ("displayName", "task", "script"):
        node = step.get(key)
        if node is not None and node.text:
            return f"Step {node.text.strip()[:40]!r}"
    return "A step"


def _check_injection(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """AZ001: text an outsider wrote, expanded into a command line."""
    for step in _steps(document):
        for line, command in ci.script_lines(step, _SCRIPT_KEYS):
            match = next(ci.untrusted_matches(command, _UNTRUSTED, ci.HARMLESS_FIELDS), None)
            if match is None:
                continue
            yield Finding(
                rule_id="AZ001",
                severity=Severity.CRITICAL,
                title=f"{_describe(step)} expands $({match.group('name')}) into a command",
                path=path,
                line=line,
                evidence=command.strip()[:120],
                remediation=(
                    "Azure substitutes this before the shell parses the line, "
                    "so a commit message containing $(...) or a backtick runs "
                    "on the agent. Map it into an env: block and reference it "
                    "as \"$VAR\", which the shell will not re-expand."
                ),
            )


def _check_pool(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """AZ002: a self-hosted pool, which keeps whatever a job leaves behind."""
    for key, node in document.walk():
        if key != "pool":
            continue
        name = node.get("name") if node.is_map else node
        if name is None or not name.text:
            continue
        value = name.text.strip().strip("\"'")
        if value.lower().startswith(("ubuntu-", "windows-", "macos-", "vs20")):
            continue
        yield Finding(
            rule_id="AZ002",
            severity=Severity.MEDIUM,
            title=f"Pipeline runs on the self-hosted pool {value!r}",
            path=path,
            line=name.line,
            evidence=f"pool: {value}",
            remediation=(
                "A self-hosted agent keeps state between jobs, so anything one "
                "job leaves behind is available to the next. Use ephemeral "
                "agents, and never pair one with a pipeline a fork can trigger."
            ),
            confidence=Confidence.MEDIUM,
        )


def _check_container(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """AZ003: a container image the pipeline pulls, unpinned."""
    for key, node in document.walk():
        if key not in ("container", "image"):
            continue
        reference = (node.get("image") if node.is_map else node)
        if reference is None or not reference.text:
            continue
        value = reference.text.strip().strip("\"'")
        if wellknown.is_interpolated(value):
            continue
        match = _IMAGE_TAG.match(value)
        if match is None or match.group("digest"):
            continue
        tag = match.group("tag")
        if tag is not None and tag != "latest":
            continue
        yield Finding(
            rule_id="AZ003",
            severity=Severity.MEDIUM,
            title=f"Pipeline pulls {value}, which floats",
            path=path,
            line=reference.line,
            evidence=f"container: {value}",
            remediation=(
                "The image a pipeline runs in is the code it runs. An unpinned "
                "tag means a rebuild can execute something nobody reviewed."
            ),
            confidence=Confidence.MEDIUM,
        )


def _check_debug(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """AZ004: the switch that writes every variable into the job log."""
    for key, node in document.walk():
        if key.lower() != "system.debug" or not node.truthy():
            continue
        yield Finding(
            rule_id="AZ004",
            severity=Severity.HIGH,
            title="system.debug writes every variable into the job log",
            path=path,
            line=node.line,
            evidence="system.debug: true",
            remediation=(
                "Debug logging prints the values of variables, secret ones "
                "included, into a log that is often readable by anyone who can "
                "see the project. Turn it on by hand for one run, not in the "
                "file for every run."
            ),
        )


_RULES = (_check_injection, _check_pool, _check_container, _check_debug)


def scan_pipeline(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every Azure Pipelines rule against one definition."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    if not is_named_pipeline(path) and not any(
        f"{key}:" in text for key in _PIPELINE_KEYS
    ):
        return []

    source = yamlish.strip_templates(text) if yamlish.is_templated(text) else text
    findings: "list[Finding]" = []
    for document in yamlish.parse(source):
        if not is_pipeline(path, document):
            continue
        for rule in _RULES:
            findings.extend(rule(path, document))
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not a pipeline."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_yaml_path(path)
        for finding in scan_pipeline(path, text, markers)
    ]
