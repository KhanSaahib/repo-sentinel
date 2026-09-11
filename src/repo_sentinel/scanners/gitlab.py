"""Audit GitLab CI pipelines for the mistakes their GitHub cousins make too.

Two CI systems, one class of bug. GitLab interpolates its predefined variables
into the shell exactly as Actions interpolates its contexts, and several of
those variables carry text an outsider wrote: a commit message, a merge request
title, a branch name on a fork. ``echo "Building $CI_COMMIT_TITLE"`` is a
command injection whenever a title can contain ``$(...)``.

The rest is the same family of thing: a job image that can be repointed, a
build step that pipes the network into a shell, and the debug switch that
prints every variable the job can see -- masked ones included -- into a log
that is often world-readable.

Pipelines are recognised by name (``.gitlab-ci.yml``) or by shape: a document
with jobs that carry a ``script``. The second form matters because ``include:``
lets a pipeline live in any file, in any repository, under any name.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown, yamlish
from . import ci
from ..findings import Confidence, Finding, Severity

_YAML_SUFFIXES = (".yaml", ".yml")
_PIPELINE_NAMES = ("gitlab-ci.yml", "gitlab-ci.yaml")

#: Keys that are configuration rather than jobs.
_RESERVED = frozenset(
    {
        "stages", "variables", "default", "include", "workflow", "image",
        "services", "cache", "before_script", "after_script", "pages",
    }
)

_SCRIPT_KEYS = ("script", "before_script", "after_script")

#: Predefined variables whose value an outside contributor writes. A fork's
#: merge request supplies its own branch name, commit message and title, and
#: the account that opened it supplies the user fields.
_UNTRUSTED_VARIABLES = (
    "CI_COMMIT_MESSAGE",
    "CI_COMMIT_TITLE",
    "CI_COMMIT_DESCRIPTION",
    "CI_COMMIT_REF_NAME",
    "CI_COMMIT_BRANCH",
    "CI_COMMIT_TAG",
    "CI_COMMIT_AUTHOR",
    "CI_MERGE_REQUEST_TITLE",
    "CI_MERGE_REQUEST_DESCRIPTION",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
    "CI_MERGE_REQUEST_LABELS",
    "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
    "GITLAB_USER_NAME",
    "GITLAB_USER_LOGIN",
    "GITLAB_USER_EMAIL",
)
_UNTRUSTED = re.compile(
    r"\$\{?(?P<name>" + "|".join(_UNTRUSTED_VARIABLES) + r")\b\}?"
)

_IMAGE_TAG = re.compile(r"^(?P<image>[^\s@]+?)(?::(?P<tag>[^:/@]+))?(?:@(?P<digest>sha256:\w+))?$")


def is_yaml_path(path: str) -> bool:
    return posixpath.basename(path.replace("\\", "/")).lower().endswith(_YAML_SUFFIXES)


def is_named_pipeline(path: str) -> bool:
    return posixpath.basename(path.replace("\\", "/")).lower().endswith(_PIPELINE_NAMES)


def is_pipeline(path: str, document: "yamlish.Node") -> bool:
    """True for a document GitLab would run as a pipeline.

    By name, or by shape when the name says nothing: ``include:`` lets a
    pipeline fragment live anywhere, and a file full of jobs is a file full of
    jobs whatever it is called.
    """
    if not document.is_map or document.get("apiVersion") is not None:
        return False
    if is_named_pipeline(path):
        return True
    return any(True for _ in _jobs(document))


def _jobs(document: "yamlish.Node") -> "Iterator[tuple[str, yamlish.Node]]":
    """Top-level entries that are jobs: a mapping carrying a script.

    Hidden keys -- the ``.template`` convention -- are included. GitLab does
    not run them directly, but every job that ``extends`` one runs its script,
    so an injection written in a template is an injection in each of them, and
    reporting it once where it is written beats reporting it in five places
    where it was inherited.
    """
    for name, node in document.items():
        if name in _RESERVED:
            continue
        if node.is_map and any(node.get(key) is not None for key in _SCRIPT_KEYS):
            yield name, node


def _script_lines(node: "yamlish.Node") -> "Iterator[tuple[int, str]]":
    """Every shell line in a job, from all three script keys."""
    return ci.script_lines(node, _SCRIPT_KEYS)


def _image_of(node: "yamlish.Node") -> "yamlish.Node | None":
    """The image reference, whether written as a scalar or as a mapping."""
    image = node.get("image")
    if image is None:
        return None
    return image.get("name") if image.is_map else image


def _check_injection(path: str, name: str, job: "yamlish.Node") -> "Iterator[Finding]":
    """GL002: text an outsider wrote, substituted into a shell command."""
    for line_number, line in _script_lines(job):
        match = next(ci.untrusted_matches(line, _UNTRUSTED, ci.HARMLESS_FIELDS), None)
        if match is None:
            continue
        yield Finding(
            rule_id="GL002",
            severity=Severity.CRITICAL,
            title=f"Job {name!r} interpolates ${match.group('name')} into a shell command",
            path=path,
            line=line_number,
            evidence=line.strip(),
            remediation=(
                "A fork's merge request supplies this value, so a title "
                "containing $(...) runs on the runner. Read it from the "
                "environment inside a quoted variable the shell does not "
                "re-expand, and never paste it into a command line."
            ),
        )


def _check_pipe_to_shell(path: str, name: str, job: "yamlish.Node") -> "Iterator[Finding]":
    """GL003: a build step that trusts a URL with its shell."""
    for line_number, line in _script_lines(job):
        if not wellknown.downloads_and_runs(line):
            continue
        yield Finding(
            rule_id="GL003",
            severity=Severity.HIGH,
            title=f"Job {name!r} pipes a downloaded script straight into a shell",
            path=path,
            line=line_number,
            evidence=line.strip(),
            remediation=(
                "Whoever controls that URL -- or anyone who takes it over "
                "later -- runs code with the job's token and variables. "
                "Download, verify a checksum, then run."
            ),
        )


def _check_image(path: str, name: str, node: "yamlish.Node") -> "Iterator[Finding]":
    """GL001: an image reference that can mean something else tomorrow."""
    image = _image_of(node)
    if image is None:
        return
    reference = image.text.strip().strip("\"'")
    if not reference or wellknown.is_interpolated(reference):
        return
    match = _IMAGE_TAG.match(reference)
    if match is None or match.group("digest"):
        return
    tag = match.group("tag")
    if tag is not None and tag != "latest":
        return
    yield Finding(
        rule_id="GL001",
        severity=Severity.MEDIUM,
        title=f"{name} runs on {reference}, which floats",
        path=path,
        line=image.line,
        evidence=f"image: {reference}",
        remediation=(
            "The image a pipeline pulls is the code it runs. An unpinned tag "
            "means a rebuild can execute something nobody reviewed. Pin a "
            "version, or a digest for an image you do not publish."
        ),
        confidence=Confidence.MEDIUM,
    )


def _check_debug_trace(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """GL004: the switch that prints every variable into the job log."""
    for key, node in document.walk():
        if key != "CI_DEBUG_TRACE" or not node.truthy():
            continue
        yield Finding(
            rule_id="GL004",
            severity=Severity.HIGH,
            title="CI_DEBUG_TRACE prints every variable into the job log",
            path=path,
            line=node.line,
            evidence="CI_DEBUG_TRACE: true",
            remediation=(
                "Debug tracing disables variable masking, so every secret the "
                "job can see is written to a log that is often readable by "
                "anyone who can see the project. Turn it on temporarily, by "
                "hand, on a job with no secrets -- never in the file."
            ),
        )


def scan_pipeline(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every GitLab rule against one pipeline file."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    # A pipeline is either named like one or has jobs with scripts in it.
    # Anything else is somebody else's YAML.
    if not is_named_pipeline(path) and "script:" not in text:
        return []

    source = yamlish.strip_templates(text) if yamlish.is_templated(text) else text
    findings: "list[Finding]" = []
    for document in yamlish.parse(source):
        if not is_pipeline(path, document):
            continue
        findings.extend(_check_debug_trace(path, document))
        default = document.get("default")
        if default is not None and default.is_map:
            findings.extend(_check_image(path, "The default image", default))
        elif document.get("image") is not None:
            findings.extend(_check_image(path, "The default image", document))
        for name, job in _jobs(document):
            findings.extend(_check_image(path, f"Job {name!r}", job))
            findings.extend(_check_injection(path, name, job))
            findings.extend(_check_pipe_to_shell(path, name, job))
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
