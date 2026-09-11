"""Audit CircleCI configuration.

The fourth CI system, and the same four rules the other three needed: a
variable an outsider writes expanded into a command, a job image that can be
repointed, an orb reference that is explicitly mutable, and a build step that
pipes the network into a shell.

CircleCI's own twist is the orb. ``circleci/aws-cli@volatile`` and
``somebody/orb@dev:branch`` are documented as *deliberately* moving references
-- the registry will hand you whatever was published last -- so an orb pinned
that way is a supply chain you do not control, spelled out in the file.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown, yamlish
from ..findings import Confidence, Finding, Severity
from . import ci

_YAML_SUFFIXES = (".yaml", ".yml")

#: Environment variables CircleCI sets from the branch, tag or account that
#: triggered the build -- all of which an outside contributor chooses.
_UNTRUSTED_VARIABLES = (
    "CIRCLE_BRANCH",
    "CIRCLE_TAG",
    "CIRCLE_USERNAME",
    "CIRCLE_PR_USERNAME",
    "CIRCLE_PR_REPONAME",
    "CIRCLE_PULL_REQUEST",
)
_UNTRUSTED = re.compile(
    r"\$\{?(?P<name>" + "|".join(_UNTRUSTED_VARIABLES) + r")\b\}?"
)

#: Orb references the registry is documented to move under you.
_MOVING_ORB = re.compile(r"@(?:volatile|dev:)", re.IGNORECASE)

_IMAGE_TAG = re.compile(r"^(?P<image>[^\s@]+?)(?::(?P<tag>[^:/@]+))?(?:@(?P<digest>sha256:\w+))?$")
_SCRIPT_KEYS = ("command", "run")


def is_yaml_path(path: str) -> bool:
    return posixpath.basename(path.replace("\\", "/")).lower().endswith(_YAML_SUFFIXES)


def is_named_config(path: str) -> bool:
    """CircleCI reads one path, so the name is strong evidence."""
    normalised = path.replace("\\", "/").lower()
    return normalised.endswith(".circleci/config.yml") or normalised.endswith(
        ".circleci/config.yaml"
    )


def is_config(path: str, document: "yamlish.Node") -> bool:
    """True for a document CircleCI would run, by name or by shape."""
    if not document.is_map or document.get("apiVersion") is not None:
        return False
    if is_named_config(path):
        return True
    keys = {key for key, _ in document.items()}
    return "jobs" in keys and bool(keys & {"version", "workflows", "orbs"})


def _steps(document: "yamlish.Node") -> "Iterator[yamlish.Node]":
    """Every step of every job, wherever the config's shape puts it."""
    for key, node in document.walk():
        if key != "steps" or not node.is_list:
            continue
        for step in node.entries():
            if step.is_map:
                yield step
            for _, nested in step.items():
                if nested.is_map:
                    yield nested


def _check_injection(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """CC001: a variable an outsider writes, expanded into a command."""
    for step in _steps(document):
        for line, command in ci.script_lines(step, _SCRIPT_KEYS):
            match = next(ci.untrusted_matches(command, _UNTRUSTED, ci.HARMLESS_FIELDS), None)
            if match is None:
                continue
            yield Finding(
                rule_id="CC001",
                severity=Severity.CRITICAL,
                title=f"A step expands ${match.group('name')} into a command",
                path=path,
                line=line,
                evidence=command.strip()[:120],
                remediation=(
                    "A fork chooses its own branch name, and CircleCI puts it "
                    "straight into the command line. Read it from the "
                    "environment inside quotes the shell will not re-expand."
                ),
            )


def _check_orbs(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """CC002: an orb reference the registry is documented to move."""
    orbs = document.get("orbs")
    if orbs is None or not orbs.is_map:
        return
    for name, node in orbs.items():
        reference = node.text.strip().strip("\"'")
        if not _MOVING_ORB.search(reference):
            continue
        yield Finding(
            rule_id="CC002",
            severity=Severity.HIGH,
            title=f"Orb {name!r} is pinned to a moving reference",
            path=path,
            line=node.line,
            evidence=reference[:80],
            remediation=(
                "'volatile' and 'dev:' are documented as whatever was "
                "published most recently, which makes every build a fresh "
                "trust decision somebody else makes. Pin a released version."
            ),
        )


def _check_images(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """CC003: a job image that can mean something else tomorrow."""
    for key, node in document.walk():
        if key != "image" or not node.text:
            continue
        reference = node.text.strip().strip("\"'")
        if wellknown.is_interpolated(reference):
            continue
        match = _IMAGE_TAG.match(reference)
        if match is None or match.group("digest"):
            continue
        tag = match.group("tag")
        if tag is not None and tag != "latest":
            continue
        yield Finding(
            rule_id="CC003",
            severity=Severity.MEDIUM,
            title=f"A job runs on {reference}, which floats",
            path=path,
            line=node.line,
            evidence=f"image: {reference}",
            remediation=(
                "The image a job runs in is the code it runs. Pin a version "
                "tag, or a digest for an image you do not publish."
            ),
            confidence=Confidence.MEDIUM,
        )


def _check_pipe_to_shell(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """CC004: a build step that trusts a URL with its shell."""
    for step in _steps(document):
        for line, command in ci.script_lines(step, _SCRIPT_KEYS):
            if not wellknown.PIPE_TO_SHELL.search(command):
                continue
            yield Finding(
                rule_id="CC004",
                severity=Severity.HIGH,
                title="A step pipes a downloaded script straight into a shell",
                path=path,
                line=line,
                evidence=command.strip()[:120],
                remediation=(
                    "Whoever controls that URL runs code with the job's "
                    "environment, which on CircleCI includes every context "
                    "variable the job was granted. Download, verify, then run."
                ),
            )


_RULES = (_check_injection, _check_orbs, _check_images, _check_pipe_to_shell)


def scan_config(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every CircleCI rule against one configuration file."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []
    if not is_named_config(path) and "jobs:" not in text:
        return []

    source = yamlish.strip_templates(text) if yamlish.is_templated(text) else text
    findings: "list[Finding]" = []
    for document in yamlish.parse(source):
        if not is_config(path, document):
            continue
        for rule in _RULES:
            findings.extend(rule(path, document))
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not a config."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_yaml_path(path)
        for finding in scan_config(path, text, markers)
    ]
