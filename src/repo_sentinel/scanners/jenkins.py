"""Audit Jenkinsfiles, as far as is honest without parsing Groovy.

A Jenkinsfile is a Groovy program, and this tool has no business parsing one.
What it can read is the part that matters: the shell steps, which is where a
pipeline's security decisions actually live.

The interesting detail is Groovy's quoting, because it decides whether an
interpolation is a bug at all. ``sh "echo ${env.BRANCH_NAME}"`` is interpolated
by *Groovy*, before the shell ever sees it, so a branch called
``$(curl evil)`` runs on the agent. ``sh 'echo $BRANCH_NAME'`` is a single
quoted string that Groovy leaves alone, so the shell expands the variable
itself and the value is never parsed as code. The two lines look nearly
identical and differ entirely, which is exactly the kind of thing a reviewer
skims past -- and exactly why the rule is worth having.

Everything here is line-based and says so. A Jenkinsfile that builds its
commands through a helper function, or a shared library, is invisible to this.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown
from ..findings import Confidence, Finding, Severity

#: ``sh``, ``bat`` or ``powershell`` followed by its string argument. The quote
#: is captured because Groovy only interpolates the double-quoted forms.
_SHELL_STEP = re.compile(
    r"""\b(?P<step>sh|bat|powershell|pwsh)\s*
        (?:\(\s*)?
        (?:script\s*:\s*)?
        (?P<quote>\"\"\"|'''|\"|')
        (?P<body>.*?)
        (?P=quote)""",
    re.VERBOSE | re.DOTALL,
)

#: Groovy interpolation of something an outside contributor writes. On a
#: multibranch pipeline the branch name, the change title and the author all
#: come from whoever opened the pull request.
_UNTRUSTED = re.compile(
    r"\$\{?\s*(?:env\.|params\.)?(?P<name>"
    r"BRANCH_NAME|CHANGE_TITLE|CHANGE_BRANCH|CHANGE_AUTHOR|CHANGE_AUTHOR_DISPLAY_NAME"
    r"|CHANGE_TARGET|GIT_BRANCH|GIT_LOCAL_BRANCH|TAG_NAME"
    r")\b"
)

_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|k|da)?sh\b"
)

#: ``image 'node:latest'`` inside an agent block, in either quoting style.
_AGENT_IMAGE = re.compile(r"\bimage\s+(?P<quote>[\"'])(?P<image>[^\"']+)(?P=quote)")
_IMAGE_TAG = re.compile(r"^(?P<image>[^\s@]+?)(?::(?P<tag>[^:/@]+))?(?:@(?P<digest>sha256:\w+))?$")

_JENKINS_NAMES = ("jenkinsfile",)


def is_jenkinsfile(path: str, text: str = "") -> bool:
    """True for a file Jenkins would execute as a pipeline.

    By name in the usual case, and by shape for the ``.groovy`` files that hold
    a pipeline without being called one -- but only when the text actually
    opens a ``pipeline`` or ``node`` block, because most Groovy in a repository
    is not a Jenkinsfile.
    """
    name = posixpath.basename(path.replace("\\", "/")).lower()
    if name.startswith(_JENKINS_NAMES) or name.endswith(".jenkinsfile"):
        return True
    if not name.endswith(".groovy"):
        return False
    return bool(re.search(r"^\s*(?:pipeline|node)\s*[({]", text, re.MULTILINE))


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _shell_steps(text: str) -> "Iterator[tuple[int, str, str]]":
    """Yield ``(line, quote, body)`` for every shell step in the file."""
    for match in _SHELL_STEP.finditer(text):
        yield _line_of(text, match.start()), match.group("quote"), match.group("body")


def _check_injection(path: str, text: str) -> "Iterator[Finding]":
    """JK001: Groovy interpolating an outsider's text into a command."""
    for line, quote, body in _shell_steps(text):
        if quote.startswith("'"):
            continue  # Groovy does not interpolate a single-quoted string
        match = _UNTRUSTED.search(body)
        if match is None:
            continue
        yield Finding(
            rule_id="JK001",
            severity=Severity.CRITICAL,
            title=f"A shell step interpolates {match.group('name')} through Groovy",
            path=path,
            line=line,
            evidence=body.strip().splitlines()[0][:120] if body.strip() else "",
            remediation=(
                "Groovy substitutes this before the shell sees the line, so a "
                "branch name containing $(...) runs on the agent. Single-quote "
                "the step -- sh 'echo $BRANCH_NAME' -- and let the shell expand "
                "the variable, which never parses the value as code."
            ),
        )


def _check_pipe_to_shell(path: str, text: str) -> "Iterator[Finding]":
    """JK003: a build step that trusts a URL with the agent's shell."""
    for line, _quote, body in _shell_steps(text):
        if not _PIPE_TO_SHELL.search(body):
            continue
        yield Finding(
            rule_id="JK003",
            severity=Severity.HIGH,
            title="A shell step pipes a downloaded script straight into a shell",
            path=path,
            line=line,
            evidence=body.strip().splitlines()[0][:120],
            remediation=(
                "Whoever controls that URL runs code on the agent, with "
                "whatever credentials the job was given. Download, verify a "
                "checksum, then run."
            ),
        )


def _check_agent_images(path: str, text: str) -> "Iterator[Finding]":
    """JK002: an agent image that can mean something else tomorrow."""
    for match in _AGENT_IMAGE.finditer(text):
        reference = match.group("image").strip()
        if wellknown.is_interpolated(reference):
            continue
        parsed = _IMAGE_TAG.match(reference)
        if parsed is None or parsed.group("digest"):
            continue
        tag = parsed.group("tag")
        if tag is not None and tag != "latest":
            continue
        yield Finding(
            rule_id="JK002",
            severity=Severity.MEDIUM,
            title=f"An agent runs on {reference}, which floats",
            path=path,
            line=_line_of(text, match.start()),
            evidence=f"image '{reference}'",
            remediation=(
                "The image an agent runs is the code it runs. Pin a version "
                "tag, or a digest for an image you do not publish."
            ),
            confidence=Confidence.MEDIUM,
        )


_RULES = (_check_injection, _check_agent_images, _check_pipe_to_shell)


def scan_jenkinsfile(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every Jenkinsfile rule against one pipeline."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    findings: "list[Finding]" = []
    for rule in _RULES:
        findings.extend(rule(path, text))
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not a pipeline."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_jenkinsfile(path, text)
        for finding in scan_jenkinsfile(path, text, markers)
    ]
