"""Audit Dockerfiles for the mistakes that end up in production images.

A Dockerfile is build configuration that nobody reviews twice, and the same
four errors turn up in it over and over: a base image that can be swapped out
from under you, a container that runs as root, an install step that pipes the
network into a shell, and a credential baked into a layer where ``docker
history`` will happily read it back.

Like the workflow scanner this is line-based rather than a real parser, but it
does two things a naive grep cannot. It joins backslash continuations, so a
``RUN`` command split over eight lines is judged as the one command it is; and
it tracks build stages, so ``USER`` is only asked about the stage that actually
becomes the image.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown
from ..findings import Confidence, Finding, Severity, redact
from ..heuristics import is_secret_name, looks_generated

_INSTRUCTION = re.compile(r"^\s*(?P<name>[A-Za-z]+)\s+(?P<rest>.*)$")
#: Docker has no inline comments -- a "#" mid-line is part of the argument --
#: so a suppression marker written at the end of an instruction would
#: otherwise become part of the image reference and stop it parsing. The
#: marker is this tool's, so this tool removes it; every other "#" is left
#: exactly where the author put it.
_MARKER_COMMENT = re.compile(r"\s+#\s*repo-sentinel:.*$")
_FROM = re.compile(
    r"^(?P<image>[^\s]+?)(?::(?P<tag>[^\s@]+))?(?:@(?P<digest>sha256:[0-9a-f]{64}))?"
    r"(?:\s+[Aa][Ss]\s+(?P<stage>\S+))?\s*$"
)
_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|k|da)?sh\b"
)
_INSECURE_FETCH = re.compile(
    r"\b(?:curl\b[^|;]*\s(?:-k|--insecure)|wget\b[^|;]*--no-check-certificate"
    r"|npm\b[^|;]*--strict-ssl[= ]false|pip\b[^|;]*--trusted-host)\b"
)
_ENV_PAIR = re.compile(r"""(?P<name>[A-Za-z_][\w.-]*)=(?P<value>"[^"]*"|'[^']*'|\S+)""")
_ROOT_USER = re.compile(r"^(?:root|0)(?::|$)")

_DOCKERFILE_NAMES = frozenset({"dockerfile", "containerfile"})


def is_dockerfile_path(path: str) -> bool:
    """True for the several spellings of "this is a container build file"."""
    name = posixpath.basename(path.replace("\\", "/")).lower()
    if name in _DOCKERFILE_NAMES:
        return True
    return name.startswith("dockerfile.") or name.endswith((".dockerfile", ".containerfile"))


def iter_instructions(lines: list[str]) -> Iterator[tuple[int, str, str]]:
    """Yield ``(line_number, INSTRUCTION, arguments)`` with continuations joined.

    The line number reported is where the instruction *starts*, which is where
    a reader will look for it and where an editor will put the cursor.
    """
    index = 0
    while index < len(lines):
        raw = lines[index]
        start = index
        if not raw.strip() or raw.lstrip().startswith("#"):
            index += 1
            continue
        joined = raw.rstrip()
        while joined.endswith("\\") and index + 1 < len(lines):
            index += 1
            joined = joined[:-1].rstrip() + " " + lines[index].strip()
        index += 1
        match = _INSTRUCTION.match(_MARKER_COMMENT.sub("", joined))
        if match is None:
            continue
        yield start + 1, match.group("name").upper(), match.group("rest").strip()


def _check_base_image(path: str, line: int, argument: str) -> Iterator[Finding]:
    """DK001: what the build will pull the next time it runs."""
    match = _FROM.match(argument)
    if match is None:
        return
    image = match.group("image")
    if image.lower() == "scratch":
        return
    # "java:0-${VARIANT}" is a tag chosen by a build argument, so its shape
    # here says nothing about what will be pulled.
    if wellknown.is_interpolated(argument):
        return
    if match.group("digest"):
        return
    tag = match.group("tag")
    floating = tag is None or tag == "latest"
    yield Finding(
        rule_id="DK001",
        severity=Severity.MEDIUM if floating else Severity.LOW,
        title=(
            f"Base image {image!r} floats on {tag or 'the default tag'}"
            if floating
            else f"Base image {image}:{tag} is pinned to a mutable tag"
        ),
        path=path,
        line=line,
        evidence=f"FROM {argument}",
        remediation=(
            "Pin the base image to a digest (FROM image:tag@sha256:...) so a "
            "rebuild cannot silently pull different code, and let a bot bump it."
        ),
    )


def _check_run(path: str, line: int, command: str) -> Iterator[Finding]:
    """DK003 and DK006: what a build step trusts the network to hand it."""
    if _PIPE_TO_SHELL.search(command):
        yield Finding(
            rule_id="DK003",
            severity=Severity.HIGH,
            title="Build step pipes a downloaded script straight into a shell",
            path=path,
            line=line,
            evidence=_shorten(command),
            remediation=(
                "Whoever controls that URL -- or anyone who takes it over later -- "
                "executes code in your build. Download to a file, verify a checksum "
                "or signature, then run it."
            ),
        )
    if _INSECURE_FETCH.search(command):
        yield Finding(
            rule_id="DK006",
            severity=Severity.MEDIUM,
            title="Build step disables transport security while fetching",
            path=path,
            line=line,
            evidence=_shorten(command),
            remediation=(
                "Skipping certificate verification makes the download trivially "
                "tamperable. Fix the certificate chain instead, or vendor the artifact."
            ),
        )


def _check_env(path: str, line: int, instruction: str, argument: str) -> Iterator[Finding]:
    """DK004: a credential baked into a layer.

    Every ENV and ARG value survives in the image metadata, so ``docker history``
    reads them back out of any published image. Deleting the value in a later
    layer does not remove it from the earlier one.
    """
    for match in _ENV_PAIR.finditer(argument):
        name = match.group("name")
        value = match.group("value").strip("\"'")
        if not is_secret_name(name) or not looks_generated(value):
            continue
        yield Finding(
            rule_id="DK004",
            severity=Severity.HIGH,
            title=f"{instruction} {name} bakes a credential into the image",
            path=path,
            line=line,
            evidence=f"{instruction} {name}={redact(value)}",
            remediation=(
                "Image layers are public once the image is. Use a build secret "
                "(RUN --mount=type=secret) at build time, or inject the value at "
                "run time; either way, rotate this one."
            ),
            confidence=Confidence.MEDIUM,
        )


def _check_add(path: str, line: int, argument: str) -> Iterator[Finding]:
    """DK005: ADD fetching over the network, where COPY would not."""
    if not re.match(r"^(?:--\S+\s+)*(?:https?|ftp)://", argument, re.IGNORECASE):
        return
    yield Finding(
        rule_id="DK005",
        severity=Severity.MEDIUM,
        title="ADD fetches a remote URL into the image",
        path=path,
        line=line,
        evidence=_shorten(f"ADD {argument}"),
        remediation=(
            "ADD downloads without verifying anything and cannot be cached "
            "reliably. Fetch in a RUN step with a checksum check, or use COPY "
            "with a vendored file."
        ),
    )


def _shorten(text: str, limit: int = 160) -> str:
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def scan_dockerfile(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> list[Finding]:
    """Run every Dockerfile rule against one build file."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    lines = text.splitlines()
    findings: list[Finding] = []

    stage_line = 0
    stage_image = ""
    stage_user: str | None = None
    stages: list[tuple[int, str, "str | None"]] = []

    for line, instruction, argument in iter_instructions(lines):
        if instruction == "FROM":
            stages.append((stage_line, stage_image, stage_user))
            stage_line, stage_image, stage_user = line, argument, None
            findings.extend(_check_base_image(path, line, argument))
        elif instruction == "USER":
            stage_user = argument.split()[0] if argument.split() else ""
        elif instruction == "RUN":
            findings.extend(_check_run(path, line, argument))
        elif instruction in ("ENV", "ARG"):
            findings.extend(_check_env(path, line, instruction, argument))
        elif instruction == "ADD":
            findings.extend(_check_add(path, line, argument))

    stages.append((stage_line, stage_image, stage_user))
    findings.extend(_check_final_user(path, stages))
    return marks.filter_findings(findings)


def _check_final_user(
    path: str, stages: list[tuple[int, str, "str | None"]]
) -> Iterator[Finding]:
    """DK002: only the last stage becomes the image, so only it is asked.

    Earlier stages in a multi-stage build are compilers and toolchains that are
    thrown away; demanding an unprivileged user in those is the kind of finding
    that gets a whole tool switched off.
    """
    final = stages[-1]
    line, image, user = final
    if not image or image.split(":")[0].lower() == "scratch":
        return
    if user is not None and not _ROOT_USER.match(user):
        return
    yield Finding(
        rule_id="DK002",
        severity=Severity.MEDIUM,
        title=(
            "Final image runs as root"
            if user is None
            else f"Final image explicitly runs as {user!r}"
        ),
        path=path,
        line=line,
        evidence="no USER instruction" if user is None else f"USER {user}",
        remediation=(
            "A process that is root in the container is root against the kernel "
            "if anything escapes. Create a user and end the final stage with a "
            "USER instruction."
        ),
        confidence=Confidence.MEDIUM if user is None else Confidence.HIGH,
    )


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not a Dockerfile."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_dockerfile_path(path)
        for finding in scan_dockerfile(path, text, markers)
    ]
