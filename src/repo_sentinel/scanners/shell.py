"""Audit shell scripts and Makefiles.

Every other scanner finds ``curl | sh`` inside something: a Dockerfile, a
pipeline, an install script named in a manifest. This one finds it where it
usually lives -- in the script itself, which the manifest merely points at, and
which nobody re-reads after it works.

Three rules, all about what a script does to the machine that runs it:
downloading code and executing it unverified, turning off certificate checking
to get past a failure, and making something world-writable.

Files are found by extension, by name, or by shebang. The shebang matters: a
setup script with no extension is still a shell script, and is exactly the kind
of file a repository accumulates.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown
from ..findings import Confidence, Finding, Severity

_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh", ".command", ".mk")
_MAKEFILE_NAMES = ("makefile", "gnumakefile", "bsdmakefile")
_SHEBANG = re.compile(r"^#!.*\b(?:ba|z|k|da)?sh\b")

#: ``chmod 777`` and ``chmod -R 0666``: the last octal digit is the one that
#: grants everybody, and 2, 3, 6 and 7 all include write.
_OCTAL_WORLD_WRITABLE = re.compile(
    r"\bchmod\b[^|;&]*?\s(?:-[\w-]+\s+)*(?P<mode>0?[0-7][0-7][2367])\b"
)

#: ``chmod a+w``, ``chmod o+w``, ``chmod +w``. The who-list decides, and it is
#: read in code rather than in the pattern: "u+w" is an owner granting
#: themselves write access, which is the ordinary case and not a finding.
_SYMBOLIC_MODE = re.compile(
    r"\bchmod\b[^|;&]*?\s(?:-[\w-]+\s+)*(?P<who>[ugoa]*)(?P<op>[+=])(?P<what>[rwxXst]*)"
)


def is_shell_path(path: str, text: str = "") -> bool:
    """True for a file a shell or make would execute."""
    name = posixpath.basename(path.replace("\\", "/")).lower()
    if name.endswith(_SHELL_SUFFIXES) or name in _MAKEFILE_NAMES:
        return True
    if name.startswith("makefile."):
        return True
    return bool(text) and bool(_SHEBANG.match(text.splitlines()[0] if text else ""))


def _lines(text: str) -> "Iterator[tuple[int, str]]":
    """Yield ``(line_number, text)``, joining backslash continuations.

    A command split over four lines is one command, and the finding belongs on
    the line where it starts -- which is where a reader will look for it.
    """
    number = 0
    joined = ""
    start = 1
    for index, line in enumerate(text.splitlines(), start=1):
        if not joined:
            start = index
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            joined += stripped[:-1] + " "
            continue
        joined += stripped
        number = start
        yield number, joined
        joined = ""
    if joined:
        yield start, joined


def _is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("#") and not stripped.startswith("#!")


def _check_downloads(path: str, text: str) -> "Iterator[Finding]":
    """SH001: code fetched and executed in one step."""
    for number, line in _lines(text):
        if _is_comment(line) or not wellknown.PIPE_TO_SHELL.search(line):
            continue
        yield Finding(
            rule_id="SH001",
            severity=Severity.HIGH,
            title="A script downloads code and runs it in one step",
            path=path,
            line=number,
            evidence=line.strip()[:120],
            remediation=(
                "Whoever controls that URL -- or takes it over later -- runs "
                "code as whoever runs this script, which for an install script "
                "is usually root. Download to a file, check a signature or a "
                "checksum, then run it."
            ),
        )


def _check_verification(path: str, text: str) -> "Iterator[Finding]":
    """SH002: certificate checking turned off to get past a failure."""
    for number, line in _lines(text):
        if _is_comment(line) or not wellknown.SKIPS_VERIFICATION.search(line):
            continue
        yield Finding(
            rule_id="SH002",
            severity=Severity.MEDIUM,
            title="A script disables certificate verification",
            path=path,
            line=number,
            evidence=line.strip()[:120],
            remediation=(
                "This is added to get past one broken certificate and then "
                "never removed, and it removes the only check that what "
                "arrived came from where it claimed. Fix the trust store, or "
                "vendor the file."
            ),
        )


def _world_writable_mode(line: str) -> "str | None":
    """The mode in a chmod that grants write access to everybody, if any."""
    octal = _OCTAL_WORLD_WRITABLE.search(line)
    if octal is not None:
        return octal.group("mode")

    symbolic = _SYMBOLIC_MODE.search(line)
    if symbolic is None or "w" not in symbolic.group("what"):
        return None
    who = symbolic.group("who")
    # An empty who-list means "all", subject to umask. "u+w" is an owner
    # granting themselves write access, which is most chmods ever written.
    if who and not set(who) & {"a", "o"}:
        return None
    return f"{who}{symbolic.group('op')}{symbolic.group('what')}"


def _check_permissions(path: str, text: str) -> "Iterator[Finding]":
    """SH003: a mode that lets any account on the machine rewrite the file."""
    for number, line in _lines(text):
        if _is_comment(line):
            continue
        mode = _world_writable_mode(line)
        if mode is None:
            continue
        yield Finding(
            rule_id="SH003",
            severity=Severity.MEDIUM,
            title=f"A script makes something world-writable ({mode})",
            path=path,
            line=number,
            evidence=line.strip()[:120],
            remediation=(
                "Any account on the machine can rewrite this, and for a script "
                "or a unit file that means any account decides what runs next. "
                "Give the owner write access and nobody else."
            ),
            confidence=Confidence.MEDIUM,
        )


_RULES = (_check_downloads, _check_verification, _check_permissions)


def scan_script(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every shell rule against one script."""
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
    """Scan ``(path, text)`` pairs, ignoring anything a shell would not run."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_shell_path(path, text)
        for finding in scan_script(path, text, markers)
    ]
