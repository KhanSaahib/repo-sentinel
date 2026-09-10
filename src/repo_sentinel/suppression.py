"""Directives that tell the scanner to stay quiet about part of a file.

Three scopes, in increasing blast radius:

* a trailing marker suppresses the one line it sits on;
* a start/end pair suppresses everything between the two markers, inclusive,
  which is what a generated block or a fixture full of invented keys needs;
* a file-level marker suppresses the whole file.

A file-level directive counts only inside the first
:data:`FILE_MARKER_MAX_LINE` lines. Without that restriction, any file that
merely *describes* the directive - this project's own README, a style guide, a
checked-in design note - would silently stop being scanned, and a scanner that
a sentence about it can switch off is worse than no scanner. Keeping the
directive in the header also means a reader can tell that a file is unscanned
without reading to the bottom of it.

The one failure mode here that hides findings by accident is a start marker
whose end is missing: everything after it goes quiet, however far that reaches.
So that case is reported as a finding rather than trusted. A scanner should
always be able to say what it decided not to look at.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable

from .findings import Finding, Severity

__all__ = [
    "FILE_MARKER_MAX_LINE",
    "LINE_MARKER",
    "UNTERMINATED_RULE_ID",
    "Suppressions",
    "marker_scope",
    "parse",
    "unterminated_finding",
]

#: The plain one-line form, quoted back at users in remediation text.
LINE_MARKER = "repo-sentinel: ignore"

#: How far into a file a file-level directive is still honoured. Twenty lines
#: clears a licence header and a module docstring without reaching the prose of
#: a document that happens to mention the marker in passing.
FILE_MARKER_MAX_LINE = 20

#: Reserved for the scanner's own hygiene checks rather than a class of secret.
UNTERMINATED_RULE_ID = "SEC900"

# Assembled from a prefix and an optional suffix rather than spelled out: a
# module whose source matched its own pattern would suppress itself. The
# trailing lookahead makes a mistyped directive ("ignore-fil") match nothing at
# all, so a typo fails towards reporting rather than towards silence.
_MARKER = re.compile(r"repo-sentinel:[ \t]*ignore(?P<scope>-file|-start|-end)?(?![\w-])")

_SCOPES = {None: "line", "-file": "file", "-start": "start", "-end": "end"}


def marker_scope(line: str) -> str | None:
    """Return the scope of the directive on ``line``, or None if it carries none.

    One of ``"line"``, ``"file"``, ``"start"`` or ``"end"``.
    """
    # Every line of every file passes through here twice, and almost none of
    # them carry a directive. A substring test is an order of magnitude cheaper
    # than the pattern, and the pattern cannot match without it.
    if "repo-sentinel" not in line:
        return None
    match = _MARKER.search(line)
    if match is None:
        return None
    return _SCOPES[match.group("scope")]


@dataclasses.dataclass(frozen=True)
class Suppressions:
    """Which lines of one file its author asked the scanner to skip."""

    whole_file: bool = False
    lines: frozenset[int] = frozenset()
    unterminated_start: int | None = None

    def suppresses(self, line: int) -> bool:
        """True when a finding reported at ``line`` should be dropped."""
        return self.whole_file or line in self.lines

    def filter_findings(self, findings: Iterable[Finding]) -> list[Finding]:
        """Drop the findings that this file's directives cover."""
        return [finding for finding in findings if not self.suppresses(finding.line)]


def parse(text: str) -> Suppressions:
    """Collect every directive in ``text`` into one lookup.

    A marker line suppresses itself as well as whatever it delimits. Someone
    who writes a start marker means "from here", and the line a marker sits on
    can carry a finding of its own - which is exactly the per-line case.

    A second start inside an open block is not a nesting level: the first end
    closes the block, because treating starts as a counter would let a missing
    end hide behind a later pair.
    """
    whole_file = False
    lines = set()
    block_start = None

    for number, line in enumerate(text.splitlines(), start=1):
        scope = marker_scope(line)
        if scope is None:
            if block_start is not None:
                lines.add(number)
            continue

        lines.add(number)
        if scope == "file" and number <= FILE_MARKER_MAX_LINE:
            whole_file = True
        elif scope == "start" and block_start is None:
            block_start = number
        elif scope == "end":
            block_start = None

    return Suppressions(whole_file, frozenset(lines), block_start)


def unterminated_finding(path: str, marks: Suppressions) -> Finding | None:
    """Report a start marker with no matching end, or None if there is none.

    Reported at medium severity so the default CI gate catches it: an open
    block is indistinguishable from a clean file in the output, and silence is
    the one answer a scanner must never give by accident.
    """
    if marks.whole_file or marks.unterminated_start is None:
        return None
    return Finding(
        rule_id=UNTERMINATED_RULE_ID,
        severity=Severity.MEDIUM,
        title="Unterminated suppression block silences the rest of the file",
        path=path,
        line=marks.unterminated_start,
        evidence="suppression block opened here is never closed",
        remediation=(
            "Close the block with a matching end marker, or use the file-level "
            "directive if the whole file really is meant to go unscanned."
        ),
    )
