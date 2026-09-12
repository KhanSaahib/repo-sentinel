"""Read a unified diff the way a scanner needs to see it.

A credential in the working tree and a credential that has been in history
since March call for different reactions, and only the second one says the key
is certainly burned. Answering that means reading history -- and reading
history means running git, which this tool does not do. Nothing here imports
:mod:`subprocess`; ``.gitignore`` is implemented by hand rather than by asking
git, and ``--paths-from`` exists precisely so that the caller runs ``git
diff``. The same bargain applies here: the caller runs

.. code-block:: bash

    git log -p --date=iso

and this reads what comes out.

What a scanner needs from a diff is not the diff. It needs, for each commit
and each file, the lines that commit *added*, at the line numbers they landed
on -- so that a finding points at a real line of a real version of the file,
and so that a multi-line value added in one commit still reads as one value.
So each file in each commit becomes a sparse reconstruction: added lines at
their own line numbers, and blank lines everywhere else. Nothing is invented;
the lines that were already there are simply not this commit's news.

Removed lines are dropped, which is the whole point of reading history this
way. A credential that was committed and then deleted is still committed.
"""

from __future__ import annotations

import dataclasses
import datetime
import re
from collections.abc import Iterable, Iterator

__all__ = ["Addition", "Commit", "MAX_LINE", "parse", "parse_date"]

#: How far into a file this will reconstruct. A sparse rebuild costs one list
#: entry per line up to the highest line a commit touched, so a diff claiming
#: to have changed line nine million must not be allowed to ask for nine
#: million empty strings. Real source files do not reach this.
MAX_LINE = 300_000

_COMMIT = re.compile(r"^commit ([0-9a-f]{7,64})\b")
_AUTHOR = re.compile(r"^Author:\s*(.+?)\s*$")
_DATE = re.compile(r"^Date:\s*(.+?)\s*$")
_FILE = re.compile(r"^\+\+\+ (?:b/)?(.+?)\s*$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

#: ``git log`` writes dates two common ways: its own default, and --date=iso.
#: Anything else is left unparsed rather than guessed at, and a finding whose
#: date could not be read keeps the order it arrived in.
_DATE_FORMATS = ("%a %b %d %H:%M:%S %Y %z", "%Y-%m-%d %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z")


@dataclasses.dataclass(frozen=True)
class Commit:
    """Who added something, and when -- as far as the stream said."""

    sha: str = ""
    author: str = ""
    date: str = ""

    @property
    def short(self) -> str:
        return self.sha[:7]

    @property
    def when(self) -> "datetime.datetime | None":
        return parse_date(self.date)

    def describe(self) -> str:
        """The commit as a report should name it: short sha, then the day."""
        moment = self.when
        if moment is not None:
            return f"{self.short} on {moment.date().isoformat()}"
        return self.short or "an unnamed commit"


@dataclasses.dataclass(frozen=True)
class Addition:
    """The lines one commit added to one file, at the numbers they landed on."""

    commit: Commit
    path: str
    text: str


def parse_date(value: str) -> "datetime.datetime | None":
    """A git date as a datetime, or None when it is written some other way."""
    cleaned = value.strip()
    for shape in _DATE_FORMATS:
        try:
            return datetime.datetime.strptime(cleaned, shape)
        except ValueError:
            continue
    return None


def parse(lines: "Iterable[str]") -> "Iterator[Addition]":
    """Every (commit, file, added lines) the stream describes.

    Written against a line iterator rather than a string so that a repository's
    entire history -- which is a great deal larger than its working tree -- can
    be piped through without being held in memory at once.
    """
    commit = Commit()
    path = ""
    added: "dict[int, str]" = {}
    number = 0

    def finish() -> "Iterator[Addition]":
        if path and added:
            yield Addition(commit, path, _rebuild(added))

    for raw in lines:
        line = raw.rstrip("\n")

        found = _COMMIT.match(line)
        if found is not None:
            yield from finish()
            path, added, number = "", {}, 0
            commit = Commit(sha=found.group(1))
            continue

        if not path:
            # Inside a commit's header, where the author and date live. These
            # only ever appear before the first "+++", so testing for them
            # after one has been seen would be reading a line of somebody's
            # source as a header.
            header = _AUTHOR.match(line)
            if header is not None:
                commit = dataclasses.replace(commit, author=header.group(1))
                continue
            header = _DATE.match(line)
            if header is not None:
                commit = dataclasses.replace(commit, date=header.group(1))
                continue

        if line.startswith("+++"):
            yield from finish()
            added, number = {}, 0
            named = _FILE.match(line)
            # "+++ /dev/null" is a deletion: the commit's news about this file
            # is that it is gone, and nothing was added to read.
            path = "" if named is None or named.group(1) == "/dev/null" else named.group(1)
            continue

        hunk = _HUNK.match(line)
        if hunk is not None:
            number = int(hunk.group(1))
            continue

        if not path or not number:
            continue

        if line.startswith("+"):
            if number <= MAX_LINE:
                added[number] = line[1:]
            number += 1
        elif line.startswith("-"):
            continue  # a removed line occupies no number in the new file
        elif line.startswith("\\"):
            continue  # "\ No newline at end of file"
        else:
            number += 1

    yield from finish()


def _rebuild(added: "dict[int, str]") -> str:
    """The added lines at their own numbers, with blanks in between.

    The blanks matter twice over. They keep every finding's line number the one
    a reviewer can check out and look at; and they keep lines that were not
    added out of the scanners' way, so a credential is only ever reported
    against the commit that actually introduced it.
    """
    highest = max(added)
    return "\n".join(added.get(index, "") for index in range(1, highest + 1))
