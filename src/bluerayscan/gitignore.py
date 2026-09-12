"""Interpret ``.gitignore`` files well enough to walk a repository like git does.

The scanner reports credentials that were *committed*. A file git was told to
ignore never entered history, so flagging it is a false positive - and the noise
from ``.venv``, ``build/`` or a developer's local ``.env`` is exactly what makes
people stop reading the output. Ignoring those paths therefore makes the report
more honest, not less thorough.

Git does not expose its matcher as a library and this project takes no runtime
dependencies, so the subset of the format that actually turns up in real
``.gitignore`` files is reimplemented here. Patterns are compiled to regular
expressions once per file rather than interpreted per path, because a large
repository asks the same few hundred questions tens of thousands of times.

Supported: comments, blank lines, escaped and trailing whitespace, negation with
``!``, anchoring via a leading or embedded ``/``, directory-only patterns with a
trailing ``/``, the ``*``/``?``/``[...]`` wildcards (none of which cross a
``/``), and ``**`` for arbitrary depth. Nested ``.gitignore`` files govern their
own subtree, and across the applicable files the last matching pattern wins.

Deliberately not supported: ``.git/info/exclude``, the global
``core.excludesFile``, and git's rule that an already-tracked file stays tracked
however it is ignored. Honouring those means asking git itself, which would mean
shelling out to a binary whose output format is not a stable interface.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

__all__ = ["GitIgnoreFile", "GitIgnoreStack"]


def _strip_trailing_space(line: str) -> str:
    """Drop unescaped trailing whitespace, as git does when reading a pattern."""
    end = len(line)
    while end > 0 and line[end - 1] in " \t":
        backslashes = 0
        index = end - 2
        while index >= 0 and line[index] == "\\":
            backslashes += 1
            index -= 1
        if backslashes % 2 == 1:  # the space is escaped, so it is part of the name
            break
        end -= 1
    return line[:end]


def _find_class_end(segment: str, start: int) -> int:
    """Return the index of the ``]`` closing the class at ``start``, or -1."""
    index = start + 1
    if index < len(segment) and segment[index] in "!^":
        index += 1
    if index < len(segment) and segment[index] == "]":
        index += 1  # a leading ']' is a literal member, not the terminator
    while index < len(segment):
        if segment[index] == "]":
            return index
        index += 1
    return -1


def _translate_segment(segment: str) -> str:
    """Compile one path segment into a regex fragment that cannot cross ``/``."""
    out: list[str] = []
    index = 0
    length = len(segment)
    while index < length:
        char = segment[index]
        if char == "\\" and index + 1 < length:
            out.append(re.escape(segment[index + 1]))
            index += 2
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[":
            closing = _find_class_end(segment, index)
            if closing == -1:
                out.append(re.escape("["))
            else:
                body = segment[index + 1 : closing]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body + "]")
                index = closing + 1
                continue
        else:
            out.append(re.escape(char))
        index += 1
    return "".join(out)


class _Pattern:
    """One compiled ``.gitignore`` line, matched against a directory-relative path."""

    __slots__ = ("negated", "dir_only", "source", "_regex")

    def __init__(self, negated: bool, dir_only: bool, regex: "re.Pattern[str]", source: str):
        self.negated = negated
        self.dir_only = dir_only
        self.source = source
        self._regex = regex

    def matches(self, relative_path: str, is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            return False
        return self._regex.match(relative_path) is not None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<_Pattern {self.source!r}>"


def _parse_line(line: str) -> _Pattern | None:
    """Compile one raw line, or return ``None`` if it carries no rule."""
    source = line
    if line.startswith("#"):
        return None

    line = _strip_trailing_space(line)
    if not line:
        return None

    negated = line.startswith("!")
    if negated:
        line = line[1:]
    elif line[:1] == "\\" and line[1:2] in ("!", "#"):
        line = line[1:]  # an escaped marker is an ordinary first character
    if not line:
        return None

    dir_only = line.endswith("/")
    if dir_only:
        line = line[:-1]
        if not line:
            return None

    # A slash anywhere but the (already removed) end anchors the pattern to the
    # directory holding the .gitignore; otherwise it matches at any depth.
    anchored = "/" in line
    if line.startswith("/"):
        line = line[1:]
        if not line:
            return None

    segments = line.split("/")
    parts: list[str] = []
    for position, segment in enumerate(segments):
        last = position == len(segments) - 1
        if segment == "**":
            # Trailing '**' means everything below; otherwise, any depth here.
            parts.append(".*" if last else "(?:[^/]+/)*")
        else:
            parts.append(_translate_segment(segment) + ("" if last else "/"))

    prefix = "" if anchored else "(?:.*/)?"
    try:
        regex = re.compile("^" + prefix + "".join(parts) + "$")
    except re.error:
        regex = re.compile("^" + prefix + re.escape(line) + "$")
    return _Pattern(negated, dir_only, regex, source)


class GitIgnoreFile:
    """The patterns of a single ``.gitignore`` plus the subtree they govern.

    ``base`` is the slash-separated path of the containing directory relative to
    the scan root, empty for the root itself. Patterns are matched against paths
    made relative to ``base``, which is what makes a nested ``.gitignore``
    behave the same wherever the repository is checked out.
    """

    __slots__ = ("base", "patterns")

    def __init__(self, base: str, patterns: Sequence[_Pattern]):
        self.base = base.strip("/")
        self.patterns = tuple(patterns)

    @classmethod
    def from_lines(cls, lines: Iterable[str], base: str = "") -> GitIgnoreFile:
        patterns = [
            pattern
            for pattern in (_parse_line(line.rstrip("\n").rstrip("\r")) for line in lines)
            if pattern is not None
        ]
        return cls(base, patterns)

    @classmethod
    def load(cls, path: str, base: str = "") -> GitIgnoreFile | None:
        """Read a ``.gitignore``, or return ``None`` if it is unreadable or empty.

        An unreadable ignore file must not abort a scan; the worst case is that
        the walk reports a few paths git would have hidden.
        """
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                rules = cls.from_lines(handle, base)
        except OSError:
            return None
        return rules if rules.patterns else None

    def relative(self, path: str) -> str | None:
        """Re-anchor a root-relative path against this file, or ``None`` if outside."""
        if not self.base:
            return path
        if path.startswith(self.base + "/"):
            return path[len(self.base) + 1 :]
        return None


class GitIgnoreStack:
    """The ignore files in scope for one directory, outermost first.

    Immutable so that a single instance can be shared by every subdirectory that
    adds no rules of its own, which is almost all of them.
    """

    __slots__ = ("_files",)

    def __init__(self, files: Sequence[GitIgnoreFile] = ()):
        self._files = tuple(files)

    def __bool__(self) -> bool:
        return bool(self._files)

    def push(self, rules: GitIgnoreFile) -> GitIgnoreStack:
        """Return a new stack with ``rules`` applying below everything already here."""
        return GitIgnoreStack(self._files + (rules,))

    def is_ignored(self, path: str, is_dir: bool) -> bool:
        """Decide a root-relative path, letting the last matching pattern win."""
        ignored = False
        for rules in self._files:
            relative = rules.relative(path)
            if relative is None:
                continue
            for pattern in rules.patterns:
                if pattern.matches(relative, is_dir):
                    ignored = not pattern.negated
        return ignored
