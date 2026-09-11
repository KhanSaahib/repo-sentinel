"""JSON, parsed into the same nodes as YAML, keeping line numbers.

``json.loads`` is right there and it throws away the one thing a scanner
needs: where each value was. A finding at "line 1" in a two-thousand-line
CloudFormation template is a finding nobody can act on.

So this is a small recursive-descent reader producing :class:`yamlish.Node`
values -- the same type the YAML reader produces, so every rule written
against one works against the other unchanged. That is the whole reason it
exists: JSON CloudFormation was not read at all, and the alternative was a
second set of rules that would have drifted from the first within a release.

Scalars keep their source text rather than becoming Python values. ``true``
stays the string ``"true"`` so that ``Node.truthy()`` means the same thing in
both readers, and a number stays as written so a rule comparing ports does not
have to care which reader produced them.

It is strict where JSON is strict -- no trailing commas, no comments -- and
returns nothing at all rather than guessing when a document does not parse.
A partial parse of a malformed document is how a scanner reports findings that
are not there.
"""

from __future__ import annotations

import json
from typing import Optional, Tuple

from .yamlish import Node

#: Characters JSON allows between any two tokens.
_WHITESPACE = " \t\r\n"

#: How deep a document may nest before it is refused. Far past anything a
#: template or a manifest does, and far short of Python's own recursion limit
#: -- which is the point: a hostile file should hit a rule, not an interpreter
#: error. RecursionError is raised *anywhere* the stack happens to be deep,
#: including inside a profiler or a tracer, where it does damage out of all
#: proportion to the malformed file that caused it.
MAX_DEPTH = 200


class _Reader:
    """A cursor over the text, which knows what line it is on."""

    __slots__ = ("text", "position", "line")

    def __init__(self, text: str):
        self.text = text
        self.position = 0
        self.line = 1

    def skip_whitespace(self) -> None:
        while self.position < len(self.text) and self.text[self.position] in _WHITESPACE:
            if self.text[self.position] == "\n":
                self.line += 1
            self.position += 1

    def peek(self) -> str:
        return self.text[self.position] if self.position < len(self.text) else ""

    def take(self, count: int = 1) -> str:
        chunk = self.text[self.position : self.position + count]
        self.line += chunk.count("\n")
        self.position += count
        return chunk

    def expect(self, character: str) -> None:
        if self.peek() != character:
            raise ValueError(f"expected {character!r} at line {self.line}")
        self.take()


def parse(text: str) -> "Optional[Node]":
    """Read a JSON document, or return None if it is not one.

    None rather than an exception, because the callers are scanners deciding
    whether a file is theirs, and "this is not JSON" is an ordinary answer.
    """
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        reader = _Reader(text)
        reader.skip_whitespace()
        node = _parse_value(reader)
        reader.skip_whitespace()
    except (ValueError, IndexError, RecursionError):
        return None
    return node if reader.position >= len(reader.text) else None


def looks_like_json(text: str) -> bool:
    """True when a document begins the way a JSON one does."""
    stripped = text.lstrip()
    return bool(stripped) and stripped[0] in "[{"


def _parse_value(reader: _Reader, depth: int = 0) -> Node:
    if depth > MAX_DEPTH:
        raise ValueError(f"nested past {MAX_DEPTH} levels at line {reader.line}")
    reader.skip_whitespace()
    line = reader.line
    character = reader.peek()
    if character == "{":
        return _parse_object(reader, line, depth)
    if character == "[":
        return _parse_array(reader, line, depth)
    if character == '"':
        return Node(_parse_string(reader), line)
    return Node(_parse_literal(reader), line)


def _parse_object(reader: _Reader, line: int, depth: int = 0) -> Node:
    reader.expect("{")
    mapping: "dict[str, Node]" = {}
    reader.skip_whitespace()
    if reader.peek() == "}":
        reader.take()
        return Node(mapping, line)
    while True:
        reader.skip_whitespace()
        key = _parse_string(reader)
        reader.skip_whitespace()
        reader.expect(":")
        mapping[key] = _parse_value(reader, depth + 1)
        reader.skip_whitespace()
        if reader.peek() == ",":
            reader.take()
            continue
        reader.expect("}")
        return Node(mapping, line)


def _parse_array(reader: _Reader, line: int, depth: int = 0) -> Node:
    reader.expect("[")
    items: "list[Node]" = []
    reader.skip_whitespace()
    if reader.peek() == "]":
        reader.take()
        return Node(items, line)
    while True:
        items.append(_parse_value(reader, depth + 1))
        reader.skip_whitespace()
        if reader.peek() == ",":
            reader.take()
            continue
        reader.expect("]")
        return Node(items, line)


def _parse_string(reader: _Reader) -> str:
    """Read a JSON string, escapes and all, by handing the slice to ``json``.

    Finding the end is the part that needs care -- a quote preceded by an even
    number of backslashes ends the string, an odd number does not -- and the
    decoding is a solved problem nobody should solve twice.
    """
    reader.expect('"')
    start = reader.position
    while True:
        if reader.position >= len(reader.text):
            raise ValueError(f"unterminated string from line {reader.line}")
        character = reader.text[reader.position]
        if character == "\\":
            reader.take(2)
            continue
        if character == '"':
            raw = reader.text[start : reader.position]
            reader.take()
            return json.loads(f'"{raw}"')
        reader.take()


def _parse_literal(reader: _Reader) -> str:
    """Read a number, ``true``, ``false`` or ``null`` as the text it was."""
    start = reader.position
    while reader.position < len(reader.text) and reader.text[reader.position] not in ",]}" + _WHITESPACE:
        reader.take()
    literal = reader.text[start : reader.position]
    if not literal:
        raise ValueError(f"expected a value at line {reader.line}")
    return literal


def parse_documents(text: str) -> "Tuple[Node, ...]":
    """A JSON document as a one-element tuple, for callers that loop.

    The YAML reader returns a list because a stream can hold several documents.
    JSON holds one, and callers that handle both should not have to care.
    """
    node = parse(text)
    return (node,) if node is not None else ()
