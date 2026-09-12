"""Just enough HCL to ask questions about blocks.

Terraform's own grammar is large, and parsing it properly would mean a
dependency this project does not take. But almost every finding worth
reporting in a ``.tf`` file is a question about one block -- does *this*
security group rule open to the world, is *this* bucket public -- and blocks
are delimited by braces, which is a much smaller problem than HCL.

So this module reads structure and nothing else. It knows that a line ending in
``{`` opens a block, that the matching ``}`` closes it, and that braces inside
strings and comments are not braces at all. It does not know types, expressions,
interpolation, or heredocs beyond skipping their contents. Attribute values come
back as the raw text to the right of the ``=``, for a rule to interpret however
it likes.

The limits are real and worth stating where a user can see them: a rule built on
this can be defeated by unusual formatting, so the Terraform scanner reports
what it saw rather than asserting a file is clean.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterator

#: ``resource "aws_s3_bucket" "logs" {`` and its many shorter relatives:
#: ``ingress {``, ``tags = {``, ``provider "aws" {``.
_BLOCK_HEADER = re.compile(
    r"""^\s*
    (?P<kind>[A-Za-z_][\w-]*)
    (?P<labels>(?:\s+"[^"]*"|\s+[A-Za-z_][\w.-]*)*)
    \s*(?:=\s*)?\{\s*$
    """,
    re.VERBOSE,
)
_ATTRIBUTE = re.compile(r"^\s*(?P<name>[A-Za-z_][\w-]*)\s*=\s*(?P<value>.+?)\s*$")
_LABEL = re.compile(r'"([^"]*)"|([A-Za-z_][\w.-]*)')
_HEREDOC = re.compile(r"<<[-~]?(?P<tag>[A-Za-z_]\w*)")


def strip_comments(line: str) -> str:
    """Drop a trailing comment, leaving strings intact.

    Comment markers inside a string are not comments, which is the whole reason
    this is a scanner rather than a call to ``str.split("#")``.
    """
    out: list[str] = []
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            out.append(char)
            if char == "\\":
                if index + 1 < len(line):
                    out.append(line[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "\"'":
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "#" or line[index : index + 2] in ("//", "/*"):
            break
        out.append(char)
        index += 1
    return "".join(out)


def mask_strings(line: str) -> str:
    """Blank out the contents of strings, keeping their quotes.

    Brace counting has to ignore a ``{`` that is part of an interpolation or a
    JSON policy document, and the block header pattern only cares that a label
    is quoted, not what it says.
    """
    out: list[str] = []
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\":
                out.append(" " * len(line[index : index + 2]))
                index += 2
                continue
            if char == quote:
                quote = None
                out.append(char)
            else:
                out.append(" ")
            index += 1
            continue
        if char in "\"'":
            quote = char
            out.append(char)
        else:
            out.append(char)
        index += 1
    return "".join(out)


def strip_noise(line: str) -> str:
    """Structure only: no comments, and no string contents."""
    return mask_strings(strip_comments(line))


@dataclasses.dataclass(frozen=True)
class Block:
    """One braced block: what it is called, and what is inside it."""

    kind: str
    labels: "tuple[str, ...]"
    line: int
    #: ``(line_number, text)`` for every line inside, nested blocks included.
    body: "list[tuple[int, str]]"
    children: "tuple[Block, ...]" = ()

    @property
    def type(self) -> str:
        """The first label, which for a resource or data block is its type."""
        return self.labels[0] if self.labels else ""

    @property
    def name(self) -> str:
        return self.labels[1] if len(self.labels) > 1 else ""

    def label(self) -> str:
        """How a report should refer to this block."""
        return " ".join((self.kind, *(f'"{label}"' for label in self.labels)))

    def attribute(self, name: str) -> "tuple[int, str] | None":
        """Find ``name = value`` directly in this block, not in a nested one.

        Returns the line number and the raw value text, or None. A list written
        across several lines comes back joined, because a rule asking about
        ``cidr_blocks`` should not care whether the author put the entries on
        one line or five.

        Nested blocks are excluded deliberately: ``encrypted = false`` inside a
        ``root_block_device`` says something different from the same line at
        the top of the resource, and a rule that cannot tell them apart is a
        rule that reports the wrong line.
        """
        nested = {line for child in self.children for line, _ in child.body}
        nested.update(child.line for child in self.children)
        for offset, (number, text) in enumerate(self.body):
            if number in nested:
                continue
            match = _ATTRIBUTE.match(strip_comments(text))
            if match is None or match.group("name") != name:
                continue
            return number, self._join_value(match.group("value").strip(), offset)
        return None

    def _join_value(self, value: str, offset: int) -> str:
        """Pull in continuation lines until the brackets balance."""
        depth = value.count("[") - value.count("]")
        parts = [value]
        index = offset + 1
        while depth > 0 and index < len(self.body):
            text = strip_comments(self.body[index][1]).strip()
            parts.append(text)
            depth += text.count("[") - text.count("]")
            index += 1
        return " ".join(part for part in parts if part)

    def blocks(self, kind: str) -> "list[Block]":
        """Direct children of the given kind."""
        return [child for child in self.children if child.kind == kind]

    def walk(self) -> "Iterator[Block]":
        """This block and every block inside it, outermost first."""
        yield self
        for child in self.children:
            yield from child.walk()


def parse(text: str) -> "list[Block]":
    """Read the top-level blocks of an HCL document, nested blocks included."""
    lines = text.splitlines()
    blocks, _ = _parse_until(lines, 0, depth=0)
    return blocks


def _parse_until(
    lines: "list[str]", index: int, depth: int
) -> "tuple[list[Block], int]":
    """Collect blocks from ``index`` until the brace at ``depth`` closes."""
    blocks: "list[Block]" = []
    while index < len(lines):
        raw = lines[index]
        heredoc = _HEREDOC.search(strip_noise(raw))
        if heredoc is not None:
            index = _skip_heredoc(lines, index + 1, heredoc.group("tag"))
            continue

        structure = strip_noise(raw)
        if depth and structure.count("}") > structure.count("{"):
            return blocks, index

        header = _BLOCK_HEADER.match(structure)
        if header is None:
            index += 1
            continue

        children, end = _parse_until(lines, index + 1, depth + 1)
        body = [(number + 1, lines[number]) for number in range(index + 1, min(end, len(lines)))]
        blocks.append(
            Block(
                kind=header.group("kind"),
                labels=_labels_of(header, strip_comments(raw)),
                line=index + 1,
                body=body,
                children=tuple(children),
            )
        )
        index = end + 1
    return blocks, index


def _labels_of(structural: "re.Match[str]", line: str) -> "tuple[str, ...]":
    """The block's labels, read from the line with its strings still in it.

    The structural match found the header, but it was made against a line whose
    string contents were blanked for brace counting, so its labels are empty
    quotes. Matching again against the real text recovers them; the quoted-label
    pattern consumes braces happily, so only a header that fails to match twice
    falls back to nothing.
    """
    match = _BLOCK_HEADER.match(line) or structural
    return tuple(quoted or bare for quoted, bare in _LABEL.findall(match.group("labels")))


def _skip_heredoc(lines: "list[str]", index: int, tag: str) -> int:
    """Step past a heredoc body, whose contents are text rather than structure."""
    while index < len(lines) and lines[index].strip() != tag:
        index += 1
    return index + 1
