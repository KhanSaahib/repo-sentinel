"""Enough YAML to ask structural questions, and no more.

The workflow scanner gets by on indentation heuristics because the questions it
asks are shallow. Kubernetes manifests are not like that: "does this container
set resource limits" is a question about a path four levels down a document,
and the honest answer to "is there a privileged container here" cannot be found
by grepping for ``privileged: true`` -- that line means one thing under
``securityContext`` and nothing at all under ``annotations``.

So this module reads the subset of YAML that configuration is actually written
in: block mappings, block sequences, scalars, block scalars, inline flow
collections kept as raw text, and multi-document streams. Every node carries
the line it started on, because a finding without a line number is a finding
nobody acts on.

What it does not do, and what a rule built on it must therefore never claim to
have checked: anchors and aliases, merge keys, tags, multi-line flow
collections, and the several exotic scalar forms. A document using them parses
into something incomplete rather than something wrong -- unknown structure
becomes a scalar string, which reads as "no nested value here". Rules degrade
to silence, which is the safe direction for a parser this small.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterator
from typing import Tuple, Union

_COMMENT_OR_BLANK = re.compile(r"^\s*(?:#.*)?$")
_DOCUMENT_BREAK = re.compile(r"^---\s*(?:#.*)?$")
# A colon only opens a mapping when whitespace or the end of the line follows
# it. Without that rule "- 5432:5432" and "- /var/run/docker.sock:/srv" parse
# as mappings, which is how a Compose port list turns into nonsense.
_KEY = re.compile(
    r"""^(?P<key>"[^"]*"|'[^']*'|[^:#\s"'][^:#]*?)\s*:(?:[ \t]+(?P<value>.*?)|\s*)\s*$"""
)
_ITEM = re.compile(r"^-(?:\s+(?P<rest>.*?))?\s*$")
_BLOCK_SCALAR = re.compile(r"^[|>][+-]?\d*$")


@dataclasses.dataclass(frozen=True)
class Node:
    """One value, and the line it began on.

    ``value`` is a ``dict`` for a mapping, a ``list`` for a sequence, and a
    ``str`` for everything else -- including the flow collections this parser
    keeps as raw text, so that a rule wanting ``[a, b]`` can match it and a rule
    wanting structure correctly finds none.
    """

    value: "Union[dict, list, str]"
    line: int

    @property
    def is_map(self) -> bool:
        return isinstance(self.value, dict)

    @property
    def is_list(self) -> bool:
        return isinstance(self.value, list)

    @property
    def text(self) -> str:
        return self.value if isinstance(self.value, str) else ""

    def get(self, *keys: str) -> "Node | None":
        """Follow a path of mapping keys, or return None the moment it breaks."""
        node: "Node | None" = self
        for key in keys:
            if node is None or not node.is_map:
                return None
            node = node.value.get(key)  # type: ignore[union-attr]
        return node

    def items(self) -> "Iterator[tuple[str, Node]]":
        if self.is_map:
            yield from self.value.items()  # type: ignore[union-attr]

    def entries(self) -> "Iterator[Node]":
        """The elements of a sequence, or nothing for anything else."""
        if self.is_list:
            yield from self.value  # type: ignore[misc]

    def truthy(self) -> bool:
        return self.text.strip().strip("\"'").lower() in ("true", "yes", "on")

    def falsy(self) -> bool:
        return self.text.strip().strip("\"'").lower() in ("false", "no", "off")

    def walk(self) -> "Iterator[tuple[str, Node]]":
        """Every node beneath this one, as ``(key, node)``.

        The key is the mapping key a node was found under, or ``""`` for a
        sequence element. Rules use it to ask "is there a ``securityContext``
        anywhere in here" without knowing the shape of the document above it.
        """
        for key, child in self.items():
            yield key, child
            yield from child.walk()
        for child in self.entries():
            yield "", child
            yield from child.walk()


#: A Go template action: ``{{ .Values.image }}``, ``{{- if .Values.rbac }}``.
_TEMPLATE_ACTION = re.compile(r"\{\{-?.*?-?\}\}", re.DOTALL)

#: What a template expression is replaced with. Deliberately meaningless: a
#: rule that reads it is looking at a value the chart supplies from elsewhere,
#: and should draw no conclusion from its shape.
TEMPLATE_PLACEHOLDER = "__TEMPLATED__"


def is_templated(text: str) -> bool:
    """True when a document is a Go template rather than a finished manifest."""
    return "{{" in text


def strip_templates(text: str) -> str:
    """Turn a Helm-style template into something parseable, line for line.

    Charts are where most real Kubernetes manifests live, and a chart is not
    YAML: ``{{- if .Values.rbac }}`` is a control line that belongs to no
    mapping, and ``{{ .Values.image }}`` is a value that does not exist yet.

    Expressions become a placeholder scalar and control-only lines become
    blank, which keeps every remaining line at its original number -- a finding
    that points at the wrong line of a chart is worse than no finding.

    What comes out is not the manifest that will be installed; it is the parts
    of it that are written down. Rules that read a value present in the
    template are still right. Rules that conclude something from a value's
    *absence* are not, because the chart may supply it, which is why
    :mod:`.scanners.kubernetes` runs only some of its rules over a template.
    """
    out = []
    for line in text.splitlines():
        stripped = _TEMPLATE_ACTION.sub(TEMPLATE_PLACEHOLDER, line)
        naked = stripped.strip()
        if naked in (TEMPLATE_PLACEHOLDER, "-", "- " + TEMPLATE_PLACEHOLDER):
            out.append("")  # a control line: keeps the line number, adds nothing
            continue
        out.append(stripped)
    return "\n".join(out)


def strip_comment(value: str) -> str:
    """Remove a trailing comment from a scalar, leaving quoted text alone.

    YAML starts a comment at a ``#`` that follows whitespace or begins the
    value, and nowhere else: ``image: nginx  # pinned later`` is a comment and
    ``url: http://x/#anchor`` is not. Without this, every value in a commented
    file carries the comment with it -- ``true  # bluerayscan: ignore`` is
    not ``true``, so the rule reading it quietly finds nothing, which is the
    worst way for a scanner to be wrong.
    """
    quote = None
    for index, character in enumerate(value):
        if quote:
            if character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
            continue
        if character == "#" and (index == 0 or value[index - 1] in " \t"):
            return value[:index].rstrip()
    return value


def parse(text: str) -> "list[Node]":
    """Read a YAML stream into one :class:`Node` per document."""
    lines = text.splitlines()
    documents: "list[Node]" = []
    starts = [index for index, line in enumerate(lines) if _DOCUMENT_BREAK.match(line)]
    bounds = [0, *[start + 1 for start in starts], len(lines)]
    for begin, end in zip(bounds, bounds[1:]):
        chunk = _tokenise(lines, begin, end)
        if not chunk:
            continue
        node, _ = _parse_block(chunk, 0, chunk[0][0])
        documents.append(node)
    return documents


def parse_one(text: str) -> "Node | None":
    """The first document, for callers that expect a single one."""
    documents = parse(text)
    return documents[0] if documents else None


#: One tokenised line: its indent, its content, and the line it came from.
#: Spelled with typing.Tuple rather than the builtin so that it is a type alias
#: a checker can follow on 3.9 as well as a comment a reader can.
Token = Tuple[int, str, int]


def _tokenise(lines: "list[str]", begin: int, end: int) -> 'list[Token]':
    """Drop blanks and comments, and fold block scalars into one token."""
    tokens: 'list[Token]' = []
    index = begin
    while index < end:
        line = lines[index]
        if _COMMENT_OR_BLANK.match(line) or _DOCUMENT_BREAK.match(line):
            index += 1
            continue
        indent = len(line) - len(line.lstrip())
        content = line.strip()
        item = _ITEM.match(content)
        rest = item.group("rest") if item else None
        if rest and _KEY.match(rest):
            # "- name: app" is a dash and a mapping that happens to share a
            # line. Splitting it here rather than in the sequence parser keeps
            # that parser from having to rebuild the token list for every item
            # -- which it used to, at a cost of O(items squared) on a long
            # list. A 1 MB rules file took minutes.
            tokens.append((indent, "-", index + 1))
            tokens.append((indent + len(content) - len(content.lstrip("- ")), rest, index + 1))
        else:
            tokens.append((indent, content, index + 1))
        if _opens_block_scalar(content):
            index = _skip_indented(lines, index + 1, end, indent)
            continue
        index += 1
    return tokens


def _opens_block_scalar(content: str) -> bool:
    match = _KEY.match(content)
    value = match.group("value") if match else ""
    return bool(value) and bool(_BLOCK_SCALAR.match(value))


def _skip_indented(lines: "list[str]", index: int, end: int, indent: int) -> int:
    while index < end and (
        not lines[index].strip() or len(lines[index]) - len(lines[index].lstrip()) > indent
    ):
        index += 1
    return index


def _parse_block(tokens: 'list[Token]', index: int, indent: int) -> "tuple[Node, int]":
    """Parse the mapping or sequence that starts at ``tokens[index]``."""
    if index >= len(tokens):
        return Node("", 0), index
    if _ITEM.match(tokens[index][1]):
        return _parse_sequence(tokens, index, indent)
    return _parse_mapping(tokens, index, indent)


def _parse_mapping(tokens: 'list[Token]', index: int, indent: int) -> "tuple[Node, int]":
    mapping: "dict[str, Node]" = {}
    start = tokens[index][2]
    while index < len(tokens):
        current_indent, content, line = tokens[index]
        if current_indent < indent or _ITEM.match(content):
            break
        if current_indent > indent:  # stray deeper line: not ours to interpret
            index += 1
            continue
        match = _KEY.match(content)
        if match is None:
            index += 1
            continue
        key = match.group("key").strip().strip("\"'")
        value = match.group("value")
        if value and not _BLOCK_SCALAR.match(value):
            mapping[key] = Node(strip_comment(value).strip(), line)
            index += 1
            continue
        child, index = _parse_child(tokens, index + 1, current_indent, line)
        mapping[key] = child
    return Node(mapping, start), index


def _parse_sequence(tokens: 'list[Token]', index: int, indent: int) -> "tuple[Node, int]":
    items: "list[Node]" = []
    start = tokens[index][2]
    while index < len(tokens):
        current_indent, content, line = tokens[index]
        match = _ITEM.match(content)
        if current_indent < indent or match is None:
            break
        if current_indent > indent:
            index += 1
            continue
        rest = match.group("rest")
        if not rest:
            # Either a bare dash whose value is on the following lines, or the
            # first half of a "- key: value" that :func:`_tokenise` split.
            child, index = _parse_child(tokens, index + 1, current_indent, line)
            items.append(child)
            continue
        items.append(Node(strip_comment(rest).strip(), line))
        index += 1
    return Node(items, start), index


def _parse_child(
    tokens: 'list[Token]', index: int, indent: int, line: int
) -> "tuple[Node, int]":
    """The value of a key that had nothing after its colon."""
    if index >= len(tokens) or tokens[index][0] <= indent:
        if index < len(tokens) and _ITEM.match(tokens[index][1]) and tokens[index][0] == indent:
            # A sequence may sit at the same indent as the key that owns it.
            return _parse_sequence(tokens, index, indent)
        return Node("", line), index
    return _parse_block(tokens, index, tokens[index][0])
