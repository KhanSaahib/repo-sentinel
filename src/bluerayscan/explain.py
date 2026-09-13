"""Answer the question a scanner cannot answer by staying quiet.

"Did you miss my secret?" is the one question this tool's silence cannot
distinguish from "there was nothing there", and the honest answer for any
particular value is a short list of measurements rather than a finding.

Reporting near misses as findings was the other way to answer it, and it was
measured and rejected: at the tightest useful band it produced 172 findings
across the twenty-one pinned repositories, one of which a reviewer would have
wanted. Almost all of the rest were not literals at all -- one variable
assigned to another, a class name, a Vault reference. So the answer lives
here, where somebody asks for it about a value they have in their hand,
instead of arriving uninvited about four hundred they do not.
"""

from __future__ import annotations

import dataclasses
import math

from . import heuristics
from .findings import redact
from .scanners import allowlist, providers

__all__ = ["Explanation", "explain"]

@dataclasses.dataclass(frozen=True)
class Explanation:
    """Everything this tool can say about one value, and its verdict."""

    value: str
    lines: "tuple[str, ...]"
    verdict: str
    reported: bool

    def render(self) -> str:
        body = "\n".join(f"  {line}" for line in self.lines)
        return f"{redact(self.value)}\n{body}\n\n{self.verdict}"


def describe_alphabet(value: str) -> str:
    """The alphabet the heuristics counted, as a size and a name.

    Both halves come from :mod:`.heuristics`, because a name assembled here
    from its own idea of what hex is would disagree with the number beside it,
    and did.
    """
    return f"{heuristics.alphabet_size(value)} symbols ({heuristics.alphabet_name(value)})"


def explain(value: str, name: str = "") -> Explanation:
    """Measure ``value`` the way the heuristic rules do, and say what follows.

    ``name`` is the identifier it was assigned to, when there is one. It
    matters as much as the value does: the entropy rules ask about a value
    only where the name on the other side of the assignment promises a
    credential, so a perfectly random string assigned to ``build_id`` is not
    reported and this says so rather than leaving it a mystery.
    """
    stripped = value.strip()
    lines = [f"length      {len(stripped)} characters (minimum {heuristics.MIN_SECRET_LENGTH})"]
    if stripped:
        lines.append(f"alphabet    {describe_alphabet(stripped)}")
        entropy = heuristics.shannon_entropy(stripped)
        floor = heuristics.entropy_floor(stripped)
        ceiling = math.log2(min(heuristics.alphabet_size(stripped), len(stripped)))
        lines.append(f"entropy     {entropy:.2f} bits per character")
        lines.append(
            f"floor       {floor:.2f} bits -- {heuristics.ENTROPY_RATIO:g} of the "
            f"{ceiling:.2f} a value this long over this alphabet could reach"
        )

    shape = _provider_shape(stripped)
    lines.append(f"shape       {shape or 'matches no documented token shape'}")
    if name:
        answers = "yes" if heuristics.is_secret_name(name) else "no"
        lines.append(f"name        {name!r} promises a credential: {answers}")

    return Explanation(stripped, tuple(lines), *_verdict(stripped, name, shape))


def _provider_shape(value: str) -> str:
    """The name of the documented token shape ``value`` matches, or ""."""
    spans: "list[tuple[int, int]]" = []
    for rule, _, _ in providers.findings_in(
        "<explain>", 1, value, spans, False, allowlist.is_known_example
    ):
        return f"{rule.title} ({rule.rule_id})"
    return ""


def _verdict(value: str, name: str, shape: str) -> "tuple[str, bool]":
    """What the scanner would do with this value, and whether that is report it.

    The order matters and mirrors the scanners': a documented shape is
    reported wherever it appears and whatever it is called, and only when
    nothing recognises the shape does the name start to matter.
    """
    if not value:
        return "Nothing to measure.", False
    if shape:
        if allowlist.is_known_example(value) or providers.looks_invented(value):
            return (
                f"Reported only with --no-example-allowlist. This matches {shape}, "
                "but it is a value published as an example or one whose shape says "
                "it was invented.",
                False,
            )
        return f"Reported: {shape}. A documented shape is reported wherever it appears.", True

    shortfall = heuristics.entropy_shortfall(value)
    if shortfall is None:
        if len(value) < heuristics.MIN_SECRET_LENGTH:
            return (
                f"Not reported: {len(value)} characters, and the entropy rules "
                f"start at {heuristics.MIN_SECRET_LENGTH}.",
                False,
            )
        if not value.isascii():
            return (
                "Not reported: not ASCII. Credentials travel through headers, "
                "URLs and environment variables that are, and text in another "
                "script measures as high-entropy for a reason that has nothing "
                "to do with randomness.",
                False,
            )
        return (
            "Not reported: this reads as a placeholder rather than a value.",
            False,
        )
    if shortfall > 0:
        return (
            f"Not reported: {shortfall:.2f} bits below the floor. A value can be "
            "a real credential and still land here -- a short passphrase, a word "
            "somebody chose. Nothing above the floor is guessed at, and nothing "
            "below it is reported, because measuring how far below turned out to "
            "be 172 findings on the pinned corpus and one of them worth reading.",
            False,
        )
    if not name:
        return (
            "Reported where the name promises a credential. Pass --name to say "
            "what this was assigned to; the entropy rules never ask about a "
            "value on its own.",
            False,
        )
    if not heuristics.is_secret_name(name):
        return (
            f"Not reported: {name!r} does not promise a credential, so nothing "
            "asks about the value beside it. A random string assigned to a build "
            "id is a build id.",
            False,
        )
    return (
        f"Reported: high-entropy value assigned to {name!r} (SEC100 or SEC101, "
        "depending on whether it is quoted), at medium confidence.",
        True,
    )
