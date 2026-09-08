"""Detect credentials that were committed by accident.

Two complementary strategies:

1. **Provider patterns.** Tokens with a documented, distinctive shape (AWS key
   ids, GitHub PATs, Stripe keys) match on structure alone. These are high
   confidence and rarely wrong.
2. **Entropy on assignment.** A variable literally named ``password`` or
   ``api_key`` assigned a long, random-looking string. Lower confidence, so it
   is gated behind a Shannon-entropy floor and a placeholder filter.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Iterator

from ..findings import Finding, Severity, redact

#: Skip a line entirely when it carries this marker.
IGNORE_MARKER = "repo-sentinel: ignore"

_PROVIDER_RULES: tuple[tuple[str, str, Severity, re.Pattern[str], str], ...] = (
    (
        "SEC001",
        "AWS access key id",
        Severity.CRITICAL,
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
        "Deactivate the key in IAM, then rotate it. Deleting the commit is not enough.",
    ),
    (
        "SEC002",
        "GitHub personal access token",
        Severity.CRITICAL,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b"),
        "Revoke the token at github.com/settings/tokens and issue a new one.",
    ),
    (
        "SEC003",
        "GitHub fine-grained token",
        Severity.CRITICAL,
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
        "Revoke the token at github.com/settings/tokens and issue a new one.",
    ),
    (
        "SEC004",
        "Private key block",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Treat the key as compromised: generate a new pair and rotate every authorized_keys entry.",
    ),
    (
        "SEC005",
        "Stripe live secret key",
        Severity.CRITICAL,
        re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"),
        "Roll the key in the Stripe dashboard immediately.",
    ),
    (
        "SEC006",
        "Slack token",
        Severity.HIGH,
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        "Revoke the token in the Slack app configuration.",
    ),
    (
        "SEC007",
        "Google API key",
        Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Delete the key in the Google Cloud console and add API restrictions to its replacement.",
    ),
    (
        "SEC008",
        "OpenAI-style API key",
        Severity.HIGH,
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "Revoke the key in the provider dashboard.",
    ),
    (
        "SEC009",
        "JSON Web Token",
        Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "Check what the token grants; if it is a live session or service token, invalidate it.",
    ),
    (
        "SEC010",
        "Stripe test key",
        Severity.LOW,
        re.compile(r"\b[sr]k_test_[A-Za-z0-9]{16,}\b"),
        "Test keys are low risk, but keep them out of version control anyway.",
    ),
)

_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_.-]*
        (?:passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key|
           private[_-]?key|client[_-]?secret|auth)
     [A-Za-z0-9_.-]*)
    \s* [:=] \s*
    (?P<quote>["'])(?P<value>[^"']{12,256})(?P=quote)
    """
)

_PLACEHOLDER = re.compile(
    r"""(?ix)
    ^(?:
        x{3,} | \*+ | \.+ | -+ |
        (?:change|changeme|placeholder|example|sample|dummy|redacted|removed|
           todo|fixme|none|null|nil|true|false|test|testing|foo|bar|baz)
        [_-]?\w* |
        your[_-]?.* | my[_-]?.* | some[_-]?.* | insert[_-]?.* |
        <.*> | \{\{.*\}\} | \$\{.*\} | \$\(.*\) | %\w+% |
        .*(?:example\.com|localhost|127\.0\.0\.1).*
    )$
    """
)

#: Anything below this is too structured to be a generated credential.
ENTROPY_FLOOR = 3.2


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Random base64 lands near 6, English near 4."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def looks_like_placeholder(value: str) -> bool:
    """True when a value is obviously a stand-in rather than a real credential."""
    stripped = value.strip()
    if not stripped or _PLACEHOLDER.match(stripped):
        return True
    # "aaaaaaaaaaaa" and friends: one repeated character is nobody's password.
    return len(set(stripped)) <= 2


def scan_line(path: str, line_number: int, line: str) -> Iterator[Finding]:
    """Yield every finding in a single line of text."""
    if IGNORE_MARKER in line:
        return

    matched_spans: list[tuple[int, int]] = []

    for rule_id, title, severity, pattern, remediation in _PROVIDER_RULES:
        for match in pattern.finditer(line):
            matched_spans.append(match.span())
            yield Finding(
                rule_id=rule_id,
                severity=severity,
                title=title,
                path=path,
                line=line_number,
                evidence=redact(match.group(0)),
                remediation=remediation,
            )

    for match in _ASSIGNMENT.finditer(line):
        value = match.group("value")
        span = match.span("value")
        # Do not report the same string twice under two rules.
        if any(start <= span[0] < end for start, end in matched_spans):
            continue
        if looks_like_placeholder(value):
            continue
        if shannon_entropy(value) < ENTROPY_FLOOR:
            continue
        yield Finding(
            rule_id="SEC100",
            severity=Severity.HIGH,
            title=f"High-entropy value assigned to {match.group('name')!r}",
            path=path,
            line=line_number,
            evidence=redact(value),
            remediation=(
                "Move the value to an environment variable or secret store. "
                f"Add a trailing '# {IGNORE_MARKER}' comment if this is a false positive."
            ),
        )


def scan_text(path: str, text: str) -> list[Finding]:
    """Scan an entire file's contents."""
    return [
        finding
        for number, line in enumerate(text.splitlines(), start=1)
        for finding in scan_line(path, number, line)
    ]


def scan_files(files: Iterable[tuple[str, str]]) -> list[Finding]:
    """Scan ``(path, text)`` pairs."""
    return [finding for path, text in files for finding in scan_text(path, text)]
