"""Deciding whether a string looks like a generated credential.

Every rule that is not a documented token shape ends up here: the entropy
rule, the value-position rules for ``.env`` files, the Dockerfile ``ENV``
check. Keeping the judgement in one module means a placeholder that one rule
learns to ignore is ignored by all of them.

The interesting part is the entropy floor. A single global threshold cannot
work, because the maximum entropy a string can reach depends on both its
alphabet and its length: a 12-character hex token tops out at 3.58 bits per
character and a 200-character base64 blob at 6, so one number is simultaneously
too strict for the first and too lax for the second. What generalises is the
*ratio*: a generated credential lands near the ceiling of what its alphabet and
length allow, and a hand-written value lands well below it.
"""

from __future__ import annotations

import math
import re
import string

#: Fraction of the achievable maximum a value must reach to look generated.
#: Measured against real tokens: random hex, base64 and alphanumeric secrets
#: all sit above 0.9, while words, dates, paths and version strings fall well
#: under 0.7. The gap is wide, so the exact figure matters less than the shape.
ENTROPY_RATIO = 0.75

#: An absolute floor beneath the ratio, so that a very short value over a tiny
#: alphabet cannot clear the bar simply because its ceiling is low too.
MIN_ENTROPY = 2.5

#: Shortest value worth judging. Below this, entropy is noise.
MIN_SECRET_LENGTH = 12

_HEX = set(string.hexdigits)
_ALNUM = set(string.ascii_letters + string.digits)
_BASE64ISH = _ALNUM | set("+/=-_.")

#: Names that promise a credential lives on the other side of the assignment.
SECRET_NAME = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_.\[\]-]*
        (?:passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key|
           private[_-]?key|client[_-]?secret|credential|
           auth[_-]?(?:token|key|secret|pass|pw|header)|authorization|bearer)
     [A-Za-z0-9_.\[\]-]*)
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
        # Repeated dollars are how Compose escapes interpolation, so
        # "$$(cat /run/secrets/db-password)" is a command, not a credential.
        <.*> | \{\{.*\}\} | \$+\{.*\} | \$+\(.*\) | %\w+% | \$+[A-Za-z_]\w* |
        .*(?:example\.com|localhost|127\.0\.0\.1).*
    )$
    """
)

#: Values that are structure rather than secret: paths, URLs without a
#: password in them, version constraints, dotted identifiers, dates.
_STRUCTURED = (
    re.compile(r"^[~.]{0,2}/[^\s]*$"),                     # /etc/ssl/private, ./key.pem
    re.compile(r"^[a-z][a-z0-9+.-]*://[^:@\s]*$", re.I),   # a URL carrying no credential
    re.compile(r"^[~^><=v\s]*\d+(?:\.\d+)*(?:[-+][\w.]+)*$", re.I),  # 1.2.3-alpha.4, ^2.0
    re.compile(r"^\d{4}-\d{2}-\d{2}[T \d:.+Z-]*$", re.I),  # timestamps
    re.compile(r"^[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*){2,}$"),  # com.example.thing
    re.compile(r"^[\[{]"),                                # a list or object, not a value
    # A quoted type expression: tuple[int, str, int], dict[str, Node]. Common
    # wherever annotations are strings, and this one caught this project out.
    re.compile(r"^[A-Za-z_][\w.]*\[[^\]]*\]$"),
    # A screaming-snake identifier: AZURE_FEDERATED_TOKEN_FILE is the *name* of
    # an environment variable, not its value. Real tokens in this shape do not
    # exist; they carry mixed case, digits and punctuation.
    re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"),
    # An all-lowercase relative path: "testdata/secret_key". Anchored to
    # lowercase on purpose -- a base64 blob containing slashes has mixed case,
    # so this does not swallow one.
    re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9._-]+)+$"),
    # Words joined by hyphens or underscores: "unstructured", "content-type",
    # "Proxy-Authorization". Generated credentials carry digits
    # or mixed case; a pure word-list slug is vocabulary. The cost is that a
    # deliberate passphrase secret goes unreported, which is a trade worth
    # making -- this pattern is most of what a real codebase assigns to names
    # like token_type and auth_scheme.
    re.compile(r"^[A-Z]?[a-z]+(?:[-_][A-Z]?[a-z]+)*$"),
)


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


def alphabet_size(value: str) -> int:
    """The nominal size of the alphabet ``value`` appears to be drawn from.

    Nominal rather than observed: a 16-character hex token uses at most 16
    distinct characters however random it is, and judging it against its own
    observed alphabet would make every string look maximally random.
    """
    chars = set(value)
    if chars <= set(string.digits):
        return 10
    if chars <= _HEX:
        return 16
    if chars <= set(string.ascii_lowercase + string.digits + "_-"):
        return 38
    if chars <= set(string.ascii_uppercase + string.digits + "_-"):
        return 38
    if chars <= _ALNUM:
        return 62
    if chars <= _BASE64ISH:
        return 68
    return 90


def entropy_floor(value: str) -> float:
    """The entropy ``value`` must reach for its length and alphabet to look generated.

    The ceiling for a string of length *n* over an alphabet of *k* symbols is
    ``log2(min(k, n))`` -- capped by *n* because a string cannot use more
    distinct symbols than it has characters. A credential sits near that
    ceiling; a word or a version number does not.
    """
    if not value:
        return MIN_ENTROPY
    ceiling = math.log2(min(alphabet_size(value), len(value)))
    return max(MIN_ENTROPY, ENTROPY_RATIO * ceiling)


#: Interpolation anywhere in a value, not only at its start:
#: ``"GITHUB_TOKEN_${org^^}"`` is a variable name being assembled.
_EMBEDDED_INTERPOLATION = re.compile(r"\$\{|\$\(|\{\{|%\(")


def looks_like_placeholder(value: str) -> bool:
    """True when a value is obviously a stand-in rather than a real credential."""
    stripped = value.strip()
    if not stripped or _PLACEHOLDER.match(stripped):
        return True
    if _EMBEDDED_INTERPOLATION.search(stripped):
        return True
    if any(pattern.match(stripped) for pattern in _STRUCTURED):
        return True
    # "aaaaaaaaaaaa" and friends: one repeated character is nobody's password.
    return len(set(stripped)) <= 2


def is_secret_name(name: str) -> bool:
    """True when an identifier announces that its value is a credential."""
    return SECRET_NAME.search(name) is not None


def looks_generated(value: str) -> bool:
    """True when ``value`` is long enough, random enough and not a placeholder.

    The single question every heuristic rule asks. Whether the *name* on the
    other side of the assignment justifies asking it is the caller's problem.
    """
    stripped = value.strip()
    if len(stripped) < MIN_SECRET_LENGTH:
        return False
    if looks_like_placeholder(stripped):
        return False
    return shannon_entropy(stripped) >= entropy_floor(stripped)
