"""Entropy floors for the heuristic secret rule, tracked per character class.

One Shannon-entropy floor cannot be right for every candidate, because entropy
*per character* is bounded by ``log2(min(alphabet size, length))``. The
scanner's original 3.2-bit floor was therefore wrong in both directions at
once:

* **Too high for hex.** A uniformly random 16-character hex token averages 3.21
  bits per character and a 12-character one averages 2.98, so roughly half of
  all genuine short hex tokens scored under 3.2 and were never reported.
* **Too low for base64.** A random 32-character base64 token averages 4.56
  bits, so 3.2 left well over a bit of headroom, and ordinary structured text --
  URLs, dotted version strings, hyphenated words, timestamps -- cleared the
  floor and got reported as a secret.

So the floor is derived per character class instead. Each profile names the
alphabet it stands for and the fraction of that alphabet's best-case entropy a
value has to reach::

    floor = ratio * log2(min(alphabet_size, length))

Scaling by ``log2(min(alphabet_size, length))`` is what lets a single ratio hold
across lengths. A 12-character value cannot exceed log2(12) bits however random
it is, so judging it against the same absolute number as a 64-character value
penalises it for being short rather than for being predictable.

The ratios were fitted by simulating 20,000 uniformly random strings for each
(alphabet, length) pair and taking roughly the 1st percentile of the observed
ratio, so a genuinely random credential clears its own floor about 99% of the
time. They are deliberately no tighter than that: this rule is the low
confidence half of the scanner, and one missed guess costs less than output
nobody reads.
"""

from __future__ import annotations

import math
import re
from typing import NamedTuple


class EntropyProfile(NamedTuple):
    """A character class, the alphabet it stands for, and its floor ratio."""

    name: str
    alphabet_size: int
    ratio: float


#: Hex is the narrow case. Its ceiling is 4 bits per character however long the
#: value is, so the floor has to sit low. The discriminating signal here is that
#: a long single-case hex string was assigned to a credential-shaped name at
#: all, not how evenly its sixteen symbols happen to be spread.
HEX = EntropyProfile("hex", 16, 0.65)

#: Base64 and its url-safe variant: the shape almost every generated token
#: arrives in. Random values score high here, so the floor can too, and that is
#: what keeps encoded prose and structured identifiers out of the report.
BASE64 = EntropyProfile("base64", 64, 0.82)

#: Everything else -- values carrying punctuation, spaces or mixed separators.
#: These are mostly URLs, paths and English phrases rather than credentials, so
#: this profile is the strictest of the three.
MIXED = EntropyProfile("mixed", 95, 0.85)

PROFILES = (HEX, BASE64, MIXED)

_HEX_ONLY = re.compile(r"\A(?:[0-9a-f]+|[0-9A-F]+)\Z")
_BASE64_ONLY = re.compile(r"\A[A-Za-z0-9+/=_-]+\Z")
_CHARACTER_CLASSES = (
    re.compile(r"[a-z]"),
    re.compile(r"[A-Z]"),
    re.compile(r"[0-9]"),
)

#: Under this length a value's entropy says nothing worth acting on: four
#: characters drawn from a 64-symbol alphabet max out at 2 bits whether they
#: were generated or typed. The assignment rule enforces its own, longer
#: minimum; this one exists so the module is safe to call on its own.
MIN_JUDGEABLE_LENGTH = 8


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


def _distinct_classes(value: str) -> int:
    return sum(1 for pattern in _CHARACTER_CLASSES if pattern.search(value))


def classify(value: str) -> EntropyProfile:
    """Pick the profile whose alphabet best describes ``value``.

    Base64 membership deliberately also demands two of lowercase, uppercase and
    digits. A generated base64 payload of any length mixes them; a lowercase
    phrase joined by hyphens or underscores uses nothing outside the base64url
    alphabet but is still an English phrase, and letting it borrow base64's
    6-bit ceiling would measure it against a bar it was never going to clear
    either way. Sending it to :data:`MIXED` judges it against what a
    26-character value can actually reach, which is where the two separate.
    """
    if _HEX_ONLY.match(value):
        return HEX
    if _BASE64_ONLY.match(value) and _distinct_classes(value) >= 2:
        return BASE64
    return MIXED


def entropy_floor(value: str) -> float:
    """The bits per character ``value`` must reach to count as high entropy.

    Returns infinity for a value too short to judge, so a caller comparing
    against it stays quiet rather than guessing when the metric has nothing to
    say.
    """
    if len(value) < MIN_JUDGEABLE_LENGTH:
        return math.inf
    profile = classify(value)
    ceiling = math.log2(min(profile.alphabet_size, len(value)))
    return profile.ratio * ceiling


def is_high_entropy(value: str) -> bool:
    """True when ``value`` is random enough, for its own alphabet, to be a secret."""
    return shannon_entropy(value) >= entropy_floor(value)
