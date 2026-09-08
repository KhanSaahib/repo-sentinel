"""Credentials that are public by design, and so are never worth reporting.

Documentation is the largest single source of false positives in a secret
scanner. An AWS tutorial pasted into a README contains a string that is, by
construction, shaped exactly like a live access key id, and the scanner has no
way to tell from structure alone that the whole world already has it. Asking
users to bury those under per-line ignore markers does not scale, and a tool
that cries wolf on every code sample teaches people to skip its output --
which is how the one real finding gets missed.

Three mechanisms, ordered by how much evidence each needs:

1. **Exact values.** Credentials published verbatim in a vendor's own
   documentation or in an RFC. These cannot be live, because publication is
   what they are for.
2. **Vendor conventions.** AWS reserves the ``EXAMPLE`` suffix for
   documentation identifiers, so ``AKIA...EXAMPLE`` is AWS itself promising
   the key is inert. Matching the convention covers the samples nobody has
   thought to enumerate here yet.
3. **RFC 2606 reserved domains.** ``example.com`` and its siblings exist so
   that documentation can name a host without naming a real one. A JWT whose
   header or claims point at one is a specimen rather than a session, which
   catches the RFC 7519 sample tokens without pinning their exact bytes.

Every entry silences the scanner permanently for that value, so additions are
a deliberate act: an entry must be publicly documented *and* inert. "Probably
not a real key" is not enough -- that judgement belongs to the person reading
the report, not to this list. Where the exact bytes of a sample are uncertain,
prefer a convention that the vendor documents over a literal transcribed from
memory: a convention that misses is silent, whereas a wrong literal quietly
claims a coverage the scanner does not have.
"""

from __future__ import annotations

import base64
import binascii
import re

#: Credentials published verbatim by a vendor or standards document.
EXAMPLE_CREDENTIALS: frozenset = frozenset(
    {
        # AWS: the access key id and secret used throughout the IAM guides,
        # the CLI reference and every SDK "getting started" page.
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAI44QH8DHBEXAMPLE",
        "ASIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
        # The default token shown on jwt.io, which is pasted into a large share
        # of the JWT tutorials, blog posts and test suites in existence.
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    }
)

#: AWS documentation identifiers: a valid prefix, then filler, then EXAMPLE.
_AWS_EXAMPLE_ID = re.compile(
    r"^(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{9}EXAMPLE$"
)

#: AWS documentation secret access keys: 40 characters ending in EXAMPLEKEY.
_AWS_EXAMPLE_SECRET = re.compile(r"^[A-Za-z0-9/+=]{30}EXAMPLEKEY$")

#: Domains RFC 2606 reserves for documentation, so they can never be routed.
_RESERVED_DOMAINS = ("example.com", "example.org", "example.net", "example.edu")


def _decode_segment(segment: str) -> str:
    """Base64url-decode one JWT segment, returning "" when it is not text.

    JWT segments carry no padding, and a segment that fails to decode is simply
    not a segment worth reading -- the caller treats an empty result as "no
    evidence of a documentation domain" rather than as an error, because a
    malformed token should still be reported, not allowlisted.
    """
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""


def jwt_is_documentation(token: str) -> bool:
    """True when a JWT's header or claims name an RFC 2606 reserved domain.

    The signature is deliberately not verified. The question here is not
    whether the token is valid but whether it is a sample: the RFC 7519
    examples issue claims against ``http://example.com/is_root``, and no
    production issuer can use a domain that does not resolve.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False
    for segment in parts[:2]:
        decoded = _decode_segment(segment).lower()
        if any(domain in decoded for domain in _RESERVED_DOMAINS):
            return True
    return False


def is_known_example(value: str) -> bool:
    """True when ``value`` is a credential published for documentation."""
    candidate = value.strip()
    if not candidate:
        return False
    if candidate in EXAMPLE_CREDENTIALS:
        return True
    if _AWS_EXAMPLE_ID.match(candidate) or _AWS_EXAMPLE_SECRET.match(candidate):
        return True
    return candidate.startswith("eyJ") and jwt_is_documentation(candidate)
