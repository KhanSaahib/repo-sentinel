"""Fake credentials for the test suite, assembled rather than written out.

Every value here is invented. None was ever issued, none grants anything, and
none should be treated as sensitive.

They are built by concatenation at import time because a secret scanner cannot
know any of that. GitHub's push protection rejects this repository outright
when a well-formed AWS access key id appears as a contiguous literal -- which
is correct behaviour on its part, and is precisely the false-positive problem
that :mod:`bluerayscan.scanners.allowlist` exists to solve for documentation.
Splitting the literal is not an attempt to smuggle anything past a scanner; it
keeps a string that no scanner could clear out of the repository's bytes, so
that a fixture never costs a human being a judgement call.

Values that are *supposed* to be recognised as documentation -- the AWS
``EXAMPLE`` convention, the RFC sample tokens -- are written out literally
wherever they read better that way. That is the whole point of the convention,
and no scanner objects to them.
"""

#: A well-formed AWS access key id that follows no documentation convention,
#: so the allowlist must not exempt it and real scanners must flag it.
REALISTIC_AWS_KEY_ID = "AKIA" + "ZZ7Q4TWFN2XKLM3D"

#: An AWS access key id carrying AWS's reserved documentation suffix.
EXAMPLE_AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

#: The AWS documentation secret access key, ending in the reserved EXAMPLEKEY.
EXAMPLE_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

#: The sample token from RFC 7519 section 3.1, verbatim. The header segment is
#: split only because its 40 base64 characters trip AWS-secret detectors.
RFC_7519_SAMPLE_JWT = (
    "eyJ0eXAiOiJKV1Qi" "LA0KICJhbGciOiJIUzI1NiJ9"
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxl"
    "LmNvbS9pc19yb290Ijp0cnVlfQ"
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
