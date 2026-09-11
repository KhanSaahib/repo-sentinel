"""Findings that are about a file's name, not its contents.

Everything else in this tool reads text, which means everything else is blind
to the files that have none. A committed ``id_rsa`` has no line a pattern can
match; a ``.p12`` keystore, a ``.jks``, a ``.pfx`` are binary and skipped before
any rule sees them. Those are among the worst things a repository can contain
and the easiest for a scanner to miss entirely.

So this scanner works from the walk's list of paths, binaries included. It
claims less than the others -- a name is evidence about a file, not proof of
what is inside it -- and its confidence says so, except where the name is so
specific that it is not really a guess.

Two rules that keep it from becoming noise. Extensions shared by public and
private material (``.pem``, ``.key``, which are just as often certificates)
are reported at medium confidence, and only when the file was not already
readable -- if it is text, SEC004 has looked inside it and either found a
private key block or not, and that answer is better than this one. And the
example suffixes (``.example``, ``.sample``, ``.template``, ``.dist``) are
skipped throughout: a repository documenting the shape of its ``.env`` is doing
the right thing.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from ..findings import Confidence, Finding, Severity

#: Names that are private key material and essentially nothing else.
_KEY_NAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity"})

#: Extensions that hold key material in a form no text rule can read.
_KEYSTORE_SUFFIXES = (".p12", ".pfx", ".jks", ".keystore", ".ppk", ".pkcs12", ".bcfks")

#: Extensions that may be a private key, and may equally be a certificate.
_AMBIGUOUS_SUFFIXES = (".pem", ".key", ".pk8", ".asc", ".gpg")

#: Files whose whole purpose is to hold a credential for some tool.
_CREDENTIAL_NAMES = {
    ".npmrc": "an npm auth token",
    ".pypirc": "a PyPI upload token",
    ".netrc": "login credentials for any host it names",
    "_netrc": "login credentials for any host it names",
    ".pgpass": "PostgreSQL passwords",
    ".my.cnf": "MySQL credentials",
    ".dockercfg": "registry credentials",
    "credentials": "cloud provider credentials",
    "kubeconfig": "cluster credentials",
    ".env": "whatever the application keeps out of its source",
    "terraform.tfvars": "whatever the infrastructure needs and the code does not hard-code",
}

#: Suffixes that mark a file as a documented shape rather than a real one.
_EXAMPLE_MARKERS = (".example", ".sample", ".template", ".dist", ".tpl", ".defaults")

_DOT_ENV = re.compile(r"^\.env(?:\.|$)")


def _is_example(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(_EXAMPLE_MARKERS) or any(
        marker.strip(".") in lowered.split(".")[1:-1] for marker in _EXAMPLE_MARKERS
    )


def _in_a_test_tree(path: str) -> bool:
    """Fixtures full of invented keys are the point of a fixture directory."""
    parts = {part.lower() for part in path.split("/")[:-1]}
    return bool(parts & {"testdata", "fixtures", "__fixtures__", "testing"})


def scan_name(path: str, readable: bool = False) -> "Iterator[Finding]":
    """Yield the findings a file's name alone justifies."""
    normalised = path.replace("\\", "/")
    name = posixpath.basename(normalised)
    lowered = name.lower()

    if _is_example(lowered):
        return

    if lowered in _KEY_NAMES:
        yield Finding(
            rule_id="FN001",
            severity=Severity.CRITICAL,
            title=f"{name} is an SSH private key",
            path=normalised,
            line=1,
            evidence=f"file named {name!r}",
            remediation=(
                "Treat the key as compromised: generate a new pair, replace "
                "every authorized_keys entry that trusted it, and remove the "
                "file. Deleting the commit is not enough."
            ),
        )
        return

    if lowered.endswith(_KEYSTORE_SUFFIXES):
        yield Finding(
            rule_id="FN001",
            severity=Severity.HIGH,
            title=f"{name} is a keystore, which no text rule can read",
            path=normalised,
            line=1,
            evidence=f"file named {name!r}",
            remediation=(
                "A keystore is binary, so nothing else here can look inside "
                "it. If it holds a private key, rotate it; if it holds only "
                "trusted certificates, say so in a comment next to it."
            ),
            confidence=Confidence.MEDIUM,
        )
        return

    if lowered.endswith(_AMBIGUOUS_SUFFIXES) and not readable:
        yield Finding(
            rule_id="FN002",
            severity=Severity.MEDIUM,
            title=f"{name} may hold key material and could not be read",
            path=normalised,
            line=1,
            evidence=f"file named {name!r}, skipped as binary or oversized",
            remediation=(
                "These extensions carry private keys about as often as they "
                "carry certificates, and this file was not readable as text, "
                "so nothing looked inside it. Check it by hand."
            ),
            confidence=Confidence.LOW if _in_a_test_tree(normalised) else Confidence.MEDIUM,
        )
        return

    holds = _CREDENTIAL_NAMES.get(lowered)
    if holds is None and _DOT_ENV.match(lowered):
        holds = _CREDENTIAL_NAMES[".env"]
    if holds is None:
        return
    yield Finding(
        rule_id="FN003",
        severity=Severity.MEDIUM,
        title=f"{name} is committed, and it exists to hold {holds}",
        path=normalised,
        line=1,
        evidence=f"file named {name!r}",
        remediation=(
            "This file's whole purpose is to carry a credential, so having it "
            "in version control is a decision rather than an accident. If it "
            "is a template, name it with an .example suffix; if it is real, "
            "rotate what it holds and add it to .gitignore."
        ),
        confidence=Confidence.LOW if _in_a_test_tree(normalised) else Confidence.HIGH,
    )


def scan_paths(entries: "Iterable[tuple[str, bool]]") -> "list[Finding]":
    """Scan ``(path, readable)`` pairs for every file the walk reached."""
    return [
        finding for path, readable in entries for finding in scan_name(path, readable)
    ]
