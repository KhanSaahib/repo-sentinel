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

Four rules, and the fourth is about a different thing: files that are not
credentials but end up holding them as a byproduct of what they are. A
Terraform state file records every value Terraform read, generated passwords
included, in plain text. A shell history records every password that was passed
on a command line. Nobody writes a secret into either on purpose, which is
exactly why nobody remembers they are there.

Three rules keep it from becoming noise, all of the same shape: prefer contents
to names wherever contents exist.

Extensions shared by public and private material (``.pem``, ``.key``, which are
just as often certificates) are reported only when the file was *not* readable
-- if it is text, SEC004 has looked inside it and either found a private key
block or not, and that answer is better than this one.

Files that sometimes hold a credential and sometimes hold configuration --
``.npmrc``, ``.env``, ``terraform.tfvars`` -- are judged on what is in them. An
``.npmrc`` saying ``ignore-scripts=true`` is not a leak, and a committed
``.env`` of documented defaults is a template. Only the files that have no
legitimate committed form at all (``.netrc``, ``.pgpass``, ``kubeconfig``) are
reported on their name alone.

And the example suffixes (``.example``, ``.sample``, ``.template``, ``.dist``)
are skipped throughout: a repository documenting the shape of its ``.env`` is
doing the right thing.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown
from ..findings import Confidence, Finding, Severity
from ..heuristics import is_secret_name, looks_like_placeholder

#: Names that are private key material and essentially nothing else.
_KEY_NAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity"})

#: Extensions that hold key material in a form no text rule can read.
_KEYSTORE_SUFFIXES = (".p12", ".pfx", ".jks", ".keystore", ".ppk", ".pkcs12", ".bcfks")

#: Extensions that may be a private key, and may equally be a certificate.
_AMBIGUOUS_SUFFIXES = (".pem", ".key", ".pk8", ".asc", ".gpg")

#: Files that have no legitimate committed form: the file *is* the credential,
#: so its presence is the finding and its contents change nothing.
_ALWAYS_CREDENTIALS = {
    ".netrc": "login credentials for any host it names",
    "_netrc": "login credentials for any host it names",
    ".pgpass": "PostgreSQL passwords",
    ".my.cnf": "MySQL credentials",
    ".dockercfg": "registry credentials",
    "credentials": "cloud provider credentials",
    "kubeconfig": "cluster credentials",
}

#: Files that often hold a credential and just as often hold configuration.
#: An .npmrc saying "ignore-scripts=true" is not a leak; a committed .env of
#: documented defaults is a template. For these the contents decide, and the
#: name only decides when there are no contents to read.
_MAYBE_CREDENTIALS = {
    ".npmrc": "an npm auth token",
    ".pypirc": "a PyPI upload token",
    ".env": "whatever the application keeps out of its source",
    "terraform.tfvars": "whatever the infrastructure needs and the code does not hard-code",
}

#: ``NAME=value`` or ``NAME: value`` -- enough to find the key in the formats
#: this rule is asked about, all of which are flat.
_ASSIGNMENT = re.compile(r"^[\s#-]*(?P<name>[A-Za-z0-9_./\[\]:@-]{1,120}?)\s*[:=]\s*(?P<value>.*)$")

#: Files that are not credentials but end up holding them as a side effect of
#: what they are. Nobody writes a secret into these on purpose, which is
#: exactly why nobody remembers they are there.
_BYPRODUCTS = {
    ".tfstate": (
        Severity.CRITICAL,
        "Terraform state records every value Terraform read, including generated "
        "passwords and private keys, in plain text",
    ),
    ".tfstate.backup": (
        Severity.CRITICAL,
        "a Terraform state backup, which holds the same plaintext values as the state",
    ),
    ".kubeconfig": (Severity.HIGH, "cluster credentials"),
    ".dump": (Severity.MEDIUM, "whatever was in the database when it was taken"),
}

#: Shell and client histories, which record the commands somebody typed --
#: including the ones with a password on the command line.
_HISTORY_NAMES = frozenset(
    {
        ".bash_history", ".zsh_history", ".sh_history", ".history",
        ".mysql_history", ".psql_history", ".rediscli_history", ".node_repl_history",
    }
)

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
    return wellknown.is_test_path(path)


def _holds_a_credential(text: str) -> bool:
    """True when a flat config file carries a credential-shaped assignment.

    Deliberately about the *name* on the left rather than the entropy on the
    right: ``POSTGRES_PW=changeit`` is a template and ``_authToken=<token>`` is
    a leak even when the token is short. Whether the value itself is a real
    secret is SEC101's question, and it will have asked it already.
    """
    for line in text.splitlines():
        match = _ASSIGNMENT.match(line)
        if match is None:
            continue
        value = match.group("value").strip().strip("\"'")
        if value and is_secret_name(match.group("name")) and not looks_like_placeholder(value):
            return True
    return False


def scan_name(path: str, text: "str | None" = None) -> "Iterator[Finding]":
    """Yield the findings a file's name -- and, where it has one, its content -- justify.

    ``text`` is the file's contents, or None when the walk could not read it.
    A name is evidence; contents, when there are any, are better evidence, and
    the rules below prefer them wherever they exist.
    """
    readable = text is not None
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

    byproduct = next(
        ((suffix, fact) for suffix, fact in _BYPRODUCTS.items() if lowered.endswith(suffix)),
        None,
    )
    if byproduct is not None:
        severity, what = byproduct[1]
        yield Finding(
            rule_id="FN004",
            severity=severity,
            title=f"{name} is committed, and it holds {what.split(',')[0]}",
            path=normalised,
            line=1,
            evidence=f"file named {name!r}",
            remediation=(
                f"This file holds {what}. Nobody writes a secret into one on "
                "purpose, which is why nobody remembers it is there. Rotate "
                "what it contains, remove it, and add it to .gitignore."
            ),
        )
        return

    if lowered in _HISTORY_NAMES:
        yield Finding(
            rule_id="FN004",
            severity=Severity.MEDIUM,
            title=f"{name} is committed, and it records the commands somebody typed",
            path=normalised,
            line=1,
            evidence=f"file named {name!r}",
            remediation=(
                "A shell or client history includes every password that was "
                "passed on a command line. Remove it, and rotate anything the "
                "commands in it used."
            ),
        )
        return

    holds = _ALWAYS_CREDENTIALS.get(lowered)
    if holds is None:
        holds = _MAYBE_CREDENTIALS.get(lowered)
        if holds is None and _DOT_ENV.match(lowered):
            holds = _MAYBE_CREDENTIALS[".env"]
        # For these the contents decide, and only when there are contents.
        if holds is not None and text is not None and not _holds_a_credential(text):
            return
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


def scan_paths(
    entries: "Iterable[tuple[str, str | None]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs for every file the walk reached.

    ``text`` is None for the files nothing could read, which is the case these
    rules exist for.

    A file that *can* be read can also carry a suppression marker, and a rule
    that ignored one would be the only rule here that does. A file that cannot
    be read has nowhere to put a marker, which is what the ``paths`` table in
    the config file is for.
    """
    findings: "list[Finding]" = []
    for path, text in entries:
        found = list(scan_name(path, text))
        if found and text is not None and honour_markers:
            found = suppression.parse(text).filter_findings(found)
        findings.extend(found)
    return findings
