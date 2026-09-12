"""Audit application source for three decisions that disable a defence.

Every other scanner here reads configuration. This one reads code, which is a
different proposition: configuration says what a system *is*, and code says
what it does, and a line-at-a-time reader can only honestly answer questions
about idioms rather than about behaviour. So the rules are three, each a
well-known idiom with a well-known meaning, each written per language rather
than guessed at across all of them.

What they have in common is that they are all *deliberate*. Nobody disables
certificate verification by accident; it is typed to get past a failure, on a
Tuesday, with a note to put it back. The note is the part that gets lost, and
a scanner that reads the diff six months later is the only thing that will
ever ask about it again.

The limits are the usual ones, and they are real. There is no parser here, so
a construct spread over several lines is invisible, a helper called
``insecure_session()`` is invisible, and a value arriving through a variable is
invisible. A clean report from this family means "none of the three idioms
appears", which is a smaller claim than "this code verifies certificates".
"""

from __future__ import annotations

import dataclasses
import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown
from ..findings import Confidence, Finding, Severity

#: Suffixes worth reading. The list is deliberately short: a rule that does not
#: know the language it is reading is a rule that reports its own guesses.
_PYTHON = (".py", ".pyi")
_JAVASCRIPT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
_GO = (".go",)
_PHP = (".php",)
_RUBY = (".rb",)
_ANY = _PYTHON + _JAVASCRIPT + _GO + _PHP + _RUBY

#: A bundle is machine output: minified, one line long, and full of idioms it
#: never chose. Reporting it says nothing about the repository.
_GENERATED_NAMES = (".min.js", ".min.ts", ".bundle.js", "-min.js")
_LONG_LINE = 400


@dataclasses.dataclass(frozen=True)
class _Rule:
    """One idiom, the languages it means something in, and what it means."""

    rule_id: str
    pattern: "re.Pattern[str]"
    suffixes: "tuple[str, ...]"
    severity: Severity
    title: str
    remediation: str
    confidence: Confidence = Confidence.HIGH


_VERIFICATION_OFF = (
    # Python: requests and httpx both spell it this way, and both mean it.
    re.compile(r"\bverify\s*=\s*False\b"),
    re.compile(r"\bssl\._create_unverified_context\s*\("),
    re.compile(r"\bcheck_hostname\s*=\s*False\b"),
)
_NODE_VERIFICATION_OFF = (
    re.compile(r"\brejectUnauthorized\s*:\s*false\b"),
    re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0\b"),
)
_GO_VERIFICATION_OFF = (re.compile(r"\bInsecureSkipVerify\s*:\s*true\b"),)
_PHP_VERIFICATION_OFF = (
    re.compile(r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b", re.IGNORECASE),
)
_RUBY_VERIFICATION_OFF = (re.compile(r"OpenSSL::SSL::VERIFY_NONE\b"),)

#: Django's settings module, Flask's runner, and the environment variable both
#: of them read. A debug handler renders the stack, the local variables and
#: often the settings object itself to whoever triggered the error.
_DEBUG_ON = (
    re.compile(r"^\s*DEBUG\s*=\s*True\s*(?:#.*)?$", re.MULTILINE),
    re.compile(r"\.run\s*\([^)]*\bdebug\s*=\s*True"),
)
#: A credential-shaped name assigned from a generator that was never meant for
#: one. Gated on the name, because the generators themselves are ordinary:
#: Math.random() picks a colour far more often than it picks a token.
_WEAK_RANDOM = (
    re.compile(
        r"""(?ix)
        \b(?P<name>\w*(?:token|secret|password|passwd|nonce|salt|otp|
                        session[_-]?id|api[_-]?key|reset[_-]?code)\w*)
        \s*[:=]\s*
        [^\n=]{0,60}?
        \b(?P<source>Math\.random\s*\(|random\.(?:random|randint|choice|randrange|sample)\s*\(
          |rand\s*\(\s*\)|mt_rand\s*\(|Random\s*\(\s*\)\.)
        """
    ),
)

_RULES = (
    _Rule(
        "AP001", _VERIFICATION_OFF[0], _PYTHON, Severity.HIGH,
        "Certificate verification is switched off",
        "An unverified connection is an authenticated one only by accident: "
        "anything on the path can answer instead. If the certificate is "
        "self-signed, trust that certificate -- pass its CA bundle to verify= "
        "-- rather than trusting whatever arrives.",
    ),
    _Rule(
        "AP001", _VERIFICATION_OFF[1], _PYTHON, Severity.HIGH,
        "An unverified SSL context is created",
        "_create_unverified_context() exists to make a failing connection "
        "work, and it works by accepting any certificate. Build the context "
        "with the CA that actually signs the endpoint.",
    ),
    _Rule(
        "AP001", _VERIFICATION_OFF[2], _PYTHON, Severity.HIGH,
        "Hostname checking is switched off",
        "Without hostname checking a valid certificate for any host is "
        "accepted for this one, which is most of what a certificate is for.",
    ),
    _Rule(
        "AP001", _NODE_VERIFICATION_OFF[0], _JAVASCRIPT, Severity.HIGH,
        "Certificate verification is switched off",
        "rejectUnauthorized: false accepts any certificate, including one "
        "minted by whatever is between this process and the endpoint. Pass "
        "the signing CA in ca: instead.",
    ),
    _Rule(
        "AP001", _NODE_VERIFICATION_OFF[1], _ANY, Severity.HIGH,
        "TLS verification is switched off for the whole process",
        # The rule's own advice names the thing it looks for, which is the
        # ordinary reason a scanner reports itself. Marked rather than
        # reworded: the sentence is clearer with the variable in it.
        "NODE_TLS_REJECT_UNAUTHORIZED=0 disables verification for every "  # repo-sentinel: ignore[AP001]
        "connection the process makes, not the one that was failing. Node "
        "prints a warning about this for a reason.",
    ),
    _Rule(
        "AP001", _GO_VERIFICATION_OFF[0], _GO, Severity.HIGH,
        "Certificate verification is switched off",
        "InsecureSkipVerify: true accepts any certificate. If the endpoint "
        "uses a private CA, put that CA in the RootCAs pool.",
    ),
    _Rule(
        "AP001", _PHP_VERIFICATION_OFF[0], _PHP, Severity.HIGH,
        "Certificate verification is switched off",
        "Setting CURLOPT_SSL_VERIFYPEER or CURLOPT_SSL_VERIFYHOST to false "
        "accepts any certificate. Point CURLOPT_CAINFO at the right CA "
        "bundle instead.",
    ),
    _Rule(
        "AP001", _RUBY_VERIFICATION_OFF[0], _RUBY, Severity.HIGH,
        "Certificate verification is switched off",
        "VERIFY_NONE accepts any certificate. Set ca_file to the CA that "
        "signs the endpoint and leave the mode at VERIFY_PEER.",
    ),
    _Rule(
        "AP002", _DEBUG_ON[0], _PYTHON, Severity.MEDIUM,
        "Debug mode is enabled",
        "Django's debug handler renders the traceback, the local variables "
        "and the settings of whichever request failed, to whoever made it "
        "fail. Read the value from the environment and default it to False.",
        Confidence.MEDIUM,
    ),
    _Rule(
        "AP002", _DEBUG_ON[1], _PYTHON, Severity.MEDIUM,
        "A development server is started with debug enabled",
        "Flask's debugger offers an interactive console on the error page. "
        "Take the flag from the environment, and serve production through a "
        "real WSGI server rather than this one.",
        Confidence.MEDIUM,
    ),
    _Rule(
        "AP003", _WEAK_RANDOM[0], _ANY, Severity.HIGH,
        "A credential is generated by a predictable random source",
        "These generators are fast and repeatable, which is the opposite of "
        "what a token needs: given a few outputs the rest follow. Use the "
        "cryptographic source -- secrets in Python, crypto.randomBytes in "
        "Node, crypto/rand in Go.",
        Confidence.MEDIUM,
    ),
)

#: A cheap test in front of the expensive ones. Every rule above needs one of
#: these substrings to match, so a file without any is skipped without running
#: a single pattern -- which is most files in most repositories.
_HINTS = (
    "verif", "rejectunauthorized", "node_tls_reject", "check_hostname",
    "debug", "random", "rand(", "mt_rand",
)


def is_source_path(path: str) -> bool:
    """True for a file this family knows how to read."""
    name = posixpath.basename(path.replace("\\", "/")).lower()
    if name.endswith(_GENERATED_NAMES):
        return False
    return name.endswith(_ANY)


def _applies(rule: "_Rule", name: str) -> bool:
    return name.endswith(rule.suffixes)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_source(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run the rules that apply to ``path``'s language over one file."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    lowered = text.lower()
    if not any(hint in lowered for hint in _HINTS):
        return []

    name = posixpath.basename(path.replace("\\", "/")).lower()
    # A test that talks to a server with a self-signed certificate is the
    # ordinary reason any of these idioms appears, and an end-to-end suite is
    # mostly that. Measured on ingress-nginx: sixteen findings, every one of
    # them in test/e2e. Weakened rather than dropped -- the idiom copied out
    # of a test into the client it exercises is exactly how it ships.
    in_fixtures = wellknown.is_test_path(path)
    findings: "list[Finding]" = []
    for rule in _RULES:
        if not _applies(rule, name):
            continue
        for match in rule.pattern.finditer(text):
            line = _line_of(text, match.start())
            evidence = match.group(0).strip()
            if len(evidence) > _LONG_LINE:
                continue  # a minified bundle, or a line nobody wrote by hand
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    path=path,
                    line=line,
                    evidence=evidence[:120],
                    remediation=rule.remediation,
                    confidence=rule.confidence.weaker if in_fixtures else rule.confidence,
                )
            )
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not source."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_source_path(path)
        for finding in scan_source(path, text, markers)
    ]
