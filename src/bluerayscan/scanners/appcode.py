"""Audit application source for the decisions that disable a defence.

Every other scanner here reads configuration. This one reads code, which is a
different proposition: configuration says what a system *is*, and code says
what it does, and a line-at-a-time reader can only honestly answer questions
about idioms rather than about behaviour. So the rules are few, each a
well-known idiom with a well-known meaning, each written per language rather
than guessed at across all of them. The bar for adding one is that the idiom
has a single meaning in the language it is read in: requests' ``verify``
keyword set to false is a Python spelling, and the same characters in a Go
file are a guess. (Written out like that on purpose -- spelled the usual way,
this sentence would be a finding in this scanner's own source, which is a
thing worth knowing about a scanner that reads for idioms.)

What they have in common is that they are all *deliberate*. Nobody disables
certificate verification by accident; it is typed to get past a failure, on a
Tuesday, with a note to put it back. The note is the part that gets lost, and
a scanner that reads the diff six months later is the only thing that will
ever ask about it again.

The limits are the usual ones, and they are real. There is no parser here, so
a construct spread over several lines is invisible, a helper called
``insecure_session()`` is invisible, and a value arriving through a variable is
invisible. A clean report from this family means "none of these idioms
appears", which is a smaller claim than "this code verifies certificates".
"""

from __future__ import annotations

import dataclasses
import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression
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
    #: Literal substrings, at least one of which appears in every string this
    #: pattern can match, tested case-insensitively. The point is the same as
    #: the provider rules': running fourteen patterns over every source file in
    #: a monorepo is most of what a scan of one costs, and a file that mentions
    #: none of a rule's words cannot trip it. A wrong hint disables the rule
    #: silently, which is what the corpus test is for.
    hints: "tuple[str, ...]" = ()


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

#: PyYAML's load() without a Loader builds arbitrary Python objects, which is
#: remote code execution wherever the document came from a request. Versions
#: since 6.0 default to SafeLoader; a call with an explicit Loader is either
#: safe or deliberate, and either way not this.
#:
#: The lookahead steps over parenthesised arguments rather than stopping at the
#: first ``)``, because the first argument is very often a call itself.
#: ``yaml.load(trust_as_template(f), Loader=AnsibleLoader)`` is safe and was
#: reported: the ``)`` of the inner call ended the lookahead before it reached
#: the loader. Five of Ansible's own call sites, every one of them passing a
#: loader, and one of those -- ``_tags.Origin(path=str(filename)).tag(x)`` --
#: two calls deep.
#:
#: Two deep is where it stops, because ``re`` does not recurse. A third level
#: reports a call that is safe, which is the direction to fail in: the
#: alternative is scanning to the end of the line for a loader, and then a
#: genuinely unguarded ``yaml.load`` goes quiet because something else on the
#: line mentioned one. A missed finding here is a missed remote execution.
#: The lookahead cannot run past the closing parenthesis of the ``load`` call
#: itself, because every way forward needs an opening parenthesis first.
_NO_PARENS = r"[^()\n]{0,400}"
_ONE_DEEP = rf"{_NO_PARENS}(?:\({_NO_PARENS}\){_NO_PARENS})*"
_TWO_DEEP = rf"{_NO_PARENS}(?:\({_ONE_DEEP}\){_NO_PARENS})*"
_UNSAFE_YAML = re.compile(rf"\byaml\.load\s*\((?!{_TWO_DEEP}\bLoader\s*=)")
#: PHP's unserialize() on a superglobal: the request decides which objects get
#: built and which of their destructors run.
_UNSAFE_UNSERIALIZE = re.compile(r"\bunserialize\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST)\b")

#: A password put through a digest built for speed. Both of these are the
#: whole attack: a stolen table of them is a few hours of guessing, and the
#: fix is a function designed to be slow.
_FAST_PASSWORD_HASH = re.compile(
    r"""(?ix)
    \b(?:hashlib\.)?(?P<digest>md5|sha1|sha256|sha512)\s*\(
    [^)\n]{0,60}?
    \b(?P<what>password|passwd|passphrase)\b
    """
)

#: A shell command built out of something the process did not choose. PHP's
#: superglobals are the unambiguous case -- the request is in the command --
#: and the other two are the shapes that carry a value into a shell: a Python
#: call with shell=True and an interpolated string, and Node's exec() with a
#: template literal in it.
_PHP_SHELL_FROM_REQUEST = re.compile(
    r"\b(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\("
    r"[^)\n]{0,80}\$_(?:GET|POST|COOKIE|REQUEST)\b"
)
_PYTHON_SHELL_INTERPOLATION = re.compile(
    r"""(?x)
    \bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\(
    (?=[^)\n]*\bshell\s*=\s*True)
    [^)\n]*?
    (?:f['\"]|\.format\s*\(|\s\+\s|%\s*[\w(])
    """
)
_NODE_SHELL_INTERPOLATION = re.compile(
    r"\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*`[^`\n]*\$\{"
)

#: A JSON Web Token is a claim plus a signature, and the signature is the only
#: reason to believe the claim. "none" is an algorithm in the spec meaning
#: there is no signature, which makes a token anyone can type: change the
#: subject to "admin", re-encode, send. A library that is told to accept it
#: accepts a forgery, so the list is read for the word rather than for the
#: length of it -- ``algorithms: ["none", "HS256"]`` still accepts the forgery,
#: because the token says which one it used.
#:
#: The call has to name the library on the same line. "none" is what half the
#: world calls the absence of a compression or a cipher, and a list of
#: supported algorithms containing it is ordinary everywhere except here. That
#: makes a construct spread over several lines invisible, which is a limit this
#: family already has and states.
_JWT_NONE_ALGORITHM = re.compile(
    r"""(?x)
    \b(?:jwt|jsonwebtoken)\b
    [^\n]{0,120}?
    \balgorithms?\s*[:=]\s*[\[(]
    [^\])\n]{0,80}?
    ['"]none['"]
    """,
    re.IGNORECASE,
)
#: golang-jwt names the same decision in one identifier, and names it honestly.
_GO_JWT_NONE = re.compile(r"\bUnsafeAllowNoneSignatureType\b")

_RULES = (
    _Rule(
        "AP001", _VERIFICATION_OFF[0], _PYTHON, Severity.HIGH,
        "Certificate verification is switched off",
        "An unverified connection is an authenticated one only by accident: "
        "anything on the path can answer instead. If the certificate is "
        "self-signed, trust that certificate -- pass its CA bundle to verify= "
        "-- rather than trusting whatever arrives.",
        hints=("verify",),
    ),
    _Rule(
        "AP001", _VERIFICATION_OFF[1], _PYTHON, Severity.HIGH,
        "An unverified SSL context is created",
        "_create_unverified_context() exists to make a failing connection "
        "work, and it works by accepting any certificate. Build the context "
        "with the CA that actually signs the endpoint.",
        hints=("_create_unverified_context",),
    ),
    _Rule(
        "AP001", _VERIFICATION_OFF[2], _PYTHON, Severity.HIGH,
        "Hostname checking is switched off",
        "Without hostname checking a valid certificate for any host is "
        "accepted for this one, which is most of what a certificate is for.",
        hints=("check_hostname",),
    ),
    _Rule(
        "AP001", _NODE_VERIFICATION_OFF[0], _JAVASCRIPT, Severity.HIGH,
        "Certificate verification is switched off",
        "rejectUnauthorized: false accepts any certificate, including one "
        "minted by whatever is between this process and the endpoint. Pass "
        "the signing CA in ca: instead.",
        hints=("rejectunauthorized",),
    ),
    _Rule(
        "AP001", _NODE_VERIFICATION_OFF[1], _ANY, Severity.HIGH,
        "TLS verification is switched off for the whole process",
        # The rule's own advice names the thing it looks for, which is the
        # ordinary reason a scanner reports itself. Marked rather than
        # reworded: the sentence is clearer with the variable in it.
        "NODE_TLS_REJECT_UNAUTHORIZED=0 disables verification for every "  # bluerayscan: ignore[AP001]
        "connection the process makes, not the one that was failing. Node "
        "prints a warning about this for a reason.",
        hints=("node_tls_reject_unauthorized",),
    ),
    _Rule(
        "AP001", _GO_VERIFICATION_OFF[0], _GO, Severity.HIGH,
        "Certificate verification is switched off",
        "InsecureSkipVerify: true accepts any certificate. If the endpoint "
        "uses a private CA, put that CA in the RootCAs pool.",
        hints=("insecureskipverify",),
    ),
    _Rule(
        "AP001", _PHP_VERIFICATION_OFF[0], _PHP, Severity.HIGH,
        "Certificate verification is switched off",
        "Setting CURLOPT_SSL_VERIFYPEER or CURLOPT_SSL_VERIFYHOST to false "
        "accepts any certificate. Point CURLOPT_CAINFO at the right CA "
        "bundle instead.",
        hints=("curlopt_ssl_verify",),
    ),
    _Rule(
        "AP001", _RUBY_VERIFICATION_OFF[0], _RUBY, Severity.HIGH,
        "Certificate verification is switched off",
        "VERIFY_NONE accepts any certificate. Set ca_file to the CA that "
        "signs the endpoint and leave the mode at VERIFY_PEER.",
        hints=("verify_none",),
    ),
    _Rule(
        "AP002", _DEBUG_ON[0], _PYTHON, Severity.MEDIUM,
        "Debug mode is enabled",
        "Django's debug handler renders the traceback, the local variables "
        "and the settings of whichever request failed, to whoever made it "
        "fail. Read the value from the environment and default it to False.",
        Confidence.MEDIUM,
        hints=("debug",),
    ),
    _Rule(
        "AP002", _DEBUG_ON[1], _PYTHON, Severity.MEDIUM,
        "A development server is started with debug enabled",
        "Flask's debugger offers an interactive console on the error page. "
        "Take the flag from the environment, and serve production through a "
        "real WSGI server rather than this one.",
        Confidence.MEDIUM,
        hints=("debug",),
    ),
    _Rule(
        "AP004", _UNSAFE_YAML, _PYTHON, Severity.HIGH,
        "YAML is parsed into arbitrary Python objects",
        # The advice names the call, which is the ordinary reason a scanner
        # reports itself.
        "yaml.load() without a Loader builds whatever the document names, "  # bluerayscan: ignore[AP004]
        "which is remote code execution if the document came from anywhere "
        "but this repository. yaml.safe_load() is the same call without that.",
        Confidence.MEDIUM,
        hints=("yaml.load",),
    ),
    _Rule(
        "AP004", _UNSAFE_UNSERIALIZE, _PHP, Severity.HIGH,
        "A request is deserialised into PHP objects",
        "unserialize() on a superglobal lets the request choose which classes "
        "are built and which destructors run. Use json_decode(), or pass "
        "allowed_classes: false.",
        hints=("unserialize",),
    ),
    _Rule(
        "AP005", _FAST_PASSWORD_HASH, _PYTHON + _PHP + _RUBY + _JAVASCRIPT, Severity.MEDIUM,
        "A password is hashed with a fast digest",
        "These digests are built for speed, which is the whole attack: a "
        "stolen table of them is a few hours of guessing. Use bcrypt, scrypt "
        "or argon2 -- a function designed to be slow, with a per-password "
        "salt it stores for you.",
        Confidence.MEDIUM,
        hints=("md5", "sha1", "sha256", "sha512"),
    ),
    _Rule(
        "AP006", _PHP_SHELL_FROM_REQUEST, _PHP, Severity.CRITICAL,
        "A request is interpolated into a shell command",
        "The request chooses part of the command line, which is the whole of "
        "command injection. Use escapeshellarg() if the value must be passed, "
        "and prefer an argument list to a shell string.",
        hints=("exec", "system", "passthru", "popen"),
    ),
    _Rule(
        "AP006", _PYTHON_SHELL_INTERPOLATION, _PYTHON, Severity.HIGH,
        "A shell command is built by interpolation",
        "shell=True hands the string to a shell, which reads the parts that "
        "came from elsewhere as syntax. Drop shell=True and pass a list of "
        "arguments; the shell was doing nothing you needed.",
        Confidence.MEDIUM,
        hints=("subprocess",),
    ),
    _Rule(
        "AP006", _NODE_SHELL_INTERPOLATION, _JAVASCRIPT, Severity.HIGH,
        "A shell command is built from a template literal",
        "exec() runs the string through a shell, which reads an interpolated "
        "value as syntax. execFile() takes the command and its arguments "
        "separately, which is the same call without the shell.",
        Confidence.MEDIUM,
        hints=("exec",),
    ),
    _Rule(
        "AP003", _WEAK_RANDOM[0], _ANY, Severity.HIGH,
        "A credential is generated by a predictable random source",
        "These generators are fast and repeatable, which is the opposite of "
        "what a token needs: given a few outputs the rest follow. Use the "
        "cryptographic source -- secrets in Python, crypto.randomBytes in "
        "Node, crypto/rand in Go.",
        Confidence.MEDIUM,
        hints=("random", "rand(", "mt_rand"),
    ),
    _Rule(
        "AP007", _JWT_NONE_ALGORITHM, _PYTHON + _JAVASCRIPT, Severity.CRITICAL,
        "A JWT is accepted with the \"none\" algorithm",
        "\"none\" means the token carries no signature, so anyone can write one: "
        "change the subject to an administrator, re-encode, send. Name the "
        "algorithms you actually issue -- and only those -- when verifying.",
        hints=("jwt", "jsonwebtoken"),
    ),
    _Rule(
        "AP007", _GO_JWT_NONE, _GO, Severity.CRITICAL,
        "A JWT is accepted with the \"none\" algorithm",
        "golang-jwt names this constant honestly. A token with no signature "
        "is a token anyone can write. Parse with the algorithms you issue.",
        hints=("unsafeallownone",),
    ),
)

#: A cheap test in front of the expensive ones. Every rule above needs one of
#: these substrings to match, so a file without any is skipped without running
#: a single pattern -- which is most files in most repositories.
_HINTS = (
    "verif", "rejectunauthorized", "node_tls_reject", "check_hostname",
    "debug", "random", "rand(", "mt_rand", "yaml.load", "unserialize",
    "md5", "sha1", "sha256", "sha512", "exec", "system", "passthru",
    "popen", "subprocess", "jwt", "jsonwebtoken", "unsafeallownone",
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


#: How a line of a comment begins, in the five languages this family reads.
#: ``*`` is a docblock continuation, which is where PHP and JavaScript put the
#: usage example that made this necessary.
_COMMENT_OPENS = ("#", "//", "*", "/*")


def _is_comment_line(text: str, offset: int) -> bool:
    """True when the match at ``offset`` sits on a line that is only a comment.

    A comment does not run. A commented-out call to PyYAML's loader is somebody
    deciding against it, and a docblock showing how to call a query builder is
    documentation -- Nextcloud's passes the literal string "password" to md5 to
    illustrate a column update, five times across two files, which is not a
    password being hashed with a fast digest, it is a sentence about one.

    (Both examples are described rather than written out. Spelled the usual way
    this docstring is two findings in this scanner's own source, and was: the
    self-scan caught them, which is twice now that writing about an idiom has
    been the idiom.)

    Whole-line comments only. A comment after code on the same line would mean
    deciding whether a ``//`` is a comment or the middle of a URL, which needs
    to track quoting, and the shell family makes the same trade for the same
    reason. A line in the middle of a ``/* */`` block that begins with neither
    ``*`` nor ``/*`` is still read.
    """
    start = text.rfind("\n", 0, offset) + 1
    return text[start:offset + 1].lstrip().startswith(_COMMENT_OPENS)


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
    findings: "list[Finding]" = []
    for rule in _RULES:
        if not _applies(rule, name):
            continue
        # The rule's own words, before the rule's own pattern. A TypeScript
        # monorepo is mostly files that mention "debug" and nothing else, and
        # running the other thirteen patterns over each of them was the
        # largest single cost in a scan of one.
        if rule.hints and not any(hint in lowered for hint in rule.hints):
            continue
        for match in rule.pattern.finditer(text):
            if _is_comment_line(text, match.start()):
                continue
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
                    confidence=rule.confidence,
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
