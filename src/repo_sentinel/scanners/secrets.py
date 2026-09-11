"""Detect credentials that were committed by accident.

Three complementary strategies, in descending order of confidence:

1. **Provider patterns.** Tokens with a documented, distinctive shape (AWS key
   ids, GitHub PATs, Stripe keys) match on structure alone. These are rarely
   wrong, so they are reported at high confidence.
2. **Entropy on a quoted assignment.** A variable literally named ``password``
   or ``api_key`` assigned a long, random-looking string. The rule is guessing,
   so it is gated behind the per-value entropy floor in :mod:`..heuristics`.
3. **Entropy in a value position.** The same judgement applied to file formats
   where credentials are written bare: ``.env``, ``.npmrc``, ``.pypirc``, INI
   files and YAML. There is no quoting to key on, so the file's syntax has to
   stand in for it -- which is why this rule fires only in files whose format
   is known to put values after ``=`` or ``:``.

Everything is filtered through :mod:`.allowlist`, which drops credentials that
vendors and RFCs publish as examples. Structure alone cannot distinguish a
tutorial's AWS key from a live one, and a scanner that flags every README is a
scanner people learn to ignore.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import posixpath
import re
from collections.abc import Callable, Iterable, Iterator
from typing import Optional, Union

from .. import suppression
from ..findings import Confidence, Finding, Severity, redact
from ..heuristics import is_secret_name, looks_generated, looks_like_placeholder
from . import allowlist

#: The one-line form of the suppression marker. :mod:`..suppression` owns the
#: file-level and block-level forms, which need the whole file to interpret.
IGNORE_MARKER = suppression.LINE_MARKER


@dataclasses.dataclass(frozen=True)
class ProviderRule:
    """One credential shape, and what to say when it turns up."""

    rule_id: str
    title: str
    severity: Severity
    pattern: "re.Pattern[str]"
    remediation: str
    confidence: Confidence = Confidence.HIGH
    #: Which group holds the credential itself. Group 0 -- the whole match --
    #: is the common case; a named group is used where the match carries
    #: context worth keeping in the report, such as the host a URL points at.
    secret_group: Union[int, str] = 0
    #: Optional second opinion, for shapes loose enough to need one.
    reject: Optional[Callable[["re.Match[str]"], bool]] = None


#: ``scheme://user:password@host`` is how every manual writes a connection
#: string, so a bare lowercase word in the password position is documentation
#: far more often than it is a credential. Real ones carry a digit, a capital
#: or a symbol; the ones that do not are a weak-password problem rather than a
#: leaked-password one, and this is not that tool.
_PROSE_PASSWORD = re.compile(r"[a-z]{1,12}$")


def _url_credential_is_noise(match: "re.Match[str]") -> bool:
    """Filter for SEC020: most ``user:pass@host`` matches are documentation."""
    password = match.group("password")
    if looks_like_placeholder(password) or len(set(password)) <= 3:
        return True
    if _PROSE_PASSWORD.match(password):
        return True
    return looks_like_placeholder(match.group(0))


_PROVIDER_RULES: tuple[ProviderRule, ...] = (
    ProviderRule(
        "SEC001",
        "AWS access key id",
        Severity.CRITICAL,
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
        "Deactivate the key in IAM, then rotate it. Deleting the commit is not enough.",
    ),
    ProviderRule(
        "SEC002",
        "GitHub personal access token",
        Severity.CRITICAL,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b"),
        "Revoke the token at github.com/settings/tokens and issue a new one.",
    ),
    ProviderRule(
        "SEC003",
        "GitHub fine-grained token",
        Severity.CRITICAL,
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
        "Revoke the token at github.com/settings/tokens and issue a new one.",
    ),
    ProviderRule(
        "SEC004",
        "Private key block",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Treat the key as compromised: generate a new pair and rotate every authorized_keys entry.",
    ),
    ProviderRule(
        "SEC005",
        "Stripe live secret key",
        Severity.CRITICAL,
        re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"),
        "Roll the key in the Stripe dashboard immediately.",
    ),
    ProviderRule(
        "SEC006",
        "Slack token",
        Severity.HIGH,
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        "Revoke the token in the Slack app configuration.",
    ),
    ProviderRule(
        "SEC007",
        "Google API key",
        Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Delete the key in the Google Cloud console and add API restrictions to its replacement.",
    ),
    ProviderRule(
        "SEC008",
        "OpenAI-style API key",
        Severity.HIGH,
        re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"),
        "Revoke the key in the provider dashboard.",
    ),
    ProviderRule(
        "SEC009",
        "JSON Web Token",
        Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "Check what the token grants; if it is a live session or service token, invalidate it.",
    ),
    ProviderRule(
        "SEC010",
        "Stripe test key",
        Severity.LOW,
        re.compile(r"\b[sr]k_test_[A-Za-z0-9]{16,}\b"),
        "Test keys are low risk, but keep them out of version control anyway.",
    ),
    ProviderRule(
        "SEC011",
        "Azure storage account key",
        Severity.CRITICAL,
        re.compile(r"AccountKey=(?P<key>[A-Za-z0-9+/]{86}==)"),
        "Rotate the key in the storage account, then switch clients to a SAS token or managed identity.",
        secret_group="key",
    ),
    ProviderRule(
        "SEC012",
        "Google OAuth client secret",
        Severity.CRITICAL,
        re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
        "Reset the client secret in the Google Cloud console credentials page.",
    ),
    ProviderRule(
        "SEC013",
        "SendGrid API key",
        Severity.CRITICAL,
        re.compile(r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b"),
        "Delete the key in SendGrid settings; it can send mail as your domain.",
    ),
    ProviderRule(
        "SEC014",
        "Twilio API key SID",
        Severity.HIGH,
        # Loose by nature: 32 hex characters behind a two-letter prefix. Real,
        # but not distinctive enough to assert on its own, hence the confidence.
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "Delete the key in the Twilio console. Its paired secret is shown only once, so treat both as lost.",
        confidence=Confidence.MEDIUM,
    ),
    ProviderRule(
        "SEC015",
        "npm access token",
        Severity.CRITICAL,
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "Revoke the token at npmjs.com/settings/~/tokens; it can publish under your account.",
    ),
    ProviderRule(
        "SEC016",
        "PyPI upload token",
        Severity.CRITICAL,
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
        "Revoke the token in your PyPI account settings; it can publish releases of your project.",
    ),
    ProviderRule(
        "SEC017",
        "Docker Hub access token",
        Severity.CRITICAL,
        re.compile(r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"),
        "Delete the token in Docker Hub security settings; it can push images others will run.",
    ),
    ProviderRule(
        "SEC018",
        "Slack incoming webhook URL",
        Severity.HIGH,
        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/+-]{20,}"),
        "Anyone holding the URL can post as the app. Regenerate the webhook in the Slack app configuration.",
    ),
    ProviderRule(
        "SEC019",
        "Hugging Face access token",
        Severity.HIGH,
        re.compile(r"\bhf_[A-Za-z0-9]{34}\b"),
        "Revoke the token at huggingface.co/settings/tokens.",
    ),
    ProviderRule(
        "SEC020",
        "Credentials embedded in a URL",
        Severity.HIGH,
        re.compile(
            r"\b(?P<scheme>[a-z][a-z0-9+.-]{1,15})://"
            r"(?P<user>[^\s/:@]{1,64}):(?P<password>[^\s/:@]{3,128})@(?P<host>[^\s/:@]+)",
            re.IGNORECASE,
        ),
        "Move the password out of the connection string; most clients accept it from the environment instead.",
        confidence=Confidence.MEDIUM,
        secret_group="password",
        reject=_url_credential_is_noise,
    ),
)

#: One alternation of every provider pattern, used only to answer "is there any
#: point looking closer at this line". Almost no line in a repository contains a
#: credential, and running twenty patterns over each of them to discover that is
#: most of the time this scanner spends. Built from the rules themselves rather
#: than hand-written, so it cannot drift away from what it is standing in for;
#: named groups are stripped because two rules may reuse a group name and the
#: combined pattern would not compile.
_ANY_PROVIDER = re.compile(
    "|".join(
        "(?{flags}:{body})".format(
            flags="i" if rule.pattern.flags & re.IGNORECASE else "",
            body=re.sub(r"\(\?P<\w+>", "(?:", rule.pattern.pattern),
        )
        for rule in _PROVIDER_RULES
    )
)

#: A run of base64 long enough to be hiding something. Encoding is not
#: encryption, but it is enough to make a credential invisible to every rule
#: that reads the line it sits on -- kubeconfigs, CI variables and manifests
#: are full of them -- so SEC022 decodes these and asks the provider rules
#: what they see.
#: Two alphabets, scanned separately on purpose. A single class containing
#: both would swallow the name in front of the value -- "TOKEN=QUtJ..." is one
#: unbroken run of it -- and the joined string decodes to nothing, which is how
#: a rule quietly stops firing.
_BASE64_RUNS = (
    re.compile(r"[A-Za-z0-9+/]{24,}"),
    re.compile(r"[A-Za-z0-9_-]{24,}"),
)

#: The two fields that together make a file a Google service account key.
#: Either alone is unremarkable; the pair is a credential with no expiry that
#: is accepted by every Google API the account can reach.
_SERVICE_ACCOUNT_TYPE = re.compile(r'"type"\s*:\s*"service_account"')
_SERVICE_ACCOUNT_KEY = re.compile(r'"private_key(?:_id)?"\s*:')

#: Quoted assignment: ``api_key = "...."`` in any language that quotes strings.
_QUOTED_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_.\[\]-]*
        (?:passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key|
           private[_-]?key|client[_-]?secret|credential|
           auth[_-]?(?:token|key|secret|pass|pw|header)|authorization|bearer)
     [A-Za-z0-9_.\[\]-]*)
    \s* [:=] \s*
    (?P<quote>["'])(?P<value>[^"']{12,256})(?P=quote)
    """
)

#: Bare assignment: ``API_KEY=....`` with no quoting to key on. Only trusted in
#: files whose format puts a value on the right of ``=`` or ``:``; see
#: :func:`has_value_positions`.
_BARE_ASSIGNMENT = re.compile(
    r"""(?x)
    ^[\s#-]* (?:export\s+)?
    (?P<name>[A-Za-z0-9_.\[\]/:@-]{1,120}?)
    \s* [:=] \s*
    (?P<value>[^\s"'\#][^\#\n]{10,255}?)
    \s* (?:\#.*)? $
    """
)

#: File formats that write credentials bare, without quotes.
_VALUE_POSITION_NAMES = frozenset(
    {".env", ".npmrc", ".pypirc", ".netrc", "_netrc", ".dockercfg", ".pgpass", ".my.cnf"}
)
#: TOML is absent on purpose: it requires quotes, so its credentials are
#: already the quoted-assignment rule's business.
_VALUE_POSITION_SUFFIXES = (".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml")


def has_value_positions(path: str) -> bool:
    """True when ``path`` names a format whose values are written unquoted.

    The bare-assignment rule needs this gate. In Python or Go, ``key = value``
    without quotes is a reference to another variable and reporting it would be
    nonsense; in a ``.env`` file it is the credential itself.
    """
    name = posixpath.basename(path.replace("\\", "/"))
    lowered = name.lower()
    if lowered in _VALUE_POSITION_NAMES or lowered.startswith(".env"):
        return True
    return lowered.endswith(_VALUE_POSITION_SUFFIXES)


def _evidence_for(match: "re.Match[str]", rule: ProviderRule) -> str:
    """Redact the credential while keeping whatever context the match carries."""
    if rule.secret_group == 0:
        return redact(match.group(0))
    start, end = match.span(rule.secret_group)
    whole_start = match.start()
    text = match.group(0)
    return (
        text[: start - whole_start]
        + redact(match.group(rule.secret_group))
        + text[end - whole_start :]
    )


def scan_line(
    path: str,
    line_number: int,
    line: str,
    *,
    allow_examples: bool = True,
    value_position: bool = False,
) -> Iterator[Finding]:
    """Yield every finding in a single line of text.

    Set ``allow_examples`` to False to report documented example credentials
    too. That is rarely what you want day to day, but an auditor reviewing the
    scanner's own blind spots needs to see what it chose not to say.

    ``value_position`` enables the bare-assignment rule, which only makes sense
    in the file formats :func:`has_value_positions` recognises.
    """
    if suppression.marker_scope(line) is not None:
        return

    matched_spans: list[tuple[int, int]] = []

    yield from _provider_findings(path, line_number, line, matched_spans, allow_examples)

    yield from _scan_encoded(
        path, line_number, line, matched_spans, allow_examples
    )

    yield from _scan_assignments(
        path, line_number, line, matched_spans, allow_examples, value_position
    )


def _provider_findings(
    path: str,
    line_number: int,
    line: str,
    matched_spans: "list[tuple[int, int]]",
    allow_examples: bool,
) -> Iterator[Finding]:
    """Every documented token shape, in one line of text.

    Spans of everything matched are recorded even when the finding is
    suppressed as a known example, so that a value the allowlist silenced
    cannot resurface under the entropy rules below.
    """
    # The prefilter answers 'is there a credential shape on this line at all'
    # in one pass. Only when it says yes is it worth asking twenty rules
    # which one, which on a real repository is almost never.
    if not _ANY_PROVIDER.search(line):
        return
    for rule in _PROVIDER_RULES:
        for match in rule.pattern.finditer(line):
            secret = match.group(rule.secret_group)
            matched_spans.append(match.span(rule.secret_group))
            if rule.reject is not None and rule.reject(match):
                continue
            if allow_examples and allowlist.is_known_example(secret):
                continue
            yield Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                path=path,
                line=line_number,
                evidence=_evidence_for(match, rule),
                remediation=rule.remediation,
                confidence=rule.confidence,
            )


def _scan_assignments(
    path: str,
    line_number: int,
    line: str,
    matched_spans: list[tuple[int, int]],
    allow_examples: bool,
    value_position: bool,
) -> Iterator[Finding]:
    """The two entropy rules, which differ only in how they find the value."""
    # Both rules need an assignment, and the quoted one needs a quote. Checking
    # for the characters first skips the pattern entirely on most lines.
    if "=" not in line and ":" not in line:
        return
    candidates: list[tuple[str, str, tuple[int, int], str, Severity]] = []

    if '"' in line or "'" in line:
        for match in _QUOTED_ASSIGNMENT.finditer(line):
            candidates.append(
                (
                    "SEC100",
                    match.group("name"),
                    match.span("value"),
                    match.group("value"),
                    Severity.HIGH,
                )
            )

    if value_position:
        match = _BARE_ASSIGNMENT.match(line)
        if match is not None and is_secret_name(match.group("name")):
            candidates.append(
                (
                    "SEC101",
                    match.group("name"),
                    match.span("value"),
                    match.group("value"),
                    Severity.HIGH,
                )
            )

    for rule_id, name, span, value, severity in candidates:
        # Do not report the same string twice under two rules.
        if any(start <= span[0] < end for start, end in matched_spans):
            continue
        if allow_examples and allowlist.is_known_example(value):
            continue
        if not looks_generated(value):
            continue
        matched_spans.append(span)
        shape = "quoted string" if rule_id == "SEC100" else "value position"
        yield Finding(
            rule_id=rule_id,
            severity=severity,
            title=f"High-entropy {shape} assigned to {name!r}",
            path=path,
            line=line_number,
            evidence=redact(value),
            remediation=(
                "Move the value to an environment variable or secret store. "
                f"Add a trailing '# {IGNORE_MARKER}' comment if this is a false positive."
            ),
            confidence=Confidence.MEDIUM,
        )


def _runs(line: str) -> "Iterator[re.Match[str]]":
    """Every base64-looking run in a line, under either alphabet."""
    for pattern in _BASE64_RUNS:
        yield from pattern.finditer(line)


def _decode_base64(value: str) -> str:
    """Decode a base64 run to text, or "" when it is not base64 text.

    Deliberately forgiving about padding and about the URL-safe alphabet, and
    deliberately unforgiving about the result: a blob that decodes to bytes
    rather than text is a blob, not a hidden credential.
    """
    candidate = value.replace("-", "+").replace("_", "/")
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        return base64.b64decode(padded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""


def _scan_encoded(
    path: str,
    line_number: int,
    line: str,
    matched_spans: "list[tuple[int, int]]",
    allow_examples: bool,
) -> Iterator[Finding]:
    """SEC022: a provider credential hiding inside a base64 value.

    Only provider rules are applied to the decoded text, never the entropy
    ones. Decoded base64 is random-looking by construction, so entropy would
    fire on every certificate in the repository; a documented token shape
    inside one is a different claim entirely.

    A run that yields a finding has its span recorded, so the entropy rules do
    not then report the same base64 token a second time for being long and
    random -- which it is, and which is no longer the interesting part.
    """
    seen: "set[str]" = set()
    for match in _runs(line):
        decoded = _decode_base64(match.group(0))
        if not decoded or decoded in seen:
            continue
        seen.add(decoded)
        inner: "list[tuple[int, int]]" = []
        for finding in _provider_findings(path, line_number, decoded, inner, allow_examples):
            matched_spans.append(match.span())
            yield Finding(
                rule_id="SEC022",
                severity=finding.severity,
                title=f"{finding.title}, base64 encoded",
                path=path,
                line=line_number,
                evidence=finding.evidence,
                remediation=(
                    f"{finding.remediation} Encoding is not encryption: the "
                    "value is as committed as if it were written out."
                ),
                confidence=finding.confidence,
            )


def scan_document(path: str, text: str) -> Iterator[Finding]:
    """Findings that only exist when the whole file is read at once.

    A line-at-a-time scanner cannot see that ``"type": "service_account"`` on
    line two and ``"private_key"`` on line five are the same object. That pair
    is a Google service account key file, which is a credential with no expiry
    and usually far more authority than whatever needed it.
    """
    type_match = _SERVICE_ACCOUNT_TYPE.search(text)
    if type_match is None or not _SERVICE_ACCOUNT_KEY.search(text):
        return
    yield Finding(
        rule_id="SEC021",
        severity=Severity.CRITICAL,
        title="Google service account key file",
        path=path,
        line=text.count("\n", 0, type_match.start()) + 1,
        evidence='"type": "service_account" with a private key',
        remediation=(
            "Delete the key in the Google Cloud console -- it does not expire, "
            "so the file being old is no comfort -- and move the workload to "
            "workload identity federation or an attached service account."
        ),
    )


def scan_text(path: str, text: str, *, allow_examples: bool = True) -> list[Finding]:
    """Scan an entire file's contents, honouring its suppression directives.

    This is where file-level and block-level markers are resolved, because
    neither can be understood from a single line. The unterminated-block
    warning is raised here rather than in the workflow scanner so that it is
    reported once per file, whatever the file happens to be.
    """
    marks = suppression.parse(text)
    if marks.whole_file:
        return []

    value_position = has_value_positions(path)
    findings = [
        finding
        for number, line in enumerate(text.splitlines(), start=1)
        if not marks.suppresses(number)
        for finding in scan_line(
            path,
            number,
            line,
            allow_examples=allow_examples,
            value_position=value_position,
        )
    ]

    findings.extend(scan_document(path, text))

    # Appended after the filter on purpose: the warning sits on a suppressed
    # line by definition, and suppressing the report of a runaway suppression
    # is how a file goes quiet without anyone noticing.
    warning = suppression.unterminated_finding(path, marks)
    if warning is not None:
        findings.append(warning)
    return findings


def scan_files(
    files: Iterable[tuple[str, str]], *, allow_examples: bool = True
) -> list[Finding]:
    """Scan ``(path, text)`` pairs."""
    return [
        finding
        for path, text in files
        for finding in scan_text(path, text, allow_examples=allow_examples)
    ]
