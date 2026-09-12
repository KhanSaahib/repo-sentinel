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
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown
from ..findings import Confidence, Finding, Severity, redact
from ..heuristics import is_secret_name, looks_generated, looks_like_placeholder
from . import allowlist, providers

#: The one-line form of the suppression marker. :mod:`..suppression` owns the
#: file-level and block-level forms, which need the whole file to interpret.
IGNORE_MARKER = suppression.LINE_MARKER


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
#: The key field *and its value*: a chart shipping a template service account
#: with "private_key": "" is showing the shape, not leaking the key.
_SERVICE_ACCOUNT_KEY = re.compile(r'"private_key(?:_id)?"\s*:\s*"(?P<value>[^"]*)"')

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

def _without_continuation(value: str) -> str:
    """Drop a shell line continuation from the end of a bare value.

    A YAML ``run:`` block is full of lines like
    ``--github-token=env:GITHUB_TOKEN \\``, which the value-position rule reads
    as an assignment -- correctly, as far as it goes. The backslash is the
    shell's, not the value's, and leaving it attached defeats every filter that
    asks what shape the value has.
    """
    trimmed = value.rstrip()
    return trimmed[:-1].rstrip() if trimmed.endswith("\\") else trimmed


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
    # A marker that names no rules silences the line outright, so there is
    # nothing to look for. A marker that names rules leaves the rest of them
    # in force, and the filtering happens once the findings exist.
    directive = suppression.marker(line)
    if directive is not None and not directive[1]:
        return

    matched_spans: list[tuple[int, int]] = []

    # Both of these need a long run of credential characters or one of the two
    # literal shapes; the entropy rules below do not, so they run either way.
    if providers.CANDIDATE.search(line):
        yield from _provider_findings(path, line_number, line, matched_spans, allow_examples)
        yield from _scan_encoded(path, line_number, line, matched_spans, allow_examples)

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
    """Every documented token shape, in one line of text."""
    for rule, _secret, evidence in providers.findings_in(
        path, line_number, line, matched_spans, allow_examples, allowlist.is_known_example
    ):
        yield Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            title=rule.title,
            path=path,
            line=line_number,
            evidence=evidence,
            remediation=rule.remediation,
            confidence=rule.confidence,
            subject=redact(_secret),
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
        bare = _BARE_ASSIGNMENT.match(line)
        if bare is not None and is_secret_name(bare.group("name")):
            candidates.append(
                (
                    "SEC101",
                    bare.group("name"),
                    bare.span("value"),
                    _without_continuation(bare.group("value")),
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
                subject=finding.subject,
            )


def scan_document(path: str, text: str) -> Iterator[Finding]:
    """Findings that only exist when the whole file is read at once.

    A line-at-a-time scanner cannot see that ``"type": "service_account"`` on
    line two and ``"private_key"`` on line five are the same object. That pair
    is a Google service account key file, which is a credential with no expiry
    and usually far more authority than whatever needed it.
    """
    type_match = _SERVICE_ACCOUNT_TYPE.search(text)
    if type_match is None:
        return
    if not any(
        match.group("value") and not looks_like_placeholder(match.group("value"))
        for match in _SERVICE_ACCOUNT_KEY.finditer(text)
    ):
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


def scan_text(
    path: str,
    text: str,
    *,
    allow_examples: bool = True,
    marks: "suppression.Suppressions | None" = None,
) -> list[Finding]:
    """Scan an entire file's contents, honouring its suppression directives.

    This is where file-level and block-level markers are resolved, because
    neither can be understood from a single line. The unterminated-block
    warning is raised here rather than in the workflow scanner so that it is
    reported once per file, whatever the file happens to be.
    """
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    value_position = has_value_positions(path)
    findings = marks.filter_findings(
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
    )

    findings.extend(marks.filter_findings(scan_document(path, text)))

    # Appended after the filter on purpose: the warning sits on a suppressed
    # line by definition, and suppressing the report of a runaway suppression
    # is how a file goes quiet without anyone noticing.
    warning = suppression.unterminated_finding(path, marks)
    if warning is not None:
        findings.append(warning)
    return _weigh_for_context(path, findings)


def _weigh_for_context(path: str, findings: "list[Finding]") -> "list[Finding]":
    """Weigh a finding by where it was made. Nothing is silenced.

    Two places, and they are weighed differently because the mistakes people
    make in them are different.

    In **documentation**, every finding drops a step. A credential written into
    prose is usually an example -- that is what prose is for -- and this is as
    true of a documented token shape as of a high-entropy string: Grafana's own
    manual contains two dozen service account tokens, none of them real. A live
    key does get pasted into a README, so the finding stays; it is
    ``--min-confidence high`` that stops hearing about it.

    In a **fixture tree**, only the rules that were already guessing drop. The
    entropy rules are worth less there because invented credentials are the
    point of a fixture. A documented token shape is not worth less, because the
    classic way a real key reaches a repository is a test that once talked to a
    real service.
    """
    if not findings:
        return findings
    prose = wellknown.is_prose_path(path)
    fixtures = wellknown.is_test_path(path)
    if not (prose or fixtures):
        return findings

    weighed = []
    for finding in findings:
        if prose and finding.confidence > Confidence.LOW:
            weighed.append(dataclasses.replace(finding, confidence=finding.confidence.weaker))
        elif fixtures and finding.confidence == Confidence.MEDIUM:
            weighed.append(dataclasses.replace(finding, confidence=Confidence.LOW))
        else:
            weighed.append(finding)
    return weighed


def scan_files(
    files: Iterable[tuple[str, str]],
    *,
    allow_examples: bool = True,
    honour_markers: bool = True,
) -> list[Finding]:
    """Scan ``(path, text)`` pairs."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        for finding in scan_text(path, text, allow_examples=allow_examples, marks=markers)
    ]
