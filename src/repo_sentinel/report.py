"""Turning findings into something a person, a pipeline or GitHub can read.

Six formats, for six readers:

* **text**, for the person who just ran the command. Worst first, with the fix
  attached to the problem, because a finding without a next action is a nag.
* **json**, for anything that wants to post-process the run.
* **sarif**, for GitHub's code scanning tab, which turns a CI run into
  annotations on the pull request that introduced the line.
* **markdown**, for a comment posted onto the pull request itself, where the
  people arguing about the change are already looking.
* **github**, the workflow-command form, which makes findings appear as
  annotations on the diff without needing the permission SARIF upload does.
* **junit**, for the CI systems that are not GitHub: GitLab, Azure and Jenkins
  all draw a test report without being asked twice.

Formatting lives here rather than in the CLI so that the CLI is only argument
handling, and so that a new format is a function rather than a branch inside a
function.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from xml.sax.saxutils import escape, quoteattr

from . import rules
from .findings import Confidence, Finding, Severity

_COLOURS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

#: SARIF has three levels where this tool has four; criticals and highs both
#: have to fail a review, so both map to "error".
_SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

#: GitHub renders its own severity band from this number, not from the level.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}

_CLEAN = "No findings. That is not proof of safety, but it is a good sign."


def summarise(findings: Sequence[Finding]) -> str:
    """``3 finding(s): 1 critical, 2 medium`` -- the line CI logs get grepped for."""
    counts: dict[Severity, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    breakdown = ", ".join(
        f"{counts[severity]} {severity.value}"
        for severity in sorted(counts, key=lambda severity: -severity.rank)
    )
    return f"{len(findings)} finding(s): {breakdown}"


def _severity_label(finding: Finding, *, colour: bool) -> str:
    label = finding.severity.value.upper()
    return f"{_COLOURS[finding.severity]}{label}{_RESET}" if colour else label


def _confidence_note(finding: Finding, *, colour: bool) -> str:
    """The parenthetical that says a rule is guessing, or nothing if it is not."""
    if finding.confidence >= Confidence.HIGH:
        return ""
    marker = f"({finding.confidence.value} confidence)"
    return f"  {_DIM}{marker}{_RESET}" if colour else f"  {marker}"


def _repeat_note(finding: Finding) -> str:
    """``and on 12 more lines``, when one value was pasted more than once."""
    if finding.occurrences < 2:
        return ""
    return f" (and on {finding.occurrences - 1} more line{'' if finding.occurrences == 2 else 's'})"


def _body(finding: Finding, indent: str) -> "list[str]":
    lines = [f"{indent}{finding.title}{_repeat_note(finding)}"]
    if finding.evidence:
        lines.append(f"{indent}evidence: {finding.evidence}")
    if finding.remediation:
        lines.append(f"{indent}fix: {finding.remediation}")
    return lines


def format_text(
    findings: Sequence[Finding],
    *,
    colour: bool,
    notes: Sequence[str] = (),
    by_file: bool = False,
) -> str:
    """Human-readable output. ``notes`` are appended after the summary line.

    With ``by_file`` the path is printed once and its findings sit under it.
    That is what sorting by path is *for*: a report read file by file, where
    repeating ``src/app.py`` eleven times pushes the part that differs off to
    the right. Worst-first output stays flat, because there the path is the
    thing that changes on every line.
    """
    lines: list[str] = []
    if by_file:
        current = None
        for finding in findings:
            if finding.path != current:
                if current is not None:
                    lines.append("")
                current = finding.path
                path = f"{_BOLD}{finding.path}{_RESET}" if colour else finding.path
                lines.append(path)
            header = (
                f"  {_severity_label(finding, colour=colour)} {finding.rule_id}"
                f"  line {finding.line}{_confidence_note(finding, colour=colour)}"
            )
            lines.append(header)
            lines.extend(_body(finding, "      "))
        if findings:
            lines.append("")
    else:
        for finding in findings:
            header = (
                f"{_severity_label(finding, colour=colour)} {finding.rule_id}"
                f"  {finding.path}:{finding.line}"
                f"{_confidence_note(finding, colour=colour)}"
            )
            lines.append(header)
            lines.extend(_body(finding, "    "))
            lines.append("")

    lines.append(summarise(findings) if findings else _CLEAN)
    lines.extend(notes)
    return "\n".join(lines)


def format_summary(findings: Sequence[Finding], *, notes: Sequence[str] = ()) -> str:
    """The summary line and nothing else, for a pipeline log that is read once.

    The counts still distinguish severities, because "12 findings" and "12
    findings, one critical" call for different reactions and a quiet mode that
    loses that distinction is just a broken one.
    """
    return "\n".join([summarise(findings) if findings else _CLEAN, *notes])


def format_json(findings: Sequence[Finding], *, version: str, notes: Sequence[str] = ()) -> str:
    payload = {
        "version": version,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    if notes:
        payload["notes"] = list(notes)
    return json.dumps(payload, indent=2)


#: A coloured dot reads faster than a word in a table, and GitHub renders these
#: wherever a comment can appear.
_MARKERS = {
    Severity.CRITICAL: "\U0001f534",
    Severity.HIGH: "\U0001f7e0",
    Severity.MEDIUM: "\U0001f7e1",
    Severity.LOW: "\U0001f535",
}

#: Rows beyond this are summarised rather than listed. A pull request comment
#: that needs scrolling past four hundred rows is one nobody reads at all.
MARKDOWN_ROW_LIMIT = 50


def _escape(text: str) -> str:
    """Make a value safe to put inside a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def format_markdown(
    findings: Sequence[Finding], *, notes: Sequence[str] = (), limit: int = MARKDOWN_ROW_LIMIT
) -> str:
    """A report that can be pasted into a pull request and read at a glance.

    The table carries what triage needs -- how bad, which rule, where -- and the
    fixes go underneath, once per rule rather than once per finding. A comment
    that repeats the same three-line remediation forty times is one people
    learn to collapse without reading.
    """
    if not findings:
        return "\n".join(["### repo-sentinel", "", _CLEAN, *(f"_{note}_" for note in notes)])

    lines = [f"### repo-sentinel: {summarise(findings)}", ""]
    lines.append("| | Rule | Location | Finding |")
    lines.append("| --- | --- | --- | --- |")
    for finding in findings[:limit]:
        marker = f"{_MARKERS[finding.severity]} {finding.severity.value}"
        detail = _escape(finding.title) + _escape(_repeat_note(finding))
        if finding.confidence < Confidence.HIGH:
            detail += f" _({finding.confidence.value} confidence)_"
        lines.append(
            f"| {marker} | `{finding.rule_id}` | `{finding.path}:{finding.line}` | {detail} |"
        )

    if len(findings) > limit:
        lines.append(f"| | | | _...and {len(findings) - limit} more_ |")

    remedies: "dict[str, str]" = {}
    for finding in findings:
        if finding.remediation and finding.rule_id not in remedies:
            remedies[finding.rule_id] = finding.remediation

    if remedies:
        lines.extend(["", "<details>", "<summary>What to do</summary>", ""])
        for rule_id, remediation in remedies.items():
            lines.append(f"- **{rule_id}** -- {remediation}")
        lines.extend(["", "</details>"])

    if notes:
        lines.extend(["", *(f"_{note}_" for note in notes)])
    return "\n".join(lines)


#: GitHub's annotation levels. Criticals and highs both have to stop a review.
_ANNOTATION_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
}

#: Characters GitHub's workflow command parser reads as structure.
_ANNOTATION_ESCAPES = (("%", "%25"), ("\r", "%0D"), ("\n", "%0A"), (":", "%3A"), (",", "%2C"))


def _annotation_escape(text: str, *, in_property: bool) -> str:
    """Escape a value for a workflow command, which is a line-oriented format."""
    for character, replacement in _ANNOTATION_ESCAPES:
        if character in (":", ",") and not in_property:
            continue
        text = text.replace(character, replacement)
    return text


def format_github(findings: Sequence[Finding], *, notes: Sequence[str] = ()) -> str:
    """Workflow commands, so findings land on the pull request's diff.

    SARIF is the better destination, but uploading it needs
    ``security-events: write``, which a workflow triggered by a fork's pull
    request does not have. Annotations need no permission at all: they are
    lines on stdout that the runner interprets. Same findings, worse home, far
    fewer prerequisites.
    """
    lines = []
    for finding in findings:
        level = _ANNOTATION_LEVELS[finding.severity]
        title = _annotation_escape(
            f"{finding.rule_id} {finding.severity.value}", in_property=True
        )
        location = (
            f"file={_annotation_escape(finding.path, in_property=True)},"
            f"line={max(finding.line, 1)},title={title}"
        )
        message = finding.title
        if finding.occurrences > 1:
            message = f"{message} (repeated on {finding.occurrences} lines in this file)"
        if finding.remediation:
            message = f"{message} — {finding.remediation}"
        lines.append(f"::{level} {location}::{_annotation_escape(message, in_property=False)}")

    lines.extend(f"::notice::{_annotation_escape(note, in_property=False)}" for note in notes)
    if not findings:
        lines.append(f"::notice::{_CLEAN}")
    return "\n".join(lines)


def format_sarif(findings: Sequence[Finding], *, version: str) -> str:
    """SARIF 2.1.0, the format GitHub's Security tab ingests.

    Rules are emitted once and referenced by index, which is what the schema
    wants and also what keeps the file small when one rule fires forty times.
    Only rules that actually fired are described: a static catalogue of every
    rule would tell GitHub about checks this run never made.

    The fingerprint travels as a ``partialFingerprint``, so that code scanning
    tracks a finding across the reformattings and line moves that would
    otherwise close it and reopen it as new.
    """
    ordered_rules: list[str] = []
    for finding in findings:
        if finding.rule_id not in ordered_rules:
            ordered_rules.append(finding.rule_id)

    driver_rules = [_sarif_rule(rule_id, findings) for rule_id in ordered_rules]
    results = [
        _sarif_result(finding, ordered_rules.index(finding.rule_id)) for finding in findings
    ]

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "repo-sentinel",
                        "version": version,
                        "informationUri": "https://github.com/KhanSaahib/repo-sentinel",
                        "rules": driver_rules,
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }
    return json.dumps(document, indent=2)


#: Where a reader of the Security tab can find out what a rule is for. The
#: anchor is the family's heading, because that is where the paragraph
#: explaining the rule lives; a per-rule anchor would point at a table row.
_DOCUMENTATION = "https://github.com/KhanSaahib/repo-sentinel/blob/main/docs/RULES.md"


def _sarif_rule(rule_id: str, findings: Sequence[Finding]) -> dict:
    catalogued = rules.get(rule_id)
    example = next(finding for finding in findings if finding.rule_id == rule_id)
    severity = catalogued.severity if catalogued else example.severity
    category = catalogued.category if catalogued else "other"
    return {
        "id": rule_id,
        "name": catalogued.name if catalogued else rule_id,
        "shortDescription": {"text": catalogued.summary if catalogued else example.title},
        "fullDescription": {"text": example.remediation or example.title},
        "help": {"text": example.remediation or example.title},
        "helpUri": f"{_DOCUMENTATION}#{category.replace(' ', '-')}",
        "defaultConfiguration": {"level": _SARIF_LEVELS[severity]},
        "properties": {
            "tags": ["security", category] + ([catalogued.cwe] if catalogued and catalogued.cwe else []),
            "security-severity": _SECURITY_SEVERITY[severity],
        },
    }


def _sarif_result(finding: Finding, rule_index: int) -> dict:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _SARIF_LEVELS[finding.severity],
        "message": {"text": _sarif_message(finding)},
        "partialFingerprints": {"repoSentinel/v1": finding.fingerprint},
        "properties": {"confidence": finding.confidence.value},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
    }


def _sarif_message(finding: Finding) -> str:
    parts = [finding.title]
    if finding.occurrences > 1:
        parts.append(f"Repeated on {finding.occurrences} lines in this file.")
    if finding.evidence:
        parts.append(f"Evidence: {finding.evidence}")
    if finding.remediation:
        parts.append(finding.remediation)
    return " ".join(parts)


def format_junit(
    findings: Sequence[Finding], *, notes: Sequence[str] = (), duration: float = 0.0
) -> str:
    """JUnit XML, which every CI system except GitHub already knows how to draw.

    GitLab has ``artifacts: reports: junit``, Azure has PublishTestResults,
    Jenkins has the junit step, and all three render it as a list of failures
    with a message and a body -- which is a finding with its remediation.
    SARIF is the better format and GitHub is the only place it goes; this is
    for the other three, and it needs no permission and no plugin.

    One testcase per finding, named for where it is, classed by family so the
    CI groups them the way the catalogue does. A clean run emits one passing
    case rather than an empty suite: a report with no tests in it renders as a
    broken job rather than a quiet one.
    """
    cases: "list[str]" = []
    for finding in findings:
        name = f"{finding.rule_id} {finding.path}:{finding.line}"
        family = rules.RULES[finding.rule_id].category if finding.rule_id in rules.RULES else "other"
        body = "\n".join(
            part
            for part in (
                finding.title + _repeat_note(finding),
                f"evidence: {finding.evidence}" if finding.evidence else "",
                f"confidence: {finding.confidence.value}",
                finding.remediation,
            )
            if part
        )
        cases.append(
            f"    <testcase name={_attribute(name)} "
            f"classname={_attribute('repo-sentinel.' + family)}>\n"
            f"      <failure message={_attribute(finding.title)} "
            f"type={_attribute(finding.severity.value)}>{_text(body)}</failure>\n"
            "    </testcase>"
        )
    if not cases:
        cases.append(
            f"    <testcase name={_attribute('no findings')} "
            f"classname={_attribute('repo-sentinel')} />"
        )

    properties = ""
    if notes:
        properties = (
            "    <properties>\n"
            + "\n".join(
                f"      <property name={_attribute('note')} value={_attribute(note)} />"
                for note in notes
            )
            + "\n    </properties>\n"
        )
    count = len(cases)
    failures = len(findings)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuites name="repo-sentinel" tests="{count}" failures="{failures}">\n'
        f'  <testsuite name="repo-sentinel" tests="{count}" failures="{failures}" '
        f'time="{duration:.3f}">\n'
        f"{properties}"
        + "\n".join(cases)
        + "\n  </testsuite>\n</testsuites>"
    )


def _attribute(value: str) -> str:
    return quoteattr(value)


def _text(value: str) -> str:
    return escape(value)


def _matching_rules(pattern: "str | None") -> "list[rules.Rule]":
    """The catalogue, or the part of it somebody asked about.

    A pattern matches a rule id or its prefix (``SEC``, ``k8s001``), a family
    name (``terraform``), or any word in the summary (``bucket``). One
    argument, three meanings, because a person typing "repo-sentinel rules
    kubernetes" does not want to learn which of the three it was.
    """
    catalogue = list(rules.RULES.values())
    if not pattern:
        return catalogue
    needle = pattern.strip().lower()
    return [
        rule
        for rule in catalogue
        if rule.id.lower().startswith(needle)
        or rule.category.startswith(needle)
        or needle in rule.summary.lower()
        or needle in rule.name
    ]


_CWE_URL = "https://cwe.mitre.org/data/definitions/{number}.html"


def format_rule_detail(rule: "rules.Rule") -> str:
    """Everything the catalogue knows about one rule, as a card.

    Printed when a pattern narrows to a single rule, because at that point the
    person is not browsing -- they have a finding in front of them and want to
    know what it means, whether it applies to their repository, and how to make
    it stop if it is wrong. A one-line table entry answers none of those.
    """
    family = rules.FAMILIES[rule.category]
    lines = [
        f"{rule.id}  {rule.name}",
        "",
        f"  {rule.summary}.",
        "",
        f"  Severity   {rule.severity.value} at worst; context can lower it, never raise it",
        f"  Family     {rule.category} -- {family.reads}",
    ]
    if rule.cwe:
        number = rule.cwe.split("-")[-1]
        lines.append(f"  Weakness   {rule.cwe}  {_CWE_URL.format(number=number)}")
    lines.extend(
        [
            "",
            f"  Wrong here      # repo-sentinel: ignore[{rule.id}]",
            f"  Wrong always    --disable {rule.id}",
            f"  The long form   docs/RULES.md#{family.anchor}",
        ]
    )
    return "\n".join(lines)


def format_rule_catalogue(pattern: "str | None" = None, *, as_json: bool = False) -> str:
    """Print what the scanner checks for, without needing something to find."""
    matched = _matching_rules(pattern)
    if as_json:
        return json.dumps(
            {
                "rules": [
                    {
                        "id": rule.id,
                        "name": rule.name,
                        "summary": rule.summary,
                        "severity": rule.severity.value,
                        "category": rule.category,
                        "cwe": rule.cwe,
                    }
                    for rule in matched
                ]
            },
            indent=2,
        )

    if not matched:
        return (
            f"No rule matches {pattern!r}. "
            "Try a family (secrets, kubernetes, terraform), an id, or a word."
        )

    if len(matched) == 1:
        return format_rule_detail(matched[0])

    grouped: "dict[str, list[rules.Rule]]" = {}
    for rule in matched:
        grouped.setdefault(rule.category, []).append(rule)

    lines: list[str] = []
    for category, catalogued in grouped.items():
        lines.append(f"{category}:")
        for rule in catalogued:
            lines.append(f"  {rule.id}  {rule.severity.value:<8}  {rule.summary}")
        lines.append("")
    total = f"{len(matched)} rule(s)"
    lines.append(total + "." if pattern is None else f"{total} of {len(rules.RULES)}.")
    return "\n".join(lines)
