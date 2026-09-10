"""Turning findings into something a person, a pipeline or GitHub can read.

Three formats, for three readers:

* **text**, for the person who just ran the command. Worst first, with the fix
  attached to the problem, because a finding without a next action is a nag.
* **json**, for anything that wants to post-process the run.
* **sarif**, for GitHub's code scanning tab, which turns a CI run into
  annotations on the pull request that introduced the line.

Formatting lives here rather than in the CLI so that the CLI is only argument
handling, and so that a new format is a function rather than a branch inside a
function.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

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


def format_text(
    findings: Sequence[Finding], *, colour: bool, notes: Sequence[str] = ()
) -> str:
    """Human-readable output. ``notes`` are appended after the summary line."""
    lines: list[str] = []
    for finding in findings:
        label = finding.severity.value.upper()
        if colour:
            label = f"{_COLOURS[finding.severity]}{label}{_RESET}"
        header = f"{label} {finding.rule_id}  {finding.path}:{finding.line}"
        if finding.confidence < Confidence.HIGH:
            marker = f"({finding.confidence.value} confidence)"
            header += f"  {_DIM}{marker}{_RESET}" if colour else f"  {marker}"
        lines.append(header)
        lines.append(f"    {finding.title}")
        if finding.evidence:
            lines.append(f"    evidence: {finding.evidence}")
        if finding.remediation:
            lines.append(f"    fix: {finding.remediation}")
        lines.append("")

    lines.append(summarise(findings) if findings else _CLEAN)
    lines.extend(notes)
    return "\n".join(lines)


def format_json(findings: Sequence[Finding], *, version: str, notes: Sequence[str] = ()) -> str:
    payload = {
        "version": version,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    if notes:
        payload["notes"] = list(notes)
    return json.dumps(payload, indent=2)


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


def _sarif_rule(rule_id: str, findings: Sequence[Finding]) -> dict:
    catalogued = rules.get(rule_id)
    example = next(finding for finding in findings if finding.rule_id == rule_id)
    severity = catalogued.severity if catalogued else example.severity
    return {
        "id": rule_id,
        "name": catalogued.name if catalogued else rule_id,
        "shortDescription": {"text": catalogued.summary if catalogued else example.title},
        "fullDescription": {"text": example.remediation or example.title},
        "help": {"text": example.remediation or example.title},
        "defaultConfiguration": {"level": _SARIF_LEVELS[severity]},
        "properties": {
            "tags": ["security", catalogued.category if catalogued else "other"],
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
    if finding.evidence:
        parts.append(f"Evidence: {finding.evidence}")
    if finding.remediation:
        parts.append(finding.remediation)
    return " ".join(parts)


def format_rule_catalogue(*, as_json: bool = False) -> str:
    """Print what the scanner checks for, without needing something to find."""
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
                    }
                    for rule in rules.RULES.values()
                ]
            },
            indent=2,
        )

    lines: list[str] = []
    for category, catalogued in rules.by_category().items():
        lines.append(f"{category}:")
        for rule in catalogued:
            lines.append(f"  {rule.id}  {rule.severity.value:<8}  {rule.summary}")
        lines.append("")
    lines.append(f"{len(rules.RULES)} rules.")
    return "\n".join(lines)
