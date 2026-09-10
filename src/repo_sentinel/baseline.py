"""Accepting the findings you already know about, so CI can fail on new ones.

A scanner introduced to a repository that has been running for years reports
its entire history at once, and a build that has been red since Tuesday tells
nobody anything. The usual answer is to fix everything first, which means the
tool is adopted by projects that need it least.

A baseline is the other answer: record what is already there, then fail only on
what arrives after. It is a compromise, and it should look like one -- the file
is a list of debts, not a list of exemptions, and the scanner reports how many
of them it is holding every time it runs.

Two properties make the file safe to commit:

* **It never contains a secret.** Entries store a fingerprint of the *redacted*
  evidence, along with the rule and the path. There is nothing to recover.
* **It does not pin line numbers.** Findings are matched on identity, not
  position, so reformatting a file does not resurrect its accepted findings --
  and equally, moving a secret to another file does not keep it accepted.

An entry that no longer matches anything is reported rather than dropped: the
usual reason is that a finding was genuinely fixed, and knowing that is how a
baseline shrinks instead of calcifying.
"""

from __future__ import annotations

import dataclasses
import json
import os
from collections.abc import Iterable, Sequence

from .findings import Finding

#: Where ``--baseline`` looks when given no path of its own.
DEFAULT_PATH = ".repo-sentinel-baseline.json"

#: Bumped only for a change that older readers could not interpret.
SCHEMA_VERSION = 1


class BaselineError(Exception):
    """The baseline file could not be read, or was not a baseline file."""


@dataclasses.dataclass(frozen=True)
class Entry:
    """One accepted finding, described well enough for a human to review it."""

    fingerprint: str
    rule_id: str
    path: str
    title: str

    @classmethod
    def of(cls, finding: Finding) -> "Entry":
        return cls(finding.fingerprint, finding.rule_id, finding.path, finding.title)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Baseline:
    """The accepted findings recorded by a previous run."""

    entries: tuple[Entry, ...] = ()

    @property
    def fingerprints(self) -> frozenset:
        return frozenset(entry.fingerprint for entry in self.entries)

    def partition(
        self, findings: Sequence[Finding]
    ) -> "tuple[list[Finding], list[Finding], list[Entry]]":
        """Split ``findings`` into new and accepted, and name the stale entries.

        Returns ``(new, accepted, stale)``. ``stale`` holds entries that matched
        nothing this run -- fixed, moved, or covering a file that has since been
        deleted. They are worth surfacing but never worth failing on.
        """
        known = self.fingerprints
        new = [finding for finding in findings if finding.fingerprint not in known]
        accepted = [finding for finding in findings if finding.fingerprint in known]
        seen = {finding.fingerprint for finding in accepted}
        stale = [entry for entry in self.entries if entry.fingerprint not in seen]
        return new, accepted, stale


def load(path: str) -> Baseline:
    """Read a baseline file, or raise :class:`BaselineError` explaining why not."""
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        raise BaselineError(
            f"no baseline at {path!r}; create one with --write-baseline"
        ) from None
    except OSError as error:
        raise BaselineError(f"could not read {path!r}: {error}") from None
    except json.JSONDecodeError as error:
        raise BaselineError(f"{path!r} is not valid JSON: {error}") from None

    if not isinstance(payload, dict) or "findings" not in payload:
        raise BaselineError(f"{path!r} does not look like a repo-sentinel baseline")

    version = payload.get("baseline_version")
    if version != SCHEMA_VERSION:
        raise BaselineError(
            f"{path!r} uses baseline schema {version!r}, expected {SCHEMA_VERSION}; "
            "regenerate it with --write-baseline"
        )

    entries = []
    for record in payload["findings"]:
        try:
            entries.append(
                Entry(
                    fingerprint=str(record["fingerprint"]),
                    rule_id=str(record.get("rule_id", "")),
                    path=str(record.get("path", "")),
                    title=str(record.get("title", "")),
                )
            )
        except (TypeError, KeyError) as error:
            raise BaselineError(f"{path!r} has a malformed entry: {error}") from None
    return Baseline(tuple(entries))


def entries(findings: Iterable[Finding]) -> "list[Entry]":
    """The unique entries for ``findings``, in a stable order.

    Sorted so that a regenerated file differs only where the findings differ. A
    baseline that reshuffles itself on every run produces review noise, and
    review noise is how it stops being reviewed.
    """
    return sorted(
        {Entry.of(finding) for finding in findings},
        key=lambda entry: (entry.path, entry.rule_id, entry.fingerprint),
    )


def dumps(findings: Iterable[Finding], *, version: str) -> str:
    """Serialise ``findings`` as a baseline document."""
    document = {
        "baseline_version": SCHEMA_VERSION,
        "generated_by": f"repo-sentinel {version}",
        "note": (
            "Findings accepted as pre-existing. Entries hold a hash of already "
            "redacted evidence, never a credential. Shrink this file; do not grow it."
        ),
        "findings": [entry.to_dict() for entry in entries(findings)],
    }
    return json.dumps(document, indent=2) + "\n"


def write(path: str, findings: Iterable[Finding], *, version: str) -> int:
    """Write a baseline file and return how many findings it accepted."""
    findings = list(findings)
    text = dumps(findings, version=version)
    directory = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as error:
        raise BaselineError(f"could not write {path!r}: {error}") from None
    return len(entries(findings))
