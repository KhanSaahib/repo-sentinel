"""Record accepted findings so CI only fails on new ones.

Adopting a scanner on an existing repository is the hard part. A first run on
real code produces findings that are all true and none of them today's problem,
and a gate that is red from the first commit is a gate people route around. A
baseline lets a team draw a line: everything known on this date is acknowledged,
and the build breaks on what arrives after it.

The design turns on what a baseline entry is keyed by. Keying on the line number
would be the obvious choice and the wrong one: adding an import at the top of a
file shifts every line below it, the whole baseline goes stale at once, and the
team's only practical response is to regenerate it without reading it, which is
how a real leak gets waved through. So an entry is keyed by rule, path and
redacted evidence, and survives the code moving around inside its file.

Path is deliberately part of the key. The same credential appearing in a new
file is a new decision that deserves a fresh look, even when it was accepted
somewhere else.

Nothing secret is written here. The evidence stored is the same redacted form
that goes into a report, because baseline files are meant to be committed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence

from .findings import Finding

#: Bumped only if the entry key changes meaning, which invalidates every file.
FORMAT_VERSION = 1


class BaselineError(Exception):
    """A baseline file could not be read, or is not a baseline file."""


def fingerprint(finding: Finding) -> str:
    """Return the stable identity of ``finding`` for baseline matching.

    Line number and severity are excluded on purpose. Line numbers move when
    unrelated code changes; severity is a property of the rule, and a rule whose
    severity is retuned should not silently resurrect findings a team already
    accepted.
    """
    material = "\x00".join((finding.rule_id, finding.path, finding.evidence))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def serialise(findings: Iterable[Finding]) -> str:
    """Render ``findings`` as the text of a baseline file.

    Entries are sorted and the output carries no timestamp, so regenerating a
    baseline over unchanged findings produces a byte-identical file. A baseline
    that churns on every run is one nobody can review in a diff.
    """
    entries = [
        {
            "fingerprint": fingerprint(finding),
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "title": finding.title,
        }
        for finding in findings
    ]
    entries.sort(key=lambda entry: (entry["path"], entry["rule_id"], entry["fingerprint"]))
    # De-duplicate: two identical credentials on different lines of one file
    # share a fingerprint, and one entry is enough to accept both.
    unique: list[dict] = []
    seen: set = set()
    for entry in entries:
        if entry["fingerprint"] in seen:
            continue
        seen.add(entry["fingerprint"])
        unique.append(entry)
    payload = {
        "baseline_version": FORMAT_VERSION,
        "note": (
            "Findings accepted at the time this file was written. Matching is by "
            "fingerprint only; line and title are context for human review."
        ),
        "findings": unique,
    }
    return json.dumps(payload, indent=2) + "\n"


class Baseline:
    """The set of fingerprints a repository has already accepted."""

    def __init__(self, fingerprints: Iterable[str]) -> None:
        self._fingerprints = set(fingerprints)
        self._matched: set = set()

    def __len__(self) -> int:
        return len(self._fingerprints)

    @classmethod
    def load(cls, path: str) -> "Baseline":
        """Read a baseline file, raising :class:`BaselineError` if it is unusable.

        A missing or corrupt baseline is an error rather than an empty baseline.
        Treating it as empty would turn a typo in a CI argument into a silently
        stricter build, or — once someone adds ``|| true`` to quieten that — into
        no gate at all.
        """
        try:
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError:
            raise BaselineError(
                f"baseline file not found: {path} (create it with --write-baseline)"
            ) from None
        except OSError as error:
            raise BaselineError(f"cannot read baseline file {path}: {error}") from None
        except json.JSONDecodeError as error:
            raise BaselineError(f"baseline file {path} is not valid JSON: {error}") from None

        if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
            raise BaselineError(f"baseline file {path} is missing a 'findings' list")

        version = payload.get("baseline_version")
        if version != FORMAT_VERSION:
            raise BaselineError(
                f"baseline file {path} has format version {version!r}, "
                f"but this version of repo-sentinel writes {FORMAT_VERSION}; "
                "regenerate it with --write-baseline"
            )

        fingerprints = []
        for entry in payload["findings"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("fingerprint"), str):
                raise BaselineError(f"baseline file {path} has an entry without a fingerprint")
            fingerprints.append(entry["fingerprint"])
        return cls(fingerprints)

    def accepts(self, finding: Finding) -> bool:
        """True when ``finding`` was already recorded. Records the hit as seen."""
        digest = fingerprint(finding)
        if digest in self._fingerprints:
            self._matched.add(digest)
            return True
        return False

    def filter(self, findings: Sequence[Finding]) -> list[Finding]:
        """Return the findings this baseline does not account for."""
        return [finding for finding in findings if not self.accepts(finding)]

    @property
    def stale_count(self) -> int:
        """Entries that matched nothing in the last :meth:`filter` call.

        Usually these are findings someone fixed, and pruning them keeps the
        baseline honest about how much debt is left. They are reported rather
        than removed automatically, because "the finding stopped appearing" also
        describes a file that dropped out of the scan.
        """
        return len(self._fingerprints) - len(self._matched)
