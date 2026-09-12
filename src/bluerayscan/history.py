"""Scan what a repository's history added, rather than what it still holds.

A credential in the working tree may never have been pushed. A credential in
history has been on every clone, every fork, every CI cache and every mirror
since the day it landed, and deleting the file does not take it back. Those are
different problems with different answers, and only the second one is certain.

This reads a unified diff -- ``git log -p`` -- and reports the credentials the
commits in it introduced, each named with the commit that introduced it. The
caller runs git; see :mod:`bluerayscan.diffs` for why.

Only the credential rules run here, and that is deliberate. A container that
ran as root in 2021 and does not today is fixed; a workflow that was once
hijackable and was then repaired is repaired. Configuration in history is
history. A credential in history is a credential, until somebody rotates it,
and that is the one question worth asking of a diff.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable

from . import diffs, suppression
from .findings import Finding
from .scanners import filenames, secrets

__all__ = ["HistoryReport", "scan_stream"]


@dataclasses.dataclass(frozen=True)
class HistoryReport:
    """What one pass over a diff stream learned, including how much it read."""

    findings: "list[Finding]"
    commit_count: int
    file_count: int

    @property
    def summary(self) -> str:
        commits = f"{self.commit_count} commit(s)"
        files = f"{self.file_count} file revision(s)"
        return f"Read {commits} and {files}."


def scan_stream(lines: "Iterable[str]", *, allow_examples: bool = True) -> HistoryReport:
    """Every credential the commits in ``lines`` added, oldest commit kept.

    A value added, reverted and added again appears in several commits. What
    matters for rotation is the earliest of them -- that is the day the key
    became public -- so findings are folded by identity and the oldest commit
    wins. Oldest by the date in the stream where git wrote one this can read,
    and otherwise by the order it arrived in, which for ``git log`` means the
    last time it was seen.
    """
    best: "dict[tuple[str, str], tuple[Finding, diffs.Commit, int]]" = {}
    commits: "set[str]" = set()
    revisions = 0

    for position, addition in enumerate(diffs.parse(lines)):
        commits.add(addition.commit.sha)
        revisions += 1
        found = list(filenames.scan_name(addition.path, addition.text))
        found += secrets.scan_text(addition.path, addition.text, allow_examples=allow_examples)
        for finding in found:
            # A reconstruction holds one commit's added lines, so a suppression
            # block opened in an older commit has no end in it and one closed
            # in a newer commit has no start. That rule is about the hygiene of
            # a file as it stands, which is not a question a diff can be asked.
            if finding.rule_id == suppression.UNTERMINATED_RULE_ID:
                continue
            key = (addition.path, finding.fingerprint)
            previous = best.get(key)
            if previous is None or _is_older(addition.commit, position, previous[1], previous[2]):
                best[key] = (finding, addition.commit, position)

    findings = [
        dataclasses.replace(finding, origin=commit.describe())
        for finding, commit, _ in best.values()
    ]
    return HistoryReport(
        findings=sorted(findings, key=lambda finding: finding.sort_key),
        commit_count=len(commits),
        file_count=revisions,
    )


def _is_older(
    commit: "diffs.Commit", position: int, against: "diffs.Commit", was: int
) -> bool:
    """True when ``commit`` introduced something before ``against`` did.

    Dates decide it when both are written in a shape :mod:`.diffs` can read.
    When they are not, the stream's own order does, and later in a ``git log``
    means earlier in the repository -- which is the direction git prints by
    default and the only assumption available once the dates are unreadable.
    """
    mine, theirs = commit.when, against.when
    if mine is not None and theirs is not None:
        return mine < theirs
    return position > was
