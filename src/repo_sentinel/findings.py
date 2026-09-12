"""Finding, Severity and Confidence: the vocabulary every scanner shares."""

from __future__ import annotations

import dataclasses
import hashlib
from enum import Enum


#: Declaration order is the ranking, memoised per enum class because ``rank``
#: is read once per comparison and comparisons happen once per sort step.
_RANKS: dict = {}


class _Ranked(str, Enum):
    """A string enum whose members compare by rank rather than alphabetically."""

    @property
    def rank(self) -> int:
        ranks = _RANKS.get(type(self))
        if ranks is None:
            ranks = _RANKS[type(self)] = {
                member: index for index, member in enumerate(type(self))
            }
        return ranks[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def parse(cls, value: str) -> "_Ranked":
        try:
            return cls(value.strip().lower())
        except ValueError:
            valid = ", ".join(member.value for member in cls)
            name = cls.__name__.lower()
            raise ValueError(f"unknown {name} {value!r} (expected one of: {valid})") from None


class Severity(_Ranked):
    """How badly a finding should ruin your day, worst last."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(_Ranked):
    """How sure the rule is that it found a real instance, surest last.

    Severity and confidence answer different questions, and collapsing them
    into one number loses both. A private key block is critical *and* certain;
    a high-entropy string assigned to ``api_key`` is just as dangerous if real,
    but the rule is guessing. Triage wants to know which it is looking at, and
    a CI gate wants to fail on severity without being ruined by heuristics --
    which is what ``--min-confidence`` is for.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def weaker(self) -> "Confidence":
        """One step down, for a finding whose surroundings argue against it.

        Documentation and fixture trees both weaken a rule without refuting
        it, and both want the same arithmetic. Low is the floor: a rule that
        is already guessing cannot guess less, and silencing it there would
        be a filter pretending to be a judgement.
        """
        return Confidence.MEDIUM if self == Confidence.HIGH else Confidence.LOW


def redact(secret: str, keep: int = 4) -> str:
    """Return a version of ``secret`` safe to print in a report or CI log.

    Findings get pasted into issues and pipeline output, so the scanner must
    never be the thing that leaks the credential it just found. Short values
    are replaced wholesale rather than partially revealed.
    """
    if len(secret) <= keep * 2:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * (len(secret) - keep * 2)}{secret[-keep:]}"


@dataclasses.dataclass(frozen=True)
class Finding:
    """One problem, at one place, found by one rule."""

    rule_id: str
    severity: Severity
    title: str
    path: str
    line: int
    evidence: str = ""
    remediation: str = ""
    confidence: Confidence = Confidence.HIGH
    #: What this finding is *about*, when two rules could legitimately find the
    #: same thing -- in practice, the redacted credential. Findings that carry
    #: the same subject at the same place are one problem reported twice, and
    #: :func:`repo_sentinel.engine.collapse` keeps the best of them. An empty
    #: subject, which is the default, never collapses: two rules sharing a line
    #: by coincidence are two findings, and guessing otherwise loses one.
    subject: str = ""

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["fingerprint"] = self.fingerprint
        # Internal plumbing for de-duplication, not something a consumer of the
        # report has any use for.
        data.pop("subject", None)
        return data

    @property
    def fingerprint(self) -> str:
        """A stable identity for this finding, for baselines and de-duplication.

        Deliberately excludes the line number: adding an import at the top of a
        file must not resurface every finding below it as new. What it does
        include is the evidence, so that editing the offending value -- a new
        key, a different action pin -- produces a new finding rather than
        inheriting the old one's acceptance.

        The evidence is already redacted by the time it reaches here, so a
        fingerprint committed to a baseline file never carries the secret.
        """
        material = "\0".join((self.rule_id, self.path, self.evidence))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    @property
    def sort_key(self) -> tuple:
        """Worst first, then surest first, then in file order."""
        return (-self.severity.rank, -self.confidence.rank, self.path, self.line, self.rule_id)
