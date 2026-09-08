"""Finding and Severity types shared by every scanner."""

from __future__ import annotations

import dataclasses
from enum import Enum


class Severity(str, Enum):
    """How badly a finding should ruin your day, worst last."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().lower())
        except ValueError:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from None


_RANKS = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


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

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        data["severity"] = self.severity.value
        return data

    @property
    def sort_key(self) -> tuple:
        return (-self.severity.rank, self.path, self.line, self.rule_id)
