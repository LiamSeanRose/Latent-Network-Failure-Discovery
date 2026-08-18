"""What the tool emits.

One type for every tier, because a user does not care which engine found a problem
— they care what it is, how bad it is, and how it was established. `tier` and
`evidence` carry the latter so a finding can be argued with rather than trusted.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Tier(StrEnum):
    FACTS = "facts"
    TIMING = "timing"


_ORDER: Final = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    rule: str
    tier: Tier
    severity: Severity
    device: str
    title: str
    detail: str
    evidence: tuple[str, ...] = ()
    trigger: str | None = None
    remedy: str | None = None

    @property
    def sort_key(self) -> tuple[int, str, str]:
        return (_ORDER[self.severity], self.device, self.rule)


def rank(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.sort_key)
