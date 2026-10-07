"""Turns a bag of findings into a 0-100 score and a risk level."""
from __future__ import annotations

from collections import defaultdict

from .models import Finding, RiskLevel

# score thresholds (inclusive lower bounds)
_LEVELS = ((60, RiskLevel.HIGH_THREAT), (30, RiskLevel.SUSPICIOUS), (10, RiskLevel.LOW_RISK))
_REPEAT_BONUS, _REPEAT_CAP = 2, 10


def score_findings(findings: list[Finding]) -> int:
    """Group by finding code: the strongest hit counts in full, repeats add a little.

    This keeps a page with 50 identical http links from outscoring one real
    credential form, while still reflecting that "more is worse".
    """
    groups: dict[str, list[int]] = defaultdict(list)
    for f in findings:
        groups[f.code].append(f.score)
    total = 0
    for scores in groups.values():
        scores.sort(reverse=True)
        total += scores[0] + min((len(scores) - 1) * _REPEAT_BONUS, _REPEAT_CAP)
    return min(total, 100)


def level_for(score: int) -> RiskLevel:
    for floor, level in _LEVELS:
        if score >= floor:
            return level
    return RiskLevel.SAFE
