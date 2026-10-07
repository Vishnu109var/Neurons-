
from __future__ import annotations

import importlib
import os
import re
from typing import Protocol

from .models import RiskLevel, TextReport
from .risk import level_for


class TextAnalyzer(Protocol):
    def analyze(self, subject: str, body: str) -> TextReport: ...


_CUES = {
    r"verify (your )?(account|identity|details)": 0.25,
    r"(account|card).{0,30}(suspend|block|lock|expire)": 0.25,
    r"(update|confirm).{0,20}(kyc|password|details|pan|aadhaar)": 0.25,
    r"\b(urgent|immediately|within 24 hours|final notice)\b": 0.15,
    r"click (here|the link|below)": 0.10,
    r"\b(otp|cvv|pin)\b": 0.15,
}


class HeuristicTextAnalyzer:
    def analyze(self, subject: str, body: str) -> TextReport:
        text = f"{subject}\n{body}".lower()
        hits = [(pattern, weight) for pattern, weight in _CUES.items() if re.search(pattern, text)]
        prob = min(sum(w for _, w in hits), 0.99)
        return TextReport(
            phishing_probability=round(prob, 2),
            risk_level=level_for(int(prob * 100)),
            signals=[p for p, _ in hits],
        )


def load_analyzer() -> TextAnalyzer:
    spec = os.environ.get("NLP_ANALYZER", "").strip()
    if not spec:
        return HeuristicTextAnalyzer()
    module_name, _, attr = spec.partition(":")
    factory = getattr(importlib.import_module(module_name), attr)
    return factory()
