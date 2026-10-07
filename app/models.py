"""Typed contracts shared by the scanner, the aggregator and the API."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_THREAT = "HIGH_THREAT"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {RiskLevel.SAFE: 0, RiskLevel.LOW_RISK: 1, RiskLevel.SUSPICIOUS: 2, RiskLevel.HIGH_THREAT: 3}


class Finding(BaseModel):
    """One piece of evidence found inside an attachment."""
    code: str                      # stable machine id, e.g. EXTERNAL_FORM_ACTION
    detail: str                    # human readable
    score: int                     # contribution to the 0-100 risk score
    url: str | None = None


class AttachmentReport(BaseModel):
    attachment_scanned: bool
    file_name: str
    file_type: str | None = None   # "pdf" | "html" | None when unsupported
    has_malicious_form: bool = False
    has_malicious_script: bool = False
    suspicious_links: list[str] = Field(default_factory=list)
    attachment_risk_score: int = 0
    attachment_risk_level: RiskLevel = RiskLevel.SAFE
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    scan_ms: float = 0.0


class TextReport(BaseModel):
    """Output of Shruthi's NLP module (see app/nlp.py for the adapter)."""
    phishing_probability: float = 0.0   # 0..1
    risk_level: RiskLevel = RiskLevel.SAFE
    signals: list[str] = Field(default_factory=list)
    error: str | None = None


class PipelineResult(BaseModel):
    """The single JSON document handed to Ruchit's backend."""
    overall_risk_level: RiskLevel
    overall_risk_score: int
    text_analysis: TextReport
    attachments: list[AttachmentReport]
    # Flat mirror of the first attachment, matching the spec's example payload.
    attachment_scanned: bool
    file_name: str | None = None
    has_malicious_form: bool = False
    attachment_risk_level: RiskLevel = RiskLevel.SAFE
    total_ms: float
    within_budget: bool
