"""Entry point for scanning one attachment: sniff the type, dispatch, score."""
from __future__ import annotations

import os
import time

from .collector import Collector
from .html_scanner import scan_html
from .models import AttachmentReport, RiskLevel
from .pdf_scanner import scan_pdf
from .risk import level_for, score_findings

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
_HTML_EXT = {".html", ".htm", ".xhtml"}
_HTML_HINTS = (b"<html", b"<form", b"<script", b"<!doctype html", b"<body")


def sniff_type(file_name: str, data: bytes) -> str | None:
    """Decide from the content first, the extension second - names are attacker-controlled."""
    head = data[:2048]
    if b"%PDF-" in head[:1024]:
        return "pdf"
    ext = os.path.splitext(file_name.lower())[1]
    if ext in _HTML_EXT:
        return "html"
    # HTML disguised as a PDF (or as a nameless file) is a classic trick.
    if ext in (".pdf", "") and any(h in head.lower() for h in _HTML_HINTS):
        return "html"
    return None


def scan_attachment(file_name: str, data: bytes, deadline: float | None = None, budget_s: float = 1.0) -> AttachmentReport:
    """Scan one attachment. Never raises: failures come back inside the report.

    `deadline` is an absolute time.monotonic() value; the scanners poll it and
    stop early rather than blow the pipeline's latency budget.
    """
    started = time.monotonic()
    deadline = deadline if deadline is not None else started + budget_s
    safe_name = os.path.basename(file_name or "unnamed")

    def done(report: AttachmentReport) -> AttachmentReport:
        report.scan_ms = round((time.monotonic() - started) * 1000, 1)
        return report

    if len(data) > MAX_ATTACHMENT_BYTES:
        return done(AttachmentReport(
            attachment_scanned=False, file_name=safe_name, error="Attachment larger than 10 MB - not scanned",
            attachment_risk_level=RiskLevel.SUSPICIOUS, attachment_risk_score=30,
        ))

    kind = sniff_type(safe_name, data)
    if kind is None:
        return done(AttachmentReport(attachment_scanned=False, file_name=safe_name, error="Unsupported file type (only .pdf and .html are inspected)"))

    col = Collector(deadline)
    ext = os.path.splitext(safe_name.lower())[1]
    if (kind == "pdf") != (ext == ".pdf") and ext in _HTML_EXT | {".pdf"}:
        col.add("EXTENSION_MISMATCH", f"File named {ext} is really {kind.upper()}", 15)

    try:
        (scan_pdf if kind == "pdf" else scan_html)(data, col)
    except Exception as exc:  # parser bugs must not take the pipeline down
        col.add("SCAN_ERROR", f"Scanner failed: {type(exc).__name__}", 20)

    score = score_findings(col.findings)
    level = level_for(score)
    # A confirmed credential form is a threat regardless of how the points add up.
    if col.malicious_form and level.rank < RiskLevel.SUSPICIOUS.rank:
        level = RiskLevel.SUSPICIOUS
    return done(AttachmentReport(
        attachment_scanned=True,
        file_name=safe_name,
        file_type=kind,
        has_malicious_form=col.malicious_form,
        has_malicious_script=col.malicious_script,
        suspicious_links=col.suspicious_links,
        attachment_risk_score=score,
        attachment_risk_level=level,
        findings=col.findings,
    ))
