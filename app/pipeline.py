"""Runs the NLP text check and every attachment scan in parallel and merges the results."""
from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

from .models import AttachmentReport, PipelineResult, RiskLevel, TextReport
from .nlp import TextAnalyzer
from .scanner import scan_attachment

BUDGET_S = 1.5
SAFETY_MARGIN_S = 0.15       # leave room for serialisation and the HTTP round trip
MAX_ATTACHMENTS = 10


class Pipeline:
    def __init__(self, analyzer: TextAnalyzer, budget_s: float = BUDGET_S, workers: int = 8) -> None:
        self.analyzer = analyzer
        self.budget_s = budget_s
        # Threads are enough here: the heavy parts (lxml, zlib) release the GIL,
        # and scanners stop themselves at the deadline.
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan")

    def close(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)

    async def run(self, subject: str, body: str, attachments: list[tuple[str, bytes]]) -> PipelineResult:
        started = time.monotonic()
        hard_stop = started + self.budget_s - SAFETY_MARGIN_S
        loop = asyncio.get_running_loop()

        text_task = loop.run_in_executor(self.pool, self.analyzer.analyze, subject, body)
        scan_tasks = [
            loop.run_in_executor(self.pool, scan_attachment, name, data, hard_stop)
            for name, data in attachments[:MAX_ATTACHMENTS]
        ]

        text = await self._await(text_task, hard_stop, self._text_fallback)
        reports = [
            await self._await(task, hard_stop, lambda why, n=name: self._attachment_fallback(n, why))
            for task, (name, _) in zip(scan_tasks, attachments)
        ]
        if len(attachments) > MAX_ATTACHMENTS:
            reports.append(AttachmentReport(
                attachment_scanned=False, file_name=f"(+{len(attachments) - MAX_ATTACHMENTS} more)",
                error=f"Only the first {MAX_ATTACHMENTS} attachments are scanned",
                attachment_risk_level=RiskLevel.LOW_RISK, attachment_risk_score=10,
            ))
        return self._merge(text, reports, started)

    @staticmethod
    async def _await(task, hard_stop: float, fallback):
        try:
            return await asyncio.wait_for(task, timeout=max(hard_stop - time.monotonic(), 0.01))
        except asyncio.TimeoutError:
            return fallback("timed out")
        except Exception as exc:  # a crashing analyzer must not sink the whole response
            return fallback(f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _text_fallback(why: str) -> TextReport:
        return TextReport(error=f"Text analysis unavailable ({why})")

    @staticmethod
    def _attachment_fallback(name: str, why: str) -> AttachmentReport:
        # Fail closed: a file we could not finish checking is not "safe".
        return AttachmentReport(
            attachment_scanned=False, file_name=name, error=f"Scan incomplete ({why})",
            attachment_risk_level=RiskLevel.SUSPICIOUS, attachment_risk_score=30,
        )

    def _merge(self, text: TextReport, reports: list[AttachmentReport], started: float) -> PipelineResult:
        worst_attachment = max(reports, key=lambda r: r.attachment_risk_score, default=None)
        att_score = worst_attachment.attachment_risk_score if worst_attachment else 0
        text_score = int(text.phishing_probability * 100)

        score = max(att_score, text_score)
        level = max(
            [text.risk_level, *(r.attachment_risk_level for r in reports)],
            key=lambda lv: lv.rank,
        )
        # Independent evidence from the text AND a file is stronger than either alone.
        if text.risk_level.rank >= RiskLevel.SUSPICIOUS.rank and att_score >= 30:
            level, score = RiskLevel.HIGH_THREAT, min(100, max(score, 60) + 10)

        first = reports[0] if reports else None
        total_ms = (time.monotonic() - started) * 1000
        return PipelineResult(
            overall_risk_level=level,
            overall_risk_score=score,
            text_analysis=text,
            attachments=reports,
            attachment_scanned=any(r.attachment_scanned for r in reports),
            file_name=first.file_name if first else None,
            has_malicious_form=any(r.has_malicious_form for r in reports),
            attachment_risk_level=max((r.attachment_risk_level for r in reports), key=lambda lv: lv.rank, default=RiskLevel.SAFE),
            total_ms=round(total_ms, 1),
            within_budget=total_ms <= self.budget_s * 1000,
        )
