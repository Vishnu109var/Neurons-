"""Small accumulator the scanners write into while they walk a file."""
from __future__ import annotations

import time

from .models import Finding
from .urls import SUSPICIOUS_LINK_SCORE, UrlSignal, assess_url

MAX_URLS = 200   # per attachment; stops a link-farm file from eating the time budget


class Collector:
    def __init__(self, deadline: float) -> None:
        self.deadline = deadline          # time.monotonic() value after which we stop digging
        self.findings: list[Finding] = []
        self.suspicious_links: list[str] = []
        self.malicious_form = False
        self.malicious_script = False
        self.truncated = False
        self._seen_urls: set[str] = set()

    def out_of_time(self) -> bool:
        if time.monotonic() >= self.deadline:
            if not self.truncated:
                self.truncated = True
                self.add("SCAN_TRUNCATED", "Time budget hit before the whole file was inspected", 15)
            return True
        return False

    def add(self, code: str, detail: str, score: int, url: str | None = None) -> None:
        self.findings.append(Finding(code=code, detail=detail, score=score, url=url))

    def check_url(self, url: str, where: str) -> list[UrlSignal]:
        """Assess a URL once per attachment and record whatever is wrong with it."""
        if url in self._seen_urls or len(self._seen_urls) >= MAX_URLS:
            return []
        self._seen_urls.add(url)
        signals = assess_url(url)
        for s in signals:
            self.add(s.code, f"{s.detail} [{where}]", s.score, url)
        if sum(s.score for s in signals) >= SUSPICIOUS_LINK_SCORE:
            self.suspicious_links.append(url)
        return signals
